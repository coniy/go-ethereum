package searcher

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/rpc"
	"golang.org/x/crypto/sha3"
	"math/big"
	"time"
)

// API offers an API for accepting bundled transactions and MEV purposes
type API struct {
	b     ethapi.Backend
	chain *core.BlockChain
}

// NewSearcherAPI creates a new Tx Bundle API instance.
func NewSearcherAPI(b ethapi.Backend, chain *core.BlockChain) *API {
	return &API{
		b:     b,
		chain: chain,
	}
}

// SearcherCallBundle will simulate a bundle of transactions at the top of a given block
// number with the state of another (or the same) block. This can be used to
// simulate future blocks with the current state, or it can be used to simulate
// a past block.
// The sender is responsible for signing the transactions and using the correct
// nonce and ensuring validity
func (s *API) SearcherCallBundle(ctx context.Context, args CallBundleArgs) (*CallBundleResult, error) {
	if len(args.Txs) == 0 {
		return nil, errors.New("bundle missing txs")
	}
	if args.StateBlockNumberOrHash == (rpc.BlockNumberOrHash{}) {
		args.StateBlockNumberOrHash = rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	}

	timeoutMilliSeconds := int64(5000)
	if args.Timeout != nil {
		timeoutMilliSeconds = *args.Timeout
	}
	timeout := time.Millisecond * time.Duration(timeoutMilliSeconds)

	var txs types.Transactions
	for _, encodedTx := range args.Txs {
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(encodedTx); err != nil {
			return nil, err
		}
		txs = append(txs, tx)
	}

	state, parent, err := s.b.StateAndHeaderByNumberOrHash(ctx, args.StateBlockNumberOrHash)
	if state == nil || err != nil {
		return nil, err
	}

	// override state
	if err := args.StateOverrides.Apply(state); err != nil {
		return nil, err
	}

	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).Set(parent.Number).Add(parent.Number, common.Big1),
		GasLimit:   parent.GasLimit,
		Time:       parent.Time + 12, // eth average block time is 12 seconds
		Difficulty: new(big.Int).Set(parent.Difficulty),
		Coinbase:   parent.Coinbase,
	}
	if s.b.ChainConfig().IsLondon(big.NewInt(parent.Number.Int64())) {
		header.BaseFee = misc.CalcBaseFee(s.b.ChainConfig(), parent)
	}

	// header overrides
	args.BlockOverrides.Apply(header)

	// Setup the gas pool (also for unmetered requests)
	// and apply the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)

	bundleHash := sha3.NewLegacyKeccak256()
	signer := types.MakeSigner(s.b.ChainConfig(), header.Number)
	// Setup context so it may be cancelled the call has completed
	// or, in case of unmetered gas, setup a context with a timeout.
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer cancel()

	ret := &CallBundleResult{
		CoinbaseDiff:      state.GetBalance(header.Coinbase),
		GasFees:           new(big.Int),
		EthSentToCoinbase: new(big.Int),
		StateBlockNumber:  parent.Number.Int64(),
		Results:           make([]CallBundleTxResult, 0, len(txs)),
	}
	for i, tx := range txs {
		// Check if the context was cancelled (eg. timed-out)
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		coinbaseBalanceBeforeTx := state.GetBalance(header.Coinbase)
		state.SetTxContext(tx.Hash(), i)

		receipt, result, err := applyTransactionWithResult(s.b.ChainConfig(), s.chain, &header.Coinbase, gp, state, header, tx, &header.GasUsed, *s.chain.GetVMConfig())
		if err != nil {
			return nil, fmt.Errorf("tx %s error: %w", tx.Hash(), err)
		}
		ret.TotalGasUsed += receipt.GasUsed
		bundleHash.Write(tx.Hash().Bytes())

		txResult := CallBundleTxResult{
			TxHash:       tx.Hash(),
			GasUsed:      receipt.GasUsed,
			ReturnData:   result.ReturnData,
			Logs:         receipt.Logs,
			CoinbaseDiff: new(big.Int).Sub(state.GetBalance(header.Coinbase), coinbaseBalanceBeforeTx),
			CallMsg: &CallMsg{
				Gas:        tx.Gas(),
				GasPrice:   tx.GasPrice(),
				GasFeeCap:  tx.GasFeeCap(),
				GasTipCap:  tx.GasTipCap(),
				Value:      tx.Value(),
				Nonce:      tx.Nonce(),
				Data:       tx.Data(),
				AccessList: tx.AccessList(),
			},
		}
		txResult.CallMsg.From, err = types.Sender(signer, tx)
		if err != nil {
			return nil, fmt.Errorf("tx %s error: %w", tx.Hash(), err)
		}
		txResult.CallMsg.To = receipt.ContractAddress
		if tx.To() != nil {
			txResult.CallMsg.To = *tx.To()
		}
		txResult.GasPrice, err = tx.EffectiveGasTip(header.BaseFee)
		if err != nil {
			return nil, fmt.Errorf("tx %s error: %w", tx.Hash(), err)
		}
		txResult.GasFees = new(big.Int).Mul(big.NewInt(int64(receipt.GasUsed)), txResult.GasPrice)
		ret.GasFees.Add(ret.GasFees, txResult.GasFees)
		txResult.EthSentToCoinbase = new(big.Int).Sub(txResult.CoinbaseDiff, txResult.GasFees)
		txResult.GasPrice = new(big.Int).Div(txResult.CoinbaseDiff, big.NewInt(int64(receipt.GasUsed)))

		if result.Err != nil {
			txResult.Error = result.Err.Error()
		}
		reason, errUnpack := abi.UnpackRevert(result.Revert())
		if errUnpack == nil {
			txResult.Error = fmt.Sprintf("execution reverted: %v", reason)
		}

		ret.Results = append(ret.Results, txResult)
	}

	ret.CoinbaseDiff = new(big.Int).Sub(state.GetBalance(header.Coinbase), ret.CoinbaseDiff)
	ret.EthSentToCoinbase = new(big.Int).Sub(ret.CoinbaseDiff, ret.GasFees)
	ret.BundleGasPrice = new(big.Int).Div(ret.CoinbaseDiff, big.NewInt(int64(ret.TotalGasUsed)))
	ret.BundleHash = common.BytesToHash(bundleHash.Sum(nil))

	return ret, nil
}

func (s *API) SearcherCall(ctx context.Context, args CallArgs) (*CallResult, error) {
	if len(args.Txs) == 0 {
		return nil, errors.New("missing txs")
	}
	if args.StateBlockNumberOrHash == (rpc.BlockNumberOrHash{}) {
		args.StateBlockNumberOrHash = rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
	}

	timeoutMS := int64(5000)
	if args.Timeout != nil {
		timeoutMS = *args.Timeout
	}
	timeout := time.Millisecond * time.Duration(timeoutMS)

	state, parent, err := s.b.StateAndHeaderByNumberOrHash(ctx, args.StateBlockNumberOrHash)
	if state == nil || err != nil {
		return nil, err
	}

	// override state
	if err := args.StateOverrides.Apply(state); err != nil {
		return nil, err
	}

	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).Set(parent.Number).Add(parent.Number, common.Big1),
		GasLimit:   parent.GasLimit,
		Time:       parent.Time + 12, // eth average block time is 12 seconds
		Difficulty: new(big.Int).Set(parent.Difficulty),
		Coinbase:   parent.Coinbase,
		BaseFee:    new(big.Int).Set(parent.BaseFee),
	}

	// header overrides
	args.BlockOverrides.Apply(header)

	// RPC Call gas cap
	globalGasCap := s.b.RPCGasCap()

	// Gas pool
	gp := new(core.GasPool).AddGas(math.MaxUint64)

	// Block context
	blockContext := core.NewEVMBlockContext(header, s.chain, &header.Coinbase)

	// Setup context so it may be cancelled when the call
	// has completed or, in case of unmetered gas, setup
	// a context with a timeout
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// This makes sure resources are cleaned up
	defer cancel()

	// Feed each of the transactions into the VM ctx
	// And try and estimate the gas used
	ret := &CallResult{
		StateBlockNumber: parent.Number.Int64(),
		Results:          make([]CallTxResult, 0, len(args.Txs)),
	}
	for i, callMsg := range args.Txs {
		// Check if the context was cancelled (eg. timed-out)
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		// Since it is a txCall we'll just prepare the
		// state with a random hash
		var txHash common.Hash
		rand.Read(txHash[:])

		// New random hash since its a call
		state.SetTxContext(txHash, i)

		// Convert tx args to msg to apply state transition
		txArgs := ethapi.TransactionArgs{
			From:                 &callMsg.From,
			To:                   &callMsg.To,
			Gas:                  (*hexutil.Uint64)(&callMsg.Gas),
			GasPrice:             (*hexutil.Big)(callMsg.GasPrice),
			MaxFeePerGas:         (*hexutil.Big)(callMsg.GasFeeCap),
			MaxPriorityFeePerGas: (*hexutil.Big)(callMsg.GasTipCap),
			Value:                (*hexutil.Big)(callMsg.Value),
			Data:                 &callMsg.Data,
			AccessList:           &callMsg.AccessList,
		}
		msg, err := txArgs.ToMessage(globalGasCap, header.BaseFee)
		if err != nil {
			return nil, err
		}

		// Create a new EVM environment
		evm := vm.NewEVM(blockContext, core.NewEVMTxContext(msg), state, s.chain.Config(), vm.Config{NoBaseFee: true})

		// Apply state transition
		var txResult CallTxResult
		result, err := core.ApplyMessage(evm, msg, gp)
		if err != nil {
			txResult.Error = fmt.Sprintf("%s (supplied gas %d)", err.Error(), msg.Gas())
		} else {
			// Modifications are committed to the state
			// Only delete empty objects if EIP158/161 (a.k.a Spurious Dragon) is in effect
			state.Finalise(evm.ChainConfig().IsEIP158(blockContext.BlockNumber))

			txResult.Logs = state.GetLogs(txHash, header.Number.Uint64(), header.Hash())

			if result.Err != nil {
				txResult.Error = result.Err.Error()
			}
			reason, errUnpack := abi.UnpackRevert(result.Revert())
			if errUnpack == nil {
				txResult.Error = fmt.Sprintf("execution reverted: %v", reason)
			}
			txResult.GasUsed = result.UsedGas
			ret.TotalGasUsed += result.UsedGas
			txResult.ReturnData = result.ReturnData
		}

		ret.Results = append(ret.Results, txResult)
	}

	return ret, nil
}
