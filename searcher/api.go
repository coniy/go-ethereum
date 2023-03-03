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
	"github.com/ethereum/go-ethereum/log"
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

// CallBundle will simulate a bundle of transactions at the top of a given block
// number with the state of another (or the same) block. This can be used to
// simulate future blocks with the current state, or it can be used to simulate
// a past block.
// The sender is responsible for signing the transactions and using the correct
// nonce and ensuring validity
func (s *API) CallBundle(ctx context.Context, args CallBundleArgs) (*CallBundleResult, error) {
	if len(args.Txs) == 0 {
		return nil, errors.New("bundle missing txs")
	}
	if args.BlockNumber == 0 {
		return nil, errors.New("bundle missing blockNumber")
	}

	var txs types.Transactions

	for _, encodedTx := range args.Txs {
		tx := new(types.Transaction)
		if err := tx.UnmarshalBinary(encodedTx); err != nil {
			return nil, err
		}
		txs = append(txs, tx)
	}
	defer func(start time.Time) { log.Debug("Executing EVM call finished", "runtime", time.Since(start)) }(time.Now())

	timeoutMilliSeconds := int64(5000)
	if args.Timeout != nil {
		timeoutMilliSeconds = *args.Timeout
	}
	timeout := time.Millisecond * time.Duration(timeoutMilliSeconds)

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

	state, parent, err := s.b.StateAndHeaderByNumberOrHash(ctx, args.StateBlockNumberOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	blockNumber := big.NewInt(int64(args.BlockNumber))

	timestamp := parent.Time + 12
	if args.Timestamp != nil {
		timestamp = *args.Timestamp
	}
	coinbase := parent.Coinbase
	if args.Coinbase != nil {
		coinbase = *args.Coinbase
	}
	difficulty := parent.Difficulty
	if args.Difficulty != nil {
		difficulty = args.Difficulty
	}
	gasLimit := parent.GasLimit
	if args.GasLimit != nil {
		gasLimit = *args.GasLimit
	}
	var baseFee *big.Int
	if args.BaseFee != nil {
		baseFee = args.BaseFee
	} else if s.b.ChainConfig().IsLondon(big.NewInt(args.BlockNumber.Int64())) {
		baseFee = misc.CalcBaseFee(s.b.ChainConfig(), parent)
	}
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     blockNumber,
		GasLimit:   gasLimit,
		Time:       timestamp,
		Difficulty: difficulty,
		Coinbase:   coinbase,
		BaseFee:    baseFee,
	}

	vmconfig := vm.Config{}

	// Setup the gas pool (also for unmetered requests)
	// and apply the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)

	bundleHash := sha3.NewLegacyKeccak256()
	signer := types.MakeSigner(s.b.ChainConfig(), blockNumber)
	result := &CallBundleResult{
		CoinbaseDiff:      state.GetBalance(coinbase),
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

		coinbaseBalanceBeforeTx := state.GetBalance(coinbase)
		state.SetTxContext(tx.Hash(), i)

		receipt, execResult, err := applyTransactionWithResult(s.b.ChainConfig(), s.chain, &coinbase, gp, state, header, tx, &header.GasUsed, vmconfig)
		if err != nil {
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}
		result.TotalGasUsed += receipt.GasUsed

		from, err := types.Sender(signer, tx)
		if err != nil {
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}
		to := receipt.ContractAddress
		if tx.To() != nil {
			to = *tx.To()
		}
		gasPrice, err := tx.EffectiveGasTip(header.BaseFee)
		if err != nil {
			return nil, fmt.Errorf("err: %w; txhash %s", err, tx.Hash())
		}
		txGasFees := new(big.Int).Mul(big.NewInt(int64(receipt.GasUsed)), gasPrice)
		result.GasFees.Add(result.GasFees, txGasFees)
		bundleHash.Write(tx.Hash().Bytes())

		var errString string
		revertData := execResult.Revert()
		if len(revertData) > 0 {
			reason, errUnpack := abi.UnpackRevert(execResult.Revert())
			if errUnpack != nil {
				errString = "execution reverted"
			} else {
				errString = fmt.Sprintf("execution reverted: %v", reason)
			}
		}

		txCoinbaseDiff := new(big.Int).Sub(state.GetBalance(coinbase), coinbaseBalanceBeforeTx)

		result.Results = append(result.Results, CallBundleTxResult{
			TxHash:            tx.Hash(),
			GasUsed:           receipt.GasUsed,
			Error:             errString,
			ReturnData:        execResult.ReturnData,
			Logs:              receipt.Logs,
			CoinbaseDiff:      txCoinbaseDiff,
			GasFees:           txGasFees,
			EthSentToCoinbase: new(big.Int).Sub(txCoinbaseDiff, txGasFees),
			GasPrice:          new(big.Int).Div(txCoinbaseDiff, big.NewInt(int64(receipt.GasUsed))),
			CallMsg: &CallMsg{
				From:                 from,
				To:                   to,
				Gas:                  tx.Gas(),
				GasPrice:             tx.GasPrice(),
				MaxFeePerGas:         tx.GasFeeCap(),
				MaxPriorityFeePerGas: tx.GasTipCap(),
				Value:                tx.Value(),
				Nonce:                tx.Nonce(),
				Data:                 tx.Data(),
				AccessList:           tx.AccessList(),
			},
		})
	}

	result.CoinbaseDiff = new(big.Int).Sub(state.GetBalance(coinbase), result.CoinbaseDiff)
	result.EthSentToCoinbase = new(big.Int).Sub(result.CoinbaseDiff, result.GasFees)
	result.BundleGasPrice = new(big.Int).Div(result.CoinbaseDiff, big.NewInt(int64(result.TotalGasUsed)))
	result.BundleHash = common.BytesToHash(bundleHash.Sum(nil))

	return result, nil
}

func (s *API) Call(ctx context.Context, args CallArgs) (*CallResult, error) {
	if len(args.Txs) == 0 {
		return nil, errors.New("bundle missing txs")
	}
	if args.BlockNumber == 0 {
		return nil, errors.New("bundle missing blockNumber")
	}

	timeoutMS := int64(5000)
	if args.Timeout != nil {
		timeoutMS = *args.Timeout
	}
	timeout := time.Millisecond * time.Duration(timeoutMS)

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

	state, parent, err := s.b.StateAndHeaderByNumberOrHash(ctx, args.StateBlockNumberOrHash)
	if state == nil || err != nil {
		return nil, err
	}
	blockNumber := big.NewInt(int64(args.BlockNumber))
	timestamp := parent.Time + 12
	if args.Timestamp != nil {
		timestamp = *args.Timestamp
	}
	coinbase := parent.Coinbase
	if args.Coinbase != nil {
		coinbase = *args.Coinbase
	}

	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     blockNumber,
		GasLimit:   parent.GasLimit,
		Time:       timestamp,
		Difficulty: parent.Difficulty,
		Coinbase:   coinbase,
		BaseFee:    parent.BaseFee,
	}

	// RPC Call gas cap
	globalGasCap := s.b.RPCGasCap()

	// Gas pool
	gp := new(core.GasPool).AddGas(math.MaxUint64)

	// Block context
	blockContext := core.NewEVMBlockContext(header, s.chain, &coinbase)

	// override state
	if args.StateOverrides != nil {
		stateOverrides := make(ethapi.StateOverride)
		for addr, override := range *args.StateOverrides {
			stateOverrides[addr] = ethapi.OverrideAccount(override)
		}
		if err := stateOverrides.Apply(state); err != nil {
			return nil, err
		}
	}
	(*ethapi.BlockOverrides)(args.BlockOverrides).Apply(&blockContext)

	// Feed each of the transactions into the VM ctx
	// And try and estimate the gas used
	result := &CallResult{
		StateBlockNumber: parent.Number.Int64(),
		Results:          make([]CallTxResult, 0, len(args.Txs)),
	}
	for i, callMsg := range args.Txs {
		// Check if the context was cancelled (eg. timed-out)
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		// Since its a txCall we'll just prepare the
		// state with a random hash
		var randomHash common.Hash
		rand.Read(randomHash[:])

		// New random hash since its a call
		state.SetTxContext(randomHash, i)

		// Convert tx args to msg to apply state transition
		txArgs := ethapi.TransactionArgs{
			From:                 &callMsg.From,
			To:                   &callMsg.To,
			Gas:                  (*hexutil.Uint64)(&callMsg.Gas),
			GasPrice:             (*hexutil.Big)(callMsg.GasPrice),
			MaxFeePerGas:         (*hexutil.Big)(callMsg.MaxFeePerGas),
			MaxPriorityFeePerGas: (*hexutil.Big)(callMsg.MaxPriorityFeePerGas),
			Value:                (*hexutil.Big)(callMsg.Value),
			Nonce:                (*hexutil.Uint64)(&callMsg.Nonce),
			Data:                 &callMsg.Data,
			AccessList:           &callMsg.AccessList,
		}
		msg, err := txArgs.ToMessage(globalGasCap, header.BaseFee)
		if err != nil {
			return nil, err
		}

		// Prepare the hashes
		txContext := core.NewEVMTxContext(msg)

		// Get EVM Environment
		vmenv := vm.NewEVM(blockContext, txContext, state, s.b.ChainConfig(), vm.Config{NoBaseFee: true})

		// Apply state transition
		execResult, execErr := core.ApplyMessage(vmenv, msg, gp)

		// Modifications are committed to the state
		// Only delete empty objects if EIP158/161 (a.k.a Spurious Dragon) is in effect
		state.Finalise(vmenv.ChainConfig().IsEIP158(blockNumber))

		txResult := CallTxResult{
			Logs: state.GetLogs(randomHash, header.Number.Uint64(), header.Hash()),
		}
		if execErr != nil {
			txResult.Error = execErr.Error()
		}
		if execResult != nil {
			revertData := execResult.Revert()
			if len(revertData) > 0 {
				reason, errUnpack := abi.UnpackRevert(execResult.Revert())
				if errUnpack != nil {
					txResult.Error = "execution reverted"
				} else {
					txResult.Error = fmt.Sprintf("execution reverted: %v", reason)
				}
			}
			txResult.GasUsed = execResult.UsedGas
			result.TotalGasUsed += execResult.UsedGas
			txResult.ReturnData = execResult.ReturnData
		}

		result.Results = append(result.Results, txResult)
	}

	return result, nil
}
