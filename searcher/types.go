package searcher

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
	"math/big"
)

type OverrideAccount struct {
	Nonce     *uint64                      `json:"nonce,omitempty"`
	Code      *hexutil.Bytes               `json:"code,omitempty"`
	Balance   *big.Int                     `json:"balance,omitempty"`
	State     *map[common.Hash]common.Hash `json:"state,omitempty"`
	StateDiff *map[common.Hash]common.Hash `json:"stateDiff,omitempty"`
}

type StateOverride map[common.Address]OverrideAccount

// Apply overrides the fields of specified accounts into the given state.
func (diff *StateOverride) Apply(state *state.StateDB) error {
	if diff == nil {
		return nil
	}
	for addr, account := range *diff {
		// Override account nonce.
		if account.Nonce != nil {
			state.SetNonce(addr, *account.Nonce)
		}
		// Override account(contract) code.
		if account.Code != nil {
			state.SetCode(addr, *account.Code)
		}
		// Override account balance.
		if account.Balance != nil {
			state.SetBalance(addr, account.Balance)
		}
		if account.State != nil && account.StateDiff != nil {
			return fmt.Errorf("account %s has both 'state' and 'stateDiff'", addr.Hex())
		}
		// Replace entire state if caller requires.
		if account.State != nil {
			state.SetStorage(addr, *account.State)
		}
		// Apply state diff into specified accounts.
		if account.StateDiff != nil {
			for key, value := range *account.StateDiff {
				state.SetState(addr, key, value)
			}
		}
	}
	// Now finalize the changes. Finalize is normally performed between transactions.
	// By using finalize, the overrides are semantically behaving as
	// if they were created in a transaction just before the tracing occur.
	state.Finalise(false)
	return nil
}

type BlockOverrides struct {
	Number     *big.Int        `json:"number,omitempty"`
	Difficulty *big.Int        `json:"difficulty,omitempty"`
	Time       *uint64         `json:"time,omitempty"`
	GasLimit   *uint64         `json:"gasLimit,omitempty"`
	Coinbase   *common.Address `json:"coinbase,omitempty"`
	Random     *common.Hash    `json:"random,omitempty"`
	BaseFee    *big.Int        `json:"baseFee,omitempty"`
}

// Apply overrides the given header fields into the given block context.
func (diff *BlockOverrides) Apply(header *types.Header) {
	if diff == nil {
		return
	}
	if diff.Number != nil {
		header.Number = diff.Number
	}
	if diff.Difficulty != nil {
		header.Difficulty = diff.Difficulty
	}
	if diff.Time != nil {
		header.Time = *diff.Time
	}
	if diff.GasLimit != nil {
		header.GasLimit = *diff.GasLimit
	}
	if diff.Coinbase != nil {
		header.Coinbase = *diff.Coinbase
	}
	if diff.BaseFee != nil {
		header.BaseFee = diff.BaseFee
	}
}

type CallMsg struct {
	From      common.Address `json:"from,omitempty"`
	To        common.Address `json:"to,omitempty"`
	Gas       uint64         `json:"gas,omitempty"`
	GasPrice  *big.Int       `json:"gasPrice,omitempty"`
	GasFeeCap *big.Int       `json:"gasFeeCap,omitempty"`
	GasTipCap *big.Int       `json:"gasTipCap,omitempty"`
	Value     *big.Int       `json:"value,omitempty"`
	Nonce     uint64         `json:"nonce,omitempty"` // transaction returned nonce
	Data      hexutil.Bytes  `json:"data,omitempty"`

	// Introduced by AccessListTxType transaction.
	AccessList types.AccessList `json:"accessList,omitempty"`
}

type CallBundleArgs struct {
	Txs                    []hexutil.Bytes       `json:"txs,omitempty"`
	StateBlockNumberOrHash rpc.BlockNumberOrHash `json:"stateBlockNumber,omitempty"`
	Timeout                *int64                `json:"timeout,omitempty"`
	BlockOverrides         *BlockOverrides       `json:"blockOverrides,omitempty"`
	StateOverrides         *StateOverride        `json:"stateOverrides,omitempty"`
}

type CallBundleResult struct {
	BundleGasPrice    *big.Int             `json:"bundleGasPrice,omitempty"`
	BundleHash        common.Hash          `json:"bundleHash,omitempty"`
	CoinbaseDiff      *big.Int             `json:"coinbaseDiff,omitempty"`
	GasFees           *big.Int             `json:"gasFees,omitempty"`
	EthSentToCoinbase *big.Int             `json:"ethSentToCoinbase,omitempty"`
	StateBlockNumber  int64                `json:"stateBlockNumber,omitempty"`
	TotalGasUsed      uint64               `json:"totalGasUsed,omitempty"`
	Results           []CallBundleTxResult `json:"results,omitempty"`
}

type CallBundleTxResult struct {
	TxHash            common.Hash   `json:"txHash,omitempty"`
	GasUsed           uint64        `json:"gasUsed,omitempty"`
	Error             string        `json:"error,omitempty"`
	ReturnData        hexutil.Bytes `json:"returnData,omitempty"`
	Logs              []*types.Log  `json:"logs,omitempty"`
	CoinbaseDiff      *big.Int      `json:"coinbaseDiff,omitempty"`
	GasFees           *big.Int      `json:"gasFees,omitempty"`
	EthSentToCoinbase *big.Int      `json:"ethSentToCoinbase,omitempty"`
	GasPrice          *big.Int      `json:"gasPrice,omitempty"`
	CallMsg           *CallMsg      `json:"callMsg,omitempty"`
}

type CallArgs struct {
	Txs                    []CallMsg             `json:"txs,omitempty"`
	StateBlockNumberOrHash rpc.BlockNumberOrHash `json:"stateBlockNumber,omitempty"`
	Timeout                *int64                `json:"timeout,omitempty"`
	BlockOverrides         *BlockOverrides       `json:"blockOverrides,omitempty"`
	StateOverrides         *StateOverride        `json:"stateOverrides,omitempty"`
}

type CallResult struct {
	StateBlockNumber int64          `json:"stateBlockNumber,omitempty"`
	TotalGasUsed     uint64         `json:"totalGasUsed,omitempty"`
	Results          []CallTxResult `json:"results,omitempty"`
}

type CallTxResult struct {
	GasUsed    uint64        `json:"gasUsed,omitempty"`
	Error      string        `json:"error,omitempty"`
	ReturnData hexutil.Bytes `json:"returnData,omitempty"`
	Logs       []*types.Log  `json:"logs,omitempty"`
}
