package searcher

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/rpc"
	"math/big"
)

type OverrideAccount ethapi.OverrideAccount

type StateOverride map[common.Address]OverrideAccount

type BlockOverrides ethapi.BlockOverrides

type CallMsg struct {
	From                 common.Address `json:"from,omitempty"`
	To                   common.Address `json:"to,omitempty"`
	Gas                  uint64         `json:"gas,omitempty"`
	GasPrice             *big.Int       `json:"gasPrice,omitempty"`
	MaxFeePerGas         *big.Int       `json:"maxFeePerGas,omitempty"`
	MaxPriorityFeePerGas *big.Int       `json:"maxPriorityFeePerGas,omitempty"`
	Value                *big.Int       `json:"value,omitempty"`
	Nonce                uint64         `json:"nonce,omitempty"`
	Data                 hexutil.Bytes  `json:"data,omitempty"`

	// Introduced by AccessListTxType transaction.
	AccessList types.AccessList `json:"accessList,omitempty"`
}

type CallBundleArgs struct {
	Txs                    []hexutil.Bytes       `json:"txs,omitempty"`
	BlockNumber            rpc.BlockNumber       `json:"blockNumber,omitempty"`
	StateBlockNumberOrHash rpc.BlockNumberOrHash `json:"stateBlockNumber,omitempty"`
	Coinbase               *common.Address       `json:"coinbase,omitempty"`
	Timestamp              *uint64               `json:"timestamp,omitempty"`
	Timeout                *int64                `json:"timeout,omitempty"`
	GasLimit               *uint64               `json:"gasLimit,omitempty"`
	Difficulty             *big.Int              `json:"difficulty,omitempty"`
	BaseFee                *big.Int              `json:"baseFee,omitempty"`
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
	BlockNumber            rpc.BlockNumber       `json:"blockNumber,omitempty"`
	StateBlockNumberOrHash rpc.BlockNumberOrHash `json:"stateBlockNumber,omitempty"`
	Coinbase               *common.Address       `json:"coinbase,omitempty"`
	Timestamp              *uint64               `json:"timestamp,omitempty"`
	Timeout                *int64                `json:"timeout,omitempty"`
	StateOverrides         *StateOverride        `json:"stateOverrides,omitempty"`
	BlockOverrides         *BlockOverrides       `json:"blockOverrides,omitempty"`
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
