package searcher

import (
	"errors"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/holiman/uint256"
	"math/big"
)

func (f *CallFrame) processOutput(output []byte, err error) {
	output = common.CopyBytes(output)
	if err == nil {
		f.Output = output
		return
	}
	f.Error = err.Error()
	if !errors.Is(err, vm.ErrExecutionReverted) || len(output) == 0 {
		return
	}
	f.Output = output
	if len(output) < 4 {
		return
	}
	if unpacked, err := abi.UnpackRevert(output); err == nil {
		f.RevertReason = unpacked
	}
}

// accessList is an accumulator for the set of accounts and storage slots an EVM
// contract execution touches.
type accessList map[common.Address]accessListSlots

// accessListSlots is an accumulator for the set of storage slots within a single
// contract that an EVM contract execution touches.
type accessListSlots map[common.Hash]struct{}

// newAccessList creates a new accessList.
func newAccessList() accessList {
	return make(map[common.Address]accessListSlots)
}

// addAddress adds an address to the accesslist.
func (al accessList) addAddress(address common.Address) {
	// Set address if not previously present
	if _, present := al[address]; !present {
		al[address] = make(map[common.Hash]struct{})
	}
}

// addSlot adds a storage slot to the accesslist.
func (al accessList) addSlot(address common.Address, slot common.Hash) {
	// Set address if not previously present
	al.addAddress(address)

	// Set the slot on the surely existent storage set
	al[address][slot] = struct{}{}
}

// accesslist converts the accesslist to a types.AccessList.
func (al accessList) accessList() types.AccessList {
	acl := make(types.AccessList, 0, len(al))
	for addr, slots := range al {
		tuple := types.AccessTuple{Address: addr, StorageKeys: []common.Hash{}}
		for slot := range slots {
			tuple.StorageKeys = append(tuple.StorageKeys, slot)
		}
		acl = append(acl, tuple)
	}
	return acl
}

type Tracer struct {
	config    TracerConfig
	env       *tracing.VMContext
	callstack []*CallFrame
	gasLimit  uint64
	list      accessList // Set of accounts and storage slots touched
	ops       []Operation
}

type TracerConfig struct {
	WithCall           bool                        `json:"withCall,omitempty"`
	WithLog            bool                        `json:"withLog,omitempty"`
	WithAccessList     bool                        `json:"withAccessList,omitempty"`
	AccessListExcludes map[common.Address]struct{} `json:"accessListExcludes,omitempty"`
	WithOpcode         bool                        `json:"withOpcode,omitempty"`
	WithMemory         bool                        `json:"withMemory,omitempty"`
	WithStack          bool                        `json:"withStack,omitempty"`
}

type Operation struct {
	PC            uint64                      `json:"pc"`
	Op            string                      `json:"op"`
	Gas           uint64                      `json:"gas"`
	GasCost       uint64                      `json:"gasCost,omitempty"`
	Memory        []byte                      `json:"memory,omitempty"`
	Stack         []uint256.Int               `json:"stack,omitempty"`
	ReturnData    []byte                      `json:"returnData,omitempty"`
	Storage       map[common.Hash]common.Hash `json:"storage,omitempty"`
	Depth         int                         `json:"depth,omitempty"`
	RefundCounter uint64                      `json:"refund,omitempty"`
	Error         string                      `json:"error,omitempty"`
}

// NewCombinedTracer returns a native go tracer which tracks
// call frames of a tx, and implements vm.EVMLogger.
func NewCombinedTracer(config TracerConfig) *Tracer {
	// First callframe contains tx context info
	// and is populated on start and end.
	tracer := &Tracer{
		config:    config,
		callstack: []*CallFrame{{}},
	}
	if config.WithAccessList {
		tracer.list = newAccessList()
	}
	return tracer
}

func (t *Tracer) Hooks() *tracing.Hooks {
	h := new(tracing.Hooks)
	if t.config.WithCall {
		h.OnTxStart = t.OnTxStart
		h.OnTxEnd = t.OnTxEnd
		h.OnEnter = t.OnEnter
		h.OnExit = t.OnExit
		if t.config.WithLog {
			h.OnLog = t.OnLog
		}
	}
	if t.config.WithAccessList {
		h.OnEnter = t.OnEnter
		h.OnExit = t.OnExit
	}
	if t.config.WithOpcode {
		h.OnTxStart = t.OnTxStart
		h.OnTxEnd = t.OnTxEnd
	}
	return h
}

func (t *Tracer) OnTxStart(env *tracing.VMContext, tx *types.Transaction, from common.Address) {
	t.gasLimit = tx.Gas()
}

func (t *Tracer) OnTxEnd(receipt *types.Receipt, err error) {
	if err != nil {
		return
	}
	if t.config.WithCall {
		t.callstack[0].GasUsed = receipt.GasUsed
	}
}

// OnEnter is called when EVM enters a new scope (via call, create or selfdestruct).
func (t *Tracer) OnEnter(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	if depth == 0 {
		t.callstack[0] = &CallFrame{
			Type:  CallType(vm.OpCode(typ).String()),
			From:  from,
			To:    to,
			Value: value,
			Gas:   t.gasLimit,
			Input: common.CopyBytes(input),
		}
	} else {
		t.callstack = append(t.callstack, &CallFrame{
			Type:  CallType(vm.OpCode(typ).String()),
			From:  from,
			To:    to,
			Value: value,
			Gas:   gas,
			Input: common.CopyBytes(input),
		})
	}
}

func (t *Tracer) OnExit(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
	if depth == 0 {
		// capture end
		if len(t.callstack) != 1 {
			return
		}
		t.callstack[0].GasUsed = gasUsed
		t.callstack[0].processOutput(output, err)
		return
	}

	size := len(t.callstack)
	if size <= 1 {
		return
	}
	// Pop call.
	call := t.callstack[size-1]
	t.callstack = t.callstack[:size-1]
	size -= 1

	call.GasUsed = gasUsed
	call.processOutput(output, err)
	// Nest call into parent.
	t.callstack[size-1].Calls = append(t.callstack[size-1].Calls, call)
}

// OnOpcode logs a new structured log message and pushes it out to the environment
// also tracks SLOAD/SSTORE ops to track storage change.
func (t *Tracer) OnOpcode(pc uint64, opcode byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {

	op := vm.OpCode(opcode)
	stack := scope.StackData()
	stackLen := len(scope.StackData())

	if t.config.WithOpcode {
		// Copy a snapshot of the current memory state to a new buffer
		var mem []byte
		memory := scope.MemoryData()
		if t.config.WithMemory {
			mem = make([]byte, len(memory))
			copy(mem, memory)
		}
		// Copy a snapshot of the current stack state to a new buffer
		var stck []uint256.Int
		if t.config.WithStack {
			stck = make([]uint256.Int, stackLen)
			copy(stck, stack)
		}

		// Copy a snapshot of the current storage to a new container
		var storage map[common.Hash]common.Hash
		if op == vm.SLOAD || op == vm.SSTORE {
			// capture SLOAD opcodes and record the read entry in the local storage
			if op == vm.SLOAD && stackLen >= 1 {
				slot := common.Hash(stack[stackLen-1].Bytes32())
				value := t.env.StateDB.GetState(scope.Address(), slot)
				storage = map[common.Hash]common.Hash{
					slot: value,
				}
			} else if op == vm.SSTORE && stackLen >= 2 {
				// capture SSTORE opcodes and record the written entry in the local storage.
				slot := common.Hash(stack[stackLen-1].Bytes32())
				value := common.Hash(stack[stackLen-2].Bytes32())
				storage = map[common.Hash]common.Hash{
					slot: value,
				}
			}
		}

		var rdata []byte
		rdata = make([]byte, len(rData))
		copy(rdata, rData)

		var errString string
		if err != nil {
			errString = err.Error()
		}

		// create a new snapshot of the EVM.
		t.ops = append(t.ops, Operation{
			PC:            pc,
			Op:            op.String(),
			Gas:           gas,
			GasCost:       cost,
			Memory:        mem,
			Stack:         stck,
			ReturnData:    rdata,
			Storage:       storage,
			Depth:         depth,
			RefundCounter: t.env.StateDB.GetRefund(),
			Error:         errString,
		})
	}

	if t.config.WithAccessList {
		if op == vm.SLOAD || op == vm.SSTORE {
			if stackLen >= 1 {
				addr := scope.Address()
				if _, ok := t.config.AccessListExcludes[addr]; !ok {
					slot := common.Hash(stack[stackLen-1].Bytes32())
					t.list.addSlot(addr, slot)
				}
			}
		} else if op == vm.BALANCE || op == vm.EXTCODESIZE || op == vm.EXTCODECOPY || op == vm.EXTCODEHASH || op == vm.SELFDESTRUCT {
			if stackLen >= 1 {
				addr := common.Address(stack[stackLen-1].Bytes20())
				if _, ok := t.config.AccessListExcludes[addr]; !ok {
					t.list.addAddress(addr)
				}
			}
		} else if op == vm.CALL || op == vm.STATICCALL || op == vm.DELEGATECALL || op == vm.CALLCODE {
			if stackLen >= 5 {
				addr := common.Address(stack[stackLen-2].Bytes20())
				if _, ok := t.config.AccessListExcludes[addr]; !ok {
					t.list.addAddress(addr)
				}
			}
		}
	}
}

func (t *Tracer) OnLog(log *types.Log) {
	l := &CallLog{
		Address:  log.Address,
		Topics:   log.Topics,
		Data:     log.Data,
		Position: len(t.callstack[len(t.callstack)-1].Calls),
	}
	t.callstack[len(t.callstack)-1].Logs = append(t.callstack[len(t.callstack)-1].Logs, l)
}

func (t *Tracer) CallFrame() *CallFrame {
	return t.callstack[0]
}

// AccessList returns the current accesslist maintained by the tracer.
func (t *Tracer) AccessList() types.AccessList {
	return t.list.accessList()
}

func (t *Tracer) Operations() []Operation {
	return t.ops
}
