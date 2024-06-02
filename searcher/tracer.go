package searcher

import (
	"errors"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"math/big"
)

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
	config       TracerConfig
	env          *tracing.VMContext
	rootFrame    *Frame
	currentFrame *Frame
	gasLimit     uint64
	list         accessList // Set of accounts and storage slots touched
}

type TracerConfig struct {
	WithFrame          bool                        `json:"withFrame,omitempty"`
	WithStorage        bool                        `json:"withStorage,omitempty"`
	WithAccessList     bool                        `json:"withAccessList,omitempty"`
	AccessListExcludes map[common.Address]struct{} `json:"accessListExcludes,omitempty"`
}

// NewTracer returns a native go tracer which tracks
// call frames of a tx, and implements vm.EVMLogger.
func NewTracer(config TracerConfig) *Tracer {
	// First call frame contains tx context info
	// and is populated on start and end.
	tracer := &Tracer{
		config: config,
	}
	if config.WithAccessList {
		tracer.list = newAccessList()
	}
	return tracer
}

func (t *Tracer) Hooks() *tracing.Hooks {
	h := new(tracing.Hooks)
	if t.config.WithFrame {
		h.OnTxStart = t.OnTxStart
		h.OnTxEnd = t.OnTxEnd
		h.OnEnter = t.OnEnter
		h.OnExit = t.OnExit
		h.OnLog = t.OnLog
	}
	if t.config.WithStorage || t.config.WithAccessList {
		h.OnOpcode = t.OnOpcode
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
	if t.rootFrame != nil {
		call, ok := t.rootFrame.Value.(*FrameCall)
		if ok && call != nil {
			call.GasUsed = receipt.GasUsed
		}
	}
}

// OnEnter is called when EVM enters a new scope (via call, create or selfdestruct).
func (t *Tracer) OnEnter(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	if value != nil && value.Sign() == 0 {
		value = nil
	}
	if depth == 0 {
		t.rootFrame = &Frame{
			Opcode: vm.OpCode(typ),
			Value: &FrameCall{
				From:  from,
				To:    to,
				Value: value,
				Gas:   t.gasLimit,
				Input: common.CopyBytes(input),
			},
		}
		t.currentFrame = t.rootFrame
	} else {
		sub := &Frame{
			Opcode: vm.OpCode(typ),
			Value: &FrameCall{
				From:  from,
				To:    to,
				Value: value,
				Gas:   gas,
				Input: common.CopyBytes(input),
			},
			Parent: t.currentFrame,
		}
		t.currentFrame.Subs = append(t.currentFrame.Subs, sub)
		t.currentFrame = sub
	}
}

func (f *Frame) processOutput(gasUsed uint64, output []byte, err error) {
	call := f.Value.(*FrameCall)
	call.GasUsed = gasUsed
	output = common.CopyBytes(output)
	call.Output = output
	if err == nil {
		return
	}
	call.Error = err.Error()
	if !errors.Is(err, vm.ErrExecutionReverted) || len(output) < 4 {
		return
	}
	if unpacked, err := abi.UnpackRevert(output); err == nil {
		call.RevertReason = unpacked
	}
}

func (t *Tracer) OnExit(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
	if t.currentFrame == nil {
		return
	}
	t.currentFrame.processOutput(gasUsed, output, err)
	t.currentFrame = t.currentFrame.Parent
}

// OnOpcode logs a new structured log message and pushes it out to the environment
// also tracks SLOAD/SSTORE ops to track storage change.
func (t *Tracer) OnOpcode(pc uint64, opcode byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
	if err != nil {
		return
	}
	op := vm.OpCode(opcode)
	stack := scope.StackData()
	stackLen := len(scope.StackData())
	switch op {
	case vm.SLOAD:
		if stackLen < 1 {
			return
		}
		if t.config.WithStorage {
			slot := common.Hash(stack[stackLen-1].Bytes32())
			value := t.env.StateDB.GetState(scope.Address(), slot)
			t.currentFrame.Subs = append(t.currentFrame.Subs, &Frame{
				Opcode: op,
				Value: &FrameStorage{
					Key:   slot,
					Value: value,
				},
			})
		}
		if t.config.WithAccessList {
			addr := scope.Address()
			if _, ok := t.config.AccessListExcludes[addr]; !ok {
				slot := common.Hash(stack[stackLen-1].Bytes32())
				t.list.addSlot(addr, slot)
			}
		}
	case vm.SSTORE:
		if stackLen < 2 {
			return
		}
		if t.config.WithStorage {
			slot := common.Hash(stack[stackLen-1].Bytes32())
			value := common.Hash(stack[stackLen-2].Bytes32())
			t.currentFrame.Subs = append(t.currentFrame.Subs, &Frame{
				Opcode: op,
				Value: &FrameStorage{
					Key:   slot,
					Value: value,
				},
			})
		}
		if t.config.WithAccessList {
			addr := scope.Address()
			if _, ok := t.config.AccessListExcludes[addr]; !ok {
				slot := common.Hash(stack[stackLen-1].Bytes32())
				t.list.addSlot(addr, slot)
			}
		}
	case vm.TLOAD:
		if stackLen < 1 {
			return
		}
		if t.config.WithStorage {
			slot := common.Hash(stack[stackLen-1].Bytes32())
			value := t.env.StateDB.(vm.StateDB).GetTransientState(scope.Address(), slot)
			t.currentFrame.Subs = append(t.currentFrame.Subs, &Frame{
				Opcode: op,
				Value: &FrameStorage{
					Key:   slot,
					Value: value,
				},
			})
		}
	case vm.TSTORE:
		if stackLen < 2 {
			return
		}
		if t.config.WithStorage {
			slot := common.Hash(stack[stackLen-1].Bytes32())
			value := common.Hash(stack[stackLen-2].Bytes32())
			t.currentFrame.Subs = append(t.currentFrame.Subs, &Frame{
				Opcode: op,
				Value: &FrameStorage{
					Key:   slot,
					Value: value,
				},
			})
		}
	case vm.BALANCE, vm.EXTCODESIZE, vm.EXTCODECOPY, vm.EXTCODEHASH, vm.SELFDESTRUCT:
		if stackLen < 1 {
			return
		}
		if t.config.WithAccessList {
			addr := common.Address(stack[stackLen-1].Bytes20())
			if _, ok := t.config.AccessListExcludes[addr]; !ok {
				t.list.addAddress(addr)
			}
		}
	case vm.CALL, vm.STATICCALL, vm.DELEGATECALL, vm.CALLCODE:
		if stackLen < 5 {
			return
		}
		if t.config.WithAccessList {
			addr := common.Address(stack[stackLen-2].Bytes20())
			if _, ok := t.config.AccessListExcludes[addr]; !ok {
				t.list.addAddress(addr)
			}
		}
	}
}

func (t *Tracer) OnLog(log *types.Log) {
	t.currentFrame.Subs = append(t.currentFrame.Subs, &Frame{
		Opcode: vm.LOG0 + vm.OpCode(len(log.Topics)),
		Value: &FrameLog{
			Address: log.Address,
			Topics:  log.Topics,
			Data:    log.Data,
		},
	})
}

func (t *Tracer) Frame() *Frame {
	return t.rootFrame
}

// AccessList returns the current accesslist maintained by the tracer.
func (t *Tracer) AccessList() types.AccessList {
	return t.list.accessList()
}
