// Copyright 2025 The Kaia Authors
// This file is part of the Kaia library.
//
// The Kaia library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The Kaia library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the Kaia library. If not, see <http://www.gnu.org/licenses/>.

package tests

import (
	"errors"
	"math/big"

	"github.com/kaiachain/kaia/blockchain/state"
	"github.com/kaiachain/kaia/blockchain/types"
	"github.com/kaiachain/kaia/blockchain/vm"
	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/common/math"
	"github.com/kaiachain/kaia/params"
	"github.com/kaiachain/kaia/storage/database"
)

// pre process functions

func useEthBlockGasLimit(evm *vm.EVM, gasLimit uint64) {
	// Change GasLimit to the one in the eth header
	evm.Context.GasLimit = gasLimit
}

func useEthIntrinsicGas(msg *types.Transaction, r params.Rules) {
	// When istanbul is enabled, instrinsic gas is different from eth, so enable IsPrague to make them equal
	if r.IsIstanbul {
		r.IsPrague = true
	}
	updatedIntrinsicGas, _ := types.IntrinsicGas(msg.Data(), msg.AccessList(), msg.AuthList(), msg.To() == nil, r)
	sender := msg.ValidatedSender()
	sigCopy := msg.RawSignatureValues()

	var (
		gasPrice  *big.Int
		gasFeeCap *big.Int
		gasTipCap *big.Int
	)

	switch msg.Type() {
	case types.TxTypeEthereumSetCode, types.TxTypeEthereumDynamicFee:
		gasFeeCap = msg.GasFeeCap()
		gasTipCap = msg.GasTipCap()
	case types.TxTypeEthereumAccessList, types.TxTypeLegacyTransaction:
		gasPrice = msg.GasPrice()
	default:
		panic("not ethereum transaction type")
	}

	// Replace msg intrinsic gas with eth intrinsic gas
	*msg = *types.NewMessage(sender, msg.To(), msg.Nonce(), msg.GetTxInternalData().GetAmount(), msg.Gas(), gasPrice, gasFeeCap, gasTipCap, msg.Data(), true, updatedIntrinsicGas, msg.AccessList(), r.ChainID, msg.AuthList())
	msg.SetSignature(sigCopy)
}

func useEthGasPrice(evm *vm.EVM, msg *types.Transaction, baseFee *big.Int) {
	evm.GasPrice, _ = calculateEthGasPrice(evm.ChainConfig().Rules(evm.Context.BlockNumber), msg.GasPrice(), baseFee, msg.GasFeeCap(), msg.GasTipCap())
}

func useEthOpCodeGas(evm *vm.EVM, r params.Rules) {
	if r.IsCancun {
		// EIP-1052 must be activated for backward compatibility on Kaia. But EIP-2929 is activated instead of it on Ethereum
		vm.ChangeGasCostForTest(&evm.Config.JumpTable, vm.EXTCODEHASH, params.WarmStorageReadCostEIP2929)
	}
}

// post process functions

func useEthMiningReward(statedb *state.StateDB, coinbase common.Address, tx *types.Transaction, baseFee *big.Int, usedGas uint64, rules params.Rules) {
	ethGasPrice, _ := calculateEthGasPrice(rules, tx.GasPrice(), baseFee, tx.GasFeeCap(), tx.GasTipCap())
	ethReward := calculateEthMiningReward(ethGasPrice, tx.GasFeeCap(), tx.GasTipCap(), baseFee, usedGas, rules)
	statedb.AddBalance(coinbase, ethReward)
}

func useEthGenesisState(statedb *state.StateDB) (common.Hash, error) {
	return useEthStateRootWithOption(statedb, false)
}

func useEthState(statedb *state.StateDB) (common.Hash, error) {
	return useEthStateRootWithOption(statedb, true)
}

// helper functions

func calculateEthGasPrice(r params.Rules, envGasPrice, envBaseFee, envMaxFeePerGas, envMaxPriorityFeePerGas *big.Int) (*big.Int, error) {
	// https://github.com/ethereum/go-ethereum/blob/v1.14.11/tests/state_test_util.go#L241-L249
	var baseFee *big.Int
	if r.IsLondon {
		baseFee = envBaseFee
		if baseFee == nil {
			// Retesteth uses `0x10` for genesis baseFee. Therefore, it defaults to
			// parent - 2 : 0xa as the basefee for 'this' context.
			baseFee = big.NewInt(0x0a)
		}
	}

	// https://github.com/ethereum/go-ethereum/blob/v1.14.11/tests/state_test_util.go#L402-L416
	gasPrice := envGasPrice
	if baseFee != nil {
		gasPrice = math.BigMin(new(big.Int).Add(envMaxPriorityFeePerGas, baseFee), envMaxFeePerGas)
	}

	if gasPrice == nil {
		return nil, errors.New("no gas price provided")
	}

	return gasPrice, nil
}

func calculateEthMiningReward(gasPrice, maxFeePerGas, maxPriorityFeePerGas, envBaseFee *big.Int, usedGas uint64, rules params.Rules) *big.Int {
	effectiveTip := new(big.Int).Set(gasPrice)

	// https://github.com/ethereum/go-ethereum/blob/v1.14.11/tests/state_test_util.go#L241-L249
	// https://github.com/ethereum/go-ethereum/blob/v1.14.11/core/state_transition.go#L462-L465
	if rules.IsLondon {
		baseFee := new(big.Int).Set(envBaseFee)
		if baseFee == nil {
			// Retesteth uses `0x10` for genesis baseFee. Therefore, it defaults to
			// parent - 2 : 0xa as the basefee for 'this' context.
			baseFee = big.NewInt(0x0a)
		}
		effectiveTip = math.BigMin(maxPriorityFeePerGas, new(big.Int).Sub(maxFeePerGas, baseFee))
	}

	fee := new(big.Int).SetUint64(usedGas)
	return fee.Mul(fee, effectiveTip)
}

func useEthStateRootWithOption(statedb *state.StateDB, deleteEmptyObjects bool) (common.Hash, error) {
	memDb := database.NewMemoryDBManager()
	db := state.NewDatabase(memDb)
	newState, _ := state.New(common.Hash{}, db, nil, nil)

	for addr, acc := range statedb.RawDump().Accounts {
		b, ok := new(big.Int).SetString(acc.Balance, 10)
		if !ok {
			return common.Hash{}, errors.New("balance is not decimal")
		}
		newState.SetLegacyAccountForTest(
			common.HexToAddress(addr),
			acc.Nonce,
			b,
			common.HexToHash(acc.Root),
			common.HexToHash(acc.CodeHash).Bytes(),
		)
	}

	return newState.IntermediateRoot(deleteEmptyObjects), nil
}
