// Modifications Copyright 2024 The Kaia Authors
// Modifications Copyright 2018 The klaytn Authors
// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.
//
// This file is derived from miner/worker.go (2018/06/04).
// Modified and improved for the klaytn development.
// Modified and improved for the Kaia development.

package work

import (
	"math/big"
	"testing"

	"github.com/kaiachain/kaia/blockchain"
	"github.com/kaiachain/kaia/blockchain/types"
	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/crypto"
	"github.com/kaiachain/kaia/params"
	"github.com/stretchr/testify/require"
)

func TestFilterGaslessTransaction(t *testing.T) {
	proposerKey, err := crypto.HexToECDSA("bb047e5940b6d83354d9432db7c449ac8fca2248008aaa7271369880f9f11cc1")
	require.NoError(t, err)
	userKey, err := crypto.GenerateKey()
	userAddr := crypto.PubkeyToAddress(userKey.PublicKey)
	require.NoError(t, err)

	lendTx, err := types.SignTx(types.NewTransaction(0, userAddr, big.NewInt(100), 100000, big.NewInt(1), nil), types.LatestSignerForChainID(params.TestChainConfig.ChainID), proposerKey)
	require.NoError(t, err)

	approveTx, err := types.SignTx(types.NewTransaction(0, common.HexToAddress("0xAAAA"), big.NewInt(100), 100000, big.NewInt(1), nil), types.LatestSignerForChainID(params.TestChainConfig.ChainID), userKey)
	require.NoError(t, err)

	swapTx, err := types.SignTx(types.NewTransaction(1, common.HexToAddress("0xBBBB"), big.NewInt(100), 100000, big.NewInt(1), nil), types.LatestSignerForChainID(params.TestChainConfig.ChainID), userKey)
	require.NoError(t, err)

	pending := map[common.Address]types.Transactions{}
	pending[blockchain.ProposerAddr] = types.Transactions{lendTx}
	pending[userAddr] = types.Transactions{approveTx, swapTx}
	pending = filterGaslessTransaction(pending)
	require.Equal(t, 1, pending[blockchain.ProposerAddr].Len())
	require.Equal(t, 2, pending[userAddr].Len())

	pending = map[common.Address]types.Transactions{}
	pending[userAddr] = types.Transactions{approveTx, swapTx}
	pending = filterGaslessTransaction(pending)
	require.Equal(t, 0, pending[blockchain.ProposerAddr].Len())
	require.Equal(t, 0, pending[userAddr].Len())

	pending = map[common.Address]types.Transactions{}
	pending[blockchain.ProposerAddr] = types.Transactions{lendTx}
	pending[userAddr] = types.Transactions{swapTx}
	pending = filterGaslessTransaction(pending)
	require.Equal(t, 1, pending[blockchain.ProposerAddr].Len())
	require.Equal(t, 1, pending[userAddr].Len())

	pending = map[common.Address]types.Transactions{}
	pending[blockchain.ProposerAddr] = types.Transactions{lendTx}
	pending[userAddr] = types.Transactions{approveTx}
	pending = filterGaslessTransaction(pending)
	require.Equal(t, 0, pending[blockchain.ProposerAddr].Len())
	require.Equal(t, 0, pending[userAddr].Len())

	pending = map[common.Address]types.Transactions{}
	pending[blockchain.ProposerAddr] = types.Transactions{lendTx}
	pending = filterGaslessTransaction(pending)
	require.Equal(t, 0, pending[blockchain.ProposerAddr].Len())
	require.Equal(t, 0, pending[userAddr].Len())

	pending = map[common.Address]types.Transactions{}
	pending[userAddr] = types.Transactions{approveTx}
	pending = filterGaslessTransaction(pending)
	require.Equal(t, 0, pending[blockchain.ProposerAddr].Len())
	require.Equal(t, 0, pending[userAddr].Len())

	pending = map[common.Address]types.Transactions{}
	pending[userAddr] = types.Transactions{swapTx}
	pending = filterGaslessTransaction(pending)
	require.Equal(t, 0, pending[blockchain.ProposerAddr].Len())
	require.Equal(t, 0, pending[userAddr].Len())
}
