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

package impl

import (
	"math/big"
	"testing"

	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/crypto"
	gasless_cfg "github.com/kaiachain/kaia/kaiax/gasless/config"
	"github.com/kaiachain/kaia/params"
	"github.com/stretchr/testify/require"
)

func TestInit(t *testing.T) {
	key, _ := crypto.GenerateKey()
	tcs := []struct {
		opts     *InitOpts
		disabled bool
		err      error
	}{
		{
			&InitOpts{
				testChainConfig,
				key,
				&testTxPool{},
			},
			false,
			nil,
		},
		{
			nil,
			true,
			ErrInitUnexpectedNil,
		},
		{
			&InitOpts{
				nil,
				key,
				&testTxPool{},
			},
			true,
			ErrInitUnexpectedNil,
		},
		{
			&InitOpts{
				testChainConfig,
				nil,
				&testTxPool{},
			},
			true,
			ErrInitUnexpectedNil,
		},
		{
			&InitOpts{
				testChainConfig,
				key,
				nil,
			},
			true,
			ErrInitUnexpectedNil,
		},
		{
			&InitOpts{
				&params.ChainConfig{
					ChainID: big.NewInt(1),
					Gasless: nil,
				},
				key,
				&testTxPool{},
			},
			true,
			ErrInitUnexpectedNil,
		},
		{
			&InitOpts{
				&params.ChainConfig{
					ChainID: big.NewInt(1),
					Gasless: nil,
				},
				key,
				&testTxPool{},
			},
			true,
			ErrInitUnexpectedNil,
		},
		{
			&InitOpts{
				&params.ChainConfig{
					ChainID: big.NewInt(1),
					Gasless: &gasless_cfg.ChainConfig{
						SwapRouters:   []common.Address{common.HexToAddress("0x1234")},
						AllowedTokens: []common.Address{common.HexToAddress("0xabcd")},
						IsDisabled:    true,
					},
				},
				key,
				&testTxPool{},
			},
			true,
			nil,
		},
	}

	for _, tc := range tcs {
		g := NewGaslessModule()
		disabled, err := g.Init(tc.opts)
		require.Equal(t, tc.disabled, disabled)
		require.ErrorIs(t, tc.err, err)
	}
}
