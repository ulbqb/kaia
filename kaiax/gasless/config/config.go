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

package config

import (
	"github.com/kaiachain/kaia/common"
	"github.com/urfave/cli/v2"
)

var (
	SwapRoutersFlag = &cli.StringSliceFlag{
		Name:    "gasless.swap-routers",
		Usage:   "swap router addresses for gasless module",
		Aliases: []string{"genesis.module.gasless.swap-routers"},
	}
	AllowedTokensFlag = &cli.StringSliceFlag{
		Name:    "gasless.allowed-tokens",
		Usage:   "allowed token addresses for gasless module",
		Aliases: []string{"genesis.module.gasless.allowed-tokens"},
	}
	DisableFlag = &cli.BoolFlag{
		Name:    "gasless.disable",
		Usage:   "disable gasless module",
		Value:   false,
		Aliases: []string{"genesis.module.gasless.disable"},
	}
)

type ChainConfig struct {
	SwapRouters   []common.Address `json:"swapRouters"`
	AllowedTokens []common.Address `json:"allowedTokens"`
	IsDisabled    bool             `json:"isDisabled"`
}

func GenGenesis(ctx *cli.Context) *ChainConfig {
	swapRouters := []common.Address{}
	for _, addr := range ctx.StringSlice(SwapRoutersFlag.Name) {
		swapRouters = append(swapRouters, common.HexToAddress(addr))
	}
	allowedTokens := []common.Address{}
	for _, addr := range ctx.StringSlice(AllowedTokensFlag.Name) {
		allowedTokens = append(allowedTokens, common.HexToAddress(addr))
	}
	return &ChainConfig{
		SwapRouters:   swapRouters,
		AllowedTokens: allowedTokens,
		IsDisabled:    ctx.Bool(DisableFlag.Name),
	}
}
