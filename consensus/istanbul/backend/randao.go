// Copyright 2024 The Kaia Authors
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
package backend

import (
	"math/big"

	"github.com/kaiachain/kaia/common/hexutil"
	istanbulCommon "github.com/kaiachain/kaia/consensus/istanbul/common"
	"github.com/kaiachain/kaia/crypto/bls"
)

// Calculate KIP-114 Randao header fields
// https://github.com/klaytn/kips/blob/kip114/KIPs/kip-114.md
func (sb *backend) CalcRandao(number *big.Int, prevMixHash []byte) ([]byte, []byte, error) {
	if sb.blsSecretKey == nil {
		return nil, nil, errNoBlsKey
	}
	if len(prevMixHash) != 32 {
		logger.Error("invalid prevMixHash", "number", number.Uint64(), "prevMixHash", hexutil.Encode(prevMixHash))
		return nil, nil, errInvalidRandaoFields
	}

	// block_num_to_bytes() = num.to_bytes(32, byteorder="big")
	msg := istanbulCommon.CalcRandaoMsg(number)

	// calc_random_reveal() = sign(privateKey, headerNumber)
	randomReveal := bls.Sign(sb.blsSecretKey, msg[:]).Marshal()

	// calc_mix_hash() = xor(prevMixHash, keccak256(randomReveal))
	mixHash := istanbulCommon.CalcMixHash(randomReveal, prevMixHash)

	return randomReveal, mixHash, nil
}
