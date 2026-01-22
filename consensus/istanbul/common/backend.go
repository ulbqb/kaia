package common

import (
	"math/big"

	"github.com/kaiachain/kaia/blockchain/types"
	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/consensus"
	"github.com/kaiachain/kaia/crypto"
	"github.com/kaiachain/kaia/crypto/sha3"
	"github.com/kaiachain/kaia/params"
	"github.com/kaiachain/kaia/rlp"
)

// FIXME: Need to update this for Istanbul
// sigHash returns the hash which is used as input for the Istanbul
// signing. It is the hash of the entire header apart from the 65 byte signature
// contained at the end of the extra data.
//
// Note, the method requires the extra data to be at least 65 bytes, otherwise it
// panics. This is done to avoid accidentally using both forms (signature present
// or not), which could be abused to produce different hashes for the same header.
func SigHash(header *types.Header) (hash common.Hash) {
	hasher := sha3.NewKeccak256()

	// Clean seal is required for calculating proposer seal.
	rlp.Encode(hasher, types.IstanbulFilteredHeader(header, false))
	hasher.Sum(hash[:0])
	return hash
}

// At the fork block's parent, pretend that prevMixHash is ZeroMixHash.
func HeaderMixHash(chain consensus.ChainReader, header *types.Header) []byte {
	if chain.Config().IsRandaoForkBlockParent(header.Number) {
		return params.ZeroMixHash
	} else {
		return header.MixHash
	}
}

// ecrecover extracts the Kaia account address from a signed header.
func ECRecover(header *types.Header) (common.Address, error) {
	// Retrieve the signature from the header extra-data
	istanbulExtra, err := types.ExtractIstanbulExtra(header)
	if err != nil {
		return common.Address{}, err
	}
	addr, err := CacheSignatureAddresses(SigHash(header).Bytes(), istanbulExtra.Seal)
	if err != nil {
		return addr, err
	}

	return addr, nil
}

// block_num_to_bytes() = num.to_bytes(32, byteorder="big")
func CalcRandaoMsg(number *big.Int) common.Hash {
	return common.BytesToHash(number.Bytes())
}

// calc_mix_hash() = xor(prevMixHash, keccak256(randomReveal))
func CalcMixHash(randomReveal, prevMixHash []byte) []byte {
	mixHash := make([]byte, 32)
	revealHash := crypto.Keccak256(randomReveal)
	for i := 0; i < 32; i++ {
		mixHash[i] = prevMixHash[i] ^ revealHash[i]
	}
	return mixHash
}
