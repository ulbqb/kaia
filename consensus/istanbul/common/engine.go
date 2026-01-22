package common

import (
	"encoding/hex"
	"math/big"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/consensus/istanbul"
)

var (
	defaultBlockScore = big.NewInt(1)
	now               = time.Now

	inmemoryBlocks             = 2048 // Number of blocks to precompute validators' addresses
	inmemoryValidatorsPerBlock = 30   // Approximate number of validators' addresses from ecrecover
	signatureAddresses, _      = lru.NewARC(inmemoryBlocks * inmemoryValidatorsPerBlock)
)

// cacheSignatureAddresses extracts the address from the given data and signature and cache them for later usage.
func CacheSignatureAddresses(data []byte, sig []byte) (common.Address, error) {
	sigStr := hex.EncodeToString(sig)
	if addr, ok := signatureAddresses.Get(sigStr); ok {
		return addr.(common.Address), nil
	}
	addr, err := istanbul.GetSignatureAddress(data, sig)
	if err != nil {
		return common.Address{}, err
	}
	signatureAddresses.Add(sigStr, addr)
	return addr, err
}
