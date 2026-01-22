package interfaces

import (
	"github.com/kaiachain/kaia/blockchain/types"
	"github.com/kaiachain/kaia/consensus"
)

// NOTE: Use existing consensus.ChainReader instead of defining new ChainHeaderReader
type Verifier interface {
	// VerifyHeader validates header fields (common checks)
	VerifyHeader(chain consensus.ChainReader, header *types.Header) error

	// VerifySeals validates consensus proof
	// IBFT: verify CommittedSeals
	// HotStuff-2: verify QC
	VerifySeals(chain consensus.ChainReader, header *types.Header) error
}

// Implementations:
// - IBFTVerifier: IBFT committedSeals verifier
// - HotStuffVerifier: HotStuff QC verifier
