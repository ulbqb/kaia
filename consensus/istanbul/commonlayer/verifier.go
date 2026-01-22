package commonlayer

import (
	"bytes"
	"errors"
	"math/big"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/kaiachain/kaia/blockchain/types"
	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/consensus"
	"github.com/kaiachain/kaia/consensus/interfaces"
	"github.com/kaiachain/kaia/consensus/istanbul"
	istanbulCommon "github.com/kaiachain/kaia/consensus/istanbul/common"
	istanbulCore "github.com/kaiachain/kaia/consensus/istanbul/core"
	"github.com/kaiachain/kaia/consensus/misc"
	"github.com/kaiachain/kaia/consensus/misc/eip4844"
	"github.com/kaiachain/kaia/crypto/bls"
	"github.com/kaiachain/kaia/kaiax"
	"github.com/kaiachain/kaia/kaiax/gov"
	"github.com/kaiachain/kaia/kaiax/randao"
	"github.com/kaiachain/kaia/kaiax/valset"
)

var (
	inmemoryBlocks             = 2048 // Number of blocks to precompute validators' addresses
	inmemoryValidatorsPerBlock = 30   // Approximate number of validators' addresses from ecrecover
	signatureAddresses, _      = lru.NewARC(inmemoryBlocks * inmemoryValidatorsPerBlock)

	allowedFutureBlockTime = 1 * time.Second
	defaultBlockScore      = big.NewInt(1)
)

var _ interfaces.Verifier = &IstanbulVerifier{}

type IstanbulVerifier struct {
	config           *istanbul.Config
	consensusModules []kaiax.ConsensusModule
	govModule        gov.GovModule
	randaoModule     randao.RandaoModule
	valsetModule     valset.ValsetModule
}

// VerifyHeader checks whether a header conforms to the consensus rules of a
// given engine. Verifying the seal may be done optionally here, or explicitly
// via the VerifySeal method.
func (sb *IstanbulVerifier) VerifyHeader(chain consensus.ChainReader, header *types.Header) error {
	var parent []*types.Header
	if header.Number.Sign() == 0 {
		// If current block is genesis, the parent is also genesis
		parent = append(parent, chain.GetHeaderByNumber(0))
	} else {
		parent = append(parent, chain.GetHeader(header.ParentHash, header.Number.Uint64()-1))
	}
	return sb.verifyHeader(chain, header, parent)
}

// VerifySeal checks whether the crypto seal on a header is valid according to
// the consensus rules of the given engine.
func (sb *IstanbulVerifier) VerifySeals(chain consensus.ChainReader, header *types.Header) error {
	// get parent header and ensure the signer is in parent's validator set
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}

	// ensure that the blockscore equals to defaultBlockScore
	if header.BlockScore.Cmp(defaultBlockScore) != 0 {
		return errInvalidBlockScore
	}
	return sb.verifySigner(chain, header, nil)
}

// verifyHeader checks whether a header conforms to the consensus rules.The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
func (sb *IstanbulVerifier) verifyHeader(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	if header.Number == nil {
		return errUnknownBlock
	}

	// Header verify before/after magma fork
	if chain.Config().IsMagmaForkEnabled(header.Number) {
		if len(parents) > 0 {
			// the kip71Config used when creating the block number is a previous block config.
			blockNum := header.Number.Uint64()
			pset := sb.govModule.GetParamSet(blockNum)
			kip71 := pset.ToKip71Config()
			if err := misc.VerifyMagmaHeader(parents[len(parents)-1], header, kip71); err != nil {
				return err
			}
		}
		// For Magma fork, BaseFee is allowed even without parents (first header)
	} else if header.BaseFee != nil {
		return consensus.ErrInvalidBaseFee
	}

	// Don't waste time checking blocks from the future
	if header.Time.Cmp(big.NewInt(time.Now().Add(allowedFutureBlockTime).Unix())) > 0 {
		return consensus.ErrFutureBlock
	}

	// Ensure that the extra data format is satisfied
	if _, err := types.ExtractIstanbulExtra(header); err != nil {
		return errInvalidExtraDataFormat
	}
	// Ensure that the block's blockscore is meaningful (may not be correct at this point)
	if header.BlockScore == nil || header.BlockScore.Cmp(defaultBlockScore) != 0 {
		return errInvalidBlockScore
	}

	// TODO-kaiax: further flatten the code inside; especially after most of the checks are moved to consensus modules
	if err := sb.verifyCascadingFields(chain, header, parents); err != nil {
		return err
	}

	for _, module := range sb.consensusModules {
		if err := module.VerifyHeader(header); err != nil {
			return err
		}
	}

	return sb.verifyCommittedSeals(chain, header, nil)
}

// verifyCascadingFields verifies all the header fields that are not standalone,
// rather depend on a batch of previous headers. The caller may optionally pass
// in a batch of parents (ascending order) to avoid looking those up from the
// database. This is useful for concurrently verifying a batch of new headers.
func (sb *IstanbulVerifier) verifyCascadingFields(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	// The genesis block is the always valid dead-end
	number := header.Number.Uint64()
	if number == 0 {
		return nil
	}
	// Ensure that the block's timestamp isn't too close to it's parent
	var parent *types.Header
	if len(parents) > 0 {
		parent = parents[len(parents)-1]
	} else {
		parent = chain.GetHeader(header.ParentHash, number-1)
	}
	if parent == nil || parent.Number.Uint64() != number-1 || parent.Hash() != header.ParentHash {
		return consensus.ErrUnknownAncestor
	}
	if parent.Time.Uint64()+sb.config.BlockPeriod > header.Time.Uint64() {
		return errInvalidTimestamp
	}
	if err := sb.verifySigner(chain, header, parents); err != nil {
		return err
	}

	// VerifyRandao must be after verifySigner because it needs the signer (proposer) address
	if chain.Config().IsRandaoForkEnabled(header.Number) {
		prevMixHash := istanbulCommon.HeaderMixHash(chain, parent)
		if err := sb.VerifyRandao(chain, header, prevMixHash); err != nil {
			return err
		}
	} else if header.RandomReveal != nil || header.MixHash != nil {
		return errUnexpectedRandao
	}

	// Verify the existence / non-existence of osaka-specific header fields
	osaka := chain.Config().IsOsakaForkEnabled(header.Number)
	if !osaka {
		switch {
		case header.ExcessBlobGas != nil:
			return errUnexpectedExcessBlobGasBeforeOsaka
		case header.BlobGasUsed != nil:
			return errUnexpectedBlobGasUsedBeforeOsaka
		}
	} else {
		if err := eip4844.VerifyEIP4844Header(chain.Config(), parent, header); err != nil {
			return err
		}
	}

	return nil
}

func (sb *IstanbulVerifier) Author(header *types.Header) (common.Address, error) {
	return istanbulCommon.ECRecover(header)
}

func (sb *IstanbulVerifier) VerifyRandao(chain consensus.ChainReader, header *types.Header, prevMixHash []byte) error {
	if header.Number.Sign() == 0 {
		return nil // Do not verify genesis block
	}

	proposer, err := sb.Author(header)
	if err != nil {
		return err
	}

	// [proposerPubkey, proposerPop] = get_proposer_pubkey_pop()
	// if not pop_verify(proposerPubkey, proposerPop): return False
	proposerPub, err := sb.randaoModule.GetBlsPubkey(proposer, header.Number)
	if err != nil {
		return err
	}

	// if not verify(proposerPubkey, newHeader.number, newHeader.randomReveal): return False
	sig := header.RandomReveal
	msg := istanbulCommon.CalcRandaoMsg(header.Number)
	ok, err := bls.VerifySignature(sig, msg, proposerPub)
	if err != nil {
		return err
	} else if !ok {
		return errInvalidRandaoFields
	}

	// if not newHeader.mixHash == calc_mix_hash(prevMixHash, newHeader.randomReveal): return False
	mixHash := istanbulCommon.CalcMixHash(header.RandomReveal, prevMixHash)
	if !bytes.Equal(header.MixHash, mixHash) {
		return errInvalidRandaoFields
	}

	return nil
}

func (sb *IstanbulVerifier) verifyCommittedSeals(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	number := header.Number.Uint64()
	// We don't need to verify committed seals in the genesis block
	if number == 0 {
		return nil
	}

	// Retrieve the snapshot needed to verify this header and cache it
	valSet, err := sb.GetCommitteeStateByRound(number, uint64(header.Round()))
	if err != nil {
		return err
	}

	extra, err := types.ExtractIstanbulExtra(header)
	if err != nil {
		return err
	}
	// The length of Committed seals should be larger than 0
	if len(extra.CommittedSeal) == 0 {
		return errEmptyCommittedSeals
	}

	council := valSet.Council().Copy()
	// Check whether the committed seals are generated by parent's validators
	validSeal := 0
	proposalSeal := istanbulCore.PrepareCommittedSeal(header.Hash())
	// 1. Get committed seals from current header
	for _, seal := range extra.CommittedSeal {
		// 2. Get the original address by seal and parent block hash
		addr, err := istanbulCommon.CacheSignatureAddresses(proposalSeal, seal)
		if err != nil {
			return errInvalidSignature
		}
		// Every validator can have only one seal. If more than one seals are signed by a
		// validator, the validator cannot be found and errInvalidCommittedSeals is returned.
		if council.Remove(addr) {
			validSeal += 1
		} else {
			return errInvalidCommittedSeals
		}
	}

	// The length of validSeal should be larger than number of faulty node + 1
	if validSeal <= 2*valSet.F() {
		return errInvalidCommittedSeals
	}

	return nil
}

func (sb *IstanbulVerifier) GetCommitteeStateByRound(num uint64, round uint64) (*istanbul.RoundCommitteeState, error) {
	blockValSet, err := sb.GetValidatorSet(num)
	if err != nil {
		return nil, err
	}

	committee, err := sb.valsetModule.GetCommittee(num, round)
	if err != nil {
		return nil, err
	}

	proposer, err := sb.valsetModule.GetProposer(num, round)
	if err != nil {
		return nil, err
	}

	committeeSize := sb.govModule.GetParamSet(num).CommitteeSize
	return istanbul.NewRoundCommitteeState(blockValSet, committeeSize, committee, proposer), nil
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers
// concurrently. The method returns a quit channel to abort the operations and
// a results channel to retrieve the async verifications (the order is that of
// the input slice).
func (sb *IstanbulVerifier) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))
	go func() {
		errored := false
		for i, header := range headers {
			var err error
			if errored { // If errored once in the batch, skip the rest
				err = consensus.ErrUnknownAncestor
			} else {
				err = sb.verifyHeader(chain, header, headers[:i])
			}

			if err != nil {
				errored = true
			}

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// verifySigner checks whether the signer is in parent's validator set
func (sb *IstanbulVerifier) verifySigner(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {
	// Verifying the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return errUnknownBlock
	}

	// Retrieve the snapshot needed to verify this header and cache it
	valSet, err := sb.GetValidatorSet(number)
	if err != nil {
		return err
	}

	// resolve the authorization key and check against signers
	signer, err := istanbulCommon.ECRecover(header)
	if err != nil {
		return err
	}

	// Signer should be in the validator set of previous block's extraData.
	if !valSet.Qualified().Contains(signer) {
		return errUnauthorized
	}
	return nil
}

func (sb *IstanbulVerifier) GetValidatorSet(num uint64) (*istanbul.BlockValSet, error) {
	council, err := sb.valsetModule.GetCouncil(num)
	if err != nil {
		return nil, err
	}

	demoted, err := sb.valsetModule.GetDemotedValidators(num)
	if err != nil {
		return nil, err
	}

	return istanbul.NewBlockValSet(council, demoted), nil
}

var (
	// address.
	errInvalidSignature = errors.New("invalid signature")
	// errUnknownBlock is returned when the list of validators is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")
	// errUnauthorized is returned if a header is signed by a non authorized entity.
	errUnauthorized = errors.New("unauthorized")
	// errInvalidBlockScore is returned if the BlockScore of a block is not 1
	errInvalidBlockScore = errors.New("invalid blockscore")
	// errInvalidExtraDataFormat is returned when the extra data format is incorrect
	errInvalidExtraDataFormat = errors.New("invalid extra data format")
	// errInvalidTimestamp is returned if the timestamp of a block is lower than the previous block's timestamp + the minimum block period.
	errInvalidTimestamp = errors.New("invalid timestamp")
	// errInvalidCommittedSeals is returned if the committed seal is not signed by any of parent validators.
	errInvalidCommittedSeals = errors.New("invalid committed seals")
	// errEmptyCommittedSeals is returned if the field of committed seals is zero.
	errEmptyCommittedSeals = errors.New("zero committed seals")
	// errInvalidRandaoFields is returned if the Randao fields randomReveal or mixHash are invalid.
	errInvalidRandaoFields = errors.New("invalid randao fields")
	// errUnexpectedRandao is returned if the Randao fields randomReveal or mixHash are present when must not.
	errUnexpectedRandao = errors.New("unexpected randao fields")
	// errUnexpectedExcessBlobGasBeforeOsaka is returned if the excessBlobGas is present before the osaka fork.
	errUnexpectedExcessBlobGasBeforeOsaka = errors.New("unexpected excessBlobGas before osaka")
	// errUnexpectedBlobGasUsedBeforeOsaka is returned if the blobGasUsed is present before the osaka fork.
	errUnexpectedBlobGasUsedBeforeOsaka = errors.New("unexpected blobGasUsed before osaka")
)
