// Modifications Copyright 2024 The Kaia Authors
// Modifications Copyright 2018 The klaytn Authors
// Copyright 2017 The go-ethereum Authors
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
// This file is derived from quorum/consensus/istanbul/core/handler.go (2018/06/04).
// Modified and improved for the klaytn development.
// Modified and improved for the Kaia development.

package core

import (
	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/consensus/istanbul"
)

// Start implements core.Engine.Start
func (c *core) Start() error {
	// Start a new round from last sequence + 1
	c.startNewRound(common.Big0)

	// Tests will handle events itself, so we have to make subscribeEvents()
	// be able to call in test.
	c.subscribeEvents()
	c.handlerWg.Add(1)
	go c.handleEvents()

	return nil
}

// Stop implements core.Engine.Stop
func (c *core) Stop() error {
	c.stopTimer()
	c.unsubscribeEvents()

	// Make sure the handler goroutine exits
	c.handlerWg.Wait()
	return nil
}

// ----------------------------------------------------------------------------

// Subscribe both internal and external events
func (c *core) subscribeEvents() {
	c.events = c.backend.EventMux().Subscribe(
		// external events
		istanbul.RequestEvent{},
		istanbul.MessageEvent{},
		// internal events
		backlogEvent{},
	)
	c.timeoutSub = c.backend.EventMux().Subscribe(
		timeoutEvent{},
	)
	c.finalCommittedSub = c.backend.EventMux().Subscribe(
		istanbul.FinalCommittedEvent{},
	)
}

// Unsubscribe all events
func (c *core) unsubscribeEvents() {
	c.events.Unsubscribe()
	c.timeoutSub.Unsubscribe()
	c.finalCommittedSub.Unsubscribe()
}

func (c *core) handleEvents() {
	// Clear state
	defer func() {
		c.current = nil
		c.handlerWg.Done()
	}()

	for {
		select {
		case event, ok := <-c.events.Chan():
			if !ok {
				return
			}
			// A real event arrived, process interesting content
			switch ev := event.Data.(type) {
			case istanbul.RequestEvent:
				r := &istanbul.Request{
					Proposal: ev.Proposal,
				}
				err := c.handleRequest(r)
				if err == errFutureMessage {
					c.storeRequestMsg(r)
				}
			case istanbul.MessageEvent:
				if err := c.handleMsg(ev.Payload); err == nil {
					c.backend.GossipSubPeer(ev.Hash, ev.Payload)
					// c.backend.Gossip(c.valSet, ev.Payload)
				}
			case backlogEvent:
				if !c.currentCommittee.Qualified().Contains(ev.src) {
					c.logger.Error("Invalid address in valSet", "addr", ev.src)
					continue
				}
				// No need to check signature for internal messages
				if err := c.handleCheckedMsg(ev.msg, ev.src); err == nil {
					p, err := ev.msg.Payload()
					if err != nil {
						c.logger.Warn("Get message payload failed", "err", err)
						continue
					}
					c.backend.GossipSubPeer(ev.Hash, p)
					// c.backend.Gossip(c.valSet, p)
				}
			}
		case ev, ok := <-c.timeoutSub.Chan():
			if !ok || ev.Data == nil {
				logger.Error("Drop an empty message from timeout channel")
				return
			}
			data, ok := ev.Data.(timeoutEvent)
			if !ok || data.nextView == nil {
				logger.Error("Invalid message from timeout channel", "msg", ev.Data)
				return
			}
			c.handleTimeoutMsg(data.nextView)
		case event, ok := <-c.finalCommittedSub.Chan():
			if !ok {
				return
			}
			switch event.Data.(type) {
			case istanbul.FinalCommittedEvent:
				c.handleFinalCommitted()
			}
		}
	}
}

// sendEvent sends events to mux
func (c *core) sendEvent(ev interface{}) {
	c.backend.EventMux().Post(ev)
}

func (c *core) handleMsg(payload []byte) error {
	logger := c.logger.NewWith()

	// Decode message and check its signature
	msg := new(message)
	if err := msg.FromPayload(payload, c.validateFn); err != nil {
		if c.backend.NodeType() == common.CONSENSUSNODE {
			if err != istanbul.ErrUnauthorizedAddress {
				logger.Error("Failed to decode message from payload", "err", err)
				return err
			}

			msgView, msgDecodeErr := msg.GetView()
			if msgDecodeErr != nil {
				logger.Error("Failed to decode message while getting view information", "code", msg.Code, "err", msgDecodeErr)
				return err
			}

			// Print view and address to help you analyze the node is valid or not.
			// This information will help you to analyze whether the msg sender is valid or not.
			// Furthermore, if the node is still syncing, there is a high probability that msg sender is a valid validator.
			logger.Warn("Received Consensus msg is signed by an unauthorized address. It could happen when the node is unsynced temporarily.", "senderAddress", msg.Address, "nodeView", c.currentView().String(), "msgView", msgView.String())
		}
		return err
	}

	// Only accept message if the address is valid
	if !c.currentCommittee.Qualified().Contains(msg.Address) {
		logger.Error("Invalid address in message", "msg", msg)
		return istanbul.ErrUnauthorizedAddress
	}

	return c.handleCheckedMsg(msg, msg.Address)
}

func (c *core) handleCheckedMsg(msg *message, src common.Address) error {
	logger := c.logger.NewWith("address", c.address, "from", src)

	// Store the message if it's a future message
	testBacklog := func(err error) error {
		if err == errFutureMessage {
			c.storeBacklog(msg, src)
		}

		return err
	}

	switch msg.Code {
	case msgPreprepare:
		return testBacklog(c.handlePreprepare(msg, src))
	case msgPrepare:
		return testBacklog(c.handlePrepare(msg, src))
	case msgCommit:
		return testBacklog(c.handleCommit(msg, src))
	case msgRoundChange:
		return testBacklog(c.handleRoundChange(msg, src))
	default:
		logger.Error("Invalid message type", "msg", msg)
	}

	return errInvalidMessage
}

func (c *core) handleTimeoutMsg(nextView *istanbul.View) {
	// TODO-Kaia-Istanbul: EN/PN should not handle consensus msgs.
	if c.backend.NodeType() != common.CONSENSUSNODE {
		logger.Trace("PN/EN doesn't need to handle timeout messages",
			"nodeType", c.backend.NodeType().String())
		return
	}

	lastProposal, _ := c.backend.LastProposal()
	if lastProposal == nil {
		logger.Error("Received timeout message but can't find the last proposal", "msgView", nextView.String())
		return
	}

	if lastProposal.Number().Cmp(nextView.Sequence) >= 0 {
		logger.Debug("This timeoutMsg is outdated",
			"blockNumber", lastProposal.Number().Uint64(), "msgView", nextView.String())
		return
	}

	// If we're not waiting for round change yet, we can try to catch up
	// the max round with F+1 round change message. We only need to catch up
	// if the max round is larger than current round.
	if !c.waitingForRoundChange {
		maxRound := c.roundChangeSet.MaxRound(c.currentCommittee.F() + 1)
		if maxRound != nil && maxRound.Cmp(c.current.Round()) > 0 {
			logger.Warn("[RC] Send round change because of timeout event")
			c.sendRoundChange(maxRound)
			return
		}
	}

	if lastProposal.Number().Cmp(c.current.Sequence()) >= 0 {
		c.logger.Trace("round change timeout, catch up latest sequence", "number", lastProposal.Number().Uint64())
		c.startNewRound(common.Big0)
	} else {
		c.sendRoundChange(nextView.Round)
	}
}
