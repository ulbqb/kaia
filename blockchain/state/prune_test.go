// Modifications Copyright 2024 The Kaia Authors

package state

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/storage/database"
	"github.com/kaiachain/kaia/storage/statedb"
)

func TestRollback(t *testing.T) {
	// worker.go:commitBundleTransactiond
	dbm := database.NewMemoryDBManager()
	opts := &statedb.TrieOpts{}
	dbm.WritePruningEnabled()
	opts.PruningBlockNumber = 1

	sdb := NewDatabase(dbm)
	state, _ := New(common.Hash{}, sdb, nil, opts)

	var (
		acc  = common.HexToAddress("0x0000000000000000000000000000000000000aaa")
		acc2 = common.HexToAddress("0x0000000000000000000000000000000000000bbb")
		acc3 = common.HexToAddress("0x0000000000000000000000000000000000000ccc")
	)
	// set retention
	// insert block required

	// ACC == 10
	state.AddBalance(acc2, big.NewInt(30))
	state.AddBalance(acc3, big.NewInt(40))
	state.AddBalance(acc, big.NewInt(10))
	root10, _ := state.Commit(true)
	fmt.Println("root", root10.Hex())

	state, _ = New(root10, sdb, nil, opts)
	snapshot := state.Copy()

	// ACC == 200
	state.SetBalance(acc, big.NewInt(200))

	root200, _ := state.Commit(true)
	fmt.Println("root", root200.Hex())
	state.Database().TrieDB().Cap(0)

	// ACC == 10
	state.Set(snapshot)

	marks := dbm.ReadPruningMarks(0, 2)
	for _, mark := range marks {
		fmt.Println("delete", mark.Hash.Hex())
		dbm.DeleteTrieNode(mark.Hash)
	}

	// Already opened
	fmt.Println("balance", state.GetBalance(acc))

	// Newly opening
	state, err := New(root10, sdb, nil, opts)
	fmt.Println("err", err)
	if state != nil {
		fmt.Println("balance", state.GetBalance(acc))
	}

	t.Fail()
}

// 1. make statedb copy thorugh state.Copy()
// 2. let pruning module mark candidates
// 3. check copied if statedb is not reflected
