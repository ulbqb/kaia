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

package impl

import (
	"testing"

	"github.com/kaiachain/kaia/common"
	"github.com/kaiachain/kaia/common/hexutil"
	"github.com/kaiachain/kaia/storage/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSchema_ValsetVoteBlockNums(t *testing.T) {
	db := database.NewMemDB()
	nums := []uint64{10, 20, 30, 40, 50}
	writeValidatorVoteBlockNums(db, nums)
	assert.Equal(t, nums, ReadValidatorVoteBlockNums(db))

	insertValidatorVoteBlockNums(db, 22)
	assert.Equal(t, []uint64{10, 20, 22, 30, 40, 50}, ReadValidatorVoteBlockNums(db))

	trimValidatorVoteBlockNums(db, 30)
	assert.Equal(t, []uint64{10, 20, 22}, ReadValidatorVoteBlockNums(db))
}

func TestSchema_Council(t *testing.T) {
	db := database.NewMemDB()
	num := uint64(10)
	addrs := []common.Address{
		common.HexToAddress("0x1234"),
		common.HexToAddress("0x5678"),
	}
	writeCouncil(db, num, addrs)
	assert.Equal(t, addrs, ReadCouncil(db, num))
}

func TestSchema_IstanbulSnapshot(t *testing.T) {
	db := database.NewMemDB()
	hash := common.HexToHash("0x1234")

	db.Put(istanbulSnapshotKey(hash), []byte(""))
	addrs := ReadIstanbulSnapshot(db, hash)
	assert.Nil(t, addrs)

	// Kairos block 125079552
	b := hexutil.MustDecode("0x7b2265706f6368223a3630343830302c226e756d626572223a3132353037393535322c2268617368223a22307866303136633937653138343462653136333238396364326261396535336662346530656334636438313134363465313635616533623133336335653761636634222c22766f746573223a5b7b2276616c696461746f72223a22307839396662313764333234666130653037663233623439643039303238616330393139343134646236222c226b6579223a22676f7665726e616e63652e61646476616c696461746f72222c2276616c7565223a22307865383564313937613830643630353634363136393833663564326131313262393766363161306666227d2c7b2276616c696461746f72223a22307839396662313764333234666130653037663233623439643039303238616330393139343134646236222c226b6579223a22676f7665726e616e63652e72656d6f766576616c696461746f72222c2276616c7565223a22307834623966393838333164613161663935663936613161643364373861643861313235646262343532227d5d2c2274616c6c79223a5b7b226b6579223a22676f7665726e616e63652e61646476616c696461746f72222c2276616c7565223a22307865383564313937613830643630353634363136393833663564326131313262393766363161306666222c22766f746573223a313030307d2c7b226b6579223a22676f7665726e616e63652e72656d6f766576616c696461746f72222c2276616c7565223a22307834623966393838333164613161663935663936613161643364373861643861313235646262343532222c22766f746573223a313030307d5d2c2276616c696461746f7273223a5b22307835373165353364663630376265393734333161356262656663613164666665356165663536663464222c22307835636231613764636362643064633434366533363430383938656465383832303336383535346338222c22307839396662313764333234666130653037663233623439643039303238616330393139343134646236222c22307862373466663964656133393766653965323331646635343565623533666532616466373736636232225d2c22706f6c696379223a322c2273756267726f757073697a65223a32322c227265776172644164647273223a5b22307836353539613762363234386233343262633131666263646639333433323132626263333437656463222c22307861383666643636376336613334306335336363356437393662613834646265316632396362326637222c22307862326264333137386166666363643966396635313839343537663163616437643137613031633964222c22307838323832396136306336656163346533653964366564303038393163363965383835333766643464225d2c22766f74696e67506f776572223a5b313030302c313030302c313030302c313030305d2c22776569676874223a5b302c302c302c305d2c2270726f706f73657273223a5b22307862373466663964656133393766653965323331646635343565623533666532616466373736636232222c22307839396662313764333234666130653037663233623439643039303238616330393139343134646236222c22307835373165353364663630376265393734333161356262656663613164666665356165663536663464222c22307835636231613764636362643064633434366533363430383938656465383832303336383535346338225d2c2270726f706f73657273426c6f636b4e756d223a3132353037383430302c2264656d6f74656456616c696461746f7273223a5b22307865383564313937613830643630353634363136393833663564326131313262393766363161306666225d7d")
	t.Logf("snapshot json %s", b)
	db.Put(istanbulSnapshotKey(hash), b)
	addrs = ReadIstanbulSnapshot(db, hash)
	assert.Equal(t, hexToAddrs(
		// This sample has 4 (qualified) validators
		"0x571e53df607be97431a5bbefca1dffe5aef56f4d",
		"0x5cb1a7dccbd0dc446e3640898ede8820368554c8",
		"0x99fb17d324fa0e07f23b49d09028ac0919414db6",
		"0xb74ff9dea397fe9e231df545eb53fe2adf776cb2",
		// and 1 demoted validator
		"0xe85d197a80d60564616983f5d2a112b97f61a0ff",
	), addrs)
}

func TestSchema_LowestScannedVoteNum(t *testing.T) {
	db := database.NewMemDB()

	assert.Nil(t, ReadLowestScannedVoteNum(db))

	num := uint64(10)
	writeLowestScannedVoteNum(db, num)
	pNum := ReadLowestScannedVoteNum(db)
	require.NotNil(t, pNum)
	assert.Equal(t, num, *pNum)
}