/*
 * Copyright (C) 2020 The poly network Authors
 * This file is part of The poly network library.
 *
 * The  poly network  is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The  poly network  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * You should have received a copy of the GNU Lesser General Public License
 * along with The poly network .  If not, see <http://www.gnu.org/licenses/>.
 */

package context

import (
	"fmt"
	"io/ioutil"

	"github.com/cosmos/cosmos-sdk/crypto"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/types"
	"github.com/polynetwork/cosmos-relayer/log"
	polysdk "github.com/polynetwork/poly-go-sdk"
)

func GetAccountByPassword(sdk *polysdk.PolySdk, path string, pwd []byte) (*polysdk.Account, error) {
	wallet, err := sdk.OpenWallet(path)
	if err != nil {
		return nil, fmt.Errorf("open wallet error: %v", err)
	}
	user, err := wallet.GetDefaultAccount(pwd)
	if err != nil {
		return nil, fmt.Errorf("getDefaultAccount error: %v", err)
	}
	return user, nil
}

func GetCosmosPrivateKey(path string, pwd []byte) (cryptotypes.PrivKey, types.AccAddress, error) {
	bz, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, types.AccAddress{}, err
	}

	privKey, _, err := crypto.UnarmorDecryptPrivKey(string(bz), string(pwd))
	if err != nil {
		return nil, types.AccAddress{}, fmt.Errorf("failed to decrypt private key: %v", err)
	}

	return privKey, types.AccAddress(privKey.PubKey().Address().Bytes()), nil
}

func setCosmosEnv(chainId string) {
	switch chainId {
	case "cc-cosmos":
		return
	case "carbon-1":
		fallthrough
	case "switcheochain":
		config := types.GetConfig()
		config.SetBech32PrefixForAccount("swth", "swthpub")
		config.SetBech32PrefixForValidator("swthvaloper", "swthvaloperpub")
		config.SetBech32PrefixForConsensusNode("swthvalcons", "swthvalconspub")
		config.Seal()
	case "switcheo-tradehub-1":
		config := types.GetConfig()
		config.SetBech32PrefixForAccount("swth", "swthpub")
		config.SetBech32PrefixForValidator("swthvaloper", "swthvaloperpub")
		config.SetBech32PrefixForConsensusNode("swthvalcons", "swthvalconspub")
	case "carbon":
		config := types.GetConfig()
		config.SetBech32PrefixForAccount("swth", "swthpub")
		config.SetBech32PrefixForValidator("swthvaloper", "swthvaloperpub")
		config.SetBech32PrefixForConsensusNode("swthvalcons", "swthvalconspub")
	default:
		log.Warnf("cosmos chain id not known %s, so use default settings", chainId)
	}
}

func setUpPoly(poly *polysdk.PolySdk) error {
	poly.NewRpcClient().SetAddress(RCtx.Conf.PolyRpcAddr)
	hdr, err := poly.GetHeaderByHeight(0)
	if err != nil {
		return err
	}
	poly.SetChainId(hdr.ChainID)
	return nil
}
