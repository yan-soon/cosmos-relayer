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
	"context"
	"fmt"
	"sync"

	"google.golang.org/grpc"

	sdkcli "github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	signingtypes "github.com/cosmos/cosmos-sdk/types/tx/signing"
	authtxtypes "github.com/cosmos/cosmos-sdk/x/auth/tx"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"

	tmcrypto "github.com/tendermint/tendermint/crypto"
	rpchttp "github.com/tendermint/tendermint/rpc/client/http"
	rpctypes "github.com/tendermint/tendermint/rpc/core/types"

	polysdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/core/types"
	"github.com/polynetwork/poly/native/service/header_sync/cosmos"

	headersynctypes "github.com/Switcheo/polynetwork-cosmos/x/headersync/types"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	"github.com/polynetwork/cosmos-relayer/db"
	"github.com/polynetwork/cosmos-relayer/log"
)

type InfoType int

const (
	TyTx InfoType = iota
	TyHeader
	TyUpdateHeight
)

var (
	RCtx = &Ctx{}
)

func NewCodecForRelayer() *codec.LegacyAmino {
	cdc := codec.NewLegacyAmino()
	cdc.RegisterInterface((*tmcrypto.PubKey)(nil), nil)
	headersynctypes.RegisterCodec(cdc)
	cryptocodec.RegisterCrypto(cdc)
	return cdc
}

func InitCtx(conf *Conf) (err error) {
	RCtx.Conf = conf
	setCosmosConfig(conf.CosmosAddrPrefix)

	// channels
	RCtx.ToCosmos = make(chan *PolyInfo, ChanBufSize)
	RCtx.ToPoly = make(chan *CosmosInfo, ChanBufSize)

	// legacy cdc
	RCtx.Cosmos.Cdc = NewCodecForRelayer()

	// init http rpc client for tendermint for unmigrated stuff
	if RCtx.Cosmos.RpcClient, err = rpchttp.New(conf.CosmosRpcAddr, "/websocket"); err != nil {
		return fmt.Errorf("failed to init rpc client: %v", err)
	}
	log.Tracef("rpc client initalized")

	// init grpc connection for cosmos-sdk
	if RCtx.Cosmos.GrpcConn, err = GetGRPCConnection(conf.CosmosGrpcAddr); err != nil {
		return fmt.Errorf("failed to init grpc connection: %v", err)
	}
	log.Tracef("grpc conn initalized")

	// init tx config for signing txs
	interfaceRegistry := codectypes.NewInterfaceRegistry()
	// Choose codec: Amino or Protobuf. Here, we use Protobuf
	protoCodec := codec.NewProtoCodec(interfaceRegistry)
	RCtx.Cosmos.TxConfig = authtxtypes.NewTxConfig(protoCodec, []signingtypes.SignMode{signingtypes.SignMode_SIGN_MODE_DIRECT})

	// init broadcaster key
	if RCtx.Cosmos.PrivKey, RCtx.Cosmos.Address, err = GetCosmosPrivateKey(conf.CosmosWallet, []byte(conf.CosmosWalletPwd)); err != nil {
		return err
	}

	// check account
	authclient := authtypes.NewQueryClient(RCtx.Cosmos.GrpcConn)
	accountRes, err := authclient.Account(
		context.Background(),
		&authtypes.QueryAccountRequest{
			Address: RCtx.Cosmos.Address.String(),
		},
	)
	if err != nil {
		return err
	}
	log.Tracef("query")
	ba := authtypes.BaseAccount{}
	err = ba.Unmarshal(accountRes.Account.Value)
	if err != nil {
		return err
	}

	// get account sequence
	RCtx.Cosmos.Sequence = &CosmosSeq{
		lock: sync.Mutex{},
		val:  ba.GetSequence(),
	}
	RCtx.Cosmos.AccountNumber = ba.GetAccountNumber()

	// set tx prices

	// prepare Poly staff
	RCtx.Poly = polysdk.NewPolySdk()
	if err := setUpPoly(RCtx.Poly); err != nil {
		return err
	}
	if RCtx.PolyAcc, err = GetAccountByPassword(RCtx.Poly, conf.PolyWallet, []byte(conf.PolyWalletPwd)); err != nil {
		return err
	}

	RCtx.Db, err = db.NewDatabase(conf.DBPath)
	if err != nil {
		return err
	}

	if RCtx.CMStatus, err = NewCosmosStatus(); err != nil {
		panic(fmt.Errorf("failed to new cosmos_status: %v", err))
	}
	if RCtx.PolyStatus, err = NewPolyStatus(); err != nil {
		panic(fmt.Errorf("failed to new poly_status: %v", err))
	}

	return nil
}

type Cosmos struct {
	Cdc           *codec.LegacyAmino
	TxConfig      sdkcli.TxConfig
	RpcClient     *rpchttp.HTTP
	GrpcConn      *grpc.ClientConn // to build sdk grpc clients for sdk queries
	PrivKey       cryptotypes.PrivKey
	Address       sdk.AccAddress
	Sequence      *CosmosSeq
	AccountNumber uint64
}
type Ctx struct {
	// configuration
	Conf *Conf

	// To transfer cross chain tx from listening to relaying
	ToCosmos chan *PolyInfo
	ToPoly   chan *CosmosInfo

	// Cosmos
	Cosmos Cosmos

	// Poly chain
	Poly    *polysdk.PolySdk
	PolyAcc *polysdk.Account

	// DB
	Db *db.Database

	// status for relayed tx
	CMStatus   *CosmosStatus
	PolyStatus *PolyStatus
}

func (c *Ctx) NewTxBuilder() sdkcli.TxBuilder {
	// Set other tx details
	txBuilder := c.Cosmos.TxConfig.NewTxBuilder()
	fee, err := sdk.ParseCoinsNormalized(c.Conf.CosmosTxFee)
	if err != nil {
		panic(err)
	}
	txBuilder.SetFeeAmount(fee)
	txBuilder.SetTimeoutHeight(18446744073709551615) // XXX: TODO
	txBuilder.SetGasLimit(c.Conf.CosmosGasLimit)
	return txBuilder
}

type PolyInfo struct {
	// type 0 means only tx; type 2 means header and tx; type 1 means only header;
	Type InfoType

	// to update height of Poly on COSMOS
	Height uint32

	// tx part
	Tx *PolyTx

	// header part
	Hdr *types.Header

	// proof of header which is not during current epoch
	HeaderProof string

	// any header in current epoch can be trust anchor
	EpochAnchor string
}

type PolyTx struct {
	Height      uint32
	Proof       string
	TxHash      string
	IsEpoch     bool
	CCID        []byte
	FromChainId uint64
}

type CosmosInfo struct {
	// type 1 means header and tx; type 2 means only header;
	Type InfoType

	// to update height of chain
	Height int64

	// tx part
	Tx *CosmosTx

	// header part
	Hdrs []*cosmos.CosmosHeader
}

type CosmosTx struct {
	Tx          *rpctypes.ResultTx
	ProofHeight int64
	Proof       []byte
	PVal        []byte
}

type CosmosSeq struct {
	lock sync.Mutex
	val  uint64
}

func (seq *CosmosSeq) GetAndAdd() uint64 {
	seq.lock.Lock()
	defer func() {
		seq.val += 1
		seq.lock.Unlock()
	}()
	return seq.val
}

// GetGRPCConnection Obtains a gRPC connection
// CONTRACT: should always close the connection after using: defer grpcConn.Close()
// Example:
// grpcConn, _ := getGRPCConnection("127.0.0.1:9090")
// defer grpcConn.Close()
func GetGRPCConnection(targetGRPCAddress string) (*grpc.ClientConn, error) {
	// log.Info("Obtaining gRPC connection from: ", targetGRPCAddress)
	// Create a connection to the gRPC server.
	grpcConn, err := grpc.Dial(
		targetGRPCAddress,   // your gRPC server address.
		grpc.WithInsecure(), // The SDK doesn't support any transport security mechanism.
	)
	if err != nil {
		log.Error("Failed to obtain gRPC connection from: ", targetGRPCAddress)
		return nil, err
	}
	return grpcConn, nil
}
