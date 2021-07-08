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
	"time"

	ccmtypes "github.com/Switcheo/polynetwork-cosmos/x/ccm/types"
)

const (
	PerPage                 = 100 // (0, 100]
	HdrLimitPerBatch        = 50
	ChanBufSize             = 256
	CosmosCrossChainModName = ccmtypes.ModuleName
	ProofPath               = "/store/" + ccmtypes.ModuleName + "/key"
	RightHeightUpdate       = "update latest height"
	CrossChainTxEvent       = "make_from_cosmos_proof"
	TxAlreadyExist          = "already done"
	NewEpoch                = "lower than epoch switching height"
	SeqErr                  = "verify correct account sequence and chain-id"
	BroadcastConnTimeOut    = "connection timed out"
	UtxoNotEnough           = "current utxo is not enough"
	CosmosTxNotInEpoch      = "Compare height"
	NoUsefulHeaders         = "no header you commited is useful"
)

var (
	SleepSecs = func(n int) {
		time.Sleep(time.Duration(n) * time.Second)
	}
)
