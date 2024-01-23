module github.com/polynetwork/cosmos-relayer

go 1.14

require (
	github.com/boltdb/bolt v1.3.1
	github.com/cmars/basen v0.0.0-20150613233007-fe3947df716e // indirect
	github.com/cometbft/cometbft v0.37.2
	github.com/cosmos/cosmos-sdk v0.39.1
	github.com/ontio/ontology v1.11.0
	github.com/polynetwork/cosmos-poly-module v0.0.0-20200722084435-f917a9a3331f
	github.com/polynetwork/poly v0.0.0-20200715030435-4f1d1a0adb44
	github.com/polynetwork/poly-go-sdk v0.0.0-20200722030827-6875b6018b93
	github.com/stretchr/testify v1.8.1
	github.com/tendermint/tendermint v0.33.7
	launchpad.net/gocheck v0.0.0-20140225173054-000000000087 // indirect
)

replace github.com/btcsuite/btcd => github.com/btcsuite/btcd v0.22.2
