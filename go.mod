module github.com/polynetwork/cosmos-relayer

go 1.16

require (
	github.com/Switcheo/polynetwork-cosmos v0.0.0-20240124090553-72d8c37c7418
	github.com/boltdb/bolt v1.3.1
	github.com/cometbft/cometbft v0.37.2
	github.com/cosmos/cosmos-sdk v0.47.5
	github.com/ontio/ontology v1.11.1-0.20200812075204-26cf1fa5dd47
	github.com/polynetwork/poly v0.0.0-20210629094731-3f755d4b4404
	github.com/polynetwork/poly-go-sdk v0.0.0-20210114120411-3dcba035134f
	github.com/stretchr/testify v1.8.4
	github.com/tendermint/tendermint v0.34.11
	google.golang.org/grpc v1.56.2
)

replace github.com/gogo/protobuf => github.com/regen-network/protobuf v1.3.3-alpha.regen.1

replace github.com/cosmos/cosmos-sdk => github.com/Switcheo/cosmos-sdk v0.47.5-0.20240119065259-675e01adc46f

replace github.com/polynetwork/poly => github.com/Switcheo/poly v0.0.0-20240123071231-ca0ffcaf031c

replace github.com/btcsuite/btcd => github.com/btcsuite/btcd v0.22.2

replace github.com/ontio/ontology-crypto => github.com/ontio/ontology-crypto v1.2.1
