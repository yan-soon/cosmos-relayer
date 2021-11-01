module github.com/polynetwork/cosmos-relayer

go 1.16

require (
	github.com/Switcheo/polynetwork-cosmos v0.0.0-20210929081223-d1db4c411745
	github.com/boltdb/bolt v1.3.1
	github.com/cosmos/cosmos-sdk v0.42.6
	github.com/ontio/ontology v1.11.1-0.20200812075204-26cf1fa5dd47
	github.com/polynetwork/poly v0.0.0-20210629094731-3f755d4b4404
	github.com/polynetwork/poly-go-sdk v0.0.0-20210114120411-3dcba035134f
	github.com/stretchr/testify v1.7.0
	github.com/tendermint/tendermint v0.34.11
	google.golang.org/grpc v1.40.0
)

replace google.golang.org/grpc => google.golang.org/grpc v1.33.2

replace github.com/gogo/protobuf => github.com/regen-network/protobuf v1.3.3-alpha.regen.1

replace github.com/cosmos/cosmos-sdk => github.com/Switcheo/cosmos-sdk v0.42.4-0.20210831093444-8d0abdf21f60

replace github.com/polynetwork/poly => github.com/Switcheo/poly v0.0.0-20210708043258-47d107cc1dc3
