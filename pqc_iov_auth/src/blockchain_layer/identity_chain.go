// 身份注册与撤销、环根管理协议 [cite: 18]
package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
)

type IdentityChain struct {
	sdk *fabsdk.FabricSDK
}

func NewIdentityChain(configPath string) (*IdentityChain, error) {
	sdk, err := fabsdk.New(config.FromFile(configPath))
	if err != nil {
		return nil, err
	}
	return &IdentityChain{sdk: sdk}, nil
}

func (ic *IdentityChain) RegisterDevice(deviceID string, ringRoot []byte) error {
	client, err := channel.New(ic.sdk.ChannelContext("mychannel", fabsdk.WithUser("Admin")))
	if err != nil {
		return err
	}

	args := [][]byte{
		[]byte("registerDevice"),
		[]byte(deviceID),
		[]byte(hex.EncodeToString(ringRoot)),
	}

	_, err = client.Execute(channel.Request{
		ChaincodeID: "identitychain",
		Fcn:         "registerDevice",
		Args:        args,
	})

	if err != nil {
		log.Printf("注册设备失败: %v", err)
		return err
	}

	log.Printf("设备 %s 注册成功，环根: %s", deviceID, hex.EncodeToString(ringRoot)[:16])
	return nil
}

func (ic *IdentityChain) RevokeDevice(deviceID string) error {
	client, err := channel.New(ic.sdk.ChannelContext("mychannel", fabsdk.WithUser("Admin")))
	if err != nil {
		return err
	}

	args := [][]byte{
		[]byte("revokeDevice"),
		[]byte(deviceID),
	}

	_, err = client.Execute(channel.Request{
		ChaincodeID: "identitychain",
		Fcn:         "revokeDevice",
		Args:        args,
	})

	if err != nil {
		log.Printf("撤销设备失败: %v", err)
		return err
	}

	log.Printf("设备 %s 已撤销", deviceID)
	return nil
}

func (ic *IdentityChain) GetRingRoot(deviceID string) ([]byte, error) {
	client, err := channel.New(ic.sdk.ChannelContext("mychannel", fabsdk.WithUser("Admin")))
	if err != nil {
		return nil, err
	}

	args := [][]byte{
		[]byte("getRingRoot"),
		[]byte(deviceID),
	}

	response, err := client.Query(channel.Request{
		ChaincodeID: "identitychain",
		Fcn:         "getRingRoot",
		Args:        args,
	})

	if err != nil {
		return nil, err
	}

	ringRootHex := string(response.Payload)
	ringRoot, err := hex.DecodeString(ringRootHex)
	if err != nil {
		return nil, err
	}

	return ringRoot, nil
}

func main() {
	// 示例用法
	ic, err := NewIdentityChain("config.yaml")
	if err != nil {
		log.Fatal(err)
	}

	ringRoot := []byte("example_ring_root_bytes")
	err = ic.RegisterDevice("device123", ringRoot)
	if err != nil {
		log.Fatal(err)
	}

	retrievedRoot, err := ic.GetRingRoot("device123")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Retrieved ring root: %s\n", hex.EncodeToString(retrievedRoot))
}