package main

import (
	"testing"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
)

func TestRegisterDevice(t *testing.T) {
	// Mock SDK
	sdk := fabsdk.New(nil) // 实际测试中需要配置

	ic := &IdentityChain{sdk: sdk}

	ringRoot := []byte("test_ring_root")
	err := ic.RegisterDevice("test_device", ringRoot)
	if err != nil {
		t.Errorf("注册设备失败: %v", err)
	}
}

func TestRevokeDevice(t *testing.T) {
	sdk := fabsdk.New(nil)
	ic := &IdentityChain{sdk: sdk}

	err := ic.RevokeDevice("test_device")
	if err != nil {
		t.Errorf("撤销设备失败: %v", err)
	}
}

func TestGetRingRoot(t *testing.T) {
	sdk := fabsdk.New(nil)
	ic := &IdentityChain{sdk: sdk}

	_, err := ic.GetRingRoot("test_device")
	if err != nil {
		t.Errorf("获取环根失败: %v", err)
	}
}