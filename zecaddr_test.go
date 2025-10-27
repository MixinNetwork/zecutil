package zecutil

import (
	"log"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

func TestEncode(t *testing.T) {
	var (
		wif *btcutil.WIF
		err error
	)

	if wif, err = btcutil.DecodeWIF(testWif); err != nil {
		t.Fatal("can't parse wif")
	}

	var encodedAddr string
	encodedAddr, err = Encode(wif.PrivKey.PubKey().SerializeCompressed(), &chaincfg.Params{
		Name: "testnet3",
	})

	if err != nil {
		t.Fatal(err)
	}

	expectedAddr := senderAddr
	if expectedAddr != encodedAddr {
		t.Fatal("incorrect encode", "expected", expectedAddr, "got", encodedAddr)
	}

	_, err = Encode(wif.PrivKey.PubKey().SerializeCompressed(), &chaincfg.Params{
		Name: "dummy",
	})

	if err == nil {
		t.Fatal("incorect error, got nil")
	}
}

func TestDecode(t *testing.T) {
	addrs := []string{
		"tmF834qorixnCV18bVrkM8WN1Xasy5eXcZV",
		"tmRfZVuDK6gVDfwJie1zepKjAELqaGAgWZr",
	}

	for _, addr := range addrs {
		a, err := DecodeAddress(addr, "testnet3")
		if err != nil {
			t.Fatal("got err", "expected nil", "got", err)
		}

		if !a.IsForNet(&chaincfg.Params{Name: "testnet3"}) {
			t.Fatal("incorrect net")
		}

		if a.EncodeAddress() != addr {
			t.Fatal("incorrect decode")
		}
	}
}

func TestBech32MEncodeDecode(t *testing.T) {
	wif, err := btcutil.DecodeWIF(testWif)
	if err != nil {
		t.Fatal("can't parse wif")
	}

	pubKey := btcutil.Hash160(wif.PrivKey.PubKey().SerializeCompressed())
	log.Println("pubKey:", len(pubKey))

	addr, err := EncodeTex(pubKey, &chaincfg.Params{Name: "testnet3"})
	if err != nil {
		t.Fatal(err)
	}
	log.Println("addr:", addr)

	addr, err = EncodeTex(pubKey, &chaincfg.Params{Name: "mainnet"})
	if err != nil {
		t.Fatal(err)
	}
	log.Println("addr:", addr)
}
