package zecutil

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	testWif    = "cPAM37GAZpXkS7YRJGRggyKrGk7qEZKjNkXvq9gcgzjYaghrjGhg"
	senderAddr = "tmRfZVuDK6gVDfwJie1zepKjAELqaGAgWZr"
)

var netParams = &chaincfg.Params{
	Name: "test",
}

func newV5TxForSigning(t *testing.T) (*MsgTx, []byte, *btcutil.WIF) {
	t.Helper()

	wif, err := btcutil.DecodeWIF(testWif)
	if err != nil {
		t.Fatal("can't parse wif")
	}

	ph, err := chainhash.NewHashFromStr(
		"e446be46fe7b44de1baf3b451227da8bbabc96b27ba17940ad759a8b6e61151c",
	)
	if err != nil {
		t.Fatal(err)
	}

	newTx := wire.NewMsgTx(5)
	newTx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(ph, 1), nil, nil))

	type receiver struct {
		addr   string
		amount int64
	}

	receivers := []receiver{
		{"tmF834qorixnCV18bVrkM8WN1Xasy5eXcZV", 200000},
		{senderAddr, 299750000},
	}

	for _, receiver := range receivers {
		decoded := base58.Decode(receiver.addr)
		addr, err := btcutil.NewAddressPubKeyHash(decoded[2:len(decoded)-4], netParams)
		if err != nil {
			t.Fatal(err)
		}

		receiverPkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			t.Fatal(err)
		}

		newTx.AddTxOut(wire.NewTxOut(receiver.amount, receiverPkScript))
	}

	prevTxScript, err := hex.DecodeString("76a914aefaebf9c83deba2ec76e080e2cec850dec161b188ac")
	if err != nil {
		t.Fatal(err)
	}

	return &MsgTx{
		MsgTx:        newTx,
		InputAmounts: []int64{300000000},
		InputScripts: [][]byte{prevTxScript},
	}, prevTxScript, wif
}

func TestSign(t *testing.T) {
	var (
		wif *btcutil.WIF
		err error
	)

	if wif, err = btcutil.DecodeWIF(testWif); err != nil {
		t.Fatal("can't parse wif")
	}

	var ph *chainhash.Hash
	if ph, err = chainhash.NewHashFromStr(
		"e446be46fe7b44de1baf3b451227da8bbabc96b27ba17940ad759a8b6e61151c",
	); err != nil {
		t.Fatal(err)
	}

	newTx := wire.NewMsgTx(4)
	txIn := wire.NewTxIn(wire.NewOutPoint(ph, 1), nil, nil)
	newTx.AddTxIn(txIn)

	type receiver struct {
		addr   string
		amount int64
	}

	receivers := []receiver{
		{"tmF834qorixnCV18bVrkM8WN1Xasy5eXcZV", 200000},
		{senderAddr, 299750000},
	}

	for _, receiver := range receivers {
		decoded := base58.Decode(receiver.addr)
		var addr *btcutil.AddressPubKeyHash
		if addr, err = btcutil.NewAddressPubKeyHash(decoded[2:len(decoded)-4], netParams); err != nil {
			t.Fatal(err)
		}

		receiverPkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			t.Fatal(err)
		}

		txOut := wire.NewTxOut(receiver.amount, receiverPkScript)
		newTx.AddTxOut(txOut)
	}

	zecTx := &MsgTx{
		MsgTx: newTx,
	}

	var prevTxScript []byte
	if prevTxScript, err = hex.DecodeString("76a914aefaebf9c83deba2ec76e080e2cec850dec161b188ac"); err != nil {
		t.Fatal(err)
	}
	sigScript, err := SignTxOutput(
		netParams,
		zecTx,
		0,
		prevTxScript,
		txscript.SigHashAll,
		txscript.KeyClosure(func(a btcutil.Address) (*btcec.PrivateKey, bool, error) {
			return wif.PrivKey, wif.CompressPubKey, nil
		}),
		nil,
		nil,
		0)
	if err != nil {
		t.Fatal(err)
	}
	txIn.SignatureScript = sigScript

	var buf bytes.Buffer
	if err = zecTx.ZecEncode(&buf, 0, wire.BaseEncoding); err != nil {
		t.Fatal(err)
	}

	final := "0400008085202f89011c15616e8b9a75ad4079a17bb296bcba8bda2712453baf1bde447bfe46be46e4010000006a47304402204976de53c0c32d8f6e5cdaffe48d67b73e6e76a0419d6596276645bce5920534022062ac1b1cf6758c24b805c62ff465930d0e38c7805aabdc6b8044e7917ab602d7012103362327ee808f5961d26ef1a431386d6190638d67c14aa0e78e2eba1b58870cc0ffffffff02400d0300000000001976a9143b535da0ba90dad71ea005cccfe3cca47d746b3a88ac70d2dd11000000001976a914aefaebf9c83deba2ec76e080e2cec850dec161b188ac00000000000000000000000000000000000000"
	if hex.EncodeToString(buf.Bytes()) != final {
		t.Fatal("incorrect sig")
	}
}

func TestHash(t *testing.T) {
	var (
		err error
		ph  *chainhash.Hash
	)

	if ph, err = chainhash.NewHashFromStr(
		"669f631ce20574fc33cd3e810bac941aff7b661e21ba4769e01bfd68509fc4e6",
	); err != nil {
		t.Fatal(err)
	}

	var ss []byte
	if ss, err = hex.DecodeString("4730440220307f094227b2e9b130ed9ee5fce75a043bb940681b204d11ca0c3c517f61f9f60220629e30a2f52e68e1ad6070be544bffc42bc439e7a8ea337f5974f6586222d69f012102da48746d58e04a4fb4ce381773cb6c8cedb71d009ebb740dea053c3e0f6cbf3c"); err != nil {
		t.Fatal(err)
	}

	newTx := wire.NewMsgTx(4)
	txIn := wire.NewTxIn(wire.NewOutPoint(ph, 1), ss, nil)
	newTx.AddTxIn(txIn)

	decoded := base58.Decode("tmHuu9Z7m5W7PcT4orLEANwnHKrB2aDfx5C")
	var addr *btcutil.AddressPubKeyHash
	if addr, err = btcutil.NewAddressPubKeyHash(decoded[2:len(decoded)-4], netParams); err != nil {
		t.Fatal(err)
	}

	pa, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}

	newTx.AddTxOut(wire.NewTxOut(299999742, pa))

	zecTx := &MsgTx{
		MsgTx: newTx,
	}

	expected := "ccae1a38b07c1d314cd0c1daa23baf6a4b2ff7f9b47046a94ccb6fadf9496ad3"
	if zecTx.TxHash().String() != expected {
		t.Fatal("Incorrect hash", "expected", expected, "got", zecTx.TxHash().String())
	}
}

func TestSignV5(t *testing.T) {
	var (
		wif *btcutil.WIF
		err error
	)

	if wif, err = btcutil.DecodeWIF(testWif); err != nil {
		t.Fatal("can't parse wif")
	}

	var ph *chainhash.Hash
	if ph, err = chainhash.NewHashFromStr(
		"e446be46fe7b44de1baf3b451227da8bbabc96b27ba17940ad759a8b6e61151c",
	); err != nil {
		t.Fatal(err)
	}

	newTx := wire.NewMsgTx(5)
	txIn := wire.NewTxIn(wire.NewOutPoint(ph, 1), nil, nil)
	newTx.AddTxIn(txIn)

	type receiver struct {
		addr   string
		amount int64
	}

	receivers := []receiver{
		{"tmF834qorixnCV18bVrkM8WN1Xasy5eXcZV", 200000},
		{senderAddr, 299750000},
	}

	for _, receiver := range receivers {
		decoded := base58.Decode(receiver.addr)
		var addr *btcutil.AddressPubKeyHash
		if addr, err = btcutil.NewAddressPubKeyHash(decoded[2:len(decoded)-4], netParams); err != nil {
			t.Fatal(err)
		}

		receiverPkScript, err := txscript.PayToAddrScript(addr)
		if err != nil {
			t.Fatal(err)
		}

		txOut := wire.NewTxOut(receiver.amount, receiverPkScript)
		newTx.AddTxOut(txOut)
	}

	var prevTxScript []byte
	if prevTxScript, err = hex.DecodeString("76a914aefaebf9c83deba2ec76e080e2cec850dec161b188ac"); err != nil {
		t.Fatal(err)
	}

	zecTx := &MsgTx{
		MsgTx:        newTx,
		InputAmounts: []int64{300000000},
		InputScripts: [][]byte{prevTxScript},
	}

	sigScript, err := SignTxOutput(
		netParams,
		zecTx,
		0,
		prevTxScript,
		txscript.SigHashAll,
		txscript.KeyClosure(func(a btcutil.Address) (*btcec.PrivateKey, bool, error) {
			return wif.PrivKey, wif.CompressPubKey, nil
		}),
		nil,
		nil,
		300000000)
	if err != nil {
		t.Fatal(err)
	}
	txIn.SignatureScript = sigScript

	var buf bytes.Buffer
	if err = zecTx.ZecEncode(&buf, 0, wire.BaseEncoding); err != nil {
		t.Fatal(err)
	}

	final := "050000800a27a72630f337540000000000000000011c15616e8b9a75ad4079a17bb296bcba8bda2712453baf1bde447bfe46be46e4010000006a473044022027dfa380bd09d304105c6c5088b4027e9a1d3840f23493ab12ad4b204a849f7a022052492ab4fc271448759193d85703ac1750f894a298d0ba06cb3279c62589c556012103362327ee808f5961d26ef1a431386d6190638d67c14aa0e78e2eba1b58870cc0ffffffff02400d0300000000001976a9143b535da0ba90dad71ea005cccfe3cca47d746b3a88ac70d2dd11000000001976a914aefaebf9c83deba2ec76e080e2cec850dec161b188ac000000"
	got := hex.EncodeToString(buf.Bytes())
	if got != final {
		t.Fatalf("incorrect v5 raw transaction serialization, expected: %s, got: %s", final, got)
	}

	expectedHash := "101b48dea0eb34d37549383dddf9a5588636a891e413b1d2b65415c10527baf0"
	if zecTx.TxHash().String() != expectedHash {
		t.Fatalf("incorrect v5 transaction hash, expected: %s, got: %s", expectedHash, zecTx.TxHash().String())
	}
}

func TestSignV5RejectsMissingInputMetadata(t *testing.T) {
	zecTx, prevTxScript, wif := newV5TxForSigning(t)

	zecTx.InputAmounts = nil
	_, err := SignTxOutput(
		netParams,
		zecTx,
		0,
		prevTxScript,
		txscript.SigHashAll,
		txscript.KeyClosure(func(a btcutil.Address) (*btcec.PrivateKey, bool, error) {
			return wif.PrivKey, wif.CompressPubKey, nil
		}),
		nil,
		nil,
		300000000)
	if err == nil {
		t.Fatal("expected error for missing v5 input amounts")
	}

	zecTx.InputAmounts = []int64{300000000}
	zecTx.InputScripts = nil
	_, err = SignTxOutput(
		netParams,
		zecTx,
		0,
		prevTxScript,
		txscript.SigHashAll,
		txscript.KeyClosure(func(a btcutil.Address) (*btcec.PrivateKey, bool, error) {
			return wif.PrivKey, wif.CompressPubKey, nil
		}),
		nil,
		nil,
		300000000)
	if err == nil {
		t.Fatal("expected error for missing v5 input scripts")
	}
}

func TestSignV5RejectsInvalidInputMetadata(t *testing.T) {
	zecTx, prevTxScript, wif := newV5TxForSigning(t)

	zecTx.InputAmounts[0] = 300000001
	_, err := SignTxOutput(
		netParams,
		zecTx,
		0,
		prevTxScript,
		txscript.SigHashAll,
		txscript.KeyClosure(func(a btcutil.Address) (*btcec.PrivateKey, bool, error) {
			return wif.PrivKey, wif.CompressPubKey, nil
		}),
		nil,
		nil,
		300000000)
	if err == nil {
		t.Fatal("expected error for mismatched v5 input amount")
	}

	zecTx.InputAmounts[0] = -1
	_, err = SignTxOutput(
		netParams,
		zecTx,
		0,
		prevTxScript,
		txscript.SigHashAll,
		txscript.KeyClosure(func(a btcutil.Address) (*btcec.PrivateKey, bool, error) {
			return wif.PrivKey, wif.CompressPubKey, nil
		}),
		nil,
		nil,
		-1)
	if err == nil {
		t.Fatal("expected error for negative v5 input amount")
	}

	zecTx.InputAmounts[0] = maxZecMoney + 1
	_, err = SignTxOutput(
		netParams,
		zecTx,
		0,
		prevTxScript,
		txscript.SigHashAll,
		txscript.KeyClosure(func(a btcutil.Address) (*btcec.PrivateKey, bool, error) {
			return wif.PrivKey, wif.CompressPubKey, nil
		}),
		nil,
		nil,
		maxZecMoney+1)
	if err == nil {
		t.Fatal("expected error for v5 input amount above max money")
	}
}

func TestSignV5RejectsInvalidOutputs(t *testing.T) {
	zecTx, prevTxScript, wif := newV5TxForSigning(t)

	for _, value := range []int64{-1, maxZecMoney + 1} {
		zecTx.TxOut[0].Value = value
		_, err := SignTxOutput(
			netParams,
			zecTx,
			0,
			prevTxScript,
			txscript.SigHashAll,
			txscript.KeyClosure(func(a btcutil.Address) (*btcec.PrivateKey, bool, error) {
				return wif.PrivKey, wif.CompressPubKey, nil
			}),
			nil,
			nil,
			300000000)
		if err == nil {
			t.Fatalf("expected error for invalid v5 output amount %d", value)
		}
	}
}

func TestZecEncodeV5RejectsInvalidConsensusFields(t *testing.T) {
	zecTx, _, _ := newV5TxForSigning(t)

	zecTx.expiryHeight = maxExpiryHeight + 1
	var buf bytes.Buffer
	if err := zecTx.ZecEncode(&buf, 0, wire.BaseEncoding); err == nil {
		t.Fatal("expected error for invalid v5 expiry height")
	}

	zecTx.expiryHeight = 0
	zecTx.TxOut[0].Value = -1
	buf.Reset()
	if err := zecTx.ZecEncode(&buf, 0, wire.BaseEncoding); err == nil {
		t.Fatal("expected error for invalid v5 output amount")
	}
}

func TestSignV5RejectsInvalidHashTypes(t *testing.T) {
	zecTx, prevTxScript, wif := newV5TxForSigning(t)

	for _, hashType := range []txscript.SigHashType{
		txscript.SigHashOld,
		txscript.SigHashAll | 0x40,
	} {
		_, err := SignTxOutput(
			netParams,
			zecTx,
			0,
			prevTxScript,
			hashType,
			txscript.KeyClosure(func(a btcutil.Address) (*btcec.PrivateKey, bool, error) {
				return wif.PrivKey, wif.CompressPubKey, nil
			}),
			nil,
			nil,
			300000000)
		if err == nil {
			t.Fatalf("expected error for invalid v5 hash type %d", hashType)
		}
	}
}

func TestSignV5RejectsSigHashSingleWithoutOutput(t *testing.T) {
	zecTx, prevTxScript, wif := newV5TxForSigning(t)
	zecTx.TxOut = nil

	_, err := SignTxOutput(
		netParams,
		zecTx,
		0,
		prevTxScript,
		txscript.SigHashSingle,
		txscript.KeyClosure(func(a btcutil.Address) (*btcec.PrivateKey, bool, error) {
			return wif.PrivKey, wif.CompressPubKey, nil
		}),
		nil,
		nil,
		300000000)
	if err == nil {
		t.Fatal("expected error for v5 SIGHASH_SINGLE without a matching output")
	}
}

func TestV5SignatureHashUsesInputScriptPubKey(t *testing.T) {
	zecTx, _, _ := newV5TxForSigning(t)

	redeemScript, err := txscript.NewScriptBuilder().AddOp(txscript.OP_TRUE).Script()
	if err != nil {
		t.Fatal(err)
	}
	scriptPubKey, err := txscript.NewScriptBuilder().
		AddOp(txscript.OP_HASH160).
		AddData(btcutil.Hash160(redeemScript)).
		AddOp(txscript.OP_EQUAL).
		Script()
	if err != nil {
		t.Fatal(err)
	}

	cache, err := NewTxSigHashes(zecTx)
	if err != nil {
		t.Fatal(err)
	}

	zecTx.InputScripts[0] = scriptPubKey
	got, err := blake2bSignatureHash(redeemScript, cache, txscript.SigHashAll, zecTx, 0, 300000000)
	if err != nil {
		t.Fatal(err)
	}

	zecTx.InputScripts[0] = redeemScript
	oldBehavior, err := blake2bSignatureHash(redeemScript, cache, txscript.SigHashAll, zecTx, 0, 300000000)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(got, oldBehavior) {
		t.Fatal("v5 signature hash did not commit to the spent output scriptPubKey")
	}
}
