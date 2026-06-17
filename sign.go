package zecutil

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	sigHashMask    = 0x1f
	blake2BSigHash = "ZcashSigHash"
)

const (
	versionOverwinter int32 = 3
	versionSapling    int32 = 4
	versionV5         int32 = 5
)

const (
	versionOverwinterGroupID uint32 = 0x3C48270
	versionSaplingGroupID    uint32 = 0x892f2085
	versionV5GroupID         uint32 = 0x26a7270a
	defaultConsensusBranchId uint32 = 0x5437f330 // NU6.2
)

// RawTxInSignature returns the serialized ECDSA signature for the input idx of
// the given transaction, with hashType appended to it.
func RawTxInSignature(
	tx *MsgTx,
	idx int,
	subScript []byte,
	hashType txscript.SigHashType,
	key *btcec.PrivateKey,
	amt int64,
) (_ []byte, err error) {
	var cache *txscript.TxSigHashes
	if cache, err = NewTxSigHashes(tx); err != nil {
		return nil, err
	}

	bHash, err := blake2bSignatureHash(subScript, cache, hashType, tx, idx, amt)
	if err != nil {
		return nil, err
	}

	signature := ecdsa.Sign(key, bHash)
	return append(signature.Serialize(), byte(hashType)), nil
}

// SignTxOutput for sign zec transactions inputs
func SignTxOutput(
	chainParams *chaincfg.Params,
	tx *MsgTx,
	idx int,
	pkScript []byte,
	hashType txscript.SigHashType,
	kdb txscript.KeyDB,
	sdb txscript.ScriptDB,
	previousScript []byte,
	amt int64,
) ([]byte, error) {
	sigScript, class, addresses, nrequired, err := sign(
		chainParams,
		tx,
		idx,
		pkScript,
		hashType,
		kdb,
		sdb,
		amt,
	)
	if err != nil {
		return nil, err
	}

	if class == txscript.ScriptHashTy {
		// TODO: keep the sub addressed and pass down to merge.
		realSigScript, _, _, _, err := sign(
			chainParams,
			tx,
			idx,
			sigScript,
			hashType,
			kdb,
			sdb,
			amt,
		)
		if err != nil {
			return nil, err
		}

		// Append the p2sh script as the last push in the script.
		builder := txscript.NewScriptBuilder()
		builder.AddOps(realSigScript)
		builder.AddData(sigScript)

		sigScript, _ = builder.Script()
		// TODO: keep a copy of the script for merging.
	}

	// Merge scripts. with any previous data, if any.
	mergedScript := mergeScripts(
		chainParams,
		tx,
		idx,
		pkScript,
		class,
		addresses,
		nrequired,
		sigScript,
		previousScript,
	)
	return mergedScript, nil
}

// sigHashKey return blake2b key by current height
func sigHashKey(tx *MsgTx) []byte {
	// https://github.com/zcash/zcash/blob/89f5ee5dec3fdfd70202baeaf74f09fa32bfb1a8/src/chainparams.cpp#L99
	// https://github.com/zcash/zcash/blob/master/src/consensus/upgrades.cpp#L11
	// activation levels are used for testnet because mainnet is already updated
	// TODO: need implement own complete chain params and use them
	branchID := make([]byte, 4)
	binary.LittleEndian.PutUint32(branchID, tx.GetConsensusBranchId())
	return append([]byte(blake2BSigHash), branchID...)
}

func isValidV5SigHashType(hashType txscript.SigHashType) bool {
	switch hashType {
	case txscript.SigHashAll,
		txscript.SigHashNone,
		txscript.SigHashSingle,
		txscript.SigHashAll | txscript.SigHashAnyOneCanPay,
		txscript.SigHashNone | txscript.SigHashAnyOneCanPay,
		txscript.SigHashSingle | txscript.SigHashAnyOneCanPay:
		return true
	default:
		return false
	}
}

// blake2bSignatureHash
func blake2bSignatureHash(
	subScript []byte,
	sigHashes *txscript.TxSigHashes,
	hashType txscript.SigHashType,
	tx *MsgTx,
	idx int,
	amt int64,
) (_ []byte, err error) {
	// As a sanity check, ensure the passed input index for the transaction
	// is valid.
	if idx < 0 || idx > len(tx.TxIn)-1 {
		return nil, fmt.Errorf("blake2bSignatureHash error: idx %d but %d txins", idx, len(tx.TxIn))
	}
	switch tx.Version {
	case versionOverwinter:
	case versionSapling:
	case versionV5:
	default:
		return nil, fmt.Errorf("blake2bSignatureHash error: version %d", tx.Version)
	}

	if tx.Version == versionV5 {
		if !isValidV5SigHashType(hashType) {
			return nil, fmt.Errorf("blake2bSignatureHash error: invalid v5 hash type %d", hashType)
		}
		if hashType&sigHashMask == txscript.SigHashSingle && idx >= len(tx.TxOut) {
			return nil, fmt.Errorf("blake2bSignatureHash error: SigHashSingle idx %d but %d txouts", idx, len(tx.TxOut))
		}
		if len(tx.InputAmounts) != len(tx.TxIn) {
			return nil, fmt.Errorf("blake2bSignatureHash error: got %d input amounts for %d txins", len(tx.InputAmounts), len(tx.TxIn))
		}
		if len(tx.InputScripts) != len(tx.TxIn) {
			return nil, fmt.Errorf("blake2bSignatureHash error: got %d input scripts for %d txins", len(tx.InputScripts), len(tx.TxIn))
		}
		if tx.InputAmounts[idx] != amt {
			return nil, fmt.Errorf("blake2bSignatureHash error: amount %d does not match input amount %d", amt, tx.InputAmounts[idx])
		}
		for inputIdx, inputAmount := range tx.InputAmounts {
			if inputAmount < 0 {
				return nil, fmt.Errorf("blake2bSignatureHash error: negative input amount %d at index %d", inputAmount, inputIdx)
			}
		}

		// S.1: header_digest
		var headerBuf bytes.Buffer
		_ = binary.Write(&headerBuf, binary.LittleEndian, uint32(tx.Version)|(1<<31))
		_ = binary.Write(&headerBuf, binary.LittleEndian, versionV5GroupID)
		_ = binary.Write(&headerBuf, binary.LittleEndian, tx.GetConsensusBranchId())
		_ = binary.Write(&headerBuf, binary.LittleEndian, tx.LockTime)
		_ = binary.Write(&headerBuf, binary.LittleEndian, tx.expiryHeight)
		headerDigest, err := blake2bHash(headerBuf.Bytes(), []byte("ZTxIdHeadersHash"))
		if err != nil {
			return nil, err
		}

		// S.2b: prevouts_sig_digest
		var prevoutsDigest chainhash.Hash
		if hashType&txscript.SigHashAnyOneCanPay == 0 {
			var buf bytes.Buffer
			for _, ti := range tx.TxIn {
				_, _ = buf.Write(ti.PreviousOutPoint.Hash[:])
				_ = binary.Write(&buf, binary.LittleEndian, ti.PreviousOutPoint.Index)
			}
			prevoutsDigest, err = blake2bHash(buf.Bytes(), []byte("ZTxIdPrevoutHash"))
		} else {
			prevoutsDigest, err = blake2bHash(nil, []byte("ZTxIdPrevoutHash"))
		}
		if err != nil {
			return nil, err
		}

		// S.2c: amounts_sig_digest
		var amountsDigest chainhash.Hash
		if hashType&txscript.SigHashAnyOneCanPay == 0 {
			var buf bytes.Buffer
			for _, val := range tx.InputAmounts {
				_ = binary.Write(&buf, binary.LittleEndian, val)
			}
			amountsDigest, err = blake2bHash(buf.Bytes(), []byte("ZTxTrAmountsHash"))
		} else {
			amountsDigest, err = blake2bHash(nil, []byte("ZTxTrAmountsHash"))
		}
		if err != nil {
			return nil, err
		}

		// S.2d: scriptpubkeys_sig_digest
		var scriptpubkeysDigest chainhash.Hash
		if hashType&txscript.SigHashAnyOneCanPay == 0 {
			var buf bytes.Buffer
			for _, script := range tx.InputScripts {
				_ = wire.WriteVarBytes(&buf, 0, script)
			}
			scriptpubkeysDigest, err = blake2bHash(buf.Bytes(), []byte("ZTxTrScriptsHash"))
		} else {
			scriptpubkeysDigest, err = blake2bHash(nil, []byte("ZTxTrScriptsHash"))
		}
		if err != nil {
			return nil, err
		}

		// S.2e: sequence_sig_digest
		var sequenceDigest chainhash.Hash
		if hashType&txscript.SigHashAnyOneCanPay == 0 {
			var buf bytes.Buffer
			for _, ti := range tx.TxIn {
				_ = binary.Write(&buf, binary.LittleEndian, ti.Sequence)
			}
			sequenceDigest, err = blake2bHash(buf.Bytes(), []byte("ZTxIdSequencHash"))
		} else {
			sequenceDigest, err = blake2bHash(nil, []byte("ZTxIdSequencHash"))
		}
		if err != nil {
			return nil, err
		}

		// S.2f: outputs_sig_digest
		var outputsDigest chainhash.Hash
		if hashType&sigHashMask != txscript.SigHashSingle && hashType&sigHashMask != txscript.SigHashNone {
			var buf bytes.Buffer
			for _, to := range tx.TxOut {
				_ = WriteTxOut(&buf, 0, tx.Version, to)
			}
			outputsDigest, err = blake2bHash(buf.Bytes(), []byte("ZTxIdOutputsHash"))
		} else if hashType&sigHashMask == txscript.SigHashSingle && idx < len(tx.TxOut) {
			var buf bytes.Buffer
			_ = WriteTxOut(&buf, 0, tx.Version, tx.TxOut[idx])
			outputsDigest, err = blake2bHash(buf.Bytes(), []byte("ZTxIdOutputsHash"))
		} else {
			outputsDigest, err = blake2bHash(nil, []byte("ZTxIdOutputsHash"))
		}
		if err != nil {
			return nil, err
		}

		// S.2g: txin_sig_digest
		var txinDigest chainhash.Hash
		if idx != math.MaxUint32 {
			var buf bytes.Buffer
			_, _ = buf.Write(tx.TxIn[idx].PreviousOutPoint.Hash[:])
			_ = binary.Write(&buf, binary.LittleEndian, tx.TxIn[idx].PreviousOutPoint.Index)
			_ = binary.Write(&buf, binary.LittleEndian, amt)
			_ = wire.WriteVarBytes(&buf, 0, tx.InputScripts[idx])
			_ = binary.Write(&buf, binary.LittleEndian, tx.TxIn[idx].Sequence)
			txinDigest, err = blake2bHash(buf.Bytes(), []byte("Zcash___TxInHash"))
		} else {
			txinDigest, err = blake2bHash(nil, []byte("Zcash___TxInHash"))
		}
		if err != nil {
			return nil, err
		}

		// S.2: transparent_sig_digest
		var transparentSigDigest chainhash.Hash
		{
			var buf bytes.Buffer
			_ = buf.WriteByte(byte(hashType))
			_, _ = buf.Write(prevoutsDigest[:])
			_, _ = buf.Write(amountsDigest[:])
			_, _ = buf.Write(scriptpubkeysDigest[:])
			_, _ = buf.Write(sequenceDigest[:])
			_, _ = buf.Write(outputsDigest[:])
			_, _ = buf.Write(txinDigest[:])
			transparentSigDigest, err = blake2bHash(buf.Bytes(), []byte("ZTxIdTranspaHash"))
			if err != nil {
				return nil, err
			}
		}

		// S.3: sapling_digest (empty)
		saplingDigest, err := blake2bHash(nil, []byte("ZTxIdSaplingHash"))
		if err != nil {
			return nil, err
		}

		// S.4: orchard_digest (empty)
		orchardDigest, err := blake2bHash(nil, []byte("ZTxIdOrchardHash"))
		if err != nil {
			return nil, err
		}

		// Combine to signature_digest
		var sigBuf bytes.Buffer
		_, _ = sigBuf.Write(headerDigest[:])
		_, _ = sigBuf.Write(transparentSigDigest[:])
		_, _ = sigBuf.Write(saplingDigest[:])
		_, _ = sigBuf.Write(orchardDigest[:])

		var consensusBranchIdLE [4]byte
		littleEndian.PutUint32(consensusBranchIdLE[:], tx.GetConsensusBranchId())
		sigPersonalization := append([]byte("ZcashTxHash_"), consensusBranchIdLE[:]...)

		sigDigest, err := blake2bHash(sigBuf.Bytes(), sigPersonalization)
		if err != nil {
			return nil, err
		}
		return sigDigest.CloneBytes(), nil
	}

	// We'll utilize this buffer throughout to incrementally calculate
	// the signature hash for this transaction.
	var sigHash bytes.Buffer

	// << GetHeader
	// First write out, then encode the transaction's nVersion number. Zcash current nVersion = 3
	var bVersion [4]byte
	binary.LittleEndian.PutUint32(bVersion[:], uint32(tx.Version)|(1<<31))
	sigHash.Write(bVersion[:])

	var versionGroupID = versionOverwinterGroupID
	if tx.Version == versionSapling {
		versionGroupID = versionSaplingGroupID
	}

	// << nVersionGroupId
	// Version group ID
	var nVersion [4]byte
	binary.LittleEndian.PutUint32(nVersion[:], versionGroupID)
	sigHash.Write(nVersion[:])

	// Next write out the possibly pre-calculated hashes for the sequence
	// numbers of all inputs, and the hashes of the previous outs for all
	// outputs.
	var zeroHash chainhash.Hash

	// << hashPrevouts
	// If anyone can pay isn't active, then we can use the cached
	// hashPrevOuts, otherwise we just write zeroes for the prev outs.
	if hashType&txscript.SigHashAnyOneCanPay == 0 {
		sigHash.Write(sigHashes.HashPrevOutsV0[:])
	} else {
		sigHash.Write(zeroHash[:])
	}

	// << hashSequence
	// If the sighash isn't anyone can pay, single, or none, the use the
	// cached hash sequences, otherwise write all zeroes for the
	// hashSequence.
	if hashType&txscript.SigHashAnyOneCanPay == 0 &&
		hashType&sigHashMask != txscript.SigHashSingle &&
		hashType&sigHashMask != txscript.SigHashNone {
		sigHash.Write(sigHashes.HashSequenceV0[:])
	} else {
		sigHash.Write(zeroHash[:])
	}

	// << hashOutputs
	// If the current signature mode isn't single, or none, then we can
	// re-use the pre-generated hashoutputs sighash fragment. Otherwise,
	// we'll serialize and add only the target output index to the signature
	// pre-image.
	if hashType&sigHashMask != txscript.SigHashSingle && hashType&sigHashMask != txscript.SigHashNone {
		sigHash.Write(sigHashes.HashOutputsV0[:])
	} else if hashType&sigHashMask == txscript.SigHashSingle && idx < len(tx.TxOut) {
		var (
			b bytes.Buffer
			h chainhash.Hash
		)
		if err = wire.WriteTxOut(&b, 0, 0, tx.TxOut[idx]); err != nil {
			return nil, err
		}

		if h, err = blake2bHash(b.Bytes(), []byte(outputsHashPersonalization)); err != nil {
			return nil, err
		}
		sigHash.Write(h.CloneBytes())
	} else {
		sigHash.Write(zeroHash[:])
	}

	// << hashJoinSplits
	sigHash.Write(zeroHash[:])

	// << hashShieldedSpends
	if tx.Version == versionSapling {
		sigHash.Write(zeroHash[:])
	}

	// << hashShieldedOutputs
	if tx.Version == versionSapling {
		sigHash.Write(zeroHash[:])
	}

	// << nLockTime
	var lockTime [4]byte
	binary.LittleEndian.PutUint32(lockTime[:], tx.LockTime)
	sigHash.Write(lockTime[:])

	// << nExpiryHeight
	var expiryTime [4]byte
	binary.LittleEndian.PutUint32(expiryTime[:], tx.expiryHeight)
	sigHash.Write(expiryTime[:])

	// << valueBalance
	if tx.Version == versionSapling {
		var valueBalance [8]byte
		binary.LittleEndian.PutUint64(valueBalance[:], 0)
		sigHash.Write(valueBalance[:])
	}

	// << nHashType
	var bHashType [4]byte
	binary.LittleEndian.PutUint32(bHashType[:], uint32(hashType))
	sigHash.Write(bHashType[:])

	if idx != math.MaxUint32 {
		// << prevout
		// Next, write the outpoint being spent.
		sigHash.Write(tx.TxIn[idx].PreviousOutPoint.Hash[:])
		var bIndex [4]byte
		binary.LittleEndian.PutUint32(bIndex[:], tx.TxIn[idx].PreviousOutPoint.Index)
		sigHash.Write(bIndex[:])

		// << scriptCode
		// For p2wsh outputs, and future outputs, the script code is the
		// original script, with all code separators removed, serialized
		// with a var int length prefix.
		// wire.WriteVarBytes(&sigHash, 0, subScript)
		if err = wire.WriteVarBytes(&sigHash, 0, subScript); err != nil {
			return nil, err
		}

		// << amount
		// Next, add the input amount, and sequence number of the input being
		// signed.
		if err = binary.Write(&sigHash, binary.LittleEndian, amt); err != nil {
			return nil, err
		}

		// << nSequence
		var bSequence [4]byte
		binary.LittleEndian.PutUint32(bSequence[:], tx.TxIn[idx].Sequence)
		sigHash.Write(bSequence[:])
	}

	var h chainhash.Hash
	if h, err = blake2bHash(sigHash.Bytes(), sigHashKey(tx)); err != nil {
		return nil, err
	}

	return h.CloneBytes(), nil
}

func sign(
	chainParams *chaincfg.Params,
	tx *MsgTx,
	idx int,
	subScript []byte,
	hashType txscript.SigHashType,
	kdb txscript.KeyDB,
	sdb txscript.ScriptDB,
	amt int64,
) ([]byte, txscript.ScriptClass, []btcutil.Address, int, error) {
	class, addresses, nrequired, err := txscript.ExtractPkScriptAddrs(subScript, chainParams)
	if err != nil {
		return nil, txscript.NonStandardTy, nil, 0, err
	}

	switch class {
	case txscript.PubKeyHashTy:
		// look up key for address
		key, compressed, err := kdb.GetKey(addresses[0])
		if err != nil {
			return nil, class, nil, 0, err
		}

		script, err := SignatureScript(tx, idx, subScript, hashType, key, compressed, amt)
		if err != nil {
			return nil, class, nil, 0, err
		}

		return script, class, addresses, nrequired, nil
	case txscript.ScriptHashTy:
		script, err := sdb.GetScript(addresses[0])
		if err != nil {
			return nil, class, nil, 0, err
		}

		return script, class, addresses, nrequired, nil
	case txscript.MultiSigTy:
		script, _ := signMultiSig(tx, idx, subScript, hashType, addresses, nrequired, kdb, amt)
		return script, class, addresses, nrequired, nil
	default:
		return nil, class, nil, 0,
			errors.New("can't sign unknown transactions")
	}
}

// signMultiSig signs as many of the outputs in the provided multisig script as
// possible. It returns the generated script and a boolean if the script fulfils
// the contract (i.e. nrequired signatures are provided).  Since it is arguably
// legal to not be able to sign any of the outputs, no error is returned.
func signMultiSig(
	tx *MsgTx,
	idx int,
	subScript []byte,
	hashType txscript.SigHashType,
	addresses []btcutil.Address,
	nRequired int,
	kdb txscript.KeyDB,
	amt int64,
) ([]byte, bool) {
	// We start with a single OP_FALSE to work around the (now standard)
	// but in the reference implementation that causes a spurious pop at
	// the end of OP_CHECKMULTISIG.
	builder := txscript.NewScriptBuilder().AddOp(txscript.OP_FALSE)
	signed := 0
	for _, addr := range addresses {
		key, _, err := kdb.GetKey(addr)
		if err != nil {
			continue
		}
		sig, err := RawTxInSignature(tx, idx, subScript, hashType, key, amt)
		if err != nil {
			continue
		}

		builder.AddData(sig)
		signed++
		if signed == nRequired {
			break
		}

	}

	script, _ := builder.Script()
	return script, signed == nRequired
}

// SignatureScript generate transaction hash and sign it
func SignatureScript(
	tx *MsgTx,
	idx int,
	subscript []byte,
	hashType txscript.SigHashType,
	privKey *btcec.PrivateKey,
	compress bool,
	amount int64,
) ([]byte, error) {
	sig, err := RawTxInSignature(tx, idx, subscript, hashType, privKey, amount)
	if err != nil {
		return nil, err
	}

	pk := privKey.PubKey()
	var pkData []byte
	if compress {
		pkData = pk.SerializeCompressed()
	} else {
		pkData = pk.SerializeUncompressed()
	}

	return txscript.NewScriptBuilder().AddData(sig).AddData(pkData).Script()
}

func mergeScripts(
	_ *chaincfg.Params,
	_ *MsgTx,
	_ int,
	_ []byte,
	class txscript.ScriptClass,
	_ []btcutil.Address,
	_ int,
	sigScript,
	prevScript []byte,
) []byte {
	switch class {
	// It doesn't actually make sense to merge anything other than multiig
	// and scripthash (because it could contain multisig). Everything else
	// has either zero signature, can't be spent, or has a single signature
	// which is either present or not. The other two cases are handled
	// above. In the conflict case here we just assume the longest is
	// correct (this matches behaviour of the reference implementation).
	default:
		if len(sigScript) > len(prevScript) {
			return sigScript
		}
		return prevScript
	}
}
