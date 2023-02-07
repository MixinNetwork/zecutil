package zecutil

import (
	"bytes"
	"encoding/binary"
	"math"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	prevoutsHashPersonalization = "ZcashPrevoutHash"
	sequenceHashPersonalization = "ZcashSequencHash"
	outputsHashPersonalization  = "ZcashOutputsHash"
)

// NewTxSigHashes computes, and returns the cached sighashes of the given
// transaction.
func NewTxSigHashes(tx *MsgTx) *txscript.TxSigHashes {
	var (
		sigHashes txscript.TxSigHashes
		zeroHash  chainhash.Hash
	)

	// Base segwit (witness version v0), and taproot (witness version v1)
	// differ in how the set of pre-computed cached sighash midstate is
	// computed. For taproot, the prevouts, sequence, and outputs are
	// computed as normal, but a single sha256 hash invocation is used. In
	// addition, the hashes of all the previous input amounts and scripts
	// are included as well.
	//
	// Based on the above distinction, we'll run through all the referenced
	// inputs to determine what we need to compute.
	var hasV0Inputs bool
	for _, txIn := range tx.TxIn {
		// If this is a coinbase input, then we know that we only need
		// the v0 midstate (though it won't be used) in this instance.
		outpoint := txIn.PreviousOutPoint
		if outpoint.Index == math.MaxUint32 && outpoint.Hash == zeroHash {
			hasV0Inputs = true
			continue
		}
	}

	// Now that we know which cached midstate we need to calculate, we can
	// go ahead and do so.
	//
	// First, we can calculate the information that both segwit v0 and v1
	// need: the prevout, sequence and output hashes. For v1 the only
	// difference is that this is a single instead of a double hash.
	//
	// Both v0 and v1 share this base data computed using a sha256 single
	// hash.
	// sigHashes.HashPrevOutsV1 = calcHashPrevOuts(tx)
	// sigHashes.HashSequenceV1 = calcHashSequence(tx)
	// sigHashes.HashOutputsV1 = calcHashOutputs(tx)

	// The v0 data is the same as the v1 (newer data) but it uses a double
	// hash instead.
	if hasV0Inputs {
		sigHashes.HashPrevOutsV0 = chainhash.HashH(
			sigHashes.HashPrevOutsV0[:],
		)
		sigHashes.HashSequenceV0 = chainhash.HashH(
			sigHashes.HashSequenceV0[:],
		)
		sigHashes.HashOutputsV0 = chainhash.HashH(
			sigHashes.HashOutputsV0[:],
		)
	}

	return &sigHashes
}

// calcHashPrevOuts calculates a single hash of all the previous outputs
// (txid:index) referenced within the passed transaction. This calculated hash
// can be re-used when validating all inputs spending segwit outputs, with a
// signature hash type of SigHashAll. This allows validation to re-use previous
// hashing computation, reducing the complexity of validating SigHashAll inputs
// from  O(N^2) to O(N).
func calcHashPrevOuts(tx *MsgTx) chainhash.Hash {
	var b bytes.Buffer
	for _, in := range tx.TxIn {
		// First write out the 32-byte transaction ID one of whose
		// outputs are being referenced by this input.
		b.Write(in.PreviousOutPoint.Hash[:])

		// Next, we'll encode the index of the referenced output as a
		// little endian integer.
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], in.PreviousOutPoint.Index)
		b.Write(buf[:])
	}

	return chainhash.HashH(b.Bytes())
}

// calcHashSequence computes an aggregated hash of each of the sequence numbers
// within the inputs of the passed transaction. This single hash can be re-used
// when validating all inputs spending segwit outputs, which include signatures
// using the SigHashAll sighash type. This allows validation to re-use previous
// hashing computation, reducing the complexity of validating SigHashAll inputs
// from O(N^2) to O(N).
func calcHashSequence(tx *MsgTx) chainhash.Hash {
	var b bytes.Buffer
	for _, in := range tx.TxIn {
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], in.Sequence)
		b.Write(buf[:])
	}

	return chainhash.HashH(b.Bytes())
}

// calcHashOutputs computes a hash digest of all outputs created by the
// transaction encoded using the wire format. This single hash can be re-used
// when validating all inputs spending witness programs, which include
// signatures using the SigHashAll sighash type. This allows computation to be
// cached, reducing the total hashing complexity from O(N^2) to O(N).
func calcHashOutputs(tx *MsgTx) chainhash.Hash {
	var b bytes.Buffer
	for _, out := range tx.TxOut {
		wire.WriteTxOut(&b, 0, 0, out)
	}

	return chainhash.HashH(b.Bytes())
}
