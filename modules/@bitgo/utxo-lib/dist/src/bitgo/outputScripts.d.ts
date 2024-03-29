/// <reference types="node" />
import * as bitcoinjs from 'bitcoinjs-lib';
import { Network } from '..';
import { Triple, Tuple } from './types';
export { scriptTypeForChain } from './wallet/chains';
export declare const scriptTypeP2shP2pk = "p2shP2pk";
export declare type ScriptTypeP2shP2pk = typeof scriptTypeP2shP2pk;
export declare const scriptTypes2Of3: readonly ["p2sh", "p2shP2wsh", "p2wsh", "p2tr", "p2trMusig2"];
export declare type ScriptType2Of3 = (typeof scriptTypes2Of3)[number];
export declare function isScriptType2Of3(t: string): t is ScriptType2Of3;
export declare type ScriptType = ScriptTypeP2shP2pk | ScriptType2Of3;
/**
 * @return true iff scriptType requires witness data
 */
export declare function hasWitnessData(scriptType: ScriptType): scriptType is 'p2shP2wsh' | 'p2wsh' | 'p2tr' | 'p2trMusig2';
/**
 * @param network
 * @param scriptType
 * @return true iff script type is supported for network
 */
export declare function isSupportedScriptType(network: Network, scriptType: ScriptType): boolean;
/**
 * @param t
 * @return string prevOut as defined in PREVOUT_TYPES (bitcoinjs-lib/.../transaction_builder.js)
 */
export declare function scriptType2Of3AsPrevOutType(t: ScriptType2Of3): string;
export declare type SpendableScript = {
    scriptPubKey: Buffer;
    redeemScript?: Buffer;
    witnessScript?: Buffer;
};
export declare type SpendScriptP2tr = {
    controlBlock: Buffer;
    witnessScript: Buffer;
    leafVersion: number;
    leafHash: Buffer;
};
/**
 * Tweak data holder for P2tr Musig2 key path.
 */
export declare type KeyPathP2trMusig2 = {
    internalPubkey: Buffer;
    outputPubkey: Buffer;
    taptreeRoot: Buffer;
};
/**
 * Return scripts for p2sh-p2pk (used for BCH/BSV replay protection)
 * @param pubkey
 */
export declare function createOutputScriptP2shP2pk(pubkey: Buffer): SpendableScript;
export declare function getOutputScript(scriptType: 'p2sh' | 'p2shP2wsh' | 'p2wsh', conditionScript: Buffer): Buffer;
/**
 * Return scripts for 2-of-3 multisig output
 * @param pubkeys - the key triple for multisig
 * @param scriptType
 * @param network - if set, performs sanity check for scriptType support
 * @returns {{redeemScript, witnessScript, scriptPubKey}}
 */
export declare function createOutputScript2of3(pubkeys: Buffer[], scriptType: ScriptType2Of3, network?: Network): SpendableScript;
export declare function toXOnlyPublicKey(b: Buffer): Buffer;
/**
 * Validates size of the pub key for 32 bytes and returns the same iff true.
 */
export declare function checkXOnlyPublicKey(b: Buffer): Buffer;
/**
 * Validates size of the pub key for 32 bytes and returns the same iff true.
 */
export declare function checkPlainPublicKey(b: Buffer): Buffer;
export declare function checkTapMerkleRoot(b: Buffer): Buffer;
export declare function checkTxHash(b: Buffer): Buffer;
export declare function createPaymentP2tr(pubkeys: Triple<Buffer>, redeemIndex?: number | {
    signer: Buffer;
    cosigner: Buffer;
}): bitcoinjs.Payment;
export declare function createPaymentP2trMusig2(pubkeys: Triple<Buffer>, redeemIndex?: number | {
    signer: Buffer;
    cosigner: Buffer;
}): bitcoinjs.Payment;
export declare function getLeafHash(params: bitcoinjs.Payment | {
    publicKeys: Triple<Buffer>;
    signer: Buffer;
    cosigner: Buffer;
}): Buffer;
export declare function createKeyPathP2trMusig2(pubkeys: Triple<Buffer>): KeyPathP2trMusig2;
export declare function createSpendScriptP2tr(pubkeys: Triple<Buffer>, keyCombination: Tuple<Buffer>): SpendScriptP2tr;
export declare function createSpendScriptP2trMusig2(pubkeys: Triple<Buffer>, keyCombination: Tuple<Buffer>): SpendScriptP2tr;
//# sourceMappingURL=outputScripts.d.ts.map