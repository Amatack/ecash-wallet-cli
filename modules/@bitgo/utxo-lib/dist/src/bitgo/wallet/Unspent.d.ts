/// <reference types="node" />
import { UtxoTransactionBuilder } from '../UtxoTransactionBuilder';
import { WalletUnspentSigner } from './WalletUnspentSigner';
import { KeyName, RootWalletKeys } from './WalletKeys';
import { UtxoTransaction } from '../UtxoTransaction';
import { Triple } from '../types';
import { UnspentWithPrevTx, Unspent } from '../Unspent';
import { ChainCode } from './chains';
import { UtxoPsbt } from '../UtxoPsbt';
/** Final (non-replaceable) */
export declare const TX_INPUT_SEQUENCE_NUMBER_FINAL = 4294967295;
/** Non-Final (Replaceable)
 * Reference: https://github.com/bitcoin/bitcoin/blob/v25.1/src/rpc/rawtransaction_util.cpp#L49
 * */
export declare const MAX_BIP125_RBF_SEQUENCE: number;
export interface WalletUnspent<TNumber extends number | bigint = number> extends Unspent<TNumber> {
    chain: ChainCode;
    index: number;
    witnessScript?: string;
    valueString?: string;
}
export interface NonWitnessWalletUnspent<TNumber extends number | bigint = number> extends UnspentWithPrevTx<TNumber>, WalletUnspent<TNumber> {
}
export declare function isWalletUnspent<TNumber extends number | bigint>(u: Unspent<TNumber>): u is WalletUnspent<TNumber>;
export declare function signInputWithUnspent<TNumber extends number | bigint>(txBuilder: UtxoTransactionBuilder<TNumber>, inputIndex: number, unspent: WalletUnspent<TNumber>, unspentSigner: WalletUnspentSigner<RootWalletKeys>): void;
/**
 * @param tx
 * @param inputIndex
 * @param unspents
 * @param walletKeys
 * @return triple of booleans indicating a valid signature for each pubkey
 */
export declare function verifySignatureWithUnspent<TNumber extends number | bigint>(tx: UtxoTransaction<TNumber>, inputIndex: number, unspents: Unspent<TNumber>[], walletKeys: RootWalletKeys): Triple<boolean>;
/**
 * @deprecated
 * Used in certain legacy signing methods that do not derive signing data from index/chain
 */
export interface WalletUnspentLegacy<TNumber extends number | bigint = number> extends WalletUnspent<TNumber> {
    /** @deprecated - obviated by signWithUnspent */
    redeemScript?: string;
    /** @deprecated - obviated by verifyWithUnspent */
    witnessScript?: string;
}
/**
 * @param psbt
 * @param inputIndex
 * @param id Unspent ID
 * @returns true iff the unspent ID on the unspent and psbt input match
 */
export declare function psbtIncludesUnspentAtIndex(psbt: UtxoPsbt, inputIndex: number, id: string): boolean;
/**
 * Update the psbt input at the given index
 * @param psbt
 * @param inputIndex
 * @param u
 * @param redeemScript Only overrides if there is no redeemScript in the input currently
 */
export declare function updateReplayProtectionUnspentToPsbt(psbt: UtxoPsbt, inputIndex: number, u: Unspent<bigint>, redeemScript?: Buffer, customParams?: {
    skipNonWitnessUtxo?: boolean;
}): void;
export declare function addReplayProtectionUnspentToPsbt(psbt: UtxoPsbt, u: Unspent<bigint>, redeemScript: Buffer, customParams?: {
    skipNonWitnessUtxo?: boolean;
}): void;
/**
 * Update the PSBT with the unspent data for the input at the given index if the data is not there already.
 *
 * If skipNonWitnessUtxo is true, then the nonWitnessUtxo will not be added for an input that requires it (e.g. non-segwit)
 * and instead the witnessUtxo will be added
 *
 * @param psbt
 * @param inputIndex
 * @param u
 * @param rootWalletKeys
 * @param signer
 * @param cosigner
 * @param customParams
 */
export declare function updateWalletUnspentForPsbt(psbt: UtxoPsbt, inputIndex: number, u: WalletUnspent<bigint>, rootWalletKeys: RootWalletKeys, signer: KeyName, cosigner: KeyName, customParams?: {
    skipNonWitnessUtxo?: boolean;
}): void;
export declare function addWalletUnspentToPsbt(psbt: UtxoPsbt, u: WalletUnspent<bigint>, rootWalletKeys: RootWalletKeys, signer: KeyName, cosigner: KeyName, customParams?: {
    isReplaceableByFee?: boolean;
    skipNonWitnessUtxo?: boolean;
}): void;
//# sourceMappingURL=Unspent.d.ts.map