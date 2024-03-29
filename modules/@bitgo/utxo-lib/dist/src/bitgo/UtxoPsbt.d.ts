/// <reference types="node" />
import { Psbt as PsbtBase } from 'bip174';
import { Bip32Derivation, PsbtInput } from 'bip174/src/lib/interfaces';
import { BIP32Interface } from 'bip32';
import { HDSigner, Signer, Psbt, TxOutput, Network } from '..';
import { UtxoTransaction } from './UtxoTransaction';
import { Triple } from './types';
import { ProprietaryKeySearch, ProprietaryKeyValue } from './PsbtUtil';
declare type SignatureParams = {
    /** When true, and add the second (last) nonce and signature for a taproot key
     * path spend deterministically. Throws an error if done for the first nonce/signature
     * of a taproot keypath spend. Ignore for all other input types.
     */
    deterministic: boolean;
    /** Allowed sighash types */
    sighashTypes: number[];
};
export interface HDTaprootSigner extends HDSigner {
    /**
     * The path string must match /^m(\/\d+'?)+$/
     * ex. m/44'/0'/0'/1/23 levels with ' must be hard derivations
     */
    derivePath(path: string): HDTaprootSigner;
    /**
     * Input hash (the "message digest") for the signature algorithm
     * Return a 64 byte signature (32 byte r and 32 byte s in that order)
     */
    signSchnorr(hash: Buffer): Buffer;
}
/**
 * HD signer object for taproot p2tr musig2 key path sign
 */
export interface HDTaprootMusig2Signer extends HDSigner {
    /**
     * Musig2 requires signer's 32-bytes private key to be passed to it.
     */
    privateKey: Buffer;
    /**
     * The path string must match /^m(\/\d+'?)+$/
     * ex. m/44'/0'/0'/1/23 levels with ' must be hard derivations
     */
    derivePath(path: string): HDTaprootMusig2Signer;
}
export interface SchnorrSigner {
    publicKey: Buffer;
    signSchnorr(hash: Buffer): Buffer;
}
export interface Musig2Signer {
    publicKey: Buffer;
    privateKey: Buffer;
}
export interface TaprootSigner {
    leafHashes: Buffer[];
    signer: SchnorrSigner;
}
export interface PsbtOpts {
    network: Network;
    maximumFeeRate?: number;
    bip32PathsAbsolute?: boolean;
}
export declare class UtxoPsbt<Tx extends UtxoTransaction<bigint> = UtxoTransaction<bigint>> extends Psbt {
    private nonceStore;
    protected static transactionFromBuffer(buffer: Buffer, network: Network): UtxoTransaction<bigint>;
    static createPsbt(opts: PsbtOpts, data?: PsbtBase): UtxoPsbt;
    static fromBuffer(buffer: Buffer, opts: PsbtOpts): UtxoPsbt;
    static fromHex(data: string, opts: PsbtOpts): UtxoPsbt;
    /**
     * @param parent - Parent key. Matched with `bip32Derivations` using `fingerprint` property.
     * @param bip32Derivations - possible derivations for input or output
     * @param ignoreY - when true, ignore the y coordinate when matching public keys
     * @return derived bip32 node if matching derivation is found, undefined if none is found
     * @throws Error if more than one match is found
     */
    static deriveKeyPair(parent: BIP32Interface, bip32Derivations: Bip32Derivation[], { ignoreY }: {
        ignoreY: boolean;
    }): BIP32Interface | undefined;
    static deriveKeyPairForInput(bip32: BIP32Interface, input: PsbtInput): Buffer | undefined;
    get network(): Network;
    toHex(): string;
    /**
     * It is expensive to attempt to compute every output address using psbt.txOutputs[outputIndex]
     * to then just get the script. Here, we are doing the same thing as what txOutputs() does in
     * bitcoinjs-lib, but without iterating over each output.
     * @param outputIndex
     * @returns output script at the given index
     */
    getOutputScript(outputIndex: number): Buffer;
    getNonWitnessPreviousTxids(): string[];
    addNonWitnessUtxos(txBufs: Record<string, Buffer>): this;
    static fromTransaction(transaction: UtxoTransaction<bigint>, prevOutputs: TxOutput<bigint>[]): UtxoPsbt;
    getUnsignedTx(): UtxoTransaction<bigint>;
    protected static newTransaction(network: Network): UtxoTransaction<bigint>;
    protected get tx(): Tx;
    protected checkForSignatures(propName?: string): void;
    /**
     * @returns true if the input at inputIndex is a taproot key path.
     * Checks for presence of minimum required key path input fields and absence of any script path only input fields.
     */
    isTaprootKeyPathInput(inputIndex: number): boolean;
    /**
     * @returns true if the input at inputIndex is a taproot script path.
     * Checks for presence of minimum required script path input fields and absence of any key path only input fields.
     */
    isTaprootScriptPathInput(inputIndex: number): boolean;
    /**
     * @returns true if the input at inputIndex is a taproot
     */
    isTaprootInput(inputIndex: number): boolean;
    private isMultisigTaprootScript;
    /**
     * Mostly copied from bitcoinjs-lib/ts_src/psbt.ts
     */
    finalizeAllInputs(): this;
    finalizeTaprootInput(inputIndex: number): this;
    /**
     * Finalizes a taproot musig2 input by aggregating all partial sigs.
     * IMPORTANT: Always call validate* function before finalizing.
     */
    finalizeTaprootMusig2Input(inputIndex: number): this;
    finalizeTapInputWithSingleLeafScriptAndSignature(inputIndex: number): this;
    /**
     * Mostly copied from bitcoinjs-lib/ts_src/psbt.ts
     *
     * Unlike the function it overrides, this does not take a validator. In BitGo
     * context, we know how we want to validate so we just hard code the right
     * validator.
     */
    validateSignaturesOfAllInputs(): boolean;
    /**
     * @returns true iff any matching valid signature is found for a derived pub key from given HD key pair.
     */
    validateSignaturesOfInputHD(inputIndex: number, hdKeyPair: BIP32Interface): boolean;
    /**
     * @returns true iff any valid signature(s) are found from bip32 data of PSBT or for given pub key.
     */
    validateSignaturesOfInputCommon(inputIndex: number, pubkey?: Buffer): boolean;
    private getMusig2SessionKey;
    /**
     * @returns true for following cases.
     * If valid musig2 partial signatures exists for both 2 keys, it will also verify aggregated sig
     * for aggregated tweaked key (output key), otherwise only verifies partial sig.
     * If pubkey is passed in input, it will check sig only for that pubkey,
     * if no sig exits for such key, throws error.
     * For invalid state of input data, it will throw errors.
     */
    validateTaprootMusig2SignaturesOfInput(inputIndex: number, pubkey?: Buffer): boolean;
    validateTaprootSignaturesOfInput(inputIndex: number, pubkey?: Buffer): boolean;
    /**
     * @param inputIndex
     * @param rootNodes optional input root bip32 nodes to verify with. If it is not provided, globalXpub will be used.
     * @return array of boolean values. True when corresponding index in `publicKeys` has signed the transaction.
     * If no signature in the tx or no public key matching signature, the validation is considered as false.
     */
    getSignatureValidationArray(inputIndex: number, { rootNodes }?: {
        rootNodes?: Triple<BIP32Interface>;
    }): Triple<boolean>;
    /**
     * Mostly copied from bitcoinjs-lib/ts_src/psbt.ts
     */
    signAllInputsHD(hdKeyPair: HDTaprootSigner | HDTaprootMusig2Signer, params?: number[] | Partial<SignatureParams>): this;
    /**
     * Mostly copied from bitcoinjs-lib/ts_src/psbt.ts:signInputHD
     */
    signTaprootInputHD(inputIndex: number, hdKeyPair: HDTaprootSigner | HDTaprootMusig2Signer, { sighashTypes, deterministic }?: {
        sighashTypes?: number[] | undefined;
        deterministic?: boolean | undefined;
    }): this;
    signInput(inputIndex: number, keyPair: Signer, sighashTypes?: number[]): this;
    signInputHD(inputIndex: number, hdKeyPair: HDTaprootSigner | HDTaprootMusig2Signer, params?: number[] | Partial<SignatureParams>): this;
    private getMusig2Participants;
    private getMusig2Nonces;
    /**
     * Signs p2tr musig2 key path input with 2 aggregated keys.
     *
     * Note: Only can sign deterministically as the cosigner
     * @param inputIndex
     * @param signer - XY public key and private key are required
     * @param sighashTypes
     * @param deterministic If true, sign the musig input deterministically
     */
    signTaprootMusig2Input(inputIndex: number, signer: Musig2Signer, { sighashTypes, deterministic }?: {
        sighashTypes?: number[] | undefined;
        deterministic?: boolean | undefined;
    }): this;
    signTaprootInput(inputIndex: number, signer: SchnorrSigner, leafHashes: Buffer[], sighashTypes?: number[]): this;
    private getTaprootOutputScript;
    private getTaprootHashForSig;
    /**
     * Adds proprietary key value pair to PSBT input.
     * Default identifierEncoding is utf-8 for identifier.
     */
    addProprietaryKeyValToInput(inputIndex: number, keyValueData: ProprietaryKeyValue): this;
    /**
     * Adds or updates (if exists) proprietary key value pair to PSBT input.
     * Default identifierEncoding is utf-8 for identifier.
     */
    addOrUpdateProprietaryKeyValToInput(inputIndex: number, keyValueData: ProprietaryKeyValue): this;
    /**
     * To search any data from proprietary key value against keydata.
     * Default identifierEncoding is utf-8 for identifier.
     */
    getProprietaryKeyVals(inputIndex: number, keySearch?: ProprietaryKeySearch): ProprietaryKeyValue[];
    /**
     * To delete any data from proprietary key value.
     * Default identifierEncoding is utf-8 for identifier.
     */
    deleteProprietaryKeyVals(inputIndex: number, keysToDelete?: ProprietaryKeySearch): this;
    private createMusig2NonceForInput;
    private setMusig2NoncesInner;
    /**
     * Generates and sets MuSig2 nonce to taproot key path input at inputIndex.
     * If input is not a taproot key path, no action.
     *
     * @param inputIndex input index
     * @param keyPair derived key pair
     * @param sessionId Optional extra entropy. If provided it must either be a counter unique to this secret key,
     * (converted to an array of 32 bytes), or 32 uniformly random bytes.
     * @param deterministic If true, set the cosigner nonce deterministically
     */
    setInputMusig2Nonce(inputIndex: number, derivedKeyPair: BIP32Interface, params?: {
        sessionId?: Buffer;
        deterministic?: boolean;
    }): this;
    /**
     * Generates and sets MuSig2 nonce to taproot key path input at inputIndex.
     * If input is not a taproot key path, no action.
     *
     * @param inputIndex input index
     * @param keyPair HD root key pair
     * @param sessionId Optional extra entropy. If provided it must either be a counter unique to this secret key,
     * (converted to an array of 32 bytes), or 32 uniformly random bytes.
     * @param deterministic If true, set the cosigner nonce deterministically
     */
    setInputMusig2NonceHD(inputIndex: number, keyPair: BIP32Interface, params?: {
        sessionId?: Buffer;
        deterministic?: boolean;
    }): this;
    /**
     * Generates and sets MuSig2 nonce to all taproot key path inputs. Other inputs will be skipped.
     *
     * @param inputIndex input index
     * @param keyPair derived key pair
     * @param sessionId Optional extra entropy. If provided it must either be a counter unique to this secret key,
     * (converted to an array of 32 bytes), or 32 uniformly random bytes.
     */
    setAllInputsMusig2Nonce(keyPair: BIP32Interface, params?: {
        sessionId?: Buffer;
        deterministic?: boolean;
    }): this;
    /**
     * Generates and sets MuSig2 nonce to all taproot key path inputs. Other inputs will be skipped.
     *
     * @param inputIndex input index
     * @param keyPair HD root key pair
     * @param sessionId Optional extra entropy. If provided it must either be a counter unique to this secret key,
     * (converted to an array of 32 bytes), or 32 uniformly random bytes.
     */
    setAllInputsMusig2NonceHD(keyPair: BIP32Interface, params?: {
        sessionId?: Buffer;
        deterministic?: boolean;
    }): this;
    clone(): this;
    extractTransaction(disableFeeCheck?: boolean): UtxoTransaction<bigint>;
}
export {};
//# sourceMappingURL=UtxoPsbt.d.ts.map