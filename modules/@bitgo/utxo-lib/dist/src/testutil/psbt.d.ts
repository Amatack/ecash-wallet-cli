import { ScriptType, ScriptType2Of3 } from '../bitgo/outputScripts';
import { KeyName, RootWalletKeys, Unspent, UtxoPsbt, UtxoTransaction } from '../bitgo';
import { Network } from '../networks';
/**
 * input script type and value.
 * use p2trMusig2 for p2trMusig2 script path.
 * use taprootKeyPathSpend for p2trMusig2 key path.
 */
export declare type InputScriptType = ScriptType | 'taprootKeyPathSpend';
export declare type OutputScriptType = ScriptType2Of3;
/**
 * input script type and value
 */
export interface Input {
    scriptType: InputScriptType;
    value: bigint;
}
/**
 * should set either address or scriptType, never both.
 * set isInternalAddress=true for internal output address
 */
export interface Output {
    address?: string;
    scriptType?: OutputScriptType;
    value: bigint;
    isInternalAddress?: boolean;
}
/**
 * array of supported input script types.
 * use p2trMusig2 for p2trMusig2 script path.
 * use taprootKeyPathSpend for p2trMusig2 key path.
 */
export declare const inputScriptTypes: readonly ["p2sh", "p2shP2wsh", "p2wsh", "p2tr", "p2trMusig2", "taprootKeyPathSpend", "p2shP2pk"];
/**
 * array of supported output script types.
 */
export declare const outputScriptTypes: readonly ["p2sh", "p2shP2wsh", "p2wsh", "p2tr", "p2trMusig2"];
/**
 * create unspent object from input script type, index, network and root wallet key.
 */
export declare function toUnspent(input: Input, index: number, network: Network, rootWalletKeys: RootWalletKeys): Unspent<bigint>;
/**
 * returns signer and cosigner names for InputScriptType.
 * user and undefined as signer and cosigner respectively for p2shP2pk.
 * user and backup as signer and cosigner respectively for p2trMusig2.
 * user and bitgo as signer and cosigner respectively for other input script types.
 */
export declare function getSigners(inputType: InputScriptType): {
    signerName: KeyName;
    cosignerName?: KeyName;
};
/**
 * signs with first or second signature for single input.
 * p2shP2pk is signed only with first sign.
 */
export declare function signPsbtInput(psbt: UtxoPsbt, input: Input, inputIndex: number, rootWalletKeys: RootWalletKeys, sign: 'halfsigned' | 'fullsigned', params?: {
    signers?: {
        signerName: KeyName;
        cosignerName?: KeyName;
    };
    deterministic?: boolean;
    skipNonWitnessUtxo?: boolean;
}): void;
/**
 * signs with first or second signature for all inputs.
 * p2shP2pk is signed only with first sign.
 */
export declare function signAllPsbtInputs(psbt: UtxoPsbt, inputs: Input[], rootWalletKeys: RootWalletKeys, sign: 'halfsigned' | 'fullsigned', params?: {
    signers?: {
        signerName: KeyName;
        cosignerName?: KeyName;
    };
    deterministic?: boolean;
    skipNonWitnessUtxo?: boolean;
}): void;
/**
 * construct psbt for given inputs, outputs, network and root wallet keys.
 */
export declare function constructPsbt(inputs: Input[], outputs: Output[], network: Network, rootWalletKeys: RootWalletKeys, sign: 'unsigned' | 'halfsigned' | 'fullsigned', params?: {
    signers?: {
        signerName: KeyName;
        cosignerName?: KeyName;
    };
    deterministic?: boolean;
    skipNonWitnessUtxo?: boolean;
}): UtxoPsbt;
/**
 * Verifies signatures of fully signed tx (with taproot key path support).
 * NOTE: taproot key path tx can only be built and signed with PSBT.
 */
export declare function verifyFullySignedSignatures(tx: UtxoTransaction<bigint>, unspents: Unspent<bigint>[], walletKeys: RootWalletKeys, signer: KeyName, cosigner: KeyName): boolean;
//# sourceMappingURL=psbt.d.ts.map