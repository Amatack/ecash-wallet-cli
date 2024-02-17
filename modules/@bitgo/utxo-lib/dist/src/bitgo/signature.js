"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.signInput2Of3 = exports.signInputP2shP2pk = exports.getDefaultSigHash = exports.verifySignatureWithPublicKey = exports.verifySignatureWithPublicKeys = exports.getSignaturesWithPublicKeys = exports.verifySignature = exports.getSignatureVerifications = void 0;
const bitcoinjs_lib_1 = require("bitcoinjs-lib");
const UtxoTransaction_1 = require("./UtxoTransaction");
const outputScripts_1 = require("./outputScripts");
const networks_1 = require("../networks");
const noble_ecc_1 = require("../noble_ecc");
const parseInput_1 = require("./parseInput");
const taproot_1 = require("../taproot");
/**
 * @deprecated - use {@see verifySignaturesWithPublicKeys} instead
 * Get signature verifications for multsig transaction
 * @param transaction
 * @param inputIndex
 * @param amount - must be set for segwit transactions and BIP143 transactions
 * @param verificationSettings
 * @param prevOutputs - must be set for p2tr and p2trMusig2 transactions
 * @returns SignatureVerification[] - in order of parsed non-empty signatures
 */
function getSignatureVerifications(transaction, inputIndex, amount, verificationSettings = {}, prevOutputs) {
    /* istanbul ignore next */
    if (!transaction.ins) {
        throw new Error(`invalid transaction`);
    }
    const input = transaction.ins[inputIndex];
    /* istanbul ignore next */
    if (!input) {
        throw new Error(`no input at index ${inputIndex}`);
    }
    if ((!input.script || input.script.length === 0) && input.witness.length === 0) {
        // Unsigned input: no signatures.
        return [];
    }
    const parsedScript = parseInput_1.parseSignatureScript2Of3(input);
    if (parsedScript.scriptType === 'taprootKeyPathSpend' || parsedScript.scriptType === 'taprootScriptPathSpend') {
        if (parsedScript.scriptType === 'taprootKeyPathSpend' &&
            (verificationSettings.signatureIndex || verificationSettings.publicKey)) {
            throw new Error(`signatureIndex and publicKey parameters not supported for taprootKeyPathSpend`);
        }
        if (verificationSettings.signatureIndex !== undefined) {
            throw new Error(`signatureIndex parameter not supported for taprootScriptPathSpend`);
        }
        if (!prevOutputs) {
            throw new Error(`prevOutputs not set`);
        }
        if (prevOutputs.length !== transaction.ins.length) {
            throw new Error(`prevOutputs length ${prevOutputs.length}, expected ${transaction.ins.length}`);
        }
    }
    if (parsedScript.scriptType !== 'taprootKeyPathSpend' &&
        parsedScript.scriptType !== 'taprootScriptPathSpend' &&
        prevOutputs) {
        const prevOutScript = prevOutputs[inputIndex].script;
        const output = outputScripts_1.getOutputScript(parsedScript.scriptType, parsedScript.pubScript);
        if (!prevOutScript.equals(output)) {
            throw new Error(`prevout script ${prevOutScript.toString('hex')} does not match computed script ${output.toString('hex')}`);
        }
    }
    let publicKeys;
    if (parsedScript.scriptType === 'taprootKeyPathSpend') {
        if (!prevOutputs) {
            throw new Error(`prevOutputs not set`);
        }
        publicKeys = [taproot_1.getTaprootOutputKey(prevOutputs[inputIndex].script)];
    }
    else {
        publicKeys = parsedScript.publicKeys.filter((buf) => verificationSettings.publicKey === undefined ||
            verificationSettings.publicKey.equals(buf) ||
            verificationSettings.publicKey.slice(1).equals(buf));
    }
    const signatures = parsedScript.signatures
        .filter((s) => s && s.length)
        .filter((s, i) => verificationSettings.signatureIndex === undefined || verificationSettings.signatureIndex === i);
    return signatures.map((signatureBuffer) => {
        if (signatureBuffer === 0 || signatureBuffer.length === 0) {
            return { signedBy: undefined, signature: undefined };
        }
        let hashType = bitcoinjs_lib_1.Transaction.SIGHASH_DEFAULT;
        if (signatureBuffer.length === 65) {
            hashType = signatureBuffer[signatureBuffer.length - 1];
            signatureBuffer = signatureBuffer.slice(0, -1);
        }
        if (parsedScript.scriptType === 'taprootScriptPathSpend') {
            if (!prevOutputs) {
                throw new Error(`prevOutputs not set`);
            }
            const { controlBlock, pubScript } = parsedScript;
            const leafHash = bitcoinjs_lib_1.taproot.getTapleafHash(noble_ecc_1.ecc, controlBlock, pubScript);
            const signatureHash = transaction.hashForWitnessV1(inputIndex, prevOutputs.map(({ script }) => script), prevOutputs.map(({ value }) => value), hashType, leafHash);
            const signedBy = publicKeys.filter((k) => Buffer.isBuffer(signatureBuffer) && noble_ecc_1.ecc.verifySchnorr(signatureHash, k, signatureBuffer));
            if (signedBy.length === 0) {
                return { signedBy: undefined, signature: undefined };
            }
            if (signedBy.length === 1) {
                return { signedBy: signedBy[0], signature: signatureBuffer };
            }
            throw new Error(`illegal state: signed by multiple public keys`);
        }
        else if (parsedScript.scriptType === 'taprootKeyPathSpend') {
            if (!prevOutputs) {
                throw new Error(`prevOutputs not set`);
            }
            const signatureHash = transaction.hashForWitnessV1(inputIndex, prevOutputs.map(({ script }) => script), prevOutputs.map(({ value }) => value), hashType);
            const result = noble_ecc_1.ecc.verifySchnorr(signatureHash, publicKeys[0], signatureBuffer);
            return result
                ? { signedBy: publicKeys[0], signature: signatureBuffer }
                : { signedBy: undefined, signature: undefined };
        }
        else {
            // slice the last byte from the signature hash input because it's the hash type
            const { signature, hashType } = bitcoinjs_lib_1.ScriptSignature.decode(signatureBuffer);
            const transactionHash = parsedScript.scriptType === 'p2shP2wsh' || parsedScript.scriptType === 'p2wsh'
                ? transaction.hashForWitnessV0(inputIndex, parsedScript.pubScript, amount, hashType)
                : transaction.hashForSignatureByNetwork(inputIndex, parsedScript.pubScript, amount, hashType);
            const signedBy = publicKeys.filter((publicKey) => noble_ecc_1.ecc.verify(transactionHash, publicKey, signature, 
            /*
              Strict verification (require lower-S value), as required by BIP-0146
              https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki
              https://github.com/bitcoin-core/secp256k1/blob/ac83be33/include/secp256k1.h#L478-L508
              https://github.com/bitcoinjs/tiny-secp256k1/blob/v1.1.6/js.js#L231-L233
            */
            true));
            if (signedBy.length === 0) {
                return { signedBy: undefined, signature: undefined };
            }
            if (signedBy.length === 1) {
                return { signedBy: signedBy[0], signature: signatureBuffer };
            }
            throw new Error(`illegal state: signed by multiple public keys`);
        }
    });
}
exports.getSignatureVerifications = getSignatureVerifications;
/**
 * @deprecated use {@see verifySignatureWithPublicKeys} instead
 * @param transaction
 * @param inputIndex
 * @param amount
 * @param verificationSettings - if publicKey is specified, returns true iff any signature is signed by publicKey.
 * @param prevOutputs - must be set for p2tr transactions
 */
function verifySignature(transaction, inputIndex, amount, verificationSettings = {}, prevOutputs) {
    const signatureVerifications = getSignatureVerifications(transaction, inputIndex, amount, verificationSettings, prevOutputs).filter((v) => 
    // If no publicKey is set in verificationSettings, all signatures must be valid.
    // Otherwise, a single valid signature by the specified pubkey is sufficient.
    verificationSettings.publicKey === undefined ||
        (v.signedBy !== undefined &&
            (verificationSettings.publicKey.equals(v.signedBy) ||
                verificationSettings.publicKey.slice(1).equals(v.signedBy))));
    return signatureVerifications.length > 0 && signatureVerifications.every((v) => v.signedBy !== undefined);
}
exports.verifySignature = verifySignature;
/**
 * @param v
 * @param publicKey
 * @return true iff signature is by publicKey (or xonly variant of publicKey)
 */
function isSignatureByPublicKey(v, publicKey) {
    return (!!v.signedBy &&
        (v.signedBy.equals(publicKey) ||
            /* for p2tr signatures, we pass the pubkey in 33-byte format recover it from the signature in 32-byte format */
            (publicKey.length === 33 && isSignatureByPublicKey(v, publicKey.slice(1)))));
}
/**
 * @param transaction
 * @param inputIndex
 * @param prevOutputs
 * @param publicKeys
 * @return array with signature corresponding to n-th key, undefined if no match found
 */
function getSignaturesWithPublicKeys(transaction, inputIndex, prevOutputs, publicKeys) {
    if (transaction.ins.length !== prevOutputs.length) {
        throw new Error(`input length must match prevOutputs length`);
    }
    const signatureVerifications = getSignatureVerifications(transaction, inputIndex, prevOutputs[inputIndex].value, {}, prevOutputs);
    return publicKeys.map((publicKey) => {
        const v = signatureVerifications.find((v) => isSignatureByPublicKey(v, publicKey));
        return v ? v.signature : undefined;
    });
}
exports.getSignaturesWithPublicKeys = getSignaturesWithPublicKeys;
/**
 * @param transaction
 * @param inputIndex
 * @param prevOutputs - transaction outputs for inputs
 * @param publicKeys - public keys to check signatures for
 * @return array of booleans indicating a valid signature for every pubkey in _publicKeys_
 */
function verifySignatureWithPublicKeys(transaction, inputIndex, prevOutputs, publicKeys) {
    return getSignaturesWithPublicKeys(transaction, inputIndex, prevOutputs, publicKeys).map((s) => s !== undefined);
}
exports.verifySignatureWithPublicKeys = verifySignatureWithPublicKeys;
/**
 * Wrapper for {@see verifySignatureWithPublicKeys} for single pubkey
 * @param transaction
 * @param inputIndex
 * @param prevOutputs
 * @param publicKey
 * @return true iff signature is valid
 */
function verifySignatureWithPublicKey(transaction, inputIndex, prevOutputs, publicKey) {
    return verifySignatureWithPublicKeys(transaction, inputIndex, prevOutputs, [publicKey])[0];
}
exports.verifySignatureWithPublicKey = verifySignatureWithPublicKey;
function getDefaultSigHash(network, scriptType) {
    switch (networks_1.getMainnet(network)) {
        case networks_1.networks.bitcoincash:
        case networks_1.networks.bitcoinsv:
        case networks_1.networks.bitcoingold:
        case networks_1.networks.ecash:
            return bitcoinjs_lib_1.Transaction.SIGHASH_ALL | UtxoTransaction_1.UtxoTransaction.SIGHASH_FORKID;
        default:
            switch (scriptType) {
                case 'p2tr':
                case 'p2trMusig2':
                    return bitcoinjs_lib_1.Transaction.SIGHASH_DEFAULT;
                default:
                    return bitcoinjs_lib_1.Transaction.SIGHASH_ALL;
            }
    }
}
exports.getDefaultSigHash = getDefaultSigHash;
function signInputP2shP2pk(txBuilder, vin, keyPair) {
    const prevOutScriptType = 'p2sh-p2pk';
    const { redeemScript, witnessScript } = outputScripts_1.createOutputScriptP2shP2pk(keyPair.publicKey);
    keyPair.network = txBuilder.network;
    txBuilder.sign({
        vin,
        prevOutScriptType,
        keyPair,
        hashType: getDefaultSigHash(txBuilder.network),
        redeemScript,
        witnessScript,
        witnessValue: undefined,
    });
}
exports.signInputP2shP2pk = signInputP2shP2pk;
function signInput2Of3(txBuilder, vin, scriptType, pubkeys, keyPair, cosigner, amount) {
    let controlBlock;
    let redeemScript;
    let witnessScript;
    const prevOutScriptType = outputScripts_1.scriptType2Of3AsPrevOutType(scriptType);
    if (scriptType === 'p2tr') {
        ({ witnessScript, controlBlock } = outputScripts_1.createSpendScriptP2tr(pubkeys, [keyPair.publicKey, cosigner]));
    }
    else {
        ({ redeemScript, witnessScript } = outputScripts_1.createOutputScript2of3(pubkeys, scriptType));
    }
    keyPair.network = txBuilder.network;
    txBuilder.sign({
        vin,
        prevOutScriptType,
        keyPair,
        hashType: getDefaultSigHash(txBuilder.network, scriptType),
        redeemScript,
        witnessScript,
        witnessValue: amount,
        controlBlock,
    });
}
exports.signInput2Of3 = signInput2Of3;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic2lnbmF0dXJlLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL2JpdGdvL3NpZ25hdHVyZS50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFFQSxpREFBZ0Y7QUFFaEYsdURBQW9EO0FBRXBELG1EQVF5QjtBQUV6QiwwQ0FBNEQ7QUFDNUQsNENBQTZDO0FBQzdDLDZDQUF3RDtBQUN4RCx3Q0FBaUQ7QUE4QmpEOzs7Ozs7Ozs7R0FTRztBQUNILFNBQWdCLHlCQUF5QixDQUN2QyxXQUFxQyxFQUNyQyxVQUFrQixFQUNsQixNQUFlLEVBQ2YsdUJBQTZDLEVBQUUsRUFDL0MsV0FBaUM7SUFFakMsMEJBQTBCO0lBQzFCLElBQUksQ0FBQyxXQUFXLENBQUMsR0FBRyxFQUFFO1FBQ3BCLE1BQU0sSUFBSSxLQUFLLENBQUMscUJBQXFCLENBQUMsQ0FBQztLQUN4QztJQUVELE1BQU0sS0FBSyxHQUFHLFdBQVcsQ0FBQyxHQUFHLENBQUMsVUFBVSxDQUFDLENBQUM7SUFDMUMsMEJBQTBCO0lBQzFCLElBQUksQ0FBQyxLQUFLLEVBQUU7UUFDVixNQUFNLElBQUksS0FBSyxDQUFDLHFCQUFxQixVQUFVLEVBQUUsQ0FBQyxDQUFDO0tBQ3BEO0lBRUQsSUFBSSxDQUFDLENBQUMsS0FBSyxDQUFDLE1BQU0sSUFBSSxLQUFLLENBQUMsTUFBTSxDQUFDLE1BQU0sS0FBSyxDQUFDLENBQUMsSUFBSSxLQUFLLENBQUMsT0FBTyxDQUFDLE1BQU0sS0FBSyxDQUFDLEVBQUU7UUFDOUUsaUNBQWlDO1FBQ2pDLE9BQU8sRUFBRSxDQUFDO0tBQ1g7SUFFRCxNQUFNLFlBQVksR0FBRyxxQ0FBd0IsQ0FBQyxLQUFLLENBQUMsQ0FBQztJQUVyRCxJQUFJLFlBQVksQ0FBQyxVQUFVLEtBQUsscUJBQXFCLElBQUksWUFBWSxDQUFDLFVBQVUsS0FBSyx3QkFBd0IsRUFBRTtRQUM3RyxJQUNFLFlBQVksQ0FBQyxVQUFVLEtBQUsscUJBQXFCO1lBQ2pELENBQUMs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RUFBRTtRQUN6QixDQUFDLEVBQUUsYUFBYSxFQUFFLFlBQVksRUFBRSxHQUFHLHFDQUFxQixDQUFDLE9BQU8sRUFBRSxDQUFDLE9BQU8sQ0FBQyxTQUFTLEVBQUUsUUFBUSxDQUFDLENBQUMsQ0FBQyxDQUFDO0tBQ25HO1NBQU07UUFDTCxDQUFDLEVBQUUsWUFBWSxFQUFFLGFBQWEsRUFBRSxHQUFHLHNDQUFzQixDQUFDLE9BQU8sRUFBRSxVQUFVLENBQUMsQ0FBQyxDQUFDO0tBQ2pGO0lBRUQsT0FBTyxDQUFDLE9BQU8sR0FBRyxTQUFTLENBQUMsT0FBTyxDQUFDO0lBRXBDLFNBQVMsQ0FBQyxJQUFJLENBQUM7UUFDYixHQUFHO1FBQ0gsaUJBQWlCO1FBQ2pCLE9BQU87UUFDUCxRQUFRLEVBQUUsaUJBQWlCLENBQUMsU0FBUyxDQUFDLE9BQWtCLEVBQUUsVUFBVSxDQUFDO1FBQ3JFLFlBQVk7UUFDWixhQUFhO1FBQ2IsWUFBWSxFQUFFLE1BQU07UUFDcEIsWUFBWTtLQUNiLENBQUMsQ0FBQztBQUNMLENBQUM7QUFoQ0Qsc0NBZ0NDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgQklQMzJJbnRlcmZhY2UgfSBmcm9tICdiaXAzMic7XG5cbmltcG9ydCB7IFRyYW5zYWN0aW9uLCB0YXByb290LCBUeE91dHB1dCwgU2NyaXB0U2lnbmF0dXJlIH0gZnJvbSAnYml0Y29pbmpzLWxpYic7XG5cbmltcG9ydCB7IFV0eG9UcmFuc2FjdGlvbiB9IGZyb20gJy4vVXR4b1RyYW5zYWN0aW9uJztcbmltcG9ydCB7IFV0eG9UcmFuc2FjdGlvbkJ1aWxkZXIgfSBmcm9tICcuL1V0eG9UcmFuc2FjdGlvbkJ1aWxkZXInO1xuaW1wb3J0IHtcbiAgY3JlYXRlT3V0cHV0U2NyaXB0Mm9mMyxcbiAgY3JlYXRlT3V0cHV0U2NyaXB0UDJzaFAycGssXG4gIGNyZWF0ZVNwZW5kU2NyaXB0UDJ0cixcbiAgZ2V0T3V0cHV0U2NyaXB0LFxuICBTY3JpcHRUeXBlLFxuICBTY3JpcHRUeXBlMk9mMyxcbiAgc2NyaXB0VHlwZTJPZjNBc1ByZXZPdXRUeXBlLFxufSBmcm9tICcuL291dHB1dFNjcmlwdHMnO1xuaW1wb3J0IHsgVHJpcGxlIH0gZnJvbSAnLi90eXBlcyc7XG5pbXBvcnQgeyBnZXRNYWlubmV0LCBOZXR3b3JrLCBuZXR3b3JrcyB9IGZyb20gJy4uL25ldHdvcmtzJztcbmltcG9ydCB7IGVjYyBhcyBlY2NMaWIgfSBmcm9tICcuLi9ub2JsZV9lY2MnO1xuaW1wb3J0IHsgcGFyc2VTaWduYXR1cmVTY3JpcHQyT2YzIH0gZnJvbSAnLi9wYXJzZUlucHV0JztcbmltcG9ydCB7IGdldFRhcHJvb3RPdXRwdXRLZXkgfSBmcm9tICcuLi90YXByb290JztcblxuLyoqXG4gKiBDb25zdHJhaW50cyBmb3Igc2lnbmF0dXJlIHZlcmlmaWNhdGlvbnMuXG4gKiBQYXJhbWV0ZXJzIGFyZSBjb25qdW5jdGl2ZTogaWYgbXVsdGlwbGUgcGFyYW1ldGVycyBhcmUgc2V0LCBhIHZlcmlmaWNhdGlvbiBmb3IgYW4gaW5kaXZpZHVhbFxuICogc2lnbmF0dXJlIG11c3Qgc2F0aXNmeSBhbGwgb2YgdGhlbS5cbiAqL1xuZXhwb3J0IHR5cGUgVmVyaWZpY2F0aW9uU2V0dGluZ3MgPSB7XG4gIC8qKlxuICAgKiBUaGUgaW5kZXggb2YgdGhlIHNpZ25hdHVyZSB0byB2ZXJpZnkuIE9ubHkgaXRlcmF0ZXMgb3ZlciBub24tZW1wdHkgc2lnbmF0dXJlcy5cbiAgICovXG4gIHNpZ25hdHVyZUluZGV4PzogbnVtYmVyO1xuICAvKipcbiAgICogVGhlIHB1YmxpYyBrZXkgdG8gdmVyaWZ5LlxuICAgKi9cbiAgcHVibGljS2V5PzogQnVmZmVyO1xufTtcblxuLyoqXG4gKiBSZXN1bHQgZm9yIGEgaW5kaXZpZHVhbCBzaWduYXR1cmUgdmVyaWZpY2F0aW9uXG4gKi9cbmV4cG9ydCB0eXBlIFNpZ25hdHVyZVZlcmlmaWNhdGlvbiA9XG4gIHwge1xuICAgICAgLyoqIFNldCB0byB0aGUgcHVibGljIGtleSB0aGF0IHNpZ25lZCBmb3IgdGhlIHNpZ25hdHVyZSAqL1xuICAgICAgc2lnbmVkQnk6IEJ1ZmZlcjtcbiAgICAgIC8qKiBTZXQgdG8gdGhlIHNpZ25hdHVyZSBidWZmZXIgKi9cbiAgICAgIHNpZ25hdHVyZTogQnVmZmVyO1xuICAgIH1cbiAgfCB7IHNpZ25lZEJ5OiB1bmRlZmluZWQ7IHNpZ25hdHVyZTogdW5kZWZpbmVkIH07XG5cbi8qKlxuICogQGRlcHJlY2F0ZWQgLSB1c2Uge0BzZWUgdmVyaWZ5U2lnbmF0dXJlc1dpdGhQdWJsaWNLZXlzfSBpbnN0ZWFkXG4gKiBHZXQgc2lnbmF0dXJlIHZlcmlmaWNhdGlvbnMgZm9yIG11bHRzaWcgdHJhbnNhY3Rpb25cbiAqIEBwYXJhbSB0cmFuc2FjdGlvblxuICogQHBhcmFtIGlucHV0SW5kZXhcbiAqIEBwYXJhbSBhbW91bnQgLSBtdXN0IGJlIHNldCBmb3Igc2Vnd2l0IHRyYW5zYWN0aW9ucyBhbmQgQklQMTQzIHRyYW5zYWN0aW9uc1xuICogQHBhcmFtIHZlcmlmaWNhdGlvblNldHRpbmdzXG4gKiBAcGFyYW0gcHJldk91dHB1dHMgLSBtdXN0IGJlIHNldCBmb3IgcDJ0ciBhbmQgcDJ0ck11c2lnMiB0cmFuc2FjdGlvbnNcbiAqIEByZXR1cm5zIFNpZ25hdHVyZVZlcmlmaWNhdGlvbltdIC0gaW4gb3JkZXIgb2YgcGFyc2VkIG5vbi1lbXB0eSBzaWduYXR1cmVzXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBnZXRTaWduYXR1cmVWZXJpZmljYXRpb25zPFROdW1iZXIgZXh0ZW5kcyBudW1iZXIgfCBiaWdpbnQ+KFxuICB0cmFuc2FjdGlvbjogVXR4b1RyYW5zYWN0aW9uPFROdW1iZXI+LFxuICBpbnB1dEluZGV4OiBudW1iZXIsXG4gIGFtb3VudDogVE51bWJlcixcbiAgdmVyaWZpY2F0aW9uU2V0dGluZ3M6IFZlcmlmaWNhdGlvblNldHRpbmdzID0ge30sXG4gIHByZXZPdXRwdXRzPzogVHhPdXRwdXQ8VE51bWJlcj5bXVxuKTogU2lnbmF0dXJlVmVyaWZpY2F0aW9uW10ge1xuICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCAqL1xuICBpZiAoIXRyYW5zYWN0aW9uLmlucykge1xuICAgIHRocm93IG5ldyBFcnJvcihgaW52YWxpZCB0cmFuc2FjdGlvbmApO1xuICB9XG5cbiAgY29uc3QgaW5wdXQgPSB0cmFuc2FjdGlvbi5pbnNbaW5wdXRJbmRleF07XG4gIC8qIGlzdGFuYnVsIGlnbm9yZSBuZXh0ICovXG4gIGlmICghaW5wdXQpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoYG5vIGlucHV0IGF0IGluZGV4ICR7aW5wdXRJbmRleH1gKTtcbiAgfVxuXG4gIGlmICgoIWlucHV0LnNjcmlwdCB8fCBpbnB1dC5zY3JpcHQubGVuZ3RoID09PSAwKSAmJiBpbnB1dC53aXRuZXNzLmxlbmd0aCA9PT0gMCkge1xuICAgIC8vIFVuc2lnbmVkIGlucHV0OiBubyBzaWduYXR1cmVzLlxuICAgIHJldHVybiBbXTtcbiAgfVxuXG4gIGNvbnN0IHBhcnNlZFNjcmlwdCA9IHBhcnNlU2lnbmF0dXJlU2NyaXB0Mk9mMyhpbnB1dCk7XG5cbiAgaWYgKHBhcnNlZFNjcmlwdC5zY3JpcHRUeXBlID09PSAndGFwcm9vdEtleVBhdGhTcGVuZCcgfHwgcGFyc2VkU2NyaXB0LnNjcmlwdFR5cGUgPT09ICd0YXByb290U2NyaXB0UGF0aFNwZW5kJykge1xuICAgIGlmIChcbiAgICAgIHBhcnNlZFNjcmlwdC5zY3JpcHRUeXBlID09PSAndGFwcm9vdEtleVBhdGhTcGVuZCcgJiZcbiAgICAgICh2ZXJpZmljYXRpb25TZXR0aW5ncy5zaWduYXR1cmVJbmRleCB8fCB2ZXJpZmljYXRpb25TZXR0aW5ncy5wdWJsaWNLZXkpXG4gICAgKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYHNpZ25hdHVyZUluZGV4IGFuZCBwdWJsaWNLZXkgcGFyYW1ldGVycyBub3Qgc3VwcG9ydGVkIGZvciB0YXByb290S2V5UGF0aFNwZW5kYCk7XG4gICAgfVxuXG4gICAgaWYgKHZlcmlmaWNhdGlvblNldHRpbmdzLnNpZ25hdHVyZUluZGV4ICE9PSB1bmRlZmluZWQpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihgc2lnbmF0dXJlSW5kZXggcGFyYW1ldGVyIG5vdCBzdXBwb3J0ZWQgZm9yIHRhcHJvb3RTY3JpcHRQYXRoU3BlbmRgKTtcbiAgICB9XG5cbiAgICBpZiAoIXByZXZPdXRwdXRzKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYHByZXZPdXRwdXRzIG5vdCBzZXRgKTtcbiAgICB9XG5cbiAgICBpZiAocHJldk91dHB1dHMubGVuZ3RoICE9PSB0cmFuc2FjdGlvbi5pbnMubGVuZ3RoKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYHByZXZPdXRwdXRzIGxlbmd0aCAke3ByZXZPdXRwdXRzLmxlbmd0aH0sIGV4cGVjdGVkICR7dHJhbnNhY3Rpb24uaW5zLmxlbmd0aH1gKTtcbiAgICB9XG4gIH1cblxuICBpZiAoXG4gICAgcGFyc2VkU2NyaXB0LnNjcmlwdFR5cGUgIT09ICd0YXByb290S2V5UGF0aFNwZW5kJyAmJlxuICAgIHBhcnNlZFNjcmlwdC5zY3JpcHRUeXBlICE9PSAndGFwcm9vdFNjcmlwdFBhdGhTcGVuZCcgJiZcbiAgICBwcmV2T3V0cHV0c1xuICApIHtcbiAgICBjb25zdCBwcmV2T3V0U2NyaXB0ID0gcHJldk91dHB1dHNbaW5wdXRJbmRleF0uc2NyaXB0O1xuXG4gICAgY29uc3Qgb3V0cHV0ID0gZ2V0T3V0cHV0U2NyaXB0KHBhcnNlZFNjcmlwdC5zY3JpcHRUeXBlLCBwYXJzZWRTY3JpcHQucHViU2NyaXB0KTtcbiAgICBpZiAoIXByZXZPdXRTY3JpcHQuZXF1YWxzKG91dHB1dCkpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgYHByZXZvdXQgc2NyaXB0ICR7cHJldk91dFNjcmlwdC50b1N0cmluZygnaGV4Jyl9IGRvZXMgbm90IG1hdGNoIGNvbXB1dGVkIHNjcmlwdCAke291dHB1dC50b1N0cmluZygnaGV4Jyl9YFxuICAgICAgKTtcbiAgICB9XG4gIH1cblxuICBsZXQgcHVibGljS2V5czogQnVmZmVyW107XG4gIGlmIChwYXJzZWRTY3JpcHQuc2NyaXB0VHlwZSA9PT0gJ3RhcHJvb3RLZXlQYXRoU3BlbmQnKSB7XG4gICAgaWYgKCFwcmV2T3V0cHV0cykge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKGBwcmV2T3V0cHV0cyBub3Qgc2V0YCk7XG4gICAgfVxuICAgIHB1YmxpY0tleXMgPSBbZ2V0VGFwcm9vdE91dHB1dEtleShwcmV2T3V0cHV0c1tpbnB1dEluZGV4XS5zY3JpcHQpXTtcbiAgfSBlbHNlIHtcbiAgICBwdWJsaWNLZXlzID0gcGFyc2VkU2NyaXB0LnB1YmxpY0tleXMuZmlsdGVyKFxuICAgICAgKGJ1ZikgPT5cbiAgICAgICAgdmVyaWZpY2F0aW9uU2V0dGluZ3MucHVibGljS2V5ID09PSB1bmRlZmluZWQgfHxcbiAgICAgICAgdmVyaWZpY2F0aW9uU2V0dGluZ3MucHVibGljS2V5LmVxdWFscyhidWYpIHx8XG4gICAgICAgIHZlcmlmaWNhdGlvblNldHRpbmdzLnB1YmxpY0tleS5zbGljZSgxKS5lcXVhbHMoYnVmKVxuICAgICk7XG4gIH1cblxuICBjb25zdCBzaWduYXR1cmVzID0gcGFyc2VkU2NyaXB0LnNpZ25hdHVyZXNcbiAgICAuZmlsdGVyKChzKSA9PiBzICYmIHMubGVuZ3RoKVxuICAgIC5maWx0ZXIoKHMsIGkpID0+IHZlcmlmaWNhdGlvblNldHRpbmdzLnNpZ25hdHVyZUluZGV4ID09PSB1bmRlZmluZWQgfHwgdmVyaWZpY2F0aW9uU2V0dGluZ3Muc2lnbmF0dXJlSW5kZXggPT09IGkpO1xuXG4gIHJldHVybiBzaWduYXR1cmVzLm1hcCgoc2lnbmF0dXJlQnVmZmVyKTogU2lnbmF0dXJlVmVyaWZpY2F0aW9uID0+IHtcbiAgICBpZiAoc2lnbmF0dXJlQnVmZmVyID09PSAwIHx8IHNpZ25hdHVyZUJ1ZmZlci5sZW5ndGggPT09IDApIHtcbiAgICAgIHJldHVybiB7IHNpZ25lZEJ5OiB1bmRlZmluZWQsIHNpZ25hdHVyZTogdW5kZWZpbmVkIH07XG4gICAgfVxuXG4gICAgbGV0IGhhc2hUeXBlID0gVHJhbnNhY3Rpb24uU0lHSEFTSF9ERUZBVUxUO1xuXG4gICAgaWYgKHNpZ25hdHVyZUJ1ZmZlci5sZW5ndGggPT09IDY1KSB7XG4gICAgICBoYXNoVHlwZSA9IHNpZ25hdHVyZUJ1ZmZlcltzaWduYXR1cmVCdWZmZXIubGVuZ3RoIC0gMV07XG4gICAgICBzaWduYXR1cmVCdWZmZXIgPSBzaWduYXR1cmVCdWZmZXIuc2xpY2UoMCwgLTEpO1xuICAgIH1cblxuICAgIGlmIChwYXJzZWRTY3JpcHQuc2NyaXB0VHlwZSA9PT0gJ3RhcHJvb3RTY3JpcHRQYXRoU3BlbmQnKSB7XG4gICAgICBpZiAoIXByZXZPdXRwdXRzKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcihgcHJldk91dHB1dHMgbm90IHNldGApO1xuICAgICAgfVxuICAgICAgY29uc3QgeyBjb250cm9sQmxvY2ssIHB1YlNjcmlwdCB9ID0gcGFyc2VkU2NyaXB0O1xuICAgICAgY29uc3QgbGVhZkhhc2ggPSB0YXByb290LmdldFRhcGxlYWZIYXNoKGVjY0xpYiwgY29udHJvbEJsb2NrLCBwdWJTY3JpcHQpO1xuICAgICAgY29uc3Qgc2lnbmF0dXJlSGFzaCA9IHRyYW5zYWN0aW9uLmhhc2hGb3JXaXRuZXNzVjEoXG4gICAgICAgIGlucHV0SW5kZXgsXG4gICAgICAgIHByZXZPdXRwdXRzLm1hcCgoeyBzY3JpcHQgfSkgPT4gc2NyaXB0KSxcbiAgICAgICAgcHJldk91dHB1dHMubWFwKCh7IHZhbHVlIH0pID0+IHZhbHVlKSxcbiAgICAgICAgaGFzaFR5cGUsXG4gICAgICAgIGxlYWZIYXNoXG4gICAgICApO1xuXG4gICAgICBjb25zdCBzaWduZWRCeSA9IHB1YmxpY0tleXMuZmlsdGVyKFxuICAgICAgICAoaykgPT4gQnVmZmVyLmlzQnVmZmVyKHNpZ25hdHVyZUJ1ZmZlcikgJiYgZWNjTGliLnZlcmlmeVNjaG5vcnIoc2lnbmF0dXJlSGFzaCwgaywgc2lnbmF0dXJlQnVmZmVyKVxuICAgICAgKTtcblxuICAgICAgaWYgKHNpZ25lZEJ5Lmxlbmd0aCA9PT0gMCkge1xuICAgICAgICByZXR1cm4geyBzaWduZWRCeTogdW5kZWZpbmVkLCBzaWduYXR1cmU6IHVuZGVmaW5lZCB9O1xuICAgICAgfVxuICAgICAgaWYgKHNpZ25lZEJ5Lmxlbmd0aCA9PT0gMSkge1xuICAgICAgICByZXR1cm4geyBzaWduZWRCeTogc2lnbmVkQnlbMF0sIHNpZ25hdHVyZTogc2lnbmF0dXJlQnVmZmVyIH07XG4gICAgICB9XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYGlsbGVnYWwgc3RhdGU6IHNpZ25lZCBieSBtdWx0aXBsZSBwdWJsaWMga2V5c2ApO1xuICAgIH0gZWxzZSBpZiAocGFyc2VkU2NyaXB0LnNjcmlwdFR5cGUgPT09ICd0YXByb290S2V5UGF0aFNwZW5kJykge1xuICAgICAgaWYgKCFwcmV2T3V0cHV0cykge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYHByZXZPdXRwdXRzIG5vdCBzZXRgKTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IHNpZ25hdHVyZUhhc2ggPSB0cmFuc2FjdGlvbi5oYXNoRm9yV2l0bmVzc1YxKFxuICAgICAgICBpbnB1dEluZGV4LFxuICAgICAgICBwcmV2T3V0cHV0cy5tYXAoKHsgc2NyaXB0IH0pID0+IHNjcmlwdCksXG4gICAgICAgIHByZXZPdXRwdXRzLm1hcCgoeyB2YWx1ZSB9KSA9PiB2YWx1ZSksXG4gICAgICAgIGhhc2hUeXBlXG4gICAgICApO1xuICAgICAgY29uc3QgcmVzdWx0ID0gZWNjTGliLnZlcmlmeVNjaG5vcnIoc2lnbmF0dXJlSGFzaCwgcHVibGljS2V5c1swXSwgc2lnbmF0dXJlQnVmZmVyKTtcbiAgICAgIHJldHVybiByZXN1bHRcbiAgICAgICAgPyB7IHNpZ25lZEJ5OiBwdWJsaWNLZXlzWzBdLCBzaWduYXR1cmU6IHNpZ25hdHVyZUJ1ZmZlciB9XG4gICAgICAgIDogeyBzaWduZWRCeTogdW5kZWZpbmVkLCBzaWduYXR1cmU6IHVuZGVmaW5lZCB9O1xuICAgIH0gZWxzZSB7XG4gICAgICAvLyBzbGljZSB0aGUgbGFzdCBieXRlIGZyb20gdGhlIHNpZ25hdHVyZSBoYXNoIGlucHV0IGJlY2F1c2UgaXQncyB0aGUgaGFzaCB0eXBlXG4gICAgICBjb25zdCB7IHNpZ25hdHVyZSwgaGFzaFR5cGUgfSA9IFNjcmlwdFNpZ25hdHVyZS5kZWNvZGUoc2lnbmF0dXJlQnVmZmVyKTtcbiAgICAgIGNvbnN0IHRyYW5zYWN0aW9uSGFzaCA9XG4gICAgICAgIHBhcnNlZFNjcmlwdC5zY3JpcHRUeXBlID09PSAncDJzaFAyd3NoJyB8fCBwYXJzZWRTY3JpcHQuc2NyaXB0VHlwZSA9PT0gJ3Ayd3NoJ1xuICAgICAgICAgID8gdHJhbnNhY3Rpb24uaGFzaEZvcldpdG5lc3NWMChpbnB1dEluZGV4LCBwYXJzZWRTY3JpcHQucHViU2NyaXB0LCBhbW91bnQsIGhhc2hUeXBlKVxuICAgICAgICAgIDogdHJhbnNhY3Rpb24uaGFzaEZvclNpZ25hdHVyZUJ5TmV0d29yayhpbnB1dEluZGV4LCBwYXJzZWRTY3JpcHQucHViU2NyaXB0LCBhbW91bnQsIGhhc2hUeXBlKTtcbiAgICAgIGNvbnN0IHNpZ25lZEJ5ID0gcHVibGljS2V5cy5maWx0ZXIoKHB1YmxpY0tleSkgPT5cbiAgICAgICAgZWNjTGliLnZlcmlmeShcbiAgICAgICAgICB0cmFuc2FjdGlvbkhhc2gsXG4gICAgICAgICAgcHVibGljS2V5LFxuICAgICAgICAgIHNpZ25hdHVyZSxcbiAgICAgICAgICAvKlxuICAgICAgICAgICAgU3RyaWN0IHZlcmlmaWNhdGlvbiAocmVxdWlyZSBsb3dlci1TIHZhbHVlKSwgYXMgcmVxdWlyZWQgYnkgQklQLTAxNDZcbiAgICAgICAgICAgIGh0dHBzOi8vZ2l0aHViLmNvbS9iaXRjb2luL2JpcHMvYmxvYi9tYXN0ZXIvYmlwLTAxNDYubWVkaWF3aWtpXG4gICAgICAgICAgICBodHRwczovL2dpdGh1Yi5jb20vYml0Y29pbi1jb3JlL3NlY3AyNTZrMS9ibG9iL2FjODNiZTMzL2luY2x1ZGUvc2VjcDI1NmsxLmgjTDQ3OC1MNTA4XG4gICAgICAgICAgICBodHRwczovL2dpdGh1Yi5jb20vYml0Y29pbmpzL3Rpbnktc2VjcDI1NmsxL2Jsb2IvdjEuMS42L2pzLmpzI0wyMzEtTDIzM1xuICAgICAgICAgICovXG4gICAgICAgICAgdHJ1ZVxuICAgICAgICApXG4gICAgICApO1xuXG4gICAgICBpZiAoc2lnbmVkQnkubGVuZ3RoID09PSAwKSB7XG4gICAgICAgIHJldHVybiB7IHNpZ25lZEJ5OiB1bmRlZmluZWQsIHNpZ25hdHVyZTogdW5kZWZpbmVkIH07XG4gICAgICB9XG4gICAgICBpZiAoc2lnbmVkQnkubGVuZ3RoID09PSAxKSB7XG4gICAgICAgIHJldHVybiB7IHNpZ25lZEJ5OiBzaWduZWRCeVswXSwgc2lnbmF0dXJlOiBzaWduYXR1cmVCdWZmZXIgfTtcbiAgICAgIH1cbiAgICAgIHRocm93IG5ldyBFcnJvcihgaWxsZWdhbCBzdGF0ZTogc2lnbmVkIGJ5IG11bHRpcGxlIHB1YmxpYyBrZXlzYCk7XG4gICAgfVxuICB9KTtcbn1cblxuLyoqXG4gKiBAZGVwcmVjYXRlZCB1c2Uge0BzZWUgdmVyaWZ5U2lnbmF0dXJlV2l0aFB1YmxpY0tleXN9IGluc3RlYWRcbiAqIEBwYXJhbSB0cmFuc2FjdGlvblxuICogQHBhcmFtIGlucHV0SW5kZXhcbiAqIEBwYXJhbSBhbW91bnRcbiAqIEBwYXJhbSB2ZXJpZmljYXRpb25TZXR0aW5ncyAtIGlmIHB1YmxpY0tleSBpcyBzcGVjaWZpZWQsIHJldHVybnMgdHJ1ZSBpZmYgYW55IHNpZ25hdHVyZSBpcyBzaWduZWQgYnkgcHVibGljS2V5LlxuICogQHBhcmFtIHByZXZPdXRwdXRzIC0gbXVzdCBiZSBzZXQgZm9yIHAydHIgdHJhbnNhY3Rpb25zXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiB2ZXJpZnlTaWduYXR1cmU8VE51bWJlciBleHRlbmRzIG51bWJlciB8IGJpZ2ludD4oXG4gIHRyYW5zYWN0aW9uOiBVdHhvVHJhbnNhY3Rpb248VE51bWJlcj4sXG4gIGlucHV0SW5kZXg6IG51bWJlcixcbiAgYW1vdW50OiBUTnVtYmVyLFxuICB2ZXJpZmljYXRpb25TZXR0aW5nczogVmVyaWZpY2F0aW9uU2V0dGluZ3MgPSB7fSxcbiAgcHJldk91dHB1dHM/OiBUeE91dHB1dDxUTnVtYmVyPltdXG4pOiBib29sZWFuIHtcbiAgY29uc3Qgc2lnbmF0dXJlVmVyaWZpY2F0aW9ucyA9IGdldFNpZ25hdHVyZVZlcmlmaWNhdGlvbnMoXG4gICAgdHJhbnNhY3Rpb24sXG4gICAgaW5wdXRJbmRleCxcbiAgICBhbW91bnQsXG4gICAgdmVyaWZpY2F0aW9uU2V0dGluZ3MsXG4gICAgcHJldk91dHB1dHNcbiAgKS5maWx0ZXIoXG4gICAgKHYpID0+XG4gICAgICAvLyBJZiBubyBwdWJsaWNLZXkgaXMgc2V0IGluIHZlcmlmaWNhdGlvblNldHRpbmdzLCBhbGwgc2lnbmF0dXJlcyBtdXN0IGJlIHZhbGlkLlxuICAgICAgLy8gT3RoZXJ3aXNlLCBhIHNpbmdsZSB2YWxpZCBzaWduYXR1cmUgYnkgdGhlIHNwZWNpZmllZCBwdWJrZXkgaXMgc3VmZmljaWVudC5cbiAgICAgIHZlcmlmaWNhdGlvblNldHRpbmdzLnB1YmxpY0tleSA9PT0gdW5kZWZpbmVkIHx8XG4gICAgICAodi5zaWduZWRCeSAhPT0gdW5kZWZpbmVkICYmXG4gICAgICAgICh2ZXJpZmljYXRpb25TZXR0aW5ncy5wdWJsaWNLZXkuZXF1YWxzKHYuc2lnbmVkQnkpIHx8XG4gICAgICAgICAgdmVyaWZpY2F0aW9uU2V0dGluZ3MucHVibGljS2V5LnNsaWNlKDEpLmVxdWFscyh2LnNpZ25lZEJ5KSkpXG4gICk7XG5cbiAgcmV0dXJuIHNpZ25hdHVyZVZlcmlmaWNhdGlvbnMubGVuZ3RoID4gMCAmJiBzaWduYXR1cmVWZXJpZmljYXRpb25zLmV2ZXJ5KCh2KSA9PiB2LnNpZ25lZEJ5ICE9PSB1bmRlZmluZWQpO1xufVxuXG4vKipcbiAqIEBwYXJhbSB2XG4gKiBAcGFyYW0gcHVibGljS2V5XG4gKiBAcmV0dXJuIHRydWUgaWZmIHNpZ25hdHVyZSBpcyBieSBwdWJsaWNLZXkgKG9yIHhvbmx5IHZhcmlhbnQgb2YgcHVibGljS2V5KVxuICovXG5mdW5jdGlvbiBpc1NpZ25hdHVyZUJ5UHVibGljS2V5KHY6IFNpZ25hdHVyZVZlcmlmaWNhdGlvbiwgcHVibGljS2V5OiBCdWZmZXIpOiBib29sZWFuIHtcbiAgcmV0dXJuIChcbiAgICAhIXYuc2lnbmVkQnkgJiZcbiAgICAodi5zaWduZWRCeS5lcXVhbHMocHVibGljS2V5KSB8fFxuICAgICAgLyogZm9yIHAydHIgc2lnbmF0dXJlcywgd2UgcGFzcyB0aGUgcHVia2V5IGluIDMzLWJ5dGUgZm9ybWF0IHJlY292ZXIgaXQgZnJvbSB0aGUgc2lnbmF0dXJlIGluIDMyLWJ5dGUgZm9ybWF0ICovXG4gICAgICAocHVibGljS2V5Lmxlbmd0aCA9PT0gMzMgJiYgaXNTaWduYXR1cmVCeVB1YmxpY0tleSh2LCBwdWJsaWNLZXkuc2xpY2UoMSkpKSlcbiAgKTtcbn1cblxuLyoqXG4gKiBAcGFyYW0gdHJhbnNhY3Rpb25cbiAqIEBwYXJhbSBpbnB1dEluZGV4XG4gKiBAcGFyYW0gcHJldk91dHB1dHNcbiAqIEBwYXJhbSBwdWJsaWNLZXlzXG4gKiBAcmV0dXJuIGFycmF5IHdpdGggc2lnbmF0dXJlIGNvcnJlc3BvbmRpbmcgdG8gbi10aCBrZXksIHVuZGVmaW5lZCBpZiBubyBtYXRjaCBmb3VuZFxuICovXG5leHBvcnQgZnVuY3Rpb24gZ2V0U2lnbmF0dXJlc1dpdGhQdWJsaWNLZXlzPFROdW1iZXIgZXh0ZW5kcyBudW1iZXIgfCBiaWdpbnQ+KFxuICB0cmFuc2FjdGlvbjogVXR4b1RyYW5zYWN0aW9uPFROdW1iZXI+LFxuICBpbnB1dEluZGV4OiBudW1iZXIsXG4gIHByZXZPdXRwdXRzOiBUeE91dHB1dDxUTnVtYmVyPltdLFxuICBwdWJsaWNLZXlzOiBCdWZmZXJbXVxuKTogQXJyYXk8QnVmZmVyIHwgdW5kZWZpbmVkPiB7XG4gIGlmICh0cmFuc2FjdGlvbi5pbnMubGVuZ3RoICE9PSBwcmV2T3V0cHV0cy5sZW5ndGgpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoYGlucHV0IGxlbmd0aCBtdXN0IG1hdGNoIHByZXZPdXRwdXRzIGxlbmd0aGApO1xuICB9XG5cbiAgY29uc3Qgc2lnbmF0dXJlVmVyaWZpY2F0aW9ucyA9IGdldFNpZ25hdHVyZVZlcmlmaWNhdGlvbnMoXG4gICAgdHJhbnNhY3Rpb24sXG4gICAgaW5wdXRJbmRleCxcbiAgICBwcmV2T3V0cHV0c1tpbnB1dEluZGV4XS52YWx1ZSxcbiAgICB7fSxcbiAgICBwcmV2T3V0cHV0c1xuICApO1xuXG4gIHJldHVybiBwdWJsaWNLZXlzLm1hcCgocHVibGljS2V5KSA9PiB7XG4gICAgY29uc3QgdiA9IHNpZ25hdHVyZVZlcmlmaWNhdGlvbnMuZmluZCgodikgPT4gaXNTaWduYXR1cmVCeVB1YmxpY0tleSh2LCBwdWJsaWNLZXkpKTtcbiAgICByZXR1cm4gdiA/IHYuc2lnbmF0dXJlIDogdW5kZWZpbmVkO1xuICB9KTtcbn1cblxuLyoqXG4gKiBAcGFyYW0gdHJhbnNhY3Rpb25cbiAqIEBwYXJhbSBpbnB1dEluZGV4XG4gKiBAcGFyYW0gcHJldk91dHB1dHMgLSB0cmFuc2FjdGlvbiBvdXRwdXRzIGZvciBpbnB1dHNcbiAqIEBwYXJhbSBwdWJsaWNLZXlzIC0gcHVibGljIGtleXMgdG8gY2hlY2sgc2lnbmF0dXJlcyBmb3JcbiAqIEByZXR1cm4gYXJyYXkgb2YgYm9vbGVhbnMgaW5kaWNhdGluZyBhIHZhbGlkIHNpZ25hdHVyZSBmb3IgZXZlcnkgcHVia2V5IGluIF9wdWJsaWNLZXlzX1xuICovXG5leHBvcnQgZnVuY3Rpb24gdmVyaWZ5U2lnbmF0dXJlV2l0aFB1YmxpY0tleXM8VE51bWJlciBleHRlbmRzIG51bWJlciB8IGJpZ2ludD4oXG4gIHRyYW5zYWN0aW9uOiBVdHhvVHJhbnNhY3Rpb248VE51bWJlcj4sXG4gIGlucHV0SW5kZXg6IG51bWJlcixcbiAgcHJldk91dHB1dHM6IFR4T3V0cHV0PFROdW1iZXI+W10sXG4gIHB1YmxpY0tleXM6IEJ1ZmZlcltdXG4pOiBib29sZWFuW10ge1xuICByZXR1cm4gZ2V0U2lnbmF0dXJlc1dpdGhQdWJsaWNLZXlzKHRyYW5zYWN0aW9uLCBpbnB1dEluZGV4LCBwcmV2T3V0cHV0cywgcHVibGljS2V5cykubWFwKChzKSA9PiBzICE9PSB1bmRlZmluZWQpO1xufVxuXG4vKipcbiAqIFdyYXBwZXIgZm9yIHtAc2VlIHZlcmlmeVNpZ25hdHVyZVdpdGhQdWJsaWNLZXlzfSBmb3Igc2luZ2xlIHB1YmtleVxuICogQHBhcmFtIHRyYW5zYWN0aW9uXG4gKiBAcGFyYW0gaW5wdXRJbmRleFxuICogQHBhcmFtIHByZXZPdXRwdXRzXG4gKiBAcGFyYW0gcHVibGljS2V5XG4gKiBAcmV0dXJuIHRydWUgaWZmIHNpZ25hdHVyZSBpcyB2YWxpZFxuICovXG5leHBvcnQgZnVuY3Rpb24gdmVyaWZ5U2lnbmF0dXJlV2l0aFB1YmxpY0tleTxUTnVtYmVyIGV4dGVuZHMgbnVtYmVyIHwgYmlnaW50PihcbiAgdHJhbnNhY3Rpb246IFV0eG9UcmFuc2FjdGlvbjxUTnVtYmVyPixcbiAgaW5wdXRJbmRleDogbnVtYmVyLFxuICBwcmV2T3V0cHV0czogVHhPdXRwdXQ8VE51bWJlcj5bXSxcbiAgcHVibGljS2V5OiBCdWZmZXJcbik6IGJvb2xlYW4ge1xuICByZXR1cm4gdmVyaWZ5U2lnbmF0dXJlV2l0aFB1YmxpY0tleXModHJhbnNhY3Rpb24sIGlucHV0SW5kZXgsIHByZXZPdXRwdXRzLCBbcHVibGljS2V5XSlbMF07XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBnZXREZWZhdWx0U2lnSGFzaChuZXR3b3JrOiBOZXR3b3JrLCBzY3JpcHRUeXBlPzogU2NyaXB0VHlwZSk6IG51bWJlciB7XG4gIHN3aXRjaCAoZ2V0TWFpbm5ldChuZXR3b3JrKSkge1xuICAgIGNhc2UgbmV0d29ya3MuYml0Y29pbmNhc2g6XG4gICAgY2FzZSBuZXR3b3Jrcy5iaXRjb2luc3Y6XG4gICAgY2FzZSBuZXR3b3Jrcy5iaXRjb2luZ29sZDpcbiAgICBjYXNlIG5ldHdvcmtzLmVjYXNoOlxuICAgICAgcmV0dXJuIFRyYW5zYWN0aW9uLlNJR0hBU0hfQUxMIHwgVXR4b1RyYW5zYWN0aW9uLlNJR0hBU0hfRk9SS0lEO1xuICAgIGRlZmF1bHQ6XG4gICAgICBzd2l0Y2ggKHNjcmlwdFR5cGUpIHtcbiAgICAgICAgY2FzZSAncDJ0cic6XG4gICAgICAgIGNhc2UgJ3AydHJNdXNpZzInOlxuICAgICAgICAgIHJldHVybiBUcmFuc2FjdGlvbi5TSUdIQVNIX0RFRkFVTFQ7XG4gICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgcmV0dXJuIFRyYW5zYWN0aW9uLlNJR0hBU0hfQUxMO1xuICAgICAgfVxuICB9XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBzaWduSW5wdXRQMnNoUDJwazxUTnVtYmVyIGV4dGVuZHMgbnVtYmVyIHwgYmlnaW50PihcbiAgdHhCdWlsZGVyOiBVdHhvVHJhbnNhY3Rpb25CdWlsZGVyPFROdW1iZXI+LFxuICB2aW46IG51bWJlcixcbiAga2V5UGFpcjogQklQMzJJbnRlcmZhY2Vcbik6IHZvaWQge1xuICBjb25zdCBwcmV2T3V0U2NyaXB0VHlwZSA9ICdwMnNoLXAycGsnO1xuICBjb25zdCB7IHJlZGVlbVNjcmlwdCwgd2l0bmVzc1NjcmlwdCB9ID0gY3JlYXRlT3V0cHV0U2NyaXB0UDJzaFAycGsoa2V5UGFpci5wdWJsaWNLZXkpO1xuICBrZXlQYWlyLm5ldHdvcmsgPSB0eEJ1aWxkZXIubmV0d29yaztcblxuICB0eEJ1aWxkZXIuc2lnbih7XG4gICAgdmluLFxuICAgIHByZXZPdXRTY3JpcHRUeXBlLFxuICAgIGtleVBhaXIsXG4gICAgaGFzaFR5cGU6IGdldERlZmF1bHRTaWdIYXNoKHR4QnVpbGRlci5uZXR3b3JrIGFzIE5ldHdvcmspLFxuICAgIHJlZGVlbVNjcmlwdCxcbiAgICB3aXRuZXNzU2NyaXB0LFxuICAgIHdpdG5lc3NWYWx1ZTogdW5kZWZpbmVkLFxuICB9KTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHNpZ25JbnB1dDJPZjM8VE51bWJlciBleHRlbmRzIG51bWJlciB8IGJpZ2ludD4oXG4gIHR4QnVpbGRlcjogVXR4b1RyYW5zYWN0aW9uQnVpbGRlcjxUTnVtYmVyPixcbiAgdmluOiBudW1iZXIsXG4gIHNjcmlwdFR5cGU6IFNjcmlwdFR5cGUyT2YzLFxuICBwdWJrZXlzOiBUcmlwbGU8QnVmZmVyPixcbiAga2V5UGFpcjogQklQMzJJbnRlcmZhY2UsXG4gIGNvc2lnbmVyOiBCdWZmZXIsXG4gIGFtb3VudDogVE51bWJlclxuKTogdm9pZCB7XG4gIGxldCBjb250cm9sQmxvY2s7XG4gIGxldCByZWRlZW1TY3JpcHQ7XG4gIGxldCB3aXRuZXNzU2NyaXB0O1xuXG4gIGNvbnN0IHByZXZPdXRTY3JpcHRUeXBlID0gc2NyaXB0VHlwZTJPZjNBc1ByZXZPdXRUeXBlKHNjcmlwdFR5cGUpO1xuICBpZiAoc2NyaXB0VHlwZSA9PT0gJ3AydHInKSB7XG4gICAgKHsgd2l0bmVzc1NjcmlwdCwgY29udHJvbEJsb2NrIH0gPSBjcmVhdGVTcGVuZFNjcmlwdFAydHIocHVia2V5cywgW2tleVBhaXIucHVibGljS2V5LCBjb3NpZ25lcl0pKTtcbiAgfSBlbHNlIHtcbiAgICAoeyByZWRlZW1TY3JpcHQsIHdpdG5lc3NTY3JpcHQgfSA9IGNyZWF0ZU91dHB1dFNjcmlwdDJvZjMocHVia2V5cywgc2NyaXB0VHlwZSkpO1xuICB9XG5cbiAga2V5UGFpci5uZXR3b3JrID0gdHhCdWlsZGVyLm5ldHdvcms7XG5cbiAgdHhCdWlsZGVyLnNpZ24oe1xuICAgIHZpbixcbiAgICBwcmV2T3V0U2NyaXB0VHlwZSxcbiAgICBrZXlQYWlyLFxuICAgIGhhc2hUeXBlOiBnZXREZWZhdWx0U2lnSGFzaCh0eEJ1aWxkZXIubmV0d29yayBhcyBOZXR3b3JrLCBzY3JpcHRUeXBlKSxcbiAgICByZWRlZW1TY3JpcHQsXG4gICAgd2l0bmVzc1NjcmlwdCxcbiAgICB3aXRuZXNzVmFsdWU6IGFtb3VudCxcbiAgICBjb250cm9sQmxvY2ssXG4gIH0pO1xufVxuIl19