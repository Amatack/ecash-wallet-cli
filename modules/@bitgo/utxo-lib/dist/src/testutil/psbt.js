"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyFullySignedSignatures = exports.constructPsbt = exports.signAllPsbtInputs = exports.signPsbtInput = exports.getSigners = exports.toUnspent = exports.outputScriptTypes = exports.inputScriptTypes = void 0;
const assert = require("assert");
const outputScripts_1 = require("../bitgo/outputScripts");
const bitgo_1 = require("../bitgo");
const mock_1 = require("./mock");
const address_1 = require("../address");
/**
 * array of supported input script types.
 * use p2trMusig2 for p2trMusig2 script path.
 * use taprootKeyPathSpend for p2trMusig2 key path.
 */
exports.inputScriptTypes = [...outputScripts_1.scriptTypes2Of3, 'taprootKeyPathSpend', outputScripts_1.scriptTypeP2shP2pk];
/**
 * array of supported output script types.
 */
exports.outputScriptTypes = outputScripts_1.scriptTypes2Of3;
/**
 * create unspent object from input script type, index, network and root wallet key.
 */
function toUnspent(input, index, network, rootWalletKeys) {
    if (input.scriptType === 'p2shP2pk') {
        return mock_1.mockReplayProtectionUnspent(network, input.value, { key: rootWalletKeys['user'], vout: index });
    }
    else {
        const chain = bitgo_1.getInternalChainCode(input.scriptType === 'taprootKeyPathSpend' ? 'p2trMusig2' : input.scriptType);
        return mock_1.mockWalletUnspent(network, input.value, {
            chain,
            vout: index,
            keys: rootWalletKeys,
            index,
        });
    }
}
exports.toUnspent = toUnspent;
/**
 * returns signer and cosigner names for InputScriptType.
 * user and undefined as signer and cosigner respectively for p2shP2pk.
 * user and backup as signer and cosigner respectively for p2trMusig2.
 * user and bitgo as signer and cosigner respectively for other input script types.
 */
function getSigners(inputType) {
    return {
        signerName: 'user',
        cosignerName: inputType === 'p2shP2pk' ? undefined : inputType === 'p2trMusig2' ? 'backup' : 'bitgo',
    };
}
exports.getSigners = getSigners;
/**
 * signs with first or second signature for single input.
 * p2shP2pk is signed only with first sign.
 */
function signPsbtInput(psbt, input, inputIndex, rootWalletKeys, sign, params) {
    function signPsbt(psbt, signFunc, skipNonWitnessUtxo) {
        if (skipNonWitnessUtxo) {
            bitgo_1.withUnsafeNonSegwit(psbt, signFunc);
        }
        else {
            signFunc();
        }
    }
    const { signers, deterministic, skipNonWitnessUtxo } = params !== null && params !== void 0 ? params : {};
    const { signerName, cosignerName } = signers ? signers : getSigners(input.scriptType);
    if (sign === 'halfsigned') {
        if (input.scriptType === 'p2shP2pk') {
            signPsbt(psbt, () => psbt.signInput(inputIndex, rootWalletKeys[signerName]), skipNonWitnessUtxo);
        }
        else {
            signPsbt(psbt, () => psbt.signInputHD(inputIndex, rootWalletKeys[signerName]), skipNonWitnessUtxo);
        }
    }
    if (sign === 'fullsigned' && cosignerName && input.scriptType !== 'p2shP2pk') {
        signPsbt(psbt, () => psbt.signInputHD(inputIndex, rootWalletKeys[cosignerName], { deterministic }), skipNonWitnessUtxo);
    }
}
exports.signPsbtInput = signPsbtInput;
/**
 * signs with first or second signature for all inputs.
 * p2shP2pk is signed only with first sign.
 */
function signAllPsbtInputs(psbt, inputs, rootWalletKeys, sign, params) {
    const { signers, deterministic, skipNonWitnessUtxo } = params !== null && params !== void 0 ? params : {};
    inputs.forEach((input, inputIndex) => {
        signPsbtInput(psbt, input, inputIndex, rootWalletKeys, sign, { signers, deterministic, skipNonWitnessUtxo });
    });
}
exports.signAllPsbtInputs = signAllPsbtInputs;
/**
 * construct psbt for given inputs, outputs, network and root wallet keys.
 */
function constructPsbt(inputs, outputs, network, rootWalletKeys, sign, params) {
    const { signers, deterministic, skipNonWitnessUtxo } = params !== null && params !== void 0 ? params : {};
    const totalInputAmount = inputs.reduce((sum, input) => sum + input.value, BigInt(0));
    const outputInputAmount = outputs.reduce((sum, output) => sum + output.value, BigInt(0));
    assert(totalInputAmount >= outputInputAmount, 'total output can not exceed total input');
    assert(!outputs.some((o) => (o.scriptType && o.address) || (!o.scriptType && !o.address)), 'only either output script type or address should be provided');
    const psbt = bitgo_1.createPsbtForNetwork({ network });
    const unspents = inputs.map((input, i) => toUnspent(input, i, network, rootWalletKeys));
    unspents.forEach((u, i) => {
        const { signerName, cosignerName } = signers ? signers : getSigners(inputs[i].scriptType);
        if (bitgo_1.isWalletUnspent(u) && cosignerName) {
            bitgo_1.addWalletUnspentToPsbt(psbt, u, rootWalletKeys, signerName, cosignerName, { skipNonWitnessUtxo });
        }
        else {
            const { redeemScript } = outputScripts_1.createOutputScriptP2shP2pk(rootWalletKeys[signerName].publicKey);
            assert(redeemScript);
            bitgo_1.addReplayProtectionUnspentToPsbt(psbt, u, redeemScript, { skipNonWitnessUtxo });
        }
    });
    outputs.forEach((output, i) => {
        if (output.scriptType) {
            bitgo_1.addWalletOutputToPsbt(psbt, rootWalletKeys, output.isInternalAddress ? bitgo_1.getInternalChainCode(output.scriptType) : bitgo_1.getExternalChainCode(output.scriptType), i, output.value);
        }
        else if (output.address) {
            const { address, value } = output;
            psbt.addOutput({ script: address_1.toOutputScript(address, network), value });
        }
    });
    if (sign === 'unsigned') {
        return psbt;
    }
    psbt.setAllInputsMusig2NonceHD(rootWalletKeys['user']);
    psbt.setAllInputsMusig2NonceHD(rootWalletKeys['bitgo'], { deterministic });
    signAllPsbtInputs(psbt, inputs, rootWalletKeys, 'halfsigned', { signers, skipNonWitnessUtxo });
    if (sign === 'fullsigned') {
        signAllPsbtInputs(psbt, inputs, rootWalletKeys, sign, { signers, deterministic, skipNonWitnessUtxo });
    }
    return psbt;
}
exports.constructPsbt = constructPsbt;
/**
 * Verifies signatures of fully signed tx (with taproot key path support).
 * NOTE: taproot key path tx can only be built and signed with PSBT.
 */
function verifyFullySignedSignatures(tx, unspents, walletKeys, signer, cosigner) {
    const prevOutputs = unspents.map((u) => bitgo_1.toOutput(u, tx.network));
    return unspents.every((u, index) => {
        if (bitgo_1.parseSignatureScript2Of3(tx.ins[index]).scriptType === 'taprootKeyPathSpend') {
            const result = bitgo_1.getSignatureVerifications(tx, index, u.value, undefined, prevOutputs);
            return result.length === 1 && result[0].signature;
        }
        else {
            const result = bitgo_1.verifySignatureWithUnspent(tx, index, unspents, walletKeys);
            if ((signer === 'user' && cosigner === 'bitgo') || (signer === 'bitgo' && cosigner === 'user')) {
                return result[0] && !result[1] && result[2];
            }
            else if ((signer === 'user' && cosigner === 'backup') || (signer === 'backup' && cosigner === 'user')) {
                return result[0] && result[1] && !result[2];
            }
            else {
                return !result[0] && result[1] && result[2];
            }
        }
    });
}
exports.verifyFullySignedSignatures = verifyFullySignedSignatures;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoicHNidC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy90ZXN0dXRpbC9wc2J0LnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUFBLGlDQUFpQztBQUVqQywwREFNZ0M7QUFDaEMsb0NBa0JrQjtBQUVsQixpQ0FBd0U7QUFDeEUsd0NBQTRDO0FBNkI1Qzs7OztHQUlHO0FBQ1UsUUFBQSxnQkFBZ0IsR0FBRyxDQUFDLEdBQUcsK0JBQWUsRUFBRSxxQkFBcUIsRUFBRSxrQ0FBa0IsQ0FBVSxDQUFDO0FBRXpHOztHQUVHO0FBQ1UsUUFBQSxpQkFBaUIsR0FBRywrQkFBZSxDQUFDO0FBRWpEOztHQUVHO0FBQ0gsU0FBZ0IsU0FBUyxDQUN2QixLQUFZLEVBQ1osS0FBYSxFQUNiLE9BQWdCLEVBQ2hCLGNBQThCO0lBRTlCLElBQUksS0FBSyxDQUFDLFVBQVUsS0FBSyxVQUFVLEVBQUU7UUFDbkMsT0FBTyxrQ0FBMkIsQ0FBQyxPQUFPLEVBQUUsS0FBSyxDQUFDLEtBQUssRUFBRSxFQUFFLEdBQUcsRUFBRSxjQUFjLENBQUMsTUFBTSxDQUFDLEVBQUUsSUFBSSxFQUFFLEtBQUssRUFBRSxDQUFDLENBQUM7S0FDeEc7U0FBTTtRQUNMLE1BQU0sS0FBSyxHQUFHLDRCQUFvQixDQUFDLEtBQUssQ0FBQyxVQUFVLEtBQUsscUJBQXFCLENBQUMsQ0FBQyxDQUFDLFlBQVksQ0FBQyxDQUFDLENBQUMsS0FBSyxDQUFDLFVBQVUsQ0FBQyxDQUFDO1FBQ2pILE9BQU8sd0JBQWlCLENBQUMsT0FBTyxFQUFFLEtBQUssQ0FBQyxLQUFLLEVBQUU7WUFDN0MsS0FBSztZQUNMLElBQUksRUFBRSxLQUFLO1lBQ1gsSUFBSSxFQUFFLGNBQWM7WUFDcEIsS0FBSztTQUNOLENBQUMsQ0FBQztLQUNKO0FBQ0gsQ0FBQztBQWpCRCw4QkFpQkM7QUFFRDs7Ozs7R0FLRztBQUNILFNBQWdCLFVBQVUsQ0FBQyxTQUEwQjtJQUNuRCxPQUFPO1FBQ0wsVUFBVSxF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Q0FBQyxDQUFDLENBQUMsQ0FBQyxTQUFTLENBQUM7U0FDbkQ7YUFBTTtZQUNMLE1BQU0sTUFBTSxHQUFHLGtDQUEwQixDQUFDLEVBQUUsRUFBRSxLQUFLLEVBQUUsUUFBUSxFQUFFLFVBQVUsQ0FBQyxDQUFDO1lBQzNFLElBQUksQ0FBQyxNQUFNLEtBQUssTUFBTSxJQUFJLFFBQVEsS0FBSyxPQUFPLENBQUMsSUFBSSxDQUFDLE1BQU0sS0FBSyxPQUFPLElBQUksUUFBUSxLQUFLLE1BQU0sQ0FBQyxFQUFFO2dCQUM5RixPQUFPLE1BQU0sQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsSUFBSSxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUM7YUFDN0M7aUJBQU0sSUFBSSxDQUFDLE1BQU0sS0FBSyxNQUFNLElBQUksUUFBUSxLQUFLLFFBQVEsQ0FBQyxJQUFJLENBQUMsTUFBTSxLQUFLLFFBQVEsSUFBSSxRQUFRLEtBQUssTUFBTSxDQUFDLEVBQUU7Z0JBQ3ZHLE9BQU8sTUFBTSxDQUFDLENBQUMsQ0FBQyxJQUFJLE1BQU0sQ0FBQyxDQUFDLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQzthQUM3QztpQkFBTTtnQkFDTCxPQUFPLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxJQUFJLE1BQU0sQ0FBQyxDQUFDLENBQUMsSUFBSSxNQUFNLENBQUMsQ0FBQyxDQUFDLENBQUM7YUFDN0M7U0FDRjtJQUNILENBQUMsQ0FBQyxDQUFDO0FBQ0wsQ0FBQztBQXZCRCxrRUF1QkMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgKiBhcyBhc3NlcnQgZnJvbSAnYXNzZXJ0JztcblxuaW1wb3J0IHtcbiAgY3JlYXRlT3V0cHV0U2NyaXB0UDJzaFAycGssXG4gIFNjcmlwdFR5cGUsXG4gIFNjcmlwdFR5cGUyT2YzLFxuICBzY3JpcHRUeXBlUDJzaFAycGssXG4gIHNjcmlwdFR5cGVzMk9mMyxcbn0gZnJvbSAnLi4vYml0Z28vb3V0cHV0U2NyaXB0cyc7XG5pbXBvcnQge1xuICBhZGRSZXBsYXlQcm90ZWN0aW9uVW5zcGVudFRvUHNidCxcbiAgYWRkV2FsbGV0T3V0cHV0VG9Qc2J0LFxuICBhZGRXYWxsZXRVbnNwZW50VG9Qc2J0LFxuICBjcmVhdGVQc2J0Rm9yTmV0d29yayxcbiAgZ2V0RXh0ZXJuYWxDaGFpbkNvZGUsXG4gIGdldEludGVybmFsQ2hhaW5Db2RlLFxuICBnZXRTaWduYXR1cmVWZXJpZmljYXRpb25zLFxuICBpc1dhbGxldFVuc3BlbnQsXG4gIEtleU5hbWUsXG4gIHBhcnNlU2lnbmF0dXJlU2NyaXB0Mk9mMyxcbiAgUm9vdFdhbGxldEtleXMsXG4gIHRvT3V0cHV0LFxuICBVbnNwZW50LFxuICBVdHhvUHNidCxcbiAgVXR4b1RyYW5zYWN0aW9uLFxuICB2ZXJpZnlTaWduYXR1cmVXaXRoVW5zcGVudCxcbiAgd2l0aFVuc2FmZU5vblNlZ3dpdCxcbn0gZnJvbSAnLi4vYml0Z28nO1xuaW1wb3J0IHsgTmV0d29yayB9IGZyb20gJy4uL25ldHdvcmtzJztcbmltcG9ydCB7IG1vY2tSZXBsYXlQcm90ZWN0aW9uVW5zcGVudCwgbW9ja1dhbGxldFVuc3BlbnQgfSBmcm9tICcuL21vY2snO1xuaW1wb3J0IHsgdG9PdXRwdXRTY3JpcHQgfSBmcm9tICcuLi9hZGRyZXNzJztcblxuLyoqXG4gKiBpbnB1dCBzY3JpcHQgdHlwZSBhbmQgdmFsdWUuXG4gKiB1c2UgcDJ0ck11c2lnMiBmb3IgcDJ0ck11c2lnMiBzY3JpcHQgcGF0aC5cbiAqIHVzZSB0YXByb290S2V5UGF0aFNwZW5kIGZvciBwMnRyTXVzaWcyIGtleSBwYXRoLlxuICovXG5leHBvcnQgdHlwZSBJbnB1dFNjcmlwdFR5cGUgPSBTY3JpcHRUeXBlIHwgJ3RhcHJvb3RLZXlQYXRoU3BlbmQnO1xuZXhwb3J0IHR5cGUgT3V0cHV0U2NyaXB0VHlwZSA9IFNjcmlwdFR5cGUyT2YzO1xuXG4vKipcbiAqIGlucHV0IHNjcmlwdCB0eXBlIGFuZCB2YWx1ZVxuICovXG5leHBvcnQgaW50ZXJmYWNlIElucHV0IHtcbiAgc2NyaXB0VHlwZTogSW5wdXRTY3JpcHRUeXBlO1xuICB2YWx1ZTogYmlnaW50O1xufVxuXG4vKipcbiAqIHNob3VsZCBzZXQgZWl0aGVyIGFkZHJlc3Mgb3Igc2NyaXB0VHlwZSwgbmV2ZXIgYm90aC5cbiAqIHNldCBpc0ludGVybmFsQWRkcmVzcz10cnVlIGZvciBpbnRlcm5hbCBvdXRwdXQgYWRkcmVzc1xuICovXG5leHBvcnQgaW50ZXJmYWNlIE91dHB1dCB7XG4gIGFkZHJlc3M/OiBzdHJpbmc7XG4gIHNjcmlwdFR5cGU/OiBPdXRwdXRTY3JpcHRUeXBlO1xuICB2YWx1ZTogYmlnaW50O1xuICBpc0ludGVybmFsQWRkcmVzcz86IGJvb2xlYW47XG59XG5cbi8qKlxuICogYXJyYXkgb2Ygc3VwcG9ydGVkIGlucHV0IHNjcmlwdCB0eXBlcy5cbiAqIHVzZSBwMnRyTXVzaWcyIGZvciBwMnRyTXVzaWcyIHNjcmlwdCBwYXRoLlxuICogdXNlIHRhcHJvb3RLZXlQYXRoU3BlbmQgZm9yIHAydHJNdXNpZzIga2V5IHBhdGguXG4gKi9cbmV4cG9ydCBjb25zdCBpbnB1dFNjcmlwdFR5cGVzID0gWy4uLnNjcmlwdFR5cGVzMk9mMywgJ3RhcHJvb3RLZXlQYXRoU3BlbmQnLCBzY3JpcHRUeXBlUDJzaFAycGtdIGFzIGNvbnN0O1xuXG4vKipcbiAqIGFycmF5IG9mIHN1cHBvcnRlZCBvdXRwdXQgc2NyaXB0IHR5cGVzLlxuICovXG5leHBvcnQgY29uc3Qgb3V0cHV0U2NyaXB0VHlwZXMgPSBzY3JpcHRUeXBlczJPZjM7XG5cbi8qKlxuICogY3JlYXRlIHVuc3BlbnQgb2JqZWN0IGZyb20gaW5wdXQgc2NyaXB0IHR5cGUsIGluZGV4LCBuZXR3b3JrIGFuZCByb290IHdhbGxldCBrZXkuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiB0b1Vuc3BlbnQoXG4gIGlucHV0OiBJbnB1dCxcbiAgaW5kZXg6IG51bWJlcixcbiAgbmV0d29yazogTmV0d29yayxcbiAgcm9vdFdhbGxldEtleXM6IFJvb3RXYWxsZXRLZXlzXG4pOiBVbnNwZW50PGJpZ2ludD4ge1xuICBpZiAoaW5wdXQuc2NyaXB0VHlwZSA9PT0gJ3Ayc2hQMnBrJykge1xuICAgIHJldHVybiBtb2NrUmVwbGF5UHJvdGVjdGlvblVuc3BlbnQobmV0d29yaywgaW5wdXQudmFsdWUsIHsga2V5OiByb290V2FsbGV0S2V5c1sndXNlciddLCB2b3V0OiBpbmRleCB9KTtcbiAgfSBlbHNlIHtcbiAgICBjb25zdCBjaGFpbiA9IGdldEludGVybmFsQ2hhaW5Db2RlKGlucHV0LnNjcmlwdFR5cGUgPT09ICd0YXByb290S2V5UGF0aFNwZW5kJyA/ICdwMnRyTXVzaWcyJyA6IGlucHV0LnNjcmlwdFR5cGUpO1xuICAgIHJldHVybiBtb2NrV2FsbGV0VW5zcGVudChuZXR3b3JrLCBpbnB1dC52YWx1ZSwge1xuICAgICAgY2hhaW4sXG4gICAgICB2b3V0OiBpbmRleCxcbiAgICAgIGtleXM6IHJvb3RXYWxsZXRLZXlzLFxuICAgICAgaW5kZXgsXG4gICAgfSk7XG4gIH1cbn1cblxuLyoqXG4gKiByZXR1cm5zIHNpZ25lciBhbmQgY29zaWduZXIgbmFtZXMgZm9yIElucHV0U2NyaXB0VHlwZS5cbiAqIHVzZXIgYW5kIHVuZGVmaW5lZCBhcyBzaWduZXIgYW5kIGNvc2lnbmVyIHJlc3BlY3RpdmVseSBmb3IgcDJzaFAycGsuXG4gKiB1c2VyIGFuZCBiYWNrdXAgYXMgc2lnbmVyIGFuZCBjb3NpZ25lciByZXNwZWN0aXZlbHkgZm9yIHAydHJNdXNpZzIuXG4gKiB1c2VyIGFuZCBiaXRnbyBhcyBzaWduZXIgYW5kIGNvc2lnbmVyIHJlc3BlY3RpdmVseSBmb3Igb3RoZXIgaW5wdXQgc2NyaXB0IHR5cGVzLlxuICovXG5leHBvcnQgZnVuY3Rpb24gZ2V0U2lnbmVycyhpbnB1dFR5cGU6IElucHV0U2NyaXB0VHlwZSk6IHsgc2lnbmVyTmFtZTogS2V5TmFtZTsgY29zaWduZXJOYW1lPzogS2V5TmFtZSB9IHtcbiAgcmV0dXJuIHtcbiAgICBzaWduZXJOYW1lOiAndXNlcicsXG4gICAgY29zaWduZXJOYW1lOiBpbnB1dFR5cGUgPT09ICdwMnNoUDJwaycgPyB1bmRlZmluZWQgOiBpbnB1dFR5cGUgPT09ICdwMnRyTXVzaWcyJyA/ICdiYWNrdXAnIDogJ2JpdGdvJyxcbiAgfTtcbn1cblxuLyoqXG4gKiBzaWducyB3aXRoIGZpcnN0IG9yIHNlY29uZCBzaWduYXR1cmUgZm9yIHNpbmdsZSBpbnB1dC5cbiAqIHAyc2hQMnBrIGlzIHNpZ25lZCBvbmx5IHdpdGggZmlyc3Qgc2lnbi5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHNpZ25Qc2J0SW5wdXQoXG4gIHBzYnQ6IFV0eG9Qc2J0LFxuICBpbnB1dDogSW5wdXQsXG4gIGlucHV0SW5kZXg6IG51bWJlcixcbiAgcm9vdFdhbGxldEtleXM6IFJvb3RXYWxsZXRLZXlzLFxuICBzaWduOiAnaGFsZnNpZ25lZCcgfCAnZnVsbHNpZ25lZCcsXG4gIHBhcmFtcz86IHtcbiAgICBzaWduZXJzPzogeyBzaWduZXJOYW1lOiBLZXlOYW1lOyBjb3NpZ25lck5hbWU/OiBLZXlOYW1lIH07XG4gICAgZGV0ZXJtaW5pc3RpYz86IGJvb2xlYW47XG4gICAgc2tpcE5vbldpdG5lc3NVdHhvPzogYm9vbGVhbjtcbiAgfVxuKTogdm9pZCB7XG4gIGZ1bmN0aW9uIHNpZ25Qc2J0KHBzYnQ6IFV0eG9Qc2J0LCBzaWduRnVuYzogKCkgPT4gdm9pZCwgc2tpcE5vbldpdG5lc3NVdHhvPzogYm9vbGVhbikge1xuICAgIGlmIChza2lwTm9uV2l0bmVzc1V0eG8pIHtcbiAgICAgIHdpdGhVbnNhZmVOb25TZWd3aXQocHNidCwgc2lnbkZ1bmMpO1xuICAgIH0gZWxzZSB7XG4gICAgICBzaWduRnVuYygpO1xuICAgIH1cbiAgfVxuXG4gIGNvbnN0IHsgc2lnbmVycywgZGV0ZXJtaW5pc3RpYywgc2tpcE5vbldpdG5lc3NVdHhvIH0gPSBwYXJhbXMgPz8ge307XG4gIGNvbnN0IHsgc2lnbmVyTmFtZSwgY29zaWduZXJOYW1lIH0gPSBzaWduZXJzID8gc2lnbmVycyA6IGdldFNpZ25lcnMoaW5wdXQuc2NyaXB0VHlwZSk7XG4gIGlmIChzaWduID09PSAnaGFsZnNpZ25lZCcpIHtcbiAgICBpZiAoaW5wdXQuc2NyaXB0VHlwZSA9PT0gJ3Ayc2hQMnBrJykge1xuICAgICAgc2lnblBzYnQocHNidCwgKCkgPT4gcHNidC5zaWduSW5wdXQoaW5wdXRJbmRleCwgcm9vdFdhbGxldEtleXNbc2lnbmVyTmFtZV0pLCBza2lwTm9uV2l0bmVzc1V0eG8pO1xuICAgIH0gZWxzZSB7XG4gICAgICBzaWduUHNidChwc2J0LCAoKSA9PiBwc2J0LnNpZ25JbnB1dEhEKGlucHV0SW5kZXgsIHJvb3RXYWxsZXRLZXlzW3NpZ25lck5hbWVdKSwgc2tpcE5vbldpdG5lc3NVdHhvKTtcbiAgICB9XG4gIH1cbiAgaWYgKHNpZ24gPT09ICdmdWxsc2lnbmVkJyAmJiBjb3NpZ25lck5hbWUgJiYgaW5wdXQuc2NyaXB0VHlwZSAhPT0gJ3Ayc2hQMnBrJykge1xuICAgIHNpZ25Qc2J0KFxuICAgICAgcHNidCxcbiAgICAgICgpID0+IHBzYnQuc2lnbklucHV0SEQoaW5wdXRJbmRleCwgcm9vdFdhbGxldEtleXNbY29zaWduZXJOYW1lXSwgeyBkZXRlcm1pbmlzdGljIH0pLFxuICAgICAgc2tpcE5vbldpdG5lc3NVdHhvXG4gICAgKTtcbiAgfVxufVxuXG4vKipcbiAqIHNpZ25zIHdpdGggZmlyc3Qgb3Igc2Vjb25kIHNpZ25hdHVyZSBmb3IgYWxsIGlucHV0cy5cbiAqIHAyc2hQMnBrIGlzIHNpZ25lZCBvbmx5IHdpdGggZmlyc3Qgc2lnbi5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHNpZ25BbGxQc2J0SW5wdXRzKFxuICBwc2J0OiBVdHhvUHNidCxcbiAgaW5wdXRzOiBJbnB1dFtdLFxuICByb290V2FsbGV0S2V5czogUm9vdFdhbGxldEtleXMsXG4gIHNpZ246ICdoYWxmc2lnbmVkJyB8ICdmdWxsc2lnbmVkJyxcbiAgcGFyYW1zPzoge1xuICAgIHNpZ25lcnM/OiB7IHNpZ25lck5hbWU6IEtleU5hbWU7IGNvc2lnbmVyTmFtZT86IEtleU5hbWUgfTtcbiAgICBkZXRlcm1pbmlzdGljPzogYm9vbGVhbjtcbiAgICBza2lwTm9uV2l0bmVzc1V0eG8/OiBib29sZWFuO1xuICB9XG4pOiB2b2lkIHtcbiAgY29uc3QgeyBzaWduZXJzLCBkZXRlcm1pbmlzdGljLCBza2lwTm9uV2l0bmVzc1V0eG8gfSA9IHBhcmFtcyA/PyB7fTtcbiAgaW5wdXRzLmZvckVhY2goKGlucHV0LCBpbnB1dEluZGV4KSA9PiB7XG4gICAgc2lnblBzYnRJbnB1dChwc2J0LCBpbnB1dCwgaW5wdXRJbmRleCwgcm9vdFdhbGxldEtleXMsIHNpZ24sIHsgc2lnbmVycywgZGV0ZXJtaW5pc3RpYywgc2tpcE5vbldpdG5lc3NVdHhvIH0pO1xuICB9KTtcbn1cblxuLyoqXG4gKiBjb25zdHJ1Y3QgcHNidCBmb3IgZ2l2ZW4gaW5wdXRzLCBvdXRwdXRzLCBuZXR3b3JrIGFuZCByb290IHdhbGxldCBrZXlzLlxuICovXG5leHBvcnQgZnVuY3Rpb24gY29uc3RydWN0UHNidChcbiAgaW5wdXRzOiBJbnB1dFtdLFxuICBvdXRwdXRzOiBPdXRwdXRbXSxcbiAgbmV0d29yazogTmV0d29yayxcbiAgcm9vdFdhbGxldEtleXM6IFJvb3RXYWxsZXRLZXlzLFxuICBzaWduOiAndW5zaWduZWQnIHwgJ2hhbGZzaWduZWQnIHwgJ2Z1bGxzaWduZWQnLFxuICBwYXJhbXM/OiB7XG4gICAgc2lnbmVycz86IHsgc2lnbmVyTmFtZTogS2V5TmFtZTsgY29zaWduZXJOYW1lPzogS2V5TmFtZSB9O1xuICAgIGRldGVybWluaXN0aWM/OiBib29sZWFuO1xuICAgIHNraXBOb25XaXRuZXNzVXR4bz86IGJvb2xlYW47XG4gIH1cbik6IFV0eG9Qc2J0IHtcbiAgY29uc3QgeyBzaWduZXJzLCBkZXRlcm1pbmlzdGljLCBza2lwTm9uV2l0bmVzc1V0eG8gfSA9IHBhcmFtcyA/PyB7fTtcbiAgY29uc3QgdG90YWxJbnB1dEFtb3VudCA9IGlucHV0cy5yZWR1Y2UoKHN1bSwgaW5wdXQpID0+IHN1bSArIGlucHV0LnZhbHVlLCBCaWdJbnQoMCkpO1xuICBjb25zdCBvdXRwdXRJbnB1dEFtb3VudCA9IG91dHB1dHMucmVkdWNlKChzdW0sIG91dHB1dCkgPT4gc3VtICsgb3V0cHV0LnZhbHVlLCBCaWdJbnQoMCkpO1xuICBhc3NlcnQodG90YWxJbnB1dEFtb3VudCA+PSBvdXRwdXRJbnB1dEFtb3VudCwgJ3RvdGFsIG91dHB1dCBjYW4gbm90IGV4Y2VlZCB0b3RhbCBpbnB1dCcpO1xuICBhc3NlcnQoXG4gICAgIW91dHB1dHMuc29tZSgobykgPT4gKG8uc2NyaXB0VHlwZSAmJiBvLmFkZHJlc3MpIHx8ICghby5zY3JpcHRUeXBlICYmICFvLmFkZHJlc3MpKSxcbiAgICAnb25seSBlaXRoZXIgb3V0cHV0IHNjcmlwdCB0eXBlIG9yIGFkZHJlc3Mgc2hvdWxkIGJlIHByb3ZpZGVkJ1xuICApO1xuXG4gIGNvbnN0IHBzYnQgPSBjcmVhdGVQc2J0Rm9yTmV0d29yayh7IG5ldHdvcmsgfSk7XG4gIGNvbnN0IHVuc3BlbnRzID0gaW5wdXRzLm1hcCgoaW5wdXQsIGkpID0+IHRvVW5zcGVudChpbnB1dCwgaSwgbmV0d29yaywgcm9vdFdhbGxldEtleXMpKTtcblxuICB1bnNwZW50cy5mb3JFYWNoKCh1LCBpKSA9PiB7XG4gICAgY29uc3QgeyBzaWduZXJOYW1lLCBjb3NpZ25lck5hbWUgfSA9IHNpZ25lcnMgPyBzaWduZXJzIDogZ2V0U2lnbmVycyhpbnB1dHNbaV0uc2NyaXB0VHlwZSk7XG4gICAgaWYgKGlzV2FsbGV0VW5zcGVudCh1KSAmJiBjb3NpZ25lck5hbWUpIHtcbiAgICAgIGFkZFdhbGxldFVuc3BlbnRUb1BzYnQocHNidCwgdSwgcm9vdFdhbGxldEtleXMsIHNpZ25lck5hbWUsIGNvc2lnbmVyTmFtZSwgeyBza2lwTm9uV2l0bmVzc1V0eG8gfSk7XG4gICAgfSBlbHNlIHtcbiAgICAgIGNvbnN0IHsgcmVkZWVtU2NyaXB0IH0gPSBjcmVhdGVPdXRwdXRTY3JpcHRQMnNoUDJwayhyb290V2FsbGV0S2V5c1tzaWduZXJOYW1lXS5wdWJsaWNLZXkpO1xuICAgICAgYXNzZXJ0KHJlZGVlbVNjcmlwdCk7XG4gICAgICBhZGRSZXBsYXlQcm90ZWN0aW9uVW5zcGVudFRvUHNidChwc2J0LCB1LCByZWRlZW1TY3JpcHQsIHsgc2tpcE5vbldpdG5lc3NVdHhvIH0pO1xuICAgIH1cbiAgfSk7XG5cbiAgb3V0cHV0cy5mb3JFYWNoKChvdXRwdXQsIGkpID0+IHtcbiAgICBpZiAob3V0cHV0LnNjcmlwdFR5cGUpIHtcbiAgICAgIGFkZFdhbGxldE91dHB1dFRvUHNidChcbiAgICAgICAgcHNidCxcbiAgICAgICAgcm9vdFdhbGxldEtleXMsXG4gICAgICAgIG91dHB1dC5pc0ludGVybmFsQWRkcmVzcyA/IGdldEludGVybmFsQ2hhaW5Db2RlKG91dHB1dC5zY3JpcHRUeXBlKSA6IGdldEV4dGVybmFsQ2hhaW5Db2RlKG91dHB1dC5zY3JpcHRUeXBlKSxcbiAgICAgICAgaSxcbiAgICAgICAgb3V0cHV0LnZhbHVlXG4gICAgICApO1xuICAgIH0gZWxzZSBpZiAob3V0cHV0LmFkZHJlc3MpIHtcbiAgICAgIGNvbnN0IHsgYWRkcmVzcywgdmFsdWUgfSA9IG91dHB1dDtcbiAgICAgIHBzYnQuYWRkT3V0cHV0KHsgc2NyaXB0OiB0b091dHB1dFNjcmlwdChhZGRyZXNzLCBuZXR3b3JrKSwgdmFsdWUgfSk7XG4gICAgfVxuICB9KTtcblxuICBpZiAoc2lnbiA9PT0gJ3Vuc2lnbmVkJykge1xuICAgIHJldHVybiBwc2J0O1xuICB9XG5cbiAgcHNidC5zZXRBbGxJbnB1dHNNdXNpZzJOb25jZUhEKHJvb3RXYWxsZXRLZXlzWyd1c2VyJ10pO1xuICBwc2J0LnNldEFsbElucHV0c011c2lnMk5vbmNlSEQocm9vdFdhbGxldEtleXNbJ2JpdGdvJ10sIHsgZGV0ZXJtaW5pc3RpYyB9KTtcblxuICBzaWduQWxsUHNidElucHV0cyhwc2J0LCBpbnB1dHMsIHJvb3RXYWxsZXRLZXlzLCAnaGFsZnNpZ25lZCcsIHsgc2lnbmVycywgc2tpcE5vbldpdG5lc3NVdHhvIH0pO1xuXG4gIGlmIChzaWduID09PSAnZnVsbHNpZ25lZCcpIHtcbiAgICBzaWduQWxsUHNidElucHV0cyhwc2J0LCBpbnB1dHMsIHJvb3RXYWxsZXRLZXlzLCBzaWduLCB7IHNpZ25lcnMsIGRldGVybWluaXN0aWMsIHNraXBOb25XaXRuZXNzVXR4byB9KTtcbiAgfVxuXG4gIHJldHVybiBwc2J0O1xufVxuXG4vKipcbiAqIFZlcmlmaWVzIHNpZ25hdHVyZXMgb2YgZnVsbHkgc2lnbmVkIHR4ICh3aXRoIHRhcHJvb3Qga2V5IHBhdGggc3VwcG9ydCkuXG4gKiBOT1RFOiB0YXByb290IGtleSBwYXRoIHR4IGNhbiBvbmx5IGJlIGJ1aWx0IGFuZCBzaWduZWQgd2l0aCBQU0JULlxuICovXG5leHBvcnQgZnVuY3Rpb24gdmVyaWZ5RnVsbHlTaWduZWRTaWduYXR1cmVzKFxuICB0eDogVXR4b1RyYW5zYWN0aW9uPGJpZ2ludD4sXG4gIHVuc3BlbnRzOiBVbnNwZW50PGJpZ2ludD5bXSxcbiAgd2FsbGV0S2V5czogUm9vdFdhbGxldEtleXMsXG4gIHNpZ25lcjogS2V5TmFtZSxcbiAgY29zaWduZXI6IEtleU5hbWVcbik6IGJvb2xlYW4ge1xuICBjb25zdCBwcmV2T3V0cHV0cyA9IHVuc3BlbnRzLm1hcCgodSkgPT4gdG9PdXRwdXQodSwgdHgubmV0d29yaykpO1xuICByZXR1cm4gdW5zcGVudHMuZXZlcnkoKHUsIGluZGV4KSA9PiB7XG4gICAgaWYgKHBhcnNlU2lnbmF0dXJlU2NyaXB0Mk9mMyh0eC5pbnNbaW5kZXhdKS5zY3JpcHRUeXBlID09PSAndGFwcm9vdEtleVBhdGhTcGVuZCcpIHtcbiAgICAgIGNvbnN0IHJlc3VsdCA9IGdldFNpZ25hdHVyZVZlcmlmaWNhdGlvbnModHgsIGluZGV4LCB1LnZhbHVlLCB1bmRlZmluZWQsIHByZXZPdXRwdXRzKTtcbiAgICAgIHJldHVybiByZXN1bHQubGVuZ3RoID09PSAxICYmIHJlc3VsdFswXS5zaWduYXR1cmU7XG4gICAgfSBlbHNlIHtcbiAgICAgIGNvbnN0IHJlc3VsdCA9IHZlcmlmeVNpZ25hdHVyZVdpdGhVbnNwZW50KHR4LCBpbmRleCwgdW5zcGVudHMsIHdhbGxldEtleXMpO1xuICAgICAgaWYgKChzaWduZXIgPT09ICd1c2VyJyAmJiBjb3NpZ25lciA9PT0gJ2JpdGdvJykgfHwgKHNpZ25lciA9PT0gJ2JpdGdvJyAmJiBjb3NpZ25lciA9PT0gJ3VzZXInKSkge1xuICAgICAgICByZXR1cm4gcmVzdWx0WzBdICYmICFyZXN1bHRbMV0gJiYgcmVzdWx0WzJdO1xuICAgICAgfSBlbHNlIGlmICgoc2lnbmVyID09PSAndXNlcicgJiYgY29zaWduZXIgPT09ICdiYWNrdXAnKSB8fCAoc2lnbmVyID09PSAnYmFja3VwJyAmJiBjb3NpZ25lciA9PT0gJ3VzZXInKSkge1xuICAgICAgICByZXR1cm4gcmVzdWx0WzBdICYmIHJlc3VsdFsxXSAmJiAhcmVzdWx0WzJdO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcmV0dXJuICFyZXN1bHRbMF0gJiYgcmVzdWx0WzFdICYmIHJlc3VsdFsyXTtcbiAgICAgIH1cbiAgICB9XG4gIH0pO1xufVxuIl19