"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.addWalletUnspentToPsbt = exports.updateWalletUnspentForPsbt = exports.addReplayProtectionUnspentToPsbt = exports.updateReplayProtectionUnspentToPsbt = exports.psbtIncludesUnspentAtIndex = exports.verifySignatureWithUnspent = exports.signInputWithUnspent = exports.isWalletUnspent = exports.MAX_BIP125_RBF_SEQUENCE = exports.TX_INPUT_SEQUENCE_NUMBER_FINAL = void 0;
const __1 = require("../..");
const outputScripts_1 = require("../outputScripts");
const address_1 = require("../../address");
const signature_1 = require("../signature");
const Unspent_1 = require("../Unspent");
const chains_1 = require("./chains");
const Musig2_1 = require("../Musig2");
const transaction_1 = require("../transaction");
const parseInput_1 = require("../parseInput");
const utils_1 = require("bip174/src/lib/utils");
const PsbtUtil_1 = require("../PsbtUtil");
/** Final (non-replaceable) */
exports.TX_INPUT_SEQUENCE_NUMBER_FINAL = 0xffffffff;
/** Non-Final (Replaceable)
 * Reference: https://github.com/bitcoin/bitcoin/blob/v25.1/src/rpc/rawtransaction_util.cpp#L49
 * */
exports.MAX_BIP125_RBF_SEQUENCE = 0xffffffff - 2;
function isWalletUnspent(u) {
    return u.chain !== undefined;
}
exports.isWalletUnspent = isWalletUnspent;
function signInputWithUnspent(txBuilder, inputIndex, unspent, unspentSigner) {
    const { walletKeys, signer, cosigner } = unspentSigner.deriveForChainAndIndex(unspent.chain, unspent.index);
    const scriptType = outputScripts_1.scriptTypeForChain(unspent.chain);
    const pubScript = outputScripts_1.createOutputScript2of3(walletKeys.publicKeys, scriptType).scriptPubKey;
    const pubScriptExpected = address_1.toOutputScript(unspent.address, txBuilder.network);
    if (!pubScript.equals(pubScriptExpected)) {
        throw new Error(`pubscript mismatch: expected ${pubScriptExpected.toString('hex')} got ${pubScript.toString('hex')}`);
    }
    signature_1.signInput2Of3(txBuilder, inputIndex, scriptType, walletKeys.publicKeys, signer, cosigner.publicKey, unspent.value);
}
exports.signInputWithUnspent = signInputWithUnspent;
/**
 * @param tx
 * @param inputIndex
 * @param unspents
 * @param walletKeys
 * @return triple of booleans indicating a valid signature for each pubkey
 */
function verifySignatureWithUnspent(tx, inputIndex, unspents, walletKeys) {
    var _a, _b;
    if (tx.ins.length !== unspents.length) {
        throw new Error(`input length must match unspents length`);
    }
    const input = tx.ins[inputIndex];
    /* istanbul ignore next */
    if (!input) {
        throw new Error(`no input at index ${inputIndex}`);
    }
    const unspent = unspents[inputIndex];
    if (!isWalletUnspent(unspent) || (!((_a = input.script) === null || _a === void 0 ? void 0 : _a.length) && !((_b = input.witness) === null || _b === void 0 ? void 0 : _b.length))) {
        return [false, false, false];
    }
    const parsedInput = parseInput_1.parseSignatureScript(input);
    const prevOutputs = unspents.map((u) => Unspent_1.toOutput(u, tx.network));
    // If it is a taproot keyPathSpend input, the only valid signature combinations is user-bitgo. We can
    // only verify that the aggregated signature is valid, not that the individual partial-signature is valid.
    // Therefore, we can only say that either all partial signatures are valid, or none are.
    if (parsedInput.scriptType === 'taprootKeyPathSpend') {
        const result = signature_1.getSignatureVerifications(tx, inputIndex, unspent.value, undefined, prevOutputs);
        return result.length === 1 && result[0].signature ? [true, false, true] : [false, false, false];
    }
    return signature_1.verifySignatureWithPublicKeys(tx, inputIndex, prevOutputs, walletKeys.deriveForChainAndIndex(unspent.chain, unspent.index).publicKeys);
}
exports.verifySignatureWithUnspent = verifySignatureWithUnspent;
/**
 * @param psbt
 * @param inputIndex
 * @param id Unspent ID
 * @returns true iff the unspent ID on the unspent and psbt input match
 */
function psbtIncludesUnspentAtIndex(psbt, inputIndex, id) {
    utils_1.checkForInput(psbt.data.inputs, inputIndex);
    const { txid, vout } = Unspent_1.parseOutputId(id);
    const psbtOutPoint = Unspent_1.getOutputIdForInput(psbt.txInputs[inputIndex]);
    return psbtOutPoint.txid === txid && psbtOutPoint.vout === vout;
}
exports.psbtIncludesUnspentAtIndex = psbtIncludesUnspentAtIndex;
/**
 * Update the psbt input at the given index
 * @param psbt
 * @param inputIndex
 * @param u
 * @param redeemScript Only overrides if there is no redeemScript in the input currently
 */
function updateReplayProtectionUnspentToPsbt(psbt, inputIndex, u, redeemScript, customParams) {
    if (!psbtIncludesUnspentAtIndex(psbt, inputIndex, u.id)) {
        throw new Error(`unspent does not correspond to psbt input`);
    }
    const input = utils_1.checkForInput(psbt.data.inputs, inputIndex);
    if (redeemScript && !input.redeemScript) {
        psbt.updateInput(inputIndex, { redeemScript });
    }
    // Because Zcash directly hashes the value for non-segwit transactions, we do not need to check indirectly
    // with the previous transaction. Therefore, we can treat Zcash non-segwit transactions as Bitcoin
    // segwit transactions
    const isZcash = __1.getMainnet(psbt.network) === __1.networks.zcash;
    if (!Unspent_1.isUnspentWithPrevTx(u) && !isZcash && !(customParams === null || customParams === void 0 ? void 0 : customParams.skipNonWitnessUtxo)) {
        throw new Error('Error, require previous tx to add to PSBT');
    }
    if ((isZcash && !input.witnessUtxo) || (customParams === null || customParams === void 0 ? void 0 : customParams.skipNonWitnessUtxo)) {
        const { script, value } = Unspent_1.toPrevOutput(u, psbt.network);
        psbt.updateInput(inputIndex, { witnessUtxo: { script, value } });
    }
    else if (!isZcash && !input.nonWitnessUtxo) {
        psbt.updateInput(inputIndex, { nonWitnessUtxo: u.prevTx });
    }
    const sighashType = signature_1.getDefaultSigHash(psbt.network);
    if (psbt.data.inputs[inputIndex].sighashType === undefined) {
        psbt.updateInput(inputIndex, { sighashType });
    }
}
exports.updateReplayProtectionUnspentToPsbt = updateReplayProtectionUnspentToPsbt;
function addUnspentToPsbt(psbt, id, { sequenceNumber = exports.TX_INPUT_SEQUENCE_NUMBER_FINAL } = {}) {
    const { txid, vout } = Unspent_1.parseOutputId(id);
    psbt.addInput({
        hash: txid,
        index: vout,
        sequence: sequenceNumber,
    });
}
function addReplayProtectionUnspentToPsbt(psbt, u, redeemScript, customParams) {
    addUnspentToPsbt(psbt, u.id);
    updateReplayProtectionUnspentToPsbt(psbt, psbt.inputCount - 1, u, redeemScript, customParams);
}
exports.addReplayProtectionUnspentToPsbt = addReplayProtectionUnspentToPsbt;
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
function updateWalletUnspentForPsbt(psbt, inputIndex, u, rootWalletKeys, signer, cosigner, customParams) {
    if (!psbtIncludesUnspentAtIndex(psbt, inputIndex, u.id)) {
        throw new Error(`unspent does not correspond to psbt input`);
    }
    const input = utils_1.checkForInput(psbt.data.inputs, inputIndex);
    // Because Zcash directly hashes the value for non-segwit transactions, we do not need to check indirectly
    // with the previous transaction. Therefore, we can treat Zcash non-segwit transactions as Bitcoin
    // segwit transactions
    const isZcashOrSegwit = chains_1.isSegwit(u.chain) || __1.getMainnet(psbt.network) === __1.networks.zcash;
    if ((isZcashOrSegwit && !input.witnessUtxo) || (customParams === null || customParams === void 0 ? void 0 : customParams.skipNonWitnessUtxo)) {
        const { script, value } = Unspent_1.toPrevOutput(u, psbt.network);
        psbt.updateInput(inputIndex, { witnessUtxo: { script, value } });
    }
    else if (!isZcashOrSegwit) {
        if (!Unspent_1.isUnspentWithPrevTx(u)) {
            throw new Error('Error, require previous tx to add to PSBT');
        }
        if (!input.witnessUtxo && !input.nonWitnessUtxo) {
            // Force the litecoin transaction to have no MWEB advanced transaction flag
            if (__1.getMainnet(psbt.network) === __1.networks.litecoin) {
                u.prevTx = transaction_1.createTransactionFromBuffer(u.prevTx, psbt.network, { amountType: 'bigint' }).toBuffer();
            }
            psbt.updateInput(inputIndex, { nonWitnessUtxo: u.prevTx });
        }
    }
    const walletKeys = rootWalletKeys.deriveForChainAndIndex(u.chain, u.index);
    const scriptType = outputScripts_1.scriptTypeForChain(u.chain);
    const sighashType = signature_1.getDefaultSigHash(psbt.network, scriptType);
    if (psbt.data.inputs[inputIndex].sighashType === undefined) {
        psbt.updateInput(inputIndex, { sighashType });
    }
    const isBackupFlow = signer === 'backup' || cosigner === 'backup';
    if (scriptType === 'p2tr' || (scriptType === 'p2trMusig2' && isBackupFlow)) {
        if (input.tapLeafScript && input.tapBip32Derivation) {
            return;
        }
        const createSpendScriptP2trFn = scriptType === 'p2tr' ? outputScripts_1.createSpendScriptP2tr : outputScripts_1.createSpendScriptP2trMusig2;
        const { controlBlock, witnessScript, leafVersion, leafHash } = createSpendScriptP2trFn(walletKeys.publicKeys, [
            walletKeys[signer].publicKey,
            walletKeys[cosigner].publicKey,
        ]);
        if (!input.tapLeafScript) {
            psbt.updateInput(inputIndex, {
                tapLeafScript: [{ controlBlock, script: witnessScript, leafVersion }],
            });
        }
        if (!input.tapBip32Derivation) {
            psbt.updateInput(inputIndex, {
                tapBip32Derivation: [signer, cosigner].map((key) => ({
                    leafHashes: [leafHash],
                    pubkey: outputScripts_1.toXOnlyPublicKey(walletKeys[key].publicKey),
                    path: rootWalletKeys.getDerivationPath(rootWalletKeys[key], u.chain, u.index),
                    masterFingerprint: rootWalletKeys[key].fingerprint,
                })),
            });
        }
    }
    else if (scriptType === 'p2trMusig2') {
        const { internalPubkey: tapInternalKey, outputPubkey: tapOutputKey, taptreeRoot, } = outputScripts_1.createKeyPathP2trMusig2(walletKeys.publicKeys);
        if (psbt.getProprietaryKeyVals(inputIndex, {
            identifier: PsbtUtil_1.PSBT_PROPRIETARY_IDENTIFIER,
            subtype: PsbtUtil_1.ProprietaryKeySubtype.MUSIG2_PARTICIPANT_PUB_KEYS,
        }).length === 0) {
            const participantsKeyValData = Musig2_1.encodePsbtMusig2Participants({
                tapOutputKey,
                tapInternalKey,
                participantPubKeys: [walletKeys.user.publicKey, walletKeys.bitgo.publicKey],
            });
            psbt.addProprietaryKeyValToInput(inputIndex, participantsKeyValData);
        }
        if (!input.tapInternalKey) {
            psbt.updateInput(inputIndex, {
                tapInternalKey: tapInternalKey,
            });
        }
        if (!input.tapMerkleRoot) {
            psbt.updateInput(inputIndex, {
                tapMerkleRoot: taptreeRoot,
            });
        }
        if (!input.tapBip32Derivation) {
            psbt.updateInput(inputIndex, {
                tapBip32Derivation: [signer, cosigner].map((key) => ({
                    leafHashes: [],
                    pubkey: outputScripts_1.toXOnlyPublicKey(walletKeys[key].publicKey),
                    path: rootWalletKeys.getDerivationPath(rootWalletKeys[key], u.chain, u.index),
                    masterFingerprint: rootWalletKeys[key].fingerprint,
                })),
            });
        }
    }
    else {
        if (!input.bip32Derivation) {
            psbt.updateInput(inputIndex, {
                bip32Derivation: [0, 1, 2].map((idx) => ({
                    pubkey: walletKeys.triple[idx].publicKey,
                    path: walletKeys.paths[idx],
                    masterFingerprint: rootWalletKeys.triple[idx].fingerprint,
                })),
            });
        }
        const { witnessScript, redeemScript } = outputScripts_1.createOutputScript2of3(walletKeys.publicKeys, scriptType);
        if (witnessScript && !input.witnessScript) {
            psbt.updateInput(inputIndex, { witnessScript });
        }
        if (redeemScript && !input.redeemScript) {
            psbt.updateInput(inputIndex, { redeemScript });
        }
    }
}
exports.updateWalletUnspentForPsbt = updateWalletUnspentForPsbt;
function addWalletUnspentToPsbt(psbt, u, rootWalletKeys, signer, cosigner, customParams) {
    let sequenceNumber = exports.TX_INPUT_SEQUENCE_NUMBER_FINAL;
    if (customParams && customParams.isReplaceableByFee) {
        sequenceNumber = exports.MAX_BIP125_RBF_SEQUENCE;
    }
    addUnspentToPsbt(psbt, u.id, { sequenceNumber });
    updateWalletUnspentForPsbt(psbt, psbt.inputCount - 1, u, rootWalletKeys, signer, cosigner, customParams ? { skipNonWitnessUtxo: customParams.skipNonWitnessUtxo } : {});
}
exports.addWalletUnspentToPsbt = addWalletUnspentToPsbt;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiVW5zcGVudC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3NyYy9iaXRnby93YWxsZXQvVW5zcGVudC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFBQSw2QkFBc0Q7QUFFdEQsb0RBTzBCO0FBQzFCLDJDQUErQztBQUMvQyw0Q0FLc0I7QUFLdEIsd0NBUW9CO0FBQ3BCLHFDQUErQztBQUUvQyxzQ0FBeUQ7QUFDekQsZ0RBQTZEO0FBQzdELDhDQUFxRDtBQUNyRCxnREFBcUQ7QUFDckQsMENBQWlGO0FBRWpGLDhCQUE4QjtBQUNqQixRQUFBLDhCQUE4QixHQUFHLFVBQVUsQ0FBQztBQUV6RDs7S0FFSztBQUNRLFFBQUEsdUJBQXVCLEdBQUcsVUFBVSxHQUFHLENBQUMsQ0FBQztBQWF0RCxTQUFnQixlQUFlLENBQWtDLENBQW1CO0lBQ2xGLE9BQVEsQ0FBNEIsQ0FBQyxLQUFLLEtBQUssU0FBUyxDQUFDO0FBQzNELENBQUM7QUFGRCwwQ0FFQztBQUVELFNBQWdCLG9CQUFvQixDQUNsQyxTQUEwQyxFQUMxQyxVQUFrQixFQUNsQixPQUErQixFQUMvQixhQUFrRDtJQUVsRCxNQUFNLEVBQUUsVUFBVSxFQUFFLE1BQU0sRUFBRSxRQUFRLEVBQUUsR0FBRyxhQUFhLENBQUMsc0JBQXNCLENBQUMsT0FBTyxDQUFDLEtBQUssRUFBRSxPQUFPLENBQUMsS0FBSyxDQUFDLENBQUM7SUFDNUcsTUFBTSxVQUFVLEdBQUcsa0NBQWtCLENBQUMsT0FBTyxDQUFDLEtBQUssQ0FBQyxDQUFDO0lBQ3JELE1BQU0sU0FBUyxHQUFHLHNDQUFzQixDQUFDLFVBQVUsQ0FBQyxVQUFVLEVBQUUsVUFBVSxDQUFDLENBQUMsWUFBWSxDQUFDO0lBQ3pGLE1BQU0saUJBQWlCLEdBQUcsd0JBQWMsQ0FBQyxPQUFPLENBQUMsT0FBTyxFQUFFLFNBQVMsQ0FBQyxPQUFrQixDQUFDLENBQUM7SUFDeEYsSUFBSSxDQUFDLFNBQVMsQ0FBQyxNQUFNLENBQUMs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SSxDQUFDLFdBQVcsQ0FBQyxVQUFVLEVBQUUsRUFBRSxhQUFhLEVBQUUsQ0FBQyxDQUFDO1NBQ2pEO1FBQ0QsSUFBSSxZQUFZLElBQUksQ0FBQyxLQUFLLENBQUMsWUFBWSxFQUFFO1lBQ3ZDLElBQUksQ0FBQyxXQUFXLENBQUMsVUFBVSxFQUFFLEVBQUUsWUFBWSxFQUFFLENBQUMsQ0FBQztTQUNoRDtLQUNGO0FBQ0gsQ0FBQztBQWxJRCxnRUFrSUM7QUFFRCxTQUFnQixzQkFBc0IsQ0FDcEMsSUFBYyxFQUNkLENBQXdCLEVBQ3hCLGNBQThCLEVBQzlCLE1BQWUsRUFDZixRQUFpQixFQUNqQixZQUE2RTtJQUU3RSxJQUFJLGNBQWMsR0FBRyxzQ0FBOEIsQ0FBQztJQUNwRCxJQUFJLFlBQVksSUFBSSxZQUFZLENBQUMsa0JBQWtCLEVBQUU7UUFDbkQsY0FBYyxHQUFHLCtCQUF1QixDQUFDO0tBQzFDO0lBRUQsZ0JBQWdCLENBQUMsSUFBSSxFQUFFLENBQUMsQ0FBQyxFQUFFLEVBQUUsRUFBRSxjQUFjLEVBQUUsQ0FBQyxDQUFDO0lBQ2pELDBCQUEwQixDQUN4QixJQUFJLEVBQ0osSUFBSSxDQUFDLFVBQVUsR0FBRyxDQUFDLEVBQ25CLENBQUMsRUFDRCxjQUFjLEVBQ2QsTUFBTSxFQUNOLFFBQVEsRUFDUixZQUFZLENBQUMsQ0FBQyxDQUFDLEVBQUUsa0JBQWtCLEVBQUUsWUFBWSxDQUFDLGtCQUFrQixFQUFFLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FDNUUsQ0FBQztBQUNKLENBQUM7QUF2QkQsd0RBdUJDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgZ2V0TWFpbm5ldCwgTmV0d29yaywgbmV0d29ya3MgfSBmcm9tICcuLi8uLic7XG5pbXBvcnQgeyBVdHhvVHJhbnNhY3Rpb25CdWlsZGVyIH0gZnJvbSAnLi4vVXR4b1RyYW5zYWN0aW9uQnVpbGRlcic7XG5pbXBvcnQge1xuICBjcmVhdGVLZXlQYXRoUDJ0ck11c2lnMixcbiAgY3JlYXRlT3V0cHV0U2NyaXB0Mm9mMyxcbiAgY3JlYXRlU3BlbmRTY3JpcHRQMnRyLFxuICBjcmVhdGVTcGVuZFNjcmlwdFAydHJNdXNpZzIsXG4gIHNjcmlwdFR5cGVGb3JDaGFpbixcbiAgdG9YT25seVB1YmxpY0tleSxcbn0gZnJvbSAnLi4vb3V0cHV0U2NyaXB0cyc7XG5pbXBvcnQgeyB0b091dHB1dFNjcmlwdCB9IGZyb20gJy4uLy4uL2FkZHJlc3MnO1xuaW1wb3J0IHtcbiAgZ2V0RGVmYXVsdFNpZ0hhc2gsXG4gIGdldFNpZ25hdHVyZVZlcmlmaWNhdGlvbnMsXG4gIHNpZ25JbnB1dDJPZjMsXG4gIHZlcmlmeVNpZ25hdHVyZVdpdGhQdWJsaWNLZXlzLFxufSBmcm9tICcuLi9zaWduYXR1cmUnO1xuaW1wb3J0IHsgV2FsbGV0VW5zcGVudFNpZ25lciB9IGZyb20gJy4vV2FsbGV0VW5zcGVudFNpZ25lcic7XG5pbXBvcnQgeyBLZXlOYW1lLCBSb290V2FsbGV0S2V5cyB9IGZyb20gJy4vV2FsbGV0S2V5cyc7XG5pbXBvcnQgeyBVdHhvVHJhbnNhY3Rpb24gfSBmcm9tICcuLi9VdHhvVHJhbnNhY3Rpb24nO1xuaW1wb3J0IHsgVHJpcGxlIH0gZnJvbSAnLi4vdHlwZXMnO1xuaW1wb3J0IHtcbiAgdG9PdXRwdXQsXG4gIFVuc3BlbnRXaXRoUHJldlR4LFxuICBVbnNwZW50LFxuICBpc1Vuc3BlbnRXaXRoUHJldlR4LFxuICB0b1ByZXZPdXRwdXQsXG4gIHBhcnNlT3V0cHV0SWQsXG4gIGdldE91dHB1dElkRm9ySW5wdXQsXG59IGZyb20gJy4uL1Vuc3BlbnQnO1xuaW1wb3J0IHsgQ2hhaW5Db2RlLCBpc1NlZ3dpdCB9IGZyb20gJy4vY2hhaW5zJztcbmltcG9ydCB7IFV0eG9Qc2J0IH0gZnJvbSAnLi4vVXR4b1BzYnQnO1xuaW1wb3J0IHsgZW5jb2RlUHNidE11c2lnMlBhcnRpY2lwYW50cyB9IGZyb20gJy4uL011c2lnMic7XG5pbXBvcnQgeyBjcmVhdGVUcmFuc2FjdGlvbkZyb21CdWZmZXIgfSBmcm9tICcuLi90cmFuc2FjdGlvbic7XG5pbXBvcnQgeyBwYXJzZVNpZ25hdHVyZVNjcmlwdCB9IGZyb20gJy4uL3BhcnNlSW5wdXQnO1xuaW1wb3J0IHsgY2hlY2tGb3JJbnB1dCB9IGZyb20gJ2JpcDE3NC9zcmMvbGliL3V0aWxzJztcbmltcG9ydCB7IFByb3ByaWV0YXJ5S2V5U3VidHlwZSwgUFNCVF9QUk9QUklFVEFSWV9JREVOVElGSUVSIH0gZnJvbSAnLi4vUHNidFV0aWwnO1xuXG4vKiogRmluYWwgKG5vbi1yZXBsYWNlYWJsZSkgKi9cbmV4cG9ydCBjb25zdCBUWF9JTlBVVF9TRVFVRU5DRV9OVU1CRVJfRklOQUwgPSAweGZmZmZmZmZmO1xuXG4vKiogTm9uLUZpbmFsIChSZXBsYWNlYWJsZSlcbiAqIFJlZmVyZW5jZTogaHR0cHM6Ly9naXRodWIuY29tL2JpdGNvaW4vYml0Y29pbi9ibG9iL3YyNS4xL3NyYy9ycGMvcmF3dHJhbnNhY3Rpb25fdXRpbC5jcHAjTDQ5XG4gKiAqL1xuZXhwb3J0IGNvbnN0IE1BWF9CSVAxMjVfUkJGX1NFUVVFTkNFID0gMHhmZmZmZmZmZiAtIDI7XG5cbmV4cG9ydCBpbnRlcmZhY2UgV2FsbGV0VW5zcGVudDxUTnVtYmVyIGV4dGVuZHMgbnVtYmVyIHwgYmlnaW50ID0gbnVtYmVyPiBleHRlbmRzIFVuc3BlbnQ8VE51bWJlcj4ge1xuICBjaGFpbjogQ2hhaW5Db2RlO1xuICBpbmRleDogbnVtYmVyO1xuICB3aXRuZXNzU2NyaXB0Pzogc3RyaW5nO1xuICB2YWx1ZVN0cmluZz86IHN0cmluZztcbn1cblxuZXhwb3J0IGludGVyZmFjZSBOb25XaXRuZXNzV2FsbGV0VW5zcGVudDxUTnVtYmVyIGV4dGVuZHMgbnVtYmVyIHwgYmlnaW50ID0gbnVtYmVyPlxuICBleHRlbmRzIFVuc3BlbnRXaXRoUHJldlR4PFROdW1iZXI+LFxuICAgIFdhbGxldFVuc3BlbnQ8VE51bWJlcj4ge31cblxuZXhwb3J0IGZ1bmN0aW9uIGlzV2FsbGV0VW5zcGVudDxUTnVtYmVyIGV4dGVuZHMgbnVtYmVyIHwgYmlnaW50Pih1OiBVbnNwZW50PFROdW1iZXI+KTogdSBpcyBXYWxsZXRVbnNwZW50PFROdW1iZXI+IHtcbiAgcmV0dXJuICh1IGFzIFdhbGxldFVuc3BlbnQ8VE51bWJlcj4pLmNoYWluICE9PSB1bmRlZmluZWQ7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBzaWduSW5wdXRXaXRoVW5zcGVudDxUTnVtYmVyIGV4dGVuZHMgbnVtYmVyIHwgYmlnaW50PihcbiAgdHhCdWlsZGVyOiBVdHhvVHJhbnNhY3Rpb25CdWlsZGVyPFROdW1iZXI+LFxuICBpbnB1dEluZGV4OiBudW1iZXIsXG4gIHVuc3BlbnQ6IFdhbGxldFVuc3BlbnQ8VE51bWJlcj4sXG4gIHVuc3BlbnRTaWduZXI6IFdhbGxldFVuc3BlbnRTaWduZXI8Um9vdFdhbGxldEtleXM+XG4pOiB2b2lkIHtcbiAgY29uc3QgeyB3YWxsZXRLZXlzLCBzaWduZXIsIGNvc2lnbmVyIH0gPSB1bnNwZW50U2lnbmVyLmRlcml2ZUZvckNoYWluQW5kSW5kZXgodW5zcGVudC5jaGFpbiwgdW5zcGVudC5pbmRleCk7XG4gIGNvbnN0IHNjcmlwdFR5cGUgPSBzY3JpcHRUeXBlRm9yQ2hhaW4odW5zcGVudC5jaGFpbik7XG4gIGNvbnN0IHB1YlNjcmlwdCA9IGNyZWF0ZU91dHB1dFNjcmlwdDJvZjMod2FsbGV0S2V5cy5wdWJsaWNLZXlzLCBzY3JpcHRUeXBlKS5zY3JpcHRQdWJLZXk7XG4gIGNvbnN0IHB1YlNjcmlwdEV4cGVjdGVkID0gdG9PdXRwdXRTY3JpcHQodW5zcGVudC5hZGRyZXNzLCB0eEJ1aWxkZXIubmV0d29yayBhcyBOZXR3b3JrKTtcbiAgaWYgKCFwdWJTY3JpcHQuZXF1YWxzKHB1YlNjcmlwdEV4cGVjdGVkKSkge1xuICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgIGBwdWJzY3JpcHQgbWlzbWF0Y2g6IGV4cGVjdGVkICR7cHViU2NyaXB0RXhwZWN0ZWQudG9TdHJpbmcoJ2hleCcpfSBnb3QgJHtwdWJTY3JpcHQudG9TdHJpbmcoJ2hleCcpfWBcbiAgICApO1xuICB9XG4gIHNpZ25JbnB1dDJPZjM8VE51bWJlcj4oXG4gICAgdHhCdWlsZGVyLFxuICAgIGlucHV0SW5kZXgsXG4gICAgc2NyaXB0VHlwZSxcbiAgICB3YWxsZXRLZXlzLnB1YmxpY0tleXMsXG4gICAgc2lnbmVyLFxuICAgIGNvc2lnbmVyLnB1YmxpY0tleSxcbiAgICB1bnNwZW50LnZhbHVlXG4gICk7XG59XG5cbi8qKlxuICogQHBhcmFtIHR4XG4gKiBAcGFyYW0gaW5wdXRJbmRleFxuICogQHBhcmFtIHVuc3BlbnRzXG4gKiBAcGFyYW0gd2FsbGV0S2V5c1xuICogQHJldHVybiB0cmlwbGUgb2YgYm9vbGVhbnMgaW5kaWNhdGluZyBhIHZhbGlkIHNpZ25hdHVyZSBmb3IgZWFjaCBwdWJrZXlcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHZlcmlmeVNpZ25hdHVyZVdpdGhVbnNwZW50PFROdW1iZXIgZXh0ZW5kcyBudW1iZXIgfCBiaWdpbnQ+KFxuICB0eDogVXR4b1RyYW5zYWN0aW9uPFROdW1iZXI+LFxuICBpbnB1dEluZGV4OiBudW1iZXIsXG4gIHVuc3BlbnRzOiBVbnNwZW50PFROdW1iZXI+W10sXG4gIHdhbGxldEtleXM6IFJvb3RXYWxsZXRLZXlzXG4pOiBUcmlwbGU8Ym9vbGVhbj4ge1xuICBpZiAodHguaW5zLmxlbmd0aCAhPT0gdW5zcGVudHMubGVuZ3RoKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKGBpbnB1dCBsZW5ndGggbXVzdCBtYXRjaCB1bnNwZW50cyBsZW5ndGhgKTtcbiAgfVxuXG4gIGNvbnN0IGlucHV0ID0gdHguaW5zW2lucHV0SW5kZXhdO1xuICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCAqL1xuICBpZiAoIWlucHV0KSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKGBubyBpbnB1dCBhdCBpbmRleCAke2lucHV0SW5kZXh9YCk7XG4gIH1cblxuICBjb25zdCB1bnNwZW50ID0gdW5zcGVudHNbaW5wdXRJbmRleF07XG4gIGlmICghaXNXYWxsZXRVbnNwZW50KHVuc3BlbnQpIHx8ICghaW5wdXQuc2NyaXB0Py5sZW5ndGggJiYgIWlucHV0LndpdG5lc3M/Lmxlbmd0aCkpIHtcbiAgICByZXR1cm4gW2ZhbHNlLCBmYWxzZSwgZmFsc2VdO1xuICB9XG5cbiAgY29uc3QgcGFyc2VkSW5wdXQgPSBwYXJzZVNpZ25hdHVyZVNjcmlwdChpbnB1dCk7XG4gIGNvbnN0IHByZXZPdXRwdXRzID0gdW5zcGVudHMubWFwKCh1KSA9PiB0b091dHB1dCh1LCB0eC5uZXR3b3JrKSk7XG5cbiAgLy8gSWYgaXQgaXMgYSB0YXByb290IGtleVBhdGhTcGVuZCBpbnB1dCwgdGhlIG9ubHkgdmFsaWQgc2lnbmF0dXJlIGNvbWJpbmF0aW9ucyBpcyB1c2VyLWJpdGdvLiBXZSBjYW5cbiAgLy8gb25seSB2ZXJpZnkgdGhhdCB0aGUgYWdncmVnYXRlZCBzaWduYXR1cmUgaXMgdmFsaWQsIG5vdCB0aGF0IHRoZSBpbmRpdmlkdWFsIHBhcnRpYWwtc2lnbmF0dXJlIGlzIHZhbGlkLlxuICAvLyBUaGVyZWZvcmUsIHdlIGNhbiBvbmx5IHNheSB0aGF0IGVpdGhlciBhbGwgcGFydGlhbCBzaWduYXR1cmVzIGFyZSB2YWxpZCwgb3Igbm9uZSBhcmUuXG4gIGlmIChwYXJzZWRJbnB1dC5zY3JpcHRUeXBlID09PSAndGFwcm9vdEtleVBhdGhTcGVuZCcpIHtcbiAgICBjb25zdCByZXN1bHQgPSBnZXRTaWduYXR1cmVWZXJpZmljYXRpb25zKHR4LCBpbnB1dEluZGV4LCB1bnNwZW50LnZhbHVlLCB1bmRlZmluZWQsIHByZXZPdXRwdXRzKTtcbiAgICByZXR1cm4gcmVzdWx0Lmxlbmd0aCA9PT0gMSAmJiByZXN1bHRbMF0uc2lnbmF0dXJlID8gW3RydWUsIGZhbHNlLCB0cnVlXSA6IFtmYWxzZSwgZmFsc2UsIGZhbHNlXTtcbiAgfVxuXG4gIHJldHVybiB2ZXJpZnlTaWduYXR1cmVXaXRoUHVibGljS2V5cyhcbiAgICB0eCxcbiAgICBpbnB1dEluZGV4LFxuICAgIHByZXZPdXRwdXRzLFxuICAgIHdhbGxldEtleXMuZGVyaXZlRm9yQ2hhaW5BbmRJbmRleCh1bnNwZW50LmNoYWluLCB1bnNwZW50LmluZGV4KS5wdWJsaWNLZXlzXG4gICkgYXMgVHJpcGxlPGJvb2xlYW4+O1xufVxuXG4vKipcbiAqIEBkZXByZWNhdGVkXG4gKiBVc2VkIGluIGNlcnRhaW4gbGVnYWN5IHNpZ25pbmcgbWV0aG9kcyB0aGF0IGRvIG5vdCBkZXJpdmUgc2lnbmluZyBkYXRhIGZyb20gaW5kZXgvY2hhaW5cbiAqL1xuZXhwb3J0IGludGVyZmFjZSBXYWxsZXRVbnNwZW50TGVnYWN5PFROdW1iZXIgZXh0ZW5kcyBudW1iZXIgfCBiaWdpbnQgPSBudW1iZXI+IGV4dGVuZHMgV2FsbGV0VW5zcGVudDxUTnVtYmVyPiB7XG4gIC8qKiBAZGVwcmVjYXRlZCAtIG9idmlhdGVkIGJ5IHNpZ25XaXRoVW5zcGVudCAqL1xuICByZWRlZW1TY3JpcHQ/OiBzdHJpbmc7XG4gIC8qKiBAZGVwcmVjYXRlZCAtIG9idmlhdGVkIGJ5IHZlcmlmeVdpdGhVbnNwZW50ICovXG4gIHdpdG5lc3NTY3JpcHQ/OiBzdHJpbmc7XG59XG5cbi8qKlxuICogQHBhcmFtIHBzYnRcbiAqIEBwYXJhbSBpbnB1dEluZGV4XG4gKiBAcGFyYW0gaWQgVW5zcGVudCBJRFxuICogQHJldHVybnMgdHJ1ZSBpZmYgdGhlIHVuc3BlbnQgSUQgb24gdGhlIHVuc3BlbnQgYW5kIHBzYnQgaW5wdXQgbWF0Y2hcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHBzYnRJbmNsdWRlc1Vuc3BlbnRBdEluZGV4KHBzYnQ6IFV0eG9Qc2J0LCBpbnB1dEluZGV4OiBudW1iZXIsIGlkOiBzdHJpbmcpOiBib29sZWFuIHtcbiAgY2hlY2tGb3JJbnB1dChwc2J0LmRhdGEuaW5wdXRzLCBpbnB1dEluZGV4KTtcblxuICBjb25zdCB7IHR4aWQsIHZvdXQgfSA9IHBhcnNlT3V0cHV0SWQoaWQpO1xuICBjb25zdCBwc2J0T3V0UG9pbnQgPSBnZXRPdXRwdXRJZEZvcklucHV0KHBzYnQudHhJbnB1dHNbaW5wdXRJbmRleF0pO1xuICByZXR1cm4gcHNidE91dFBvaW50LnR4aWQgPT09IHR4aWQgJiYgcHNidE91dFBvaW50LnZvdXQgPT09IHZvdXQ7XG59XG5cbi8qKlxuICogVXBkYXRlIHRoZSBwc2J0IGlucHV0IGF0IHRoZSBnaXZlbiBpbmRleFxuICogQHBhcmFtIHBzYnRcbiAqIEBwYXJhbSBpbnB1dEluZGV4XG4gKiBAcGFyYW0gdVxuICogQHBhcmFtIHJlZGVlbVNjcmlwdCBPbmx5IG92ZXJyaWRlcyBpZiB0aGVyZSBpcyBubyByZWRlZW1TY3JpcHQgaW4gdGhlIGlucHV0IGN1cnJlbnRseVxuICovXG5leHBvcnQgZnVuY3Rpb24gdXBkYXRlUmVwbGF5UHJvdGVjdGlvblVuc3BlbnRUb1BzYnQoXG4gIHBzYnQ6IFV0eG9Qc2J0LFxuICBpbnB1dEluZGV4OiBudW1iZXIsXG4gIHU6IFVuc3BlbnQ8YmlnaW50PixcbiAgcmVkZWVtU2NyaXB0PzogQnVmZmVyLFxuICBjdXN0b21QYXJhbXM/OiB7IHNraXBOb25XaXRuZXNzVXR4bz86IGJvb2xlYW4gfVxuKTogdm9pZCB7XG4gIGlmICghcHNidEluY2x1ZGVzVW5zcGVudEF0SW5kZXgocHNidCwgaW5wdXRJbmRleCwgdS5pZCkpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoYHVuc3BlbnQgZG9lcyBub3QgY29ycmVzcG9uZCB0byBwc2J0IGlucHV0YCk7XG4gIH1cbiAgY29uc3QgaW5wdXQgPSBjaGVja0ZvcklucHV0KHBzYnQuZGF0YS5pbnB1dHMsIGlucHV0SW5kZXgpO1xuXG4gIGlmIChyZWRlZW1TY3JpcHQgJiYgIWlucHV0LnJlZGVlbVNjcmlwdCkge1xuICAgIHBzYnQudXBkYXRlSW5wdXQoaW5wdXRJbmRleCwgeyByZWRlZW1TY3JpcHQgfSk7XG4gIH1cblxuICAvLyBCZWNhdXNlIFpjYXNoIGRpcmVjdGx5IGhhc2hlcyB0aGUgdmFsdWUgZm9yIG5vbi1zZWd3aXQgdHJhbnNhY3Rpb25zLCB3ZSBkbyBub3QgbmVlZCB0byBjaGVjayBpbmRpcmVjdGx5XG4gIC8vIHdpdGggdGhlIHByZXZpb3VzIHRyYW5zYWN0aW9uLiBUaGVyZWZvcmUsIHdlIGNhbiB0cmVhdCBaY2FzaCBub24tc2Vnd2l0IHRyYW5zYWN0aW9ucyBhcyBCaXRjb2luXG4gIC8vIHNlZ3dpdCB0cmFuc2FjdGlvbnNcbiAgY29uc3QgaXNaY2FzaCA9IGdldE1haW5uZXQocHNidC5uZXR3b3JrKSA9PT0gbmV0d29ya3MuemNhc2g7XG4gIGlmICghaXNVbnNwZW50V2l0aFByZXZUeCh1KSAmJiAhaXNaY2FzaCAmJiAhY3VzdG9tUGFyYW1zPy5za2lwTm9uV2l0bmVzc1V0eG8pIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ0Vycm9yLCByZXF1aXJlIHByZXZpb3VzIHR4IHRvIGFkZCB0byBQU0JUJyk7XG4gIH1cbiAgaWYgKChpc1pjYXNoICYmICFpbnB1dC53aXRuZXNzVXR4bykgfHwgY3VzdG9tUGFyYW1zPy5za2lwTm9uV2l0bmVzc1V0eG8pIHtcbiAgICBjb25zdCB7IHNjcmlwdCwgdmFsdWUgfSA9IHRvUHJldk91dHB1dCh1LCBwc2J0Lm5ldHdvcmspO1xuICAgIHBzYnQudXBkYXRlSW5wdXQoaW5wdXRJbmRleCwgeyB3aXRuZXNzVXR4bzogeyBzY3JpcHQsIHZhbHVlIH0gfSk7XG4gIH0gZWxzZSBpZiAoIWlzWmNhc2ggJiYgIWlucHV0Lm5vbldpdG5lc3NVdHhvKSB7XG4gICAgcHNidC51cGRhdGVJbnB1dChpbnB1dEluZGV4LCB7IG5vbldpdG5lc3NVdHhvOiAodSBhcyBVbnNwZW50V2l0aFByZXZUeDxiaWdpbnQ+KS5wcmV2VHggfSk7XG4gIH1cblxuICBjb25zdCBzaWdoYXNoVHlwZSA9IGdldERlZmF1bHRTaWdIYXNoKHBzYnQubmV0d29yayk7XG4gIGlmIChwc2J0LmRhdGEuaW5wdXRzW2lucHV0SW5kZXhdLnNpZ2hhc2hUeXBlID09PSB1bmRlZmluZWQpIHtcbiAgICBwc2J0LnVwZGF0ZUlucHV0KGlucHV0SW5kZXgsIHsgc2lnaGFzaFR5cGUgfSk7XG4gIH1cbn1cblxuZnVuY3Rpb24gYWRkVW5zcGVudFRvUHNidChcbiAgcHNidDogVXR4b1BzYnQsXG4gIGlkOiBzdHJpbmcsXG4gIHsgc2VxdWVuY2VOdW1iZXIgPSBUWF9JTlBVVF9TRVFVRU5DRV9OVU1CRVJfRklOQUwgfTogeyBzZXF1ZW5jZU51bWJlcj86IG51bWJlciB9ID0ge31cbik6IHZvaWQge1xuICBjb25zdCB7IHR4aWQsIHZvdXQgfSA9IHBhcnNlT3V0cHV0SWQoaWQpO1xuICBwc2J0LmFkZElucHV0KHtcbiAgICBoYXNoOiB0eGlkLFxuICAgIGluZGV4OiB2b3V0LFxuICAgIHNlcXVlbmNlOiBzZXF1ZW5jZU51bWJlcixcbiAgfSk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBhZGRSZXBsYXlQcm90ZWN0aW9uVW5zcGVudFRvUHNidChcbiAgcHNidDogVXR4b1BzYnQsXG4gIHU6IFVuc3BlbnQ8YmlnaW50PixcbiAgcmVkZWVtU2NyaXB0OiBCdWZmZXIsXG4gIGN1c3RvbVBhcmFtcz86IHsgc2tpcE5vbldpdG5lc3NVdHhvPzogYm9vbGVhbiB9XG4pOiB2b2lkIHtcbiAgYWRkVW5zcGVudFRvUHNidChwc2J0LCB1LmlkKTtcbiAgdXBkYXRlUmVwbGF5UHJvdGVjdGlvblVuc3BlbnRUb1BzYnQocHNidCwgcHNidC5pbnB1dENvdW50IC0gMSwgdSwgcmVkZWVtU2NyaXB0LCBjdXN0b21QYXJhbXMpO1xufVxuXG4vKipcbiAqIFVwZGF0ZSB0aGUgUFNCVCB3aXRoIHRoZSB1bnNwZW50IGRhdGEgZm9yIHRoZSBpbnB1dCBhdCB0aGUgZ2l2ZW4gaW5kZXggaWYgdGhlIGRhdGEgaXMgbm90IHRoZXJlIGFscmVhZHkuXG4gKlxuICogSWYgc2tpcE5vbldpdG5lc3NVdHhvIGlzIHRydWUsIHRoZW4gdGhlIG5vbldpdG5lc3NVdHhvIHdpbGwgbm90IGJlIGFkZGVkIGZvciBhbiBpbnB1dCB0aGF0IHJlcXVpcmVzIGl0IChlLmcuIG5vbi1zZWd3aXQpXG4gKiBhbmQgaW5zdGVhZCB0aGUgd2l0bmVzc1V0eG8gd2lsbCBiZSBhZGRlZFxuICpcbiAqIEBwYXJhbSBwc2J0XG4gKiBAcGFyYW0gaW5wdXRJbmRleFxuICogQHBhcmFtIHVcbiAqIEBwYXJhbSByb290V2FsbGV0S2V5c1xuICogQHBhcmFtIHNpZ25lclxuICogQHBhcmFtIGNvc2lnbmVyXG4gKiBAcGFyYW0gY3VzdG9tUGFyYW1zXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiB1cGRhdGVXYWxsZXRVbnNwZW50Rm9yUHNidChcbiAgcHNidDogVXR4b1BzYnQsXG4gIGlucHV0SW5kZXg6IG51bWJlcixcbiAgdTogV2FsbGV0VW5zcGVudDxiaWdpbnQ+LFxuICByb290V2FsbGV0S2V5czogUm9vdFdhbGxldEtleXMsXG4gIHNpZ25lcjogS2V5TmFtZSxcbiAgY29zaWduZXI6IEtleU5hbWUsXG4gIGN1c3RvbVBhcmFtcz86IHsgc2tpcE5vbldpdG5lc3NVdHhvPzogYm9vbGVhbiB9XG4pOiB2b2lkIHtcbiAgaWYgKCFwc2J0SW5jbHVkZXNVbnNwZW50QXRJbmRleChwc2J0LCBpbnB1dEluZGV4LCB1LmlkKSkge1xuICAgIHRocm93IG5ldyBFcnJvcihgdW5zcGVudCBkb2VzIG5vdCBjb3JyZXNwb25kIHRvIHBzYnQgaW5wdXRgKTtcbiAgfVxuICBjb25zdCBpbnB1dCA9IGNoZWNrRm9ySW5wdXQocHNidC5kYXRhLmlucHV0cywgaW5wdXRJbmRleCk7XG5cbiAgLy8gQmVjYXVzZSBaY2FzaCBkaXJlY3RseSBoYXNoZXMgdGhlIHZhbHVlIGZvciBub24tc2Vnd2l0IHRyYW5zYWN0aW9ucywgd2UgZG8gbm90IG5lZWQgdG8gY2hlY2sgaW5kaXJlY3RseVxuICAvLyB3aXRoIHRoZSBwcmV2aW91cyB0cmFuc2FjdGlvbi4gVGhlcmVmb3JlLCB3ZSBjYW4gdHJlYXQgWmNhc2ggbm9uLXNlZ3dpdCB0cmFuc2FjdGlvbnMgYXMgQml0Y29pblxuICAvLyBzZWd3aXQgdHJhbnNhY3Rpb25zXG4gIGNvbnN0IGlzWmNhc2hPclNlZ3dpdCA9IGlzU2Vnd2l0KHUuY2hhaW4pIHx8IGdldE1haW5uZXQocHNidC5uZXR3b3JrKSA9PT0gbmV0d29ya3MuemNhc2g7XG4gIGlmICgoaXNaY2FzaE9yU2Vnd2l0ICYmICFpbnB1dC53aXRuZXNzVXR4bykgfHwgY3VzdG9tUGFyYW1zPy5za2lwTm9uV2l0bmVzc1V0eG8pIHtcbiAgICBjb25zdCB7IHNjcmlwdCwgdmFsdWUgfSA9IHRvUHJldk91dHB1dCh1LCBwc2J0Lm5ldHdvcmspO1xuICAgIHBzYnQudXBkYXRlSW5wdXQoaW5wdXRJbmRleCwgeyB3aXRuZXNzVXR4bzogeyBzY3JpcHQsIHZhbHVlIH0gfSk7XG4gIH0gZWxzZSBpZiAoIWlzWmNhc2hPclNlZ3dpdCkge1xuICAgIGlmICghaXNVbnNwZW50V2l0aFByZXZUeCh1KSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdFcnJvciwgcmVxdWlyZSBwcmV2aW91cyB0eCB0byBhZGQgdG8gUFNCVCcpO1xuICAgIH1cblxuICAgIGlmICghaW5wdXQud2l0bmVzc1V0eG8gJiYgIWlucHV0Lm5vbldpdG5lc3NVdHhvKSB7XG4gICAgICAvLyBGb3JjZSB0aGUgbGl0ZWNvaW4gdHJhbnNhY3Rpb24gdG8gaGF2ZSBubyBNV0VCIGFkdmFuY2VkIHRyYW5zYWN0aW9uIGZsYWdcbiAgICAgIGlmIChnZXRNYWlubmV0KHBzYnQubmV0d29yaykgPT09IG5ldHdvcmtzLmxpdGVjb2luKSB7XG4gICAgICAgIHUucHJldlR4ID0gY3JlYXRlVHJhbnNhY3Rpb25Gcm9tQnVmZmVyKHUucHJldlR4LCBwc2J0Lm5ldHdvcmssIHsgYW1vdW50VHlwZTogJ2JpZ2ludCcgfSkudG9CdWZmZXIoKTtcbiAgICAgIH1cblxuICAgICAgcHNidC51cGRhdGVJbnB1dChpbnB1dEluZGV4LCB7IG5vbldpdG5lc3NVdHhvOiB1LnByZXZUeCB9KTtcbiAgICB9XG4gIH1cblxuICBjb25zdCB3YWxsZXRLZXlzID0gcm9vdFdhbGxldEtleXMuZGVyaXZlRm9yQ2hhaW5BbmRJbmRleCh1LmNoYWluLCB1LmluZGV4KTtcbiAgY29uc3Qgc2NyaXB0VHlwZSA9IHNjcmlwdFR5cGVGb3JDaGFpbih1LmNoYWluKTtcbiAgY29uc3Qgc2lnaGFzaFR5cGUgPSBnZXREZWZhdWx0U2lnSGFzaChwc2J0Lm5ldHdvcmssIHNjcmlwdFR5cGUpO1xuICBpZiAocHNidC5kYXRhLmlucHV0c1tpbnB1dEluZGV4XS5zaWdoYXNoVHlwZSA9PT0gdW5kZWZpbmVkKSB7XG4gICAgcHNidC51cGRhdGVJbnB1dChpbnB1dEluZGV4LCB7IHNpZ2hhc2hUeXBlIH0pO1xuICB9XG4gIGNvbnN0IGlzQmFja3VwRmxvdyA9IHNpZ25lciA9PT0gJ2JhY2t1cCcgfHwgY29zaWduZXIgPT09ICdiYWNrdXAnO1xuXG4gIGlmIChzY3JpcHRUeXBlID09PSAncDJ0cicgfHwgKHNjcmlwdFR5cGUgPT09ICdwMnRyTXVzaWcyJyAmJiBpc0JhY2t1cEZsb3cpKSB7XG4gICAgaWYgKGlucHV0LnRhcExlYWZTY3JpcHQgJiYgaW5wdXQudGFwQmlwMzJEZXJpdmF0aW9uKSB7XG4gICAgICByZXR1cm47XG4gICAgfVxuICAgIGNvbnN0IGNyZWF0ZVNwZW5kU2NyaXB0UDJ0ckZuID0gc2NyaXB0VHlwZSA9PT0gJ3AydHInID8gY3JlYXRlU3BlbmRTY3JpcHRQMnRyIDogY3JlYXRlU3BlbmRTY3JpcHRQMnRyTXVzaWcyO1xuICAgIGNvbnN0IHsgY29udHJvbEJsb2NrLCB3aXRuZXNzU2NyaXB0LCBsZWFmVmVyc2lvbiwgbGVhZkhhc2ggfSA9IGNyZWF0ZVNwZW5kU2NyaXB0UDJ0ckZuKHdhbGxldEtleXMucHVibGljS2V5cywgW1xuICAgICAgd2FsbGV0S2V5c1tzaWduZXJdLnB1YmxpY0tleSxcbiAgICAgIHdhbGxldEtleXNbY29zaWduZXJdLnB1YmxpY0tleSxcbiAgICBdKTtcbiAgICBpZiAoIWlucHV0LnRhcExlYWZTY3JpcHQpIHtcbiAgICAgIHBzYnQudXBkYXRlSW5wdXQoaW5wdXRJbmRleCwge1xuICAgICAgICB0YXBMZWFmU2NyaXB0OiBbeyBjb250cm9sQmxvY2ssIHNjcmlwdDogd2l0bmVzc1NjcmlwdCwgbGVhZlZlcnNpb24gfV0sXG4gICAgICB9KTtcbiAgICB9XG4gICAgaWYgKCFpbnB1dC50YXBCaXAzMkRlcml2YXRpb24pIHtcbiAgICAgIHBzYnQudXBkYXRlSW5wdXQoaW5wdXRJbmRleCwge1xuICAgICAgICB0YXBCaXAzMkRlcml2YXRpb246IFtzaWduZXIsIGNvc2lnbmVyXS5tYXAoKGtleSkgPT4gKHtcbiAgICAgICAgICBsZWFmSGFzaGVzOiBbbGVhZkhhc2hdLFxuICAgICAgICAgIHB1YmtleTogdG9YT25seVB1YmxpY0tleSh3YWxsZXRLZXlzW2tleV0ucHVibGljS2V5KSxcbiAgICAgICAgICBwYXRoOiByb290V2FsbGV0S2V5cy5nZXREZXJpdmF0aW9uUGF0aChyb290V2FsbGV0S2V5c1trZXldLCB1LmNoYWluLCB1LmluZGV4KSxcbiAgICAgICAgICBtYXN0ZXJGaW5nZXJwcmludDogcm9vdFdhbGxldEtleXNba2V5XS5maW5nZXJwcmludCxcbiAgICAgICAgfSkpLFxuICAgICAgfSk7XG4gICAgfVxuICB9IGVsc2UgaWYgKHNjcmlwdFR5cGUgPT09ICdwMnRyTXVzaWcyJykge1xuICAgIGNvbnN0IHtcbiAgICAgIGludGVybmFsUHVia2V5OiB0YXBJbnRlcm5hbEtleSxcbiAgICAgIG91dHB1dFB1YmtleTogdGFwT3V0cHV0S2V5LFxuICAgICAgdGFwdHJlZVJvb3QsXG4gICAgfSA9IGNyZWF0ZUtleVBhdGhQMnRyTXVzaWcyKHdhbGxldEtleXMucHVibGljS2V5cyk7XG5cbiAgICBpZiAoXG4gICAgICBwc2J0LmdldFByb3ByaWV0YXJ5S2V5VmFscyhpbnB1dEluZGV4LCB7XG4gICAgICAgIGlkZW50aWZpZXI6IFBTQlRfUFJPUFJJRVRBUllfSURFTlRJRklFUixcbiAgICAgICAgc3VidHlwZTogUHJvcHJpZXRhcnlLZXlTdWJ0eXBlLk1VU0lHMl9QQVJUSUNJUEFOVF9QVUJfS0VZUyxcbiAgICAgIH0pLmxlbmd0aCA9PT0gMFxuICAgICkge1xuICAgICAgY29uc3QgcGFydGljaXBhbnRzS2V5VmFsRGF0YSA9IGVuY29kZVBzYnRNdXNpZzJQYXJ0aWNpcGFudHMoe1xuICAgICAgICB0YXBPdXRwdXRLZXksXG4gICAgICAgIHRhcEludGVybmFsS2V5LFxuICAgICAgICBwYXJ0aWNpcGFudFB1YktleXM6IFt3YWxsZXRLZXlzLnVzZXIucHVibGljS2V5LCB3YWxsZXRLZXlzLmJpdGdvLnB1YmxpY0tleV0sXG4gICAgICB9KTtcbiAgICAgIHBzYnQuYWRkUHJvcHJpZXRhcnlLZXlWYWxUb0lucHV0KGlucHV0SW5kZXgsIHBhcnRpY2lwYW50c0tleVZhbERhdGEpO1xuICAgIH1cblxuICAgIGlmICghaW5wdXQudGFwSW50ZXJuYWxLZXkpIHtcbiAgICAgIHBzYnQudXBkYXRlSW5wdXQoaW5wdXRJbmRleCwge1xuICAgICAgICB0YXBJbnRlcm5hbEtleTogdGFwSW50ZXJuYWxLZXksXG4gICAgICB9KTtcbiAgICB9XG5cbiAgICBpZiAoIWlucHV0LnRhcE1lcmtsZVJvb3QpIHtcbiAgICAgIHBzYnQudXBkYXRlSW5wdXQoaW5wdXRJbmRleCwge1xuICAgICAgICB0YXBNZXJrbGVSb290OiB0YXB0cmVlUm9vdCxcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGlmICghaW5wdXQudGFwQmlwMzJEZXJpdmF0aW9uKSB7XG4gICAgICBwc2J0LnVwZGF0ZUlucHV0KGlucHV0SW5kZXgsIHtcbiAgICAgICAgdGFwQmlwMzJEZXJpdmF0aW9uOiBbc2lnbmVyLCBjb3NpZ25lcl0ubWFwKChrZXkpID0+ICh7XG4gICAgICAgICAgbGVhZkhhc2hlczogW10sXG4gICAgICAgICAgcHVia2V5OiB0b1hPbmx5UHVibGljS2V5KHdhbGxldEtleXNba2V5XS5wdWJsaWNLZXkpLFxuICAgICAgICAgIHBhdGg6IHJvb3RXYWxsZXRLZXlzLmdldERlcml2YXRpb25QYXRoKHJvb3RXYWxsZXRLZXlzW2tleV0sIHUuY2hhaW4sIHUuaW5kZXgpLFxuICAgICAgICAgIG1hc3RlckZpbmdlcnByaW50OiByb290V2FsbGV0S2V5c1trZXldLmZpbmdlcnByaW50LFxuICAgICAgICB9KSksXG4gICAgICB9KTtcbiAgICB9XG4gIH0gZWxzZSB7XG4gICAgaWYgKCFpbnB1dC5iaXAzMkRlcml2YXRpb24pIHtcbiAgICAgIHBzYnQudXBkYXRlSW5wdXQoaW5wdXRJbmRleCwge1xuICAgICAgICBiaXAzMkRlcml2YXRpb246IFswLCAxLCAyXS5tYXAoKGlkeCkgPT4gKHtcbiAgICAgICAgICBwdWJrZXk6IHdhbGxldEtleXMudHJpcGxlW2lkeF0ucHVibGljS2V5LFxuICAgICAgICAgIHBhdGg6IHdhbGxldEtleXMucGF0aHNbaWR4XSxcbiAgICAgICAgICBtYXN0ZXJGaW5nZXJwcmludDogcm9vdFdhbGxldEtleXMudHJpcGxlW2lkeF0uZmluZ2VycHJpbnQsXG4gICAgICAgIH0pKSxcbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGNvbnN0IHsgd2l0bmVzc1NjcmlwdCwgcmVkZWVtU2NyaXB0IH0gPSBjcmVhdGVPdXRwdXRTY3JpcHQyb2YzKHdhbGxldEtleXMucHVibGljS2V5cywgc2NyaXB0VHlwZSk7XG4gICAgaWYgKHdpdG5lc3NTY3JpcHQgJiYgIWlucHV0LndpdG5lc3NTY3JpcHQpIHtcbiAgICAgIHBzYnQudXBkYXRlSW5wdXQoaW5wdXRJbmRleCwgeyB3aXRuZXNzU2NyaXB0IH0pO1xuICAgIH1cbiAgICBpZiAocmVkZWVtU2NyaXB0ICYmICFpbnB1dC5yZWRlZW1TY3JpcHQpIHtcbiAgICAgIHBzYnQudXBkYXRlSW5wdXQoaW5wdXRJbmRleCwgeyByZWRlZW1TY3JpcHQgfSk7XG4gICAgfVxuICB9XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBhZGRXYWxsZXRVbnNwZW50VG9Qc2J0KFxuICBwc2J0OiBVdHhvUHNidCxcbiAgdTogV2FsbGV0VW5zcGVudDxiaWdpbnQ+LFxuICByb290V2FsbGV0S2V5czogUm9vdFdhbGxldEtleXMsXG4gIHNpZ25lcjogS2V5TmFtZSxcbiAgY29zaWduZXI6IEtleU5hbWUsXG4gIGN1c3RvbVBhcmFtcz86IHsgaXNSZXBsYWNlYWJsZUJ5RmVlPzogYm9vbGVhbjsgc2tpcE5vbldpdG5lc3NVdHhvPzogYm9vbGVhbiB9XG4pOiB2b2lkIHtcbiAgbGV0IHNlcXVlbmNlTnVtYmVyID0gVFhfSU5QVVRfU0VRVUVOQ0VfTlVNQkVSX0ZJTkFMO1xuICBpZiAoY3VzdG9tUGFyYW1zICYmIGN1c3RvbVBhcmFtcy5pc1JlcGxhY2VhYmxlQnlGZWUpIHtcbiAgICBzZXF1ZW5jZU51bWJlciA9IE1BWF9CSVAxMjVfUkJGX1NFUVVFTkNFO1xuICB9XG5cbiAgYWRkVW5zcGVudFRvUHNidChwc2J0LCB1LmlkLCB7IHNlcXVlbmNlTnVtYmVyIH0pO1xuICB1cGRhdGVXYWxsZXRVbnNwZW50Rm9yUHNidChcbiAgICBwc2J0LFxuICAgIHBzYnQuaW5wdXRDb3VudCAtIDEsXG4gICAgdSxcbiAgICByb290V2FsbGV0S2V5cyxcbiAgICBzaWduZXIsXG4gICAgY29zaWduZXIsXG4gICAgY3VzdG9tUGFyYW1zID8geyBza2lwTm9uV2l0bmVzc1V0eG86IGN1c3RvbVBhcmFtcy5za2lwTm9uV2l0bmVzc1V0eG8gfSA6IHt9XG4gICk7XG59XG4iXX0=