"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deleteWitnessUtxoForNonSegwitInputs = exports.clonePsbtWithoutNonWitnessUtxo = exports.extractP2msOnlyHalfSignedTx = exports.getSignatureValidationArrayPsbt = exports.addXpubsToPsbt = exports.isTransactionWithKeyPathSpendInput = exports.isTxInputArray = exports.isPsbtInputArray = exports.getStrictSignatureCounts = exports.getStrictSignatureCount = exports.parsePsbtInput = exports.getPsbtInputScriptType = exports.signWalletPsbt = exports.toWalletPsbt = void 0;
const assert = require("assert");
const utils_1 = require("bip174/src/lib/utils");
const bs58check = require("bs58check");
const UtxoPsbt_1 = require("../UtxoPsbt");
const UtxoTransaction_1 = require("../UtxoTransaction");
const outputScripts_1 = require("../outputScripts");
const WalletKeys_1 = require("./WalletKeys");
const Unspent_1 = require("../Unspent");
const transaction_1 = require("../transaction");
const Unspent_2 = require("./Unspent");
const parseInput_1 = require("../parseInput");
const Musig2_1 = require("../Musig2");
const types_1 = require("../types");
const taproot_1 = require("../../taproot");
const bitcoinjs_lib_1 = require("bitcoinjs-lib");
const index_1 = require("../../index");
const PsbtUtil_1 = require("../PsbtUtil");
function getTaprootSigners(script, walletKeys) {
    const parsedPublicKeys = parseInput_1.parsePubScript2Of3(script, 'taprootScriptPathSpend').publicKeys;
    const walletSigners = parsedPublicKeys.map((publicKey) => {
        const index = walletKeys.publicKeys.findIndex((walletPublicKey) => outputScripts_1.toXOnlyPublicKey(walletPublicKey).equals(publicKey));
        if (index >= 0) {
            return { walletKey: walletKeys.triple[index], rootKey: walletKeys.parent.triple[index] };
        }
        throw new Error('Taproot public key is not a wallet public key');
    });
    return [walletSigners[0], walletSigners[1]];
}
function updatePsbtInput(psbt, inputIndex, unspent, rootWalletKeys) {
    const input = utils_1.checkForInput(psbt.data.inputs, inputIndex);
    const signatureCount = PsbtUtil_1.getPsbtInputSignatureCount(input);
    const scriptType = outputScripts_1.scriptTypeForChain(unspent.chain);
    if (signatureCount === 0 && scriptType === 'p2tr') {
        return;
    }
    const walletKeys = rootWalletKeys.deriveForChainAndIndex(unspent.chain, unspent.index);
    if (scriptType === 'p2tr') {
        if (!Array.isArray(input.tapLeafScript) || input.tapLeafScript.length === 0) {
            throw new Error('Invalid PSBT state. Missing required fields.');
        }
        if (input.tapLeafScript.length > 1) {
            throw new Error('Bitgo only supports a single tap leaf script per input');
        }
        const [signer, cosigner] = getTaprootSigners(input.tapLeafScript[0].script, walletKeys);
        const leafHash = outputScripts_1.getLeafHash({
            publicKeys: walletKeys.publicKeys,
            signer: signer.walletKey.publicKey,
            cosigner: cosigner.walletKey.publicKey,
        });
        psbt.updateInput(inputIndex, {
            tapBip32Derivation: [signer, cosigner].map((walletSigner) => ({
                leafHashes: [leafHash],
                pubkey: outputScripts_1.toXOnlyPublicKey(walletSigner.walletKey.publicKey),
                path: rootWalletKeys.getDerivationPath(walletSigner.rootKey, unspent.chain, unspent.index),
                masterFingerprint: walletSigner.rootKey.fingerprint,
            })),
        });
    }
    else {
        if (signatureCount === 0) {
            const { witnessScript, redeemScript } = outputScripts_1.createOutputScript2of3(walletKeys.publicKeys, scriptType);
            if (witnessScript && psbt.data.inputs[inputIndex].witnessScript === undefined) {
                psbt.updateInput(inputIndex, { witnessScript });
            }
            if (redeemScript && psbt.data.inputs[inputIndex].redeemScript === undefined) {
                psbt.updateInput(inputIndex, { redeemScript });
            }
        }
        psbt.updateInput(inputIndex, {
            bip32Derivation: [0, 1, 2].map((idx) => ({
                pubkey: walletKeys.triple[idx].publicKey,
                path: walletKeys.paths[idx],
                masterFingerprint: rootWalletKeys.triple[idx].fingerprint,
            })),
        });
    }
}
/**
 * @return PSBT filled with metatdata as per input params tx, unspents and rootWalletKeys.
 * Unsigned PSBT for taproot input with witnessUtxo
 * Unsigned PSBT for other input with witnessUtxo/nonWitnessUtxo, redeemScript/witnessScript, bip32Derivation
 * Signed PSBT for taproot input with witnessUtxo, tapLeafScript, tapBip32Derivation, tapScriptSig
 * Signed PSBT for other input with witnessUtxo/nonWitnessUtxo, redeemScript/witnessScript, bip32Derivation, partialSig
 */
function toWalletPsbt(tx, unspents, rootWalletKeys) {
    const prevOutputs = unspents.map((u) => {
        assert.notStrictEqual(outputScripts_1.scriptTypeForChain(u.chain), 'p2trMusig2');
        return Unspent_1.toPrevOutputWithPrevTx(u, tx.network);
    });
    const psbt = transaction_1.createPsbtFromTransaction(tx, prevOutputs);
    unspents.forEach((u, i) => {
        if (Unspent_2.isWalletUnspent(u) && u.index !== undefined) {
            updatePsbtInput(psbt, i, u, rootWalletKeys);
        }
    });
    return psbt;
}
exports.toWalletPsbt = toWalletPsbt;
/**
 * @param psbt
 * @param inputIndex
 * @param signer
 * @param unspent
 * @return signed PSBT with signer's key for unspent
 */
function signWalletPsbt(psbt, inputIndex, signer, unspent) {
    const scriptType = outputScripts_1.scriptTypeForChain(unspent.chain);
    if (scriptType === 'p2tr' || scriptType === 'p2trMusig2') {
        psbt.signTaprootInputHD(inputIndex, signer);
    }
    else {
        psbt.signInputHD(inputIndex, signer);
    }
}
exports.signWalletPsbt = signWalletPsbt;
/**
 * @returns script type of the input
 */
function getPsbtInputScriptType(input) {
    const isP2pk = (script) => {
        try {
            const chunks = bitcoinjs_lib_1.script.decompile(script);
            return ((chunks === null || chunks === void 0 ? void 0 : chunks.length) === 2 &&
                Buffer.isBuffer(chunks[0]) &&
                bitcoinjs_lib_1.script.isCanonicalPubKey(chunks[0]) &&
                chunks[1] === index_1.opcodes.OP_CHECKSIG);
        }
        catch (e) {
            return false;
        }
    };
    let scriptType;
    if (Buffer.isBuffer(input.redeemScript) && Buffer.isBuffer(input.witnessScript)) {
        scriptType = 'p2shP2wsh';
    }
    else if (Buffer.isBuffer(input.redeemScript)) {
        scriptType = isP2pk(input.redeemScript) ? 'p2shP2pk' : 'p2sh';
    }
    else if (Buffer.isBuffer(input.witnessScript)) {
        scriptType = 'p2wsh';
    }
    if (Array.isArray(input.tapLeafScript) && input.tapLeafScript.length > 0) {
        if (scriptType) {
            throw new Error(`Found both ${scriptType} and taprootScriptPath PSBT metadata.`);
        }
        if (input.tapLeafScript.length > 1) {
            throw new Error('Bitgo only supports a single tap leaf script per input.');
        }
        scriptType = 'taprootScriptPathSpend';
    }
    if (input.tapInternalKey) {
        if (scriptType) {
            throw new Error(`Found both ${scriptType} and taprootKeyPath PSBT metadata.`);
        }
        scriptType = 'taprootKeyPathSpend';
    }
    if (scriptType) {
        return scriptType;
    }
    throw new Error('could not parse input');
}
exports.getPsbtInputScriptType = getPsbtInputScriptType;
function parseTaprootKeyPathSignatures(input) {
    const partialSigs = Musig2_1.parsePsbtMusig2PartialSigs(input);
    if (!partialSigs) {
        return { signatures: undefined, participantPublicKeys: undefined };
    }
    const signatures = partialSigs.map((pSig) => pSig.partialSig);
    const participantPublicKeys = partialSigs.map((pSig) => pSig.participantPubKey);
    return types_1.isTuple(signatures) && types_1.isTuple(participantPublicKeys)
        ? { signatures, participantPublicKeys }
        : { signatures: [signatures[0]], participantPublicKeys: [participantPublicKeys[0]] };
}
function parsePartialOrTapScriptSignatures(sig) {
    if (!(sig === null || sig === void 0 ? void 0 : sig.length)) {
        return { signatures: undefined };
    }
    if (sig.length > 2) {
        throw new Error('unexpected signature count');
    }
    const signatures = sig.map((tSig) => tSig.signature);
    return types_1.isTuple(signatures) ? { signatures } : { signatures: [signatures[0]] };
}
function parseSignatures(input, scriptType) {
    return scriptType === 'taprootKeyPathSpend'
        ? parseTaprootKeyPathSignatures(input)
        : scriptType === 'taprootScriptPathSpend'
            ? parsePartialOrTapScriptSignatures(input.tapScriptSig)
            : parsePartialOrTapScriptSignatures(input.partialSig);
}
function parseScript(input, scriptType) {
    var _a;
    let pubScript;
    if (scriptType === 'p2sh' || scriptType === 'p2shP2pk') {
        pubScript = input.redeemScript;
    }
    else if (scriptType === 'p2wsh' || scriptType === 'p2shP2wsh') {
        pubScript = input.witnessScript;
    }
    else if (scriptType === 'taprootScriptPathSpend') {
        pubScript = input.tapLeafScript ? input.tapLeafScript[0].script : undefined;
    }
    else if (scriptType === 'taprootKeyPathSpend') {
        if ((_a = input.witnessUtxo) === null || _a === void 0 ? void 0 : _a.script) {
            pubScript = input.witnessUtxo.script;
        }
        else if (input.tapInternalKey && input.tapMerkleRoot) {
            pubScript = taproot_1.createTaprootOutputScript({ internalPubKey: input.tapInternalKey, taptreeRoot: input.tapMerkleRoot });
        }
    }
    if (!pubScript) {
        throw new Error(`Invalid PSBT state for ${scriptType}. Missing required fields.`);
    }
    return parseInput_1.parsePubScript(pubScript, scriptType);
}
/**
 * @return psbt metadata are parsed as per below conditions.
 * redeemScript/witnessScript/tapLeafScript matches BitGo.
 * signature and public key count matches BitGo.
 * P2SH-P2PK => scriptType, redeemScript, public key, signature.
 * P2SH => scriptType, redeemScript, public keys, signatures.
 * PW2SH => scriptType, witnessScript, public keys, signatures.
 * P2SH-PW2SH => scriptType, redeemScript, witnessScript, public keys, signatures.
 * P2TR and P2TR MUSIG2 script path => scriptType (taprootScriptPathSpend), pubScript (leaf script), controlBlock,
 * scriptPathLevel, leafVersion, public keys, signatures.
 * P2TR MUSIG2 kep path => scriptType (taprootKeyPathSpend), pubScript (scriptPubKey), participant pub keys (signer),
 * public key (tapOutputkey), signatures (partial signer sigs).
 */
function parsePsbtInput(input) {
    if (PsbtUtil_1.isPsbtInputFinalized(input)) {
        throw new Error('Finalized PSBT parsing is not supported');
    }
    const scriptType = getPsbtInputScriptType(input);
    const parsedPubScript = parseScript(input, scriptType);
    const signatures = parseSignatures(input, scriptType);
    if (parsedPubScript.scriptType === 'taprootKeyPathSpend' && 'participantPublicKeys' in signatures) {
        return {
            ...parsedPubScript,
            ...signatures,
        };
    }
    if (parsedPubScript.scriptType === 'taprootScriptPathSpend') {
        if (!input.tapLeafScript) {
            throw new Error('Invalid PSBT state for taprootScriptPathSpend. Missing required fields.');
        }
        const controlBlock = input.tapLeafScript[0].controlBlock;
        if (!parseInput_1.isValidControlBock(controlBlock)) {
            throw new Error('Invalid PSBT taprootScriptPathSpend controlBlock.');
        }
        const scriptPathLevel = parseInput_1.calculateScriptPathLevel(controlBlock);
        const leafVersion = parseInput_1.getLeafVersion(controlBlock);
        return {
            ...parsedPubScript,
            ...signatures,
            controlBlock,
            scriptPathLevel,
            leafVersion,
        };
    }
    if (parsedPubScript.scriptType === 'p2sh' ||
        parsedPubScript.scriptType === 'p2wsh' ||
        parsedPubScript.scriptType === 'p2shP2wsh') {
        if (parsedPubScript.scriptType === 'p2shP2wsh') {
            parsedPubScript.redeemScript = input.redeemScript;
        }
        return {
            ...parsedPubScript,
            ...signatures,
        };
    }
    if (parsedPubScript.scriptType === 'p2shP2pk' && (!signatures.signatures || !types_1.isTuple(signatures.signatures))) {
        return {
            ...parsedPubScript,
            signatures: signatures.signatures,
        };
    }
    throw new Error('invalid pub script');
}
exports.parsePsbtInput = parsePsbtInput;
/**
 * @returns strictly parse the input and get signature count.
 * unsigned(0), half-signed(1) or fully-signed(2)
 */
function getStrictSignatureCount(input) {
    var _a, _b;
    const calculateSignatureCount = (signatures) => {
        const count = signatures ? signatures.filter((s) => !parseInput_1.isPlaceholderSignature(s)).length : 0;
        if (count === 0 || count === 1 || count === 2) {
            return count;
        }
        throw new Error('invalid signature count');
    };
    if ('hash' in input) {
        if (((_a = input.script) === null || _a === void 0 ? void 0 : _a.length) || ((_b = input.witness) === null || _b === void 0 ? void 0 : _b.length)) {
            const parsedInput = parseInput_1.parseSignatureScript(input);
            return parsedInput.scriptType === 'taprootKeyPathSpend' ? 2 : calculateSignatureCount(parsedInput.signatures);
        }
        return 0;
    }
    else {
        return calculateSignatureCount(parsePsbtInput(input).signatures);
    }
}
exports.getStrictSignatureCount = getStrictSignatureCount;
/**
 * @returns strictly parse input and get signature count for all inputs.
 * 0=unsigned, 1=half-signed or 2=fully-signed
 */
function getStrictSignatureCounts(tx) {
    const inputs = tx instanceof UtxoPsbt_1.UtxoPsbt ? tx.data.inputs : tx instanceof UtxoTransaction_1.UtxoTransaction ? tx.ins : tx;
    return inputs.map((input, _) => getStrictSignatureCount(input));
}
exports.getStrictSignatureCounts = getStrictSignatureCounts;
/**
 * @return true iff inputs array is of PsbtInputType type
 * */
function isPsbtInputArray(inputs) {
    return !isTxInputArray(inputs);
}
exports.isPsbtInputArray = isPsbtInputArray;
/**
 * @return true iff inputs array is of TxInput type
 * */
function isTxInputArray(inputs) {
    assert(!!inputs.length, 'empty inputs array');
    return 'hash' in inputs[0];
}
exports.isTxInputArray = isTxInputArray;
/**
 * @returns true iff given psbt/transaction/tx-input-array/psbt-input-array contains at least one taproot key path spend input
 */
function isTransactionWithKeyPathSpendInput(data) {
    const inputs = data instanceof UtxoPsbt_1.UtxoPsbt ? data.data.inputs : data instanceof UtxoTransaction_1.UtxoTransaction ? data.ins : data;
    if (!inputs.length) {
        return false;
    }
    if (isPsbtInputArray(inputs)) {
        return inputs.some((input, _) => getPsbtInputScriptType(input) === 'taprootKeyPathSpend');
    }
    return inputs.some((input, _) => {
        // If the input is not signed, it cannot be a taprootKeyPathSpend input because you can only
        // extract a fully signed psbt into a transaction with taprootKeyPathSpend inputs.
        if (getStrictSignatureCount(input) === 0) {
            return false;
        }
        return parseInput_1.parseSignatureScript(input).scriptType === 'taprootKeyPathSpend';
    });
}
exports.isTransactionWithKeyPathSpendInput = isTransactionWithKeyPathSpendInput;
/**
 * Set the RootWalletKeys as the globalXpubs on the psbt
 *
 * We do all the matching of the (tap)bip32Derivations masterFingerprint to the fingerprint of the
 * extendedPubkey.
 */
function addXpubsToPsbt(psbt, rootWalletKeys) {
    const safeRootWalletKeys = new WalletKeys_1.RootWalletKeys(rootWalletKeys.triple.map((bip32) => bip32.neutered()), rootWalletKeys.derivationPrefixes);
    const xPubs = safeRootWalletKeys.triple.map((bip32) => ({
        extendedPubkey: bs58check.decode(bip32.toBase58()),
        masterFingerprint: bip32.fingerprint,
        // TODO: BG-73797 - bip174 currently requires m prefix for this to be a valid globalXpub
        path: 'm',
    }));
    psbt.updateGlobal({ globalXpub: xPubs });
}
exports.addXpubsToPsbt = addXpubsToPsbt;
/**
 * validates signatures for each 2 of 3 input against user, backup, bitgo keys derived from rootWalletKeys.
 * @returns array of input index and its [is valid user sig exist, is valid backup sig exist, is valid user bitgo exist]
 * For p2shP2pk input, [false, false, false] is returned since it is not a 2 of 3 sig input.
 */
function getSignatureValidationArrayPsbt(psbt, rootWalletKeys) {
    return psbt.data.inputs.map((input, i) => {
        const sigValArrayForInput = getPsbtInputScriptType(input) === 'p2shP2pk'
            ? [false, false, false]
            : psbt.getSignatureValidationArray(i, { rootNodes: rootWalletKeys.triple });
        return [i, sigValArrayForInput];
    });
}
exports.getSignatureValidationArrayPsbt = getSignatureValidationArrayPsbt;
/**
 * Extracts the half signed transaction from the psbt for p2ms based script types - p2sh, p2wsh, and p2shP2wsh.
 * The purpose is to provide backward compatibility to keyternal (KRS) that only supports network transaction and p2ms script types.
 */
function extractP2msOnlyHalfSignedTx(psbt) {
    assert(!!(psbt.data.inputs.length && psbt.data.outputs.length), 'empty inputs or outputs');
    const tx = psbt.getUnsignedTx();
    function isP2msParsedPsbtInput(parsed) {
        return ['p2sh', 'p2shP2wsh', 'p2wsh'].includes(parsed.scriptType);
    }
    psbt.data.inputs.forEach((input, i) => {
        var _a, _b;
        const parsed = parsePsbtInput(input);
        assert(isP2msParsedPsbtInput(parsed), `unsupported script type ${parsed.scriptType}`);
        assert(((_a = input.partialSig) === null || _a === void 0 ? void 0 : _a.length) === 1, `unexpected signature count ${(_b = input.partialSig) === null || _b === void 0 ? void 0 : _b.length}`);
        const [partialSig] = input.partialSig;
        assert(input.sighashType !== undefined && input.sighashType === bitcoinjs_lib_1.script.signature.decode(partialSig.signature).hashType, 'signature sighash does not match input sighash type');
        // type casting is to address the invalid type checking in payments.p2ms
        const signatures = parsed.publicKeys.map((pk) => partialSig.pubkey.equals(pk) ? partialSig.signature : bitcoinjs_lib_1.opcodes.OP_0);
        const isP2SH = !!parsed.redeemScript;
        const isP2WSH = !!parsed.witnessScript;
        const payment = index_1.payments.p2ms({ output: parsed.pubScript, signatures }, { validate: false, allowIncomplete: true });
        const p2wsh = isP2WSH ? index_1.payments.p2wsh({ redeem: payment }) : undefined;
        const p2sh = isP2SH ? index_1.payments.p2sh({ redeem: p2wsh || payment }) : undefined;
        if (p2sh === null || p2sh === void 0 ? void 0 : p2sh.input) {
            tx.setInputScript(i, p2sh.input);
        }
        if (p2wsh === null || p2wsh === void 0 ? void 0 : p2wsh.witness) {
            tx.setWitness(i, p2wsh.witness);
        }
    });
    return tx;
}
exports.extractP2msOnlyHalfSignedTx = extractP2msOnlyHalfSignedTx;
/**
 * Clones the psbt without nonWitnessUtxo for non-segwit inputs and witnessUtxo is added instead.
 * It is not BIP-174 compliant, so use it carefully.
 */
function clonePsbtWithoutNonWitnessUtxo(psbt) {
    const newPsbt = transaction_1.createPsbtFromHex(psbt.toHex(), psbt.network);
    const txInputs = psbt.txInputs;
    psbt.data.inputs.forEach((input, i) => {
        if (input.nonWitnessUtxo && !input.witnessUtxo) {
            const tx = UtxoTransaction_1.UtxoTransaction.fromBuffer(input.nonWitnessUtxo, false, 'bigint', psbt.network);
            if (!txInputs[i].hash.equals(tx.getHash())) {
                throw new Error(`Non-witness UTXO hash for input #${i} doesn't match the hash specified in the prevout`);
            }
            newPsbt.data.inputs[i].witnessUtxo = tx.outs[txInputs[i].index];
        }
        delete newPsbt.data.inputs[i].nonWitnessUtxo;
    });
    return newPsbt;
}
exports.clonePsbtWithoutNonWitnessUtxo = clonePsbtWithoutNonWitnessUtxo;
/**
 * Deletes witnessUtxo for non-segwit inputs to make the PSBT BIP-174 compliant.
 */
function deleteWitnessUtxoForNonSegwitInputs(psbt) {
    psbt.data.inputs.forEach((input, i) => {
        const scriptType = getPsbtInputScriptType(input);
        if (scriptType === 'p2sh' || scriptType === 'p2shP2pk') {
            delete input.witnessUtxo;
        }
    });
}
exports.deleteWitnessUtxoForNonSegwitInputs = deleteWitnessUtxoForNonSegwitInputs;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiUHNidC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3NyYy9iaXRnby93YWxsZXQvUHNidC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFBQSxpQ0FBaUM7QUFHakMsZ0RBQXFEO0FBRXJELHVDQUF1QztBQUN2QywwQ0FBdUM7QUFDdkMsd0RBQXFEO0FBQ3JELG9EQUE2RztBQUM3Ryw2Q0FBaUU7QUFDakUsd0NBQW9EO0FBQ3BELGdEQUE4RTtBQUM5RSx1Q0FBMkQ7QUFFM0QsOENBY3VCO0FBQ3ZCLHNDQUF1RDtBQUN2RCxvQ0FBMkM7QUFDM0MsMkNBQTBEO0FBQzFELGlEQUEyRTtBQUMzRSx1Q0FBZ0Q7QUFDaEQsMENBQStFO0FBcUUvRSxTQUFTLGlCQUFpQixDQUFDLE1BQWMsRUFBRSxVQUE2QjtJQUN0RSxNQUFNLGdCQUFnQixHQUFHLCtCQUFrQixDQUFDLE1BQU0sRUFBRSx3QkFBd0IsQ0FBQyxDQUFDLFVBQVUsQ0FBQztJQUN6RixNQUFNLGFBQWEsR0FBRyxnQkFBZ0IsQ0FBQyxHQUFHLENBQUMsQ0FBQyxTQUFTLEVBQUUsRUFBRTtRQUN2RCxNQUFNLEtBQUssR0FBRyxVQUFVLENBQUMsVUFBVSxDQUFDLFNBQVMsQ0FBQyxDQUFDLGVBQWUsRUFBRSxFQUFFLENBQ2hFLGdDQUFnQixDQUFDLGVBQWUsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxTQUFTLENBQUMsQ0FDcEQsQ0FBQztRQUNGLElBQUksS0FBSyxJQUFJLENBQUMsRUFBRTtZQUNkLE9BQU8sRUFBRSxTQUFTLEVBQUUsVUFBVSxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsRUFBRSxPQUFPLEVBQUUsVUFBVSxDQUFDLE1BQU0sQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLEVBQUUsQ0FBQztTQUMxRjtRQUNELE1BQU0sSUFBSSxLQUFLLENBQUMsK0NBQStDLENBQUMsQ0FBQztJQUNuRSxDQUFDLENBQUMsQ0FBQztJQUNILE9BQU8sQ0FBQyxhQUFhLENBQUMsQ0FB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V0FBVyxHQUFHLEVBQUUsQ0FBQyxJQUFJLENBQUMsUUFBUSxDQUFDLENBQUMsQ0FBQyxDQUFDLEtBQUssQ0FBQyxDQUFDO1NBQ2pFO1FBQ0QsT0FBTyxPQUFPLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQyxjQUFjLENBQUM7SUFDL0MsQ0FBQyxDQUFDLENBQUM7SUFFSCxPQUFPLE9BQU8sQ0FBQztBQUNqQixDQUFDO0FBaEJELHdFQWdCQztBQUVEOztHQUVHO0FBQ0gsU0FBZ0IsbUNBQW1DLENBQUMsSUFBYztJQUNoRSxJQUFJLENBQUMsSUFBSSxDQUFDLE1BQU0sQ0FBQyxPQUFPLENBQUMsQ0FBQyxLQUFLLEVBQUUsQ0FBQyxFQUFFLEVBQUU7UUFDcEMsTUFBTSxVQUFVLEdBQUcsc0JBQXNCLENBQUMsS0FBSyxDQUFDLENBQUM7UUFDakQsSUFBSSxVQUFVLEtBQUssTUFBTSxJQUFJLFVBQVUsS0FBSyxVQUFVLEVBQUU7WUFDdEQsT0FBTyxLQUFLLENBQUMsV0FBVyxDQUFDO1NBQzFCO0lBQ0gsQ0FBQyxDQUFDLENBQUM7QUFDTCxDQUFDO0FBUEQsa0ZBT0MiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgKiBhcyBhc3NlcnQgZnJvbSAnYXNzZXJ0JztcblxuaW1wb3J0IHsgR2xvYmFsWHB1YiwgUGFydGlhbFNpZywgUHNidElucHV0LCBUYXBTY3JpcHRTaWcgfSBmcm9tICdiaXAxNzQvc3JjL2xpYi9pbnRlcmZhY2VzJztcbmltcG9ydCB7IGNoZWNrRm9ySW5wdXQgfSBmcm9tICdiaXAxNzQvc3JjL2xpYi91dGlscyc7XG5pbXBvcnQgeyBCSVAzMkludGVyZmFjZSB9IGZyb20gJ2JpcDMyJztcbmltcG9ydCAqIGFzIGJzNThjaGVjayBmcm9tICdiczU4Y2hlY2snO1xuaW1wb3J0IHsgVXR4b1BzYnQgfSBmcm9tICcuLi9VdHhvUHNidCc7XG5pbXBvcnQgeyBVdHhvVHJhbnNhY3Rpb24gfSBmcm9tICcuLi9VdHhvVHJhbnNhY3Rpb24nO1xuaW1wb3J0IHsgY3JlYXRlT3V0cHV0U2NyaXB0Mm9mMywgZ2V0TGVhZkhhc2gsIHNjcmlwdFR5cGVGb3JDaGFpbiwgdG9YT25seVB1YmxpY0tleSB9IGZyb20gJy4uL291dHB1dFNjcmlwdHMnO1xuaW1wb3J0IHsgRGVyaXZlZFdhbGxldEtleXMsIFJvb3RXYWxsZXRLZXlzIH0gZnJvbSAnLi9XYWxsZXRLZXlzJztcbmltcG9ydCB7IHRvUHJldk91dHB1dFdpdGhQcmV2VHggfSBmcm9tICcuLi9VbnNwZW50JztcbmltcG9ydCB7IGNyZWF0ZVBzYnRGcm9tSGV4LCBjcmVhdGVQc2J0RnJvbVRyYW5zYWN0aW9uIH0gZnJvbSAnLi4vdHJhbnNhY3Rpb24nO1xuaW1wb3J0IHsgaXNXYWxsZXRVbnNwZW50LCBXYWxsZXRVbnNwZW50IH0gZnJvbSAnLi9VbnNwZW50JztcblxuaW1wb3J0IHtcbiAgZ2V0TGVhZlZlcnNpb24sXG4gIGNhbGN1bGF0ZVNjcmlwdFBhdGhMZXZlbCxcbiAgaXNWYWxpZENvbnRyb2xCb2NrLFxuICBQYXJzZWRQdWJTY3JpcHRQMm1zLFxuICBQYXJzZWRQdWJTY3JpcHRUYXByb290U2NyaXB0UGF0aCxcbiAgcGFyc2VQdWJTY3JpcHQyT2YzLFxuICBQYXJzZWRQdWJTY3JpcHRUYXByb290LFxuICBQYXJzZWRQdWJTY3JpcHRUYXByb290S2V5UGF0aCxcbiAgcGFyc2VQdWJTY3JpcHQsXG4gIFBhcnNlZFB1YlNjcmlwdFAyc2hQMnBrLFxuICBQYXJzZWRTY3JpcHRUeXBlLFxuICBpc1BsYWNlaG9sZGVyU2lnbmF0dXJlLFxuICBwYXJzZVNpZ25hdHVyZVNjcmlwdCxcbn0gZnJvbSAnLi4vcGFyc2VJbnB1dCc7XG5pbXBvcnQgeyBwYXJzZVBzYnRNdXNpZzJQYXJ0aWFsU2lncyB9IGZyb20gJy4uL011c2lnMic7XG5pbXBvcnQgeyBpc1R1cGxlLCBUcmlwbGUgfSBmcm9tICcuLi90eXBlcyc7XG5pbXBvcnQgeyBjcmVhdGVUYXByb290T3V0cHV0U2NyaXB0IH0gZnJvbSAnLi4vLi4vdGFwcm9vdCc7XG5pbXBvcnQgeyBvcGNvZGVzIGFzIG9wcywgc2NyaXB0IGFzIGJzY3JpcHQsIFR4SW5wdXQgfSBmcm9tICdiaXRjb2luanMtbGliJztcbmltcG9ydCB7IG9wY29kZXMsIHBheW1lbnRzIH0gZnJvbSAnLi4vLi4vaW5kZXgnO1xuaW1wb3J0IHsgZ2V0UHNidElucHV0U2lnbmF0dXJlQ291bnQsIGlzUHNidElucHV0RmluYWxpemVkIH0gZnJvbSAnLi4vUHNidFV0aWwnO1xuXG4vLyBvbmx5IHVzZWQgZm9yIGJ1aWxkaW5nIGBTaWduYXR1cmVDb250YWluZXJgXG50eXBlIEJhc2VTaWduYXR1cmVDb250YWluZXI8VD4gPSB7XG4gIHNpZ25hdHVyZXM6IFQ7XG59O1xuXG50eXBlIFVuc2lnbmVkU2lnbmF0dXJlQ29udGFpbmVyID0gQmFzZVNpZ25hdHVyZUNvbnRhaW5lcjx1bmRlZmluZWQ+O1xudHlwZSBIYWxmU2lnbmVkU2lnbmF0dXJlQ29udGFpbmVyID0gQmFzZVNpZ25hdHVyZUNvbnRhaW5lcjxbQnVmZmVyXT47XG50eXBlIEZ1bGxTaWduZWRTaWduYXR1cmVDb250YWluZXIgPSBCYXNlU2lnbmF0dXJlQ29udGFpbmVyPFtCdWZmZXIsIEJ1ZmZlcl0+O1xuXG50eXBlIFNpZ25hdHVyZUNvbnRhaW5lciA9IFVuc2lnbmVkU2lnbmF0dXJlQ29udGFpbmVyIHwgSGFsZlNpZ25lZFNpZ25hdHVyZUNvbnRhaW5lciB8IEZ1bGxTaWduZWRTaWduYXR1cmVDb250YWluZXI7XG5cbi8qKlxuICogQ29udGVudHMgb2YgYSBwcmUtZmluYWxpemVkIFBTQlQgSW5wdXQgZm9yIHAydHJNdXNpZzIga2V5IHBhdGggaW4gdGhlIG5vbi1maW5hbGl6ZWQgc3RhdGUuXG4gKiBUIGlzIFtCdWZmZXJdIGZvciBmaXJzdCBzaWduYXR1cmUsIFtCdWZmZXIsIEJ1ZmZlcl0gZm9yIGJvdGggc2lnbmF0dXJlcyBhbmQgYHVuZGVmaW5lZGAgZm9yIG5vIHNpZ25hdHVyZXMuXG4gKi9cbnR5cGUgQmFzZVRhcHJvb3RLZXlQYXRoU2lnbmF0dXJlQ29udGFpbmVyPFQ+ID0ge1xuICBzaWduYXR1cmVzOiBUO1xuICAvKiogT25seSBjb250YWlucyBwYXJ0aWNpcGFudHMgdGhhdCBoYXZlIGFkZGVkIGEgc2lnbmF0dXJlICovXG4gIHBhcnRpY2lwYW50UHVibGljS2V5czogVDtcbn07XG5cbnR5cGUgVW5zaWduZWRUYXByb290S2V5UGF0aFNpZ25hdHVyZUNvbnRhaW5lciA9IEJhc2VUYXByb290S2V5UGF0aFNpZ25hdHVyZUNvbnRhaW5lcjx1bmRlZmluZWQ+O1xudHlwZSBIYWxmU2lnbmVkVGFwcm9vdEtleVBhdGhTaWduYXR1cmVDb250YWluZXIgPSBCYXNlVGFwcm9vdEtleVBhdGhTaWduYXR1cmVDb250YWluZXI8W0J1ZmZlcl0+O1xudHlwZSBGdWxsU2lnbmVkVGFwcm9vdEtleVBhdGhTaWduYXR1cmVDb250YWluZXIgPSBCYXNlVGFwcm9vdEtleVBhdGhTaWduYXR1cmVDb250YWluZXI8W0J1ZmZlciwgQnVmZmVyXT47XG5cbnR5cGUgVGFwcm9vdEtleVBhdGhTaWduYXR1cmVDb250YWluZXIgPVxuICB8IFVuc2lnbmVkVGFwcm9vdEtleVBhdGhTaWduYXR1cmVDb250YWluZXJcbiAgfCBIYWxmU2lnbmVkVGFwcm9vdEtleVBhdGhTaWduYXR1cmVDb250YWluZXJcbiAgfCBGdWxsU2lnbmVkVGFwcm9vdEtleVBhdGhTaWduYXR1cmVDb250YWluZXI7XG5cbi8qKlxuICogVG8gaG9sZCBwYXJzZWQgcHNidCBkYXRhIGZvciBwMm1zIGJhc2VkIHNjcmlwdCB0eXBlcyAtIHAyc2gsIHAyd3NoLCBhbmQgcDJzaFAyd3NoXG4gKi9cbmV4cG9ydCB0eXBlIFBhcnNlZFBzYnRQMm1zID0gUGFyc2VkUHViU2NyaXB0UDJtcyAmIFNpZ25hdHVyZUNvbnRhaW5lcjtcblxuLyoqXG4gKiBUbyBob2xkIHBhcnNlZCBwc2J0IGRhdGEgZm9yIFRhcHJvb3RLZXlQYXRoU3BlbmQgc2NyaXB0IHR5cGUuXG4gKi9cbmV4cG9ydCB0eXBlIFBhcnNlZFBzYnRUYXByb290S2V5UGF0aCA9IFBhcnNlZFB1YlNjcmlwdFRhcHJvb3RLZXlQYXRoICYgVGFwcm9vdEtleVBhdGhTaWduYXR1cmVDb250YWluZXI7XG5cbi8qKlxuICogVG8gaG9sZCBwYXJzZWQgcHNidCBkYXRhIGZvciBUYXByb290U2NyaXB0UGF0aFNwZW5kIHNjcmlwdCBwYXRoIHNjcmlwdCB0eXBlLlxuICovXG5leHBvcnQgdHlwZSBQYXJzZWRQc2J0VGFwcm9vdFNjcmlwdFBhdGggPSBQYXJzZWRQdWJTY3JpcHRUYXByb290U2NyaXB0UGF0aCAmXG4gIFNpZ25hdHVyZUNvbnRhaW5lciAmIHtcbiAgICBjb250cm9sQmxvY2s6IEJ1ZmZlcjtcbiAgICBsZWFmVmVyc2lvbjogbnVtYmVyO1xuICAgIC8qKiBJbmRpY2F0ZXMgdGhlIGxldmVsIGluc2lkZSB0aGUgdGFwdHJlZS4gKi9cbiAgICBzY3JpcHRQYXRoTGV2ZWw6IG51bWJlcjtcbiAgfTtcblxuZXhwb3J0IHR5cGUgUGFyc2VkUHNidFRhcHJvb3QgPSBQYXJzZWRQc2J0VGFwcm9vdEtleVBhdGggfCBQYXJzZWRQc2J0VGFwcm9vdFNjcmlwdFBhdGg7XG5cbnR5cGUgUDJzaFAycGtTaWduYXR1cmVDb250YWluZXIgPSBVbnNpZ25lZFNpZ25hdHVyZUNvbnRhaW5lciB8IEhhbGZTaWduZWRTaWduYXR1cmVDb250YWluZXI7XG5cbmV4cG9ydCB0eXBlIFBhcnNlZFBzYnRQMnNoUDJwayA9IFBhcnNlZFB1YlNjcmlwdFAyc2hQMnBrICYgUDJzaFAycGtTaWduYXR1cmVDb250YWluZXI7XG5cbmludGVyZmFjZSBXYWxsZXRTaWduZXIge1xuICB3YWxsZXRLZXk6IEJJUDMySW50ZXJmYWNlO1xuICByb290S2V5OiBCSVAzMkludGVyZmFjZTtcbn1cblxuLyoqXG4gKiBwc2J0IGlucHV0IGluZGV4IGFuZCBpdHMgdXNlciwgYmFja3VwLCBiaXRnbyBzaWduYXR1cmVzIHN0YXR1c1xuICovXG5leHBvcnQgdHlwZSBTaWduYXR1cmVWYWxpZGF0aW9uID0gW2luZGV4OiBudW1iZXIsIHNpZ1RyaXBsZTogVHJpcGxlPGJvb2xlYW4+XTtcblxuZnVuY3Rpb24gZ2V0VGFwcm9vdFNpZ25lcnMoc2NyaXB0OiBCdWZmZXIsIHdhbGxldEtleXM6IERlcml2ZWRXYWxsZXRLZXlzKTogW1dhbGxldFNpZ25lciwgV2FsbGV0U2lnbmVyXSB7XG4gIGNvbnN0IHBhcnNlZFB1YmxpY0tleXMgPSBwYXJzZVB1YlNjcmlwdDJPZjMoc2NyaXB0LCAndGFwcm9vdFNjcmlwdFBhdGhTcGVuZCcpLnB1YmxpY0tleXM7XG4gIGNvbnN0IHdhbGxldFNpZ25lcnMgPSBwYXJzZWRQdWJsaWNLZXlzLm1hcCgocHVibGljS2V5KSA9PiB7XG4gICAgY29uc3QgaW5kZXggPSB3YWxsZXRLZXlzLnB1YmxpY0tleXMuZmluZEluZGV4KCh3YWxsZXRQdWJsaWNLZXkpID0+XG4gICAgICB0b1hPbmx5UHVibGljS2V5KHdhbGxldFB1YmxpY0tleSkuZXF1YWxzKHB1YmxpY0tleSlcbiAgICApO1xuICAgIGlmIChpbmRleCA+PSAwKSB7XG4gICAgICByZXR1cm4geyB3YWxsZXRLZXk6IHdhbGxldEtleXMudHJpcGxlW2luZGV4XSwgcm9vdEtleTogd2FsbGV0S2V5cy5wYXJlbnQudHJpcGxlW2luZGV4XSB9O1xuICAgIH1cbiAgICB0aHJvdyBuZXcgRXJyb3IoJ1RhcHJvb3QgcHVibGljIGtleSBpcyBub3QgYSB3YWxsZXQgcHVibGljIGtleScpO1xuICB9KTtcbiAgcmV0dXJuIFt3YWxsZXRTaWduZXJzWzBdLCB3YWxsZXRTaWduZXJzWzFdXTtcbn1cblxuZnVuY3Rpb24gdXBkYXRlUHNidElucHV0KFxuICBwc2J0OiBVdHhvUHNidCxcbiAgaW5wdXRJbmRleDogbnVtYmVyLFxuICB1bnNwZW50OiBXYWxsZXRVbnNwZW50PGJpZ2ludD4sXG4gIHJvb3RXYWxsZXRLZXlzOiBSb290V2FsbGV0S2V5c1xuKTogdm9pZCB7XG4gIGNvbnN0IGlucHV0ID0gY2hlY2tGb3JJbnB1dChwc2J0LmRhdGEuaW5wdXRzLCBpbnB1dEluZGV4KTtcbiAgY29uc3Qgc2lnbmF0dXJlQ291bnQgPSBnZXRQc2J0SW5wdXRTaWduYXR1cmVDb3VudChpbnB1dCk7XG4gIGNvbnN0IHNjcmlwdFR5cGUgPSBzY3JpcHRUeXBlRm9yQ2hhaW4odW5zcGVudC5jaGFpbik7XG4gIGlmIChzaWduYXR1cmVDb3VudCA9PT0gMCAmJiBzY3JpcHRUeXBlID09PSAncDJ0cicpIHtcbiAgICByZXR1cm47XG4gIH1cbiAgY29uc3Qgd2FsbGV0S2V5cyA9IHJvb3RXYWxsZXRLZXlzLmRlcml2ZUZvckNoYWluQW5kSW5kZXgodW5zcGVudC5jaGFpbiwgdW5zcGVudC5pbmRleCk7XG5cbiAgaWYgKHNjcmlwdFR5cGUgPT09ICdwMnRyJykge1xuICAgIGlmICghQXJyYXkuaXNBcnJheShpbnB1dC50YXBMZWFmU2NyaXB0KSB8fCBpbnB1dC50YXBMZWFmU2NyaXB0Lmxlbmd0aCA9PT0gMCkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdJbnZhbGlkIFBTQlQgc3RhdGUuIE1pc3NpbmcgcmVxdWlyZWQgZmllbGRzLicpO1xuICAgIH1cblxuICAgIGlmIChpbnB1dC50YXBMZWFmU2NyaXB0Lmxlbmd0aCA+IDEpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignQml0Z28gb25seSBzdXBwb3J0cyBhIHNpbmdsZSB0YXAgbGVhZiBzY3JpcHQgcGVyIGlucHV0Jyk7XG4gICAgfVxuXG4gICAgY29uc3QgW3NpZ25lciwgY29zaWduZXJdID0gZ2V0VGFwcm9vdFNpZ25lcnMoaW5wdXQudGFwTGVhZlNjcmlwdFswXS5zY3JpcHQsIHdhbGxldEtleXMpO1xuXG4gICAgY29uc3QgbGVhZkhhc2ggPSBnZXRMZWFmSGFzaCh7XG4gICAgICBwdWJsaWNLZXlzOiB3YWxsZXRLZXlzLnB1YmxpY0tleXMsXG4gICAgICBzaWduZXI6IHNpZ25lci53YWxsZXRLZXkucHVibGljS2V5LFxuICAgICAgY29zaWduZXI6IGNvc2lnbmVyLndhbGxldEtleS5wdWJsaWNLZXksXG4gICAgfSk7XG5cbiAgICBwc2J0LnVwZGF0ZUlucHV0KGlucHV0SW5kZXgsIHtcbiAgICAgIHRhcEJpcDMyRGVyaXZhdGlvbjogW3NpZ25lciwgY29zaWduZXJdLm1hcCgod2FsbGV0U2lnbmVyKSA9PiAoe1xuICAgICAgICBsZWFmSGFzaGVzOiBbbGVhZkhhc2hdLFxuICAgICAgICBwdWJrZXk6IHRvWE9ubHlQdWJsaWNLZXkod2FsbGV0U2lnbmVyLndhbGxldEtleS5wdWJsaWNLZXkpLFxuICAgICAgICBwYXRoOiByb290V2FsbGV0S2V5cy5nZXREZXJpdmF0aW9uUGF0aCh3YWxsZXRTaWduZXIucm9vdEtleSwgdW5zcGVudC5jaGFpbiwgdW5zcGVudC5pbmRleCksXG4gICAgICAgIG1hc3RlckZpbmdlcnByaW50OiB3YWxsZXRTaWduZXIucm9vdEtleS5maW5nZXJwcmludCxcbiAgICAgIH0pKSxcbiAgICB9KTtcbiAgfSBlbHNlIHtcbiAgICBpZiAoc2lnbmF0dXJlQ291bnQgPT09IDApIHtcbiAgICAgIGNvbnN0IHsgd2l0bmVzc1NjcmlwdCwgcmVkZWVtU2NyaXB0IH0gPSBjcmVhdGVPdXRwdXRTY3JpcHQyb2YzKHdhbGxldEtleXMucHVibGljS2V5cywgc2NyaXB0VHlwZSk7XG4gICAgICBpZiAod2l0bmVzc1NjcmlwdCAmJiBwc2J0LmRhdGEuaW5wdXRzW2lucHV0SW5kZXhdLndpdG5lc3NTY3JpcHQgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICBwc2J0LnVwZGF0ZUlucHV0KGlucHV0SW5kZXgsIHsgd2l0bmVzc1NjcmlwdCB9KTtcbiAgICAgIH1cbiAgICAgIGlmIChyZWRlZW1TY3JpcHQgJiYgcHNidC5kYXRhLmlucHV0c1tpbnB1dEluZGV4XS5yZWRlZW1TY3JpcHQgPT09IHVuZGVmaW5lZCkge1xuICAgICAgICBwc2J0LnVwZGF0ZUlucHV0KGlucHV0SW5kZXgsIHsgcmVkZWVtU2NyaXB0IH0pO1xuICAgICAgfVxuICAgIH1cblxuICAgIHBzYnQudXBkYXRlSW5wdXQoaW5wdXRJbmRleCwge1xuICAgICAgYmlwMzJEZXJpdmF0aW9uOiBbMCwgMSwgMl0ubWFwKChpZHgpID0+ICh7XG4gICAgICAgIHB1YmtleTogd2FsbGV0S2V5cy50cmlwbGVbaWR4XS5wdWJsaWNLZXksXG4gICAgICAgIHBhdGg6IHdhbGxldEtleXMucGF0aHNbaWR4XSxcbiAgICAgICAgbWFzdGVyRmluZ2VycHJpbnQ6IHJvb3RXYWxsZXRLZXlzLnRyaXBsZVtpZHhdLmZpbmdlcnByaW50LFxuICAgICAgfSkpLFxuICAgIH0pO1xuICB9XG59XG5cbi8qKlxuICogQHJldHVybiBQU0JUIGZpbGxlZCB3aXRoIG1ldGF0ZGF0YSBhcyBwZXIgaW5wdXQgcGFyYW1zIHR4LCB1bnNwZW50cyBhbmQgcm9vdFdhbGxldEtleXMuXG4gKiBVbnNpZ25lZCBQU0JUIGZvciB0YXByb290IGlucHV0IHdpdGggd2l0bmVzc1V0eG9cbiAqIFVuc2lnbmVkIFBTQlQgZm9yIG90aGVyIGlucHV0IHdpdGggd2l0bmVzc1V0eG8vbm9uV2l0bmVzc1V0eG8sIHJlZGVlbVNjcmlwdC93aXRuZXNzU2NyaXB0LCBiaXAzMkRlcml2YXRpb25cbiAqIFNpZ25lZCBQU0JUIGZvciB0YXByb290IGlucHV0IHdpdGggd2l0bmVzc1V0eG8sIHRhcExlYWZTY3JpcHQsIHRhcEJpcDMyRGVyaXZhdGlvbiwgdGFwU2NyaXB0U2lnXG4gKiBTaWduZWQgUFNCVCBmb3Igb3RoZXIgaW5wdXQgd2l0aCB3aXRuZXNzVXR4by9ub25XaXRuZXNzVXR4bywgcmVkZWVtU2NyaXB0L3dpdG5lc3NTY3JpcHQsIGJpcDMyRGVyaXZhdGlvbiwgcGFydGlhbFNpZ1xuICovXG5leHBvcnQgZnVuY3Rpb24gdG9XYWxsZXRQc2J0KFxuICB0eDogVXR4b1RyYW5zYWN0aW9uPGJpZ2ludD4sXG4gIHVuc3BlbnRzOiBXYWxsZXRVbnNwZW50PGJpZ2ludD5bXSxcbiAgcm9vdFdhbGxldEtleXM6IFJvb3RXYWxsZXRLZXlzXG4pOiBVdHhvUHNidCB7XG4gIGNvbnN0IHByZXZPdXRwdXRzID0gdW5zcGVudHMubWFwKCh1KSA9PiB7XG4gICAgYXNzZXJ0Lm5vdFN0cmljdEVxdWFsKHNjcmlwdFR5cGVGb3JDaGFpbih1LmNoYWluKSwgJ3AydHJNdXNpZzInKTtcbiAgICByZXR1cm4gdG9QcmV2T3V0cHV0V2l0aFByZXZUeCh1LCB0eC5uZXR3b3JrKTtcbiAgfSk7XG4gIGNvbnN0IHBzYnQgPSBjcmVhdGVQc2J0RnJvbVRyYW5zYWN0aW9uKHR4LCBwcmV2T3V0cHV0cyk7XG4gIHVuc3BlbnRzLmZvckVhY2goKHUsIGkpID0+IHtcbiAgICBpZiAoaXNXYWxsZXRVbnNwZW50KHUpICYmIHUuaW5kZXggIT09IHVuZGVmaW5lZCkge1xuICAgICAgdXBkYXRlUHNidElucHV0KHBzYnQsIGksIHUsIHJvb3RXYWxsZXRLZXlzKTtcbiAgICB9XG4gIH0pO1xuICByZXR1cm4gcHNidDtcbn1cblxuLyoqXG4gKiBAcGFyYW0gcHNidFxuICogQHBhcmFtIGlucHV0SW5kZXhcbiAqIEBwYXJhbSBzaWduZXJcbiAqIEBwYXJhbSB1bnNwZW50XG4gKiBAcmV0dXJuIHNpZ25lZCBQU0JUIHdpdGggc2lnbmVyJ3Mga2V5IGZvciB1bnNwZW50XG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBzaWduV2FsbGV0UHNidChcbiAgcHNidDogVXR4b1BzYnQsXG4gIGlucHV0SW5kZXg6IG51bWJlcixcbiAgc2lnbmVyOiBCSVAzMkludGVyZmFjZSxcbiAgdW5zcGVudDogV2FsbGV0VW5zcGVudDxiaWdpbnQ+XG4pOiB2b2lkIHtcbiAgY29uc3Qgc2NyaXB0VHlwZSA9IHNjcmlwdFR5cGVGb3JDaGFpbih1bnNwZW50LmNoYWluKTtcbiAgaWYgKHNjcmlwdFR5cGUgPT09ICdwMnRyJyB8fCBzY3JpcHRUeXBlID09PSAncDJ0ck11c2lnMicpIHtcbiAgICBwc2J0LnNpZ25UYXByb290SW5wdXRIRChpbnB1dEluZGV4LCBzaWduZXIpO1xuICB9IGVsc2Uge1xuICAgIHBzYnQuc2lnbklucHV0SEQoaW5wdXRJbmRleCwgc2lnbmVyKTtcbiAgfVxufVxuXG4vKipcbiAqIEByZXR1cm5zIHNjcmlwdCB0eXBlIG9mIHRoZSBpbnB1dFxuICovXG5leHBvcnQgZnVuY3Rpb24gZ2V0UHNidElucHV0U2NyaXB0VHlwZShpbnB1dDogUHNidElucHV0KTogUGFyc2VkU2NyaXB0VHlwZSB7XG4gIGNvbnN0IGlzUDJwayA9IChzY3JpcHQ6IEJ1ZmZlcikgPT4ge1xuICAgIHRyeSB7XG4gICAgICBjb25zdCBjaHVua3MgPSBic2NyaXB0LmRlY29tcGlsZShzY3JpcHQpO1xuICAgICAgcmV0dXJuIChcbiAgICAgICAgY2h1bmtzPy5sZW5ndGggPT09IDIgJiZcbiAgICAgICAgQnVmZmVyLmlzQnVmZmVyKGNodW5rc1swXSkgJiZcbiAgICAgICAgYnNjcmlwdC5pc0Nhbm9uaWNhbFB1YktleShjaHVua3NbMF0pICYmXG4gICAgICAgIGNodW5rc1sxXSA9PT0gb3Bjb2Rlcy5PUF9DSEVDS1NJR1xuICAgICAgKTtcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuICB9O1xuICBsZXQgc2NyaXB0VHlwZTogUGFyc2VkU2NyaXB0VHlwZSB8IHVuZGVmaW5lZDtcbiAgaWYgKEJ1ZmZlci5pc0J1ZmZlcihpbnB1dC5yZWRlZW1TY3JpcHQpICYmIEJ1ZmZlci5pc0J1ZmZlcihpbnB1dC53aXRuZXNzU2NyaXB0KSkge1xuICAgIHNjcmlwdFR5cGUgPSAncDJzaFAyd3NoJztcbiAgfSBlbHNlIGlmIChCdWZmZXIuaXNCdWZmZXIoaW5wdXQucmVkZWVtU2NyaXB0KSkge1xuICAgIHNjcmlwdFR5cGUgPSBpc1AycGsoaW5wdXQucmVkZWVtU2NyaXB0KSA/ICdwMnNoUDJwaycgOiAncDJzaCc7XG4gIH0gZWxzZSBpZiAoQnVmZmVyLmlzQnVmZmVyKGlucHV0LndpdG5lc3NTY3JpcHQpKSB7XG4gICAgc2NyaXB0VHlwZSA9ICdwMndzaCc7XG4gIH1cbiAgaWYgKEFycmF5LmlzQXJyYXkoaW5wdXQudGFwTGVhZlNjcmlwdCkgJiYgaW5wdXQudGFwTGVhZlNjcmlwdC5sZW5ndGggPiAwKSB7XG4gICAgaWYgKHNjcmlwdFR5cGUpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihgRm91bmQgYm90aCAke3NjcmlwdFR5cGV9IGFuZCB0YXByb290U2NyaXB0UGF0aCBQU0JUIG1ldGFkYXRhLmApO1xuICAgIH1cbiAgICBpZiAoaW5wdXQudGFwTGVhZlNjcmlwdC5sZW5ndGggPiAxKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0JpdGdvIG9ubHkgc3VwcG9ydHMgYSBzaW5nbGUgdGFwIGxlYWYgc2NyaXB0IHBlciBpbnB1dC4nKTtcbiAgICB9XG4gICAgc2NyaXB0VHlwZSA9ICd0YXByb290U2NyaXB0UGF0aFNwZW5kJztcbiAgfVxuICBpZiAoaW5wdXQudGFwSW50ZXJuYWxLZXkpIHtcbiAgICBpZiAoc2NyaXB0VHlwZSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKGBGb3VuZCBib3RoICR7c2NyaXB0VHlwZX0gYW5kIHRhcHJvb3RLZXlQYXRoIFBTQlQgbWV0YWRhdGEuYCk7XG4gICAgfVxuICAgIHNjcmlwdFR5cGUgPSAndGFwcm9vdEtleVBhdGhTcGVuZCc7XG4gIH1cbiAgaWYgKHNjcmlwdFR5cGUpIHtcbiAgICByZXR1cm4gc2NyaXB0VHlwZTtcbiAgfVxuICB0aHJvdyBuZXcgRXJyb3IoJ2NvdWxkIG5vdCBwYXJzZSBpbnB1dCcpO1xufVxuXG5mdW5jdGlvbiBwYXJzZVRhcHJvb3RLZXlQYXRoU2lnbmF0dXJlcyhpbnB1dDogUHNidElucHV0KTogVGFwcm9vdEtleVBhdGhTaWduYXR1cmVDb250YWluZXIge1xuICBjb25zdCBwYXJ0aWFsU2lncyA9IHBhcnNlUHNidE11c2lnMlBhcnRpYWxTaWdzKGlucHV0KTtcbiAgaWYgKCFwYXJ0aWFsU2lncykge1xuICAgIHJldHVybiB7IHNpZ25hdHVyZXM6IHVuZGVmaW5lZCwgcGFydGljaXBhbnRQdWJsaWNLZXlzOiB1bmRlZmluZWQgfTtcbiAgfVxuICBjb25zdCBzaWduYXR1cmVzID0gcGFydGlhbFNpZ3MubWFwKChwU2lnKSA9PiBwU2lnLnBhcnRpYWxTaWcpO1xuICBjb25zdCBwYXJ0aWNpcGFudFB1YmxpY0tleXMgPSBwYXJ0aWFsU2lncy5tYXAoKHBTaWcpID0+IHBTaWcucGFydGljaXBhbnRQdWJLZXkpO1xuICByZXR1cm4gaXNUdXBsZTxCdWZmZXI+KHNpZ25hdHVyZXMpICYmIGlzVHVwbGU8QnVmZmVyPihwYXJ0aWNpcGFudFB1YmxpY0tleXMpXG4gICAgPyB7IHNpZ25hdHVyZXMsIHBhcnRpY2lwYW50UHVibGljS2V5cyB9XG4gICAgOiB7IHNpZ25hdHVyZXM6IFtzaWduYXR1cmVzWzBdXSwgcGFydGljaXBhbnRQdWJsaWNLZXlzOiBbcGFydGljaXBhbnRQdWJsaWNLZXlzWzBdXSB9O1xufVxuXG5mdW5jdGlvbiBwYXJzZVBhcnRpYWxPclRhcFNjcmlwdFNpZ25hdHVyZXMoc2lnOiBQYXJ0aWFsU2lnW10gfCBUYXBTY3JpcHRTaWdbXSB8IHVuZGVmaW5lZCk6IFNpZ25hdHVyZUNvbnRhaW5lciB7XG4gIGlmICghc2lnPy5sZW5ndGgpIHtcbiAgICByZXR1cm4geyBzaWduYXR1cmVzOiB1bmRlZmluZWQgfTtcbiAgfVxuICBpZiAoc2lnLmxlbmd0aCA+IDIpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ3VuZXhwZWN0ZWQgc2lnbmF0dXJlIGNvdW50Jyk7XG4gIH1cbiAgY29uc3Qgc2lnbmF0dXJlcyA9IHNpZy5tYXAoKHRTaWcpID0+IHRTaWcuc2lnbmF0dXJlKTtcbiAgcmV0dXJuIGlzVHVwbGU8QnVmZmVyPihzaWduYXR1cmVzKSA/IHsgc2lnbmF0dXJlcyB9IDogeyBzaWduYXR1cmVzOiBbc2lnbmF0dXJlc1swXV0gfTtcbn1cblxuZnVuY3Rpb24gcGFyc2VTaWduYXR1cmVzKFxuICBpbnB1dDogUHNidElucHV0LFxuICBzY3JpcHRUeXBlOiBQYXJzZWRTY3JpcHRUeXBlXG4pOiBTaWduYXR1cmVDb250YWluZXIgfCBUYXByb290S2V5UGF0aFNpZ25hdHVyZUNvbnRhaW5lciB7XG4gIHJldHVybiBzY3JpcHRUeXBlID09PSAndGFwcm9vdEtleVBhdGhTcGVuZCdcbiAgICA/IHBhcnNlVGFwcm9vdEtleVBhdGhTaWduYXR1cmVzKGlucHV0KVxuICAgIDogc2NyaXB0VHlwZSA9PT0gJ3RhcHJvb3RTY3JpcHRQYXRoU3BlbmQnXG4gICAgPyBwYXJzZVBhcnRpYWxPclRhcFNjcmlwdFNpZ25hdHVyZXMoaW5wdXQudGFwU2NyaXB0U2lnKVxuICAgIDogcGFyc2VQYXJ0aWFsT3JUYXBTY3JpcHRTaWduYXR1cmVzKGlucHV0LnBhcnRpYWxTaWcpO1xufVxuXG5mdW5jdGlvbiBwYXJzZVNjcmlwdChcbiAgaW5wdXQ6IFBzYnRJbnB1dCxcbiAgc2NyaXB0VHlwZTogUGFyc2VkU2NyaXB0VHlwZVxuKTogUGFyc2VkUHViU2NyaXB0UDJtcyB8IFBhcnNlZFB1YlNjcmlwdFRhcHJvb3QgfCBQYXJzZWRQdWJTY3JpcHRQMnNoUDJwayB7XG4gIGxldCBwdWJTY3JpcHQ6IEJ1ZmZlciB8IHVuZGVmaW5lZDtcbiAgaWYgKHNjcmlwdFR5cGUgPT09ICdwMnNoJyB8fCBzY3JpcHRUeXBlID09PSAncDJzaFAycGsnKSB7XG4gICAgcHViU2NyaXB0ID0gaW5wdXQucmVkZWVtU2NyaXB0O1xuICB9IGVsc2UgaWYgKHNjcmlwdFR5cGUgPT09ICdwMndzaCcgfHwgc2NyaXB0VHlwZSA9PT0gJ3Ayc2hQMndzaCcpIHtcbiAgICBwdWJTY3JpcHQgPSBpbnB1dC53aXRuZXNzU2NyaXB0O1xuICB9IGVsc2UgaWYgKHNjcmlwdFR5cGUgPT09ICd0YXByb290U2NyaXB0UGF0aFNwZW5kJykge1xuICAgIHB1YlNjcmlwdCA9IGlucHV0LnRhcExlYWZTY3JpcHQgPyBpbnB1dC50YXBMZWFmU2NyaXB0WzBdLnNjcmlwdCA6IHVuZGVmaW5lZDtcbiAgfSBlbHNlIGlmIChzY3JpcHRUeXBlID09PSAndGFwcm9vdEtleVBhdGhTcGVuZCcpIHtcbiAgICBpZiAoaW5wdXQud2l0bmVzc1V0eG8/LnNjcmlwdCkge1xuICAgICAgcHViU2NyaXB0ID0gaW5wdXQud2l0bmVzc1V0eG8uc2NyaXB0O1xuICAgIH0gZWxzZSBpZiAoaW5wdXQudGFwSW50ZXJuYWxLZXkgJiYgaW5wdXQudGFwTWVya2xlUm9vdCkge1xuICAgICAgcHViU2NyaXB0ID0gY3JlYXRlVGFwcm9vdE91dHB1dFNjcmlwdCh7IGludGVybmFsUHViS2V5OiBpbnB1dC50YXBJbnRlcm5hbEtleSwgdGFwdHJlZVJvb3Q6IGlucHV0LnRhcE1lcmtsZVJvb3QgfSk7XG4gICAgfVxuICB9XG4gIGlmICghcHViU2NyaXB0KSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKGBJbnZhbGlkIFBTQlQgc3RhdGUgZm9yICR7c2NyaXB0VHlwZX0uIE1pc3NpbmcgcmVxdWlyZWQgZmllbGRzLmApO1xuICB9XG4gIHJldHVybiBwYXJzZVB1YlNjcmlwdChwdWJTY3JpcHQsIHNjcmlwdFR5cGUpO1xufVxuXG4vKipcbiAqIEByZXR1cm4gcHNidCBtZXRhZGF0YSBhcmUgcGFyc2VkIGFzIHBlciBiZWxvdyBjb25kaXRpb25zLlxuICogcmVkZWVtU2NyaXB0L3dpdG5lc3NTY3JpcHQvdGFwTGVhZlNjcmlwdCBtYXRjaGVzIEJpdEdvLlxuICogc2lnbmF0dXJlIGFuZCBwdWJsaWMga2V5IGNvdW50IG1hdGNoZXMgQml0R28uXG4gKiBQMlNILVAyUEsgPT4gc2NyaXB0VHlwZSwgcmVkZWVtU2NyaXB0LCBwdWJsaWMga2V5LCBzaWduYXR1cmUuXG4gKiBQMlNIID0+IHNjcmlwdFR5cGUsIHJlZGVlbVNjcmlwdCwgcHVibGljIGtleXMsIHNpZ25hdHVyZXMuXG4gKiBQVzJTSCA9PiBzY3JpcHRUeXBlLCB3aXRuZXNzU2NyaXB0LCBwdWJsaWMga2V5cywgc2lnbmF0dXJlcy5cbiAqIFAyU0gtUFcyU0ggPT4gc2NyaXB0VHlwZSwgcmVkZWVtU2NyaXB0LCB3aXRuZXNzU2NyaXB0LCBwdWJsaWMga2V5cywgc2lnbmF0dXJlcy5cbiAqIFAyVFIgYW5kIFAyVFIgTVVTSUcyIHNjcmlwdCBwYXRoID0+IHNjcmlwdFR5cGUgKHRhcHJvb3RTY3JpcHRQYXRoU3BlbmQpLCBwdWJTY3JpcHQgKGxlYWYgc2NyaXB0KSwgY29udHJvbEJsb2NrLFxuICogc2NyaXB0UGF0aExldmVsLCBsZWFmVmVyc2lvbiwgcHVibGljIGtleXMsIHNpZ25hdHVyZXMuXG4gKiBQMlRSIE1VU0lHMiBrZXAgcGF0aCA9PiBzY3JpcHRUeXBlICh0YXByb290S2V5UGF0aFNwZW5kKSwgcHViU2NyaXB0IChzY3JpcHRQdWJLZXkpLCBwYXJ0aWNpcGFudCBwdWIga2V5cyAoc2lnbmVyKSxcbiAqIHB1YmxpYyBrZXkgKHRhcE91dHB1dGtleSksIHNpZ25hdHVyZXMgKHBhcnRpYWwgc2lnbmVyIHNpZ3MpLlxuICovXG5leHBvcnQgZnVuY3Rpb24gcGFyc2VQc2J0SW5wdXQoaW5wdXQ6IFBzYnRJbnB1dCk6IFBhcnNlZFBzYnRQMm1zIHwgUGFyc2VkUHNidFRhcHJvb3QgfCBQYXJzZWRQc2J0UDJzaFAycGsge1xuICBpZiAoaXNQc2J0SW5wdXRGaW5hbGl6ZWQoaW5wdXQpKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKCdGaW5hbGl6ZWQgUFNCVCBwYXJzaW5nIGlzIG5vdCBzdXBwb3J0ZWQnKTtcbiAgfVxuICBjb25zdCBzY3JpcHRUeXBlID0gZ2V0UHNidElucHV0U2NyaXB0VHlwZShpbnB1dCk7XG4gIGNvbnN0IHBhcnNlZFB1YlNjcmlwdCA9IHBhcnNlU2NyaXB0KGlucHV0LCBzY3JpcHRUeXBlKTtcbiAgY29uc3Qgc2lnbmF0dXJlcyA9IHBhcnNlU2lnbmF0dXJlcyhpbnB1dCwgc2NyaXB0VHlwZSk7XG5cbiAgaWYgKHBhcnNlZFB1YlNjcmlwdC5zY3JpcHRUeXBlID09PSAndGFwcm9vdEtleVBhdGhTcGVuZCcgJiYgJ3BhcnRpY2lwYW50UHVibGljS2V5cycgaW4gc2lnbmF0dXJlcykge1xuICAgIHJldHVybiB7XG4gICAgICAuLi5wYXJzZWRQdWJTY3JpcHQsXG4gICAgICAuLi5zaWduYXR1cmVzLFxuICAgIH07XG4gIH1cbiAgaWYgKHBhcnNlZFB1YlNjcmlwdC5zY3JpcHRUeXBlID09PSAndGFwcm9vdFNjcmlwdFBhdGhTcGVuZCcpIHtcbiAgICBpZiAoIWlucHV0LnRhcExlYWZTY3JpcHQpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignSW52YWxpZCBQU0JUIHN0YXRlIGZvciB0YXByb290U2NyaXB0UGF0aFNwZW5kLiBNaXNzaW5nIHJlcXVpcmVkIGZpZWxkcy4nKTtcbiAgICB9XG4gICAgY29uc3QgY29udHJvbEJsb2NrID0gaW5wdXQudGFwTGVhZlNjcmlwdFswXS5jb250cm9sQmxvY2s7XG4gICAgaWYgKCFpc1ZhbGlkQ29udHJvbEJvY2soY29udHJvbEJsb2NrKSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdJbnZhbGlkIFBTQlQgdGFwcm9vdFNjcmlwdFBhdGhTcGVuZCBjb250cm9sQmxvY2suJyk7XG4gICAgfVxuICAgIGNvbnN0IHNjcmlwdFBhdGhMZXZlbCA9IGNhbGN1bGF0ZVNjcmlwdFBhdGhMZXZlbChjb250cm9sQmxvY2spO1xuICAgIGNvbnN0IGxlYWZWZXJzaW9uID0gZ2V0TGVhZlZlcnNpb24oY29udHJvbEJsb2NrKTtcbiAgICByZXR1cm4ge1xuICAgICAgLi4ucGFyc2VkUHViU2NyaXB0LFxuICAgICAgLi4uc2lnbmF0dXJlcyxcbiAgICAgIGNvbnRyb2xCbG9jayxcbiAgICAgIHNjcmlwdFBhdGhMZXZlbCxcbiAgICAgIGxlYWZWZXJzaW9uLFxuICAgIH07XG4gIH1cbiAgaWYgKFxuICAgIHBhcnNlZFB1YlNjcmlwdC5zY3JpcHRUeXBlID09PSAncDJzaCcgfHxcbiAgICBwYXJzZWRQdWJTY3JpcHQuc2NyaXB0VHlwZSA9PT0gJ3Ayd3NoJyB8fFxuICAgIHBhcnNlZFB1YlNjcmlwdC5zY3JpcHRUeXBlID09PSAncDJzaFAyd3NoJ1xuICApIHtcbiAgICBpZiAocGFyc2VkUHViU2NyaXB0LnNjcmlwdFR5cGUgPT09ICdwMnNoUDJ3c2gnKSB7XG4gICAgICBwYXJzZWRQdWJTY3JpcHQucmVkZWVtU2NyaXB0ID0gaW5wdXQucmVkZWVtU2NyaXB0O1xuICAgIH1cbiAgICByZXR1cm4ge1xuICAgICAgLi4ucGFyc2VkUHViU2NyaXB0LFxuICAgICAgLi4uc2lnbmF0dXJlcyxcbiAgICB9O1xuICB9XG4gIGlmIChwYXJzZWRQdWJTY3JpcHQuc2NyaXB0VHlwZSA9PT0gJ3Ayc2hQMnBrJyAmJiAoIXNpZ25hdHVyZXMuc2lnbmF0dXJlcyB8fCAhaXNUdXBsZShzaWduYXR1cmVzLnNpZ25hdHVyZXMpKSkge1xuICAgIHJldHVybiB7XG4gICAgICAuLi5wYXJzZWRQdWJTY3JpcHQsXG4gICAgICBzaWduYXR1cmVzOiBzaWduYXR1cmVzLnNpZ25hdHVyZXMsXG4gICAgfTtcbiAgfVxuICB0aHJvdyBuZXcgRXJyb3IoJ2ludmFsaWQgcHViIHNjcmlwdCcpO1xufVxuXG4vKipcbiAqIEByZXR1cm5zIHN0cmljdGx5IHBhcnNlIHRoZSBpbnB1dCBhbmQgZ2V0IHNpZ25hdHVyZSBjb3VudC5cbiAqIHVuc2lnbmVkKDApLCBoYWxmLXNpZ25lZCgxKSBvciBmdWxseS1zaWduZWQoMilcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGdldFN0cmljdFNpZ25hdHVyZUNvdW50KGlucHV0OiBUeElucHV0IHwgUHNidElucHV0KTogMCB8IDEgfCAyIHtcbiAgY29uc3QgY2FsY3VsYXRlU2lnbmF0dXJlQ291bnQgPSAoXG4gICAgc2lnbmF0dXJlczogW0J1ZmZlciB8IDAsIEJ1ZmZlciB8IDAsIEJ1ZmZlciB8IDBdIHwgW0J1ZmZlciwgQnVmZmVyXSB8IFtCdWZmZXJdIHwgdW5kZWZpbmVkXG4gICk6IDAgfCAxIHwgMiA9PiB7XG4gICAgY29uc3QgY291bnQgPSBzaWduYXR1cmVzID8gc2lnbmF0dXJlcy5maWx0ZXIoKHMpID0+ICFpc1BsYWNlaG9sZGVyU2lnbmF0dXJlKHMpKS5sZW5ndGggOiAwO1xuICAgIGlmIChjb3VudCA9PT0gMCB8fCBjb3VudCA9PT0gMSB8fCBjb3VudCA9PT0gMikge1xuICAgICAgcmV0dXJuIGNvdW50O1xuICAgIH1cbiAgICB0aHJvdyBuZXcgRXJyb3IoJ2ludmFsaWQgc2lnbmF0dXJlIGNvdW50Jyk7XG4gIH07XG5cbiAgaWYgKCdoYXNoJyBpbiBpbnB1dCkge1xuICAgIGlmIChpbnB1dC5zY3JpcHQ/Lmxlbmd0aCB8fCBpbnB1dC53aXRuZXNzPy5sZW5ndGgpIHtcbiAgICAgIGNvbnN0IHBhcnNlZElucHV0ID0gcGFyc2VTaWduYXR1cmVTY3JpcHQoaW5wdXQpO1xuICAgICAgcmV0dXJuIHBhcnNlZElucHV0LnNjcmlwdFR5cGUgPT09ICd0YXByb290S2V5UGF0aFNwZW5kJyA/IDIgOiBjYWxjdWxhdGVTaWduYXR1cmVDb3VudChwYXJzZWRJbnB1dC5zaWduYXR1cmVzKTtcbiAgICB9XG4gICAgcmV0dXJuIDA7XG4gIH0gZWxzZSB7XG4gICAgcmV0dXJuIGNhbGN1bGF0ZVNpZ25hdHVyZUNvdW50KHBhcnNlUHNidElucHV0KGlucHV0KS5zaWduYXR1cmVzKTtcbiAgfVxufVxuXG4vKipcbiAqIEByZXR1cm5zIHN0cmljdGx5IHBhcnNlIGlucHV0IGFuZCBnZXQgc2lnbmF0dXJlIGNvdW50IGZvciBhbGwgaW5wdXRzLlxuICogMD11bnNpZ25lZCwgMT1oYWxmLXNpZ25lZCBvciAyPWZ1bGx5LXNpZ25lZFxuICovXG5leHBvcnQgZnVuY3Rpb24gZ2V0U3RyaWN0U2lnbmF0dXJlQ291bnRzKFxuICB0eDogVXR4b1BzYnQgfCBVdHhvVHJhbnNhY3Rpb248bnVtYmVyIHwgYmlnaW50PiB8IFBzYnRJbnB1dFtdIHwgVHhJbnB1dFtdXG4pOiAoMCB8IDEgfCAyKVtdIHtcbiAgY29uc3QgaW5wdXRzID0gdHggaW5zdGFuY2VvZiBVdHhvUHNidCA/IHR4LmRhdGEuaW5wdXRzIDogdHggaW5zdGFuY2VvZiBVdHhvVHJhbnNhY3Rpb24gPyB0eC5pbnMgOiB0eDtcbiAgcmV0dXJuIGlucHV0cy5tYXAoKGlucHV0LCBfKSA9PiBnZXRTdHJpY3RTaWduYXR1cmVDb3VudChpbnB1dCkpO1xufVxuXG4vKipcbiAqIEByZXR1cm4gdHJ1ZSBpZmYgaW5wdXRzIGFycmF5IGlzIG9mIFBzYnRJbnB1dFR5cGUgdHlwZVxuICogKi9cbmV4cG9ydCBmdW5jdGlvbiBpc1BzYnRJbnB1dEFycmF5KGlucHV0czogUHNidElucHV0W10gfCBUeElucHV0W10pOiBpbnB1dHMgaXMgUHNidElucHV0W10ge1xuICByZXR1cm4gIWlzVHhJbnB1dEFycmF5KGlucHV0cyk7XG59XG5cbi8qKlxuICogQHJldHVybiB0cnVlIGlmZiBpbnB1dHMgYXJyYXkgaXMgb2YgVHhJbnB1dCB0eXBlXG4gKiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGlzVHhJbnB1dEFycmF5KGlucHV0czogUHNidElucHV0W10gfCBUeElucHV0W10pOiBpbnB1dHMgaXMgVHhJbnB1dFtdIHtcbiAgYXNzZXJ0KCEhaW5wdXRzLmxlbmd0aCwgJ2VtcHR5IGlucHV0cyBhcnJheScpO1xuICByZXR1cm4gJ2hhc2gnIGluIGlucHV0c1swXTtcbn1cblxuLyoqXG4gKiBAcmV0dXJucyB0cnVlIGlmZiBnaXZlbiBwc2J0L3RyYW5zYWN0aW9uL3R4LWlucHV0LWFycmF5L3BzYnQtaW5wdXQtYXJyYXkgY29udGFpbnMgYXQgbGVhc3Qgb25lIHRhcHJvb3Qga2V5IHBhdGggc3BlbmQgaW5wdXRcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGlzVHJhbnNhY3Rpb25XaXRoS2V5UGF0aFNwZW5kSW5wdXQoXG4gIGRhdGE6IFV0eG9Qc2J0IHwgVXR4b1RyYW5zYWN0aW9uPGJpZ2ludCB8IG51bWJlcj4gfCBQc2J0SW5wdXRbXSB8IFR4SW5wdXRbXVxuKTogYm9vbGVhbiB7XG4gIGNvbnN0IGlucHV0cyA9IGRhdGEgaW5zdGFuY2VvZiBVdHhvUHNidCA/IGRhdGEuZGF0YS5pbnB1dHMgOiBkYXRhIGluc3RhbmNlb2YgVXR4b1RyYW5zYWN0aW9uID8gZGF0YS5pbnMgOiBkYXRhO1xuICBpZiAoIWlucHV0cy5sZW5ndGgpIHtcbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cbiAgaWYgKGlzUHNidElucHV0QXJyYXkoaW5wdXRzKSkge1xuICAgIHJldHVybiBpbnB1dHMuc29tZSgoaW5wdXQsIF8pID0+IGdldFBzYnRJbnB1dFNjcmlwdFR5cGUoaW5wdXQpID09PSAndGFwcm9vdEtleVBhdGhTcGVuZCcpO1xuICB9XG4gIHJldHVybiBpbnB1dHMuc29tZSgoaW5wdXQsIF8pID0+IHtcbiAgICAvLyBJZiB0aGUgaW5wdXQgaXMgbm90IHNpZ25lZCwgaXQgY2Fubm90IGJlIGEgdGFwcm9vdEtleVBhdGhTcGVuZCBpbnB1dCBiZWNhdXNlIHlvdSBjYW4gb25seVxuICAgIC8vIGV4dHJhY3QgYSBmdWxseSBzaWduZWQgcHNidCBpbnRvIGEgdHJhbnNhY3Rpb24gd2l0aCB0YXByb290S2V5UGF0aFNwZW5kIGlucHV0cy5cbiAgICBpZiAoZ2V0U3RyaWN0U2lnbmF0dXJlQ291bnQoaW5wdXQpID09PSAwKSB7XG4gICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuICAgIHJldHVybiBwYXJzZVNpZ25hdHVyZVNjcmlwdChpbnB1dCkuc2NyaXB0VHlwZSA9PT0gJ3RhcHJvb3RLZXlQYXRoU3BlbmQnO1xuICB9KTtcbn1cblxuLyoqXG4gKiBTZXQgdGhlIFJvb3RXYWxsZXRLZXlzIGFzIHRoZSBnbG9iYWxYcHVicyBvbiB0aGUgcHNidFxuICpcbiAqIFdlIGRvIGFsbCB0aGUgbWF0Y2hpbmcgb2YgdGhlICh0YXApYmlwMzJEZXJpdmF0aW9ucyBtYXN0ZXJGaW5nZXJwcmludCB0byB0aGUgZmluZ2VycHJpbnQgb2YgdGhlXG4gKiBleHRlbmRlZFB1YmtleS5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGFkZFhwdWJzVG9Qc2J0KHBzYnQ6IFV0eG9Qc2J0LCByb290V2FsbGV0S2V5czogUm9vdFdhbGxldEtleXMpOiB2b2lkIHtcbiAgY29uc3Qgc2FmZVJvb3RXYWxsZXRLZXlzID0gbmV3IFJvb3RXYWxsZXRLZXlzKFxuICAgIHJvb3RXYWxsZXRLZXlzLnRyaXBsZS5tYXAoKGJpcDMyKSA9PiBiaXAzMi5uZXV0ZXJlZCgpKSBhcyBUcmlwbGU8QklQMzJJbnRlcmZhY2U+LFxuICAgIHJvb3RXYWxsZXRLZXlzLmRlcml2YXRpb25QcmVmaXhlc1xuICApO1xuICBjb25zdCB4UHVicyA9IHNhZmVSb290V2FsbGV0S2V5cy50cmlwbGUubWFwKFxuICAgIChiaXAzMik6IEdsb2JhbFhwdWIgPT4gKHtcbiAgICAgIGV4dGVuZGVkUHVia2V5OiBiczU4Y2hlY2suZGVjb2RlKGJpcDMyLnRvQmFzZTU4KCkpLFxuICAgICAgbWFzdGVyRmluZ2VycHJpbnQ6IGJpcDMyLmZpbmdlcnByaW50LFxuICAgICAgLy8gVE9ETzogQkctNzM3OTcgLSBiaXAxNzQgY3VycmVudGx5IHJlcXVpcmVzIG0gcHJlZml4IGZvciB0aGlzIHRvIGJlIGEgdmFsaWQgZ2xvYmFsWHB1YlxuICAgICAgcGF0aDogJ20nLFxuICAgIH0pXG4gICk7XG4gIHBzYnQudXBkYXRlR2xvYmFsKHsgZ2xvYmFsWHB1YjogeFB1YnMgfSk7XG59XG5cbi8qKlxuICogdmFsaWRhdGVzIHNpZ25hdHVyZXMgZm9yIGVhY2ggMiBvZiAzIGlucHV0IGFnYWluc3QgdXNlciwgYmFja3VwLCBiaXRnbyBrZXlzIGRlcml2ZWQgZnJvbSByb290V2FsbGV0S2V5cy5cbiAqIEByZXR1cm5zIGFycmF5IG9mIGlucHV0IGluZGV4IGFuZCBpdHMgW2lzIHZhbGlkIHVzZXIgc2lnIGV4aXN0LCBpcyB2YWxpZCBiYWNrdXAgc2lnIGV4aXN0LCBpcyB2YWxpZCB1c2VyIGJpdGdvIGV4aXN0XVxuICogRm9yIHAyc2hQMnBrIGlucHV0LCBbZmFsc2UsIGZhbHNlLCBmYWxzZV0gaXMgcmV0dXJuZWQgc2luY2UgaXQgaXMgbm90IGEgMiBvZiAzIHNpZyBpbnB1dC5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGdldFNpZ25hdHVyZVZhbGlkYXRpb25BcnJheVBzYnQocHNidDogVXR4b1BzYnQsIHJvb3RXYWxsZXRLZXlzOiBSb290V2FsbGV0S2V5cyk6IFNpZ25hdHVyZVZhbGlkYXRpb25bXSB7XG4gIHJldHVybiBwc2J0LmRhdGEuaW5wdXRzLm1hcCgoaW5wdXQsIGkpID0+IHtcbiAgICBjb25zdCBzaWdWYWxBcnJheUZvcklucHV0OiBUcmlwbGU8Ym9vbGVhbj4gPVxuICAgICAgZ2V0UHNidElucHV0U2NyaXB0VHlwZShpbnB1dCkgPT09ICdwMnNoUDJwaydcbiAgICAgICAgPyBbZmFsc2UsIGZhbHNlLCBmYWxzZV1cbiAgICAgICAgOiBwc2J0LmdldFNpZ25hdHVyZVZhbGlkYXRpb25BcnJheShpLCB7IHJvb3ROb2Rlczogcm9vdFdhbGxldEtleXMudHJpcGxlIH0pO1xuICAgIHJldHVybiBbaSwgc2lnVmFsQXJyYXlGb3JJbnB1dF07XG4gIH0pO1xufVxuXG4vKipcbiAqIEV4dHJhY3RzIHRoZSBoYWxmIHNpZ25lZCB0cmFuc2FjdGlvbiBmcm9tIHRoZSBwc2J0IGZvciBwMm1zIGJhc2VkIHNjcmlwdCB0eXBlcyAtIHAyc2gsIHAyd3NoLCBhbmQgcDJzaFAyd3NoLlxuICogVGhlIHB1cnBvc2UgaXMgdG8gcHJvdmlkZSBiYWNrd2FyZCBjb21wYXRpYmlsaXR5IHRvIGtleXRlcm5hbCAoS1JTKSB0aGF0IG9ubHkgc3VwcG9ydHMgbmV0d29yayB0cmFuc2FjdGlvbiBhbmQgcDJtcyBzY3JpcHQgdHlwZXMuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBleHRyYWN0UDJtc09ubHlIYWxmU2lnbmVkVHgocHNidDogVXR4b1BzYnQpOiBVdHhvVHJhbnNhY3Rpb248YmlnaW50PiB7XG4gIGFzc2VydCghIShwc2J0LmRhdGEuaW5wdXRzLmxlbmd0aCAmJiBwc2J0LmRhdGEub3V0cHV0cy5sZW5ndGgpLCAnZW1wdHkgaW5wdXRzIG9yIG91dHB1dHMnKTtcbiAgY29uc3QgdHggPSBwc2J0LmdldFVuc2lnbmVkVHgoKTtcblxuICBmdW5jdGlvbiBpc1AybXNQYXJzZWRQc2J0SW5wdXQoXG4gICAgcGFyc2VkOiBQYXJzZWRQc2J0UDJtcyB8IFBhcnNlZFBzYnRUYXByb290IHwgUGFyc2VkUHNidFAyc2hQMnBrXG4gICk6IHBhcnNlZCBpcyBQYXJzZWRQc2J0UDJtcyB7XG4gICAgcmV0dXJuIFsncDJzaCcsICdwMnNoUDJ3c2gnLCAncDJ3c2gnXS5pbmNsdWRlcyhwYXJzZWQuc2NyaXB0VHlwZSk7XG4gIH1cblxuICBwc2J0LmRhdGEuaW5wdXRzLmZvckVhY2goKGlucHV0LCBpKSA9PiB7XG4gICAgY29uc3QgcGFyc2VkID0gcGFyc2VQc2J0SW5wdXQoaW5wdXQpO1xuICAgIGFzc2VydChpc1AybXNQYXJzZWRQc2J0SW5wdXQocGFyc2VkKSwgYHVuc3VwcG9ydGVkIHNjcmlwdCB0eXBlICR7cGFyc2VkLnNjcmlwdFR5cGV9YCk7XG4gICAgYXNzZXJ0KGlucHV0LnBhcnRpYWxTaWc/Lmxlbmd0aCA9PT0gMSwgYHVuZXhwZWN0ZWQgc2lnbmF0dXJlIGNvdW50ICR7aW5wdXQucGFydGlhbFNpZz8ubGVuZ3RofWApO1xuICAgIGNvbnN0IFtwYXJ0aWFsU2lnXSA9IGlucHV0LnBhcnRpYWxTaWc7XG4gICAgYXNzZXJ0KFxuICAgICAgaW5wdXQuc2lnaGFzaFR5cGUgIT09IHVuZGVmaW5lZCAmJiBpbnB1dC5zaWdoYXNoVHlwZSA9PT0gYnNjcmlwdC5zaWduYXR1cmUuZGVjb2RlKHBhcnRpYWxTaWcuc2lnbmF0dXJlKS5oYXNoVHlwZSxcbiAgICAgICdzaWduYXR1cmUgc2lnaGFzaCBkb2VzIG5vdCBtYXRjaCBpbnB1dCBzaWdoYXNoIHR5cGUnXG4gICAgKTtcblxuICAgIC8vIHR5cGUgY2FzdGluZyBpcyB0byBhZGRyZXNzIHRoZSBpbnZhbGlkIHR5cGUgY2hlY2tpbmcgaW4gcGF5bWVudHMucDJtc1xuICAgIGNvbnN0IHNpZ25hdHVyZXMgPSBwYXJzZWQucHVibGljS2V5cy5tYXAoKHBrKSA9PlxuICAgICAgcGFydGlhbFNpZy5wdWJrZXkuZXF1YWxzKHBrKSA/IHBhcnRpYWxTaWcuc2lnbmF0dXJlIDogKG9wcy5PUF8wIGFzIHVua25vd24gYXMgQnVmZmVyKVxuICAgICk7XG5cbiAgICBjb25zdCBpc1AyU0ggPSAhIXBhcnNlZC5yZWRlZW1TY3JpcHQ7XG4gICAgY29uc3QgaXNQMldTSCA9ICEhcGFyc2VkLndpdG5lc3NTY3JpcHQ7XG5cbiAgICBjb25zdCBwYXltZW50ID0gcGF5bWVudHMucDJtcyh7IG91dHB1dDogcGFyc2VkLnB1YlNjcmlwdCwgc2lnbmF0dXJlcyB9LCB7IHZhbGlkYXRlOiBmYWxzZSwgYWxsb3dJbmNvbXBsZXRlOiB0cnVlIH0pO1xuICAgIGNvbnN0IHAyd3NoID0gaXNQMldTSCA/IHBheW1lbnRzLnAyd3NoKHsgcmVkZWVtOiBwYXltZW50IH0pIDogdW5kZWZpbmVkO1xuICAgIGNvbnN0IHAyc2ggPSBpc1AyU0ggPyBwYXltZW50cy5wMnNoKHsgcmVkZWVtOiBwMndzaCB8fCBwYXltZW50IH0pIDogdW5kZWZpbmVkO1xuXG4gICAgaWYgKHAyc2g/LmlucHV0KSB7XG4gICAgICB0eC5zZXRJbnB1dFNjcmlwdChpLCBwMnNoLmlucHV0KTtcbiAgICB9XG4gICAgaWYgKHAyd3NoPy53aXRuZXNzKSB7XG4gICAgICB0eC5zZXRXaXRuZXNzKGksIHAyd3NoLndpdG5lc3MpO1xuICAgIH1cbiAgfSk7XG5cbiAgcmV0dXJuIHR4O1xufVxuXG4vKipcbiAqIENsb25lcyB0aGUgcHNidCB3aXRob3V0IG5vbldpdG5lc3NVdHhvIGZvciBub24tc2Vnd2l0IGlucHV0cyBhbmQgd2l0bmVzc1V0eG8gaXMgYWRkZWQgaW5zdGVhZC5cbiAqIEl0IGlzIG5vdCBCSVAtMTc0IGNvbXBsaWFudCwgc28gdXNlIGl0IGNhcmVmdWxseS5cbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGNsb25lUHNidFdpdGhvdXROb25XaXRuZXNzVXR4byhwc2J0OiBVdHhvUHNidCk6IFV0eG9Qc2J0IHtcbiAgY29uc3QgbmV3UHNidCA9IGNyZWF0ZVBzYnRGcm9tSGV4KHBzYnQudG9IZXgoKSwgcHNidC5uZXR3b3JrKTtcbiAgY29uc3QgdHhJbnB1dHMgPSBwc2J0LnR4SW5wdXRzO1xuXG4gIHBzYnQuZGF0YS5pbnB1dHMuZm9yRWFjaCgoaW5wdXQsIGkpID0+IHtcbiAgICBpZiAoaW5wdXQubm9uV2l0bmVzc1V0eG8gJiYgIWlucHV0LndpdG5lc3NVdHhvKSB7XG4gICAgICBjb25zdCB0eCA9IFV0eG9UcmFuc2FjdGlvbi5mcm9tQnVmZmVyPGJpZ2ludD4oaW5wdXQubm9uV2l0bmVzc1V0eG8sIGZhbHNlLCAnYmlnaW50JywgcHNidC5uZXR3b3JrKTtcbiAgICAgIGlmICghdHhJbnB1dHNbaV0uaGFzaC5lcXVhbHModHguZ2V0SGFzaCgpKSkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYE5vbi13aXRuZXNzIFVUWE8gaGFzaCBmb3IgaW5wdXQgIyR7aX0gZG9lc24ndCBtYXRjaCB0aGUgaGFzaCBzcGVjaWZpZWQgaW4gdGhlIHByZXZvdXRgKTtcbiAgICAgIH1cbiAgICAgIG5ld1BzYnQuZGF0YS5pbnB1dHNbaV0ud2l0bmVzc1V0eG8gPSB0eC5vdXRzW3R4SW5wdXRzW2ldLmluZGV4XTtcbiAgICB9XG4gICAgZGVsZXRlIG5ld1BzYnQuZGF0YS5pbnB1dHNbaV0ubm9uV2l0bmVzc1V0eG87XG4gIH0pO1xuXG4gIHJldHVybiBuZXdQc2J0O1xufVxuXG4vKipcbiAqIERlbGV0ZXMgd2l0bmVzc1V0eG8gZm9yIG5vbi1zZWd3aXQgaW5wdXRzIHRvIG1ha2UgdGhlIFBTQlQgQklQLTE3NCBjb21wbGlhbnQuXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBkZWxldGVXaXRuZXNzVXR4b0Zvck5vblNlZ3dpdElucHV0cyhwc2J0OiBVdHhvUHNidCk6IHZvaWQge1xuICBwc2J0LmRhdGEuaW5wdXRzLmZvckVhY2goKGlucHV0LCBpKSA9PiB7XG4gICAgY29uc3Qgc2NyaXB0VHlwZSA9IGdldFBzYnRJbnB1dFNjcmlwdFR5cGUoaW5wdXQpO1xuICAgIGlmIChzY3JpcHRUeXBlID09PSAncDJzaCcgfHwgc2NyaXB0VHlwZSA9PT0gJ3Ayc2hQMnBrJykge1xuICAgICAgZGVsZXRlIGlucHV0LndpdG5lc3NVdHhvO1xuICAgIH1cbiAgfSk7XG59XG4iXX0=