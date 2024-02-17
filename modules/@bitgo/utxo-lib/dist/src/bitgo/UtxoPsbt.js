"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UtxoPsbt = void 0;
const assert = require("assert");
const bip174_1 = require("bip174");
const utils_1 = require("bip174/src/lib/utils");
const bufferutils_1 = require("bitcoinjs-lib/src/bufferutils");
const bip32_1 = require("bip32");
const bs58check = require("bs58check");
const proprietaryKeyVal_1 = require("bip174/src/lib/proprietaryKeyVal");
const __1 = require("..");
const UtxoTransaction_1 = require("./UtxoTransaction");
const Unspent_1 = require("./Unspent");
const scriptTypes_1 = require("./psbt/scriptTypes");
const fromHalfSigned_1 = require("./psbt/fromHalfSigned");
const outputScripts_1 = require("./outputScripts");
const parseInput_1 = require("./parseInput");
const Musig2_1 = require("./Musig2");
const types_1 = require("./types");
const taproot_1 = require("../taproot");
const PsbtUtil_1 = require("./PsbtUtil");
function defaultSighashTypes() {
    return [__1.Transaction.SIGHASH_DEFAULT, __1.Transaction.SIGHASH_ALL];
}
function addForkIdToSighashesIfNeeded(network, sighashTypes) {
    switch (__1.getMainnet(network)) {
        case __1.networks.bitcoincash:
        case __1.networks.bitcoinsv:
        case __1.networks.bitcoingold:
        case __1.networks.ecash:
            return [...sighashTypes, ...sighashTypes.map((s) => s | UtxoTransaction_1.UtxoTransaction.SIGHASH_FORKID)];
        default:
            return sighashTypes;
    }
}
function toSignatureParams(network, v) {
    if (Array.isArray(v))
        return toSignatureParams(network, { sighashTypes: v });
    const defaultSignatureParams = { deterministic: false, sighashTypes: defaultSighashTypes() };
    const ret = { ...defaultSignatureParams, ...v };
    ret.sighashTypes = addForkIdToSighashesIfNeeded(network, ret.sighashTypes);
    return ret;
}
/**
 * @param a
 * @param b
 * @returns true if the two public keys are equal ignoring the y coordinate.
 */
function equalPublicKeyIgnoreY(a, b) {
    return outputScripts_1.toXOnlyPublicKey(a).equals(outputScripts_1.toXOnlyPublicKey(b));
}
// TODO: upstream does `checkInputsForPartialSigs` before doing things like
// `setVersion`. Our inputs could have tapscriptsigs (or in future tapkeysigs)
// and not fail that check. Do we want to do anything about that?
class UtxoPsbt extends __1.Psbt {
    constructor() {
        super(...arguments);
        this.nonceStore = new Musig2_1.Musig2NonceStore();
    }
    static transactionFromBuffer(buffer, network) {
        return UtxoTransaction_1.UtxoTransaction.fromBuffer(buffer, false, 'bigint', network);
    }
    static createPsbt(opts, data) {
        return new UtxoPsbt(opts, data || new bip174_1.Psbt(new __1.PsbtTransaction({ tx: new UtxoTransaction_1.UtxoTransaction(opts.network) })));
    }
    static fromBuffer(buffer, opts) {
        const transactionFromBuffer = (buffer) => {
            const tx = this.transactionFromBuffer(buffer, opts.network);
            return new __1.PsbtTransaction({ tx });
        };
        const psbtBase = bip174_1.Psbt.fromBuffer(buffer, transactionFromBuffer, {
            bip32PathsAbsolute: opts.bip32PathsAbsolute,
        });
        const psbt = this.createPsbt(opts, psbtBase);
        // Upstream checks for duplicate inputs here, but it seems to be of dubious value.
        return psbt;
    }
    static fromHex(data, opts) {
        return this.fromBuffer(Buffer.from(data, 'hex'), opts);
    }
    /**
     * @param parent - Parent key. Matched with `bip32Derivations` using `fingerprint` property.
     * @param bip32Derivations - possible derivations for input or output
     * @param ignoreY - when true, ignore the y coordinate when matching public keys
     * @return derived bip32 node if matching derivation is found, undefined if none is found
     * @throws Error if more than one match is found
     */
    static deriveKeyPair(parent, bip32Derivations, { ignoreY }) {
        const matchingDerivations = bip32Derivations.filter((bipDv) => {
            return bipDv.masterFingerprint.equals(parent.fingerprint);
        });
        if (!matchingDerivations.length) {
            // No fingerprint match
            return undefined;
        }
        if (matchingDerivations.length !== 1) {
            throw new Error(`more than one matching derivation for fingerprint ${parent.fingerprint.toString('hex')}: ${matchingDerivations.length}`);
        }
        const [derivation] = matchingDerivations;
        const node = parent.derivePath(derivation.path);
        if (!node.publicKey.equals(derivation.pubkey)) {
            if (!ignoreY || !equalPublicKeyIgnoreY(node.publicKey, derivation.pubkey)) {
                throw new Error('pubkey did not match bip32Derivation');
            }
        }
        return node;
    }
    static deriveKeyPairForInput(bip32, input) {
        var _a, _b, _c, _d;
        return ((_a = input.tapBip32Derivation) === null || _a === void 0 ? void 0 : _a.length)
            ? (_b = UtxoPsbt.deriveKeyPair(bip32, input.tapBip32Derivation, { ignoreY: true })) === null || _b === void 0 ? void 0 : _b.publicKey
            : ((_c = input.bip32Derivation) === null || _c === void 0 ? void 0 : _c.length)
                ? (_d = UtxoPsbt.deriveKeyPair(bip32, input.bip32Derivation, { ignoreY: false })) === null || _d === void 0 ? void 0 : _d.publicKey
                : bip32 === null || bip32 === void 0 ? void 0 : bip32.publicKey;
    }
    get network() {
        return this.tx.network;
    }
    toHex() {
        return this.toBuffer().toString('hex');
    }
    /**
     * It is expensive to attempt to compute every output address using psbt.txOutputs[outputIndex]
     * to then just get the script. Here, we are doing the same thing as what txOutputs() does in
     * bitcoinjs-lib, but without iterating over each output.
     * @param outputIndex
     * @returns output script at the given index
     */
    getOutputScript(outputIndex) {
        return this.__CACHE.__TX.outs[outputIndex].script;
    }
    getNonWitnessPreviousTxids() {
        const txInputs = this.txInputs; // These are somewhat costly to extract
        const txidSet = new Set();
        this.data.inputs.forEach((input, index) => {
            if (!input.witnessUtxo) {
                throw new Error('Must have witness UTXO for all inputs');
            }
            if (!scriptTypes_1.isSegwit(input.witnessUtxo.script, input.redeemScript)) {
                txidSet.add(Unspent_1.getOutputIdForInput(txInputs[index]).txid);
            }
        });
        return [...txidSet];
    }
    addNonWitnessUtxos(txBufs) {
        const txInputs = this.txInputs; // These are somewhat costly to extract
        this.data.inputs.forEach((input, index) => {
            if (!input.witnessUtxo) {
                throw new Error('Must have witness UTXO for all inputs');
            }
            if (!scriptTypes_1.isSegwit(input.witnessUtxo.script, input.redeemScript)) {
                const { txid } = Unspent_1.getOutputIdForInput(txInputs[index]);
                if (txBufs[txid] === undefined) {
                    throw new Error('Not all required previous transactions provided');
                }
                this.updateInput(index, { nonWitnessUtxo: txBufs[txid] });
            }
        });
        return this;
    }
    static fromTransaction(transaction, prevOutputs) {
        if (prevOutputs.length !== transaction.ins.length) {
            throw new Error(`Transaction has ${transaction.ins.length} inputs, but ${prevOutputs.length} previous outputs provided`);
        }
        const clonedTransaction = transaction.clone();
        const updates = fromHalfSigned_1.unsign(clonedTransaction, prevOutputs);
        const psbtBase = new bip174_1.Psbt(new __1.PsbtTransaction({ tx: clonedTransaction }));
        clonedTransaction.ins.forEach(() => psbtBase.inputs.push({ unknownKeyVals: [] }));
        clonedTransaction.outs.forEach(() => psbtBase.outputs.push({ unknownKeyVals: [] }));
        const psbt = this.createPsbt({ network: transaction.network }, psbtBase);
        updates.forEach((update, index) => {
            psbt.updateInput(index, update);
            psbt.updateInput(index, { witnessUtxo: { script: prevOutputs[index].script, value: prevOutputs[index].value } });
        });
        return psbt;
    }
    getUnsignedTx() {
        return this.tx.clone();
    }
    static newTransaction(network) {
        return new UtxoTransaction_1.UtxoTransaction(network);
    }
    get tx() {
        return this.data.globalMap.unsignedTx.tx;
    }
    checkForSignatures(propName) {
        this.data.inputs.forEach((input) => {
            var _a, _b;
            if (((_a = input.tapScriptSig) === null || _a === void 0 ? void 0 : _a.length) || input.tapKeySig || ((_b = input.partialSig) === null || _b === void 0 ? void 0 : _b.length)) {
                throw new Error(`Cannot modify ${propName !== null && propName !== void 0 ? propName : 'transaction'} - signatures exist.`);
            }
        });
    }
    /**
     * @returns true if the input at inputIndex is a taproot key path.
     * Checks for presence of minimum required key path input fields and absence of any script path only input fields.
     */
    isTaprootKeyPathInput(inputIndex) {
        var _a, _b, _c;
        const input = utils_1.checkForInput(this.data.inputs, inputIndex);
        return (!!input.tapInternalKey &&
            !!input.tapMerkleRoot &&
            !(((_a = input.tapLeafScript) === null || _a === void 0 ? void 0 : _a.length) ||
                ((_b = input.tapScriptSig) === null || _b === void 0 ? void 0 : _b.length) ||
                ((_c = input.tapBip32Derivation) === null || _c === void 0 ? void 0 : _c.some((v) => v.leafHashes.length))));
    }
    /**
     * @returns true if the input at inputIndex is a taproot script path.
     * Checks for presence of minimum required script path input fields and absence of any key path only input fields.
     */
    isTaprootScriptPathInput(inputIndex) {
        var _a;
        const input = utils_1.checkForInput(this.data.inputs, inputIndex);
        return (!!((_a = input.tapLeafScript) === null || _a === void 0 ? void 0 : _a.length) &&
            !(this.getProprietaryKeyVals(inputIndex, {
                identifier: PsbtUtil_1.PSBT_PROPRIETARY_IDENTIFIER,
                subtype: PsbtUtil_1.ProprietaryKeySubtype.MUSIG2_PARTICIPANT_PUB_KEYS,
            }).length ||
                this.getProprietaryKeyVals(inputIndex, {
                    identifier: PsbtUtil_1.PSBT_PROPRIETARY_IDENTIFIER,
                    subtype: PsbtUtil_1.ProprietaryKeySubtype.MUSIG2_PUB_NONCE,
                }).length ||
                this.getProprietaryKeyVals(inputIndex, {
                    identifier: PsbtUtil_1.PSBT_PROPRIETARY_IDENTIFIER,
                    subtype: PsbtUtil_1.ProprietaryKeySubtype.MUSIG2_PARTIAL_SIG,
                }).length));
    }
    /**
     * @returns true if the input at inputIndex is a taproot
     */
    isTaprootInput(inputIndex) {
        var _a, _b, _c;
        const input = utils_1.checkForInput(this.data.inputs, inputIndex);
        const isP2TR = (script) => {
            try {
                taproot_1.getTaprootOutputKey(script);
                return true;
            }
            catch (e) {
                return false;
            }
        };
        return !!(input.tapInternalKey ||
            input.tapMerkleRoot ||
            ((_a = input.tapLeafScript) === null || _a === void 0 ? void 0 : _a.length) ||
            ((_b = input.tapBip32Derivation) === null || _b === void 0 ? void 0 : _b.length) ||
            ((_c = input.tapScriptSig) === null || _c === void 0 ? void 0 : _c.length) ||
            this.getProprietaryKeyVals(inputIndex, {
                identifier: PsbtUtil_1.PSBT_PROPRIETARY_IDENTIFIER,
                subtype: PsbtUtil_1.ProprietaryKeySubtype.MUSIG2_PARTICIPANT_PUB_KEYS,
            }).length ||
            this.getProprietaryKeyVals(inputIndex, {
                identifier: PsbtUtil_1.PSBT_PROPRIETARY_IDENTIFIER,
                subtype: PsbtUtil_1.ProprietaryKeySubtype.MUSIG2_PUB_NONCE,
            }).length ||
            this.getProprietaryKeyVals(inputIndex, {
                identifier: PsbtUtil_1.PSBT_PROPRIETARY_IDENTIFIER,
                subtype: PsbtUtil_1.ProprietaryKeySubtype.MUSIG2_PARTIAL_SIG,
            }).length ||
            (input.witnessUtxo && isP2TR(input.witnessUtxo.script)));
    }
    isMultisigTaprootScript(script) {
        try {
            parseInput_1.parsePubScript2Of3(script, 'taprootScriptPathSpend');
            return true;
        }
        catch (e) {
            return false;
        }
    }
    /**
     * Mostly copied from bitcoinjs-lib/ts_src/psbt.ts
     */
    finalizeAllInputs() {
        utils_1.checkForInput(this.data.inputs, 0); // making sure we have at least one
        this.data.inputs.map((input, idx) => {
            var _a;
            if ((_a = input.tapLeafScript) === null || _a === void 0 ? void 0 : _a.length) {
                return this.isMultisigTaprootScript(input.tapLeafScript[0].script)
                    ? this.finalizeTaprootInput(idx)
                    : this.finalizeTapInputWithSingleLeafScriptAndSignature(idx);
            }
            else if (this.isTaprootKeyPathInput(idx)) {
                return this.finalizeTaprootMusig2Input(idx);
            }
            return this.finalizeInput(idx);
        });
        return this;
    }
    finalizeTaprootInput(inputIndex) {
        var _a, _b;
        const sanitizeSignature = (sig) => {
            const sighashType = sig.length === 64 ? __1.Transaction.SIGHASH_DEFAULT : sig.readUInt8(sig.length - 1);
            const inputSighashType = input.sighashType === undefined ? __1.Transaction.SIGHASH_DEFAULT : input.sighashType;
            assert(sighashType === inputSighashType, 'signature sighash does not match input sighash type');
            // TODO BTC-663 This should be fixed in platform. This is just a workaround fix.
            return sighashType === __1.Transaction.SIGHASH_DEFAULT && sig.length === 65 ? sig.slice(0, 64) : sig;
        };
        const input = utils_1.checkForInput(this.data.inputs, inputIndex);
        // witness = control-block script first-sig second-sig
        if (((_a = input.tapLeafScript) === null || _a === void 0 ? void 0 : _a.length) !== 1) {
            throw new Error('Only one leaf script supported for finalizing');
        }
        const { controlBlock, script } = input.tapLeafScript[0];
        const witness = [script, controlBlock];
        const [pubkey1, pubkey2] = parseInput_1.parsePubScript2Of3(script, 'taprootScriptPathSpend').publicKeys;
        for (const pk of [pubkey1, pubkey2]) {
            const sig = (_b = input.tapScriptSig) === null || _b === void 0 ? void 0 : _b.find(({ pubkey }) => equalPublicKeyIgnoreY(pk, pubkey));
            if (!sig) {
                throw new Error('Could not find signatures in Script Sig.');
            }
            witness.unshift(sanitizeSignature(sig.signature));
        }
        const witnessLength = witness.reduce((s, b) => s + b.length + bufferutils_1.varuint.encodingLength(b.length), 1);
        const bufferWriter = bufferutils_1.BufferWriter.withCapacity(witnessLength);
        bufferWriter.writeVector(witness);
        const finalScriptWitness = bufferWriter.end();
        this.data.updateInput(inputIndex, { finalScriptWitness });
        this.data.clearFinalizedInput(inputIndex);
        return this;
    }
    /**
     * Finalizes a taproot musig2 input by aggregating all partial sigs.
     * IMPORTANT: Always call validate* function before finalizing.
     */
    finalizeTaprootMusig2Input(inputIndex) {
        const input = utils_1.checkForInput(this.data.inputs, inputIndex);
        const partialSigs = Musig2_1.parsePsbtMusig2PartialSigs(input);
        if ((partialSigs === null || partialSigs === void 0 ? void 0 : partialSigs.length) !== 2) {
            throw new Error(`invalid number of partial signatures ${partialSigs ? partialSigs.length : 0} to finalize`);
        }
        const { partialSigs: pSigs, sigHashType } = Musig2_1.getSigHashTypeFromSigs(partialSigs);
        const { sessionKey } = this.getMusig2SessionKey(inputIndex, sigHashType);
        const aggSig = Musig2_1.musig2AggregateSigs(pSigs.map((pSig) => pSig.partialSig), sessionKey);
        const sig = sigHashType === __1.Transaction.SIGHASH_DEFAULT ? aggSig : Buffer.concat([aggSig, Buffer.of(sigHashType)]);
        // single signature with 64/65 bytes size is script witness for key path spend
        const bufferWriter = bufferutils_1.BufferWriter.withCapacity(1 + bufferutils_1.varuint.encodingLength(sig.length) + sig.length);
        bufferWriter.writeVector([sig]);
        const finalScriptWitness = bufferWriter.end();
        this.data.updateInput(inputIndex, { finalScriptWitness });
        this.data.clearFinalizedInput(inputIndex);
        // deleting only BitGo proprietary key values.
        this.deleteProprietaryKeyVals(inputIndex, { identifier: PsbtUtil_1.PSBT_PROPRIETARY_IDENTIFIER });
        return this;
    }
    finalizeTapInputWithSingleLeafScriptAndSignature(inputIndex) {
        var _a, _b;
        const input = utils_1.checkForInput(this.data.inputs, inputIndex);
        if (((_a = input.tapLeafScript) === null || _a === void 0 ? void 0 : _a.length) !== 1) {
            throw new Error('Only one leaf script supported for finalizing');
        }
        if (((_b = input.tapScriptSig) === null || _b === void 0 ? void 0 : _b.length) !== 1) {
            throw new Error('Could not find signatures in Script Sig.');
        }
        const { controlBlock, script } = input.tapLeafScript[0];
        const witness = [input.tapScriptSig[0].signature, script, controlBlock];
        const witnessLength = witness.reduce((s, b) => s + b.length + bufferutils_1.varuint.encodingLength(b.length), 1);
        const bufferWriter = bufferutils_1.BufferWriter.withCapacity(witnessLength);
        bufferWriter.writeVector(witness);
        const finalScriptWitness = bufferWriter.end();
        this.data.updateInput(inputIndex, { finalScriptWitness });
        this.data.clearFinalizedInput(inputIndex);
        return this;
    }
    /**
     * Mostly copied from bitcoinjs-lib/ts_src/psbt.ts
     *
     * Unlike the function it overrides, this does not take a validator. In BitGo
     * context, we know how we want to validate so we just hard code the right
     * validator.
     */
    validateSignaturesOfAllInputs() {
        utils_1.checkForInput(this.data.inputs, 0); // making sure we have at least one
        const results = this.data.inputs.map((input, idx) => {
            return this.validateSignaturesOfInputCommon(idx);
        });
        return results.reduce((final, res) => res && final, true);
    }
    /**
     * @returns true iff any matching valid signature is found for a derived pub key from given HD key pair.
     */
    validateSignaturesOfInputHD(inputIndex, hdKeyPair) {
        const input = utils_1.checkForInput(this.data.inputs, inputIndex);
        const pubKey = UtxoPsbt.deriveKeyPairForInput(hdKeyPair, input);
        if (!pubKey) {
            throw new Error('can not derive from HD key pair');
        }
        return this.validateSignaturesOfInputCommon(inputIndex, pubKey);
    }
    /**
     * @returns true iff any valid signature(s) are found from bip32 data of PSBT or for given pub key.
     */
    validateSignaturesOfInputCommon(inputIndex, pubkey) {
        try {
            if (this.isTaprootScriptPathInput(inputIndex)) {
                return this.validateTaprootSignaturesOfInput(inputIndex, pubkey);
            }
            else if (this.isTaprootKeyPathInput(inputIndex)) {
                return this.validateTaprootMusig2SignaturesOfInput(inputIndex, pubkey);
            }
            return this.validateSignaturesOfInput(inputIndex, (p, m, s) => __1.ecc.verify(m, p, s, true), pubkey);
        }
        catch (err) {
            // Not an elegant solution. Might need upstream changes like custom error types.
            if (err.message === 'No signatures for this pubkey') {
                return false;
            }
            throw err;
        }
    }
    getMusig2SessionKey(inputIndex, sigHashType) {
        const input = utils_1.checkForInput(this.data.inputs, inputIndex);
        if (!input.tapInternalKey || !input.tapMerkleRoot) {
            throw new Error('both tapInternalKey and tapMerkleRoot are required');
        }
        const participants = this.getMusig2Participants(inputIndex, input.tapInternalKey, input.tapMerkleRoot);
        const nonces = this.getMusig2Nonces(inputIndex, participants);
        const { hash } = this.getTaprootHashForSig(inputIndex, [sigHashType]);
        const sessionKey = Musig2_1.createMusig2SigningSession({
            pubNonces: [nonces[0].pubNonce, nonces[1].pubNonce],
            pubKeys: participants.participantPubKeys,
            txHash: hash,
            internalPubKey: input.tapInternalKey,
            tapTreeRoot: input.tapMerkleRoot,
        });
        return { participants, nonces, hash, sessionKey };
    }
    /**
     * @returns true for following cases.
     * If valid musig2 partial signatures exists for both 2 keys, it will also verify aggregated sig
     * for aggregated tweaked key (output key), otherwise only verifies partial sig.
     * If pubkey is passed in input, it will check sig only for that pubkey,
     * if no sig exits for such key, throws error.
     * For invalid state of input data, it will throw errors.
     */
    validateTaprootMusig2SignaturesOfInput(inputIndex, pubkey) {
        const input = utils_1.checkForInput(this.data.inputs, inputIndex);
        const partialSigs = Musig2_1.parsePsbtMusig2PartialSigs(input);
        if (!partialSigs) {
            throw new Error(`No signatures to validate`);
        }
        let myPartialSigs = partialSigs;
        if (pubkey) {
            myPartialSigs = partialSigs.filter((kv) => equalPublicKeyIgnoreY(kv.participantPubKey, pubkey));
            if ((myPartialSigs === null || myPartialSigs === void 0 ? void 0 : myPartialSigs.length) < 1) {
                throw new Error('No signatures for this pubkey');
            }
        }
        const { partialSigs: mySigs, sigHashType } = Musig2_1.getSigHashTypeFromSigs(myPartialSigs);
        const { participants, nonces, hash, sessionKey } = this.getMusig2SessionKey(inputIndex, sigHashType);
        const results = mySigs.map((mySig) => {
            const myNonce = nonces.find((kv) => equalPublicKeyIgnoreY(kv.participantPubKey, mySig.participantPubKey));
            if (!myNonce) {
                throw new Error('Found no pub nonce for pubkey');
            }
            return Musig2_1.musig2PartialSigVerify(mySig.partialSig, mySig.participantPubKey, myNonce.pubNonce, sessionKey);
        });
        // For valid single sig or 1 or 2 failure sigs, no need to validate aggregated sig. So skip.
        const result = results.every((res) => res);
        if (!result || mySigs.length < 2) {
            return result;
        }
        const aggSig = Musig2_1.musig2AggregateSigs(mySigs.map((mySig) => mySig.partialSig), sessionKey);
        return __1.ecc.verifySchnorr(hash, participants.tapOutputKey, aggSig);
    }
    validateTaprootSignaturesOfInput(inputIndex, pubkey) {
        var _a, _b;
        const input = this.data.inputs[inputIndex];
        const tapSigs = (input || {}).tapScriptSig;
        if (!input || !tapSigs || tapSigs.length < 1) {
            throw new Error('No signatures to validate');
        }
        let mySigs;
        if (pubkey) {
            mySigs = tapSigs.filter((sig) => equalPublicKeyIgnoreY(sig.pubkey, pubkey));
            if (mySigs.length < 1) {
                throw new Error('No signatures for this pubkey');
            }
        }
        else {
            mySigs = tapSigs;
        }
        const results = [];
        assert(((_a = input.tapLeafScript) === null || _a === void 0 ? void 0 : _a.length) === 1, `single tapLeafScript is expected. Got ${(_b = input.tapLeafScript) === null || _b === void 0 ? void 0 : _b.length}`);
        const [tapLeafScript] = input.tapLeafScript;
        const pubKeys = this.isMultisigTaprootScript(tapLeafScript.script)
            ? parseInput_1.parsePubScript2Of3(tapLeafScript.script, 'taprootScriptPathSpend').publicKeys
            : undefined;
        for (const pSig of mySigs) {
            const { signature, leafHash, pubkey } = pSig;
            if (pubKeys) {
                assert(pubKeys.find((pk) => pubkey.equals(pk)), 'public key not found in tap leaf script');
            }
            let sigHashType;
            let sig;
            if (signature.length === 65) {
                sigHashType = signature[64];
                sig = signature.slice(0, 64);
            }
            else {
                sigHashType = __1.Transaction.SIGHASH_DEFAULT;
                sig = signature;
            }
            const { hash } = this.getTaprootHashForSig(inputIndex, [sigHashType], leafHash);
            results.push(__1.ecc.verifySchnorr(hash, pubkey, sig));
        }
        return results.every((res) => res);
    }
    /**
     * @param inputIndex
     * @param rootNodes optional input root bip32 nodes to verify with. If it is not provided, globalXpub will be used.
     * @return array of boolean values. True when corresponding index in `publicKeys` has signed the transaction.
     * If no signature in the tx or no public key matching signature, the validation is considered as false.
     */
    getSignatureValidationArray(inputIndex, { rootNodes } = {}) {
        var _a, _b;
        if (!rootNodes && (!((_a = this.data.globalMap.globalXpub) === null || _a === void 0 ? void 0 : _a.length) || !types_1.isTriple(this.data.globalMap.globalXpub))) {
            throw new Error('Cannot get signature validation array without 3 global xpubs');
        }
        const bip32s = rootNodes
            ? rootNodes
            : (_b = this.data.globalMap.globalXpub) === null || _b === void 0 ? void 0 : _b.map((xpub) => bip32_1.BIP32Factory(__1.ecc).fromBase58(bs58check.encode(xpub.extendedPubkey)));
        if (!bip32s) {
            throw new Error('either globalMap or rootNodes is required');
        }
        const input = utils_1.checkForInput(this.data.inputs, inputIndex);
        if (!PsbtUtil_1.getPsbtInputSignatureCount(input)) {
            return [false, false, false];
        }
        return bip32s.map((bip32) => {
            const pubKey = UtxoPsbt.deriveKeyPairForInput(bip32, input);
            if (!pubKey) {
                return false;
            }
            try {
                return this.validateSignaturesOfInputCommon(inputIndex, pubKey);
            }
            catch (err) {
                // Not an elegant solution. Might need upstream changes like custom error types.
                if (err.message === 'No signatures for this pubkey') {
                    return false;
                }
                throw err;
            }
        });
    }
    /**
     * Mostly copied from bitcoinjs-lib/ts_src/psbt.ts
     */
    signAllInputsHD(hdKeyPair, params) {
        if (!hdKeyPair || !hdKeyPair.publicKey || !hdKeyPair.fingerprint) {
            throw new Error('Need HDSigner to sign input');
        }
        const { sighashTypes, deterministic } = toSignatureParams(this.network, params);
        const results = [];
        for (let i = 0; i < this.data.inputs.length; i++) {
            try {
                this.signInputHD(i, hdKeyPair, { sighashTypes, deterministic });
                results.push(true);
            }
            catch (err) {
                results.push(false);
            }
        }
        if (results.every((v) => !v)) {
            throw new Error('No inputs were signed');
        }
        return this;
    }
    /**
     * Mostly copied from bitcoinjs-lib/ts_src/psbt.ts:signInputHD
     */
    signTaprootInputHD(inputIndex, hdKeyPair, { sighashTypes = [__1.Transaction.SIGHASH_DEFAULT, __1.Transaction.SIGHASH_ALL], deterministic = false } = {}) {
        var _a, _b;
        if (!this.isTaprootInput(inputIndex)) {
            throw new Error('not a taproot input');
        }
        if (!hdKeyPair || !hdKeyPair.publicKey || !hdKeyPair.fingerprint) {
            throw new Error('Need HDSigner to sign input');
        }
        const input = utils_1.checkForInput(this.data.inputs, inputIndex);
        if (!input.tapBip32Derivation || input.tapBip32Derivation.length === 0) {
            throw new Error('Need tapBip32Derivation to sign Taproot with HD');
        }
        const myDerivations = input.tapBip32Derivation
            .map((bipDv) => {
            if (bipDv.masterFingerprint.equals(hdKeyPair.fingerprint)) {
                return bipDv;
            }
        })
            .filter((v) => !!v);
        if (myDerivations.length === 0) {
            throw new Error('Need one tapBip32Derivation masterFingerprint to match the HDSigner fingerprint');
        }
        function getDerivedNode(bipDv) {
            const node = hdKeyPair.derivePath(bipDv.path);
            if (!equalPublicKeyIgnoreY(bipDv.pubkey, node.publicKey)) {
                throw new Error('pubkey did not match tapBip32Derivation');
            }
            return node;
        }
        if ((_a = input.tapLeafScript) === null || _a === void 0 ? void 0 : _a.length) {
            const signers = myDerivations.map((bipDv) => {
                const signer = getDerivedNode(bipDv);
                if (!('signSchnorr' in signer)) {
                    throw new Error('signSchnorr function is required to sign p2tr');
                }
                return { signer, leafHashes: bipDv.leafHashes };
            });
            signers.forEach(({ signer, leafHashes }) => this.signTaprootInput(inputIndex, signer, leafHashes, sighashTypes));
        }
        else if ((_b = input.tapInternalKey) === null || _b === void 0 ? void 0 : _b.length) {
            const signers = myDerivations.map((bipDv) => {
                const signer = getDerivedNode(bipDv);
                if (!('privateKey' in signer) || !signer.privateKey) {
                    throw new Error('privateKey is required to sign p2tr musig2');
                }
                return signer;
            });
            signers.forEach((signer) => this.signTaprootMusig2Input(inputIndex, signer, { sighashTypes, deterministic }));
        }
        return this;
    }
    signInput(inputIndex, keyPair, sighashTypes) {
        const { sighashTypes: sighashForNetwork } = toSignatureParams(this.network, sighashTypes);
        return super.signInput(inputIndex, keyPair, sighashForNetwork);
    }
    signInputHD(inputIndex, hdKeyPair, params) {
        const { sighashTypes, deterministic } = toSignatureParams(this.network, params);
        if (this.isTaprootInput(inputIndex)) {
            return this.signTaprootInputHD(inputIndex, hdKeyPair, { sighashTypes, deterministic });
        }
        else {
            return super.signInputHD(inputIndex, hdKeyPair, sighashTypes);
        }
    }
    getMusig2Participants(inputIndex, tapInternalKey, tapMerkleRoot) {
        const participantsKeyValData = Musig2_1.parsePsbtMusig2Participants(this.data.inputs[inputIndex]);
        if (!participantsKeyValData) {
            throw new Error(`Found 0 matching participant key value instead of 1`);
        }
        Musig2_1.assertPsbtMusig2Participants(participantsKeyValData, tapInternalKey, tapMerkleRoot);
        return participantsKeyValData;
    }
    getMusig2Nonces(inputIndex, participantsKeyValData) {
        const noncesKeyValsData = Musig2_1.parsePsbtMusig2Nonces(this.data.inputs[inputIndex]);
        if (!noncesKeyValsData || !types_1.isTuple(noncesKeyValsData)) {
            throw new Error(`Found ${(noncesKeyValsData === null || noncesKeyValsData === void 0 ? void 0 : noncesKeyValsData.length) ? noncesKeyValsData.length : 0} matching nonce key value instead of 2`);
        }
        Musig2_1.assertPsbtMusig2Nonces(noncesKeyValsData, participantsKeyValData);
        return noncesKeyValsData;
    }
    /**
     * Signs p2tr musig2 key path input with 2 aggregated keys.
     *
     * Note: Only can sign deterministically as the cosigner
     * @param inputIndex
     * @param signer - XY public key and private key are required
     * @param sighashTypes
     * @param deterministic If true, sign the musig input deterministically
     */
    signTaprootMusig2Input(inputIndex, signer, { sighashTypes = [__1.Transaction.SIGHASH_DEFAULT, __1.Transaction.SIGHASH_ALL], deterministic = false } = {}) {
        if (!this.isTaprootKeyPathInput(inputIndex)) {
            throw new Error('not a taproot musig2 input');
        }
        const input = this.data.inputs[inputIndex];
        if (!input.tapInternalKey || !input.tapMerkleRoot) {
            throw new Error('missing required input data');
        }
        // Retrieve and check that we have two participant nonces
        const participants = this.getMusig2Participants(inputIndex, input.tapInternalKey, input.tapMerkleRoot);
        const { tapOutputKey, participantPubKeys } = participants;
        const signerPubKey = participantPubKeys.find((pubKey) => equalPublicKeyIgnoreY(pubKey, signer.publicKey));
        if (!signerPubKey) {
            throw new Error('signer pub key should match one of participant pub keys');
        }
        const nonces = this.getMusig2Nonces(inputIndex, participants);
        const { hash, sighashType } = this.getTaprootHashForSig(inputIndex, sighashTypes);
        let partialSig;
        if (deterministic) {
            if (!equalPublicKeyIgnoreY(signerPubKey, participantPubKeys[1])) {
                throw new Error('can only add a deterministic signature on the cosigner');
            }
            const firstSignerNonce = nonces.find((n) => equalPublicKeyIgnoreY(n.participantPubKey, participantPubKeys[0]));
            if (!firstSignerNonce) {
                throw new Error('could not find the user nonce');
            }
            partialSig = Musig2_1.musig2DeterministicSign({
                privateKey: signer.privateKey,
                otherNonce: firstSignerNonce.pubNonce,
                publicKeys: participantPubKeys,
                internalPubKey: input.tapInternalKey,
                tapTreeRoot: input.tapMerkleRoot,
                hash,
            }).sig;
        }
        else {
            const sessionKey = Musig2_1.createMusig2SigningSession({
                pubNonces: [nonces[0].pubNonce, nonces[1].pubNonce],
                pubKeys: participantPubKeys,
                txHash: hash,
                internalPubKey: input.tapInternalKey,
                tapTreeRoot: input.tapMerkleRoot,
            });
            const signerNonce = nonces.find((kv) => equalPublicKeyIgnoreY(kv.participantPubKey, signerPubKey));
            if (!signerNonce) {
                throw new Error('pubNonce is missing. retry signing process');
            }
            partialSig = Musig2_1.musig2PartialSign(signer.privateKey, signerNonce.pubNonce, sessionKey, this.nonceStore);
        }
        if (sighashType !== __1.Transaction.SIGHASH_DEFAULT) {
            partialSig = Buffer.concat([partialSig, Buffer.of(sighashType)]);
        }
        const sig = Musig2_1.encodePsbtMusig2PartialSig({
            participantPubKey: signerPubKey,
            tapOutputKey,
            partialSig: partialSig,
        });
        this.addProprietaryKeyValToInput(inputIndex, sig);
        return this;
    }
    signTaprootInput(inputIndex, signer, leafHashes, sighashTypes = [__1.Transaction.SIGHASH_DEFAULT, __1.Transaction.SIGHASH_ALL]) {
        var _a;
        const input = utils_1.checkForInput(this.data.inputs, inputIndex);
        // Figure out if this is script path or not, if not, tweak the private key
        if (!((_a = input.tapLeafScript) === null || _a === void 0 ? void 0 : _a.length)) {
            throw new Error('tapLeafScript is required for p2tr script path');
        }
        const pubkey = outputScripts_1.toXOnlyPublicKey(signer.publicKey);
        if (input.tapLeafScript.length !== 1) {
            throw new Error('Only one leaf script supported for signing');
        }
        const [tapLeafScript] = input.tapLeafScript;
        if (this.isMultisigTaprootScript(tapLeafScript.script)) {
            const pubKeys = parseInput_1.parsePubScript2Of3(tapLeafScript.script, 'taprootScriptPathSpend').publicKeys;
            assert(pubKeys.find((pk) => pubkey.equals(pk)), 'public key not found in tap leaf script');
        }
        const parsedControlBlock = __1.taproot.parseControlBlock(__1.ecc, tapLeafScript.controlBlock);
        const { leafVersion } = parsedControlBlock;
        if (leafVersion !== tapLeafScript.leafVersion) {
            throw new Error('Tap script leaf version mismatch with control block');
        }
        const leafHash = __1.taproot.getTapleafHash(__1.ecc, parsedControlBlock, tapLeafScript.script);
        if (!leafHashes.find((l) => l.equals(leafHash))) {
            throw new Error(`Signer cannot sign for leaf hash ${leafHash.toString('hex')}`);
        }
        const { hash, sighashType } = this.getTaprootHashForSig(inputIndex, sighashTypes, leafHash);
        let signature = signer.signSchnorr(hash);
        if (sighashType !== __1.Transaction.SIGHASH_DEFAULT) {
            signature = Buffer.concat([signature, Buffer.of(sighashType)]);
        }
        this.data.updateInput(inputIndex, {
            tapScriptSig: [
                {
                    pubkey,
                    signature,
                    leafHash,
                },
            ],
        });
        return this;
    }
    getTaprootOutputScript(inputIndex) {
        var _a;
        const input = utils_1.checkForInput(this.data.inputs, inputIndex);
        if ((_a = input.tapLeafScript) === null || _a === void 0 ? void 0 : _a.length) {
            return __1.taproot.createTaprootOutputScript({
                controlBlock: input.tapLeafScript[0].controlBlock,
                leafScript: input.tapLeafScript[0].script,
            });
        }
        else if (input.tapInternalKey && input.tapMerkleRoot) {
            return __1.taproot.createTaprootOutputScript({
                internalPubKey: input.tapInternalKey,
                taptreeRoot: input.tapMerkleRoot,
            });
        }
        throw new Error('not a taproot input');
    }
    getTaprootHashForSig(inputIndex, sighashTypes, leafHash) {
        if (!this.isTaprootInput(inputIndex)) {
            throw new Error('not a taproot input');
        }
        const sighashType = this.data.inputs[inputIndex].sighashType || __1.Transaction.SIGHASH_DEFAULT;
        if (sighashTypes && sighashTypes.indexOf(sighashType) < 0) {
            throw new Error(`Sighash type is not allowed. Retry the sign method passing the ` +
                `sighashTypes array of whitelisted types. Sighash type: ${sighashType}`);
        }
        const txInputs = this.txInputs; // These are somewhat costly to extract
        const prevoutScripts = [];
        const prevoutValues = [];
        this.data.inputs.forEach((input, i) => {
            let prevout;
            if (input.nonWitnessUtxo) {
                // TODO: This could be costly, either cache it here, or find a way to share with super
                const nonWitnessUtxoTx = this.constructor.transactionFromBuffer(input.nonWitnessUtxo, this.tx.network);
                const prevoutHash = txInputs[i].hash;
                const utxoHash = nonWitnessUtxoTx.getHash();
                // If a non-witness UTXO is provided, its hash must match the hash specified in the prevout
                if (!prevoutHash.equals(utxoHash)) {
                    throw new Error(`Non-witness UTXO hash for input #${i} doesn't match the hash specified in the prevout`);
                }
                const prevoutIndex = txInputs[i].index;
                prevout = nonWitnessUtxoTx.outs[prevoutIndex];
            }
            else if (input.witnessUtxo) {
                prevout = input.witnessUtxo;
            }
            else {
                throw new Error('Need a Utxo input item for signing');
            }
            prevoutScripts.push(prevout.script);
            prevoutValues.push(prevout.value);
        });
        const outputScript = this.getTaprootOutputScript(inputIndex);
        if (!outputScript.equals(prevoutScripts[inputIndex])) {
            throw new Error(`Witness script for input #${inputIndex} doesn't match the scriptPubKey in the prevout`);
        }
        const hash = this.tx.hashForWitnessV1(inputIndex, prevoutScripts, prevoutValues, sighashType, leafHash);
        return { hash, sighashType };
    }
    /**
     * Adds proprietary key value pair to PSBT input.
     * Default identifierEncoding is utf-8 for identifier.
     */
    addProprietaryKeyValToInput(inputIndex, keyValueData) {
        return this.addUnknownKeyValToInput(inputIndex, {
            key: proprietaryKeyVal_1.encodeProprietaryKey(keyValueData.key),
            value: keyValueData.value,
        });
    }
    /**
     * Adds or updates (if exists) proprietary key value pair to PSBT input.
     * Default identifierEncoding is utf-8 for identifier.
     */
    addOrUpdateProprietaryKeyValToInput(inputIndex, keyValueData) {
        var _a;
        const input = utils_1.checkForInput(this.data.inputs, inputIndex);
        const key = proprietaryKeyVal_1.encodeProprietaryKey(keyValueData.key);
        const { value } = keyValueData;
        if ((_a = input.unknownKeyVals) === null || _a === void 0 ? void 0 : _a.length) {
            const ukvIndex = input.unknownKeyVals.findIndex((ukv) => ukv.key.equals(key));
            if (ukvIndex > -1) {
                input.unknownKeyVals[ukvIndex] = { key, value };
                return this;
            }
        }
        this.addUnknownKeyValToInput(inputIndex, {
            key,
            value,
        });
        return this;
    }
    /**
     * To search any data from proprietary key value against keydata.
     * Default identifierEncoding is utf-8 for identifier.
     */
    getProprietaryKeyVals(inputIndex, keySearch) {
        const input = utils_1.checkForInput(this.data.inputs, inputIndex);
        return PsbtUtil_1.getPsbtInputProprietaryKeyVals(input, keySearch);
    }
    /**
     * To delete any data from proprietary key value.
     * Default identifierEncoding is utf-8 for identifier.
     */
    deleteProprietaryKeyVals(inputIndex, keysToDelete) {
        var _a;
        const input = utils_1.checkForInput(this.data.inputs, inputIndex);
        if (!((_a = input.unknownKeyVals) === null || _a === void 0 ? void 0 : _a.length)) {
            return this;
        }
        if (keysToDelete && keysToDelete.subtype === undefined && Buffer.isBuffer(keysToDelete.keydata)) {
            throw new Error('invalid proprietary key search filter combination. subtype is required');
        }
        input.unknownKeyVals = input.unknownKeyVals.filter((keyValue, i) => {
            const key = proprietaryKeyVal_1.decodeProprietaryKey(keyValue.key);
            return !(keysToDelete === undefined ||
                (keysToDelete.identifier === key.identifier &&
                    (keysToDelete.subtype === undefined ||
                        (keysToDelete.subtype === key.subtype &&
                            (!Buffer.isBuffer(keysToDelete.keydata) || keysToDelete.keydata.equals(key.keydata))))));
        });
        return this;
    }
    createMusig2NonceForInput(inputIndex, keyPair, keyType, params = { deterministic: false }) {
        const input = this.data.inputs[inputIndex];
        if (!input.tapInternalKey) {
            throw new Error('tapInternalKey is required to create nonce');
        }
        if (!input.tapMerkleRoot) {
            throw new Error('tapMerkleRoot is required to create nonce');
        }
        const getDerivedKeyPair = () => {
            var _a;
            if (!((_a = input.tapBip32Derivation) === null || _a === void 0 ? void 0 : _a.length)) {
                throw new Error('tapBip32Derivation is required to create nonce');
            }
            const derived = UtxoPsbt.deriveKeyPair(keyPair, input.tapBip32Derivation, { ignoreY: true });
            if (!derived) {
                throw new Error('No bip32Derivation masterFingerprint matched the HD keyPair fingerprint');
            }
            return derived;
        };
        const derivedKeyPair = keyType === 'root' ? getDerivedKeyPair() : keyPair;
        if (!derivedKeyPair.privateKey) {
            throw new Error('privateKey is required to create nonce');
        }
        const participants = Musig2_1.parsePsbtMusig2Participants(input);
        if (!participants) {
            throw new Error(`Found 0 matching participant key value instead of 1`);
        }
        Musig2_1.assertPsbtMusig2Participants(participants, input.tapInternalKey, input.tapMerkleRoot);
        const { tapOutputKey, participantPubKeys } = participants;
        const participantPubKey = participantPubKeys.find((pubKey) => equalPublicKeyIgnoreY(pubKey, derivedKeyPair.publicKey));
        if (!Buffer.isBuffer(participantPubKey)) {
            throw new Error('participant plain pub key should match one bip32Derivation plain pub key');
        }
        const { hash } = this.getTaprootHashForSig(inputIndex);
        let pubNonce;
        if (params.deterministic) {
            if (params.sessionId) {
                throw new Error('Cannot add extra entropy when generating a deterministic nonce');
            }
            // There must be only 2 participant pubKeys if it got to this point
            if (!equalPublicKeyIgnoreY(participantPubKey, participantPubKeys[1])) {
                throw new Error(`Only the cosigner's nonce can be set deterministically`);
            }
            const nonces = Musig2_1.parsePsbtMusig2Nonces(input);
            if (!nonces) {
                throw new Error(`No nonces found on input #${inputIndex}`);
            }
            if (nonces.length > 2) {
                throw new Error(`Cannot have more than 2 nonces`);
            }
            const firstSignerNonce = nonces.find((kv) => equalPublicKeyIgnoreY(kv.participantPubKey, participantPubKeys[0]));
            if (!firstSignerNonce) {
                throw new Error('signer nonce must be set if cosigner nonce is to be derived deterministically');
            }
            pubNonce = Musig2_1.createMusig2DeterministicNonce({
                privateKey: derivedKeyPair.privateKey,
                otherNonce: firstSignerNonce.pubNonce,
                publicKeys: participantPubKeys,
                internalPubKey: input.tapInternalKey,
                tapTreeRoot: input.tapMerkleRoot,
                hash,
            });
        }
        else {
            pubNonce = Buffer.from(this.nonceStore.createMusig2Nonce(derivedKeyPair.privateKey, participantPubKey, tapOutputKey, hash, params.sessionId));
        }
        return { tapOutputKey, participantPubKey, pubNonce };
    }
    setMusig2NoncesInner(keyPair, keyType, inputIndex, params = { deterministic: false }) {
        if (keyPair.isNeutered()) {
            throw new Error('private key is required to generate nonce');
        }
        if (Buffer.isBuffer(params.sessionId) && params.sessionId.length !== 32) {
            throw new Error(`Invalid sessionId size ${params.sessionId.length}`);
        }
        const inputIndexes = inputIndex === undefined ? [...Array(this.inputCount).keys()] : [inputIndex];
        inputIndexes.forEach((index) => {
            if (!this.isTaprootKeyPathInput(index)) {
                return;
            }
            const nonce = this.createMusig2NonceForInput(index, keyPair, keyType, params);
            this.addOrUpdateProprietaryKeyValToInput(index, Musig2_1.encodePsbtMusig2PubNonce(nonce));
        });
        return this;
    }
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
    setInputMusig2Nonce(inputIndex, derivedKeyPair, params = { deterministic: false }) {
        return this.setMusig2NoncesInner(derivedKeyPair, 'derived', inputIndex, params);
    }
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
    setInputMusig2NonceHD(inputIndex, keyPair, params = { deterministic: false }) {
        utils_1.checkForInput(this.data.inputs, inputIndex);
        return this.setMusig2NoncesInner(keyPair, 'root', inputIndex, params);
    }
    /**
     * Generates and sets MuSig2 nonce to all taproot key path inputs. Other inputs will be skipped.
     *
     * @param inputIndex input index
     * @param keyPair derived key pair
     * @param sessionId Optional extra entropy. If provided it must either be a counter unique to this secret key,
     * (converted to an array of 32 bytes), or 32 uniformly random bytes.
     */
    setAllInputsMusig2Nonce(keyPair, params = { deterministic: false }) {
        return this.setMusig2NoncesInner(keyPair, 'derived', undefined, params);
    }
    /**
     * Generates and sets MuSig2 nonce to all taproot key path inputs. Other inputs will be skipped.
     *
     * @param inputIndex input index
     * @param keyPair HD root key pair
     * @param sessionId Optional extra entropy. If provided it must either be a counter unique to this secret key,
     * (converted to an array of 32 bytes), or 32 uniformly random bytes.
     */
    setAllInputsMusig2NonceHD(keyPair, params = { deterministic: false }) {
        return this.setMusig2NoncesInner(keyPair, 'root', undefined, params);
    }
    clone() {
        return super.clone();
    }
    extractTransaction(disableFeeCheck = true) {
        const tx = super.extractTransaction(disableFeeCheck);
        if (tx instanceof UtxoTransaction_1.UtxoTransaction) {
            return tx;
        }
        throw new Error('extractTransaction did not return instace of UtxoTransaction');
    }
}
exports.UtxoPsbt = UtxoPsbt;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiVXR4b1BzYnQuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9zcmMvYml0Z28vVXR4b1BzYnQudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBQUEsaUNBQWlDO0FBQ2pDLG1DQUEwQztBQVExQyxnREFBcUQ7QUFDckQsK0RBQXNFO0FBRXRFLGlDQUFxRDtBQUNyRCx1Q0FBdUM7QUFDdkMsd0VBQThGO0FBRTlGLDBCQVlZO0FBQ1osdURBQW9EO0FBQ3BELHVDQUFnRDtBQUNoRCxvREFBOEM7QUFDOUMsMERBQStDO0FBQy9DLG1EQUFtRDtBQUNuRCw2Q0FBa0Q7QUFDbEQscUNBa0JrQjtBQUNsQixtQ0FBMkQ7QUFDM0Qsd0NBQWlEO0FBQ2pELHlDQU9vQjtBQVlwQixTQUFTLG1CQUFtQjtJQUMxQixPQUFPLENBQUMsZUFBVyxDQUFDLGVBQWUsRUFBRSxlQUFXLENBQUMsV0FBVyxDQUFDLENBQUM7QUFDaEUsQ0FBQztBQUVELFNBQVMsNEJBQTRCLENBQUMsT0FBZ0IsRUFBRSxZQUFzQjtJQUM1RSxRQUFRLGNBQVUsQ0FBQyxPQUFPLENBQUMsRUFBRTtRQUMzQixLQUFLLFlBQVEsQ0FBQyxXQUFXLENBQUM7UUFDMUIsS0FBSyxZQUFRLENBQUMsU0FBUyxDQUFDO1FBQ3hCLEtBQUssWUFBUSxDQUFDLFdBQVcsQ0FBQztRQUMxQixLQUFLLFlBQVEsQ0FBQyxLQUFLO1lBQ2pCLE9BQU8sQ0FBQyxHQUFHLFlBQVksRUFBRSxHQUFHLFlBQVksQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEVBQUUsRUFBRSxDQUFDLENBQUMsR0FBRyxpQ0FBZSxDQUFDLGNBQWMsQ0FBQyxDQUFDLENBQUM7UUFDM0Y7WUFDRSxPQUFPLFlBQVksQ0FBQztLQUN2QjtBQUNILENBQUM7QUFFRCxTQUFTLGlCQUFpQixDQUFDLE9BQWdCLEVBQUUsQ0FBdUM7SUFDbEYsSUFBSSxLQUFLLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQztRQUFFLE9BQU8saUJBQWlCLENB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QztJQUN4RSxDQUFDO0lBRUQ7Ozs7Ozs7T0FPRztJQUNILHVCQUF1QixDQUNyQixPQUF1QixFQUN2QixTQUEwRCxFQUFFLGFBQWEsRUFBRSxLQUFLLEVBQUU7UUFFbEYsT0FBTyxJQUFJLENBQUMsb0JBQW9CLENBQUMsT0FBTyxFQUFFLFNBQVMsRUFBRSxTQUFTLEVBQUUsTUFBTSxDQUFDLENBQUM7SUFDMUUsQ0FBQztJQUVEOzs7Ozs7O09BT0c7SUFDSCx5QkFBeUIsQ0FDdkIsT0FBdUIsRUFDdkIsU0FBMEQsRUFBRSxhQUFhLEVBQUUsS0FBSyxFQUFFO1FBRWxGLE9BQU8sSUFBSSxDQUFDLG9CQUFvQixDQUFDLE9BQU8sRUFBRSxNQUFNLEVBQUUsU0FBUyxFQUFFLE1BQU0sQ0FBQyxDQUFDO0lBQ3ZFLENBQUM7SUFFRCxLQUFLO1FBQ0gsT0FBTyxLQUFLLENBQUMsS0FBSyxFQUFVLENBQUM7SUFDL0IsQ0FBQztJQUVELGtCQUFrQixDQUFDLGVBQWUsR0FBRyxJQUFJO1FBQ3ZDLE1BQU0sRUFBRSxHQUFHLEtBQUssQ0FBQyxrQkFBa0IsQ0FBQyxlQUFlLENBQUMsQ0FBQztRQUNyRCxJQUFJLEVBQUUsWUFBWSxpQ0FBZSxFQUFFO1lBQ2pDLE9BQU8sRUFBRSxDQUFDO1NBQ1g7UUFDRCxNQUFNLElBQUksS0FBSyxDQUFDLDhEQUE4RCxDQUFDLENBQUM7SUFDbEYsQ0FBQztDQUNGO0FBbHBDRCw0QkFrcENDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0ICogYXMgYXNzZXJ0IGZyb20gJ2Fzc2VydCc7XG5pbXBvcnQgeyBQc2J0IGFzIFBzYnRCYXNlIH0gZnJvbSAnYmlwMTc0JztcbmltcG9ydCB7XG4gIEJpcDMyRGVyaXZhdGlvbixcbiAgUHNidElucHV0LFxuICBUYXBCaXAzMkRlcml2YXRpb24sXG4gIFRyYW5zYWN0aW9uIGFzIElUcmFuc2FjdGlvbixcbiAgVHJhbnNhY3Rpb25Gcm9tQnVmZmVyLFxufSBmcm9tICdiaXAxNzQvc3JjL2xpYi9pbnRlcmZhY2VzJztcbmltcG9ydCB7IGNoZWNrRm9ySW5wdXQgfSBmcm9tICdiaXAxNzQvc3JjL2xpYi91dGlscyc7XG5pbXBvcnQgeyBCdWZmZXJXcml0ZXIsIHZhcnVpbnQgfSBmcm9tICdiaXRjb2luanMtbGliL3NyYy9idWZmZXJ1dGlscyc7XG5pbXBvcnQgeyBTZXNzaW9uS2V5IH0gZnJvbSAnQGJyYW5kb25ibGFjay9tdXNpZyc7XG5pbXBvcnQgeyBCSVAzMkZhY3RvcnksIEJJUDMySW50ZXJmYWNlIH0gZnJvbSAnYmlwMzInO1xuaW1wb3J0ICogYXMgYnM1OGNoZWNrIGZyb20gJ2JzNThjaGVjayc7XG5pbXBvcnQgeyBkZWNvZGVQcm9wcmlldGFyeUtleSwgZW5jb2RlUHJvcHJpZXRhcnlLZXkgfSBmcm9tICdiaXAxNzQvc3JjL2xpYi9wcm9wcmlldGFyeUtleVZhbCc7XG5cbmltcG9ydCB7XG4gIHRhcHJvb3QsXG4gIEhEU2lnbmVyLFxuICBTaWduZXIsXG4gIFBzYnQsXG4gIFBzYnRUcmFuc2FjdGlvbixcbiAgVHJhbnNhY3Rpb24sXG4gIFR4T3V0cHV0LFxuICBOZXR3b3JrLFxuICBlY2MgYXMgZWNjTGliLFxuICBnZXRNYWlubmV0LFxuICBuZXR3b3Jrcyxcbn0gZnJvbSAnLi4nO1xuaW1wb3J0IHsgVXR4b1RyYW5zYWN0aW9uIH0gZnJvbSAnLi9VdHhvVHJhbnNhY3Rpb24nO1xuaW1wb3J0IHsgZ2V0T3V0cHV0SWRGb3JJbnB1dCB9IGZyb20gJy4vVW5zcGVudCc7XG5pbXBvcnQgeyBpc1NlZ3dpdCB9IGZyb20gJy4vcHNidC9zY3JpcHRUeXBlcyc7XG5pbXBvcnQgeyB1bnNpZ24gfSBmcm9tICcuL3BzYnQvZnJvbUhhbGZTaWduZWQnO1xuaW1wb3J0IHsgdG9YT25seVB1YmxpY0tleSB9IGZyb20gJy4vb3V0cHV0U2NyaXB0cyc7XG5pbXBvcnQgeyBwYXJzZVB1YlNjcmlwdDJPZjMgfSBmcm9tICcuL3BhcnNlSW5wdXQnO1xuaW1wb3J0IHtcbiAgY3JlYXRlTXVzaWcyU2lnbmluZ1Nlc3Npb24sXG4gIGVuY29kZVBzYnRNdXNpZzJQYXJ0aWFsU2lnLFxuICBlbmNvZGVQc2J0TXVzaWcyUHViTm9uY2UsXG4gIG11c2lnMlBhcnRpYWxTaWduLFxuICBwYXJzZVBzYnRNdXNpZzJOb25jZXMsXG4gIHBhcnNlUHNidE11c2lnMlBhcnRpY2lwYW50cyxcbiAgUHNidE11c2lnMlBhcnRpY2lwYW50cyxcbiAgYXNzZXJ0UHNidE11c2lnMk5vbmNlcyxcbiAgYXNzZXJ0UHNidE11c2lnMlBhcnRpY2lwYW50cyxcbiAgTXVzaWcyTm9uY2VTdG9yZSxcbiAgUHNidE11c2lnMlB1Yk5vbmNlLFxuICBwYXJzZVBzYnRNdXNpZzJQYXJ0aWFsU2lncyxcbiAgbXVzaWcyUGFydGlhbFNpZ1ZlcmlmeSxcbiAgbXVzaWcyQWdncmVnYXRlU2lncyxcbiAgZ2V0U2lnSGFzaFR5cGVGcm9tU2lncyxcbiAgbXVzaWcyRGV0ZXJtaW5pc3RpY1NpZ24sXG4gIGNyZWF0ZU11c2lnMkRldGVybWluaXN0aWNOb25jZSxcbn0gZnJvbSAnLi9NdXNpZzInO1xuaW1wb3J0IHsgaXNUcmlwbGUsIGlzVHVwbGUsIFRyaXBsZSwgVHVwbGUgfSBmcm9tICcuL3R5cGVzJztcbmltcG9ydCB7IGdldFRhcHJvb3RPdXRwdXRLZXkgfSBmcm9tICcuLi90YXByb290JztcbmltcG9ydCB7XG4gIGdldFBzYnRJbnB1dFByb3ByaWV0YXJ5S2V5VmFscyxcbiAgZ2V0UHNidElucHV0U2lnbmF0dXJlQ291bnQsXG4gIFByb3ByaWV0YXJ5S2V5U2VhcmNoLFxuICBQcm9wcmlldGFyeUtleVN1YnR5cGUsXG4gIFByb3ByaWV0YXJ5S2V5VmFsdWUsXG4gIFBTQlRfUFJPUFJJRVRBUllfSURFTlRJRklFUixcbn0gZnJvbSAnLi9Qc2J0VXRpbCc7XG5cbnR5cGUgU2lnbmF0dXJlUGFyYW1zID0ge1xuICAvKiogV2hlbiB0cnVlLCBhbmQgYWRkIHRoZSBzZWNvbmQgKGxhc3QpIG5vbmNlIGFuZCBzaWduYXR1cmUgZm9yIGEgdGFwcm9vdCBrZXlcbiAgICogcGF0aCBzcGVuZCBkZXRlcm1pbmlzdGljYWxseS4gVGhyb3dzIGFuIGVycm9yIGlmIGRvbmUgZm9yIHRoZSBmaXJzdCBub25jZS9zaWduYXR1cmVcbiAgICogb2YgYSB0YXByb290IGtleXBhdGggc3BlbmQuIElnbm9yZSBmb3IgYWxsIG90aGVyIGlucHV0IHR5cGVzLlxuICAgKi9cbiAgZGV0ZXJtaW5pc3RpYzogYm9vbGVhbjtcbiAgLyoqIEFsbG93ZWQgc2lnaGFzaCB0eXBlcyAqL1xuICBzaWdoYXNoVHlwZXM6IG51bWJlcltdO1xufTtcblxuZnVuY3Rpb24gZGVmYXVsdFNpZ2hhc2hUeXBlcygpOiBudW1iZXJbXSB7XG4gIHJldHVybiBbVHJhbnNhY3Rpb24uU0lHSEFTSF9ERUZBVUxULCBUcmFuc2FjdGlvbi5TSUdIQVNIX0FMTF07XG59XG5cbmZ1bmN0aW9uIGFkZEZvcmtJZFRvU2lnaGFzaGVzSWZOZWVkZWQobmV0d29yazogTmV0d29yaywgc2lnaGFzaFR5cGVzOiBudW1iZXJbXSk6IG51bWJlcltdIHtcbiAgc3dpdGNoIChnZXRNYWlubmV0KG5ldHdvcmspKSB7XG4gICAgY2FzZSBuZXR3b3Jrcy5iaXRjb2luY2FzaDpcbiAgICBjYXNlIG5ldHdvcmtzLmJpdGNvaW5zdjpcbiAgICBjYXNlIG5ldHdvcmtzLmJpdGNvaW5nb2xkOlxuICAgIGNhc2UgbmV0d29ya3MuZWNhc2g6XG4gICAgICByZXR1cm4gWy4uLnNpZ2hhc2hUeXBlcywgLi4uc2lnaGFzaFR5cGVzLm1hcCgocykgPT4gcyB8IFV0eG9UcmFuc2FjdGlvbi5TSUdIQVNIX0ZPUktJRCldO1xuICAgIGRlZmF1bHQ6XG4gICAgICByZXR1cm4gc2lnaGFzaFR5cGVzO1xuICB9XG59XG5cbmZ1bmN0aW9uIHRvU2lnbmF0dXJlUGFyYW1zKG5ldHdvcms6IE5ldHdvcmssIHY/OiBQYXJ0aWFsPFNpZ25hdHVyZVBhcmFtcz4gfCBudW1iZXJbXSk6IFNpZ25hdHVyZVBhcmFtcyB7XG4gIGlmIChBcnJheS5pc0FycmF5KHYpKSByZXR1cm4gdG9TaWduYXR1cmVQYXJhbXMobmV0d29yaywgeyBzaWdoYXNoVHlwZXM6IHYgfSk7XG4gIGNvbnN0IGRlZmF1bHRTaWduYXR1cmVQYXJhbXMgPSB7IGRldGVybWluaXN0aWM6IGZhbHNlLCBzaWdoYXNoVHlwZXM6IGRlZmF1bHRTaWdoYXNoVHlwZXMoKSB9O1xuICBjb25zdCByZXQgPSB7IC4uLmRlZmF1bHRTaWduYXR1cmVQYXJhbXMsIC4uLnYgfTtcbiAgcmV0LnNpZ2hhc2hUeXBlcyA9IGFkZEZvcmtJZFRvU2lnaGFzaGVzSWZOZWVkZWQobmV0d29yaywgcmV0LnNpZ2hhc2hUeXBlcyk7XG4gIHJldHVybiByZXQ7XG59XG5cbi8qKlxuICogQHBhcmFtIGFcbiAqIEBwYXJhbSBiXG4gKiBAcmV0dXJucyB0cnVlIGlmIHRoZSB0d28gcHVibGljIGtleXMgYXJlIGVxdWFsIGlnbm9yaW5nIHRoZSB5IGNvb3JkaW5hdGUuXG4gKi9cbmZ1bmN0aW9uIGVxdWFsUHVibGljS2V5SWdub3JlWShhOiBCdWZmZXIsIGI6IEJ1ZmZlcik6IGJvb2xlYW4ge1xuICByZXR1cm4gdG9YT25seVB1YmxpY0tleShhKS5lcXVhbHModG9YT25seVB1YmxpY0tleShiKSk7XG59XG5cbmV4cG9ydCBpbnRlcmZhY2UgSERUYXByb290U2lnbmVyIGV4dGVuZHMgSERTaWduZXIge1xuICAvKipcbiAgICogVGhlIHBhdGggc3RyaW5nIG11c3QgbWF0Y2ggL15tKFxcL1xcZCsnPykrJC9cbiAgICogZXguIG0vNDQnLzAnLzAnLzEvMjMgbGV2ZWxzIHdpdGggJyBtdXN0IGJlIGhhcmQgZGVyaXZhdGlvbnNcbiAgICovXG4gIGRlcml2ZVBhdGgocGF0aDogc3RyaW5nKTogSERUYXByb290U2lnbmVyO1xuICAvKipcbiAgICogSW5wdXQgaGFzaCAodGhlIFwibWVzc2FnZSBkaWdlc3RcIikgZm9yIHRoZSBzaWduYXR1cmUgYWxnb3JpdGhtXG4gICAqIFJldHVybiBhIDY0IGJ5dGUgc2lnbmF0dXJlICgzMiBieXRlIHIgYW5kIDMyIGJ5dGUgcyBpbiB0aGF0IG9yZGVyKVxuICAgKi9cbiAgc2lnblNjaG5vcnIoaGFzaDogQnVmZmVyKTogQnVmZmVyO1xufVxuXG4vKipcbiAqIEhEIHNpZ25lciBvYmplY3QgZm9yIHRhcHJvb3QgcDJ0ciBtdXNpZzIga2V5IHBhdGggc2lnblxuICovXG5leHBvcnQgaW50ZXJmYWNlIEhEVGFwcm9vdE11c2lnMlNpZ25lciBleHRlbmRzIEhEU2lnbmVyIHtcbiAgLyoqXG4gICAqIE11c2lnMiByZXF1aXJlcyBzaWduZXIncyAzMi1ieXRlcyBwcml2YXRlIGtleSB0byBiZSBwYXNzZWQgdG8gaXQuXG4gICAqL1xuICBwcml2YXRlS2V5OiBCdWZmZXI7XG5cbiAgLyoqXG4gICAqIFRoZSBwYXRoIHN0cmluZyBtdXN0IG1hdGNoIC9ebShcXC9cXGQrJz8pKyQvXG4gICAqIGV4LiBtLzQ0Jy8wJy8wJy8xLzIzIGxldmVscyB3aXRoICcgbXVzdCBiZSBoYXJkIGRlcml2YXRpb25zXG4gICAqL1xuICBkZXJpdmVQYXRoKHBhdGg6IHN0cmluZyk6IEhEVGFwcm9vdE11c2lnMlNpZ25lcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBTY2hub3JyU2lnbmVyIHtcbiAgcHVibGljS2V5OiBCdWZmZXI7XG4gIHNpZ25TY2hub3JyKGhhc2g6IEJ1ZmZlcik6IEJ1ZmZlcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBNdXNpZzJTaWduZXIge1xuICBwdWJsaWNLZXk6IEJ1ZmZlcjtcbiAgcHJpdmF0ZUtleTogQnVmZmVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIFRhcHJvb3RTaWduZXIge1xuICBsZWFmSGFzaGVzOiBCdWZmZXJbXTtcbiAgc2lnbmVyOiBTY2hub3JyU2lnbmVyO1xufVxuXG5leHBvcnQgaW50ZXJmYWNlIFBzYnRPcHRzIHtcbiAgbmV0d29yazogTmV0d29yaztcbiAgbWF4aW11bUZlZVJhdGU/OiBudW1iZXI7IC8vIFtzYXQvYnl0ZV1cbiAgYmlwMzJQYXRoc0Fic29sdXRlPzogYm9vbGVhbjtcbn1cblxuLy8gVE9ETzogdXBzdHJlYW0gZG9lcyBgY2hlY2tJbnB1dHNGb3JQYXJ0aWFsU2lnc2AgYmVmb3JlIGRvaW5nIHRoaW5ncyBsaWtlXG4vLyBgc2V0VmVyc2lvbmAuIE91ciBpbnB1dHMgY291bGQgaGF2ZSB0YXBzY3JpcHRzaWdzIChvciBpbiBmdXR1cmUgdGFwa2V5c2lncylcbi8vIGFuZCBub3QgZmFpbCB0aGF0IGNoZWNrLiBEbyB3ZSB3YW50IHRvIGRvIGFueXRoaW5nIGFib3V0IHRoYXQ/XG5leHBvcnQgY2xhc3MgVXR4b1BzYnQ8VHggZXh0ZW5kcyBVdHhvVHJhbnNhY3Rpb248YmlnaW50PiA9IFV0eG9UcmFuc2FjdGlvbjxiaWdpbnQ+PiBleHRlbmRzIFBzYnQge1xuICBwcml2YXRlIG5vbmNlU3RvcmUgPSBuZXcgTXVzaWcyTm9uY2VTdG9yZSgpO1xuXG4gIHByb3RlY3RlZCBzdGF0aWMgdHJhbnNhY3Rpb25Gcm9tQnVmZmVyKGJ1ZmZlcjogQnVmZmVyLCBuZXR3b3JrOiBOZXR3b3JrKTogVXR4b1RyYW5zYWN0aW9uPGJpZ2ludD4ge1xuICAgIHJldHVybiBVdHhvVHJhbnNhY3Rpb24uZnJvbUJ1ZmZlcjxiaWdpbnQ+KGJ1ZmZlciwgZmFsc2UsICdiaWdpbnQnLCBuZXR3b3JrKTtcbiAgfVxuXG4gIHN0YXRpYyBjcmVhdGVQc2J0KG9wdHM6IFBzYnRPcHRzLCBkYXRhPzogUHNidEJhc2UpOiBVdHhvUHNidCB7XG4gICAgcmV0dXJuIG5ldyBVdHhvUHNidChcbiAgICAgIG9wdHMsXG4gICAgICBkYXRhIHx8IG5ldyBQc2J0QmFzZShuZXcgUHNidFRyYW5zYWN0aW9uKHsgdHg6IG5ldyBVdHhvVHJhbnNhY3Rpb248YmlnaW50PihvcHRzLm5ldHdvcmspIH0pKVxuICAgICk7XG4gIH1cblxuICBzdGF0aWMgZnJvbUJ1ZmZlcihidWZmZXI6IEJ1ZmZlciwgb3B0czogUHNidE9wdHMpOiBVdHhvUHNidCB7XG4gICAgY29uc3QgdHJhbnNhY3Rpb25Gcm9tQnVmZmVyOiBUcmFuc2FjdGlvbkZyb21CdWZmZXIgPSAoYnVmZmVyOiBCdWZmZXIpOiBJVHJhbnNhY3Rpb24gPT4ge1xuICAgICAgY29uc3QgdHggPSB0aGlzLnRyYW5zYWN0aW9uRnJvbUJ1ZmZlcihidWZmZXIsIG9wdHMubmV0d29yayk7XG4gICAgICByZXR1cm4gbmV3IFBzYnRUcmFuc2FjdGlvbih7IHR4IH0pO1xuICAgIH07XG4gICAgY29uc3QgcHNidEJhc2UgPSBQc2J0QmFzZS5mcm9tQnVmZmVyKGJ1ZmZlciwgdHJhbnNhY3Rpb25Gcm9tQnVmZmVyLCB7XG4gICAgICBiaXAzMlBhdGhzQWJzb2x1dGU6IG9wdHMuYmlwMzJQYXRoc0Fic29sdXRlLFxuICAgIH0pO1xuICAgIGNvbnN0IHBzYnQgPSB0aGlzLmNyZWF0ZVBzYnQob3B0cywgcHNidEJhc2UpO1xuICAgIC8vIFVwc3RyZWFtIGNoZWNrcyBmb3IgZHVwbGljYXRlIGlucHV0cyBoZXJlLCBidXQgaXQgc2VlbXMgdG8gYmUgb2YgZHViaW91cyB2YWx1ZS5cbiAgICByZXR1cm4gcHNidDtcbiAgfVxuXG4gIHN0YXRpYyBmcm9tSGV4KGRhdGE6IHN0cmluZywgb3B0czogUHNidE9wdHMpOiBVdHhvUHNidCB7XG4gICAgcmV0dXJuIHRoaXMuZnJvbUJ1ZmZlcihCdWZmZXIuZnJvbShkYXRhLCAnaGV4JyksIG9wdHMpO1xuICB9XG5cbiAgLyoqXG4gICAqIEBwYXJhbSBwYXJlbnQgLSBQYXJlbnQga2V5LiBNYXRjaGVkIHdpdGggYGJpcDMyRGVyaXZhdGlvbnNgIHVzaW5nIGBmaW5nZXJwcmludGAgcHJvcGVydHkuXG4gICAqIEBwYXJhbSBiaXAzMkRlcml2YXRpb25zIC0gcG9zc2libGUgZGVyaXZhdGlvbnMgZm9yIGlucHV0IG9yIG91dHB1dFxuICAgKiBAcGFyYW0gaWdub3JlWSAtIHdoZW4gdHJ1ZSwgaWdub3JlIHRoZSB5IGNvb3JkaW5hdGUgd2hlbiBtYXRjaGluZyBwdWJsaWMga2V5c1xuICAgKiBAcmV0dXJuIGRlcml2ZWQgYmlwMzIgbm9kZSBpZiBtYXRjaGluZyBkZXJpdmF0aW9uIGlzIGZvdW5kLCB1bmRlZmluZWQgaWYgbm9uZSBpcyBmb3VuZFxuICAgKiBAdGhyb3dzIEVycm9yIGlmIG1vcmUgdGhhbiBvbmUgbWF0Y2ggaXMgZm91bmRcbiAgICovXG4gIHN0YXRpYyBkZXJpdmVLZXlQYWlyKFxuICAgIHBhcmVudDogQklQMzJJbnRlcmZhY2UsXG4gICAgYmlwMzJEZXJpdmF0aW9uczogQmlwMzJEZXJpdmF0aW9uW10sXG4gICAgeyBpZ25vcmVZIH06IHsgaWdub3JlWTogYm9vbGVhbiB9XG4gICk6IEJJUDMySW50ZXJmYWNlIHwgdW5kZWZpbmVkIHtcbiAgICBjb25zdCBtYXRjaGluZ0Rlcml2YXRpb25zID0gYmlwMzJEZXJpdmF0aW9ucy5maWx0ZXIoKGJpcER2KSA9PiB7XG4gICAgICByZXR1cm4gYmlwRHYubWFzdGVyRmluZ2VycHJpbnQuZXF1YWxzKHBhcmVudC5maW5nZXJwcmludCk7XG4gICAgfSk7XG5cbiAgICBpZiAoIW1hdGNoaW5nRGVyaXZhdGlvbnMubGVuZ3RoKSB7XG4gICAgICAvLyBObyBmaW5nZXJwcmludCBtYXRjaFxuICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICB9XG5cbiAgICBpZiAobWF0Y2hpbmdEZXJpdmF0aW9ucy5sZW5ndGggIT09IDEpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgYG1vcmUgdGhhbiBvbmUgbWF0Y2hpbmcgZGVyaXZhdGlvbiBmb3IgZmluZ2VycHJpbnQgJHtwYXJlbnQuZmluZ2VycHJpbnQudG9TdHJpbmcoJ2hleCcpfTogJHtcbiAgICAgICAgICBtYXRjaGluZ0Rlcml2YXRpb25zLmxlbmd0aFxuICAgICAgICB9YFxuICAgICAgKTtcbiAgICB9XG5cbiAgICBjb25zdCBbZGVyaXZhdGlvbl0gPSBtYXRjaGluZ0Rlcml2YXRpb25zO1xuICAgIGNvbnN0IG5vZGUgPSBwYXJlbnQuZGVyaXZlUGF0aChkZXJpdmF0aW9uLnBhdGgpO1xuXG4gICAgaWYgKCFub2RlLnB1YmxpY0tleS5lcXVhbHMoZGVyaXZhdGlvbi5wdWJrZXkpKSB7XG4gICAgICBpZiAoIWlnbm9yZVkgfHwgIWVxdWFsUHVibGljS2V5SWdub3JlWShub2RlLnB1YmxpY0tleSwgZGVyaXZhdGlvbi5wdWJrZXkpKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcigncHVia2V5IGRpZCBub3QgbWF0Y2ggYmlwMzJEZXJpdmF0aW9uJyk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIG5vZGU7XG4gIH1cblxuICBzdGF0aWMgZGVyaXZlS2V5UGFpckZvcklucHV0KGJpcDMyOiBCSVAzMkludGVyZmFjZSwgaW5wdXQ6IFBzYnRJbnB1dCk6IEJ1ZmZlciB8IHVuZGVmaW5lZCB7XG4gICAgcmV0dXJuIGlucHV0LnRhcEJpcDMyRGVyaXZhdGlvbj8ubGVuZ3RoXG4gICAgICA/IFV0eG9Qc2J0LmRlcml2ZUtleVBhaXIoYmlwMzIsIGlucHV0LnRhcEJpcDMyRGVyaXZhdGlvbiwgeyBpZ25vcmVZOiB0cnVlIH0pPy5wdWJsaWNLZXlcbiAgICAgIDogaW5wdXQuYmlwMzJEZXJpdmF0aW9uPy5sZW5ndGhcbiAgICAgID8gVXR4b1BzYnQuZGVyaXZlS2V5UGFpcihiaXAzMiwgaW5wdXQuYmlwMzJEZXJpdmF0aW9uLCB7IGlnbm9yZVk6IGZhbHNlIH0pPy5wdWJsaWNLZXlcbiAgICAgIDogYmlwMzI/LnB1YmxpY0tleTtcbiAgfVxuXG4gIGdldCBuZXR3b3JrKCk6IE5ldHdvcmsge1xuICAgIHJldHVybiB0aGlzLnR4Lm5ldHdvcms7XG4gIH1cblxuICB0b0hleCgpOiBzdHJpbmcge1xuICAgIHJldHVybiB0aGlzLnRvQnVmZmVyKCkudG9TdHJpbmcoJ2hleCcpO1xuICB9XG5cbiAgLyoqXG4gICAqIEl0IGlzIGV4cGVuc2l2ZSB0byBhdHRlbXB0IHRvIGNvbXB1dGUgZXZlcnkgb3V0cHV0IGFkZHJlc3MgdXNpbmcgcHNidC50eE91dHB1dHNbb3V0cHV0SW5kZXhdXG4gICAqIHRvIHRoZW4ganVzdCBnZXQgdGhlIHNjcmlwdC4gSGVyZSwgd2UgYXJlIGRvaW5nIHRoZSBzYW1lIHRoaW5nIGFzIHdoYXQgdHhPdXRwdXRzKCkgZG9lcyBpblxuICAgKiBiaXRjb2luanMtbGliLCBidXQgd2l0aG91dCBpdGVyYXRpbmcgb3ZlciBlYWNoIG91dHB1dC5cbiAgICogQHBhcmFtIG91dHB1dEluZGV4XG4gICAqIEByZXR1cm5zIG91dHB1dCBzY3JpcHQgYXQgdGhlIGdpdmVuIGluZGV4XG4gICAqL1xuICBnZXRPdXRwdXRTY3JpcHQob3V0cHV0SW5kZXg6IG51bWJlcik6IEJ1ZmZlciB7XG4gICAgcmV0dXJuICh0aGlzIGFzIGFueSkuX19DQUNIRS5fX1RYLm91dHNbb3V0cHV0SW5kZXhdLnNjcmlwdCBhcyBCdWZmZXI7XG4gIH1cblxuICBnZXROb25XaXRuZXNzUHJldmlvdXNUeGlkcygpOiBzdHJpbmdbXSB7XG4gICAgY29uc3QgdHhJbnB1dHMgPSB0aGlzLnR4SW5wdXRzOyAvLyBUaGVzZSBhcmUgc29tZXdoYXQgY29zdGx5IHRvIGV4dHJhY3RcbiAgICBjb25zdCB0eGlkU2V0ID0gbmV3IFNldDxzdHJpbmc+KCk7XG4gICAgdGhpcy5kYXRhLmlucHV0cy5mb3JFYWNoKChpbnB1dCwgaW5kZXgpID0+IHtcbiAgICAgIGlmICghaW5wdXQud2l0bmVzc1V0eG8pIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdNdXN0IGhhdmUgd2l0bmVzcyBVVFhPIGZvciBhbGwgaW5wdXRzJyk7XG4gICAgICB9XG4gICAgICBpZiAoIWlzU2Vnd2l0KGlucHV0LndpdG5lc3NVdHhvLnNjcmlwdCwgaW5wdXQucmVkZWVtU2NyaXB0KSkge1xuICAgICAgICB0eGlkU2V0LmFkZChnZXRPdXRwdXRJZEZvcklucHV0KHR4SW5wdXRzW2luZGV4XSkudHhpZCk7XG4gICAgICB9XG4gICAgfSk7XG4gICAgcmV0dXJuIFsuLi50eGlkU2V0XTtcbiAgfVxuXG4gIGFkZE5vbldpdG5lc3NVdHhvcyh0eEJ1ZnM6IFJlY29yZDxzdHJpbmcsIEJ1ZmZlcj4pOiB0aGlzIHtcbiAgICBjb25zdCB0eElucHV0cyA9IHRoaXMudHhJbnB1dHM7IC8vIFRoZXNlIGFyZSBzb21ld2hhdCBjb3N0bHkgdG8gZXh0cmFjdFxuICAgIHRoaXMuZGF0YS5pbnB1dHMuZm9yRWFjaCgoaW5wdXQsIGluZGV4KSA9PiB7XG4gICAgICBpZiAoIWlucHV0LndpdG5lc3NVdHhvKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcignTXVzdCBoYXZlIHdpdG5lc3MgVVRYTyBmb3IgYWxsIGlucHV0cycpO1xuICAgICAgfVxuICAgICAgaWYgKCFpc1NlZ3dpdChpbnB1dC53aXRuZXNzVXR4by5zY3JpcHQsIGlucHV0LnJlZGVlbVNjcmlwdCkpIHtcbiAgICAgICAgY29uc3QgeyB0eGlkIH0gPSBnZXRPdXRwdXRJZEZvcklucHV0KHR4SW5wdXRzW2luZGV4XSk7XG4gICAgICAgIGlmICh0eEJ1ZnNbdHhpZF0gPT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgIHRocm93IG5ldyBFcnJvcignTm90IGFsbCByZXF1aXJlZCBwcmV2aW91cyB0cmFuc2FjdGlvbnMgcHJvdmlkZWQnKTtcbiAgICAgICAgfVxuICAgICAgICB0aGlzLnVwZGF0ZUlucHV0KGluZGV4LCB7IG5vbldpdG5lc3NVdHhvOiB0eEJ1ZnNbdHhpZF0gfSk7XG4gICAgICB9XG4gICAgfSk7XG4gICAgcmV0dXJuIHRoaXM7XG4gIH1cblxuICBzdGF0aWMgZnJvbVRyYW5zYWN0aW9uKHRyYW5zYWN0aW9uOiBVdHhvVHJhbnNhY3Rpb248YmlnaW50PiwgcHJldk91dHB1dHM6IFR4T3V0cHV0PGJpZ2ludD5bXSk6IFV0eG9Qc2J0IHtcbiAgICBpZiAocHJldk91dHB1dHMubGVuZ3RoICE9PSB0cmFuc2FjdGlvbi5pbnMubGVuZ3RoKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgIGBUcmFuc2FjdGlvbiBoYXMgJHt0cmFuc2FjdGlvbi5pbnMubGVuZ3RofSBpbnB1dHMsIGJ1dCAke3ByZXZPdXRwdXRzLmxlbmd0aH0gcHJldmlvdXMgb3V0cHV0cyBwcm92aWRlZGBcbiAgICAgICk7XG4gICAgfVxuICAgIGNvbnN0IGNsb25lZFRyYW5zYWN0aW9uID0gdHJhbnNhY3Rpb24uY2xvbmUoKTtcbiAgICBjb25zdCB1cGRhdGVzID0gdW5zaWduKGNsb25lZFRyYW5zYWN0aW9uLCBwcmV2T3V0cHV0cyk7XG5cbiAgICBjb25zdCBwc2J0QmFzZSA9IG5ldyBQc2J0QmFzZShuZXcgUHNidFRyYW5zYWN0aW9uKHsgdHg6IGNsb25lZFRyYW5zYWN0aW9uIH0pKTtcbiAgICBjbG9uZWRUcmFuc2FjdGlvbi5pbnMuZm9yRWFjaCgoKSA9PiBwc2J0QmFzZS5pbnB1dHMucHVzaCh7IHVua25vd25LZXlWYWxzOiBbXSB9KSk7XG4gICAgY2xvbmVkVHJhbnNhY3Rpb24ub3V0cy5mb3JFYWNoKCgpID0+IHBzYnRCYXNlLm91dHB1dHMucHVzaCh7IHVua25vd25LZXlWYWxzOiBbXSB9KSk7XG4gICAgY29uc3QgcHNidCA9IHRoaXMuY3JlYXRlUHNidCh7IG5ldHdvcms6IHRyYW5zYWN0aW9uLm5ldHdvcmsgfSwgcHNidEJhc2UpO1xuXG4gICAgdXBkYXRlcy5mb3JFYWNoKCh1cGRhdGUsIGluZGV4KSA9PiB7XG4gICAgICBwc2J0LnVwZGF0ZUlucHV0KGluZGV4LCB1cGRhdGUpO1xuICAgICAgcHNidC51cGRhdGVJbnB1dChpbmRleCwgeyB3aXRuZXNzVXR4bzogeyBzY3JpcHQ6IHByZXZPdXRwdXRzW2luZGV4XS5zY3JpcHQsIHZhbHVlOiBwcmV2T3V0cHV0c1tpbmRleF0udmFsdWUgfSB9KTtcbiAgICB9KTtcblxuICAgIHJldHVybiBwc2J0O1xuICB9XG5cbiAgZ2V0VW5zaWduZWRUeCgpOiBVdHhvVHJhbnNhY3Rpb248YmlnaW50PiB7XG4gICAgcmV0dXJuIHRoaXMudHguY2xvbmUoKTtcbiAgfVxuXG4gIHByb3RlY3RlZCBzdGF0aWMgbmV3VHJhbnNhY3Rpb24obmV0d29yazogTmV0d29yayk6IFV0eG9UcmFuc2FjdGlvbjxiaWdpbnQ+IHtcbiAgICByZXR1cm4gbmV3IFV0eG9UcmFuc2FjdGlvbjxiaWdpbnQ+KG5ldHdvcmspO1xuICB9XG5cbiAgcHJvdGVjdGVkIGdldCB0eCgpOiBUeCB7XG4gICAgcmV0dXJuICh0aGlzLmRhdGEuZ2xvYmFsTWFwLnVuc2lnbmVkVHggYXMgUHNidFRyYW5zYWN0aW9uKS50eCBhcyBUeDtcbiAgfVxuXG4gIHByb3RlY3RlZCBjaGVja0ZvclNpZ25hdHVyZXMocHJvcE5hbWU/OiBzdHJpbmcpOiB2b2lkIHtcbiAgICB0aGlzLmRhdGEuaW5wdXRzLmZvckVhY2goKGlucHV0KSA9PiB7XG4gICAgICBpZiAoaW5wdXQudGFwU2NyaXB0U2lnPy5sZW5ndGggfHwgaW5wdXQudGFwS2V5U2lnIHx8IGlucHV0LnBhcnRpYWxTaWc/Lmxlbmd0aCkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYENhbm5vdCBtb2RpZnkgJHtwcm9wTmFtZSA/PyAndHJhbnNhY3Rpb24nfSAtIHNpZ25hdHVyZXMgZXhpc3QuYCk7XG4gICAgICB9XG4gICAgfSk7XG4gIH1cblxuICAvKipcbiAgICogQHJldHVybnMgdHJ1ZSBpZiB0aGUgaW5wdXQgYXQgaW5wdXRJbmRleCBpcyBhIHRhcHJvb3Qga2V5IHBhdGguXG4gICAqIENoZWNrcyBmb3IgcHJlc2VuY2Ugb2YgbWluaW11bSByZXF1aXJlZCBrZXkgcGF0aCBpbnB1dCBmaWVsZHMgYW5kIGFic2VuY2Ugb2YgYW55IHNjcmlwdCBwYXRoIG9ubHkgaW5wdXQgZmllbGRzLlxuICAgKi9cbiAgaXNUYXByb290S2V5UGF0aElucHV0KGlucHV0SW5kZXg6IG51bWJlcik6IGJvb2xlYW4ge1xuICAgIGNvbnN0IGlucHV0ID0gY2hlY2tGb3JJbnB1dCh0aGlzLmRhdGEuaW5wdXRzLCBpbnB1dEluZGV4KTtcbiAgICByZXR1cm4gKFxuICAgICAgISFpbnB1dC50YXBJbnRlcm5hbEtleSAmJlxuICAgICAgISFpbnB1dC50YXBNZXJrbGVSb290ICYmXG4gICAgICAhKFxuICAgICAgICBpbnB1dC50YXBMZWFmU2NyaXB0Py5sZW5ndGggfHxcbiAgICAgICAgaW5wdXQudGFwU2NyaXB0U2lnPy5sZW5ndGggfHxcbiAgICAgICAgaW5wdXQudGFwQmlwMzJEZXJpdmF0aW9uPy5zb21lKCh2KSA9PiB2LmxlYWZIYXNoZXMubGVuZ3RoKVxuICAgICAgKVxuICAgICk7XG4gIH1cblxuICAvKipcbiAgICogQHJldHVybnMgdHJ1ZSBpZiB0aGUgaW5wdXQgYXQgaW5wdXRJbmRleCBpcyBhIHRhcHJvb3Qgc2NyaXB0IHBhdGguXG4gICAqIENoZWNrcyBmb3IgcHJlc2VuY2Ugb2YgbWluaW11bSByZXF1aXJlZCBzY3JpcHQgcGF0aCBpbnB1dCBmaWVsZHMgYW5kIGFic2VuY2Ugb2YgYW55IGtleSBwYXRoIG9ubHkgaW5wdXQgZmllbGRzLlxuICAgKi9cbiAgaXNUYXByb290U2NyaXB0UGF0aElucHV0KGlucHV0SW5kZXg6IG51bWJlcik6IGJvb2xlYW4ge1xuICAgIGNvbnN0IGlucHV0ID0gY2hlY2tGb3JJbnB1dCh0aGlzLmRhdGEuaW5wdXRzLCBpbnB1dEluZGV4KTtcbiAgICByZXR1cm4gKFxuICAgICAgISFpbnB1dC50YXBMZWFmU2NyaXB0Py5sZW5ndGggJiZcbiAgICAgICEoXG4gICAgICAgIHRoaXMuZ2V0UHJvcHJpZXRhcnlLZXlWYWxzKGlucHV0SW5kZXgsIHtcbiAgICAgICAgICBpZGVudGlmaWVyOiBQU0JUX1BST1BSSUVUQVJZX0lERU5USUZJRVIsXG4gICAgICAgICAgc3VidHlwZTogUHJvcHJpZXRhcnlLZXlTdWJ0eXBlLk1VU0lHMl9QQVJUSUNJUEFOVF9QVUJfS0VZUyxcbiAgICAgICAgfSkubGVuZ3RoIHx8XG4gICAgICAgIHRoaXMuZ2V0UHJvcHJpZXRhcnlLZXlWYWxzKGlucHV0SW5kZXgsIHtcbiAgICAgICAgICBpZGVudGlmaWVyOiBQU0JUX1BST1BSSUVUQVJZX0lERU5USUZJRVIsXG4gICAgICAgICAgc3VidHlwZTogUHJvcHJpZXRhcnlLZXlTdWJ0eXBlLk1VU0lHMl9QVUJfTk9OQ0UsXG4gICAgICAgIH0pLmxlbmd0aCB8fFxuICAgICAgICB0aGlzLmdldFByb3ByaWV0YXJ5S2V5VmFscyhpbnB1dEluZGV4LCB7XG4gICAgICAgICAgaWRlbnRpZmllcjogUFNCVF9QUk9QUklFVEFSWV9JREVOVElGSUVSLFxuICAgICAgICAgIHN1YnR5cGU6IFByb3ByaWV0YXJ5S2V5U3VidHlwZS5NVVNJRzJfUEFSVElBTF9TSUcsXG4gICAgICAgIH0pLmxlbmd0aFxuICAgICAgKVxuICAgICk7XG4gIH1cblxuICAvKipcbiAgICogQHJldHVybnMgdHJ1ZSBpZiB0aGUgaW5wdXQgYXQgaW5wdXRJbmRleCBpcyBhIHRhcHJvb3RcbiAgICovXG4gIGlzVGFwcm9vdElucHV0KGlucHV0SW5kZXg6IG51bWJlcik6IGJvb2xlYW4ge1xuICAgIGNvbnN0IGlucHV0ID0gY2hlY2tGb3JJbnB1dCh0aGlzLmRhdGEuaW5wdXRzLCBpbnB1dEluZGV4KTtcbiAgICBjb25zdCBpc1AyVFIgPSAoc2NyaXB0OiBCdWZmZXIpOiBib29sZWFuID0+IHtcbiAgICAgIHRyeSB7XG4gICAgICAgIGdldFRhcHJvb3RPdXRwdXRLZXkoc2NyaXB0KTtcbiAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgIH1cbiAgICB9O1xuICAgIHJldHVybiAhIShcbiAgICAgIGlucHV0LnRhcEludGVybmFsS2V5IHx8XG4gICAgICBpbnB1dC50YXBNZXJrbGVSb290IHx8XG4gICAgICBpbnB1dC50YXBMZWFmU2NyaXB0Py5sZW5ndGggfHxcbiAgICAgIGlucHV0LnRhcEJpcDMyRGVyaXZhdGlvbj8ubGVuZ3RoIHx8XG4gICAgICBpbnB1dC50YXBTY3JpcHRTaWc/Lmxlbmd0aCB8fFxuICAgICAgdGhpcy5nZXRQcm9wcmlldGFyeUtleVZhbHMoaW5wdXRJbmRleCwge1xuICAgICAgICBpZGVudGlmaWVyOiBQU0JUX1BST1BSSUVUQVJZX0lERU5USUZJRVIsXG4gICAgICAgIHN1YnR5cGU6IFByb3ByaWV0YXJ5S2V5U3VidHlwZS5NVVNJRzJfUEFSVElDSVBBTlRfUFVCX0tFWVMsXG4gICAgICB9KS5sZW5ndGggfHxcbiAgICAgIHRoaXMuZ2V0UHJvcHJpZXRhcnlLZXlWYWxzKGlucHV0SW5kZXgsIHtcbiAgICAgICAgaWRlbnRpZmllcjogUFNCVF9QUk9QUklFVEFSWV9JREVOVElGSUVSLFxuICAgICAgICBzdWJ0eXBlOiBQcm9wcmlldGFyeUtleVN1YnR5cGUuTVVTSUcyX1BVQl9OT05DRSxcbiAgICAgIH0pLmxlbmd0aCB8fFxuICAgICAgdGhpcy5nZXRQcm9wcmlldGFyeUtleVZhbHMoaW5wdXRJbmRleCwge1xuICAgICAgICBpZGVudGlmaWVyOiBQU0JUX1BST1BSSUVUQVJZX0lERU5USUZJRVIsXG4gICAgICAgIHN1YnR5cGU6IFByb3ByaWV0YXJ5S2V5U3VidHlwZS5NVVNJRzJfUEFSVElBTF9TSUcsXG4gICAgICB9KS5sZW5ndGggfHxcbiAgICAgIChpbnB1dC53aXRuZXNzVXR4byAmJiBpc1AyVFIoaW5wdXQud2l0bmVzc1V0eG8uc2NyaXB0KSlcbiAgICApO1xuICB9XG5cbiAgcHJpdmF0ZSBpc011bHRpc2lnVGFwcm9vdFNjcmlwdChzY3JpcHQ6IEJ1ZmZlcik6IGJvb2xlYW4ge1xuICAgIHRyeSB7XG4gICAgICBwYXJzZVB1YlNjcmlwdDJPZjMoc2NyaXB0LCAndGFwcm9vdFNjcmlwdFBhdGhTcGVuZCcpO1xuICAgICAgcmV0dXJuIHRydWU7XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbiAgfVxuXG4gIC8qKlxuICAgKiBNb3N0bHkgY29waWVkIGZyb20gYml0Y29pbmpzLWxpYi90c19zcmMvcHNidC50c1xuICAgKi9cbiAgZmluYWxpemVBbGxJbnB1dHMoKTogdGhpcyB7XG4gICAgY2hlY2tGb3JJbnB1dCh0aGlzLmRhdGEuaW5wdXRzLCAwKTsgLy8gbWFraW5nIHN1cmUgd2UgaGF2ZSBhdCBsZWFzdCBvbmVcbiAgICB0aGlzLmRhdGEuaW5wdXRzLm1hcCgoaW5wdXQsIGlkeCkgPT4ge1xuICAgICAgaWYgKGlucHV0LnRhcExlYWZTY3JpcHQ/Lmxlbmd0aCkge1xuICAgICAgICByZXR1cm4gdGhpcy5pc011bHRpc2lnVGFwcm9vdFNjcmlwdChpbnB1dC50YXBMZWFmU2NyaXB0WzBdLnNjcmlwdClcbiAgICAgICAgICA/IHRoaXMuZmluYWxpemVUYXByb290SW5wdXQoaWR4KVxuICAgICAgICAgIDogdGhpcy5maW5hbGl6ZVRhcElucHV0V2l0aFNpbmdsZUxlYWZTY3JpcHRBbmRTaWduYXR1cmUoaWR4KTtcbiAgICAgIH0gZWxzZSBpZiAodGhpcy5pc1RhcHJvb3RLZXlQYXRoSW5wdXQoaWR4KSkge1xuICAgICAgICByZXR1cm4gdGhpcy5maW5hbGl6ZVRhcHJvb3RNdXNpZzJJbnB1dChpZHgpO1xuICAgICAgfVxuICAgICAgcmV0dXJuIHRoaXMuZmluYWxpemVJbnB1dChpZHgpO1xuICAgIH0pO1xuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgZmluYWxpemVUYXByb290SW5wdXQoaW5wdXRJbmRleDogbnVtYmVyKTogdGhpcyB7XG4gICAgY29uc3Qgc2FuaXRpemVTaWduYXR1cmUgPSAoc2lnOiBCdWZmZXIpID0+IHtcbiAgICAgIGNvbnN0IHNpZ2hhc2hUeXBlID0gc2lnLmxlbmd0aCA9PT0gNjQgPyBUcmFuc2FjdGlvbi5TSUdIQVNIX0RFRkFVTFQgOiBzaWcucmVhZFVJbnQ4KHNpZy5sZW5ndGggLSAxKTtcbiAgICAgIGNvbnN0IGlucHV0U2lnaGFzaFR5cGUgPSBpbnB1dC5zaWdoYXNoVHlwZSA9PT0gdW5kZWZpbmVkID8gVHJhbnNhY3Rpb24uU0lHSEFTSF9ERUZBVUxUIDogaW5wdXQuc2lnaGFzaFR5cGU7XG4gICAgICBhc3NlcnQoc2lnaGFzaFR5cGUgPT09IGlucHV0U2lnaGFzaFR5cGUsICdzaWduYXR1cmUgc2lnaGFzaCBkb2VzIG5vdCBtYXRjaCBpbnB1dCBzaWdoYXNoIHR5cGUnKTtcbiAgICAgIC8vIFRPRE8gQlRDLTY2MyBUaGlzIHNob3VsZCBiZSBmaXhlZCBpbiBwbGF0Zm9ybS4gVGhpcyBpcyBqdXN0IGEgd29ya2Fyb3VuZCBmaXguXG4gICAgICByZXR1cm4gc2lnaGFzaFR5cGUgPT09IFRyYW5zYWN0aW9uLlNJR0hBU0hfREVGQVVMVCAmJiBzaWcubGVuZ3RoID09PSA2NSA/IHNpZy5zbGljZSgwLCA2NCkgOiBzaWc7XG4gICAgfTtcbiAgICBjb25zdCBpbnB1dCA9IGNoZWNrRm9ySW5wdXQodGhpcy5kYXRhLmlucHV0cywgaW5wdXRJbmRleCk7XG4gICAgLy8gd2l0bmVzcyA9IGNvbnRyb2wtYmxvY2sgc2NyaXB0IGZpcnN0LXNpZyBzZWNvbmQtc2lnXG4gICAgaWYgKGlucHV0LnRhcExlYWZTY3JpcHQ/Lmxlbmd0aCAhPT0gMSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdPbmx5IG9uZSBsZWFmIHNjcmlwdCBzdXBwb3J0ZWQgZm9yIGZpbmFsaXppbmcnKTtcbiAgICB9XG4gICAgY29uc3QgeyBjb250cm9sQmxvY2ssIHNjcmlwdCB9ID0gaW5wdXQudGFwTGVhZlNjcmlwdFswXTtcbiAgICBjb25zdCB3aXRuZXNzOiBCdWZmZXJbXSA9IFtzY3JpcHQsIGNvbnRyb2xCbG9ja107XG4gICAgY29uc3QgW3B1YmtleTEsIHB1YmtleTJdID0gcGFyc2VQdWJTY3JpcHQyT2YzKHNjcmlwdCwgJ3RhcHJvb3RTY3JpcHRQYXRoU3BlbmQnKS5wdWJsaWNLZXlzO1xuICAgIGZvciAoY29uc3QgcGsgb2YgW3B1YmtleTEsIHB1YmtleTJdKSB7XG4gICAgICBjb25zdCBzaWcgPSBpbnB1dC50YXBTY3JpcHRTaWc/LmZpbmQoKHsgcHVia2V5IH0pID0+IGVxdWFsUHVibGljS2V5SWdub3JlWShwaywgcHVia2V5KSk7XG4gICAgICBpZiAoIXNpZykge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ0NvdWxkIG5vdCBmaW5kIHNpZ25hdHVyZXMgaW4gU2NyaXB0IFNpZy4nKTtcbiAgICAgIH1cbiAgICAgIHdpdG5lc3MudW5zaGlmdChzYW5pdGl6ZVNpZ25hdHVyZShzaWcuc2lnbmF0dXJlKSk7XG4gICAgfVxuXG4gICAgY29uc3Qgd2l0bmVzc0xlbmd0aCA9IHdpdG5lc3MucmVkdWNlKChzLCBiKSA9PiBzICsgYi5sZW5ndGggKyB2YXJ1aW50LmVuY29kaW5nTGVuZ3RoKGIubGVuZ3RoKSwgMSk7XG5cbiAgICBjb25zdCBidWZmZXJXcml0ZXIgPSBCdWZmZXJXcml0ZXIud2l0aENhcGFjaXR5KHdpdG5lc3NMZW5ndGgpO1xuICAgIGJ1ZmZlcldyaXRlci53cml0ZVZlY3Rvcih3aXRuZXNzKTtcbiAgICBjb25zdCBmaW5hbFNjcmlwdFdpdG5lc3MgPSBidWZmZXJXcml0ZXIuZW5kKCk7XG5cbiAgICB0aGlzLmRhdGEudXBkYXRlSW5wdXQoaW5wdXRJbmRleCwgeyBmaW5hbFNjcmlwdFdpdG5lc3MgfSk7XG4gICAgdGhpcy5kYXRhLmNsZWFyRmluYWxpemVkSW5wdXQoaW5wdXRJbmRleCk7XG5cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIC8qKlxuICAgKiBGaW5hbGl6ZXMgYSB0YXByb290IG11c2lnMiBpbnB1dCBieSBhZ2dyZWdhdGluZyBhbGwgcGFydGlhbCBzaWdzLlxuICAgKiBJTVBPUlRBTlQ6IEFsd2F5cyBjYWxsIHZhbGlkYXRlKiBmdW5jdGlvbiBiZWZvcmUgZmluYWxpemluZy5cbiAgICovXG4gIGZpbmFsaXplVGFwcm9vdE11c2lnMklucHV0KGlucHV0SW5kZXg6IG51bWJlcik6IHRoaXMge1xuICAgIGNvbnN0IGlucHV0ID0gY2hlY2tGb3JJbnB1dCh0aGlzLmRhdGEuaW5wdXRzLCBpbnB1dEluZGV4KTtcbiAgICBjb25zdCBwYXJ0aWFsU2lncyA9IHBhcnNlUHNidE11c2lnMlBhcnRpYWxTaWdzKGlucHV0KTtcbiAgICBpZiAocGFydGlhbFNpZ3M/Lmxlbmd0aCAhPT0gMikge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKGBpbnZhbGlkIG51bWJlciBvZiBwYXJ0aWFsIHNpZ25hdHVyZXMgJHtwYXJ0aWFsU2lncyA/IHBhcnRpYWxTaWdzLmxlbmd0aCA6IDB9IHRvIGZpbmFsaXplYCk7XG4gICAgfVxuICAgIGNvbnN0IHsgcGFydGlhbFNpZ3M6IHBTaWdzLCBzaWdIYXNoVHlwZSB9ID0gZ2V0U2lnSGFzaFR5cGVGcm9tU2lncyhwYXJ0aWFsU2lncyk7XG4gICAgY29uc3QgeyBzZXNzaW9uS2V5IH0gPSB0aGlzLmdldE11c2lnMlNlc3Npb25LZXkoaW5wdXRJbmRleCwgc2lnSGFzaFR5cGUpO1xuXG4gICAgY29uc3QgYWdnU2lnID0gbXVzaWcyQWdncmVnYXRlU2lncyhcbiAgICAgIHBTaWdzLm1hcCgocFNpZykgPT4gcFNpZy5wYXJ0aWFsU2lnKSxcbiAgICAgIHNlc3Npb25LZXlcbiAgICApO1xuXG4gICAgY29uc3Qgc2lnID0gc2lnSGFzaFR5cGUgPT09IFRyYW5zYWN0aW9uLlNJR0hBU0hfREVGQVVMVCA/IGFnZ1NpZyA6IEJ1ZmZlci5jb25jYXQoW2FnZ1NpZywgQnVmZmVyLm9mKHNpZ0hhc2hUeXBlKV0pO1xuXG4gICAgLy8gc2luZ2xlIHNpZ25hdHVyZSB3aXRoIDY0LzY1IGJ5dGVzIHNpemUgaXMgc2NyaXB0IHdpdG5lc3MgZm9yIGtleSBwYXRoIHNwZW5kXG4gICAgY29uc3QgYnVmZmVyV3JpdGVyID0gQnVmZmVyV3JpdGVyLndpdGhDYXBhY2l0eSgxICsgdmFydWludC5lbmNvZGluZ0xlbmd0aChzaWcubGVuZ3RoKSArIHNpZy5sZW5ndGgpO1xuICAgIGJ1ZmZlcldyaXRlci53cml0ZVZlY3Rvcihbc2lnXSk7XG4gICAgY29uc3QgZmluYWxTY3JpcHRXaXRuZXNzID0gYnVmZmVyV3JpdGVyLmVuZCgpO1xuXG4gICAgdGhpcy5kYXRhLnVwZGF0ZUlucHV0KGlucHV0SW5kZXgsIHsgZmluYWxTY3JpcHRXaXRuZXNzIH0pO1xuICAgIHRoaXMuZGF0YS5jbGVhckZpbmFsaXplZElucHV0KGlucHV0SW5kZXgpO1xuICAgIC8vIGRlbGV0aW5nIG9ubHkgQml0R28gcHJvcHJpZXRhcnkga2V5IHZhbHVlcy5cbiAgICB0aGlzLmRlbGV0ZVByb3ByaWV0YXJ5S2V5VmFscyhpbnB1dEluZGV4LCB7IGlkZW50aWZpZXI6IFBTQlRfUFJPUFJJRVRBUllfSURFTlRJRklFUiB9KTtcbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIGZpbmFsaXplVGFwSW5wdXRXaXRoU2luZ2xlTGVhZlNjcmlwdEFuZFNpZ25hdHVyZShpbnB1dEluZGV4OiBudW1iZXIpOiB0aGlzIHtcbiAgICBjb25zdCBpbnB1dCA9IGNoZWNrRm9ySW5wdXQodGhpcy5kYXRhLmlucHV0cywgaW5wdXRJbmRleCk7XG4gICAgaWYgKGlucHV0LnRhcExlYWZTY3JpcHQ/Lmxlbmd0aCAhPT0gMSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdPbmx5IG9uZSBsZWFmIHNjcmlwdCBzdXBwb3J0ZWQgZm9yIGZpbmFsaXppbmcnKTtcbiAgICB9XG4gICAgaWYgKGlucHV0LnRhcFNjcmlwdFNpZz8ubGVuZ3RoICE9PSAxKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0NvdWxkIG5vdCBmaW5kIHNpZ25hdHVyZXMgaW4gU2NyaXB0IFNpZy4nKTtcbiAgICB9XG5cbiAgICBjb25zdCB7IGNvbnRyb2xCbG9jaywgc2NyaXB0IH0gPSBpbnB1dC50YXBMZWFmU2NyaXB0WzBdO1xuICAgIGNvbnN0IHdpdG5lc3M6IEJ1ZmZlcltdID0gW2lucHV0LnRhcFNjcmlwdFNpZ1swXS5zaWduYXR1cmUsIHNjcmlwdCwgY29udHJvbEJsb2NrXTtcbiAgICBjb25zdCB3aXRuZXNzTGVuZ3RoID0gd2l0bmVzcy5yZWR1Y2UoKHMsIGIpID0+IHMgKyBiLmxlbmd0aCArIHZhcnVpbnQuZW5jb2RpbmdMZW5ndGgoYi5sZW5ndGgpLCAxKTtcblxuICAgIGNvbnN0IGJ1ZmZlcldyaXRlciA9IEJ1ZmZlcldyaXRlci53aXRoQ2FwYWNpdHkod2l0bmVzc0xlbmd0aCk7XG4gICAgYnVmZmVyV3JpdGVyLndyaXRlVmVjdG9yKHdpdG5lc3MpO1xuICAgIGNvbnN0IGZpbmFsU2NyaXB0V2l0bmVzcyA9IGJ1ZmZlcldyaXRlci5lbmQoKTtcblxuICAgIHRoaXMuZGF0YS51cGRhdGVJbnB1dChpbnB1dEluZGV4LCB7IGZpbmFsU2NyaXB0V2l0bmVzcyB9KTtcbiAgICB0aGlzLmRhdGEuY2xlYXJGaW5hbGl6ZWRJbnB1dChpbnB1dEluZGV4KTtcblxuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgLyoqXG4gICAqIE1vc3RseSBjb3BpZWQgZnJvbSBiaXRjb2luanMtbGliL3RzX3NyYy9wc2J0LnRzXG4gICAqXG4gICAqIFVubGlrZSB0aGUgZnVuY3Rpb24gaXQgb3ZlcnJpZGVzLCB0aGlzIGRvZXMgbm90IHRha2UgYSB2YWxpZGF0b3IuIEluIEJpdEdvXG4gICAqIGNvbnRleHQsIHdlIGtub3cgaG93IHdlIHdhbnQgdG8gdmFsaWRhdGUgc28gd2UganVzdCBoYXJkIGNvZGUgdGhlIHJpZ2h0XG4gICAqIHZhbGlkYXRvci5cbiAgICovXG4gIHZhbGlkYXRlU2lnbmF0dXJlc09mQWxsSW5wdXRzKCk6IGJvb2xlYW4ge1xuICAgIGNoZWNrRm9ySW5wdXQodGhpcy5kYXRhLmlucHV0cywgMCk7IC8vIG1ha2luZyBzdXJlIHdlIGhhdmUgYXQgbGVhc3Qgb25lXG4gICAgY29uc3QgcmVzdWx0cyA9IHRoaXMuZGF0YS5pbnB1dHMubWFwKChpbnB1dCwgaWR4KSA9PiB7XG4gICAgICByZXR1cm4gdGhpcy52YWxpZGF0ZVNpZ25hdHVyZXNPZklucHV0Q29tbW9uKGlkeCk7XG4gICAgfSk7XG4gICAgcmV0dXJuIHJlc3VsdHMucmVkdWNlKChmaW5hbCwgcmVzKSA9PiByZXMgJiYgZmluYWwsIHRydWUpO1xuICB9XG5cbiAgLyoqXG4gICAqIEByZXR1cm5zIHRydWUgaWZmIGFueSBtYXRjaGluZyB2YWxpZCBzaWduYXR1cmUgaXMgZm91bmQgZm9yIGEgZGVyaXZlZCBwdWIga2V5IGZyb20gZ2l2ZW4gSEQga2V5IHBhaXIuXG4gICAqL1xuICB2YWxpZGF0ZVNpZ25hdHVyZXNPZklucHV0SEQoaW5wdXRJbmRleDogbnVtYmVyLCBoZEtleVBhaXI6IEJJUDMySW50ZXJmYWNlKTogYm9vbGVhbiB7XG4gICAgY29uc3QgaW5wdXQgPSBjaGVja0ZvcklucHV0KHRoaXMuZGF0YS5pbnB1dHMsIGlucHV0SW5kZXgpO1xuICAgIGNvbnN0IHB1YktleSA9IFV0eG9Qc2J0LmRlcml2ZUtleVBhaXJGb3JJbnB1dChoZEtleVBhaXIsIGlucHV0KTtcbiAgICBpZiAoIXB1YktleSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdjYW4gbm90IGRlcml2ZSBmcm9tIEhEIGtleSBwYWlyJyk7XG4gICAgfVxuICAgIHJldHVybiB0aGlzLnZhbGlkYXRlU2lnbmF0dXJlc09mSW5wdXRDb21tb24oaW5wdXRJbmRleCwgcHViS2V5KTtcbiAgfVxuXG4gIC8qKlxuICAgKiBAcmV0dXJucyB0cnVlIGlmZiBhbnkgdmFsaWQgc2lnbmF0dXJlKHMpIGFyZSBmb3VuZCBmcm9tIGJpcDMyIGRhdGEgb2YgUFNCVCBvciBmb3IgZ2l2ZW4gcHViIGtleS5cbiAgICovXG4gIHZhbGlkYXRlU2lnbmF0dXJlc09mSW5wdXRDb21tb24oaW5wdXRJbmRleDogbnVtYmVyLCBwdWJrZXk/OiBCdWZmZXIpOiBib29sZWFuIHtcbiAgICB0cnkge1xuICAgICAgaWYgKHRoaXMuaXNUYXByb290U2NyaXB0UGF0aElucHV0KGlucHV0SW5kZXgpKSB7XG4gICAgICAgIHJldHVybiB0aGlzLnZhbGlkYXRlVGFwcm9vdFNpZ25hdHVyZXNPZklucHV0KGlucHV0SW5kZXgsIHB1YmtleSk7XG4gICAgICB9IGVsc2UgaWYgKHRoaXMuaXNUYXByb290S2V5UGF0aElucHV0KGlucHV0SW5kZXgpKSB7XG4gICAgICAgIHJldHVybiB0aGlzLnZhbGlkYXRlVGFwcm9vdE11c2lnMlNpZ25hdHVyZXNPZklucHV0KGlucHV0SW5kZXgsIHB1YmtleSk7XG4gICAgICB9XG4gICAgICByZXR1cm4gdGhpcy52YWxpZGF0ZVNpZ25hdHVyZXNPZklucHV0KGlucHV0SW5kZXgsIChwLCBtLCBzKSA9PiBlY2NMaWIudmVyaWZ5KG0sIHAsIHMsIHRydWUpLCBwdWJrZXkpO1xuICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgLy8gTm90IGFuIGVsZWdhbnQgc29sdXRpb24uIE1pZ2h0IG5lZWQgdXBzdHJlYW0gY2hhbmdlcyBsaWtlIGN1c3RvbSBlcnJvciB0eXBlcy5cbiAgICAgIGlmIChlcnIubWVzc2FnZSA9PT0gJ05vIHNpZ25hdHVyZXMgZm9yIHRoaXMgcHVia2V5Jykge1xuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICB9XG4gICAgICB0aHJvdyBlcnI7XG4gICAgfVxuICB9XG5cbiAgcHJpdmF0ZSBnZXRNdXNpZzJTZXNzaW9uS2V5KFxuICAgIGlucHV0SW5kZXg6IG51bWJlcixcbiAgICBzaWdIYXNoVHlwZTogbnVtYmVyXG4gICk6IHtcbiAgICBwYXJ0aWNpcGFudHM6IFBzYnRNdXNpZzJQYXJ0aWNpcGFudHM7XG4gICAgbm9uY2VzOiBUdXBsZTxQc2J0TXVzaWcyUHViTm9uY2U+O1xuICAgIGhhc2g6IEJ1ZmZlcjtcbiAgICBzZXNzaW9uS2V5OiBTZXNzaW9uS2V5O1xuICB9IHtcbiAgICBjb25zdCBpbnB1dCA9IGNoZWNrRm9ySW5wdXQodGhpcy5kYXRhLmlucHV0cywgaW5wdXRJbmRleCk7XG4gICAgaWYgKCFpbnB1dC50YXBJbnRlcm5hbEtleSB8fCAhaW5wdXQudGFwTWVya2xlUm9vdCkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdib3RoIHRhcEludGVybmFsS2V5IGFuZCB0YXBNZXJrbGVSb290IGFyZSByZXF1aXJlZCcpO1xuICAgIH1cblxuICAgIGNvbnN0IHBhcnRpY2lwYW50cyA9IHRoaXMuZ2V0TXVzaWcyUGFydGljaXBhbnRzKGlucHV0SW5kZXgsIGlucHV0LnRhcEludGVybmFsS2V5LCBpbnB1dC50YXBNZXJrbGVSb290KTtcbiAgICBjb25zdCBub25jZXMgPSB0aGlzLmdldE11c2lnMk5vbmNlcyhpbnB1dEluZGV4LCBwYXJ0aWNpcGFudHMpO1xuXG4gICAgY29uc3QgeyBoYXNoIH0gPSB0aGlzLmdldFRhcHJvb3RIYXNoRm9yU2lnKGlucHV0SW5kZXgsIFtzaWdIYXNoVHlwZV0pO1xuXG4gICAgY29uc3Qgc2Vzc2lvbktleSA9IGNyZWF0ZU11c2lnMlNpZ25pbmdTZXNzaW9uKHtcbiAgICAgIHB1Yk5vbmNlczogW25vbmNlc1swXS5wdWJOb25jZSwgbm9uY2VzWzFdLnB1Yk5vbmNlXSxcbiAgICAgIHB1YktleXM6IHBhcnRpY2lwYW50cy5wYXJ0aWNpcGFudFB1YktleXMsXG4gICAgICB0eEhhc2g6IGhhc2gsXG4gICAgICBpbnRlcm5hbFB1YktleTogaW5wdXQudGFwSW50ZXJuYWxLZXksXG4gICAgICB0YXBUcmVlUm9vdDogaW5wdXQudGFwTWVya2xlUm9vdCxcbiAgICB9KTtcbiAgICByZXR1cm4geyBwYXJ0aWNpcGFudHMsIG5vbmNlcywgaGFzaCwgc2Vzc2lvbktleSB9O1xuICB9XG5cbiAgLyoqXG4gICAqIEByZXR1cm5zIHRydWUgZm9yIGZvbGxvd2luZyBjYXNlcy5cbiAgICogSWYgdmFsaWQgbXVzaWcyIHBhcnRpYWwgc2lnbmF0dXJlcyBleGlzdHMgZm9yIGJvdGggMiBrZXlzLCBpdCB3aWxsIGFsc28gdmVyaWZ5IGFnZ3JlZ2F0ZWQgc2lnXG4gICAqIGZvciBhZ2dyZWdhdGVkIHR3ZWFrZWQga2V5IChvdXRwdXQga2V5KSwgb3RoZXJ3aXNlIG9ubHkgdmVyaWZpZXMgcGFydGlhbCBzaWcuXG4gICAqIElmIHB1YmtleSBpcyBwYXNzZWQgaW4gaW5wdXQsIGl0IHdpbGwgY2hlY2sgc2lnIG9ubHkgZm9yIHRoYXQgcHVia2V5LFxuICAgKiBpZiBubyBzaWcgZXhpdHMgZm9yIHN1Y2gga2V5LCB0aHJvd3MgZXJyb3IuXG4gICAqIEZvciBpbnZhbGlkIHN0YXRlIG9mIGlucHV0IGRhdGEsIGl0IHdpbGwgdGhyb3cgZXJyb3JzLlxuICAgKi9cbiAgdmFsaWRhdGVUYXByb290TXVzaWcyU2lnbmF0dXJlc09mSW5wdXQoaW5wdXRJbmRleDogbnVtYmVyLCBwdWJrZXk/OiBCdWZmZXIpOiBib29sZWFuIHtcbiAgICBjb25zdCBpbnB1dCA9IGNoZWNrRm9ySW5wdXQodGhpcy5kYXRhLmlucHV0cywgaW5wdXRJbmRleCk7XG4gICAgY29uc3QgcGFydGlhbFNpZ3MgPSBwYXJzZVBzYnRNdXNpZzJQYXJ0aWFsU2lncyhpbnB1dCk7XG4gICAgaWYgKCFwYXJ0aWFsU2lncykge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKGBObyBzaWduYXR1cmVzIHRvIHZhbGlkYXRlYCk7XG4gICAgfVxuXG4gICAgbGV0IG15UGFydGlhbFNpZ3MgPSBwYXJ0aWFsU2lncztcbiAgICBpZiAocHVia2V5KSB7XG4gICAgICBteVBhcnRpYWxTaWdzID0gcGFydGlhbFNpZ3MuZmlsdGVyKChrdikgPT4gZXF1YWxQdWJsaWNLZXlJZ25vcmVZKGt2LnBhcnRpY2lwYW50UHViS2V5LCBwdWJrZXkpKTtcbiAgICAgIGlmIChteVBhcnRpYWxTaWdzPy5sZW5ndGggPCAxKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcignTm8gc2lnbmF0dXJlcyBmb3IgdGhpcyBwdWJrZXknKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBjb25zdCB7IHBhcnRpYWxTaWdzOiBteVNpZ3MsIHNpZ0hhc2hUeXBlIH0gPSBnZXRTaWdIYXNoVHlwZUZyb21TaWdzKG15UGFydGlhbFNpZ3MpO1xuICAgIGNvbnN0IHsgcGFydGljaXBhbnRzLCBub25jZXMsIGhhc2gsIHNlc3Npb25LZXkgfSA9IHRoaXMuZ2V0TXVzaWcyU2Vzc2lvbktleShpbnB1dEluZGV4LCBzaWdIYXNoVHlwZSk7XG5cbiAgICBjb25zdCByZXN1bHRzID0gbXlTaWdzLm1hcCgobXlTaWcpID0+IHtcbiAgICAgIGNvbnN0IG15Tm9uY2UgPSBub25jZXMuZmluZCgoa3YpID0+IGVxdWFsUHVibGljS2V5SWdub3JlWShrdi5wYXJ0aWNpcGFudFB1YktleSwgbXlTaWcucGFydGljaXBhbnRQdWJLZXkpKTtcbiAgICAgIGlmICghbXlOb25jZSkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ0ZvdW5kIG5vIHB1YiBub25jZSBmb3IgcHVia2V5Jyk7XG4gICAgICB9XG4gICAgICByZXR1cm4gbXVzaWcyUGFydGlhbFNpZ1ZlcmlmeShteVNpZy5wYXJ0aWFsU2lnLCBteVNpZy5wYXJ0aWNpcGFudFB1YktleSwgbXlOb25jZS5wdWJOb25jZSwgc2Vzc2lvbktleSk7XG4gICAgfSk7XG5cbiAgICAvLyBGb3IgdmFsaWQgc2luZ2xlIHNpZyBvciAxIG9yIDIgZmFpbHVyZSBzaWdzLCBubyBuZWVkIHRvIHZhbGlkYXRlIGFnZ3JlZ2F0ZWQgc2lnLiBTbyBza2lwLlxuICAgIGNvbnN0IHJlc3VsdCA9IHJlc3VsdHMuZXZlcnkoKHJlcykgPT4gcmVzKTtcbiAgICBpZiAoIXJlc3VsdCB8fCBteVNpZ3MubGVuZ3RoIDwgMikge1xuICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgICB9XG5cbiAgICBjb25zdCBhZ2dTaWcgPSBtdXNpZzJBZ2dyZWdhdGVTaWdzKFxuICAgICAgbXlTaWdzLm1hcCgobXlTaWcpID0+IG15U2lnLnBhcnRpYWxTaWcpLFxuICAgICAgc2Vzc2lvbktleVxuICAgICk7XG5cbiAgICByZXR1cm4gZWNjTGliLnZlcmlmeVNjaG5vcnIoaGFzaCwgcGFydGljaXBhbnRzLnRhcE91dHB1dEtleSwgYWdnU2lnKTtcbiAgfVxuXG4gIHZhbGlkYXRlVGFwcm9vdFNpZ25hdHVyZXNPZklucHV0KGlucHV0SW5kZXg6IG51bWJlciwgcHVia2V5PzogQnVmZmVyKTogYm9vbGVhbiB7XG4gICAgY29uc3QgaW5wdXQgPSB0aGlzLmRhdGEuaW5wdXRzW2lucHV0SW5kZXhdO1xuICAgIGNvbnN0IHRhcFNpZ3MgPSAoaW5wdXQgfHwge30pLnRhcFNjcmlwdFNpZztcbiAgICBpZiAoIWlucHV0IHx8ICF0YXBTaWdzIHx8IHRhcFNpZ3MubGVuZ3RoIDwgMSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdObyBzaWduYXR1cmVzIHRvIHZhbGlkYXRlJyk7XG4gICAgfVxuICAgIGxldCBteVNpZ3M7XG4gICAgaWYgKHB1YmtleSkge1xuICAgICAgbXlTaWdzID0gdGFwU2lncy5maWx0ZXIoKHNpZykgPT4gZXF1YWxQdWJsaWNLZXlJZ25vcmVZKHNpZy5wdWJrZXksIHB1YmtleSkpO1xuICAgICAgaWYgKG15U2lncy5sZW5ndGggPCAxKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcignTm8gc2lnbmF0dXJlcyBmb3IgdGhpcyBwdWJrZXknKTtcbiAgICAgIH1cbiAgICB9IGVsc2Uge1xuICAgICAgbXlTaWdzID0gdGFwU2lncztcbiAgICB9XG4gICAgY29uc3QgcmVzdWx0czogYm9vbGVhbltdID0gW107XG5cbiAgICBhc3NlcnQoaW5wdXQudGFwTGVhZlNjcmlwdD8ubGVuZ3RoID09PSAxLCBgc2luZ2xlIHRhcExlYWZTY3JpcHQgaXMgZXhwZWN0ZWQuIEdvdCAke2lucHV0LnRhcExlYWZTY3JpcHQ/Lmxlbmd0aH1gKTtcbiAgICBjb25zdCBbdGFwTGVhZlNjcmlwdF0gPSBpbnB1dC50YXBMZWFmU2NyaXB0O1xuICAgIGNvbnN0IHB1YktleXMgPSB0aGlzLmlzTXVsdGlzaWdUYXByb290U2NyaXB0KHRhcExlYWZTY3JpcHQuc2NyaXB0KVxuICAgICAgPyBwYXJzZVB1YlNjcmlwdDJPZjModGFwTGVhZlNjcmlwdC5zY3JpcHQsICd0YXByb290U2NyaXB0UGF0aFNwZW5kJykucHVibGljS2V5c1xuICAgICAgOiB1bmRlZmluZWQ7XG5cbiAgICBmb3IgKGNvbnN0IHBTaWcgb2YgbXlTaWdzKSB7XG4gICAgICBjb25zdCB7IHNpZ25hdHVyZSwgbGVhZkhhc2gsIHB1YmtleSB9ID0gcFNpZztcbiAgICAgIGlmIChwdWJLZXlzKSB7XG4gICAgICAgIGFzc2VydChcbiAgICAgICAgICBwdWJLZXlzLmZpbmQoKHBrKSA9PiBwdWJrZXkuZXF1YWxzKHBrKSksXG4gICAgICAgICAgJ3B1YmxpYyBrZXkgbm90IGZvdW5kIGluIHRhcCBsZWFmIHNjcmlwdCdcbiAgICAgICAgKTtcbiAgICAgIH1cbiAgICAgIGxldCBzaWdIYXNoVHlwZTogbnVtYmVyO1xuICAgICAgbGV0IHNpZzogQnVmZmVyO1xuICAgICAgaWYgKHNpZ25hdHVyZS5sZW5ndGggPT09IDY1KSB7XG4gICAgICAgIHNpZ0hhc2hUeXBlID0gc2lnbmF0dXJlWzY0XTtcbiAgICAgICAgc2lnID0gc2lnbmF0dXJlLnNsaWNlKDAsIDY0KTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHNpZ0hhc2hUeXBlID0gVHJhbnNhY3Rpb24uU0lHSEFTSF9ERUZBVUxUO1xuICAgICAgICBzaWcgPSBzaWduYXR1cmU7XG4gICAgICB9XG4gICAgICBjb25zdCB7IGhhc2ggfSA9IHRoaXMuZ2V0VGFwcm9vdEhhc2hGb3JTaWcoaW5wdXRJbmRleCwgW3NpZ0hhc2hUeXBlXSwgbGVhZkhhc2gpO1xuICAgICAgcmVzdWx0cy5wdXNoKGVjY0xpYi52ZXJpZnlTY2hub3JyKGhhc2gsIHB1YmtleSwgc2lnKSk7XG4gICAgfVxuICAgIHJldHVybiByZXN1bHRzLmV2ZXJ5KChyZXMpID0+IHJlcyk7XG4gIH1cblxuICAvKipcbiAgICogQHBhcmFtIGlucHV0SW5kZXhcbiAgICogQHBhcmFtIHJvb3ROb2RlcyBvcHRpb25hbCBpbnB1dCByb290IGJpcDMyIG5vZGVzIHRvIHZlcmlmeSB3aXRoLiBJZiBpdCBpcyBub3QgcHJvdmlkZWQsIGdsb2JhbFhwdWIgd2lsbCBiZSB1c2VkLlxuICAgKiBAcmV0dXJuIGFycmF5IG9mIGJvb2xlYW4gdmFsdWVzLiBUcnVlIHdoZW4gY29ycmVzcG9uZGluZyBpbmRleCBpbiBgcHVibGljS2V5c2AgaGFzIHNpZ25lZCB0aGUgdHJhbnNhY3Rpb24uXG4gICAqIElmIG5vIHNpZ25hdHVyZSBpbiB0aGUgdHggb3Igbm8gcHVibGljIGtleSBtYXRjaGluZyBzaWduYXR1cmUsIHRoZSB2YWxpZGF0aW9uIGlzIGNvbnNpZGVyZWQgYXMgZmFsc2UuXG4gICAqL1xuICBnZXRTaWduYXR1cmVWYWxpZGF0aW9uQXJyYXkoXG4gICAgaW5wdXRJbmRleDogbnVtYmVyLFxuICAgIHsgcm9vdE5vZGVzIH06IHsgcm9vdE5vZGVzPzogVHJpcGxlPEJJUDMySW50ZXJmYWNlPiB9ID0ge31cbiAgKTogVHJpcGxlPGJvb2xlYW4+IHtcbiAgICBpZiAoIXJvb3ROb2RlcyAmJiAoIXRoaXMuZGF0YS5nbG9iYWxNYXAuZ2xvYmFsWHB1Yj8ubGVuZ3RoIHx8ICFpc1RyaXBsZSh0aGlzLmRhdGEuZ2xvYmFsTWFwLmdsb2JhbFhwdWIpKSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdDYW5ub3QgZ2V0IHNpZ25hdHVyZSB2YWxpZGF0aW9uIGFycmF5IHdpdGhvdXQgMyBnbG9iYWwgeHB1YnMnKTtcbiAgICB9XG5cbiAgICBjb25zdCBiaXAzMnMgPSByb290Tm9kZXNcbiAgICAgID8gcm9vdE5vZGVzXG4gICAgICA6IHRoaXMuZGF0YS5nbG9iYWxNYXAuZ2xvYmFsWHB1Yj8ubWFwKCh4cHViKSA9PlxuICAgICAgICAgIEJJUDMyRmFjdG9yeShlY2NMaWIpLmZyb21CYXNlNTgoYnM1OGNoZWNrLmVuY29kZSh4cHViLmV4dGVuZGVkUHVia2V5KSlcbiAgICAgICAgKTtcblxuICAgIGlmICghYmlwMzJzKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ2VpdGhlciBnbG9iYWxNYXAgb3Igcm9vdE5vZGVzIGlzIHJlcXVpcmVkJyk7XG4gICAgfVxuXG4gICAgY29uc3QgaW5wdXQgPSBjaGVja0ZvcklucHV0KHRoaXMuZGF0YS5pbnB1dHMsIGlucHV0SW5kZXgpO1xuICAgIGlmICghZ2V0UHNidElucHV0U2lnbmF0dXJlQ291bnQoaW5wdXQpKSB7XG4gICAgICByZXR1cm4gW2ZhbHNlLCBmYWxzZSwgZmFsc2VdO1xuICAgIH1cblxuICAgIHJldHVybiBiaXAzMnMubWFwKChiaXAzMikgPT4ge1xuICAgICAgY29uc3QgcHViS2V5ID0gVXR4b1BzYnQuZGVyaXZlS2V5UGFpckZvcklucHV0KGJpcDMyLCBpbnB1dCk7XG4gICAgICBpZiAoIXB1YktleSkge1xuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICB9XG4gICAgICB0cnkge1xuICAgICAgICByZXR1cm4gdGhpcy52YWxpZGF0ZVNpZ25hdHVyZXNPZklucHV0Q29tbW9uKGlucHV0SW5kZXgsIHB1YktleSk7XG4gICAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgICAgLy8gTm90IGFuIGVsZWdhbnQgc29sdXRpb24uIE1pZ2h0IG5lZWQgdXBzdHJlYW0gY2hhbmdlcyBsaWtlIGN1c3RvbSBlcnJvciB0eXBlcy5cbiAgICAgICAgaWYgKGVyci5tZXNzYWdlID09PSAnTm8gc2lnbmF0dXJlcyBmb3IgdGhpcyBwdWJrZXknKSB7XG4gICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG4gICAgICAgIHRocm93IGVycjtcbiAgICAgIH1cbiAgICB9KSBhcyBUcmlwbGU8Ym9vbGVhbj47XG4gIH1cblxuICAvKipcbiAgICogTW9zdGx5IGNvcGllZCBmcm9tIGJpdGNvaW5qcy1saWIvdHNfc3JjL3BzYnQudHNcbiAgICovXG4gIHNpZ25BbGxJbnB1dHNIRChcbiAgICBoZEtleVBhaXI6IEhEVGFwcm9vdFNpZ25lciB8IEhEVGFwcm9vdE11c2lnMlNpZ25lcixcbiAgICBwYXJhbXM/OiBudW1iZXJbXSB8IFBhcnRpYWw8U2lnbmF0dXJlUGFyYW1zPlxuICApOiB0aGlzIHtcbiAgICBpZiAoIWhkS2V5UGFpciB8fCAhaGRLZXlQYWlyLnB1YmxpY0tleSB8fCAhaGRLZXlQYWlyLmZpbmdlcnByaW50KSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ05lZWQgSERTaWduZXIgdG8gc2lnbiBpbnB1dCcpO1xuICAgIH1cbiAgICBjb25zdCB7IHNpZ2hhc2hUeXBlcywgZGV0ZXJtaW5pc3RpYyB9ID0gdG9TaWduYXR1cmVQYXJhbXModGhpcy5uZXR3b3JrLCBwYXJhbXMpO1xuXG4gICAgY29uc3QgcmVzdWx0czogYm9vbGVhbltdID0gW107XG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCB0aGlzLmRhdGEuaW5wdXRzLmxlbmd0aDsgaSsrKSB7XG4gICAgICB0cnkge1xuICAgICAgICB0aGlzLnNpZ25JbnB1dEhEKGksIGhkS2V5UGFpciwgeyBzaWdoYXNoVHlwZXMsIGRldGVybWluaXN0aWMgfSk7XG4gICAgICAgIHJlc3VsdHMucHVzaCh0cnVlKTtcbiAgICAgIH0gY2F0Y2ggKGVycikge1xuICAgICAgICByZXN1bHRzLnB1c2goZmFsc2UpO1xuICAgICAgfVxuICAgIH1cbiAgICBpZiAocmVzdWx0cy5ldmVyeSgodikgPT4gIXYpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ05vIGlucHV0cyB3ZXJlIHNpZ25lZCcpO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIC8qKlxuICAgKiBNb3N0bHkgY29waWVkIGZyb20gYml0Y29pbmpzLWxpYi90c19zcmMvcHNidC50czpzaWduSW5wdXRIRFxuICAgKi9cbiAgc2lnblRhcHJvb3RJbnB1dEhEKFxuICAgIGlucHV0SW5kZXg6IG51bWJlcixcbiAgICBoZEtleVBhaXI6IEhEVGFwcm9vdFNpZ25lciB8IEhEVGFwcm9vdE11c2lnMlNpZ25lcixcbiAgICB7IHNpZ2hhc2hUeXBlcyA9IFtUcmFuc2FjdGlvbi5TSUdIQVNIX0RFRkFVTFQsIFRyYW5zYWN0aW9uLlNJR0hBU0hfQUxMXSwgZGV0ZXJtaW5pc3RpYyA9IGZhbHNlIH0gPSB7fVxuICApOiB0aGlzIHtcbiAgICBpZiAoIXRoaXMuaXNUYXByb290SW5wdXQoaW5wdXRJbmRleCkpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignbm90IGEgdGFwcm9vdCBpbnB1dCcpO1xuICAgIH1cbiAgICBpZiAoIWhkS2V5UGFpciB8fCAhaGRLZXlQYWlyLnB1YmxpY0tleSB8fCAhaGRLZXlQYWlyLmZpbmdlcnByaW50KSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ05lZWQgSERTaWduZXIgdG8gc2lnbiBpbnB1dCcpO1xuICAgIH1cbiAgICBjb25zdCBpbnB1dCA9IGNoZWNrRm9ySW5wdXQodGhpcy5kYXRhLmlucHV0cywgaW5wdXRJbmRleCk7XG4gICAgaWYgKCFpbnB1dC50YXBCaXAzMkRlcml2YXRpb24gfHwgaW5wdXQudGFwQmlwMzJEZXJpdmF0aW9uLmxlbmd0aCA9PT0gMCkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdOZWVkIHRhcEJpcDMyRGVyaXZhdGlvbiB0byBzaWduIFRhcHJvb3Qgd2l0aCBIRCcpO1xuICAgIH1cbiAgICBjb25zdCBteURlcml2YXRpb25zID0gaW5wdXQudGFwQmlwMzJEZXJpdmF0aW9uXG4gICAgICAubWFwKChiaXBEdikgPT4ge1xuICAgICAgICBpZiAoYmlwRHYubWFzdGVyRmluZ2VycHJpbnQuZXF1YWxzKGhkS2V5UGFpci5maW5nZXJwcmludCkpIHtcbiAgICAgICAgICByZXR1cm4gYmlwRHY7XG4gICAgICAgIH1cbiAgICAgIH0pXG4gICAgICAuZmlsdGVyKCh2KSA9PiAhIXYpIGFzIFRhcEJpcDMyRGVyaXZhdGlvbltdO1xuICAgIGlmIChteURlcml2YXRpb25zLmxlbmd0aCA9PT0gMCkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdOZWVkIG9uZSB0YXBCaXAzMkRlcml2YXRpb24gbWFzdGVyRmluZ2VycHJpbnQgdG8gbWF0Y2ggdGhlIEhEU2lnbmVyIGZpbmdlcnByaW50Jyk7XG4gICAgfVxuXG4gICAgZnVuY3Rpb24gZ2V0RGVyaXZlZE5vZGUoYmlwRHY6IFRhcEJpcDMyRGVyaXZhdGlvbik6IEhEVGFwcm9vdE11c2lnMlNpZ25lciB8IEhEVGFwcm9vdFNpZ25lciB7XG4gICAgICBjb25zdCBub2RlID0gaGRLZXlQYWlyLmRlcml2ZVBhdGgoYmlwRHYucGF0aCk7XG4gICAgICBpZiAoIWVxdWFsUHVibGljS2V5SWdub3JlWShiaXBEdi5wdWJrZXksIG5vZGUucHVibGljS2V5KSkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ3B1YmtleSBkaWQgbm90IG1hdGNoIHRhcEJpcDMyRGVyaXZhdGlvbicpO1xuICAgICAgfVxuICAgICAgcmV0dXJuIG5vZGU7XG4gICAgfVxuXG4gICAgaWYgKGlucHV0LnRhcExlYWZTY3JpcHQ/Lmxlbmd0aCkge1xuICAgICAgY29uc3Qgc2lnbmVyczogVGFwcm9vdFNpZ25lcltdID0gbXlEZXJpdmF0aW9ucy5tYXAoKGJpcER2KSA9PiB7XG4gICAgICAgIGNvbnN0IHNpZ25lciA9IGdldERlcml2ZWROb2RlKGJpcER2KTtcbiAgICAgICAgaWYgKCEoJ3NpZ25TY2hub3JyJyBpbiBzaWduZXIpKSB7XG4gICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdzaWduU2Nobm9yciBmdW5jdGlvbiBpcyByZXF1aXJlZCB0byBzaWduIHAydHInKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4geyBzaWduZXIsIGxlYWZIYXNoZXM6IGJpcER2LmxlYWZIYXNoZXMgfTtcbiAgICAgIH0pO1xuICAgICAgc2lnbmVycy5mb3JFYWNoKCh7IHNpZ25lciwgbGVhZkhhc2hlcyB9KSA9PiB0aGlzLnNpZ25UYXByb290SW5wdXQoaW5wdXRJbmRleCwgc2lnbmVyLCBsZWFmSGFzaGVzLCBzaWdoYXNoVHlwZXMpKTtcbiAgICB9IGVsc2UgaWYgKGlucHV0LnRhcEludGVybmFsS2V5Py5sZW5ndGgpIHtcbiAgICAgIGNvbnN0IHNpZ25lcnM6IE11c2lnMlNpZ25lcltdID0gbXlEZXJpdmF0aW9ucy5tYXAoKGJpcER2KSA9PiB7XG4gICAgICAgIGNvbnN0IHNpZ25lciA9IGdldERlcml2ZWROb2RlKGJpcER2KTtcbiAgICAgICAgaWYgKCEoJ3ByaXZhdGVLZXknIGluIHNpZ25lcikgfHwgIXNpZ25lci5wcml2YXRlS2V5KSB7XG4gICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdwcml2YXRlS2V5IGlzIHJlcXVpcmVkIHRvIHNpZ24gcDJ0ciBtdXNpZzInKTtcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gc2lnbmVyO1xuICAgICAgfSk7XG4gICAgICBzaWduZXJzLmZvckVhY2goKHNpZ25lcikgPT4gdGhpcy5zaWduVGFwcm9vdE11c2lnMklucHV0KGlucHV0SW5kZXgsIHNpZ25lciwgeyBzaWdoYXNoVHlwZXMsIGRldGVybWluaXN0aWMgfSkpO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHNpZ25JbnB1dChpbnB1dEluZGV4OiBudW1iZXIsIGtleVBhaXI6IFNpZ25lciwgc2lnaGFzaFR5cGVzPzogbnVtYmVyW10pOiB0aGlzIHtcbiAgICBjb25zdCB7IHNpZ2hhc2hUeXBlczogc2lnaGFzaEZvck5ldHdvcmsgfSA9IHRvU2lnbmF0dXJlUGFyYW1zKHRoaXMubmV0d29yaywgc2lnaGFzaFR5cGVzKTtcbiAgICByZXR1cm4gc3VwZXIuc2lnbklucHV0KGlucHV0SW5kZXgsIGtleVBhaXIsIHNpZ2hhc2hGb3JOZXR3b3JrKTtcbiAgfVxuXG4gIHNpZ25JbnB1dEhEKFxuICAgIGlucHV0SW5kZXg6IG51bWJlcixcbiAgICBoZEtleVBhaXI6IEhEVGFwcm9vdFNpZ25lciB8IEhEVGFwcm9vdE11c2lnMlNpZ25lcixcbiAgICBwYXJhbXM/OiBudW1iZXJbXSB8IFBhcnRpYWw8U2lnbmF0dXJlUGFyYW1zPlxuICApOiB0aGlzIHtcbiAgICBjb25zdCB7IHNpZ2hhc2hUeXBlcywgZGV0ZXJtaW5pc3RpYyB9ID0gdG9TaWduYXR1cmVQYXJhbXModGhpcy5uZXR3b3JrLCBwYXJhbXMpO1xuICAgIGlmICh0aGlzLmlzVGFwcm9vdElucHV0KGlucHV0SW5kZXgpKSB7XG4gICAgICByZXR1cm4gdGhpcy5zaWduVGFwcm9vdElucHV0SEQoaW5wdXRJbmRleCwgaGRLZXlQYWlyLCB7IHNpZ2hhc2hUeXBlcywgZGV0ZXJtaW5pc3RpYyB9KTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmV0dXJuIHN1cGVyLnNpZ25JbnB1dEhEKGlucHV0SW5kZXgsIGhkS2V5UGFpciwgc2lnaGFzaFR5cGVzKTtcbiAgICB9XG4gIH1cblxuICBwcml2YXRlIGdldE11c2lnMlBhcnRpY2lwYW50cyhpbnB1dEluZGV4OiBudW1iZXIsIHRhcEludGVybmFsS2V5OiBCdWZmZXIsIHRhcE1lcmtsZVJvb3Q6IEJ1ZmZlcikge1xuICAgIGNvbnN0IHBhcnRpY2lwYW50c0tleVZhbERhdGEgPSBwYXJzZVBzYnRNdXNpZzJQYXJ0aWNpcGFudHModGhpcy5kYXRhLmlucHV0c1tpbnB1dEluZGV4XSk7XG4gICAgaWYgKCFwYXJ0aWNpcGFudHNLZXlWYWxEYXRhKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYEZvdW5kIDAgbWF0Y2hpbmcgcGFydGljaXBhbnQga2V5IHZhbHVlIGluc3RlYWQgb2YgMWApO1xuICAgIH1cbiAgICBhc3NlcnRQc2J0TXVzaWcyUGFydGljaXBhbnRzKHBhcnRpY2lwYW50c0tleVZhbERhdGEsIHRhcEludGVybmFsS2V5LCB0YXBNZXJrbGVSb290KTtcbiAgICByZXR1cm4gcGFydGljaXBhbnRzS2V5VmFsRGF0YTtcbiAgfVxuXG4gIHByaXZhdGUgZ2V0TXVzaWcyTm9uY2VzKGlucHV0SW5kZXg6IG51bWJlciwgcGFydGljaXBhbnRzS2V5VmFsRGF0YTogUHNidE11c2lnMlBhcnRpY2lwYW50cykge1xuICAgIGNvbnN0IG5vbmNlc0tleVZhbHNEYXRhID0gcGFyc2VQc2J0TXVzaWcyTm9uY2VzKHRoaXMuZGF0YS5pbnB1dHNbaW5wdXRJbmRleF0pO1xuICAgIGlmICghbm9uY2VzS2V5VmFsc0RhdGEgfHwgIWlzVHVwbGUobm9uY2VzS2V5VmFsc0RhdGEpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgIGBGb3VuZCAke25vbmNlc0tleVZhbHNEYXRhPy5sZW5ndGggPyBub25jZXNLZXlWYWxzRGF0YS5sZW5ndGggOiAwfSBtYXRjaGluZyBub25jZSBrZXkgdmFsdWUgaW5zdGVhZCBvZiAyYFxuICAgICAgKTtcbiAgICB9XG4gICAgYXNzZXJ0UHNidE11c2lnMk5vbmNlcyhub25jZXNLZXlWYWxzRGF0YSwgcGFydGljaXBhbnRzS2V5VmFsRGF0YSk7XG4gICAgcmV0dXJuIG5vbmNlc0tleVZhbHNEYXRhO1xuICB9XG5cbiAgLyoqXG4gICAqIFNpZ25zIHAydHIgbXVzaWcyIGtleSBwYXRoIGlucHV0IHdpdGggMiBhZ2dyZWdhdGVkIGtleXMuXG4gICAqXG4gICAqIE5vdGU6IE9ubHkgY2FuIHNpZ24gZGV0ZXJtaW5pc3RpY2FsbHkgYXMgdGhlIGNvc2lnbmVyXG4gICAqIEBwYXJhbSBpbnB1dEluZGV4XG4gICAqIEBwYXJhbSBzaWduZXIgLSBYWSBwdWJsaWMga2V5IGFuZCBwcml2YXRlIGtleSBhcmUgcmVxdWlyZWRcbiAgICogQHBhcmFtIHNpZ2hhc2hUeXBlc1xuICAgKiBAcGFyYW0gZGV0ZXJtaW5pc3RpYyBJZiB0cnVlLCBzaWduIHRoZSBtdXNpZyBpbnB1dCBkZXRlcm1pbmlzdGljYWxseVxuICAgKi9cbiAgc2lnblRhcHJvb3RNdXNpZzJJbnB1dChcbiAgICBpbnB1dEluZGV4OiBudW1iZXIsXG4gICAgc2lnbmVyOiBNdXNpZzJTaWduZXIsXG4gICAgeyBzaWdoYXNoVHlwZXMgPSBbVHJhbnNhY3Rpb24uU0lHSEFTSF9ERUZBVUxULCBUcmFuc2FjdGlvbi5TSUdIQVNIX0FMTF0sIGRldGVybWluaXN0aWMgPSBmYWxzZSB9ID0ge31cbiAgKTogdGhpcyB7XG4gICAgaWYgKCF0aGlzLmlzVGFwcm9vdEtleVBhdGhJbnB1dChpbnB1dEluZGV4KSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdub3QgYSB0YXByb290IG11c2lnMiBpbnB1dCcpO1xuICAgIH1cblxuICAgIGNvbnN0IGlucHV0ID0gdGhpcy5kYXRhLmlucHV0c1tpbnB1dEluZGV4XTtcblxuICAgIGlmICghaW5wdXQudGFwSW50ZXJuYWxLZXkgfHwgIWlucHV0LnRhcE1lcmtsZVJvb3QpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignbWlzc2luZyByZXF1aXJlZCBpbnB1dCBkYXRhJyk7XG4gICAgfVxuXG4gICAgLy8gUmV0cmlldmUgYW5kIGNoZWNrIHRoYXQgd2UgaGF2ZSB0d28gcGFydGljaXBhbnQgbm9uY2VzXG4gICAgY29uc3QgcGFydGljaXBhbnRzID0gdGhpcy5nZXRNdXNpZzJQYXJ0aWNpcGFudHMoaW5wdXRJbmRleCwgaW5wdXQudGFwSW50ZXJuYWxLZXksIGlucHV0LnRhcE1lcmtsZVJvb3QpO1xuICAgIGNvbnN0IHsgdGFwT3V0cHV0S2V5LCBwYXJ0aWNpcGFudFB1YktleXMgfSA9IHBhcnRpY2lwYW50cztcbiAgICBjb25zdCBzaWduZXJQdWJLZXkgPSBwYXJ0aWNpcGFudFB1YktleXMuZmluZCgocHViS2V5KSA9PiBlcXVhbFB1YmxpY0tleUlnbm9yZVkocHViS2V5LCBzaWduZXIucHVibGljS2V5KSk7XG4gICAgaWYgKCFzaWduZXJQdWJLZXkpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignc2lnbmVyIHB1YiBrZXkgc2hvdWxkIG1hdGNoIG9uZSBvZiBwYXJ0aWNpcGFudCBwdWIga2V5cycpO1xuICAgIH1cblxuICAgIGNvbnN0IG5vbmNlcyA9IHRoaXMuZ2V0TXVzaWcyTm9uY2VzKGlucHV0SW5kZXgsIHBhcnRpY2lwYW50cyk7XG4gICAgY29uc3QgeyBoYXNoLCBzaWdoYXNoVHlwZSB9ID0gdGhpcy5nZXRUYXByb290SGFzaEZvclNpZyhpbnB1dEluZGV4LCBzaWdoYXNoVHlwZXMpO1xuXG4gICAgbGV0IHBhcnRpYWxTaWc6IEJ1ZmZlcjtcbiAgICBpZiAoZGV0ZXJtaW5pc3RpYykge1xuICAgICAgaWYgKCFlcXVhbFB1YmxpY0tleUlnbm9yZVkoc2lnbmVyUHViS2V5LCBwYXJ0aWNpcGFudFB1YktleXNbMV0pKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcignY2FuIG9ubHkgYWRkIGEgZGV0ZXJtaW5pc3RpYyBzaWduYXR1cmUgb24gdGhlIGNvc2lnbmVyJyk7XG4gICAgICB9XG5cbiAgICAgIGNvbnN0IGZpcnN0U2lnbmVyTm9uY2UgPSBub25jZXMuZmluZCgobikgPT4gZXF1YWxQdWJsaWNLZXlJZ25vcmVZKG4ucGFydGljaXBhbnRQdWJLZXksIHBhcnRpY2lwYW50UHViS2V5c1swXSkpO1xuICAgICAgaWYgKCFmaXJzdFNpZ25lck5vbmNlKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcignY291bGQgbm90IGZpbmQgdGhlIHVzZXIgbm9uY2UnKTtcbiAgICAgIH1cblxuICAgICAgcGFydGlhbFNpZyA9IG11c2lnMkRldGVybWluaXN0aWNTaWduKHtcbiAgICAgICAgcHJpdmF0ZUtleTogc2lnbmVyLnByaXZhdGVLZXksXG4gICAgICAgIG90aGVyTm9uY2U6IGZpcnN0U2lnbmVyTm9uY2UucHViTm9uY2UsXG4gICAgICAgIHB1YmxpY0tleXM6IHBhcnRpY2lwYW50UHViS2V5cyxcbiAgICAgICAgaW50ZXJuYWxQdWJLZXk6IGlucHV0LnRhcEludGVybmFsS2V5LFxuICAgICAgICB0YXBUcmVlUm9vdDogaW5wdXQudGFwTWVya2xlUm9vdCxcbiAgICAgICAgaGFzaCxcbiAgICAgIH0pLnNpZztcbiAgICB9IGVsc2Uge1xuICAgICAgY29uc3Qgc2Vzc2lvbktleSA9IGNyZWF0ZU11c2lnMlNpZ25pbmdTZXNzaW9uKHtcbiAgICAgICAgcHViTm9uY2VzOiBbbm9uY2VzWzBdLnB1Yk5vbmNlLCBub25jZXNbMV0ucHViTm9uY2VdLFxuICAgICAgICBwdWJLZXlzOiBwYXJ0aWNpcGFudFB1YktleXMsXG4gICAgICAgIHR4SGFzaDogaGFzaCxcbiAgICAgICAgaW50ZXJuYWxQdWJLZXk6IGlucHV0LnRhcEludGVybmFsS2V5LFxuICAgICAgICB0YXBUcmVlUm9vdDogaW5wdXQudGFwTWVya2xlUm9vdCxcbiAgICAgIH0pO1xuXG4gICAgICBjb25zdCBzaWduZXJOb25jZSA9IG5vbmNlcy5maW5kKChrdikgPT4gZXF1YWxQdWJsaWNLZXlJZ25vcmVZKGt2LnBhcnRpY2lwYW50UHViS2V5LCBzaWduZXJQdWJLZXkpKTtcbiAgICAgIGlmICghc2lnbmVyTm9uY2UpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdwdWJOb25jZSBpcyBtaXNzaW5nLiByZXRyeSBzaWduaW5nIHByb2Nlc3MnKTtcbiAgICAgIH1cbiAgICAgIHBhcnRpYWxTaWcgPSBtdXNpZzJQYXJ0aWFsU2lnbihzaWduZXIucHJpdmF0ZUtleSwgc2lnbmVyTm9uY2UucHViTm9uY2UsIHNlc3Npb25LZXksIHRoaXMubm9uY2VTdG9yZSk7XG4gICAgfVxuXG4gICAgaWYgKHNpZ2hhc2hUeXBlICE9PSBUcmFuc2FjdGlvbi5TSUdIQVNIX0RFRkFVTFQpIHtcbiAgICAgIHBhcnRpYWxTaWcgPSBCdWZmZXIuY29uY2F0KFtwYXJ0aWFsU2lnLCBCdWZmZXIub2Yoc2lnaGFzaFR5cGUpXSk7XG4gICAgfVxuXG4gICAgY29uc3Qgc2lnID0gZW5jb2RlUHNidE11c2lnMlBhcnRpYWxTaWcoe1xuICAgICAgcGFydGljaXBhbnRQdWJLZXk6IHNpZ25lclB1YktleSxcbiAgICAgIHRhcE91dHB1dEtleSxcbiAgICAgIHBhcnRpYWxTaWc6IHBhcnRpYWxTaWcsXG4gICAgfSk7XG4gICAgdGhpcy5hZGRQcm9wcmlldGFyeUtleVZhbFRvSW5wdXQoaW5wdXRJbmRleCwgc2lnKTtcbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHNpZ25UYXByb290SW5wdXQoXG4gICAgaW5wdXRJbmRleDogbnVtYmVyLFxuICAgIHNpZ25lcjogU2Nobm9yclNpZ25lcixcbiAgICBsZWFmSGFzaGVzOiBCdWZmZXJbXSxcbiAgICBzaWdoYXNoVHlwZXM6IG51bWJlcltdID0gW1RyYW5zYWN0aW9uLlNJR0hBU0hfREVGQVVMVCwgVHJhbnNhY3Rpb24uU0lHSEFTSF9BTExdXG4gICk6IHRoaXMge1xuICAgIGNvbnN0IGlucHV0ID0gY2hlY2tGb3JJbnB1dCh0aGlzLmRhdGEuaW5wdXRzLCBpbnB1dEluZGV4KTtcbiAgICAvLyBGaWd1cmUgb3V0IGlmIHRoaXMgaXMgc2NyaXB0IHBhdGggb3Igbm90LCBpZiBub3QsIHR3ZWFrIHRoZSBwcml2YXRlIGtleVxuICAgIGlmICghaW5wdXQudGFwTGVhZlNjcmlwdD8ubGVuZ3RoKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ3RhcExlYWZTY3JpcHQgaXMgcmVxdWlyZWQgZm9yIHAydHIgc2NyaXB0IHBhdGgnKTtcbiAgICB9XG4gICAgY29uc3QgcHVia2V5ID0gdG9YT25seVB1YmxpY0tleShzaWduZXIucHVibGljS2V5KTtcbiAgICBpZiAoaW5wdXQudGFwTGVhZlNjcmlwdC5sZW5ndGggIT09IDEpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignT25seSBvbmUgbGVhZiBzY3JpcHQgc3VwcG9ydGVkIGZvciBzaWduaW5nJyk7XG4gICAgfVxuICAgIGNvbnN0IFt0YXBMZWFmU2NyaXB0XSA9IGlucHV0LnRhcExlYWZTY3JpcHQ7XG5cbiAgICBpZiAodGhpcy5pc011bHRpc2lnVGFwcm9vdFNjcmlwdCh0YXBMZWFmU2NyaXB0LnNjcmlwdCkpIHtcbiAgICAgIGNvbnN0IHB1YktleXMgPSBwYXJzZVB1YlNjcmlwdDJPZjModGFwTGVhZlNjcmlwdC5zY3JpcHQsICd0YXByb290U2NyaXB0UGF0aFNwZW5kJykucHVibGljS2V5cztcbiAgICAgIGFzc2VydChcbiAgICAgICAgcHViS2V5cy5maW5kKChwaykgPT4gcHVia2V5LmVxdWFscyhwaykpLFxuICAgICAgICAncHVibGljIGtleSBub3QgZm91bmQgaW4gdGFwIGxlYWYgc2NyaXB0J1xuICAgICAgKTtcbiAgICB9XG5cbiAgICBjb25zdCBwYXJzZWRDb250cm9sQmxvY2sgPSB0YXByb290LnBhcnNlQ29udHJvbEJsb2NrKGVjY0xpYiwgdGFwTGVhZlNjcmlwdC5jb250cm9sQmxvY2spO1xuICAgIGNvbnN0IHsgbGVhZlZlcnNpb24gfSA9IHBhcnNlZENvbnRyb2xCbG9jaztcbiAgICBpZiAobGVhZlZlcnNpb24gIT09IHRhcExlYWZTY3JpcHQubGVhZlZlcnNpb24pIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcignVGFwIHNjcmlwdCBsZWFmIHZlcnNpb24gbWlzbWF0Y2ggd2l0aCBjb250cm9sIGJsb2NrJyk7XG4gICAgfVxuICAgIGNvbnN0IGxlYWZIYXNoID0gdGFwcm9vdC5nZXRUYXBsZWFmSGFzaChlY2NMaWIsIHBhcnNlZENvbnRyb2xCbG9jaywgdGFwTGVhZlNjcmlwdC5zY3JpcHQpO1xuICAgIGlmICghbGVhZkhhc2hlcy5maW5kKChsKSA9PiBsLmVxdWFscyhsZWFmSGFzaCkpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYFNpZ25lciBjYW5ub3Qgc2lnbiBmb3IgbGVhZiBoYXNoICR7bGVhZkhhc2gudG9TdHJpbmcoJ2hleCcpfWApO1xuICAgIH1cbiAgICBjb25zdCB7IGhhc2gsIHNpZ2hhc2hUeXBlIH0gPSB0aGlzLmdldFRhcHJvb3RIYXNoRm9yU2lnKGlucHV0SW5kZXgsIHNpZ2hhc2hUeXBlcywgbGVhZkhhc2gpO1xuICAgIGxldCBzaWduYXR1cmUgPSBzaWduZXIuc2lnblNjaG5vcnIoaGFzaCk7XG4gICAgaWYgKHNpZ2hhc2hUeXBlICE9PSBUcmFuc2FjdGlvbi5TSUdIQVNIX0RFRkFVTFQpIHtcbiAgICAgIHNpZ25hdHVyZSA9IEJ1ZmZlci5jb25jYXQoW3NpZ25hdHVyZSwgQnVmZmVyLm9mKHNpZ2hhc2hUeXBlKV0pO1xuICAgIH1cbiAgICB0aGlzLmRhdGEudXBkYXRlSW5wdXQoaW5wdXRJbmRleCwge1xuICAgICAgdGFwU2NyaXB0U2lnOiBbXG4gICAgICAgIHtcbiAgICAgICAgICBwdWJrZXksXG4gICAgICAgICAgc2lnbmF0dXJlLFxuICAgICAgICAgIGxlYWZIYXNoLFxuICAgICAgICB9LFxuICAgICAgXSxcbiAgICB9KTtcbiAgICByZXR1cm4gdGhpcztcbiAgfVxuXG4gIHByaXZhdGUgZ2V0VGFwcm9vdE91dHB1dFNjcmlwdChpbnB1dEluZGV4OiBudW1iZXIpIHtcbiAgICBjb25zdCBpbnB1dCA9IGNoZWNrRm9ySW5wdXQodGhpcy5kYXRhLmlucHV0cywgaW5wdXRJbmRleCk7XG4gICAgaWYgKGlucHV0LnRhcExlYWZTY3JpcHQ/Lmxlbmd0aCkge1xuICAgICAgcmV0dXJuIHRhcHJvb3QuY3JlYXRlVGFwcm9vdE91dHB1dFNjcmlwdCh7XG4gICAgICAgIGNvbnRyb2xCbG9jazogaW5wdXQudGFwTGVhZlNjcmlwdFswXS5jb250cm9sQmxvY2ssXG4gICAgICAgIGxlYWZTY3JpcHQ6IGlucHV0LnRhcExlYWZTY3JpcHRbMF0uc2NyaXB0LFxuICAgICAgfSk7XG4gICAgfSBlbHNlIGlmIChpbnB1dC50YXBJbnRlcm5hbEtleSAmJiBpbnB1dC50YXBNZXJrbGVSb290KSB7XG4gICAgICByZXR1cm4gdGFwcm9vdC5jcmVhdGVUYXByb290T3V0cHV0U2NyaXB0KHtcbiAgICAgICAgaW50ZXJuYWxQdWJLZXk6IGlucHV0LnRhcEludGVybmFsS2V5LFxuICAgICAgICB0YXB0cmVlUm9vdDogaW5wdXQudGFwTWVya2xlUm9vdCxcbiAgICAgIH0pO1xuICAgIH1cbiAgICB0aHJvdyBuZXcgRXJyb3IoJ25vdCBhIHRhcHJvb3QgaW5wdXQnKTtcbiAgfVxuXG4gIHByaXZhdGUgZ2V0VGFwcm9vdEhhc2hGb3JTaWcoXG4gICAgaW5wdXRJbmRleDogbnVtYmVyLFxuICAgIHNpZ2hhc2hUeXBlcz86IG51bWJlcltdLFxuICAgIGxlYWZIYXNoPzogQnVmZmVyXG4gICk6IHtcbiAgICBoYXNoOiBCdWZmZXI7XG4gICAgc2lnaGFzaFR5cGU6IG51bWJlcjtcbiAgfSB7XG4gICAgaWYgKCF0aGlzLmlzVGFwcm9vdElucHV0KGlucHV0SW5kZXgpKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ25vdCBhIHRhcHJvb3QgaW5wdXQnKTtcbiAgICB9XG4gICAgY29uc3Qgc2lnaGFzaFR5cGUgPSB0aGlzLmRhdGEuaW5wdXRzW2lucHV0SW5kZXhdLnNpZ2hhc2hUeXBlIHx8IFRyYW5zYWN0aW9uLlNJR0hBU0hfREVGQVVMVDtcbiAgICBpZiAoc2lnaGFzaFR5cGVzICYmIHNpZ2hhc2hUeXBlcy5pbmRleE9mKHNpZ2hhc2hUeXBlKSA8IDApIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICAgYFNpZ2hhc2ggdHlwZSBpcyBub3QgYWxsb3dlZC4gUmV0cnkgdGhlIHNpZ24gbWV0aG9kIHBhc3NpbmcgdGhlIGAgK1xuICAgICAgICAgIGBzaWdoYXNoVHlwZXMgYXJyYXkgb2Ygd2hpdGVsaXN0ZWQgdHlwZXMuIFNpZ2hhc2ggdHlwZTogJHtzaWdoYXNoVHlwZX1gXG4gICAgICApO1xuICAgIH1cbiAgICBjb25zdCB0eElucHV0cyA9IHRoaXMudHhJbnB1dHM7IC8vIFRoZXNlIGFyZSBzb21ld2hhdCBjb3N0bHkgdG8gZXh0cmFjdFxuICAgIGNvbnN0IHByZXZvdXRTY3JpcHRzOiBCdWZmZXJbXSA9IFtdO1xuICAgIGNvbnN0IHByZXZvdXRWYWx1ZXM6IGJpZ2ludFtdID0gW107XG5cbiAgICB0aGlzLmRhdGEuaW5wdXRzLmZvckVhY2goKGlucHV0LCBpKSA9PiB7XG4gICAgICBsZXQgcHJldm91dDtcbiAgICAgIGlmIChpbnB1dC5ub25XaXRuZXNzVXR4bykge1xuICAgICAgICAvLyBUT0RPOiBUaGlzIGNvdWxkIGJlIGNvc3RseSwgZWl0aGVyIGNhY2hlIGl0IGhlcmUsIG9yIGZpbmQgYSB3YXkgdG8gc2hhcmUgd2l0aCBzdXBlclxuICAgICAgICBjb25zdCBub25XaXRuZXNzVXR4b1R4ID0gKHRoaXMuY29uc3RydWN0b3IgYXMgdHlwZW9mIFV0eG9Qc2J0KS50cmFuc2FjdGlvbkZyb21CdWZmZXIoXG4gICAgICAgICAgaW5wdXQubm9uV2l0bmVzc1V0eG8sXG4gICAgICAgICAgdGhpcy50eC5uZXR3b3JrXG4gICAgICAgICk7XG5cbiAgICAgICAgY29uc3QgcHJldm91dEhhc2ggPSB0eElucHV0c1tpXS5oYXNoO1xuICAgICAgICBjb25zdCB1dHhvSGFzaCA9IG5vbldpdG5lc3NVdHhvVHguZ2V0SGFzaCgpO1xuXG4gICAgICAgIC8vIElmIGEgbm9uLXdpdG5lc3MgVVRYTyBpcyBwcm92aWRlZCwgaXRzIGhhc2ggbXVzdCBtYXRjaCB0aGUgaGFzaCBzcGVjaWZpZWQgaW4gdGhlIHByZXZvdXRcbiAgICAgICAgaWYgKCFwcmV2b3V0SGFzaC5lcXVhbHModXR4b0hhc2gpKSB7XG4gICAgICAgICAgdGhyb3cgbmV3IEVycm9yKGBOb24td2l0bmVzcyBVVFhPIGhhc2ggZm9yIGlucHV0ICMke2l9IGRvZXNuJ3QgbWF0Y2ggdGhlIGhhc2ggc3BlY2lmaWVkIGluIHRoZSBwcmV2b3V0YCk7XG4gICAgICAgIH1cblxuICAgICAgICBjb25zdCBwcmV2b3V0SW5kZXggPSB0eElucHV0c1tpXS5pbmRleDtcbiAgICAgICAgcHJldm91dCA9IG5vbldpdG5lc3NVdHhvVHgub3V0c1twcmV2b3V0SW5kZXhdO1xuICAgICAgfSBlbHNlIGlmIChpbnB1dC53aXRuZXNzVXR4bykge1xuICAgICAgICBwcmV2b3V0ID0gaW5wdXQud2l0bmVzc1V0eG87XG4gICAgICB9IGVsc2Uge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ05lZWQgYSBVdHhvIGlucHV0IGl0ZW0gZm9yIHNpZ25pbmcnKTtcbiAgICAgIH1cbiAgICAgIHByZXZvdXRTY3JpcHRzLnB1c2gocHJldm91dC5zY3JpcHQpO1xuICAgICAgcHJldm91dFZhbHVlcy5wdXNoKHByZXZvdXQudmFsdWUpO1xuICAgIH0pO1xuICAgIGNvbnN0IG91dHB1dFNjcmlwdCA9IHRoaXMuZ2V0VGFwcm9vdE91dHB1dFNjcmlwdChpbnB1dEluZGV4KTtcbiAgICBpZiAoIW91dHB1dFNjcmlwdC5lcXVhbHMocHJldm91dFNjcmlwdHNbaW5wdXRJbmRleF0pKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYFdpdG5lc3Mgc2NyaXB0IGZvciBpbnB1dCAjJHtpbnB1dEluZGV4fSBkb2Vzbid0IG1hdGNoIHRoZSBzY3JpcHRQdWJLZXkgaW4gdGhlIHByZXZvdXRgKTtcbiAgICB9XG4gICAgY29uc3QgaGFzaCA9IHRoaXMudHguaGFzaEZvcldpdG5lc3NWMShpbnB1dEluZGV4LCBwcmV2b3V0U2NyaXB0cywgcHJldm91dFZhbHVlcywgc2lnaGFzaFR5cGUsIGxlYWZIYXNoKTtcbiAgICByZXR1cm4geyBoYXNoLCBzaWdoYXNoVHlwZSB9O1xuICB9XG5cbiAgLyoqXG4gICAqIEFkZHMgcHJvcHJpZXRhcnkga2V5IHZhbHVlIHBhaXIgdG8gUFNCVCBpbnB1dC5cbiAgICogRGVmYXVsdCBpZGVudGlmaWVyRW5jb2RpbmcgaXMgdXRmLTggZm9yIGlkZW50aWZpZXIuXG4gICAqL1xuICBhZGRQcm9wcmlldGFyeUtleVZhbFRvSW5wdXQoaW5wdXRJbmRleDogbnVtYmVyLCBrZXlWYWx1ZURhdGE6IFByb3ByaWV0YXJ5S2V5VmFsdWUpOiB0aGlzIHtcbiAgICByZXR1cm4gdGhpcy5hZGRVbmtub3duS2V5VmFsVG9JbnB1dChpbnB1dEluZGV4LCB7XG4gICAgICBrZXk6IGVuY29kZVByb3ByaWV0YXJ5S2V5KGtleVZhbHVlRGF0YS5rZXkpLFxuICAgICAgdmFsdWU6IGtleVZhbHVlRGF0YS52YWx1ZSxcbiAgICB9KTtcbiAgfVxuXG4gIC8qKlxuICAgKiBBZGRzIG9yIHVwZGF0ZXMgKGlmIGV4aXN0cykgcHJvcHJpZXRhcnkga2V5IHZhbHVlIHBhaXIgdG8gUFNCVCBpbnB1dC5cbiAgICogRGVmYXVsdCBpZGVudGlmaWVyRW5jb2RpbmcgaXMgdXRmLTggZm9yIGlkZW50aWZpZXIuXG4gICAqL1xuICBhZGRPclVwZGF0ZVByb3ByaWV0YXJ5S2V5VmFsVG9JbnB1dChpbnB1dEluZGV4OiBudW1iZXIsIGtleVZhbHVlRGF0YTogUHJvcHJpZXRhcnlLZXlWYWx1ZSk6IHRoaXMge1xuICAgIGNvbnN0IGlucHV0ID0gY2hlY2tGb3JJbnB1dCh0aGlzLmRhdGEuaW5wdXRzLCBpbnB1dEluZGV4KTtcbiAgICBjb25zdCBrZXkgPSBlbmNvZGVQcm9wcmlldGFyeUtleShrZXlWYWx1ZURhdGEua2V5KTtcbiAgICBjb25zdCB7IHZhbHVlIH0gPSBrZXlWYWx1ZURhdGE7XG4gICAgaWYgKGlucHV0LnVua25vd25LZXlWYWxzPy5sZW5ndGgpIHtcbiAgICAgIGNvbnN0IHVrdkluZGV4ID0gaW5wdXQudW5rbm93bktleVZhbHMuZmluZEluZGV4KCh1a3YpID0+IHVrdi5rZXkuZXF1YWxzKGtleSkpO1xuICAgICAgaWYgKHVrdkluZGV4ID4gLTEpIHtcbiAgICAgICAgaW5wdXQudW5rbm93bktleVZhbHNbdWt2SW5kZXhdID0geyBrZXksIHZhbHVlIH07XG4gICAgICAgIHJldHVybiB0aGlzO1xuICAgICAgfVxuICAgIH1cbiAgICB0aGlzLmFkZFVua25vd25LZXlWYWxUb0lucHV0KGlucHV0SW5kZXgsIHtcbiAgICAgIGtleSxcbiAgICAgIHZhbHVlLFxuICAgIH0pO1xuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgLyoqXG4gICAqIFRvIHNlYXJjaCBhbnkgZGF0YSBmcm9tIHByb3ByaWV0YXJ5IGtleSB2YWx1ZSBhZ2FpbnN0IGtleWRhdGEuXG4gICAqIERlZmF1bHQgaWRlbnRpZmllckVuY29kaW5nIGlzIHV0Zi04IGZvciBpZGVudGlmaWVyLlxuICAgKi9cbiAgZ2V0UHJvcHJpZXRhcnlLZXlWYWxzKGlucHV0SW5kZXg6IG51bWJlciwga2V5U2VhcmNoPzogUHJvcHJpZXRhcnlLZXlTZWFyY2gpOiBQcm9wcmlldGFyeUtleVZhbHVlW10ge1xuICAgIGNvbnN0IGlucHV0ID0gY2hlY2tGb3JJbnB1dCh0aGlzLmRhdGEuaW5wdXRzLCBpbnB1dEluZGV4KTtcbiAgICByZXR1cm4gZ2V0UHNidElucHV0UHJvcHJpZXRhcnlLZXlWYWxzKGlucHV0LCBrZXlTZWFyY2gpO1xuICB9XG5cbiAgLyoqXG4gICAqIFRvIGRlbGV0ZSBhbnkgZGF0YSBmcm9tIHByb3ByaWV0YXJ5IGtleSB2YWx1ZS5cbiAgICogRGVmYXVsdCBpZGVudGlmaWVyRW5jb2RpbmcgaXMgdXRmLTggZm9yIGlkZW50aWZpZXIuXG4gICAqL1xuICBkZWxldGVQcm9wcmlldGFyeUtleVZhbHMoaW5wdXRJbmRleDogbnVtYmVyLCBrZXlzVG9EZWxldGU/OiBQcm9wcmlldGFyeUtleVNlYXJjaCk6IHRoaXMge1xuICAgIGNvbnN0IGlucHV0ID0gY2hlY2tGb3JJbnB1dCh0aGlzLmRhdGEuaW5wdXRzLCBpbnB1dEluZGV4KTtcbiAgICBpZiAoIWlucHV0LnVua25vd25LZXlWYWxzPy5sZW5ndGgpIHtcbiAgICAgIHJldHVybiB0aGlzO1xuICAgIH1cbiAgICBpZiAoa2V5c1RvRGVsZXRlICYmIGtleXNUb0RlbGV0ZS5zdWJ0eXBlID09PSB1bmRlZmluZWQgJiYgQnVmZmVyLmlzQnVmZmVyKGtleXNUb0RlbGV0ZS5rZXlkYXRhKSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKCdpbnZhbGlkIHByb3ByaWV0YXJ5IGtleSBzZWFyY2ggZmlsdGVyIGNvbWJpbmF0aW9uLiBzdWJ0eXBlIGlzIHJlcXVpcmVkJyk7XG4gICAgfVxuICAgIGlucHV0LnVua25vd25LZXlWYWxzID0gaW5wdXQudW5rbm93bktleVZhbHMuZmlsdGVyKChrZXlWYWx1ZSwgaSkgPT4ge1xuICAgICAgY29uc3Qga2V5ID0gZGVjb2RlUHJvcHJpZXRhcnlLZXkoa2V5VmFsdWUua2V5KTtcbiAgICAgIHJldHVybiAhKFxuICAgICAgICBrZXlzVG9EZWxldGUgPT09IHVuZGVmaW5lZCB8fFxuICAgICAgICAoa2V5c1RvRGVsZXRlLmlkZW50aWZpZXIgPT09IGtleS5pZGVudGlmaWVyICYmXG4gICAgICAgICAgKGtleXNUb0RlbGV0ZS5zdWJ0eXBlID09PSB1bmRlZmluZWQgfHxcbiAgICAgICAgICAgIChrZXlzVG9EZWxldGUuc3VidHlwZSA9PT0ga2V5LnN1YnR5cGUgJiZcbiAgICAgICAgICAgICAgKCFCdWZmZXIuaXNCdWZmZXIoa2V5c1RvRGVsZXRlLmtleWRhdGEpIHx8IGtleXNUb0RlbGV0ZS5rZXlkYXRhLmVxdWFscyhrZXkua2V5ZGF0YSkpKSkpXG4gICAgICApO1xuICAgIH0pO1xuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgcHJpdmF0ZSBjcmVhdGVNdXNpZzJOb25jZUZvcklucHV0KFxuICAgIGlucHV0SW5kZXg6IG51bWJlcixcbiAgICBrZXlQYWlyOiBCSVAzMkludGVyZmFjZSxcbiAgICBrZXlUeXBlOiAncm9vdCcgfCAnZGVyaXZlZCcsXG4gICAgcGFyYW1zOiB7IHNlc3Npb25JZD86IEJ1ZmZlcjsgZGV0ZXJtaW5pc3RpYz86IGJvb2xlYW4gfSA9IHsgZGV0ZXJtaW5pc3RpYzogZmFsc2UgfVxuICApOiBQc2J0TXVzaWcyUHViTm9uY2Uge1xuICAgIGNvbnN0IGlucHV0ID0gdGhpcy5kYXRhLmlucHV0c1tpbnB1dEluZGV4XTtcbiAgICBpZiAoIWlucHV0LnRhcEludGVybmFsS2V5KSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ3RhcEludGVybmFsS2V5IGlzIHJlcXVpcmVkIHRvIGNyZWF0ZSBub25jZScpO1xuICAgIH1cbiAgICBpZiAoIWlucHV0LnRhcE1lcmtsZVJvb3QpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcigndGFwTWVya2xlUm9vdCBpcyByZXF1aXJlZCB0byBjcmVhdGUgbm9uY2UnKTtcbiAgICB9XG4gICAgY29uc3QgZ2V0RGVyaXZlZEtleVBhaXIgPSAoKTogQklQMzJJbnRlcmZhY2UgPT4ge1xuICAgICAgaWYgKCFpbnB1dC50YXBCaXAzMkRlcml2YXRpb24/Lmxlbmd0aCkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ3RhcEJpcDMyRGVyaXZhdGlvbiBpcyByZXF1aXJlZCB0byBjcmVhdGUgbm9uY2UnKTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IGRlcml2ZWQgPSBVdHhvUHNidC5kZXJpdmVLZXlQYWlyKGtleVBhaXIsIGlucHV0LnRhcEJpcDMyRGVyaXZhdGlvbiwgeyBpZ25vcmVZOiB0cnVlIH0pO1xuICAgICAgaWYgKCFkZXJpdmVkKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcignTm8gYmlwMzJEZXJpdmF0aW9uIG1hc3RlckZpbmdlcnByaW50IG1hdGNoZWQgdGhlIEhEIGtleVBhaXIgZmluZ2VycHJpbnQnKTtcbiAgICAgIH1cbiAgICAgIHJldHVybiBkZXJpdmVkO1xuICAgIH07XG4gICAgY29uc3QgZGVyaXZlZEtleVBhaXIgPSBrZXlUeXBlID09PSAncm9vdCcgPyBnZXREZXJpdmVkS2V5UGFpcigpIDoga2V5UGFpcjtcbiAgICBpZiAoIWRlcml2ZWRLZXlQYWlyLnByaXZhdGVLZXkpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcigncHJpdmF0ZUtleSBpcyByZXF1aXJlZCB0byBjcmVhdGUgbm9uY2UnKTtcbiAgICB9XG4gICAgY29uc3QgcGFydGljaXBhbnRzID0gcGFyc2VQc2J0TXVzaWcyUGFydGljaXBhbnRzKGlucHV0KTtcbiAgICBpZiAoIXBhcnRpY2lwYW50cykge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKGBGb3VuZCAwIG1hdGNoaW5nIHBhcnRpY2lwYW50IGtleSB2YWx1ZSBpbnN0ZWFkIG9mIDFgKTtcbiAgICB9XG4gICAgYXNzZXJ0UHNidE11c2lnMlBhcnRpY2lwYW50cyhwYXJ0aWNpcGFudHMsIGlucHV0LnRhcEludGVybmFsS2V5LCBpbnB1dC50YXBNZXJrbGVSb290KTtcbiAgICBjb25zdCB7IHRhcE91dHB1dEtleSwgcGFydGljaXBhbnRQdWJLZXlzIH0gPSBwYXJ0aWNpcGFudHM7XG5cbiAgICBjb25zdCBwYXJ0aWNpcGFudFB1YktleSA9IHBhcnRpY2lwYW50UHViS2V5cy5maW5kKChwdWJLZXkpID0+XG4gICAgICBlcXVhbFB1YmxpY0tleUlnbm9yZVkocHViS2V5LCBkZXJpdmVkS2V5UGFpci5wdWJsaWNLZXkpXG4gICAgKTtcbiAgICBpZiAoIUJ1ZmZlci5pc0J1ZmZlcihwYXJ0aWNpcGFudFB1YktleSkpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcigncGFydGljaXBhbnQgcGxhaW4gcHViIGtleSBzaG91bGQgbWF0Y2ggb25lIGJpcDMyRGVyaXZhdGlvbiBwbGFpbiBwdWIga2V5Jyk7XG4gICAgfVxuXG4gICAgY29uc3QgeyBoYXNoIH0gPSB0aGlzLmdldFRhcHJvb3RIYXNoRm9yU2lnKGlucHV0SW5kZXgpO1xuXG4gICAgbGV0IHB1Yk5vbmNlOiBCdWZmZXI7XG4gICAgaWYgKHBhcmFtcy5kZXRlcm1pbmlzdGljKSB7XG4gICAgICBpZiAocGFyYW1zLnNlc3Npb25JZCkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ0Nhbm5vdCBhZGQgZXh0cmEgZW50cm9weSB3aGVuIGdlbmVyYXRpbmcgYSBkZXRlcm1pbmlzdGljIG5vbmNlJyk7XG4gICAgICB9XG4gICAgICAvLyBUaGVyZSBtdXN0IGJlIG9ubHkgMiBwYXJ0aWNpcGFudCBwdWJLZXlzIGlmIGl0IGdvdCB0byB0aGlzIHBvaW50XG4gICAgICBpZiAoIWVxdWFsUHVibGljS2V5SWdub3JlWShwYXJ0aWNpcGFudFB1YktleSwgcGFydGljaXBhbnRQdWJLZXlzWzFdKSkge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYE9ubHkgdGhlIGNvc2lnbmVyJ3Mgbm9uY2UgY2FuIGJlIHNldCBkZXRlcm1pbmlzdGljYWxseWApO1xuICAgICAgfVxuICAgICAgY29uc3Qgbm9uY2VzID0gcGFyc2VQc2J0TXVzaWcyTm9uY2VzKGlucHV0KTtcbiAgICAgIGlmICghbm9uY2VzKSB7XG4gICAgICAgIHRocm93IG5ldyBFcnJvcihgTm8gbm9uY2VzIGZvdW5kIG9uIGlucHV0ICMke2lucHV0SW5kZXh9YCk7XG4gICAgICB9XG4gICAgICBpZiAobm9uY2VzLmxlbmd0aCA+IDIpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKGBDYW5ub3QgaGF2ZSBtb3JlIHRoYW4gMiBub25jZXNgKTtcbiAgICAgIH1cbiAgICAgIGNvbnN0IGZpcnN0U2lnbmVyTm9uY2UgPSBub25jZXMuZmluZCgoa3YpID0+IGVxdWFsUHVibGljS2V5SWdub3JlWShrdi5wYXJ0aWNpcGFudFB1YktleSwgcGFydGljaXBhbnRQdWJLZXlzWzBdKSk7XG4gICAgICBpZiAoIWZpcnN0U2lnbmVyTm9uY2UpIHtcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdzaWduZXIgbm9uY2UgbXVzdCBiZSBzZXQgaWYgY29zaWduZXIgbm9uY2UgaXMgdG8gYmUgZGVyaXZlZCBkZXRlcm1pbmlzdGljYWxseScpO1xuICAgICAgfVxuXG4gICAgICBwdWJOb25jZSA9IGNyZWF0ZU11c2lnMkRldGVybWluaXN0aWNOb25jZSh7XG4gICAgICAgIHByaXZhdGVLZXk6IGRlcml2ZWRLZXlQYWlyLnByaXZhdGVLZXksXG4gICAgICAgIG90aGVyTm9uY2U6IGZpcnN0U2lnbmVyTm9uY2UucHViTm9uY2UsXG4gICAgICAgIHB1YmxpY0tleXM6IHBhcnRpY2lwYW50UHViS2V5cyxcbiAgICAgICAgaW50ZXJuYWxQdWJLZXk6IGlucHV0LnRhcEludGVybmFsS2V5LFxuICAgICAgICB0YXBUcmVlUm9vdDogaW5wdXQudGFwTWVya2xlUm9vdCxcbiAgICAgICAgaGFzaCxcbiAgICAgIH0pO1xuICAgIH0gZWxzZSB7XG4gICAgICBwdWJOb25jZSA9IEJ1ZmZlci5mcm9tKFxuICAgICAgICB0aGlzLm5vbmNlU3RvcmUuY3JlYXRlTXVzaWcyTm9uY2UoXG4gICAgICAgICAgZGVyaXZlZEtleVBhaXIucHJpdmF0ZUtleSxcbiAgICAgICAgICBwYXJ0aWNpcGFudFB1YktleSxcbiAgICAgICAgICB0YXBPdXRwdXRLZXksXG4gICAgICAgICAgaGFzaCxcbiAgICAgICAgICBwYXJhbXMuc2Vzc2lvbklkXG4gICAgICAgIClcbiAgICAgICk7XG4gICAgfVxuXG4gICAgcmV0dXJuIHsgdGFwT3V0cHV0S2V5LCBwYXJ0aWNpcGFudFB1YktleSwgcHViTm9uY2UgfTtcbiAgfVxuXG4gIHByaXZhdGUgc2V0TXVzaWcyTm9uY2VzSW5uZXIoXG4gICAga2V5UGFpcjogQklQMzJJbnRlcmZhY2UsXG4gICAga2V5VHlwZTogJ3Jvb3QnIHwgJ2Rlcml2ZWQnLFxuICAgIGlucHV0SW5kZXg/OiBudW1iZXIsXG4gICAgcGFyYW1zOiB7IHNlc3Npb25JZD86IEJ1ZmZlcjsgZGV0ZXJtaW5pc3RpYz86IGJvb2xlYW4gfSA9IHsgZGV0ZXJtaW5pc3RpYzogZmFsc2UgfVxuICApOiB0aGlzIHtcbiAgICBpZiAoa2V5UGFpci5pc05ldXRlcmVkKCkpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcigncHJpdmF0ZSBrZXkgaXMgcmVxdWlyZWQgdG8gZ2VuZXJhdGUgbm9uY2UnKTtcbiAgICB9XG4gICAgaWYgKEJ1ZmZlci5pc0J1ZmZlcihwYXJhbXMuc2Vzc2lvbklkKSAmJiBwYXJhbXMuc2Vzc2lvbklkLmxlbmd0aCAhPT0gMzIpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihgSW52YWxpZCBzZXNzaW9uSWQgc2l6ZSAke3BhcmFtcy5zZXNzaW9uSWQubGVuZ3RofWApO1xuICAgIH1cblxuICAgIGNvbnN0IGlucHV0SW5kZXhlcyA9IGlucHV0SW5kZXggPT09IHVuZGVmaW5lZCA/IFsuLi5BcnJheSh0aGlzLmlucHV0Q291bnQpLmtleXMoKV0gOiBbaW5wdXRJbmRleF07XG4gICAgaW5wdXRJbmRleGVzLmZvckVhY2goKGluZGV4KSA9PiB7XG4gICAgICBpZiAoIXRoaXMuaXNUYXByb290S2V5UGF0aElucHV0KGluZGV4KSkge1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgICBjb25zdCBub25jZSA9IHRoaXMuY3JlYXRlTXVzaWcyTm9uY2VGb3JJbnB1dChpbmRleCwga2V5UGFpciwga2V5VHlwZSwgcGFyYW1zKTtcbiAgICAgIHRoaXMuYWRkT3JVcGRhdGVQcm9wcmlldGFyeUtleVZhbFRvSW5wdXQoaW5kZXgsIGVuY29kZVBzYnRNdXNpZzJQdWJOb25jZShub25jZSkpO1xuICAgIH0pO1xuICAgIHJldHVybiB0aGlzO1xuICB9XG5cbiAgLyoqXG4gICAqIEdlbmVyYXRlcyBhbmQgc2V0cyBNdVNpZzIgbm9uY2UgdG8gdGFwcm9vdCBrZXkgcGF0aCBpbnB1dCBhdCBpbnB1dEluZGV4LlxuICAgKiBJZiBpbnB1dCBpcyBub3QgYSB0YXByb290IGtleSBwYXRoLCBubyBhY3Rpb24uXG4gICAqXG4gICAqIEBwYXJhbSBpbnB1dEluZGV4IGlucHV0IGluZGV4XG4gICAqIEBwYXJhbSBrZXlQYWlyIGRlcml2ZWQga2V5IHBhaXJcbiAgICogQHBhcmFtIHNlc3Npb25JZCBPcHRpb25hbCBleHRyYSBlbnRyb3B5LiBJZiBwcm92aWRlZCBpdCBtdXN0IGVpdGhlciBiZSBhIGNvdW50ZXIgdW5pcXVlIHRvIHRoaXMgc2VjcmV0IGtleSxcbiAgICogKGNvbnZlcnRlZCB0byBhbiBhcnJheSBvZiAzMiBieXRlcyksIG9yIDMyIHVuaWZvcm1seSByYW5kb20gYnl0ZXMuXG4gICAqIEBwYXJhbSBkZXRlcm1pbmlzdGljIElmIHRydWUsIHNldCB0aGUgY29zaWduZXIgbm9uY2UgZGV0ZXJtaW5pc3RpY2FsbHlcbiAgICovXG4gIHNldElucHV0TXVzaWcyTm9uY2UoXG4gICAgaW5wdXRJbmRleDogbnVtYmVyLFxuICAgIGRlcml2ZWRLZXlQYWlyOiBCSVAzMkludGVyZmFjZSxcbiAgICBwYXJhbXM6IHsgc2Vzc2lvbklkPzogQnVmZmVyOyBkZXRlcm1pbmlzdGljPzogYm9vbGVhbiB9ID0geyBkZXRlcm1pbmlzdGljOiBmYWxzZSB9XG4gICk6IHRoaXMge1xuICAgIHJldHVybiB0aGlzLnNldE11c2lnMk5vbmNlc0lubmVyKGRlcml2ZWRLZXlQYWlyLCAnZGVyaXZlZCcsIGlucHV0SW5kZXgsIHBhcmFtcyk7XG4gIH1cblxuICAvKipcbiAgICogR2VuZXJhdGVzIGFuZCBzZXRzIE11U2lnMiBub25jZSB0byB0YXByb290IGtleSBwYXRoIGlucHV0IGF0IGlucHV0SW5kZXguXG4gICAqIElmIGlucHV0IGlzIG5vdCBhIHRhcHJvb3Qga2V5IHBhdGgsIG5vIGFjdGlvbi5cbiAgICpcbiAgICogQHBhcmFtIGlucHV0SW5kZXggaW5wdXQgaW5kZXhcbiAgICogQHBhcmFtIGtleVBhaXIgSEQgcm9vdCBrZXkgcGFpclxuICAgKiBAcGFyYW0gc2Vzc2lvbklkIE9wdGlvbmFsIGV4dHJhIGVudHJvcHkuIElmIHByb3ZpZGVkIGl0IG11c3QgZWl0aGVyIGJlIGEgY291bnRlciB1bmlxdWUgdG8gdGhpcyBzZWNyZXQga2V5LFxuICAgKiAoY29udmVydGVkIHRvIGFuIGFycmF5IG9mIDMyIGJ5dGVzKSwgb3IgMzIgdW5pZm9ybWx5IHJhbmRvbSBieXRlcy5cbiAgICogQHBhcmFtIGRldGVybWluaXN0aWMgSWYgdHJ1ZSwgc2V0IHRoZSBjb3NpZ25lciBub25jZSBkZXRlcm1pbmlzdGljYWxseVxuICAgKi9cbiAgc2V0SW5wdXRNdXNpZzJOb25jZUhEKFxuICAgIGlucHV0SW5kZXg6IG51bWJlcixcbiAgICBrZXlQYWlyOiBCSVAzMkludGVyZmFjZSxcbiAgICBwYXJhbXM6IHsgc2Vzc2lvbklkPzogQnVmZmVyOyBkZXRlcm1pbmlzdGljPzogYm9vbGVhbiB9ID0geyBkZXRlcm1pbmlzdGljOiBmYWxzZSB9XG4gICk6IHRoaXMge1xuICAgIGNoZWNrRm9ySW5wdXQodGhpcy5kYXRhLmlucHV0cywgaW5wdXRJbmRleCk7XG4gICAgcmV0dXJuIHRoaXMuc2V0TXVzaWcyTm9uY2VzSW5uZXIoa2V5UGFpciwgJ3Jvb3QnLCBpbnB1dEluZGV4LCBwYXJhbXMpO1xuICB9XG5cbiAgLyoqXG4gICAqIEdlbmVyYXRlcyBhbmQgc2V0cyBNdVNpZzIgbm9uY2UgdG8gYWxsIHRhcHJvb3Qga2V5IHBhdGggaW5wdXRzLiBPdGhlciBpbnB1dHMgd2lsbCBiZSBza2lwcGVkLlxuICAgKlxuICAgKiBAcGFyYW0gaW5wdXRJbmRleCBpbnB1dCBpbmRleFxuICAgKiBAcGFyYW0ga2V5UGFpciBkZXJpdmVkIGtleSBwYWlyXG4gICAqIEBwYXJhbSBzZXNzaW9uSWQgT3B0aW9uYWwgZXh0cmEgZW50cm9weS4gSWYgcHJvdmlkZWQgaXQgbXVzdCBlaXRoZXIgYmUgYSBjb3VudGVyIHVuaXF1ZSB0byB0aGlzIHNlY3JldCBrZXksXG4gICAqIChjb252ZXJ0ZWQgdG8gYW4gYXJyYXkgb2YgMzIgYnl0ZXMpLCBvciAzMiB1bmlmb3JtbHkgcmFuZG9tIGJ5dGVzLlxuICAgKi9cbiAgc2V0QWxsSW5wdXRzTXVzaWcyTm9uY2UoXG4gICAga2V5UGFpcjogQklQMzJJbnRlcmZhY2UsXG4gICAgcGFyYW1zOiB7IHNlc3Npb25JZD86IEJ1ZmZlcjsgZGV0ZXJtaW5pc3RpYz86IGJvb2xlYW4gfSA9IHsgZGV0ZXJtaW5pc3RpYzogZmFsc2UgfVxuICApOiB0aGlzIHtcbiAgICByZXR1cm4gdGhpcy5zZXRNdXNpZzJOb25jZXNJbm5lcihrZXlQYWlyLCAnZGVyaXZlZCcsIHVuZGVmaW5lZCwgcGFyYW1zKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBHZW5lcmF0ZXMgYW5kIHNldHMgTXVTaWcyIG5vbmNlIHRvIGFsbCB0YXByb290IGtleSBwYXRoIGlucHV0cy4gT3RoZXIgaW5wdXRzIHdpbGwgYmUgc2tpcHBlZC5cbiAgICpcbiAgICogQHBhcmFtIGlucHV0SW5kZXggaW5wdXQgaW5kZXhcbiAgICogQHBhcmFtIGtleVBhaXIgSEQgcm9vdCBrZXkgcGFpclxuICAgKiBAcGFyYW0gc2Vzc2lvbklkIE9wdGlvbmFsIGV4dHJhIGVudHJvcHkuIElmIHByb3ZpZGVkIGl0IG11c3QgZWl0aGVyIGJlIGEgY291bnRlciB1bmlxdWUgdG8gdGhpcyBzZWNyZXQga2V5LFxuICAgKiAoY29udmVydGVkIHRvIGFuIGFycmF5IG9mIDMyIGJ5dGVzKSwgb3IgMzIgdW5pZm9ybWx5IHJhbmRvbSBieXRlcy5cbiAgICovXG4gIHNldEFsbElucHV0c011c2lnMk5vbmNlSEQoXG4gICAga2V5UGFpcjogQklQMzJJbnRlcmZhY2UsXG4gICAgcGFyYW1zOiB7IHNlc3Npb25JZD86IEJ1ZmZlcjsgZGV0ZXJtaW5pc3RpYz86IGJvb2xlYW4gfSA9IHsgZGV0ZXJtaW5pc3RpYzogZmFsc2UgfVxuICApOiB0aGlzIHtcbiAgICByZXR1cm4gdGhpcy5zZXRNdXNpZzJOb25jZXNJbm5lcihrZXlQYWlyLCAncm9vdCcsIHVuZGVmaW5lZCwgcGFyYW1zKTtcbiAgfVxuXG4gIGNsb25lKCk6IHRoaXMge1xuICAgIHJldHVybiBzdXBlci5jbG9uZSgpIGFzIHRoaXM7XG4gIH1cblxuICBleHRyYWN0VHJhbnNhY3Rpb24oZGlzYWJsZUZlZUNoZWNrID0gdHJ1ZSk6IFV0eG9UcmFuc2FjdGlvbjxiaWdpbnQ+IHtcbiAgICBjb25zdCB0eCA9IHN1cGVyLmV4dHJhY3RUcmFuc2FjdGlvbihkaXNhYmxlRmVlQ2hlY2spO1xuICAgIGlmICh0eCBpbnN0YW5jZW9mIFV0eG9UcmFuc2FjdGlvbikge1xuICAgICAgcmV0dXJuIHR4O1xuICAgIH1cbiAgICB0aHJvdyBuZXcgRXJyb3IoJ2V4dHJhY3RUcmFuc2FjdGlvbiBkaWQgbm90IHJldHVybiBpbnN0YWNlIG9mIFV0eG9UcmFuc2FjdGlvbicpO1xuICB9XG59XG4iXX0=