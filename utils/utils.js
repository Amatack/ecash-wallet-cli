const bip39 = require('bip39');
const crypto = require('crypto')
const utxolib = require('../modules/@bitgo/utxo-lib');
const BigNumber = require('bignumber.js');
const slpMdm = require('slp-mdm');
const cashaddr = require ('ecashaddrjs');

const ETOKEN_SATS = 546;
const DUST_SATS = 550;
const DEFAULT_FEE = 2.01;

const generateTokenTxInput = (
    tokenAction, // GENESIS, SEND or BURN
    totalXecUtxos,
    totalTokenUtxos,
    tokenId,
    tokenAmount, // optional - only for sending or burning
    feeInSatsPerByte,
    txBuilder,
) => {
    let totalXecInputUtxoValue = new BigNumber(0);
    let remainderXecValue = new BigNumber(0);
    let remainderTokenValue = new BigNumber(0);
    let totalXecInputUtxos = [];
    let txFee = 0;
    let tokenUtxosBeingSpent = [];

    try {
        if (
            !tokenAction ||
            !totalXecUtxos ||
            (tokenAction !== 'GENESIS' && !tokenId) ||
            !feeInSatsPerByte ||
            !txBuilder
        ) {
            throw new Error('Invalid token tx input parameter');
        }

        // collate XEC UTXOs for this token tx
        const txOutputs =
            tokenAction === 'GENESIS'
                ? 2 // one for genesis OP_RETURN output and one for change
                : 4; // for SEND/BURN token txs see T2645 on why this is not dynamically generated
        for (let i = 0; i < totalXecUtxos.length; i++) {
            const thisXecUtxo = totalXecUtxos[i];
            totalXecInputUtxoValue = totalXecInputUtxoValue.plus(
                new BigNumber(thisXecUtxo.value),
            );
            const vout = thisXecUtxo.outpoint.outIdx;
            const txid = thisXecUtxo.outpoint.txid;
            // add input with txid and index of vout
            txBuilder.addInput(txid, vout);

            totalXecInputUtxos.push(thisXecUtxo);
            txFee = calcFee(totalXecInputUtxos, txOutputs, feeInSatsPerByte);

            remainderXecValue =
                tokenAction === 'GENESIS'
                    ? totalXecInputUtxoValue
                            .minus(new BigNumber(ETOKEN_SATS))
                            .minus(new BigNumber(txFee))
                    : totalXecInputUtxoValue
                            .minus(new BigNumber(ETOKEN_SATS * 2)) // one for token send/burn output, one for token change
                            .minus(new BigNumber(txFee));

            if (remainderXecValue.gte(0)) {
                break;
            }
        }

        if (remainderXecValue.lt(0)) {
            throw new Error(`Insufficient funds`);
        }

        let filteredTokenInputUtxos = [];
        let finalTokenAmountSpent = new BigNumber(0);
        let tokenAmountBeingSpent = new BigNumber(tokenAmount);

        if (tokenAction === 'SEND' || tokenAction === 'BURN') {
            // filter for token UTXOs matching the token being sent/burnt
            filteredTokenInputUtxos = totalTokenUtxos.filter(utxo => {
                if (
                    utxo && // UTXO is associated with a token.
                    utxo.slpMeta.tokenId === tokenId && // UTXO matches the token ID.
                    !utxo.slpToken.isMintBaton // UTXO is not a minting baton.
                ) {
                    return true;
                }
                return false;
            });
            if (filteredTokenInputUtxos.length === 0) {
                throw new Error(
                    'No token UTXOs for the specified token could be found.',
                );
            }

            // collate token UTXOs to cover the token amount being sent/burnt
            for (let i = 0; i < filteredTokenInputUtxos.length; i++) {
                finalTokenAmountSpent = finalTokenAmountSpent.plus(
                    new BigNumber(filteredTokenInputUtxos[i].tokenQty),
                );
                txBuilder.addInput(
                    filteredTokenInputUtxos[i].outpoint.txid,
                    filteredTokenInputUtxos[i].outpoint.outIdx,
                );
                tokenUtxosBeingSpent.push(filteredTokenInputUtxos[i]);
                if (tokenAmountBeingSpent.lte(finalTokenAmountSpent)) {
                    break;
                }
            }

            // calculate token change
            remainderTokenValue = finalTokenAmountSpent.minus(
                new BigNumber(tokenAmount),
            );
            if (remainderTokenValue.lt(0)) {
                throw new Error(
                    'Insufficient token UTXOs for the specified token amount.',
                );
            }
        }
    } catch (err) {
        console.log(`generateTokenTxInput() error: ` + err);
        throw err;
    }

    return {
        txBuilder: txBuilder,
        inputXecUtxos: totalXecInputUtxos,
        inputTokenUtxos: tokenUtxosBeingSpent,
        remainderXecValue: remainderXecValue,
        remainderTokenValue: remainderTokenValue,
    };
};

const generateTokenTxOutput = (
    txBuilder,
    tokenAction,
    legacyCashOriginAddress,
    tokenUtxosBeingSpent = [], // optional - send or burn tx only
    remainderXecValue = new BigNumber(0), // optional - only if > dust
    tokenConfigObj = {}, // optional - genesis only
    tokenRecipientAddress = false, // optional - send tx only
    tokenAmount = false, // optional - send or burn amount for send/burn tx only
) => {
    try {
        if (!tokenAction || !legacyCashOriginAddress || !txBuilder) {
            throw new Error('Invalid token tx output parameter');
        }

        let script, opReturnObj, destinationAddress;
        switch (tokenAction) {
            case 'GENESIS':
                script = generateGenesisOpReturn(tokenConfigObj);
                destinationAddress = legacyCashOriginAddress;
                break;
            case 'SEND':
                opReturnObj = generateSendOpReturn(
                    tokenUtxosBeingSpent,
                    tokenAmount.toString(),
                );
                script = opReturnObj.script;
                destinationAddress = tokenRecipientAddress;
                break;
            case 'BURN':
                script = generateBurnOpReturn(
                    tokenUtxosBeingSpent,
                    tokenAmount,
                );
                destinationAddress = legacyCashOriginAddress;
                break;
            default:
                throw new Error('Invalid token transaction type');
        }

        // OP_RETURN needs to be the first output in the transaction.
        txBuilder.addOutput(script, 0);

        // add XEC dust output as fee for genesis, send or burn token output
        txBuilder.addOutput(
            cashaddr.toLegacy(destinationAddress),
            parseInt(ETOKEN_SATS),
        );

        // Return any token change back to the sender for send and burn txs
        if (
            tokenAction !== 'GENESIS' ||
            (opReturnObj && opReturnObj.outputs > 1)
        ) {
            // add XEC dust output as fee
            txBuilder.addOutput(
                cashaddr.toLegacy(legacyCashOriginAddress),
                parseInt(ETOKEN_SATS),
            );
        }

        // Send xec change to own address
        if (remainderXecValue.gte(new BigNumber(DUST_SATS))) {
            txBuilder.addOutput(
                cashaddr.toLegacy(legacyCashOriginAddress),
                parseInt(remainderXecValue),
            );
        }
    } catch (err) {
        console.log(`generateTokenTxOutput() error: ` + err);
        throw err;
    }

    return txBuilder;
};

const generateSendOpReturn = (tokenUtxos, sendQty) => {
    try {
        if (!tokenUtxos || !sendQty) {
            throw new Error('Invalid send token parameter');
        }
        const tokenId = tokenUtxos[0].slpMeta.tokenId;
        const decimals = 2;
        // account for token decimals
        const finalSendTokenQty = new BigNumber(sendQty).times(10 ** decimals);
        const finalSendTokenQtyStr = finalSendTokenQty.toString();

        // Calculate the total amount of tokens owned by the wallet.
        const totalTokens = tokenUtxos.reduce(
            (tot, txo) =>
                tot.plus(new BigNumber(txo.slpToken.amount)),
            new BigNumber(0),
        );

        // calculate token change
        const tokenChange = totalTokens.minus(finalSendTokenQty);
        const tokenChangeStr = tokenChange.toString();

        // When token change output is required
        let script, outputs;
        if (tokenChange > 0) {
            outputs = 2;
            // Generate the OP_RETURN as a Buffer.
            script = slpMdm.TokenType1.send(tokenId, [
                new slpMdm.BN(finalSendTokenQtyStr),
                new slpMdm.BN(tokenChangeStr),
            ]);
        } else {
            // no token change needed
            outputs = 1;
            // Generate the OP_RETURN as a Buffer.
            script = slpMdm.TokenType1.send(tokenId, [
                new slpMdm.BN(finalSendTokenQtyStr),
            ]);
        }

        return { script, outputs };
    } catch (err) {
        console.log('Error in generateSendOpReturn(): ' + err);
        throw err;
    }
};

const generateGenesisOpReturn = configObj => {
    try {
        if (!configObj) {
            throw new Error('Invalid token configuration');
        }

        // adjust initial quantity for token decimals
        const initialQty = new BigNumber(configObj.initialQty)
            .times(10 ** configObj.decimals)
            .toString();

        const script = slpMdm.TokenType1.genesis(
            configObj.ticker,
            configObj.name,
            configObj.documentUrl,
            configObj.documentHash,
            configObj.decimals,
            configObj.mintBatonVout,
            new slpMdm.BN(initialQty),
        );

        return script;
    } catch (err) {
        console.log('Error in generateGenesisOpReturn(): ' + err);
        throw err;
    }
};

const getCashtabByteCount = (p2pkhInputCount, p2pkhOutputCount) => {
    // Simplifying bch-js function for P2PKH txs only, as this is all Cashtab supports for now
    // https://github.com/Permissionless-Software-Foundation/bch-js/blob/master/src/bitcoincash.js#L408
    // The below magic numbers refer to:
    // const types = {
    //     inputs: {
    //         'P2PKH': 148 * 4,
    //     },
    //     outputs: {
    //         P2PKH: 34 * 4,
    //     },
    // };

    const inputCount = new BigNumber(p2pkhInputCount);
    const outputCount = new BigNumber(p2pkhOutputCount);
    const inputWeight = new BigNumber(148 * 4);
    const outputWeight = new BigNumber(34 * 4);
    const nonSegwitWeightConstant = new BigNumber(10 * 4);
    let totalWeight = new BigNumber(0);
    totalWeight = totalWeight
        .plus(inputCount.times(inputWeight))
        .plus(outputCount.times(outputWeight))
        .plus(nonSegwitWeightConstant);
    const byteCount = totalWeight.div(4).integerValue(BigNumber.ROUND_CEIL);

    return Number(byteCount);
};

const calcFee = (
    utxos,
    p2pkhOutputNumber = 2,
    satoshisPerByte = DEFAULT_FEE,
    opReturnByteCount = 0,
) => {
    const byteCount = getCashtabByteCount(utxos.length, p2pkhOutputNumber);
    const txFee = Math.ceil(satoshisPerByte * (byteCount + opReturnByteCount));
    return txFee;
};

const signAndBuildTx = (inputUtxos, txBuilder, wallet) => {
    if (!inputUtxos || inputUtxos.length === 0 || !txBuilder || !wallet) {
        throw new Error('Invalid buildTx parameter');
    }

    // Sign each XEC UTXO being consumed and refresh transactionBuilder
    txBuilder = signUtxosByAddress(inputUtxos, wallet, txBuilder);

    let hex;
    try {
        // build tx
        const tx = txBuilder.build();
        // output rawhex
        hex = tx.toHex();
    } catch (err) {
        throw new Error('Transaction build failed');
    }
    return hex;
};

const parseChronikUtxos = (chronikUtxos) => {
    const xecUtxos = []; // to store the XEC utxos
    const slpUtxos = []; // to store the SLP utxos

    // Chronik returns an array containing a single object if an address has utxos
    //   e.g. [{
    //      outputScript: ...,
    //      utxos: [{...}, {...}}],
    //    }]
    // hence the need to extract the embedded `utxos` array within.

    // If the wallet has no utxos, return in structured format
    if (!chronikUtxos || chronikUtxos.length === 0) {
        return {
            xecUtxos: [],
            slpUtxos: [],
        };
    }
    const chronikUtxosTrimmed = chronikUtxos[0].utxos;

    try {
        // Separate SLP utoxs from XEC utxos
        for (let i = 0; i < chronikUtxosTrimmed.length; i += 1) {
            const thisUtxo = chronikUtxosTrimmed[i];
            if (thisUtxo.slpToken) {
                slpUtxos.push(thisUtxo);
            } else {
                xecUtxos.push(thisUtxo);
            }
        }
    } catch (err) {
        console.log(`parseChronikUtxos(): Error parsing chronik utxos.`);
        throw err;
    }

    return {
        xecUtxos: xecUtxos,
        slpUtxos: slpUtxos,
    };
};

/**
 * Derives the wallet's funding wif based on the supplied mnemonic and derivation path
 * Refer to the createWallet.js example for background on key wallet attributes
 *
 * @param {string} senderMnemonic the 12 word mnemonic seed for the sending wallet
 * @param {string} derivationPath the derivation path used for the sending wallet
 * @param {string} senderAddress the eCash address of the sender
 * @returns {object} wallet the populated wallet object for use throughout sendToken()
 */
async function deriveWallet(senderMnemonic, derivationPath, senderAddress, index) {
    // Derive wallet attributes
    const rootSeedBuffer = await bip39.mnemonicToSeed(senderMnemonic, '');
    const masterHDNode = utxolib.bip32.fromSeed(
        rootSeedBuffer,
        utxolib.networks.ecash,
    );

    // Extract the wallet's wif (wallet import format), which is used to sign the transaction
    const fundingWif = masterHDNode.derivePath(derivationPath).derive(Number(index)).toWIF();

    const wallet = {
        address: senderAddress,
        mnemonic: senderMnemonic,
        fundingWif: fundingWif,
        derivationPath: derivationPath,
    };

    return wallet;
}

const signUtxosByAddress = (inputUtxos, wallet, txBuilder) => {
    for (let i = 0; i < inputUtxos.length; i++) {
        const utxo = inputUtxos[i];
        const wif = wallet.fundingWif;
        const utxoECPair = utxolib.ECPair.fromWIF(wif, utxolib.networks.ecash);

        // Specify hash type
        // This should be handled at the utxo-lib level, pending latest published version
        const hashTypes = {
            SIGHASH_ALL: 0x01,
            SIGHASH_FORKID: 0x40,
        };

        txBuilder.sign(
            i, // vin
            utxoECPair, // keyPair
            undefined, // redeemScript
            hashTypes.SIGHASH_ALL | hashTypes.SIGHASH_FORKID, // hashType
            parseInt(utxo.value), // value
        );
    }

    return txBuilder;
};

const decryptMnemonic = (encryptedMnemonic, iv, password) => {
    const cipherKey2 = crypto.createHash('sha256').update(password).digest();
        // Crear el descifrador utilizando createDecipheriv
    const decipher = crypto.createDecipheriv('aes-256-cbc', cipherKey2, iv);
    // Descifrar el texto
    
    let decryptedMnemonic = decipher.update(encryptedMnemonic, 'hex', 'utf8');
    return decryptedMnemonic += decipher.final('utf8');
};

const encryptWithPublicKey = (text, publicKey) => {
    const bufferText = Buffer.from(text, 'utf-8');
    const encrypted = crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING }, bufferText);
    return encrypted.toString('base64');
};

module.exports = {
    decryptMnemonic,
    encryptWithPublicKey,
    generateTokenTxInput,
    generateTokenTxOutput,
    signAndBuildTx,
    parseChronikUtxos,
    deriveWallet,
};