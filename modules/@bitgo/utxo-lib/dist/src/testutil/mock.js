"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.mockUnspents = exports.mockWalletUnspent = exports.mockReplayProtectionUnspent = exports.isReplayProtectionUnspent = exports.replayProtectionKeyPair = exports.mockPrevTx = void 0;
const assert = require("assert");
const noble = require("@noble/secp256k1");
const utxolib = require("..");
const networks_1 = require("../networks");
const bitgo_1 = require("../bitgo");
const address_1 = require("../address");
const outputScripts_1 = require("../bitgo/outputScripts");
const keys_1 = require("./keys");
function mockPrevTx(vout, outputScript, value, network) {
    const psbtFromNetwork = bitgo_1.createPsbtForNetwork({ network });
    const keypair = keys_1.getKey('mock-prev-tx');
    const pubkey = keypair.publicKey;
    assert(keypair.privateKey);
    const payment = utxolib.payments.p2wpkh({ pubkey });
    const destOutput = payment.output;
    if (!destOutput)
        throw new Error('Impossible, payment we just constructed has no output');
    for (let index = 0; index <= vout; index++) {
        if (index === vout) {
            psbtFromNetwork.addOutput({ script: outputScript, value });
        }
        else {
            psbtFromNetwork.addOutput({ script: destOutput, value });
        }
    }
    psbtFromNetwork.addInput({
        hash: Buffer.alloc(32, 0x01),
        index: 0,
        witnessUtxo: { script: destOutput, value: value * (BigInt(vout) + BigInt(1)) + BigInt(1000) },
    });
    psbtFromNetwork.signInput(0, {
        publicKey: pubkey,
        sign: (hash, lowR) => Buffer.from(noble.signSync(hash, keypair.privateKey, { canonical: !lowR, der: false })),
    });
    psbtFromNetwork.validateSignaturesOfAllInputs();
    psbtFromNetwork.finalizeAllInputs();
    return psbtFromNetwork.extractTransaction();
}
exports.mockPrevTx = mockPrevTx;
exports.replayProtectionKeyPair = keys_1.getKey('replay-protection');
const replayProtectionScriptPubKey = outputScripts_1.createOutputScriptP2shP2pk(exports.replayProtectionKeyPair.publicKey).scriptPubKey;
function isReplayProtectionUnspent(u, network) {
    return u.address === address_1.fromOutputScript(replayProtectionScriptPubKey, network);
}
exports.isReplayProtectionUnspent = isReplayProtectionUnspent;
function mockReplayProtectionUnspent(network, value, { key = exports.replayProtectionKeyPair, vout = 0 } = {}) {
    const outputScript = outputScripts_1.createOutputScriptP2shP2pk(key.publicKey).scriptPubKey;
    const prevTransaction = mockPrevTx(vout, outputScript, BigInt(value), network);
    return { ...bitgo_1.fromOutputWithPrevTx(prevTransaction, vout), value };
}
exports.mockReplayProtectionUnspent = mockReplayProtectionUnspent;
function mockWalletUnspent(network, value, { chain = 0, index = 0, keys = keys_1.getDefaultWalletKeys(), vout = 0, id, } = {}) {
    const derivedKeys = keys.deriveForChainAndIndex(chain, index);
    const address = address_1.fromOutputScript(outputScripts_1.createOutputScript2of3(derivedKeys.publicKeys, bitgo_1.scriptTypeForChain(chain)).scriptPubKey, network);
    if (id && typeof id === 'string') {
        return { id, address, chain, index, value };
    }
    else {
        const prevTransaction = mockPrevTx(vout, outputScripts_1.createOutputScript2of3(derivedKeys.publicKeys, bitgo_1.scriptTypeForChain(chain), network).scriptPubKey, BigInt(value), network);
        const unspent = bitgo_1.isSegwit(chain) || networks_1.getMainnet(network) === networks_1.networks.zcash
            ? bitgo_1.fromOutput(prevTransaction, vout)
            : bitgo_1.fromOutputWithPrevTx(prevTransaction, vout);
        return {
            ...unspent,
            chain,
            index,
            value,
        };
    }
}
exports.mockWalletUnspent = mockWalletUnspent;
function mockUnspents(rootWalletKeys, inputScriptTypes, testOutputAmount, network) {
    return inputScriptTypes.map((t, i) => {
        if (bitgo_1.outputScripts.isScriptType2Of3(t)) {
            return mockWalletUnspent(network, testOutputAmount, {
                keys: rootWalletKeys,
                chain: bitgo_1.getExternalChainCode(t),
                vout: i,
            });
        }
        else if (t === bitgo_1.outputScripts.scriptTypeP2shP2pk) {
            return mockReplayProtectionUnspent(network, testOutputAmount, {
                key: exports.replayProtectionKeyPair,
                vout: i,
            });
        }
        throw new Error(`invalid input type ${t}`);
    });
}
exports.mockUnspents = mockUnspents;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoibW9jay5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy90ZXN0dXRpbC9tb2NrLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUFBLGlDQUFpQztBQUVqQywwQ0FBMEM7QUFDMUMsOEJBQThCO0FBQzlCLDBDQUE0RDtBQUU1RCxvQ0Fla0I7QUFDbEIsd0NBQThDO0FBQzlDLDBEQUE0RjtBQUU1RixpQ0FBc0Q7QUFJdEQsU0FBZ0IsVUFBVSxDQUN4QixJQUFZLEVBQ1osWUFBb0IsRUFDcEIsS0FBYSxFQUNiLE9BQWdCO0lBRWhCLE1BQU0sZUFBZSxHQUFHLDRCQUFvQixDQUFDLEVBQUUsT0FBTyxFQUFFLENBQUMsQ0FBQztJQUUxRCxNQUFNLE9BQU8sR0FBRyxhQUFNLENBQUMsY0FBYyxDQUFDLENBQUM7SUFDdkMsTUFBTSxNQUFNLEdBQUcsT0FBTyxDQUFDLFNBQVMsQ0FBQztJQUNqQyxNQUFNLENBQUMsT0FBTyxDQUFDLFVBQVUsQ0FBQyxDQUFDO0lBQzNCLE1BQU0sT0FBTyxHQUFHLE9BQU8sQ0FBQyxRQUFRLENBQUMsTUFBTSxDQUFDLEVBQUUsTUFBTSxFQUFFLENBQUMsQ0FBQztJQUNwRCxNQUFNLFVBQVUsR0FBRyxPQUFPLENBQUMsTUFBTSxDQUFDO0lBQ2xDLElBQUksQ0FBQyxVQUFVO1FBQUUsTUFBTSxJQUFJLEtBQUssQ0FBQyx1REFBdUQsQ0FBQyxDQUFDO0lBRTFGLEtBQUssSUFBSSxLQUFLLEdBQUcsQ0FBQyxFQUFFLEtBQUssSUFBSSxJQUFJLEVBQUUsS0FBSyxFQUFFLEVBQUU7UUFDMUMsSUFBSSxLQUFLLEtBQUssSUFBSSxFQUFFO1lBQ2xCLGVBQWUsQ0FBQyxTQUFTLENBQUMsRUFBRSxNQUFNLEVBQUUsWUFBWSxFQUFFLEtBQUssRUFBRSxDQUFDLENBQUM7U0FDNUQ7YUFBTTtZQUNMLGVBQWUsQ0FBQyxTQUFTLENBQUMsRUFBRSxNQUFNLEVBQUUsVUFBVSxFQUFFLEtBQUssRUFBRSxDQUFDLENBQUM7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Q0FBQyxFQUFFLENBQUMsQ0FBQztJQUM3QyxDQUFDLENBQUMsQ0FBQztBQUNMLENBQUM7QUFyQkQsb0NBcUJDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0ICogYXMgYXNzZXJ0IGZyb20gJ2Fzc2VydCc7XG5pbXBvcnQgeyBCSVAzMkludGVyZmFjZSB9IGZyb20gJ2JpcDMyJztcbmltcG9ydCAqIGFzIG5vYmxlIGZyb20gJ0Bub2JsZS9zZWNwMjU2azEnO1xuaW1wb3J0ICogYXMgdXR4b2xpYiBmcm9tICcuLic7XG5pbXBvcnQgeyBnZXRNYWlubmV0LCBOZXR3b3JrLCBuZXR3b3JrcyB9IGZyb20gJy4uL25ldHdvcmtzJztcblxuaW1wb3J0IHtcbiAgQ2hhaW5Db2RlLFxuICBjcmVhdGVQc2J0Rm9yTmV0d29yayxcbiAgZnJvbU91dHB1dCxcbiAgZnJvbU91dHB1dFdpdGhQcmV2VHgsXG4gIGdldEV4dGVybmFsQ2hhaW5Db2RlLFxuICBpc1NlZ3dpdCxcbiAgTm9uV2l0bmVzc1dhbGxldFVuc3BlbnQsXG4gIG91dHB1dFNjcmlwdHMsXG4gIFJvb3RXYWxsZXRLZXlzLFxuICBzY3JpcHRUeXBlRm9yQ2hhaW4sXG4gIFVuc3BlbnQsXG4gIFVuc3BlbnRXaXRoUHJldlR4LFxuICBVdHhvVHJhbnNhY3Rpb24sXG4gIFdhbGxldFVuc3BlbnQsXG59IGZyb20gJy4uL2JpdGdvJztcbmltcG9ydCB7IGZyb21PdXRwdXRTY3JpcHQgfSBmcm9tICcuLi9hZGRyZXNzJztcbmltcG9ydCB7IGNyZWF0ZU91dHB1dFNjcmlwdDJvZjMsIGNyZWF0ZU91dHB1dFNjcmlwdFAyc2hQMnBrIH0gZnJvbSAnLi4vYml0Z28vb3V0cHV0U2NyaXB0cyc7XG5cbmltcG9ydCB7IGdldERlZmF1bHRXYWxsZXRLZXlzLCBnZXRLZXkgfSBmcm9tICcuL2tleXMnO1xuXG5leHBvcnQgdHlwZSBJbnB1dFR5cGUgPSBvdXRwdXRTY3JpcHRzLlNjcmlwdFR5cGUyT2YzO1xuXG5leHBvcnQgZnVuY3Rpb24gbW9ja1ByZXZUeChcbiAgdm91dDogbnVtYmVyLFxuICBvdXRwdXRTY3JpcHQ6IEJ1ZmZlcixcbiAgdmFsdWU6IGJpZ2ludCxcbiAgbmV0d29yazogTmV0d29ya1xuKTogVXR4b1RyYW5zYWN0aW9uPGJpZ2ludD4ge1xuICBjb25zdCBwc2J0RnJvbU5ldHdvcmsgPSBjcmVhdGVQc2J0Rm9yTmV0d29yayh7IG5ldHdvcmsgfSk7XG5cbiAgY29uc3Qga2V5cGFpciA9IGdldEtleSgnbW9jay1wcmV2LXR4Jyk7XG4gIGNvbnN0IHB1YmtleSA9IGtleXBhaXIucHVibGljS2V5O1xuICBhc3NlcnQoa2V5cGFpci5wcml2YXRlS2V5KTtcbiAgY29uc3QgcGF5bWVudCA9IHV0eG9saWIucGF5bWVudHMucDJ3cGtoKHsgcHVia2V5IH0pO1xuICBjb25zdCBkZXN0T3V0cHV0ID0gcGF5bWVudC5vdXRwdXQ7XG4gIGlmICghZGVzdE91dHB1dCkgdGhyb3cgbmV3IEVycm9yKCdJbXBvc3NpYmxlLCBwYXltZW50IHdlIGp1c3QgY29uc3RydWN0ZWQgaGFzIG5vIG91dHB1dCcpO1xuXG4gIGZvciAobGV0IGluZGV4ID0gMDsgaW5kZXggPD0gdm91dDsgaW5kZXgrKykge1xuICAgIGlmIChpbmRleCA9PT0gdm91dCkge1xuICAgICAgcHNidEZyb21OZXR3b3JrLmFkZE91dHB1dCh7IHNjcmlwdDogb3V0cHV0U2NyaXB0LCB2YWx1ZSB9KTtcbiAgICB9IGVsc2Uge1xuICAgICAgcHNidEZyb21OZXR3b3JrLmFkZE91dHB1dCh7IHNjcmlwdDogZGVzdE91dHB1dCwgdmFsdWUgfSk7XG4gICAgfVxuICB9XG4gIHBzYnRGcm9tTmV0d29yay5hZGRJbnB1dCh7XG4gICAgaGFzaDogQnVmZmVyLmFsbG9jKDMyLCAweDAxKSxcbiAgICBpbmRleDogMCxcbiAgICB3aXRuZXNzVXR4bzogeyBzY3JpcHQ6IGRlc3RPdXRwdXQsIHZhbHVlOiB2YWx1ZSAqIChCaWdJbnQodm91dCkgKyBCaWdJbnQoMSkpICsgQmlnSW50KDEwMDApIH0sXG4gIH0pO1xuICBwc2J0RnJvbU5ldHdvcmsuc2lnbklucHV0KDAsIHtcbiAgICBwdWJsaWNLZXk6IHB1YmtleSxcbiAgICBzaWduOiAoaGFzaDogQnVmZmVyLCBsb3dSPzogYm9vbGVhbikgPT5cbiAgICAgIEJ1ZmZlci5mcm9tKG5vYmxlLnNpZ25TeW5jKGhhc2gsIGtleXBhaXIucHJpdmF0ZUtleSBhcyBCdWZmZXIsIHsgY2Fub25pY2FsOiAhbG93UiwgZGVyOiBmYWxzZSB9KSksXG4gIH0pO1xuICBwc2J0RnJvbU5ldHdvcmsudmFsaWRhdGVTaWduYXR1cmVzT2ZBbGxJbnB1dHMoKTtcbiAgcHNidEZyb21OZXR3b3JrLmZpbmFsaXplQWxsSW5wdXRzKCk7XG4gIHJldHVybiBwc2J0RnJvbU5ldHdvcmsuZXh0cmFjdFRyYW5zYWN0aW9uKCk7XG59XG5cbmV4cG9ydCBjb25zdCByZXBsYXlQcm90ZWN0aW9uS2V5UGFpciA9IGdldEtleSgncmVwbGF5LXByb3RlY3Rpb24nKTtcbmNvbnN0IHJlcGxheVByb3RlY3Rpb25TY3JpcHRQdWJLZXkgPSBjcmVhdGVPdXRwdXRTY3JpcHRQMnNoUDJwayhyZXBsYXlQcm90ZWN0aW9uS2V5UGFpci5wdWJsaWNLZXkpLnNjcmlwdFB1YktleTtcblxuZXhwb3J0IGZ1bmN0aW9uIGlzUmVwbGF5UHJvdGVjdGlvblVuc3BlbnQ8VE51bWJlciBleHRlbmRzIGJpZ2ludCB8IG51bWJlcj4oXG4gIHU6IFVuc3BlbnQ8VE51bWJlcj4sXG4gIG5ldHdvcms6IE5ldHdvcmtcbik6IGJvb2xlYW4ge1xuICByZXR1cm4gdS5hZGRyZXNzID09PSBmcm9tT3V0cHV0U2NyaXB0KHJlcGxheVByb3RlY3Rpb25TY3JpcHRQdWJLZXksIG5ldHdvcmspO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gbW9ja1JlcGxheVByb3RlY3Rpb25VbnNwZW50PFROdW1iZXIgZXh0ZW5kcyBudW1iZXIgfCBiaWdpbnQ+KFxuICBuZXR3b3JrOiBOZXR3b3JrLFxuICB2YWx1ZTogVE51bWJlcixcbiAgeyBrZXkgPSByZXBsYXlQcm90ZWN0aW9uS2V5UGFpciwgdm91dCA9IDAgfTogeyBrZXk/OiBCSVAzMkludGVyZmFjZTsgdm91dD86IG51bWJlciB9ID0ge31cbik6IFVuc3BlbnRXaXRoUHJldlR4PFROdW1iZXI+IHtcbiAgY29uc3Qgb3V0cHV0U2NyaXB0ID0gY3JlYXRlT3V0cHV0U2NyaXB0UDJzaFAycGsoa2V5LnB1YmxpY0tleSkuc2NyaXB0UHViS2V5O1xuICBjb25zdCBwcmV2VHJhbnNhY3Rpb24gPSBtb2NrUHJldlR4KHZvdXQsIG91dHB1dFNjcmlwdCwgQmlnSW50KHZhbHVlKSwgbmV0d29yayk7XG4gIHJldHVybiB7IC4uLmZyb21PdXRwdXRXaXRoUHJldlR4KHByZXZUcmFuc2FjdGlvbiwgdm91dCksIHZhbHVlIH07XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBtb2NrV2FsbGV0VW5zcGVudDxUTnVtYmVyIGV4dGVuZHMgbnVtYmVyIHwgYmlnaW50PihcbiAgbmV0d29yazogTmV0d29yayxcbiAgdmFsdWU6IFROdW1iZXIsXG4gIHtcbiAgICBjaGFpbiA9IDAsXG4gICAgaW5kZXggPSAwLFxuICAgIGtleXMgPSBnZXREZWZhdWx0V2FsbGV0S2V5cygpLFxuICAgIHZvdXQgPSAwLFxuICAgIGlkLFxuICB9OiB7IGNoYWluPzogQ2hhaW5Db2RlOyBpbmRleD86IG51bWJlcjsga2V5cz86IFJvb3RXYWxsZXRLZXlzOyB2b3V0PzogbnVtYmVyOyBpZD86IHN0cmluZyB9ID0ge31cbik6IFdhbGxldFVuc3BlbnQ8VE51bWJlcj4gfCBOb25XaXRuZXNzV2FsbGV0VW5zcGVudDxUTnVtYmVyPiB7XG4gIGNvbnN0IGRlcml2ZWRLZXlzID0ga2V5cy5kZXJpdmVGb3JDaGFpbkFuZEluZGV4KGNoYWluLCBpbmRleCk7XG4gIGNvbnN0IGFkZHJlc3MgPSBmcm9tT3V0cHV0U2NyaXB0KFxuICAgIGNyZWF0ZU91dHB1dFNjcmlwdDJvZjMoZGVyaXZlZEtleXMucHVibGljS2V5cywgc2NyaXB0VHlwZUZvckNoYWluKGNoYWluKSkuc2NyaXB0UHViS2V5LFxuICAgIG5ldHdvcmtcbiAgKTtcbiAgaWYgKGlkICYmIHR5cGVvZiBpZCA9PT0gJ3N0cmluZycpIHtcbiAgICByZXR1cm4geyBpZCwgYWRkcmVzcywgY2hhaW4sIGluZGV4LCB2YWx1ZSB9O1xuICB9IGVsc2Uge1xuICAgIGNvbnN0IHByZXZUcmFuc2FjdGlvbiA9IG1vY2tQcmV2VHgoXG4gICAgICB2b3V0LFxuICAgICAgY3JlYXRlT3V0cHV0U2NyaXB0Mm9mMyhkZXJpdmVkS2V5cy5wdWJsaWNLZXlzLCBzY3JpcHRUeXBlRm9yQ2hhaW4oY2hhaW4pLCBuZXR3b3JrKS5zY3JpcHRQdWJLZXksXG4gICAgICBCaWdJbnQodmFsdWUpLFxuICAgICAgbmV0d29ya1xuICAgICk7XG4gICAgY29uc3QgdW5zcGVudCA9XG4gICAgICBpc1NlZ3dpdChjaGFpbikgfHwgZ2V0TWFpbm5ldChuZXR3b3JrKSA9PT0gbmV0d29ya3MuemNhc2hcbiAgICAgICAgPyBmcm9tT3V0cHV0KHByZXZUcmFuc2FjdGlvbiwgdm91dClcbiAgICAgICAgOiBmcm9tT3V0cHV0V2l0aFByZXZUeChwcmV2VHJhbnNhY3Rpb24sIHZvdXQpO1xuICAgIHJldHVybiB7XG4gICAgICAuLi51bnNwZW50LFxuICAgICAgY2hhaW4sXG4gICAgICBpbmRleCxcbiAgICAgIHZhbHVlLFxuICAgIH07XG4gIH1cbn1cblxuZXhwb3J0IGZ1bmN0aW9uIG1vY2tVbnNwZW50czxUTnVtYmVyIGV4dGVuZHMgbnVtYmVyIHwgYmlnaW50PihcbiAgcm9vdFdhbGxldEtleXM6IFJvb3RXYWxsZXRLZXlzLFxuICBpbnB1dFNjcmlwdFR5cGVzOiAoSW5wdXRUeXBlIHwgb3V0cHV0U2NyaXB0cy5TY3JpcHRUeXBlUDJzaFAycGspW10sXG4gIHRlc3RPdXRwdXRBbW91bnQ6IFROdW1iZXIsXG4gIG5ldHdvcms6IE5ldHdvcmtcbik6IChVbnNwZW50PFROdW1iZXI+IHwgV2FsbGV0VW5zcGVudDxUTnVtYmVyPilbXSB7XG4gIHJldHVybiBpbnB1dFNjcmlwdFR5cGVzLm1hcCgodCwgaSk6IFVuc3BlbnQ8VE51bWJlcj4gPT4ge1xuICAgIGlmIChvdXRwdXRTY3JpcHRzLmlzU2NyaXB0VHlwZTJPZjModCkpIHtcbiAgICAgIHJldHVybiBtb2NrV2FsbGV0VW5zcGVudChuZXR3b3JrLCB0ZXN0T3V0cHV0QW1vdW50LCB7XG4gICAgICAgIGtleXM6IHJvb3RXYWxsZXRLZXlzLFxuICAgICAgICBjaGFpbjogZ2V0RXh0ZXJuYWxDaGFpbkNvZGUodCksXG4gICAgICAgIHZvdXQ6IGksXG4gICAgICB9KTtcbiAgICB9IGVsc2UgaWYgKHQgPT09IG91dHB1dFNjcmlwdHMuc2NyaXB0VHlwZVAyc2hQMnBrKSB7XG4gICAgICByZXR1cm4gbW9ja1JlcGxheVByb3RlY3Rpb25VbnNwZW50KG5ldHdvcmssIHRlc3RPdXRwdXRBbW91bnQsIHtcbiAgICAgICAga2V5OiByZXBsYXlQcm90ZWN0aW9uS2V5UGFpcixcbiAgICAgICAgdm91dDogaSxcbiAgICAgIH0pO1xuICAgIH1cbiAgICB0aHJvdyBuZXcgRXJyb3IoYGludmFsaWQgaW5wdXQgdHlwZSAke3R9YCk7XG4gIH0pO1xufVxuIl19