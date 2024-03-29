"use strict";
/**
 * V1 Safe Wallets are the oldest type of wallets that BitGo supports. They were
 * created back in 2013-14 and don't use HD chains. Instead, they have only one
 * P2SH address per wallet whose redeem script uses uncompressed public keys.
 * */
Object.defineProperty(exports, "__esModule", { value: true });
exports.createLegacySafeOutputScript2of3 = exports.toCompressedPub = exports.toUncompressedPub = void 0;
const assert = require("assert");
const noble_ecc_1 = require("../../noble_ecc");
const networks_1 = require("../../networks");
const types_1 = require("../types");
const bitcoinjs = require("bitcoinjs-lib");
function getPublicKeyBuffer(publicKey, { compressed = true } = {}) {
    const res = noble_ecc_1.ecc.pointCompress(publicKey, compressed);
    if (res === null) {
        throw new Error('invalid public key');
    }
    const buffer = Buffer.from(res);
    assert.strictEqual(buffer.length, compressed ? 33 : 65);
    return buffer;
}
function toUncompressedPub(pubkey) {
    return getPublicKeyBuffer(pubkey, { compressed: false });
}
exports.toUncompressedPub = toUncompressedPub;
function toCompressedPub(pubkey) {
    return getPublicKeyBuffer(pubkey, { compressed: true });
}
exports.toCompressedPub = toCompressedPub;
/** create p2sh scripts with uncompressed pubkeys */
function createLegacySafeOutputScript2of3(pubkeys, network) {
    if (network) {
        if (!networks_1.isBitcoin(network)) {
            throw new Error(`unsupported network for legacy safe output script: ${network.coin}`);
        }
    }
    if (!types_1.isTriple(pubkeys)) {
        throw new Error(`must provide pubkey triple`);
    }
    pubkeys.forEach((key) => {
        if (key.length !== pubkeys[0].length) {
            throw new Error(`all pubkeys must have the same length`);
        }
        if (key.length !== 65 && key.length !== 33) {
            // V1 Safe BTC wallets could contain either uncompressed or compressed pubkeys
            throw new Error(`Unexpected key length ${key.length}, neither compressed nor uncompressed.`);
        }
    });
    const script2of3 = bitcoinjs.payments.p2ms({ m: 2, pubkeys });
    assert(script2of3.output);
    const scriptPubKey = bitcoinjs.payments.p2sh({ redeem: script2of3 });
    assert(scriptPubKey);
    assert(scriptPubKey.output);
    return {
        scriptPubKey: scriptPubKey.output,
        redeemScript: script2of3.output,
    };
}
exports.createLegacySafeOutputScript2of3 = createLegacySafeOutputScript2of3;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5kZXguanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi9zcmMvYml0Z28vbGVnYWN5c2FmZS9pbmRleC50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiO0FBQUE7Ozs7S0FJSzs7O0FBRUwsaUNBQWlDO0FBQ2pDLCtDQUFnRDtBQUNoRCw2Q0FBb0Q7QUFDcEQsb0NBQW9DO0FBQ3BDLDJDQUEyQztBQUUzQyxTQUFTLGtCQUFrQixDQUFDLFNBQWlCLEVBQUUsRUFBRSxVQUFVLEdBQUcsSUFBSSxFQUFFLEdBQUcsRUFBRTtJQUN2RSxNQUFNLEdBQUcsR0FBRyxlQUFNLENBQUMsYUFBYSxDQUFDLFNBQVMsRUFBRSxVQUFVLENBQUMsQ0FBQztJQUN4RCxJQUFJLEdBQUcsS0FBSyxJQUFJLEVBQUU7UUFDaEIsTUFBTSxJQUFJLEtBQUssQ0FBQyxvQkFBb0IsQ0FBQyxDQUFDO0tBQ3ZDO0lBQ0QsTUFBTSxNQUFNLEdBQUcsTUFBTSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUVoQyxNQUFNLENBQUMsV0FBVyxDQUFDLE1BQU0sQ0FBQyxNQUFNLEVBQUUsVUFBVSxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0lBQ3hELE9BQU8sTUFBTSxDQUFDO0FBQ2hCLENBQUM7QUFFRCxTQUFnQixpQkFBaUIsQ0FBQyxNQUFjO0lBQzlDLE9BQU8sa0JBQWtCLENBQUMsTUFBTSxFQUFFLEVBQUUsVUFBVSxFQUFFLEtBQUssRUFBRSxDQUFDLENBQUM7QUFDM0QsQ0FBQztBQUZELDhDQUVDO0FBRUQsU0FBZ0IsZUFBZSxDQUFDLE1BQWM7SUFDNUMsT0FBTyxrQkFBa0IsQ0FBQyxNQUFNLEVBQUUsRUFBRSxVQUFVLEVBQUUsSUFBSSxFQUFFLENBQUMsQ0FBQztBQUMxRCxDQUFDO0FBRkQsMENBRUM7QUFFRCxvREFBb0Q7QUFDcEQsU0FBZ0IsZ0NBQWdDLENBQzlDLE9BQWlCLEVBQ2pCLE9BQWlCO0lBS2pCLElBQUksT0FBTyxFQUFFO1FBQ1gsSUFBSSxDQUFDLG9CQUFTLENBQUMsT0FBTyxDQUFDLEVBQUU7WUFDdkIsTUFBTSxJQUFJLEtBQUssQ0FBQyxzREFBc0QsT0FBTyxDQUFDLElBQUksRUFBRSxDQUFDLENBQUM7U0FDdkY7S0FDRjtJQUVELElBQUksQ0FBQyxnQkFBUSxDQUFDLE9BQU8sQ0FBQyxFQUFFO1FBQ3RCLE1BQU0sSUFBSSxLQUFLLENBQUMsNEJBQTRCLENBQUMsQ0FBQztLQUMvQztJQUVELE9BQU8sQ0FBQyxPQUFPLENBQUMsQ0FBQyxHQUFHLEVBQUUsRUFBRTtRQUN0QixJQUFJLEdBQUcsQ0FBQyxNQUFNLEtBQUssT0FBTyxDQUFDLENBQUMsQ0FBQyxDQUFDLE1BQU0sRUFBRTtZQUNwQyxNQUFNLElBQUksS0FBSyxDQUFDLHVDQUF1QyxDQUFDLENBQUM7U0FDMUQ7UUFDRCxJQUFJLEdBQUcsQ0FBQyxNQUFNLEtBQUssRUFBRSxJQUFJLEdBQUcsQ0FBQyxNQUFNLEtBQUssRUFBRSxFQUFFO1lBQzFDLDhFQUE4RTtZQUM5RSxNQUFNLElBQUksS0FBSyxDQUFDLHlCQUF5QixHQUFHLENBQUMsTUFBTSx3Q0FBd0MsQ0FBQyxDQUFDO1NBQzlGO0lBQ0gsQ0FBQyxDQUFDLENBQUM7SUFFSCxNQUFNLFVBQVUsR0FBRyxTQUFTLENBQUMsUUFBUSxDQUFDLElBQUksQ0FBQyxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsT0FBTyxFQUFFLENBQUMsQ0FBQztJQUM5RCxNQUFNLENBQUMsVUFBVSxDQUFDLE1BQU0sQ0FBQyxDQUFDO0lBRTFCLE1BQU0sWUFBWSxHQUFHLFNBQVMsQ0FBQyxRQUFRLENBQUMsSUFBSSxDQUFDLEVBQUUsTUFBTSxFQUFFLFVBQVUsRUFBRSxDQUFDLENBQUM7SUFDckUsTUFBTSxDQUFDLFlBQVksQ0FBQyxDQUFDO0lBQ3JCLE1BQU0sQ0FBQyxZQUFZLENBQUMsTUFBTSxDQUFDLENBQUM7SUFFNUIsT0FBTztRQUNMLFlBQVksRUFBRSxZQUFZLENBQUMsTUFBTTtRQUNqQyxZQUFZLEVBQUUsVUFBVSxDQUFDLE1BQU07S0FDaEMsQ0FBQztBQUNKLENBQUM7QUF0Q0QsNEVBc0NDIiwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gKiBWMSBTYWZlIFdhbGxldHMgYXJlIHRoZSBvbGRlc3QgdHlwZSBvZiB3YWxsZXRzIHRoYXQgQml0R28gc3VwcG9ydHMuIFRoZXkgd2VyZVxuICogY3JlYXRlZCBiYWNrIGluIDIwMTMtMTQgYW5kIGRvbid0IHVzZSBIRCBjaGFpbnMuIEluc3RlYWQsIHRoZXkgaGF2ZSBvbmx5IG9uZVxuICogUDJTSCBhZGRyZXNzIHBlciB3YWxsZXQgd2hvc2UgcmVkZWVtIHNjcmlwdCB1c2VzIHVuY29tcHJlc3NlZCBwdWJsaWMga2V5cy5cbiAqICovXG5cbmltcG9ydCAqIGFzIGFzc2VydCBmcm9tICdhc3NlcnQnO1xuaW1wb3J0IHsgZWNjIGFzIGVjY0xpYiB9IGZyb20gJy4uLy4uL25vYmxlX2VjYyc7XG5pbXBvcnQgeyBpc0JpdGNvaW4sIE5ldHdvcmsgfSBmcm9tICcuLi8uLi9uZXR3b3Jrcyc7XG5pbXBvcnQgeyBpc1RyaXBsZSB9IGZyb20gJy4uL3R5cGVzJztcbmltcG9ydCAqIGFzIGJpdGNvaW5qcyBmcm9tICdiaXRjb2luanMtbGliJztcblxuZnVuY3Rpb24gZ2V0UHVibGljS2V5QnVmZmVyKHB1YmxpY0tleTogQnVmZmVyLCB7IGNvbXByZXNzZWQgPSB0cnVlIH0gPSB7fSk6IEJ1ZmZlciB7XG4gIGNvbnN0IHJlcyA9IGVjY0xpYi5wb2ludENvbXByZXNzKHB1YmxpY0tleSwgY29tcHJlc3NlZCk7XG4gIGlmIChyZXMgPT09IG51bGwpIHtcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ2ludmFsaWQgcHVibGljIGtleScpO1xuICB9XG4gIGNvbnN0IGJ1ZmZlciA9IEJ1ZmZlci5mcm9tKHJlcyk7XG5cbiAgYXNzZXJ0LnN0cmljdEVxdWFsKGJ1ZmZlci5sZW5ndGgsIGNvbXByZXNzZWQgPyAzMyA6IDY1KTtcbiAgcmV0dXJuIGJ1ZmZlcjtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHRvVW5jb21wcmVzc2VkUHViKHB1YmtleTogQnVmZmVyKTogQnVmZmVyIHtcbiAgcmV0dXJuIGdldFB1YmxpY0tleUJ1ZmZlcihwdWJrZXksIHsgY29tcHJlc3NlZDogZmFsc2UgfSk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiB0b0NvbXByZXNzZWRQdWIocHVia2V5OiBCdWZmZXIpOiBCdWZmZXIge1xuICByZXR1cm4gZ2V0UHVibGljS2V5QnVmZmVyKHB1YmtleSwgeyBjb21wcmVzc2VkOiB0cnVlIH0pO1xufVxuXG4vKiogY3JlYXRlIHAyc2ggc2NyaXB0cyB3aXRoIHVuY29tcHJlc3NlZCBwdWJrZXlzICovXG5leHBvcnQgZnVuY3Rpb24gY3JlYXRlTGVnYWN5U2FmZU91dHB1dFNjcmlwdDJvZjMoXG4gIHB1YmtleXM6IEJ1ZmZlcltdLFxuICBuZXR3b3JrPzogTmV0d29ya1xuKToge1xuICBzY3JpcHRQdWJLZXk6IEJ1ZmZlcjtcbiAgcmVkZWVtU2NyaXB0OiBCdWZmZXI7XG59IHtcbiAgaWYgKG5ldHdvcmspIHtcbiAgICBpZiAoIWlzQml0Y29pbihuZXR3b3JrKSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKGB1bnN1cHBvcnRlZCBuZXR3b3JrIGZvciBsZWdhY3kgc2FmZSBvdXRwdXQgc2NyaXB0OiAke25ldHdvcmsuY29pbn1gKTtcbiAgICB9XG4gIH1cblxuICBpZiAoIWlzVHJpcGxlKHB1YmtleXMpKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKGBtdXN0IHByb3ZpZGUgcHVia2V5IHRyaXBsZWApO1xuICB9XG5cbiAgcHVia2V5cy5mb3JFYWNoKChrZXkpID0+IHtcbiAgICBpZiAoa2V5Lmxlbmd0aCAhPT0gcHVia2V5c1swXS5sZW5ndGgpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihgYWxsIHB1YmtleXMgbXVzdCBoYXZlIHRoZSBzYW1lIGxlbmd0aGApO1xuICAgIH1cbiAgICBpZiAoa2V5Lmxlbmd0aCAhPT0gNjUgJiYga2V5Lmxlbmd0aCAhPT0gMzMpIHtcbiAgICAgIC8vIFYxIFNhZmUgQlRDIHdhbGxldHMgY291bGQgY29udGFpbiBlaXRoZXIgdW5jb21wcmVzc2VkIG9yIGNvbXByZXNzZWQgcHVia2V5c1xuICAgICAgdGhyb3cgbmV3IEVycm9yKGBVbmV4cGVjdGVkIGtleSBsZW5ndGggJHtrZXkubGVuZ3RofSwgbmVpdGhlciBjb21wcmVzc2VkIG5vciB1bmNvbXByZXNzZWQuYCk7XG4gICAgfVxuICB9KTtcblxuICBjb25zdCBzY3JpcHQyb2YzID0gYml0Y29pbmpzLnBheW1lbnRzLnAybXMoeyBtOiAyLCBwdWJrZXlzIH0pO1xuICBhc3NlcnQoc2NyaXB0Mm9mMy5vdXRwdXQpO1xuXG4gIGNvbnN0IHNjcmlwdFB1YktleSA9IGJpdGNvaW5qcy5wYXltZW50cy5wMnNoKHsgcmVkZWVtOiBzY3JpcHQyb2YzIH0pO1xuICBhc3NlcnQoc2NyaXB0UHViS2V5KTtcbiAgYXNzZXJ0KHNjcmlwdFB1YktleS5vdXRwdXQpO1xuXG4gIHJldHVybiB7XG4gICAgc2NyaXB0UHViS2V5OiBzY3JpcHRQdWJLZXkub3V0cHV0LFxuICAgIHJlZGVlbVNjcmlwdDogc2NyaXB0Mm9mMy5vdXRwdXQsXG4gIH07XG59XG4iXX0=