"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UtxoTransaction = exports.varSliceSize = void 0;
const assert = require("assert");
const bitcoinjs = require("bitcoinjs-lib");
const varuint = require("varuint-bitcoin");
const tnumber_1 = require("./tnumber");
const networks_1 = require("../networks");
function varSliceSize(slice) {
    const length = slice.length;
    return varuint.encodingLength(length) + length;
}
exports.varSliceSize = varSliceSize;
class UtxoTransaction extends bitcoinjs.Transaction {
    constructor(network, transaction, amountType) {
        super();
        this.network = network;
        if (transaction) {
            this.version = transaction.version;
            this.locktime = transaction.locktime;
            this.ins = transaction.ins.map((v) => ({ ...v, witness: [...v.witness] }));
            if (transaction.outs.length) {
                // amountType only matters if there are outs
                const inAmountType = typeof transaction.outs[0].value;
                assert(inAmountType === 'number' || inAmountType === 'bigint');
                const outAmountType = amountType || inAmountType;
                this.outs = transaction.outs.map((v) => ({ ...v, value: tnumber_1.toTNumber(v.value, outAmountType) }));
            }
        }
    }
    static newTransaction(network, transaction, amountType) {
        return new UtxoTransaction(network, transaction, amountType);
    }
    static fromBuffer(buf, noStrict, amountType = 'number', network, prevOutput) {
        if (!network) {
            throw new Error(`must provide network`);
        }
        return this.newTransaction(network, bitcoinjs.Transaction.fromBuffer(buf, noStrict, amountType), amountType);
    }
    addForkId(hashType) {
        /*
          ``The sighash type is altered to include a 24-bit fork id in its most significant bits.''
          We also use unsigned right shift operator `>>>` to cast to UInt32
          https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Unsigned_right_shift
         */
        if (hashType & UtxoTransaction.SIGHASH_FORKID) {
            const forkId = networks_1.isBitcoinGold(this.network) ? 79 : 0;
            return (hashType | (forkId << 8)) >>> 0;
        }
        return hashType;
    }
    hashForWitnessV0(inIndex, prevOutScript, value, hashType) {
        return super.hashForWitnessV0(inIndex, prevOutScript, value, this.addForkId(hashType));
    }
    /**
     * Calculate the hash to verify the signature against
     */
    hashForSignatureByNetwork(inIndex, prevoutScript, value, hashType) {
        switch (networks_1.getMainnet(this.network)) {
            case networks_1.networks.zcash:
                throw new Error(`illegal state`);
            case networks_1.networks.bitcoincash:
            case networks_1.networks.bitcoinsv:
            case networks_1.networks.bitcoingold:
            case networks_1.networks.ecash:
                /*
                  Bitcoin Cash supports a FORKID flag. When set, we hash using hashing algorithm
                   that is used for segregated witness transactions (defined in BIP143).
        
                  The flag is also used by BitcoinSV and BitcoinGold
        
                  https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/replay-protected-sighash.md
                 */
                const addForkId = (hashType & UtxoTransaction.SIGHASH_FORKID) > 0;
                if (addForkId) {
                    if (value === undefined) {
                        throw new Error(`must provide value`);
                    }
                    return super.hashForWitnessV0(inIndex, prevoutScript, value, this.addForkId(hashType));
                }
        }
        return super.hashForSignature(inIndex, prevoutScript, hashType);
    }
    hashForSignature(inIndex, prevOutScript, hashType, value) {
        value = value !== null && value !== void 0 ? value : this.ins[inIndex].value;
        return this.hashForSignatureByNetwork(inIndex, prevOutScript, value, hashType);
    }
    clone(amountType) {
        // No need to clone. Everything is copied in the constructor.
        return new UtxoTransaction(this.network, this, amountType);
    }
}
exports.UtxoTransaction = UtxoTransaction;
UtxoTransaction.SIGHASH_FORKID = 0x40;
/** @deprecated use SIGHASH_FORKID */
UtxoTransaction.SIGHASH_BITCOINCASHBIP143 = UtxoTransaction.SIGHASH_FORKID;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiVXR4b1RyYW5zYWN0aW9uLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL2JpdGdvL1V0eG9UcmFuc2FjdGlvbi50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7QUFBQSxpQ0FBaUM7QUFDakMsMkNBQTJDO0FBQzNDLDJDQUEyQztBQUMzQyx1Q0FBc0M7QUFFdEMsMENBQTJFO0FBRTNFLFNBQWdCLFlBQVksQ0FBQyxLQUFhO0lBQ3hDLE1BQU0sTUFBTSxHQUFHLEtBQUssQ0FBQyxNQUFNLENBQUM7SUFDNUIsT0FBTyxPQUFPLENBQUMsY0FBYyxDQUFDLE1BQU0sQ0FBQyxHQUFHLE1BQU0sQ0FBQztBQUNqRCxDQUFDO0FBSEQsb0NBR0M7QUFFRCxNQUFhLGVBQTBELFNBQVEsU0FBUyxDQUFDLFdBQW9CO0lBSzNHLFlBQ1MsT0FBZ0IsRUFDdkIsV0FBb0QsRUFDcEQsVUFBZ0M7UUFFaEMsS0FBSyxFQUFFLENBQUM7UUFKRCxZQUFPLEdBQVAsT0FBTyxDQUFTO1FBS3ZCLElBQUksV0FBVyxFQUFFO1lBQ2YsSUFBSSxDQUFDLE9BQU8sR0FBRyxXQUFXLENBQUMsT0FBTyxDQUFDO1lBQ25DLElBQUksQ0FBQyxRQUFRLEdBQUcsV0FBVyxDQUFDLFFBQVEsQ0FBQztZQUNyQyxJQUFJLENBQUMsR0FBRyxHQUFHLFdBQVcsQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxFQUFFLEVBQUUsQ0FBQyxDQUFDLEVBQUUsR0FBRyxDQUFDLEVBQUUsT0FBTyxFQUFFLENBQUMsR0FBRyxDQUFDLENBQUMsT0FBTyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUM7WUFDM0UsSUFBSSxXQUFXLENBQUMsSUFBSSxDQUFDLE1BQU0sRUFBRTtnQkFDM0IsNENBQTRDO2dCQUM1QyxNQUFNLFlBQVksR0FBRyxPQUFPLFdBQVcsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQUMsS0FBSyxDQUFDO2dCQUN0RCxNQUFNLENBQUMsWUFBWSxLQUFL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LGFBQWEsRUFBRSxRQUFRLENBQUMsQ0FBQztJQUNsRSxDQUFDO0lBRUQsZ0JBQWdCLENBQUMsT0FBZSxFQUFFLGFBQXFCLEVBQUUsUUFBZ0IsRUFBRSxLQUFlO1FBQ3hGLEtBQUssR0FBRyxLQUFLLGFBQUwsS0FBSyxjQUFMLEtBQUssR0FBSyxJQUFJLENBQUMsR0FBRyxDQUFDLE9BQU8sQ0FBUyxDQUFDLEtBQUssQ0FBQztRQUNsRCxPQUFPLElBQUksQ0FBQyx5QkFBeUIsQ0FBQyxPQUFPLEVBQUUsYUFBYSxFQUFFLEtBQUssRUFBRSxRQUFRLENBQUMsQ0FBQztJQUNqRixDQUFDO0lBRUQsS0FBSyxDQUF3QyxVQUFnQztRQUMzRSw2REFBNkQ7UUFDN0QsT0FBTyxJQUFJLGVBQWUsQ0FBTSxJQUFJLENBQUMsT0FBTyxFQUFFLElBQUksRUFBRSxVQUFVLENBQUMsQ0FBQztJQUNsRSxDQUFDOztBQWpISCwwQ0FrSEM7QUFqSFEsOEJBQWMsR0FBRyxJQUFJLENBQUM7QUFDN0IscUNBQXFDO0FBQzlCLHlDQUF5QixHQUFHLGVBQWUsQ0FBQyxjQUFjLENBQUMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgKiBhcyBhc3NlcnQgZnJvbSAnYXNzZXJ0JztcbmltcG9ydCAqIGFzIGJpdGNvaW5qcyBmcm9tICdiaXRjb2luanMtbGliJztcbmltcG9ydCAqIGFzIHZhcnVpbnQgZnJvbSAndmFydWludC1iaXRjb2luJztcbmltcG9ydCB7IHRvVE51bWJlciB9IGZyb20gJy4vdG51bWJlcic7XG5cbmltcG9ydCB7IG5ldHdvcmtzLCBOZXR3b3JrLCBnZXRNYWlubmV0LCBpc0JpdGNvaW5Hb2xkIH0gZnJvbSAnLi4vbmV0d29ya3MnO1xuXG5leHBvcnQgZnVuY3Rpb24gdmFyU2xpY2VTaXplKHNsaWNlOiBCdWZmZXIpOiBudW1iZXIge1xuICBjb25zdCBsZW5ndGggPSBzbGljZS5sZW5ndGg7XG4gIHJldHVybiB2YXJ1aW50LmVuY29kaW5nTGVuZ3RoKGxlbmd0aCkgKyBsZW5ndGg7XG59XG5cbmV4cG9ydCBjbGFzcyBVdHhvVHJhbnNhY3Rpb248VE51bWJlciBleHRlbmRzIG51bWJlciB8IGJpZ2ludCA9IG51bWJlcj4gZXh0ZW5kcyBiaXRjb2luanMuVHJhbnNhY3Rpb248VE51bWJlcj4ge1xuICBzdGF0aWMgU0lHSEFTSF9GT1JLSUQgPSAweDQwO1xuICAvKiogQGRlcHJlY2F0ZWQgdXNlIFNJR0hBU0hfRk9SS0lEICovXG4gIHN0YXRpYyBTSUdIQVNIX0JJVENPSU5DQVNIQklQMTQzID0gVXR4b1RyYW5zYWN0aW9uLlNJR0hBU0hfRk9SS0lEO1xuXG4gIGNvbnN0cnVjdG9yKFxuICAgIHB1YmxpYyBuZXR3b3JrOiBOZXR3b3JrLFxuICAgIHRyYW5zYWN0aW9uPzogYml0Y29pbmpzLlRyYW5zYWN0aW9uPGJpZ2ludCB8IG51bWJlcj4sXG4gICAgYW1vdW50VHlwZT86ICdiaWdpbnQnIHwgJ251bWJlcidcbiAgKSB7XG4gICAgc3VwZXIoKTtcbiAgICBpZiAodHJhbnNhY3Rpb24pIHtcbiAgICAgIHRoaXMudmVyc2lvbiA9IHRyYW5zYWN0aW9uLnZlcnNpb247XG4gICAgICB0aGlzLmxvY2t0aW1lID0gdHJhbnNhY3Rpb24ubG9ja3RpbWU7XG4gICAgICB0aGlzLmlucyA9IHRyYW5zYWN0aW9uLmlucy5tYXAoKHYpID0+ICh7IC4uLnYsIHdpdG5lc3M6IFsuLi52LndpdG5lc3NdIH0pKTtcbiAgICAgIGlmICh0cmFuc2FjdGlvbi5vdXRzLmxlbmd0aCkge1xuICAgICAgICAvLyBhbW91bnRUeXBlIG9ubHkgbWF0dGVycyBpZiB0aGVyZSBhcmUgb3V0c1xuICAgICAgICBjb25zdCBpbkFtb3VudFR5cGUgPSB0eXBlb2YgdHJhbnNhY3Rpb24ub3V0c1swXS52YWx1ZTtcbiAgICAgICAgYXNzZXJ0KGluQW1vdW50VHlwZSA9PT0gJ251bWJlcicgfHwgaW5BbW91bnRUeXBlID09PSAnYmlnaW50Jyk7XG4gICAgICAgIGNvbnN0IG91dEFtb3VudFR5cGU6ICdudW1iZXInIHwgJ2JpZ2ludCcgPSBhbW91bnRUeXBlIHx8IGluQW1vdW50VHlwZTtcbiAgICAgICAgdGhpcy5vdXRzID0gdHJhbnNhY3Rpb24ub3V0cy5tYXAoKHYpID0+ICh7IC4uLnYsIHZhbHVlOiB0b1ROdW1iZXIodi52YWx1ZSwgb3V0QW1vdW50VHlwZSkgfSkpO1xuICAgICAgfVxuICAgIH1cbiAgfVxuXG4gIHByb3RlY3RlZCBzdGF0aWMgbmV3VHJhbnNhY3Rpb248VE51bWJlciBleHRlbmRzIG51bWJlciB8IGJpZ2ludCA9IG51bWJlcj4oXG4gICAgbmV0d29yazogTmV0d29yayxcbiAgICB0cmFuc2FjdGlvbj86IGJpdGNvaW5qcy5UcmFuc2FjdGlvbjxiaWdpbnQgfCBudW1iZXI+LFxuICAgIGFtb3VudFR5cGU/OiAnbnVtYmVyJyB8ICdiaWdpbnQnXG4gICk6IFV0eG9UcmFuc2FjdGlvbjxUTnVtYmVyPiB7XG4gICAgcmV0dXJuIG5ldyBVdHhvVHJhbnNhY3Rpb248VE51bWJlcj4obmV0d29yaywgdHJhbnNhY3Rpb24sIGFtb3VudFR5cGUpO1xuICB9XG5cbiAgc3RhdGljIGZyb21CdWZmZXI8VE51bWJlciBleHRlbmRzIG51bWJlciB8IGJpZ2ludCA9IG51bWJlcj4oXG4gICAgYnVmOiBCdWZmZXIsXG4gICAgbm9TdHJpY3Q6IGJvb2xlYW4sXG4gICAgYW1vdW50VHlwZTogJ251bWJlcicgfCAnYmlnaW50JyA9ICdudW1iZXInLFxuICAgIG5ldHdvcms/OiBOZXR3b3JrLFxuICAgIHByZXZPdXRwdXQ/OiBiaXRjb2luanMuVHhPdXRwdXQ8VE51bWJlcj5bXVxuICApOiBVdHhvVHJhbnNhY3Rpb248VE51bWJlcj4ge1xuICAgIGlmICghbmV0d29yaykge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKGBtdXN0IHByb3ZpZGUgbmV0d29ya2ApO1xuICAgIH1cbiAgICByZXR1cm4gdGhpcy5uZXdUcmFuc2FjdGlvbjxUTnVtYmVyPihcbiAgICAgIG5ldHdvcmssXG4gICAgICBiaXRjb2luanMuVHJhbnNhY3Rpb24uZnJvbUJ1ZmZlcjxUTnVtYmVyPihidWYsIG5vU3RyaWN0LCBhbW91bnRUeXBlKSxcbiAgICAgIGFtb3VudFR5cGVcbiAgICApO1xuICB9XG5cbiAgYWRkRm9ya0lkKGhhc2hUeXBlOiBudW1iZXIpOiBudW1iZXIge1xuICAgIC8qXG4gICAgICBgYFRoZSBzaWdoYXNoIHR5cGUgaXMgYWx0ZXJlZCB0byBpbmNsdWRlIGEgMjQtYml0IGZvcmsgaWQgaW4gaXRzIG1vc3Qgc2lnbmlmaWNhbnQgYml0cy4nJ1xuICAgICAgV2UgYWxzbyB1c2UgdW5zaWduZWQgcmlnaHQgc2hpZnQgb3BlcmF0b3IgYD4+PmAgdG8gY2FzdCB0byBVSW50MzJcbiAgICAgIGh0dHBzOi8vZGV2ZWxvcGVyLm1vemlsbGEub3JnL2VuLVVTL2RvY3MvV2ViL0phdmFTY3JpcHQvUmVmZXJlbmNlL09wZXJhdG9ycy9VbnNpZ25lZF9yaWdodF9zaGlmdFxuICAgICAqL1xuICAgIGlmIChoYXNoVHlwZSAmIFV0eG9UcmFuc2FjdGlvbi5TSUdIQVNIX0ZPUktJRCkge1xuICAgICAgY29uc3QgZm9ya0lkID0gaXNCaXRjb2luR29sZCh0aGlzLm5ldHdvcmspID8gNzkgOiAwO1xuICAgICAgcmV0dXJuIChoYXNoVHlwZSB8IChmb3JrSWQgPDwgOCkpID4+PiAwO1xuICAgIH1cblxuICAgIHJldHVybiBoYXNoVHlwZTtcbiAgfVxuXG4gIGhhc2hGb3JXaXRuZXNzVjAoaW5JbmRleDogbnVtYmVyLCBwcmV2T3V0U2NyaXB0OiBCdWZmZXIsIHZhbHVlOiBUTnVtYmVyLCBoYXNoVHlwZTogbnVtYmVyKTogQnVmZmVyIHtcbiAgICByZXR1cm4gc3VwZXIuaGFzaEZvcldpdG5lc3NWMChpbkluZGV4LCBwcmV2T3V0U2NyaXB0LCB2YWx1ZSwgdGhpcy5hZGRGb3JrSWQoaGFzaFR5cGUpKTtcbiAgfVxuXG4gIC8qKlxuICAgKiBDYWxjdWxhdGUgdGhlIGhhc2ggdG8gdmVyaWZ5IHRoZSBzaWduYXR1cmUgYWdhaW5zdFxuICAgKi9cbiAgaGFzaEZvclNpZ25hdHVyZUJ5TmV0d29yayhcbiAgICBpbkluZGV4OiBudW1iZXIsXG4gICAgcHJldm91dFNjcmlwdDogQnVmZmVyLFxuICAgIHZhbHVlOiBUTnVtYmVyIHwgdW5kZWZpbmVkLFxuICAgIGhhc2hUeXBlOiBudW1iZXJcbiAgKTogQnVmZmVyIHtcbiAgICBzd2l0Y2ggKGdldE1haW5uZXQodGhpcy5uZXR3b3JrKSkge1xuICAgICAgY2FzZSBuZXR3b3Jrcy56Y2FzaDpcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKGBpbGxlZ2FsIHN0YXRlYCk7XG4gICAgICBjYXNlIG5ldHdvcmtzLmJpdGNvaW5jYXNoOlxuICAgICAgY2FzZSBuZXR3b3Jrcy5iaXRjb2luc3Y6XG4gICAgICBjYXNlIG5ldHdvcmtzLmJpdGNvaW5nb2xkOlxuICAgICAgY2FzZSBuZXR3b3Jrcy5lY2FzaDpcbiAgICAgICAgLypcbiAgICAgICAgICBCaXRjb2luIENhc2ggc3VwcG9ydHMgYSBGT1JLSUQgZmxhZy4gV2hlbiBzZXQsIHdlIGhhc2ggdXNpbmcgaGFzaGluZyBhbGdvcml0aG1cbiAgICAgICAgICAgdGhhdCBpcyB1c2VkIGZvciBzZWdyZWdhdGVkIHdpdG5lc3MgdHJhbnNhY3Rpb25zIChkZWZpbmVkIGluIEJJUDE0MykuXG5cbiAgICAgICAgICBUaGUgZmxhZyBpcyBhbHNvIHVzZWQgYnkgQml0Y29pblNWIGFuZCBCaXRjb2luR29sZFxuXG4gICAgICAgICAgaHR0cHM6Ly9naXRodWIuY29tL2JpdGNvaW5jYXNob3JnL2JpdGNvaW5jYXNoLm9yZy9ibG9iL21hc3Rlci9zcGVjL3JlcGxheS1wcm90ZWN0ZWQtc2lnaGFzaC5tZFxuICAgICAgICAgKi9cbiAgICAgICAgY29uc3QgYWRkRm9ya0lkID0gKGhhc2hUeXBlICYgVXR4b1RyYW5zYWN0aW9uLlNJR0hBU0hfRk9SS0lEKSA+IDA7XG5cbiAgICAgICAgaWYgKGFkZEZvcmtJZCkge1xuICAgICAgICAgIGlmICh2YWx1ZSA9PT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYG11c3QgcHJvdmlkZSB2YWx1ZWApO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm4gc3VwZXIuaGFzaEZvcldpdG5lc3NWMChpbkluZGV4LCBwcmV2b3V0U2NyaXB0LCB2YWx1ZSwgdGhpcy5hZGRGb3JrSWQoaGFzaFR5cGUpKTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiBzdXBlci5oYXNoRm9yU2lnbmF0dXJlKGluSW5kZXgsIHByZXZvdXRTY3JpcHQsIGhhc2hUeXBlKTtcbiAgfVxuXG4gIGhhc2hGb3JTaWduYXR1cmUoaW5JbmRleDogbnVtYmVyLCBwcmV2T3V0U2NyaXB0OiBCdWZmZXIsIGhhc2hUeXBlOiBudW1iZXIsIHZhbHVlPzogVE51bWJlcik6IEJ1ZmZlciB7XG4gICAgdmFsdWUgPSB2YWx1ZSA/PyAodGhpcy5pbnNbaW5JbmRleF0gYXMgYW55KS52YWx1ZTtcbiAgICByZXR1cm4gdGhpcy5oYXNoRm9yU2lnbmF0dXJlQnlOZXR3b3JrKGluSW5kZXgsIHByZXZPdXRTY3JpcHQsIHZhbHVlLCBoYXNoVHlwZSk7XG4gIH1cblxuICBjbG9uZTxUTjIgZXh0ZW5kcyBiaWdpbnQgfCBudW1iZXIgPSBUTnVtYmVyPihhbW91bnRUeXBlPzogJ251bWJlcicgfCAnYmlnaW50Jyk6IFV0eG9UcmFuc2FjdGlvbjxUTjI+IHtcbiAgICAvLyBObyBuZWVkIHRvIGNsb25lLiBFdmVyeXRoaW5nIGlzIGNvcGllZCBpbiB0aGUgY29uc3RydWN0b3IuXG4gICAgcmV0dXJuIG5ldyBVdHhvVHJhbnNhY3Rpb248VE4yPih0aGlzLm5ldHdvcmssIHRoaXMsIGFtb3VudFR5cGUpO1xuICB9XG59XG4iXX0=