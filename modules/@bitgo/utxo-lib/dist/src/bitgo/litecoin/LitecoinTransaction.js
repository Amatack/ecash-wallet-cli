"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LitecoinTransaction = void 0;
const bufferutils_1 = require("bitcoinjs-lib/src/bufferutils");
const UtxoTransaction_1 = require("../UtxoTransaction");
const networks_1 = require("../../networks");
/**
 * We only care about reading a transaction that can have a potentially different advanced transaction flag,
 * but we dont need to write one.
 */
class LitecoinTransaction extends UtxoTransaction_1.UtxoTransaction {
    constructor(network, tx, amountType) {
        super(network, tx, amountType);
        if (!networks_1.isLitecoin(network)) {
            throw new Error(`invalid network`);
        }
    }
    static newTransaction(network, transaction, amountType) {
        return new LitecoinTransaction(network, transaction, amountType);
    }
    clone(amountType) {
        return new LitecoinTransaction(this.network, this, amountType);
    }
    static fromBuffer(buffer, noStrict, amountType = 'number', network) {
        if (!network) {
            throw new Error(`must provide network`);
        }
        const bufferReader = new bufferutils_1.BufferReader(buffer);
        const txVersion = bufferReader.readInt32();
        const marker = bufferReader.readUInt8();
        const flag = bufferReader.readUInt8();
        if (marker === LitecoinTransaction.ADVANCED_TRANSACTION_MARKER &&
            flag === LitecoinTransaction.MWEB_PEGOUT_TX_FLAG) {
            // Litecoin has an MWEB advanced transaction marker. Slice out the marker and 5th to last byte  and read like a normal transaction
            const bufferWriter = new bufferutils_1.BufferWriter(Buffer.allocUnsafe(buffer.length - 3));
            bufferWriter.writeUInt32(txVersion);
            bufferWriter.writeSlice(buffer.slice(6, buffer.length - 5));
            bufferWriter.writeSlice(buffer.slice(buffer.length - 4, buffer.length));
            return super.fromBuffer(bufferWriter.buffer, noStrict, amountType, network);
        }
        return super.fromBuffer(buffer, noStrict, amountType, network);
    }
}
exports.LitecoinTransaction = LitecoinTransaction;
LitecoinTransaction.MWEB_PEGOUT_TX_FLAG = 0x08;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiTGl0ZWNvaW5UcmFuc2FjdGlvbi5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3NyYy9iaXRnby9saXRlY29pbi9MaXRlY29pblRyYW5zYWN0aW9uLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUFBLCtEQUEyRTtBQUUzRSx3REFBcUQ7QUFDckQsNkNBQStEO0FBSS9EOzs7R0FHRztBQUNILE1BQWEsbUJBQThELFNBQVEsaUNBQXdCO0lBR3pHLFlBQVksT0FBZ0IsRUFBRSxFQUF5QyxFQUFFLFVBQWdDO1FBQ3ZHLEtBQUssQ0FBQyxPQUFPLEVBQUUsRUFBRSxFQUFFLFVBQVUsQ0FBQyxDQUFDO1FBRS9CLElBQUksQ0FBQyxxQkFBVSxDQUFDLE9BQU8sQ0FBQyxFQUFFO1lBQ3hCLE1BQU0sSUFBSSxLQUFLLENBQUMsaUJBQWlCLENBQUMsQ0FBQztTQUNwQztJQUNILENBQUM7SUFFUyxNQUFNLENBQUMsY0FBYyxDQUM3QixPQUFnQixFQUNoQixXQUFrRCxFQUNsRCxVQUFnQztRQUVoQyxPQUFPLElBQUksbUJBQW1CLENBQVUsT0FBTyxFQUFFLFdBQVcsRUFBRSxVQUFVLENBQUMsQ0FBQztJQUM1RSxDQUFDO0lBRUQsS0FBSyxDQUF3QyxVQUFnQztRQUMzRSxPQUFPLElBQUksbUJBQW1CLENBQU0sSUFBSSxDQUFDLE9BQU8sRUFBRSxJQUFJLEVBQUUsVUFBVSxDQUFDLENBQUM7SUFDdEUsQ0FBQztJQUVELE1BQU0sQ0FBQyxVQUFVLENBQ2YsTUFBYyxFQUNkLFFBQWlCLEVBQ2pCLGFBQWtDLFFBQVEsRUFDMUMsT0FBeUI7UUFFekIsSUFBSSxDQUFDLE9BQU8sRUFBRTtZQUNaLE1BQU0sSUFBSSxLQUFLLENBQUMsc0JBQXNCLENBQUMsQ0FBQztTQUN6QztRQUVELE1BQU0sWUFBWSxHQUFHLElBQUksMEJBQVksQ0FBQyxNQUFNLENBQUMsQ0FBQztRQUM5QyxNQUFNLFNBQVMsR0FBRyxZQUFZLENBQUMsU0FBUyxFQUFFLENBQUM7UUFDM0MsTUFBTSxNQUFNLEdBQUcsWUFBWSxDQUFDLFNBQVMsRUFBRSxDQUFDO1FBQ3hDLE1BQU0sSUFBSSxHQUFHLFlBQVksQ0FBQyxTQUFTLEVBQUUsQ0FBQztRQUV0QyxJQUNFLE1BQU0sS0FBSyxtQkFBbUIsQ0FBQywyQkFBMkI7WUFDMUQsSUFBSSxLQUFLLG1CQUFtQixDQUFDLG1CQUFtQixFQUNoRDtZQUNBLGtJQUFrSTtZQUNsSSxNQUFNLFlBQVksR0FBRyxJQUFJLDBCQUFZLENBQUMsTUFBTSxDQUFDLFdBQVcsQ0FBQyxNQUFNLENBQUMsTUFBTSxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUM7WUFDN0UsWUFBWSxDQUFDLFdBQVcsQ0FBQyxTQUFTLENBQUMsQ0FBQztZQUNwQyxZQUFZLENBQUMsVUFBVSxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsQ0FBQyxFQUFFLE1BQU0sQ0FBQyxNQUFNLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQztZQUM1RCxZQUFZLENBQUMsVUFBVSxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsTUFBTSxDQUFDLE1BQU0sR0FBRyxDQUFDLEVBQUUsTUFBTSxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUM7WUFDeEUsT0FBTyxLQUFLLENBQUMsVUFBVSxDQUFDLFlBQVksQ0FBQyxNQUFNLEVBQUUsUUFBUSxFQUFFLFVBQVUsRUFBRSxPQUFPLENBQUMsQ0FBQztTQUM3RTtRQUNELE9BQU8sS0FBSyxDQUFDLFVBQVUsQ0FBQyxNQUFNLEVBQUUsUUFBUSxFQUFFLFVBQVUsRUFBRSxPQUFPLENBQUMsQ0FBQztJQUNqRSxDQUFDOztBQWxESCxrREFtREM7QUFsRFEsdUNBQW1CLEdBQUcsSUFBSSxDQUFDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgQnVmZmVyUmVhZGVyLCBCdWZmZXJXcml0ZXIgfSBmcm9tICdiaXRjb2luanMtbGliL3NyYy9idWZmZXJ1dGlscyc7XG5cbmltcG9ydCB7IFV0eG9UcmFuc2FjdGlvbiB9IGZyb20gJy4uL1V0eG9UcmFuc2FjdGlvbic7XG5pbXBvcnQgeyBpc0xpdGVjb2luLCBOZXR3b3JrLCBuZXR3b3JrcyB9IGZyb20gJy4uLy4uL25ldHdvcmtzJztcblxuZXhwb3J0IHR5cGUgTGl0ZWNvaW5OZXR3b3JrID0gdHlwZW9mIG5ldHdvcmtzLmxpdGVjb2luIHwgdHlwZW9mIG5ldHdvcmtzLmxpdGVjb2luVGVzdDtcblxuLyoqXG4gKiBXZSBvbmx5IGNhcmUgYWJvdXQgcmVhZGluZyBhIHRyYW5zYWN0aW9uIHRoYXQgY2FuIGhhdmUgYSBwb3RlbnRpYWxseSBkaWZmZXJlbnQgYWR2YW5jZWQgdHJhbnNhY3Rpb24gZmxhZyxcbiAqIGJ1dCB3ZSBkb250IG5lZWQgdG8gd3JpdGUgb25lLlxuICovXG5leHBvcnQgY2xhc3MgTGl0ZWNvaW5UcmFuc2FjdGlvbjxUTnVtYmVyIGV4dGVuZHMgbnVtYmVyIHwgYmlnaW50ID0gbnVtYmVyPiBleHRlbmRzIFV0eG9UcmFuc2FjdGlvbjxUTnVtYmVyPiB7XG4gIHN0YXRpYyBNV0VCX1BFR09VVF9UWF9GTEFHID0gMHgwODtcblxuICBjb25zdHJ1Y3RvcihuZXR3b3JrOiBOZXR3b3JrLCB0eD86IExpdGVjb2luVHJhbnNhY3Rpb248YmlnaW50IHwgbnVtYmVyPiwgYW1vdW50VHlwZT86ICdiaWdpbnQnIHwgJ251bWJlcicpIHtcbiAgICBzdXBlcihuZXR3b3JrLCB0eCwgYW1vdW50VHlwZSk7XG5cbiAgICBpZiAoIWlzTGl0ZWNvaW4obmV0d29yaykpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcihgaW52YWxpZCBuZXR3b3JrYCk7XG4gICAgfVxuICB9XG5cbiAgcHJvdGVjdGVkIHN0YXRpYyBuZXdUcmFuc2FjdGlvbjxUTnVtYmVyIGV4dGVuZHMgbnVtYmVyIHwgYmlnaW50ID0gbnVtYmVyPihcbiAgICBuZXR3b3JrOiBOZXR3b3JrLFxuICAgIHRyYW5zYWN0aW9uPzogTGl0ZWNvaW5UcmFuc2FjdGlvbjxudW1iZXIgfCBiaWdpbnQ+LFxuICAgIGFtb3VudFR5cGU/OiAnbnVtYmVyJyB8ICdiaWdpbnQnXG4gICk6IExpdGVjb2luVHJhbnNhY3Rpb248VE51bWJlcj4ge1xuICAgIHJldHVybiBuZXcgTGl0ZWNvaW5UcmFuc2FjdGlvbjxUTnVtYmVyPihuZXR3b3JrLCB0cmFuc2FjdGlvbiwgYW1vdW50VHlwZSk7XG4gIH1cblxuICBjbG9uZTxUTjIgZXh0ZW5kcyBiaWdpbnQgfCBudW1iZXIgPSBUTnVtYmVyPihhbW91bnRUeXBlPzogJ251bWJlcicgfCAnYmlnaW50Jyk6IExpdGVjb2luVHJhbnNhY3Rpb248VE4yPiB7XG4gICAgcmV0dXJuIG5ldyBMaXRlY29pblRyYW5zYWN0aW9uPFROMj4odGhpcy5uZXR3b3JrLCB0aGlzLCBhbW91bnRUeXBlKTtcbiAgfVxuXG4gIHN0YXRpYyBmcm9tQnVmZmVyPFROdW1iZXIgZXh0ZW5kcyBudW1iZXIgfCBiaWdpbnQgPSBudW1iZXI+KFxuICAgIGJ1ZmZlcjogQnVmZmVyLFxuICAgIG5vU3RyaWN0OiBib29sZWFuLFxuICAgIGFtb3VudFR5cGU6ICdudW1iZXInIHwgJ2JpZ2ludCcgPSAnbnVtYmVyJyxcbiAgICBuZXR3b3JrPzogTGl0ZWNvaW5OZXR3b3JrXG4gICk6IExpdGVjb2luVHJhbnNhY3Rpb248VE51bWJlcj4ge1xuICAgIGlmICghbmV0d29yaykge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKGBtdXN0IHByb3ZpZGUgbmV0d29ya2ApO1xuICAgIH1cblxuICAgIGNvbnN0IGJ1ZmZlclJlYWRlciA9IG5ldyBCdWZmZXJSZWFkZXIoYnVmZmVyKTtcbiAgICBjb25zdCB0eFZlcnNpb24gPSBidWZmZXJSZWFkZXIucmVhZEludDMyKCk7XG4gICAgY29uc3QgbWFya2VyID0gYnVmZmVyUmVhZGVyLnJlYWRVSW50OCgpO1xuICAgIGNvbnN0IGZsYWcgPSBidWZmZXJSZWFkZXIucmVhZFVJbnQ4KCk7XG5cbiAgICBpZiAoXG4gICAgICBtYXJrZXIgPT09IExpdGVjb2luVHJhbnNhY3Rpb24uQURWQU5DRURfVFJBTlNBQ1RJT05fTUFSS0VSICYmXG4gICAgICBmbGFnID09PSBMaXRlY29pblRyYW5zYWN0aW9uLk1XRUJfUEVHT1VUX1RYX0ZMQUdcbiAgICApIHtcbiAgICAgIC8vIExpdGVjb2luIGhhcyBhbiBNV0VCIGFkdmFuY2VkIHRyYW5zYWN0aW9uIG1hcmtlci4gU2xpY2Ugb3V0IHRoZSBtYXJrZXIgYW5kIDV0aCB0byBsYXN0IGJ5dGUgIGFuZCByZWFkIGxpa2UgYSBub3JtYWwgdHJhbnNhY3Rpb25cbiAgICAgIGNvbnN0IGJ1ZmZlcldyaXRlciA9IG5ldyBCdWZmZXJXcml0ZXIoQnVmZmVyLmFsbG9jVW5zYWZlKGJ1ZmZlci5sZW5ndGggLSAzKSk7XG4gICAgICBidWZmZXJXcml0ZXIud3JpdGVVSW50MzIodHhWZXJzaW9uKTtcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVNsaWNlKGJ1ZmZlci5zbGljZSg2LCBidWZmZXIubGVuZ3RoIC0gNSkpO1xuICAgICAgYnVmZmVyV3JpdGVyLndyaXRlU2xpY2UoYnVmZmVyLnNsaWNlKGJ1ZmZlci5sZW5ndGggLSA0LCBidWZmZXIubGVuZ3RoKSk7XG4gICAgICByZXR1cm4gc3VwZXIuZnJvbUJ1ZmZlcihidWZmZXJXcml0ZXIuYnVmZmVyLCBub1N0cmljdCwgYW1vdW50VHlwZSwgbmV0d29yayk7XG4gICAgfVxuICAgIHJldHVybiBzdXBlci5mcm9tQnVmZmVyKGJ1ZmZlciwgbm9TdHJpY3QsIGFtb3VudFR5cGUsIG5ldHdvcmspO1xuICB9XG59XG4iXX0=