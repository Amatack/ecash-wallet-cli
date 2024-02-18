"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.unspentSum = exports.addToTransactionBuilder = exports.toPrevOutputWithPrevTx = exports.toPrevOutput = exports.getOutputIdForInput = exports.formatOutputId = exports.parseOutputId = exports.fromOutputWithPrevTx = exports.fromOutput = exports.toOutput = exports.isUnspentWithPrevTx = void 0;
const address_1 = require("../address");
function isUnspentWithPrevTx(u) {
    return Buffer.isBuffer(u.prevTx);
}
exports.isUnspentWithPrevTx = isUnspentWithPrevTx;
/**
 * @return TxOutput from Unspent
 */
function toOutput(u, network) {
    return {
        script: address_1.toOutputScript(u.address, network),
        value: u.value,
    };
}
exports.toOutput = toOutput;
/**
 * @return Unspent from TxOutput
 */
function fromOutput(tx, vout) {
    const o = tx.outs[vout];
    if (!o) {
        throw new Error(`invalid vout`);
    }
    return {
        id: formatOutputId({ txid: tx.getId(), vout }),
        address: address_1.fromOutputScript(o.script, tx.network),
        value: o.value,
    };
}
exports.fromOutput = fromOutput;
function fromOutputWithPrevTx(tx, vout) {
    return {
        ...fromOutput(tx, vout),
        prevTx: tx.toBuffer(),
    };
}
exports.fromOutputWithPrevTx = fromOutputWithPrevTx;
/**
 * @param outputId
 * @return TxOutPoint
 */
function parseOutputId(outputId) {
    const parts = outputId.split(':');
    if (parts.length !== 2) {
        throw new Error(`invalid outputId, must have format txid:vout`);
    }
    const [txid, voutStr] = parts;
    const vout = Number(voutStr);
    if (txid.length !== 64) {
        throw new Error(`invalid txid ${txid} ${txid.length}`);
    }
    if (Number.isNaN(vout) || vout < 0 || !Number.isSafeInteger(vout)) {
        throw new Error(`invalid vout: must be integer >= 0`);
    }
    return { txid, vout };
}
exports.parseOutputId = parseOutputId;
/**
 * @param txid
 * @param vout
 * @return outputId
 */
function formatOutputId({ txid, vout }) {
    return `${txid}:${vout}`;
}
exports.formatOutputId = formatOutputId;
function getOutputIdForInput(i) {
    return {
        txid: Buffer.from(i.hash).reverse().toString('hex'),
        vout: i.index,
    };
}
exports.getOutputIdForInput = getOutputIdForInput;
/**
 * @return PrevOutput from Unspent
 */
function toPrevOutput(u, network) {
    return {
        ...parseOutputId(u.id),
        ...toOutput(u, network),
    };
}
exports.toPrevOutput = toPrevOutput;
/**
 * @return PrevOutput with prevTx from Unspent
 */
function toPrevOutputWithPrevTx(u, network) {
    let prevTx;
    if (typeof u.prevTx === 'string') {
        prevTx = Buffer.from(u.prevTx, 'hex');
    }
    else if (Buffer.isBuffer(u.prevTx)) {
        prevTx = u.prevTx;
    }
    else if (u.prevTx !== undefined) {
        throw new Error(`Invalid prevTx type for unspent ${u.prevTx}`);
    }
    return {
        ...parseOutputId(u.id),
        ...toOutput(u, network),
        prevTx,
    };
}
exports.toPrevOutputWithPrevTx = toPrevOutputWithPrevTx;
/**
 * @param txb
 * @param u
 * @param sequence - sequenceId
 */
function addToTransactionBuilder(txb, u, sequence) {
    const { txid, vout, script, value } = toPrevOutput(u, txb.network);
    txb.addInput(txid, vout, sequence, script, value);
}
exports.addToTransactionBuilder = addToTransactionBuilder;
/**
 * Sum the values of the unspents.
 * Throws error if sum is not a safe integer value, or if unspent amount types do not match `amountType`
 * @param unspents - array of unspents to sum
 * @param amountType - expected value type of unspents
 * @return unspentSum - type matches amountType
 */
function unspentSum(unspents, amountType = 'number') {
    if (amountType === 'bigint') {
        return unspents.reduce((sum, u) => sum + u.value, BigInt(0));
    }
    else {
        const sum = unspents.reduce((sum, u) => sum + u.value, Number(0));
        if (!Number.isSafeInteger(sum)) {
            throw new Error('unspent sum is not a safe integer number, consider using bigint');
        }
        return sum;
    }
}
exports.unspentSum = unspentSum;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiVW5zcGVudC5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9iaXRnby9VbnNwZW50LnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUVBLHdDQUE4RDtBQTRCOUQsU0FBZ0IsbUJBQW1CLENBQ2pDLENBQW1CO0lBRW5CLE9BQU8sTUFBTSxDQUFDLFFBQVEsQ0FBRSxDQUFnQyxDQUFDLE1BQU0sQ0FBQyxDQUFDO0FBQ25FLENBQUM7QUFKRCxrREFJQztBQUVEOztHQUVHO0FBQ0gsU0FBZ0IsUUFBUSxDQUFrQyxDQUFtQixFQUFFLE9BQWdCO0lBQzdGLE9BQU87UUFDTCxNQUFNLEVBQUUsd0JBQWMsQ0FBQyxDQUFDLENBQUMsT0FBTyxFQUFFLE9BQU8sQ0FBQztRQUMxQyxLQUFLLEVBQUUsQ0FBQyxDQUFDLEtBQUs7S0FDZixDQUFDO0FBQ0osQ0FBQztBQUxELDRCQUtDO0FBRUQ7O0dBRUc7QUFDSCxTQUFnQixVQUFVLENBQ3hCLEVBQTRCLEVBQzVCLElBQVk7SUFFWixNQUFNLENBQUMsR0FBRyxFQUFFLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxDQUFDO0lBQ3hCLElBQUksQ0FBQyxDQUFDLEVBQUU7UUFDTixNQUFNLElBQUksS0FBSyxDQUFDLGNBQWMsQ0FBQyxDQUFDO0tBQ2pDO0lBQ0QsT0FBTztRQUNMLEVBQUUsRUFBRSxjQUFjLENBQUMsRUFBRSxJQUFJLEVBQUUsRUFBRSxDQUFDLEtBQUssRUFBRSxFQUFFLElBQUksRUFBRSxDQUFDO1FBQzlDLE9BQU8sRUFBRSwwQkFBZ0IsQ0FBQyxDQUFDLENBQUMsTUFBTSxFQUFFLEVBQUUsQ0FBQyxPQUFPLENBQUM7UUFDL0MsS0FBSyxFQUFFLENBQUMsQ0FBQyxLQUFLO0tBQ2YsQ0FBQztBQUNKLENBQUM7QUFiRCxnQ0FhQztBQUVELFNBQWdCLG9CQUFvQixDQUNsQyxFQUE0QixFQUM1QixJQUFZO0lBRVosT0FBTztRQUNMLEdBQUcsVUFBVSxDQUFDLEVBQUUsRUFBRSxJ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QUFNLEVBQUUsSUFBSSxFQUFFLElBQUksRUFBRSxNQUFNLEVBQUUsS0FBSyxFQUFFLEdBQUcsWUFBWSxDQUFDLENBQUMsRUFBRSxHQUFHLENBQUMsT0FBa0IsQ0FBQyxDQUFDO0lBQzlFLEdBQUcsQ0FBQyxRQUFRLENBQUMsSUFBSSxFQUFFLElBQUksRUFBRSxRQUFRLEVBQUUsTUFBTSxFQUFFLEtBQUssQ0FBQyxDQUFDO0FBQ3BELENBQUM7QUFQRCwwREFPQztBQUVEOzs7Ozs7R0FNRztBQUNILFNBQWdCLFVBQVUsQ0FDeEIsUUFBOEIsRUFDOUIsYUFBa0MsUUFBUTtJQUUxQyxJQUFJLFVBQVUsS0FBSyxRQUFRLEVBQUU7UUFDM0IsT0FBTyxRQUFRLENBQUMsTUFBTSxDQUFDLENBQUMsR0FBRyxFQUFFLENBQUMsRUFBRSxFQUFFLENBQUMsR0FBRyxHQUFJLENBQUMsQ0FBQyxLQUFnQixFQUFFLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBWSxDQUFDO0tBQ3JGO1NBQU07UUFDTCxNQUFNLEdBQUcsR0FBRyxRQUFRLENBQUMsTUFBTSxDQUFDLENBQUMsR0FBRyxFQUFFLENBQUMsRUFBRSxFQUFFLENBQUMsR0FBRyxHQUFJLENBQUMsQ0FBQyxLQUFnQixFQUFFLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO1FBQzlFLElBQUksQ0FBQyxNQUFNLENBQUMsYUFBYSxDQUFDLEdBQUcsQ0FBQyxFQUFFO1lBQzlCLE1BQU0sSUFBSSxLQUFLLENBQUMsaUVBQWlFLENBQUMsQ0FBQztTQUNwRjtRQUNELE9BQU8sR0FBYyxDQUFDO0tBQ3ZCO0FBQ0gsQ0FBQztBQWJELGdDQWFDIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgVHhPdXRwdXQgfSBmcm9tICdiaXRjb2luanMtbGliJztcbmltcG9ydCB7IE5ldHdvcmsgfSBmcm9tICcuLic7XG5pbXBvcnQgeyBmcm9tT3V0cHV0U2NyaXB0LCB0b091dHB1dFNjcmlwdCB9IGZyb20gJy4uL2FkZHJlc3MnO1xuaW1wb3J0IHsgVXR4b1RyYW5zYWN0aW9uQnVpbGRlciB9IGZyb20gJy4vVXR4b1RyYW5zYWN0aW9uQnVpbGRlcic7XG5pbXBvcnQgeyBVdHhvVHJhbnNhY3Rpb24gfSBmcm9tICcuL1V0eG9UcmFuc2FjdGlvbic7XG5cbi8qKlxuICogUHVibGljIHVuc3BlbnQgZGF0YSBpbiBCaXRHby1zcGVjaWZpYyByZXByZXNlbnRhdGlvbi5cbiAqL1xuZXhwb3J0IGludGVyZmFjZSBVbnNwZW50PFROdW1iZXIgZXh0ZW5kcyBudW1iZXIgfCBiaWdpbnQgPSBudW1iZXI+IHtcbiAgLyoqXG4gICAqIEZvcm1hdDogJHt0eGlkfToke3ZvdXR9LlxuICAgKiBVc2UgYHBhcnNlT3V0cHV0SWQoaWQpYCB0byBwYXJzZS5cbiAgICovXG4gIGlkOiBzdHJpbmc7XG4gIC8qKlxuICAgKiBUaGUgbmV0d29yay1zcGVjaWZpYyBlbmNvZGVkIGFkZHJlc3MuXG4gICAqIFVzZSBgdG9PdXRwdXRTY3JpcHQoYWRkcmVzcywgbmV0d29yaylgIHRvIG9idGFpbiBzY3JpcHRQdWJLZXkuXG4gICAqL1xuICBhZGRyZXNzOiBzdHJpbmc7XG4gIC8qKlxuICAgKiBUaGUgYW1vdW50IGluIHNhdG9zaGkuXG4gICAqL1xuICB2YWx1ZTogVE51bWJlcjtcbn1cblxuZXhwb3J0IGludGVyZmFjZSBVbnNwZW50V2l0aFByZXZUeDxUTnVtYmVyIGV4dGVuZHMgbnVtYmVyIHwgYmlnaW50ID0gbnVtYmVyPiBleHRlbmRzIFVuc3BlbnQ8VE51bWJlcj4ge1xuICBwcmV2VHg6IEJ1ZmZlcjtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGlzVW5zcGVudFdpdGhQcmV2VHg8VE51bWJlciBleHRlbmRzIG51bWJlciB8IGJpZ2ludCwgVFVuc3BlbnQgZXh0ZW5kcyBVbnNwZW50PFROdW1iZXI+PihcbiAgdTogVW5zcGVudDxUTnVtYmVyPlxuKTogdSBpcyBUVW5zcGVudCAmIHsgcHJldlR4OiBCdWZmZXIgfSB7XG4gIHJldHVybiBCdWZmZXIuaXNCdWZmZXIoKHUgYXMgVW5zcGVudFdpdGhQcmV2VHg8VE51bWJlcj4pLnByZXZUeCk7XG59XG5cbi8qKlxuICogQHJldHVybiBUeE91dHB1dCBmcm9tIFVuc3BlbnRcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHRvT3V0cHV0PFROdW1iZXIgZXh0ZW5kcyBudW1iZXIgfCBiaWdpbnQ+KHU6IFVuc3BlbnQ8VE51bWJlcj4sIG5ldHdvcms6IE5ldHdvcmspOiBUeE91dHB1dDxUTnVtYmVyPiB7XG4gIHJldHVybiB7XG4gICAgc2NyaXB0OiB0b091dHB1dFNjcmlwdCh1LmFkZHJlc3MsIG5ldHdvcmspLFxuICAgIHZhbHVlOiB1LnZhbHVlLFxuICB9O1xufVxuXG4vKipcbiAqIEByZXR1cm4gVW5zcGVudCBmcm9tIFR4T3V0cHV0XG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBmcm9tT3V0cHV0PFROdW1iZXIgZXh0ZW5kcyBudW1iZXIgfCBiaWdpbnQ+KFxuICB0eDogVXR4b1RyYW5zYWN0aW9uPFROdW1iZXI+LFxuICB2b3V0OiBudW1iZXJcbik6IFVuc3BlbnQ8VE51bWJlcj4ge1xuICBjb25zdCBvID0gdHgub3V0c1t2b3V0XTtcbiAgaWYgKCFvKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKGBpbnZhbGlkIHZvdXRgKTtcbiAgfVxuICByZXR1cm4ge1xuICAgIGlkOiBmb3JtYXRPdXRwdXRJZCh7IHR4aWQ6IHR4LmdldElkKCksIHZvdXQgfSksXG4gICAgYWRkcmVzczogZnJvbU91dHB1dFNjcmlwdChvLnNjcmlwdCwgdHgubmV0d29yayksXG4gICAgdmFsdWU6IG8udmFsdWUsXG4gIH07XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBmcm9tT3V0cHV0V2l0aFByZXZUeDxUTnVtYmVyIGV4dGVuZHMgbnVtYmVyIHwgYmlnaW50PihcbiAgdHg6IFV0eG9UcmFuc2FjdGlvbjxUTnVtYmVyPixcbiAgdm91dDogbnVtYmVyXG4pOiBVbnNwZW50V2l0aFByZXZUeDxUTnVtYmVyPiB7XG4gIHJldHVybiB7XG4gICAgLi4uZnJvbU91dHB1dCh0eCwgdm91dCksXG4gICAgcHJldlR4OiB0eC50b0J1ZmZlcigpLFxuICB9O1xufVxuXG4vKipcbiAqIEBwYXJhbSBvdXRwdXRJZFxuICogQHJldHVybiBUeE91dFBvaW50XG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBwYXJzZU91dHB1dElkKG91dHB1dElkOiBzdHJpbmcpOiBUeE91dFBvaW50IHtcbiAgY29uc3QgcGFydHMgPSBvdXRwdXRJZC5zcGxpdCgnOicpO1xuICBpZiAocGFydHMubGVuZ3RoICE9PSAyKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKGBpbnZhbGlkIG91dHB1dElkLCBtdXN0IGhhdmUgZm9ybWF0IHR4aWQ6dm91dGApO1xuICB9XG4gIGNvbnN0IFt0eGlkLCB2b3V0U3RyXSA9IHBhcnRzO1xuICBjb25zdCB2b3V0ID0gTnVtYmVyKHZvdXRTdHIpO1xuICBpZiAodHhpZC5sZW5ndGggIT09IDY0KSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKGBpbnZhbGlkIHR4aWQgJHt0eGlkfSAke3R4aWQubGVuZ3RofWApO1xuICB9XG4gIGlmIChOdW1iZXIuaXNOYU4odm91dCkgfHwgdm91dCA8IDAgfHwgIU51bWJlci5pc1NhZmVJbnRlZ2VyKHZvdXQpKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKGBpbnZhbGlkIHZvdXQ6IG11c3QgYmUgaW50ZWdlciA+PSAwYCk7XG4gIH1cbiAgcmV0dXJuIHsgdHhpZCwgdm91dCB9O1xufVxuXG4vKipcbiAqIEBwYXJhbSB0eGlkXG4gKiBAcGFyYW0gdm91dFxuICogQHJldHVybiBvdXRwdXRJZFxuICovXG5leHBvcnQgZnVuY3Rpb24gZm9ybWF0T3V0cHV0SWQoeyB0eGlkLCB2b3V0IH06IFR4T3V0UG9pbnQpOiBzdHJpbmcge1xuICByZXR1cm4gYCR7dHhpZH06JHt2b3V0fWA7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBnZXRPdXRwdXRJZEZvcklucHV0KGk6IHsgaGFzaDogQnVmZmVyOyBpbmRleDogbnVtYmVyIH0pOiBUeE91dFBvaW50IHtcbiAgcmV0dXJuIHtcbiAgICB0eGlkOiBCdWZmZXIuZnJvbShpLmhhc2gpLnJldmVyc2UoKS50b1N0cmluZygnaGV4JyksXG4gICAgdm91dDogaS5pbmRleCxcbiAgfTtcbn1cblxuLyoqXG4gKiBSZWZlcmVuY2UgdG8gb3V0cHV0IG9mIGFuIGV4aXN0aW5nIHRyYW5zYWN0aW9uXG4gKi9cbmV4cG9ydCB0eXBlIFR4T3V0UG9pbnQgPSB7XG4gIHR4aWQ6IHN0cmluZztcbiAgdm91dDogbnVtYmVyO1xufTtcblxuLyoqXG4gKiBPdXRwdXQgcmVmZXJlbmNlIGFuZCBzY3JpcHQgZGF0YS5cbiAqIFN1aXRhYmxlIGZvciB1c2UgZm9yIGB0eGIuYWRkSW5wdXQoKWBcbiAqL1xuZXhwb3J0IHR5cGUgUHJldk91dHB1dDxUTnVtYmVyIGV4dGVuZHMgbnVtYmVyIHwgYmlnaW50ID0gbnVtYmVyPiA9IFR4T3V0UG9pbnQgJlxuICBUeE91dHB1dDxUTnVtYmVyPiAmIHtcbiAgICBwcmV2VHg/OiBCdWZmZXI7XG4gIH07XG5cbi8qKlxuICogQHJldHVybiBQcmV2T3V0cHV0IGZyb20gVW5zcGVudFxuICovXG5leHBvcnQgZnVuY3Rpb24gdG9QcmV2T3V0cHV0PFROdW1iZXIgZXh0ZW5kcyBudW1iZXIgfCBiaWdpbnQ+KFxuICB1OiBVbnNwZW50PFROdW1iZXI+LFxuICBuZXR3b3JrOiBOZXR3b3JrXG4pOiBQcmV2T3V0cHV0PFROdW1iZXI+IHtcbiAgcmV0dXJuIHtcbiAgICAuLi5wYXJzZU91dHB1dElkKHUuaWQpLFxuICAgIC4uLnRvT3V0cHV0KHUsIG5ldHdvcmspLFxuICB9O1xufVxuXG4vKipcbiAqIEByZXR1cm4gUHJldk91dHB1dCB3aXRoIHByZXZUeCBmcm9tIFVuc3BlbnRcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHRvUHJldk91dHB1dFdpdGhQcmV2VHg8VE51bWJlciBleHRlbmRzIG51bWJlciB8IGJpZ2ludD4oXG4gIHU6IFVuc3BlbnQ8VE51bWJlcj4gJiB7IHByZXZUeD86IHVua25vd24gfSxcbiAgbmV0d29yazogTmV0d29ya1xuKTogUHJldk91dHB1dDxUTnVtYmVyPiB7XG4gIGxldCBwcmV2VHg7XG4gIGlmICh0eXBlb2YgdS5wcmV2VHggPT09ICdzdHJpbmcnKSB7XG4gICAgcHJldlR4ID0gQnVmZmVyLmZyb20odS5wcmV2VHgsICdoZXgnKTtcbiAgfSBlbHNlIGlmIChCdWZmZXIuaXNCdWZmZXIodS5wcmV2VHgpKSB7XG4gICAgcHJldlR4ID0gdS5wcmV2VHg7XG4gIH0gZWxzZSBpZiAodS5wcmV2VHggIT09IHVuZGVmaW5lZCkge1xuICAgIHRocm93IG5ldyBFcnJvcihgSW52YWxpZCBwcmV2VHggdHlwZSBmb3IgdW5zcGVudCAke3UucHJldlR4fWApO1xuICB9XG4gIHJldHVybiB7XG4gICAgLi4ucGFyc2VPdXRwdXRJZCh1LmlkKSxcbiAgICAuLi50b091dHB1dCh1LCBuZXR3b3JrKSxcbiAgICBwcmV2VHgsXG4gIH07XG59XG5cbi8qKlxuICogQHBhcmFtIHR4YlxuICogQHBhcmFtIHVcbiAqIEBwYXJhbSBzZXF1ZW5jZSAtIHNlcXVlbmNlSWRcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGFkZFRvVHJhbnNhY3Rpb25CdWlsZGVyPFROdW1iZXIgZXh0ZW5kcyBudW1iZXIgfCBiaWdpbnQ+KFxuICB0eGI6IFV0eG9UcmFuc2FjdGlvbkJ1aWxkZXI8VE51bWJlcj4sXG4gIHU6IFVuc3BlbnQ8VE51bWJlcj4sXG4gIHNlcXVlbmNlPzogbnVtYmVyXG4pOiB2b2lkIHtcbiAgY29uc3QgeyB0eGlkLCB2b3V0LCBzY3JpcHQsIHZhbHVlIH0gPSB0b1ByZXZPdXRwdXQodSwgdHhiLm5ldHdvcmsgYXMgTmV0d29yayk7XG4gIHR4Yi5hZGRJbnB1dCh0eGlkLCB2b3V0LCBzZXF1ZW5jZSwgc2NyaXB0LCB2YWx1ZSk7XG59XG5cbi8qKlxuICogU3VtIHRoZSB2YWx1ZXMgb2YgdGhlIHVuc3BlbnRzLlxuICogVGhyb3dzIGVycm9yIGlmIHN1bSBpcyBub3QgYSBzYWZlIGludGVnZXIgdmFsdWUsIG9yIGlmIHVuc3BlbnQgYW1vdW50IHR5cGVzIGRvIG5vdCBtYXRjaCBgYW1vdW50VHlwZWBcbiAqIEBwYXJhbSB1bnNwZW50cyAtIGFycmF5IG9mIHVuc3BlbnRzIHRvIHN1bVxuICogQHBhcmFtIGFtb3VudFR5cGUgLSBleHBlY3RlZCB2YWx1ZSB0eXBlIG9mIHVuc3BlbnRzXG4gKiBAcmV0dXJuIHVuc3BlbnRTdW0gLSB0eXBlIG1hdGNoZXMgYW1vdW50VHlwZVxuICovXG5leHBvcnQgZnVuY3Rpb24gdW5zcGVudFN1bTxUTnVtYmVyIGV4dGVuZHMgbnVtYmVyIHwgYmlnaW50PihcbiAgdW5zcGVudHM6IHsgdmFsdWU6IFROdW1iZXIgfVtdLFxuICBhbW91bnRUeXBlOiAnbnVtYmVyJyB8ICdiaWdpbnQnID0gJ251bWJlcidcbik6IFROdW1iZXIge1xuICBpZiAoYW1vdW50VHlwZSA9PT0gJ2JpZ2ludCcpIHtcbiAgICByZXR1cm4gdW5zcGVudHMucmVkdWNlKChzdW0sIHUpID0+IHN1bSArICh1LnZhbHVlIGFzIGJpZ2ludCksIEJpZ0ludCgwKSkgYXMgVE51bWJlcjtcbiAgfSBlbHNlIHtcbiAgICBjb25zdCBzdW0gPSB1bnNwZW50cy5yZWR1Y2UoKHN1bSwgdSkgPT4gc3VtICsgKHUudmFsdWUgYXMgbnVtYmVyKSwgTnVtYmVyKDApKTtcbiAgICBpZiAoIU51bWJlci5pc1NhZmVJbnRlZ2VyKHN1bSkpIHtcbiAgICAgIHRocm93IG5ldyBFcnJvcigndW5zcGVudCBzdW0gaXMgbm90IGEgc2FmZSBpbnRlZ2VyIG51bWJlciwgY29uc2lkZXIgdXNpbmcgYmlnaW50Jyk7XG4gICAgfVxuICAgIHJldHVybiBzdW0gYXMgVE51bWJlcjtcbiAgfVxufVxuIl19