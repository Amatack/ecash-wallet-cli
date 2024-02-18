"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.toBufferV5 = exports.toBufferV4 = exports.writeOutputs = exports.writeInputs = exports.fromBufferV5 = exports.fromBufferV4 = exports.writeEmptySamplingBundle = exports.readEmptySaplingBundle = exports.writeEmptyOrchardBundle = exports.readEmptyOrchardBundle = exports.readEmptyVector = exports.readOutputs = exports.readInputs = exports.VALUE_INT64_ZERO = void 0;
const ZcashTransaction_1 = require("./ZcashTransaction");
exports.VALUE_INT64_ZERO = Buffer.from('0000000000000000', 'hex');
function readInputs(bufferReader) {
    const vinLen = bufferReader.readVarInt();
    const ins = [];
    for (let i = 0; i < vinLen; ++i) {
        ins.push({
            hash: bufferReader.readSlice(32),
            index: bufferReader.readUInt32(),
            script: bufferReader.readVarSlice(),
            sequence: bufferReader.readUInt32(),
            witness: [],
        });
    }
    return ins;
}
exports.readInputs = readInputs;
function readOutputs(bufferReader, amountType = 'number') {
    const voutLen = bufferReader.readVarInt();
    const outs = [];
    for (let i = 0; i < voutLen; ++i) {
        outs.push({
            value: (amountType === 'bigint' ? bufferReader.readUInt64BigInt() : bufferReader.readUInt64()),
            script: bufferReader.readVarSlice(),
        });
    }
    return outs;
}
exports.readOutputs = readOutputs;
function readEmptyVector(bufferReader) {
    const n = bufferReader.readVarInt();
    if (n !== 0) {
        throw new ZcashTransaction_1.UnsupportedTransactionError(`expected empty vector`);
    }
}
exports.readEmptyVector = readEmptyVector;
function readEmptyOrchardBundle(bufferReader) {
    // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/orchard.h#L66
    // https://github.com/zcash/librustzcash/blob/edcde252de221d4851f1e5145306c2caf95453bc/zcash_primitives/src/transaction/components/orchard.rs#L36
    const v = bufferReader.readUInt8();
    if (v !== 0x00) {
        throw new ZcashTransaction_1.UnsupportedTransactionError(`expected byte 0x00`);
    }
}
exports.readEmptyOrchardBundle = readEmptyOrchardBundle;
function writeEmptyOrchardBundle(bufferWriter) {
    // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/orchard.h#L66
    // https://github.com/zcash/librustzcash/blob/edcde252de221d4851f1e5145306c2caf95453bc/zcash_primitives/src/transaction/components/orchard.rs#L201
    bufferWriter.writeUInt8(0);
}
exports.writeEmptyOrchardBundle = writeEmptyOrchardBundle;
function readEmptySaplingBundle(bufferReader) {
    // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/transaction.h#L283
    readEmptyVector(bufferReader) /* vSpendsSapling */;
    readEmptyVector(bufferReader) /* vOutputsSapling */;
}
exports.readEmptySaplingBundle = readEmptySaplingBundle;
function writeEmptySamplingBundle(bufferWriter) {
    // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/transaction.h#L283
    bufferWriter.writeVarInt(0) /* vSpendsSapling */;
    bufferWriter.writeVarInt(0) /* vOutputsSapling */;
}
exports.writeEmptySamplingBundle = writeEmptySamplingBundle;
function fromBufferV4(bufferReader, tx, amountType = 'number') {
    // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/transaction.h#L855-L857
    tx.ins = readInputs(bufferReader);
    tx.outs = readOutputs(bufferReader, amountType);
    tx.locktime = bufferReader.readUInt32();
    if (tx.isOverwinterCompatible()) {
        tx.expiryHeight = bufferReader.readUInt32();
    }
    if (tx.isSaplingCompatible()) {
        const valueBalance = bufferReader.readSlice(8);
        if (!valueBalance.equals(exports.VALUE_INT64_ZERO)) {
            /* istanbul ignore next */
            throw new ZcashTransaction_1.UnsupportedTransactionError(`valueBalance must be zero`);
        }
        // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/transaction.h#L863
        readEmptySaplingBundle(bufferReader);
    }
    if (tx.supportsJoinSplits()) {
        // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/transaction.h#L869
        readEmptyVector(bufferReader) /* vJoinSplit */;
    }
}
exports.fromBufferV4 = fromBufferV4;
function fromBufferV5(bufferReader, tx, amountType = 'number') {
    // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/transaction.h#L815
    tx.consensusBranchId = bufferReader.readUInt32();
    tx.locktime = bufferReader.readUInt32();
    tx.expiryHeight = bufferReader.readUInt32();
    // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/transaction.h#L828
    tx.ins = readInputs(bufferReader);
    tx.outs = readOutputs(bufferReader, amountType);
    // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/transaction.h#L835
    readEmptySaplingBundle(bufferReader);
    readEmptyOrchardBundle(bufferReader);
}
exports.fromBufferV5 = fromBufferV5;
function writeInputs(bufferWriter, ins) {
    bufferWriter.writeVarInt(ins.length);
    ins.forEach(function (txIn) {
        bufferWriter.writeSlice(txIn.hash);
        bufferWriter.writeUInt32(txIn.index);
        bufferWriter.writeVarSlice(txIn.script);
        bufferWriter.writeUInt32(txIn.sequence);
    });
}
exports.writeInputs = writeInputs;
function writeOutputs(bufferWriter, outs) {
    bufferWriter.writeVarInt(outs.length);
    outs.forEach(function (txOut) {
        if (txOut.valueBuffer) {
            bufferWriter.writeSlice(txOut.valueBuffer);
        }
        else {
            bufferWriter.writeUInt64(txOut.value);
        }
        bufferWriter.writeVarSlice(txOut.script);
    });
}
exports.writeOutputs = writeOutputs;
function toBufferV4(bufferWriter, tx) {
    // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/transaction.h#L1083
    writeInputs(bufferWriter, tx.ins);
    writeOutputs(bufferWriter, tx.outs);
    bufferWriter.writeUInt32(tx.locktime);
    if (tx.isOverwinterCompatible()) {
        bufferWriter.writeUInt32(tx.expiryHeight);
    }
    if (tx.isSaplingCompatible()) {
        bufferWriter.writeSlice(exports.VALUE_INT64_ZERO);
        bufferWriter.writeVarInt(0); // vShieldedSpendLength
        bufferWriter.writeVarInt(0); // vShieldedOutputLength
    }
    if (tx.supportsJoinSplits()) {
        bufferWriter.writeVarInt(0); // joinsSplits length
    }
}
exports.toBufferV4 = toBufferV4;
function toBufferV5(bufferWriter, tx) {
    // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/transaction.h#L825-L826
    bufferWriter.writeUInt32(tx.consensusBranchId);
    bufferWriter.writeUInt32(tx.locktime);
    bufferWriter.writeUInt32(tx.expiryHeight);
    writeInputs(bufferWriter, tx.ins);
    writeOutputs(bufferWriter, tx.outs);
    // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/transaction.h#L1063
    writeEmptySamplingBundle(bufferWriter);
    // https://github.com/zcash/zcash/blob/v4.5.1/src/primitives/transaction.h#L1081
    writeEmptyOrchardBundle(bufferWriter);
}
exports.toBufferV5 = toBufferV5;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiWmNhc2hCdWZmZXJ1dGlscy5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL3NyYy9iaXRnby96Y2FzaC9aY2FzaEJ1ZmZlcnV0aWxzLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQVVBLHlEQUFtRjtBQUV0RSxRQUFBLGdCQUFnQixHQUFHLE1BQU0sQ0FBQyxJQUFJLENBQUMsa0JBQWtCLEVBQUUsS0FBSyxDQUFDLENBQUM7QUFFdkUsU0FBZ0IsVUFBVSxDQUFDLFlBQTBCO0lBQ25ELE1BQU0sTUFBTSxHQUFHLFlBQVksQ0FBQyxVQUFVLEVBQUUsQ0FBQztJQUN6QyxNQUFNLEdBQUcsR0FBYyxFQUFFLENBQUM7SUFDMUIsS0FBSyxJQUFJLENBQUMsR0FBRyxDQUFDLEVBQUUsQ0FBQyxHQUFHLE1BQU0sRUFBRSxFQUFFLENBQUMsRUFBRTtRQUMvQixHQUFHLENBQUMsSUFBSSxDQUFDO1lBQ1AsSUFBSSxFQUFFLFlBQVksQ0FBQyxTQUFTLENBQUMsRUFBRSxDQUFDO1lBQ2hDLEtBQUssRUFBRSxZQUFZLENBQUMsVUFBVSxFQUFFO1lBQ2hDLE1BQU0sRUFBRSxZQUFZLENBQUMsWUFBWSxFQUFFO1lBQ25DLFFBQVEsRUFBRSxZQUFZLENBQUMsVUFBVSxFQUFFO1lBQ25DLE9BQU8sRUFBRSxFQUFFO1NBQ1osQ0FBQyxDQUFDO0tBQ0o7SUFDRCxPQUFPLEdBQUcsQ0FBQztBQUNiLENBQUM7QUFiRCxnQ0FhQztBQUVELFNBQWdCLFdBQVcsQ0FDekIsWUFBMEIsRUFDMUIsYUFBa0MsUUFBUTtJQUUxQyxNQUFNLE9BQU8sR0FBRyxZQUFZLENBQUMsVUFBVSxFQUFFLENBQUM7SUFDMUMsTUFBTSxJQUFJLEdBQXdCLEVBQUUsQ0FBQztJQUNyQyxLQUFLLElBQUksQ0FBQyxHQUFHLENBQUMsRUFBRSxDQUFDLEdBQUcsT0FBTyxFQUFFLEVBQUUsQ0FBQyxFQUFFO1FBQ2hDLElBQUksQ0FBQyxJQUFJLENBQUM7WUFDUixLQUFLLEVBQUUs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QUFDLEVBQUUsQ0FBQyxpQkFBaUIsQ0FBQyxDQUFDO0lBQy9DLFlBQVksQ0FBQyxXQUFXLENBQUMsRUFBRSxDQUFDLFFBQVEsQ0FBQyxDQUFDO0lBQ3RDLFlBQVksQ0FBQyxXQUFXLENBQUMsRUFBRSxDQUFDLFlBQVksQ0FBQyxDQUFDO0lBQzFDLFdBQVcsQ0FBQyxZQUFZLEVBQUUsRUFBRSxDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBQ2xDLFlBQVksQ0FBVSxZQUFZLEVBQUUsRUFBRSxDQUFDLElBQUksQ0FBQyxDQUFDO0lBRTdDLGdGQUFnRjtJQUNoRix3QkFBd0IsQ0FBQyxZQUFZLENBQUMsQ0FBQztJQUN2QyxnRkFBZ0Y7SUFDaEYsdUJBQXVCLENBQUMsWUFBWSxDQUFDLENBQUM7QUFDeEMsQ0FBQztBQWZELGdDQWVDIiwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gKiBUcmFuc2FjdGlvbiAoZGUpc2VyaWFsaXphdGlvbiBoZWxwZXJzLlxuICogT25seSBzdXBwb3J0cyBmdWxsIHRyYW5zcGFyZW50IHRyYW5zYWN0aW9ucyB3aXRob3V0IHNoaWVsZGVkIGlucHV0cyBvciBvdXRwdXRzLlxuICpcbiAqIFJlZmVyZW5jZXM6XG4gKiAtIGh0dHBzOi8vZ2l0aHViLmNvbS96Y2FzaC96Y2FzaC9ibG9iL3Y0LjUuMS9zcmMvcHJpbWl0aXZlcy90cmFuc2FjdGlvbi5oI0w3NzFcbiAqL1xuaW1wb3J0IHsgVHhJbnB1dCwgVHhPdXRwdXQgfSBmcm9tICdiaXRjb2luanMtbGliJztcbmltcG9ydCB7IEJ1ZmZlclJlYWRlciwgQnVmZmVyV3JpdGVyIH0gZnJvbSAnYml0Y29pbmpzLWxpYi9zcmMvYnVmZmVydXRpbHMnO1xuXG5pbXBvcnQgeyBVbnN1cHBvcnRlZFRyYW5zYWN0aW9uRXJyb3IsIFpjYXNoVHJhbnNhY3Rpb24gfSBmcm9tICcuL1pjYXNoVHJhbnNhY3Rpb24nO1xuXG5leHBvcnQgY29uc3QgVkFMVUVfSU5UNjRfWkVSTyA9IEJ1ZmZlci5mcm9tKCcwMDAwMDAwMDAwMDAwMDAwJywgJ2hleCcpO1xuXG5leHBvcnQgZnVuY3Rpb24gcmVhZElucHV0cyhidWZmZXJSZWFkZXI6IEJ1ZmZlclJlYWRlcik6IFR4SW5wdXRbXSB7XG4gIGNvbnN0IHZpbkxlbiA9IGJ1ZmZlclJlYWRlci5yZWFkVmFySW50KCk7XG4gIGNvbnN0IGluczogVHhJbnB1dFtdID0gW107XG4gIGZvciAobGV0IGkgPSAwOyBpIDwgdmluTGVuOyArK2kpIHtcbiAgICBpbnMucHVzaCh7XG4gICAgICBoYXNoOiBidWZmZXJSZWFkZXIucmVhZFNsaWNlKDMyKSxcbiAgICAgIGluZGV4OiBidWZmZXJSZWFkZXIucmVhZFVJbnQzMigpLFxuICAgICAgc2NyaXB0OiBidWZmZXJSZWFkZXIucmVhZFZhclNsaWNlKCksXG4gICAgICBzZXF1ZW5jZTogYnVmZmVyUmVhZGVyLnJlYWRVSW50MzIoKSxcbiAgICAgIHdpdG5lc3M6IFtdLFxuICAgIH0pO1xuICB9XG4gIHJldHVybiBpbnM7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiByZWFkT3V0cHV0czxUTnVtYmVyIGV4dGVuZHMgbnVtYmVyIHwgYmlnaW50PihcbiAgYnVmZmVyUmVhZGVyOiBCdWZmZXJSZWFkZXIsXG4gIGFtb3VudFR5cGU6ICdudW1iZXInIHwgJ2JpZ2ludCcgPSAnbnVtYmVyJ1xuKTogVHhPdXRwdXQ8VE51bWJlcj5bXSB7XG4gIGNvbnN0IHZvdXRMZW4gPSBidWZmZXJSZWFkZXIucmVhZFZhckludCgpO1xuICBjb25zdCBvdXRzOiBUeE91dHB1dDxUTnVtYmVyPltdID0gW107XG4gIGZvciAobGV0IGkgPSAwOyBpIDwgdm91dExlbjsgKytpKSB7XG4gICAgb3V0cy5wdXNoKHtcbiAgICAgIHZhbHVlOiAoYW1vdW50VHlwZSA9PT0gJ2JpZ2ludCcgPyBidWZmZXJSZWFkZXIucmVhZFVJbnQ2NEJpZ0ludCgpIDogYnVmZmVyUmVhZGVyLnJlYWRVSW50NjQoKSkgYXMgVE51bWJlcixcbiAgICAgIHNjcmlwdDogYnVmZmVyUmVhZGVyLnJlYWRWYXJTbGljZSgpLFxuICAgIH0pO1xuICB9XG4gIHJldHVybiBvdXRzO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gcmVhZEVtcHR5VmVjdG9yKGJ1ZmZlclJlYWRlcjogQnVmZmVyUmVhZGVyKTogdm9pZCB7XG4gIGNvbnN0IG4gPSBidWZmZXJSZWFkZXIucmVhZFZhckludCgpO1xuICBpZiAobiAhPT0gMCkge1xuICAgIHRocm93IG5ldyBVbnN1cHBvcnRlZFRyYW5zYWN0aW9uRXJyb3IoYGV4cGVjdGVkIGVtcHR5IHZlY3RvcmApO1xuICB9XG59XG5cbmV4cG9ydCBmdW5jdGlvbiByZWFkRW1wdHlPcmNoYXJkQnVuZGxlKGJ1ZmZlclJlYWRlcjogQnVmZmVyUmVhZGVyKTogdm9pZCB7XG4gIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS96Y2FzaC96Y2FzaC9ibG9iL3Y0LjUuMS9zcmMvcHJpbWl0aXZlcy9vcmNoYXJkLmgjTDY2XG4gIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS96Y2FzaC9saWJydXN0emNhc2gvYmxvYi9lZGNkZTI1MmRlMjIxZDQ4NTFmMWU1MTQ1MzA2YzJjYWY5NTQ1M2JjL3pjYXNoX3ByaW1pdGl2ZXMvc3JjL3RyYW5zYWN0aW9uL2NvbXBvbmVudHMvb3JjaGFyZC5ycyNMMzZcbiAgY29uc3QgdiA9IGJ1ZmZlclJlYWRlci5yZWFkVUludDgoKTtcbiAgaWYgKHYgIT09IDB4MDApIHtcbiAgICB0aHJvdyBuZXcgVW5zdXBwb3J0ZWRUcmFuc2FjdGlvbkVycm9yKGBleHBlY3RlZCBieXRlIDB4MDBgKTtcbiAgfVxufVxuXG5leHBvcnQgZnVuY3Rpb24gd3JpdGVFbXB0eU9yY2hhcmRCdW5kbGUoYnVmZmVyV3JpdGVyOiBCdWZmZXJXcml0ZXIpOiB2b2lkIHtcbiAgLy8gaHR0cHM6Ly9naXRodWIuY29tL3pjYXNoL3pjYXNoL2Jsb2IvdjQuNS4xL3NyYy9wcmltaXRpdmVzL29yY2hhcmQuaCNMNjZcbiAgLy8gaHR0cHM6Ly9naXRodWIuY29tL3pjYXNoL2xpYnJ1c3R6Y2FzaC9ibG9iL2VkY2RlMjUyZGUyMjFkNDg1MWYxZTUxNDUzMDZjMmNhZjk1NDUzYmMvemNhc2hfcHJpbWl0aXZlcy9zcmMvdHJhbnNhY3Rpb24vY29tcG9uZW50cy9vcmNoYXJkLnJzI0wyMDFcbiAgYnVmZmVyV3JpdGVyLndyaXRlVUludDgoMCk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiByZWFkRW1wdHlTYXBsaW5nQnVuZGxlKGJ1ZmZlclJlYWRlcjogQnVmZmVyUmVhZGVyKTogdm9pZCB7XG4gIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS96Y2FzaC96Y2FzaC9ibG9iL3Y0LjUuMS9zcmMvcHJpbWl0aXZlcy90cmFuc2FjdGlvbi5oI0wyODNcbiAgcmVhZEVtcHR5VmVjdG9yKGJ1ZmZlclJlYWRlcikgLyogdlNwZW5kc1NhcGxpbmcgKi87XG4gIHJlYWRFbXB0eVZlY3RvcihidWZmZXJSZWFkZXIpIC8qIHZPdXRwdXRzU2FwbGluZyAqLztcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHdyaXRlRW1wdHlTYW1wbGluZ0J1bmRsZShidWZmZXJXcml0ZXI6IEJ1ZmZlcldyaXRlcik6IHZvaWQge1xuICAvLyBodHRwczovL2dpdGh1Yi5jb20vemNhc2gvemNhc2gvYmxvYi92NC41LjEvc3JjL3ByaW1pdGl2ZXMvdHJhbnNhY3Rpb24uaCNMMjgzXG4gIGJ1ZmZlcldyaXRlci53cml0ZVZhckludCgwKSAvKiB2U3BlbmRzU2FwbGluZyAqLztcbiAgYnVmZmVyV3JpdGVyLndyaXRlVmFySW50KDApIC8qIHZPdXRwdXRzU2FwbGluZyAqLztcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIGZyb21CdWZmZXJWNDxUTnVtYmVyIGV4dGVuZHMgbnVtYmVyIHwgYmlnaW50PihcbiAgYnVmZmVyUmVhZGVyOiBCdWZmZXJSZWFkZXIsXG4gIHR4OiBaY2FzaFRyYW5zYWN0aW9uPFROdW1iZXI+LFxuICBhbW91bnRUeXBlOiAnbnVtYmVyJyB8ICdiaWdpbnQnID0gJ251bWJlcidcbik6IHZvaWQge1xuICAvLyBodHRwczovL2dpdGh1Yi5jb20vemNhc2gvemNhc2gvYmxvYi92NC41LjEvc3JjL3ByaW1pdGl2ZXMvdHJhbnNhY3Rpb24uaCNMODU1LUw4NTdcbiAgdHguaW5zID0gcmVhZElucHV0cyhidWZmZXJSZWFkZXIpO1xuICB0eC5vdXRzID0gcmVhZE91dHB1dHM8VE51bWJlcj4oYnVmZmVyUmVhZGVyLCBhbW91bnRUeXBlKTtcbiAgdHgubG9ja3RpbWUgPSBidWZmZXJSZWFkZXIucmVhZFVJbnQzMigpO1xuXG4gIGlmICh0eC5pc092ZXJ3aW50ZXJDb21wYXRpYmxlKCkpIHtcbiAgICB0eC5leHBpcnlIZWlnaHQgPSBidWZmZXJSZWFkZXIucmVhZFVJbnQzMigpO1xuICB9XG5cbiAgaWYgKHR4LmlzU2FwbGluZ0NvbXBhdGlibGUoKSkge1xuICAgIGNvbnN0IHZhbHVlQmFsYW5jZSA9IGJ1ZmZlclJlYWRlci5yZWFkU2xpY2UoOCk7XG4gICAgaWYgKCF2YWx1ZUJhbGFuY2UuZXF1YWxzKFZBTFVFX0lOVDY0X1pFUk8pKSB7XG4gICAgICAvKiBpc3RhbmJ1bCBpZ25vcmUgbmV4dCAqL1xuICAgICAgdGhyb3cgbmV3IFVuc3VwcG9ydGVkVHJhbnNhY3Rpb25FcnJvcihgdmFsdWVCYWxhbmNlIG11c3QgYmUgemVyb2ApO1xuICAgIH1cblxuICAgIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS96Y2FzaC96Y2FzaC9ibG9iL3Y0LjUuMS9zcmMvcHJpbWl0aXZlcy90cmFuc2FjdGlvbi5oI0w4NjNcbiAgICByZWFkRW1wdHlTYXBsaW5nQnVuZGxlKGJ1ZmZlclJlYWRlcik7XG4gIH1cblxuICBpZiAodHguc3VwcG9ydHNKb2luU3BsaXRzKCkpIHtcbiAgICAvLyBodHRwczovL2dpdGh1Yi5jb20vemNhc2gvemNhc2gvYmxvYi92NC41LjEvc3JjL3ByaW1pdGl2ZXMvdHJhbnNhY3Rpb24uaCNMODY5XG4gICAgcmVhZEVtcHR5VmVjdG9yKGJ1ZmZlclJlYWRlcikgLyogdkpvaW5TcGxpdCAqLztcbiAgfVxufVxuXG5leHBvcnQgZnVuY3Rpb24gZnJvbUJ1ZmZlclY1PFROdW1iZXIgZXh0ZW5kcyBudW1iZXIgfCBiaWdpbnQ+KFxuICBidWZmZXJSZWFkZXI6IEJ1ZmZlclJlYWRlcixcbiAgdHg6IFpjYXNoVHJhbnNhY3Rpb248VE51bWJlcj4sXG4gIGFtb3VudFR5cGU6ICdudW1iZXInIHwgJ2JpZ2ludCcgPSAnbnVtYmVyJ1xuKTogdm9pZCB7XG4gIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS96Y2FzaC96Y2FzaC9ibG9iL3Y0LjUuMS9zcmMvcHJpbWl0aXZlcy90cmFuc2FjdGlvbi5oI0w4MTVcbiAgdHguY29uc2Vuc3VzQnJhbmNoSWQgPSBidWZmZXJSZWFkZXIucmVhZFVJbnQzMigpO1xuICB0eC5sb2NrdGltZSA9IGJ1ZmZlclJlYWRlci5yZWFkVUludDMyKCk7XG4gIHR4LmV4cGlyeUhlaWdodCA9IGJ1ZmZlclJlYWRlci5yZWFkVUludDMyKCk7XG5cbiAgLy8gaHR0cHM6Ly9naXRodWIuY29tL3pjYXNoL3pjYXNoL2Jsb2IvdjQuNS4xL3NyYy9wcmltaXRpdmVzL3RyYW5zYWN0aW9uLmgjTDgyOFxuICB0eC5pbnMgPSByZWFkSW5wdXRzKGJ1ZmZlclJlYWRlcik7XG4gIHR4Lm91dHMgPSByZWFkT3V0cHV0czxUTnVtYmVyPihidWZmZXJSZWFkZXIsIGFtb3VudFR5cGUpO1xuXG4gIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS96Y2FzaC96Y2FzaC9ibG9iL3Y0LjUuMS9zcmMvcHJpbWl0aXZlcy90cmFuc2FjdGlvbi5oI0w4MzVcbiAgcmVhZEVtcHR5U2FwbGluZ0J1bmRsZShidWZmZXJSZWFkZXIpO1xuICByZWFkRW1wdHlPcmNoYXJkQnVuZGxlKGJ1ZmZlclJlYWRlcik7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiB3cml0ZUlucHV0cyhidWZmZXJXcml0ZXI6IEJ1ZmZlcldyaXRlciwgaW5zOiBUeElucHV0W10pOiB2b2lkIHtcbiAgYnVmZmVyV3JpdGVyLndyaXRlVmFySW50KGlucy5sZW5ndGgpO1xuICBpbnMuZm9yRWFjaChmdW5jdGlvbiAodHhJbikge1xuICAgIGJ1ZmZlcldyaXRlci53cml0ZVNsaWNlKHR4SW4uaGFzaCk7XG4gICAgYnVmZmVyV3JpdGVyLndyaXRlVUludDMyKHR4SW4uaW5kZXgpO1xuICAgIGJ1ZmZlcldyaXRlci53cml0ZVZhclNsaWNlKHR4SW4uc2NyaXB0KTtcbiAgICBidWZmZXJXcml0ZXIud3JpdGVVSW50MzIodHhJbi5zZXF1ZW5jZSk7XG4gIH0pO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gd3JpdGVPdXRwdXRzPFROdW1iZXIgZXh0ZW5kcyBudW1iZXIgfCBiaWdpbnQ+KFxuICBidWZmZXJXcml0ZXI6IEJ1ZmZlcldyaXRlcixcbiAgb3V0czogVHhPdXRwdXQ8VE51bWJlcj5bXVxuKTogdm9pZCB7XG4gIGJ1ZmZlcldyaXRlci53cml0ZVZhckludChvdXRzLmxlbmd0aCk7XG4gIG91dHMuZm9yRWFjaChmdW5jdGlvbiAodHhPdXQpIHtcbiAgICBpZiAoKHR4T3V0IGFzIGFueSkudmFsdWVCdWZmZXIpIHtcbiAgICAgIGJ1ZmZlcldyaXRlci53cml0ZVNsaWNlKCh0eE91dCBhcyBhbnkpLnZhbHVlQnVmZmVyKTtcbiAgICB9IGVsc2Uge1xuICAgICAgYnVmZmVyV3JpdGVyLndyaXRlVUludDY0KHR4T3V0LnZhbHVlKTtcbiAgICB9XG5cbiAgICBidWZmZXJXcml0ZXIud3JpdGVWYXJTbGljZSh0eE91dC5zY3JpcHQpO1xuICB9KTtcbn1cblxuZXhwb3J0IGZ1bmN0aW9uIHRvQnVmZmVyVjQ8VE51bWJlciBleHRlbmRzIG51bWJlciB8IGJpZ2ludD4oXG4gIGJ1ZmZlcldyaXRlcjogQnVmZmVyV3JpdGVyLFxuICB0eDogWmNhc2hUcmFuc2FjdGlvbjxUTnVtYmVyPlxuKTogdm9pZCB7XG4gIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS96Y2FzaC96Y2FzaC9ibG9iL3Y0LjUuMS9zcmMvcHJpbWl0aXZlcy90cmFuc2FjdGlvbi5oI0wxMDgzXG4gIHdyaXRlSW5wdXRzKGJ1ZmZlcldyaXRlciwgdHguaW5zKTtcbiAgd3JpdGVPdXRwdXRzPFROdW1iZXI+KGJ1ZmZlcldyaXRlciwgdHgub3V0cyk7XG5cbiAgYnVmZmVyV3JpdGVyLndyaXRlVUludDMyKHR4LmxvY2t0aW1lKTtcblxuICBpZiAodHguaXNPdmVyd2ludGVyQ29tcGF0aWJsZSgpKSB7XG4gICAgYnVmZmVyV3JpdGVyLndyaXRlVUludDMyKHR4LmV4cGlyeUhlaWdodCk7XG4gIH1cblxuICBpZiAodHguaXNTYXBsaW5nQ29tcGF0aWJsZSgpKSB7XG4gICAgYnVmZmVyV3JpdGVyLndyaXRlU2xpY2UoVkFMVUVfSU5UNjRfWkVSTyk7XG4gICAgYnVmZmVyV3JpdGVyLndyaXRlVmFySW50KDApOyAvLyB2U2hpZWxkZWRTcGVuZExlbmd0aFxuICAgIGJ1ZmZlcldyaXRlci53cml0ZVZhckludCgwKTsgLy8gdlNoaWVsZGVkT3V0cHV0TGVuZ3RoXG4gIH1cblxuICBpZiAodHguc3VwcG9ydHNKb2luU3BsaXRzKCkpIHtcbiAgICBidWZmZXJXcml0ZXIud3JpdGVWYXJJbnQoMCk7IC8vIGpvaW5zU3BsaXRzIGxlbmd0aFxuICB9XG59XG5cbmV4cG9ydCBmdW5jdGlvbiB0b0J1ZmZlclY1PFROdW1iZXIgZXh0ZW5kcyBudW1iZXIgfCBiaWdpbnQ+KFxuICBidWZmZXJXcml0ZXI6IEJ1ZmZlcldyaXRlcixcbiAgdHg6IFpjYXNoVHJhbnNhY3Rpb248VE51bWJlcj5cbik6IHZvaWQge1xuICAvLyBodHRwczovL2dpdGh1Yi5jb20vemNhc2gvemNhc2gvYmxvYi92NC41LjEvc3JjL3ByaW1pdGl2ZXMvdHJhbnNhY3Rpb24uaCNMODI1LUw4MjZcbiAgYnVmZmVyV3JpdGVyLndyaXRlVUludDMyKHR4LmNvbnNlbnN1c0JyYW5jaElkKTtcbiAgYnVmZmVyV3JpdGVyLndyaXRlVUludDMyKHR4LmxvY2t0aW1lKTtcbiAgYnVmZmVyV3JpdGVyLndyaXRlVUludDMyKHR4LmV4cGlyeUhlaWdodCk7XG4gIHdyaXRlSW5wdXRzKGJ1ZmZlcldyaXRlciwgdHguaW5zKTtcbiAgd3JpdGVPdXRwdXRzPFROdW1iZXI+KGJ1ZmZlcldyaXRlciwgdHgub3V0cyk7XG5cbiAgLy8gaHR0cHM6Ly9naXRodWIuY29tL3pjYXNoL3pjYXNoL2Jsb2IvdjQuNS4xL3NyYy9wcmltaXRpdmVzL3RyYW5zYWN0aW9uLmgjTDEwNjNcbiAgd3JpdGVFbXB0eVNhbXBsaW5nQnVuZGxlKGJ1ZmZlcldyaXRlcik7XG4gIC8vIGh0dHBzOi8vZ2l0aHViLmNvbS96Y2FzaC96Y2FzaC9ibG9iL3Y0LjUuMS9zcmMvcHJpbWl0aXZlcy90cmFuc2FjdGlvbi5oI0wxMDgxXG4gIHdyaXRlRW1wdHlPcmNoYXJkQnVuZGxlKGJ1ZmZlcldyaXRlcik7XG59XG4iXX0=