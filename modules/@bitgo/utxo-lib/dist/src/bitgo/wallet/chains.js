"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isSegwit = exports.isInternalChainCode = exports.isExternalChainCode = exports.getInternalChainCode = exports.getExternalChainCode = exports.scriptTypeForChain = exports.toChainPair = exports.isChainCode = exports.chainCodes = exports.chainCodesP2trMusig2 = exports.chainCodesP2tr = exports.chainCodesP2wsh = exports.chainCodesP2shP2wsh = exports.chainCodesP2sh = void 0;
/**
 * All valid chain codes
 */
exports.chainCodesP2sh = [0, 1];
exports.chainCodesP2shP2wsh = [10, 11];
exports.chainCodesP2wsh = [20, 21];
exports.chainCodesP2tr = [30, 31];
exports.chainCodesP2trMusig2 = [40, 41];
exports.chainCodes = [
    ...exports.chainCodesP2sh,
    ...exports.chainCodesP2shP2wsh,
    ...exports.chainCodesP2wsh,
    ...exports.chainCodesP2tr,
    ...exports.chainCodesP2trMusig2,
];
function isChainCode(n) {
    return exports.chainCodes.includes(n);
}
exports.isChainCode = isChainCode;
const map = new Map([
    ['p2sh', exports.chainCodesP2sh],
    ['p2shP2wsh', exports.chainCodesP2shP2wsh],
    ['p2wsh', exports.chainCodesP2wsh],
    ['p2tr', exports.chainCodesP2tr],
    ['p2trMusig2', exports.chainCodesP2trMusig2],
].map(([k, v]) => [k, Object.freeze(v)]));
const pairs = [...map.values()];
/**
 * @return ChainCodePair for input
 */
function toChainPair(v) {
    let pair;
    if (Array.isArray(v)) {
        if (pairs.includes(v)) {
            pair = v;
        }
    }
    if (typeof v === 'string') {
        pair = map.get(v);
    }
    if (typeof v === 'number') {
        pair = pairs.find((p) => p.includes(v));
    }
    if (!pair) {
        throw new Error(`no pair for input ${v}`);
    }
    return pair;
}
exports.toChainPair = toChainPair;
/**
 * @return ScriptType2Of3 for input
 */
function scriptTypeForChain(chain) {
    for (const [scriptType, pair] of map.entries()) {
        if (pair.includes(chain)) {
            return scriptType;
        }
    }
    throw new Error(`invalid chain ${chain}`);
}
exports.scriptTypeForChain = scriptTypeForChain;
/**
 * @return chain code intended for external addresses
 */
function getExternalChainCode(v) {
    return toChainPair(v)[0];
}
exports.getExternalChainCode = getExternalChainCode;
/**
 * @return chain code intended for change outputs
 */
function getInternalChainCode(v) {
    return toChainPair(v)[1];
}
exports.getInternalChainCode = getInternalChainCode;
/**
 * @return true iff chain code is external
 */
function isExternalChainCode(v) {
    return toChainPair(v).indexOf(v) === 0;
}
exports.isExternalChainCode = isExternalChainCode;
/**
 * @return true iff chain code is internal
 */
function isInternalChainCode(v) {
    return toChainPair(v).indexOf(v) === 1;
}
exports.isInternalChainCode = isInternalChainCode;
/**
 * @return true iff chain code is a segwit address
 */
function isSegwit(v) {
    const segwitCodes = [
        ...exports.chainCodesP2shP2wsh,
        ...exports.chainCodesP2wsh,
        ...exports.chainCodesP2tr,
        ...exports.chainCodesP2trMusig2,
    ];
    return segwitCodes.includes(v);
}
exports.isSegwit = isSegwit;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY2hhaW5zLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vLi4vc3JjL2JpdGdvL3dhbGxldC9jaGFpbnMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBYUE7O0dBRUc7QUFDVSxRQUFBLGNBQWMsR0FBRyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQVUsQ0FBQztBQUNqQyxRQUFBLG1CQUFtQixHQUFHLENBQUMsRUFBRSxFQUFFLEVBQUUsQ0FBVSxDQUFDO0FBQ3hDLFFBQUEsZUFBZSxHQUFHLENBQUMsRUFBRSxFQUFFLEVBQUUsQ0FBVSxDQUFDO0FBQ3BDLFFBQUEsY0FBYyxHQUFHLENBQUMsRUFBRSxFQUFFLEVBQUUsQ0FBVSxDQUFDO0FBQ25DLFFBQUEsb0JBQW9CLEdBQUcsQ0FBQyxFQUFFLEVBQUUsRUFBRSxDQUFVLENBQUM7QUFDekMsUUFBQSxVQUFVLEdBQUc7SUFDeEIsR0FBRyxzQkFBYztJQUNqQixHQUFHLDJCQUFtQjtJQUN0QixHQUFHLHVCQUFlO0lBQ2xCLEdBQUcsc0JBQWM7SUFDakIsR0FBRyw0QkFBb0I7Q0FDeEIsQ0FBQztBQUVGLFNBQWdCLFdBQVcsQ0FBQyxDQUFVO0lBQ3BDLE9BQU8sa0JBQVUsQ0FBQyxRQUFRLENBQUMsQ0FBYyxDQUFDLENBQUM7QUFDN0MsQ0FBQztBQUZELGtDQUVDO0FBUUQsTUFBTSxHQUFHLEdBQUcsSUFBSSxHQUFHLENBQ2pCO0lBQ0UsQ0FBQyxNQUFNLEVBQUUsc0JBQWMsQ0FBQztJQUN4QixDQUFDLFdBQVcsRUFBRSwyQkFBbUIsQ0FBQztJQUNsQyxDQUFDLE9BQU8sRUFBRSx1QkFBZSxDQUFDO0lBQzFCLENBQUMsTUFBTSxFQUFFLHNCQUFjLENBQUM7SUFDeEIsQ0FBQyxZQUFZLEVBQUUsNEJBQW9CLENBQUM7Q0FDckMsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsRUFBRSxFQUFFLENBQUMsQ0FBQyxDQUFtQixFQUFFLE1BQU0sQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFrQixDQUFDLENBQUMsQ0FDNUUsQ0FBQztBQUVGLE1BQU0sS0FBSyxHQUFHLENBQUMsR0FBRyxHQUFHLENBQUMsTUFBTSxFQUFFLENBQUMsQ0FBQztBQUVoQzs7R0FFRztBQUNILFNBQWdCLFdBQVcsQ0FBQyxDQUE2QztJQUN2RSxJQUFJLElBQUksQ0FBQztJQUNULElBQUksS0FBSyxDQUFDLE9BQU8sQ0FBQyxDQUFDLENBQUMsRUFBRTtRQUNwQixJQUFJLEtBQUssQ0FBQyxRQUFRLENBQUMsQ0FBa0IsQ0FBQyxFQUFFO1lBQ3RDLElBQUksR0FBRyxDQUFDLENBQUM7U0FDVjtLQUNGO0lBQ0QsSUFBSSxPQUFPLENBQUMsS0FBSyxRQUFRLEVBQUU7UUFDekIsSUFBSSxHQUFHLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLENBQUM7S0FDbkI7SUFDRCxJQUFJLE9BQU8sQ0FBQyxLQUFLLFFBQVEsRUFBRTtRQUN6QixJQUFJLEdBQUcsS0FBSyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsRUFBRSxFQUFFLENBQUMsQ0FBQyxDQUFDLFFBQVEsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO0tBQ3pDO0lBQ0QsSUFBSSxDQUFDLElBQUksRUFBRTtRQUNULE1BQU0sSUFBSSxLQUFLLENBQUMscUJBQXFCLENBQUMsRUFBRSxDQUFDLENBQUM7S0FDM0M7SUFDRCxPQUFPLElBQXFCLENBQUM7QUFDL0IsQ0FBQztBQWpCRCxrQ0FpQkM7QUFFRDs7R0FFRztBQUNILFNBQWdCLGtCQUFrQixDQUFDLEtBQWdCO0lBQ2pELEtBQUssTUFBTSxDQUFDLFVBQVUsRUFBRSxJQUFJLENBQUMsSUFBSSxHQUFHLENBQUMsT0FBTyxFQUFFLEVBQUU7UUFDOUMsSUFBSSxJQUFJLENBQUMsUUFBUSxDQUFDLEtBQUssQ0FBQyxFQUFFO1lBQ3hCLE9BQU8sVUFBVSxDQUFDO1NBQ25CO0tBQ0Y7SUFDRCxNQUFNLElBQUksS0FBSyxDQUFDLGlCQUFpQixLQUFLLEVBQUUsQ0FBQyxDQUFDO0FBQzVDLENBQUM7QUFQRCxnREFPQztBQUVEOztHQUVHO0FBQ0gsU0FBZ0Isb0JBQW9CLENBQUMsQ0FBNkM7SUFDaEYsT0FBTyxXQUFXLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7QUFDM0IsQ0FBQztBQUZELG9EQUVDO0FBRUQ7O0dBRUc7QUFDSCxTQUFnQixvQkFBb0IsQ0FBQyxDQUE2QztJQUNoRixPQUFPLFdBQVcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQztBQUMzQixDQUFDO0FBRkQsb0RBRUM7QUFFRDs7R0FFRztBQUNILFNBQWdCLG1CQUFtQixDQUFDLENBQVk7SUFDOUMsT0FBTyxXQUFXLENBQUMsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxLQUFLLENBQUMsQ0FBQztBQUN6QyxDQUFDO0FBRkQsa0RBRUM7QUFFRDs7R0FFRztBQUNILFNBQWdCLG1CQUFtQixDQUFDLENBQVk7SUFDOUMsT0FBTyxXQUFXLENBQUMsQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDLENBQUMsQ0FBQyxLQUFLLENBQUMsQ0FBQztBQUN6QyxDQUFDO0FBRkQsa0RBRUM7QUFFRDs7R0FFRztBQUNILFNBQWdCLFFBQVEsQ0FBQyxDQUFZO0lBQ25DLE1BQU0sV0FBVyxHQUFnQjtRQUMvQixHQUFHLDJCQUFtQjtRQUN0QixHQUFHLHVCQUFlO1FBQ2xCLEdBQUcsc0JBQWM7UUFDakIsR0FBRyw0QkFBb0I7S0FDeEIsQ0FBQztJQUNGLE9BQU8sV0FBVyxDQUFDLFFBQVEsQ0FBQyxDQUFDLENBQUMsQ0FBQztBQUNqQyxDQUFDO0FBUkQsNEJBUUMiLCJzb3VyY2VzQ29udGVudCI6WyIvKipcbiAqIERlZmluZXMgQml0R28gbWFwcGluZ3MgYmV0d2VlbiBiaXAzMiBkZXJpdmF0aW9uIHBhdGggYW5kIHNjcmlwdCB0eXBlLlxuICpcbiAqIFRoZSBzY3JpcHRzIGZvciBhIEJpdEdvIHdhbGxldCBhZGRyZXNzIGFyZSBkZWZpbmVkIGJ5IHRoZWlyIGRlcml2YXRpb24gcGF0aC5cbiAqXG4gKiBUaGUgZGVyaXZhdGlvbiBwYXRoIGhhcyB0aGUgZm9ybWF0IGAwLzAvJHtjaGFpbn0vJHtpbmRleH1gIChpbiByYXJlIGNhc2VzIHRoZSBwcmVmaXggaXMgbm90IDAvMClcbiAqXG4gKiBUaGUgYWRkcmVzcyBzY3JpcHQgdHlwZSAoU2NyaXB0VHlwZTJPZjMpIGlzIGRlZmluZWQgYnkgdGhlIGBjaGFpbmAgcGFyYW1ldGVyLlxuICpcbiAqIFRoaXMgZmlsZSBkZWZpbmVzIHRoZSBtYXBwaW5nIGJldHdlZW4gY2hhaW4gcGFyYW1ldGVyIGFuZCBhZGRyZXNzIHR5cGUuXG4gKi9cbmltcG9ydCB7IFNjcmlwdFR5cGUyT2YzIH0gZnJvbSAnLi4vb3V0cHV0U2NyaXB0cyc7XG5cbi8qKlxuICogQWxsIHZhbGlkIGNoYWluIGNvZGVzXG4gKi9cbmV4cG9ydCBjb25zdCBjaGFpbkNvZGVzUDJzaCA9IFswLCAxXSBhcyBjb25zdDtcbmV4cG9ydCBjb25zdCBjaGFpbkNvZGVzUDJzaFAyd3NoID0gWzEwLCAxMV0gYXMgY29uc3Q7XG5leHBvcnQgY29uc3QgY2hhaW5Db2Rlc1Ayd3NoID0gWzIwLCAyMV0gYXMgY29uc3Q7XG5leHBvcnQgY29uc3QgY2hhaW5Db2Rlc1AydHIgPSBbMzAsIDMxXSBhcyBjb25zdDtcbmV4cG9ydCBjb25zdCBjaGFpbkNvZGVzUDJ0ck11c2lnMiA9IFs0MCwgNDFdIGFzIGNvbnN0O1xuZXhwb3J0IGNvbnN0IGNoYWluQ29kZXMgPSBbXG4gIC4uLmNoYWluQ29kZXNQMnNoLFxuICAuLi5jaGFpbkNvZGVzUDJzaFAyd3NoLFxuICAuLi5jaGFpbkNvZGVzUDJ3c2gsXG4gIC4uLmNoYWluQ29kZXNQMnRyLFxuICAuLi5jaGFpbkNvZGVzUDJ0ck11c2lnMixcbl07XG5leHBvcnQgdHlwZSBDaGFpbkNvZGUgPSAodHlwZW9mIGNoYWluQ29kZXMpW251bWJlcl07XG5leHBvcnQgZnVuY3Rpb24gaXNDaGFpbkNvZGUobjogdW5rbm93bik6IG4gaXMgQ2hhaW5Db2RlIHtcbiAgcmV0dXJuIGNoYWluQ29kZXMuaW5jbHVkZXMobiBhcyBDaGFpbkNvZGUpO1xufVxuXG4vKipcbiAqIEEgc2NyaXB0IHR5cGUgbWFwcyB0byB0d28gQ2hhaW5Db2RlczpcbiAqIEV4dGVybmFsIGFkZHJlc3NlcyBhcmUgaW50ZW5kZWQgZm9yIGRlcG9zaXRzLCBpbnRlcm5hbCBhZGRyZXNzZXMgYXJlIGludGVuZGVkIGZvciBjaGFuZ2Ugb3V0cHV0cy5cbiAqL1xuZXhwb3J0IHR5cGUgQ2hhaW5Db2RlUGFpciA9IFJlYWRvbmx5PFtleHRlcm5hbDogQ2hhaW5Db2RlLCBpbnRlcm5hbDogQ2hhaW5Db2RlXT47XG5cbmNvbnN0IG1hcCA9IG5ldyBNYXA8U2NyaXB0VHlwZTJPZjMsIENoYWluQ29kZVBhaXI+KFxuICBbXG4gICAgWydwMnNoJywgY2hhaW5Db2Rlc1Ayc2hdLFxuICAgIFsncDJzaFAyd3NoJywgY2hhaW5Db2Rlc1Ayc2hQMndzaF0sXG4gICAgWydwMndzaCcsIGNoYWluQ29kZXNQMndzaF0sXG4gICAgWydwMnRyJywgY2hhaW5Db2Rlc1AydHJdLFxuICAgIFsncDJ0ck11c2lnMicsIGNoYWluQ29kZXNQMnRyTXVzaWcyXSxcbiAgXS5tYXAoKFtrLCB2XSkgPT4gW2sgYXMgU2NyaXB0VHlwZTJPZjMsIE9iamVjdC5mcmVlemUodikgYXMgQ2hhaW5Db2RlUGFpcl0pXG4pO1xuXG5jb25zdCBwYWlycyA9IFsuLi5tYXAudmFsdWVzKCldO1xuXG4vKipcbiAqIEByZXR1cm4gQ2hhaW5Db2RlUGFpciBmb3IgaW5wdXRcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHRvQ2hhaW5QYWlyKHY6IENoYWluQ29kZVBhaXIgfCBDaGFpbkNvZGUgfCBTY3JpcHRUeXBlMk9mMyk6IENoYWluQ29kZVBhaXIge1xuICBsZXQgcGFpcjtcbiAgaWYgKEFycmF5LmlzQXJyYXkodikpIHtcbiAgICBpZiAocGFpcnMuaW5jbHVkZXModiBhcyBDaGFpbkNvZGVQYWlyKSkge1xuICAgICAgcGFpciA9IHY7XG4gICAgfVxuICB9XG4gIGlmICh0eXBlb2YgdiA9PT0gJ3N0cmluZycpIHtcbiAgICBwYWlyID0gbWFwLmdldCh2KTtcbiAgfVxuICBpZiAodHlwZW9mIHYgPT09ICdudW1iZXInKSB7XG4gICAgcGFpciA9IHBhaXJzLmZpbmQoKHApID0+IHAuaW5jbHVkZXModikpO1xuICB9XG4gIGlmICghcGFpcikge1xuICAgIHRocm93IG5ldyBFcnJvcihgbm8gcGFpciBmb3IgaW5wdXQgJHt2fWApO1xuICB9XG4gIHJldHVybiBwYWlyIGFzIENoYWluQ29kZVBhaXI7XG59XG5cbi8qKlxuICogQHJldHVybiBTY3JpcHRUeXBlMk9mMyBmb3IgaW5wdXRcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIHNjcmlwdFR5cGVGb3JDaGFpbihjaGFpbjogQ2hhaW5Db2RlKTogU2NyaXB0VHlwZTJPZjMge1xuICBmb3IgKGNvbnN0IFtzY3JpcHRUeXBlLCBwYWlyXSBvZiBtYXAuZW50cmllcygpKSB7XG4gICAgaWYgKHBhaXIuaW5jbHVkZXMoY2hhaW4pKSB7XG4gICAgICByZXR1cm4gc2NyaXB0VHlwZTtcbiAgICB9XG4gIH1cbiAgdGhyb3cgbmV3IEVycm9yKGBpbnZhbGlkIGNoYWluICR7Y2hhaW59YCk7XG59XG5cbi8qKlxuICogQHJldHVybiBjaGFpbiBjb2RlIGludGVuZGVkIGZvciBleHRlcm5hbCBhZGRyZXNzZXNcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGdldEV4dGVybmFsQ2hhaW5Db2RlKHY6IENoYWluQ29kZVBhaXIgfCBTY3JpcHRUeXBlMk9mMyB8IENoYWluQ29kZSk6IENoYWluQ29kZSB7XG4gIHJldHVybiB0b0NoYWluUGFpcih2KVswXTtcbn1cblxuLyoqXG4gKiBAcmV0dXJuIGNoYWluIGNvZGUgaW50ZW5kZWQgZm9yIGNoYW5nZSBvdXRwdXRzXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBnZXRJbnRlcm5hbENoYWluQ29kZSh2OiBDaGFpbkNvZGVQYWlyIHwgU2NyaXB0VHlwZTJPZjMgfCBDaGFpbkNvZGUpOiBDaGFpbkNvZGUge1xuICByZXR1cm4gdG9DaGFpblBhaXIodilbMV07XG59XG5cbi8qKlxuICogQHJldHVybiB0cnVlIGlmZiBjaGFpbiBjb2RlIGlzIGV4dGVybmFsXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBpc0V4dGVybmFsQ2hhaW5Db2RlKHY6IENoYWluQ29kZSk6IGJvb2xlYW4ge1xuICByZXR1cm4gdG9DaGFpblBhaXIodikuaW5kZXhPZih2KSA9PT0gMDtcbn1cblxuLyoqXG4gKiBAcmV0dXJuIHRydWUgaWZmIGNoYWluIGNvZGUgaXMgaW50ZXJuYWxcbiAqL1xuZXhwb3J0IGZ1bmN0aW9uIGlzSW50ZXJuYWxDaGFpbkNvZGUodjogQ2hhaW5Db2RlKTogYm9vbGVhbiB7XG4gIHJldHVybiB0b0NoYWluUGFpcih2KS5pbmRleE9mKHYpID09PSAxO1xufVxuXG4vKipcbiAqIEByZXR1cm4gdHJ1ZSBpZmYgY2hhaW4gY29kZSBpcyBhIHNlZ3dpdCBhZGRyZXNzXG4gKi9cbmV4cG9ydCBmdW5jdGlvbiBpc1NlZ3dpdCh2OiBDaGFpbkNvZGUpOiBib29sZWFuIHtcbiAgY29uc3Qgc2Vnd2l0Q29kZXM6IENoYWluQ29kZVtdID0gW1xuICAgIC4uLmNoYWluQ29kZXNQMnNoUDJ3c2gsXG4gICAgLi4uY2hhaW5Db2Rlc1Ayd3NoLFxuICAgIC4uLmNoYWluQ29kZXNQMnRyLFxuICAgIC4uLmNoYWluQ29kZXNQMnRyTXVzaWcyLFxuICBdO1xuICByZXR1cm4gc2Vnd2l0Q29kZXMuaW5jbHVkZXModik7XG59XG4iXX0=