"use strict";
// OP_0 [signatures ...]
Object.defineProperty(exports, "__esModule", { value: true });
exports.check = void 0;
const __1 = require("../../");
const __2 = require("../../");
function partialSignature(value) {
    return value === __2.opcodes.OP_0 || __1.script.isCanonicalScriptSignature(value);
}
function check(script, allowIncomplete) {
    const chunks = __1.script.decompile(script);
    if (chunks.length < 2)
        return false;
    if (chunks[0] !== __2.opcodes.OP_0)
        return false;
    if (allowIncomplete) {
        return chunks.slice(1).every(partialSignature);
    }
    return chunks.slice(1).every(__1.script.isCanonicalScriptSignature);
}
exports.check = check;
check.toJSON = () => {
    return 'multisig input';
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5wdXQuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi9zcmMvdGVtcGxhdGVzL211bHRpc2lnL2lucHV0LnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSx3QkFBd0I7OztBQUd4Qiw4QkFBMkM7QUFDM0MsOEJBQWlDO0FBRWpDLFNBQVMsZ0JBQWdCLENBQUMsS0FBc0I7SUFDOUMsT0FBTyxLQUFLLEtBQUssV0FBTyxDQUFDLElBQUksSUFBSSxVQUFPLENBQUMsMEJBQTBCLENBQUMsS0FBZSxDQUFDLENBQUM7QUFDdkYsQ0FBQztBQUVELFNBQWdCLEtBQUssQ0FBQyxNQUFzQixFQUFFLGVBQXlCO0lBQ3JFLE1BQU0sTUFBTSxHQUFHLFVBQU8sQ0FBQyxTQUFTLENBQUMsTUFBTSxDQUFVLENBQUM7SUFDbEQsSUFBSSxNQUFNLENBQUMsTUFBTSxHQUFHLENBQUM7UUFBRSxPQUFPLEtBQUssQ0FBQztJQUNwQyxJQUFJLE1BQU0sQ0FBQyxDQUFDLENBQUMsS0FBSyxXQUFPLENBQUMsSUFBSTtRQUFFLE9BQU8sS0FBSyxDQUFDO0lBRTdDLElBQUksZUFBZSxFQUFFO1FBQ25CLE9BQU8sTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQUMsQ0FBQyxLQUFLLENBQUMsZ0JBQWdCLENBQUMsQ0FBQztLQUNoRDtJQUVELE9BQVEsTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFDLENBQWMsQ0FBQyxLQUFLLENBQUMsVUFBTyxDQUFDLDBCQUEwQixDQUFDLENBQUM7QUFDakYsQ0FBQztBQVZELHNCQVVDO0FBQ0QsS0FBSyxDQUFDLE1BQU0sR0FBRyxHQUFXLEVBQUU7SUFDMUIsT0FBTyxnQkFBZ0IsQ0FBQztBQUMxQixDQUFDLENBQUMiLCJzb3VyY2VzQ29udGVudCI6WyIvLyBPUF8wIFtzaWduYXR1cmVzIC4uLl1cblxuaW1wb3J0IHsgU3RhY2sgfSBmcm9tICcuLi8uLi8nO1xuaW1wb3J0IHsgc2NyaXB0IGFzIGJzY3JpcHQgfSBmcm9tICcuLi8uLi8nO1xuaW1wb3J0IHsgb3Bjb2RlcyB9IGZyb20gJy4uLy4uLyc7XG5cbmZ1bmN0aW9uIHBhcnRpYWxTaWduYXR1cmUodmFsdWU6IG51bWJlciB8IEJ1ZmZlcik6IGJvb2xlYW4ge1xuICByZXR1cm4gdmFsdWUgPT09IG9wY29kZXMuT1BfMCB8fCBic2NyaXB0LmlzQ2Fub25pY2FsU2NyaXB0U2lnbmF0dXJlKHZhbHVlIGFzIEJ1ZmZlcik7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBjaGVjayhzY3JpcHQ6IEJ1ZmZlciB8IFN0YWNrLCBhbGxvd0luY29tcGxldGU/OiBib29sZWFuKTogYm9vbGVhbiB7XG4gIGNvbnN0IGNodW5rcyA9IGJzY3JpcHQuZGVjb21waWxlKHNjcmlwdCkgYXMgU3RhY2s7XG4gIGlmIChjaHVua3MubGVuZ3RoIDwgMikgcmV0dXJuIGZhbHNlO1xuICBpZiAoY2h1bmtzWzBdICE9PSBvcGNvZGVzLk9QXzApIHJldHVybiBmYWxzZTtcblxuICBpZiAoYWxsb3dJbmNvbXBsZXRlKSB7XG4gICAgcmV0dXJuIGNodW5rcy5zbGljZSgxKS5ldmVyeShwYXJ0aWFsU2lnbmF0dXJlKTtcbiAgfVxuXG4gIHJldHVybiAoY2h1bmtzLnNsaWNlKDEpIGFzIEJ1ZmZlcltdKS5ldmVyeShic2NyaXB0LmlzQ2Fub25pY2FsU2NyaXB0U2lnbmF0dXJlKTtcbn1cbmNoZWNrLnRvSlNPTiA9ICgpOiBzdHJpbmcgPT4ge1xuICByZXR1cm4gJ211bHRpc2lnIGlucHV0Jztcbn07XG4iXX0=