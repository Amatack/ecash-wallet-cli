"use strict";
// {signature} {pubKey}
Object.defineProperty(exports, "__esModule", { value: true });
exports.check = void 0;
const __1 = require("../../");
function isCompressedCanonicalPubKey(pubKey) {
    return __1.script.isCanonicalPubKey(pubKey) && pubKey.length === 33;
}
function check(script) {
    const chunks = __1.script.decompile(script);
    return (chunks.length === 2 &&
        __1.script.isCanonicalScriptSignature(chunks[0]) &&
        isCompressedCanonicalPubKey(chunks[1]));
}
exports.check = check;
check.toJSON = () => {
    return 'witnessPubKeyHash input';
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiaW5wdXQuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi9zcmMvdGVtcGxhdGVzL3dpdG5lc3NwdWJrZXloYXNoL2lucHV0LnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSx1QkFBdUI7OztBQUd2Qiw4QkFBMkM7QUFFM0MsU0FBUywyQkFBMkIsQ0FBQyxNQUFjO0lBQ2pELE9BQU8sVUFBTyxDQUFDLGlCQUFpQixDQUFDLE1BQU0sQ0FBQyxJQUFJLE1BQU0sQ0FBQyxNQUFNLEtBQUssRUFBRSxDQUFDO0FBQ25FLENBQUM7QUFFRCxTQUFnQixLQUFLLENBQUMsTUFBc0I7SUFDMUMsTUFBTSxNQUFNLEdBQUcsVUFBTyxDQUFDLFNBQVMsQ0FBQyxNQUFNLENBQVUsQ0FBQztJQUVsRCxPQUFPLENBQ0wsTUFBTSxDQUFDLE1BQU0sS0FBSyxDQUFDO1FBQ25CLFVBQU8sQ0FBQywwQkFBMEIsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFXLENBQUM7UUFDdkQsMkJBQTJCLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBVyxDQUFDLENBQ2pELENBQUM7QUFDSixDQUFDO0FBUkQsc0JBUUM7QUFDRCxLQUFLLENBQUMsTUFBTSxHQUFHLEdBQVcsRUFBRTtJQUMxQixPQUFPLHlCQUF5QixDQUFDO0FBQ25DLENBQUMsQ0FBQyIsInNvdXJjZXNDb250ZW50IjpbIi8vIHtzaWduYXR1cmV9IHtwdWJLZXl9XG5cbmltcG9ydCB7IFN0YWNrIH0gZnJvbSAnLi4vLi4vJztcbmltcG9ydCB7IHNjcmlwdCBhcyBic2NyaXB0IH0gZnJvbSAnLi4vLi4vJztcblxuZnVuY3Rpb24gaXNDb21wcmVzc2VkQ2Fub25pY2FsUHViS2V5KHB1YktleTogQnVmZmVyKTogYm9vbGVhbiB7XG4gIHJldHVybiBic2NyaXB0LmlzQ2Fub25pY2FsUHViS2V5KHB1YktleSkgJiYgcHViS2V5Lmxlbmd0aCA9PT0gMzM7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiBjaGVjayhzY3JpcHQ6IEJ1ZmZlciB8IFN0YWNrKTogYm9vbGVhbiB7XG4gIGNvbnN0IGNodW5rcyA9IGJzY3JpcHQuZGVjb21waWxlKHNjcmlwdCkgYXMgU3RhY2s7XG5cbiAgcmV0dXJuIChcbiAgICBjaHVua3MubGVuZ3RoID09PSAyICYmXG4gICAgYnNjcmlwdC5pc0Nhbm9uaWNhbFNjcmlwdFNpZ25hdHVyZShjaHVua3NbMF0gYXMgQnVmZmVyKSAmJlxuICAgIGlzQ29tcHJlc3NlZENhbm9uaWNhbFB1YktleShjaHVua3NbMV0gYXMgQnVmZmVyKVxuICApO1xufVxuY2hlY2sudG9KU09OID0gKCk6IHN0cmluZyA9PiB7XG4gIHJldHVybiAnd2l0bmVzc1B1YktleUhhc2ggaW5wdXQnO1xufTtcbiJdfQ==