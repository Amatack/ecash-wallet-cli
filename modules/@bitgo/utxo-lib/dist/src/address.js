"use strict";
var _a;
Object.defineProperty(exports, "__esModule", { value: true });
exports.toBech32 = exports.fromBech32 = exports.fromBase58Check = exports.toBase58Check = exports.toOutputScript = exports.fromOutputScript = void 0;
const bitcoinjs = require("bitcoinjs-lib");
const zcashAddress = require("../src/bitgo/zcash/address");
const networks_1 = require("./networks");
const index_1 = require("./index");
function fromOutputScript(outputScript, network) {
    if (networks_1.isValidNetwork(network) && networks_1.isZcash(network)) {
        return zcashAddress.fromOutputScript(outputScript, network);
    }
    // We added p2tr payments from our forked bitcoinjs-lib to utxo-lib instead. Our bitcoinjs fork will no longer have
    // p2tr support so utxo-lib should take care of retrieving a p2tr address from outputScript and bitcoinjs-lib can
    // handle the other type of payments.
    try {
        return index_1.p2trPayments.p2tr({ output: outputScript, network }).address;
    }
    catch (e) {
        // noop. try the bitcoinjs method
    }
    return bitcoinjs.address.fromOutputScript(outputScript, network);
}
exports.fromOutputScript = fromOutputScript;
function toOutputScript(address, network) {
    if (networks_1.isValidNetwork(network) && networks_1.isZcash(network)) {
        return zcashAddress.toOutputScript(address, network);
    }
    return bitcoinjs.address.toOutputScript(address, network);
}
exports.toOutputScript = toOutputScript;
function toBase58Check(hash, version, network) {
    if (networks_1.isValidNetwork(network) && networks_1.isZcash(network)) {
        return zcashAddress.toBase58Check(hash, version);
    }
    return bitcoinjs.address.toBase58Check(hash, version);
}
exports.toBase58Check = toBase58Check;
function fromBase58Check(address, network) {
    if (networks_1.isValidNetwork(network) && networks_1.isZcash(network)) {
        return zcashAddress.fromBase58Check(address);
    }
    return bitcoinjs.address.fromBase58Check(address);
}
exports.fromBase58Check = fromBase58Check;
_a = bitcoinjs.address, exports.fromBech32 = _a.fromBech32, exports.toBech32 = _a.toBech32;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYWRkcmVzcy5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9hZGRyZXNzLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7Ozs7QUFBQSwyQ0FBMkM7QUFHM0MsMkRBQTJEO0FBQzNELHlDQUE4RDtBQUM5RCxtQ0FBdUM7QUFFdkMsU0FBZ0IsZ0JBQWdCLENBQUMsWUFBb0IsRUFBRSxPQUFnQjtJQUNyRSxJQUFJLHlCQUFjLENBQUMsT0FBTyxDQUFDLElBQUksa0JBQU8sQ0FBQyxPQUFPLENBQUMsRUFBRTtRQUMvQyxPQUFPLFlBQVksQ0FBQyxnQkFBZ0IsQ0FBQyxZQUFZLEVBQUUsT0FBTyxDQUFDLENBQUM7S0FDN0Q7SUFFRCxtSEFBbUg7SUFDbkgsaUhBQWlIO0lBQ2pILHFDQUFxQztJQUNyQyxJQUFJO1FBQ0YsT0FBTyxvQkFBWSxDQUFDLElBQUksQ0FBQyxFQUFFLE1BQU0sRUFBRSxZQUFZLEVBQUUsT0FBTyxFQUFFLENBQUMsQ0FBQyxPQUFpQixDQUFDO0tBQy9FO0lBQUMsT0FBTyxDQUFDLEVBQUU7UUFDVixpQ0FBaUM7S0FDbEM7SUFFRCxPQUFPLFNBQVMsQ0FBQyxPQUFPLENBQUMsZ0JBQWdCLENBQUMsWUFBWSxFQUFFLE9BQTRCLENBQUMsQ0FBQztBQUN4RixDQUFDO0FBZkQsNENBZUM7QUFFRCxTQUFnQixjQUFjLENBQUMsT0FBZSxFQUFFLE9BQWdCO0lBQzlELElBQUkseUJBQWMsQ0FBQyxPQUFPLENBQUMsSUFBSSxrQkFBTyxDQUFDLE9BQU8sQ0FBQyxFQUFFO1FBQy9DLE9BQU8sWUFBWSxDQUFDLGNBQWMsQ0FBQyxPQUFPLEVBQUUsT0FBTyxDQUFDLENBQUM7S0FDdEQ7SUFDRCxPQUFPLFNBQVMsQ0FBQyxPQUFPLENBQUMsY0FBYyxDQUFDLE9BQU8sRUFBRSxPQUE0QixDQUFDLENBQUM7QUFDakYsQ0FBQztBQUxELHdDQUtDO0FBRUQsU0FBZ0IsYUFBYSxDQUFDLElBQVksRUFBRSxPQUFlLEVBQUUsT0FBZ0I7SUFDM0UsSUFBSSx5QkFBYyxDQUFDLE9BQU8sQ0FBQyxJQUFJLGtCQUFPLENBQUMsT0FBTyxDQUFDLEVBQUU7UUFDL0MsT0FBTyxZQUFZLENBQUMsYUFBYSxDQUFDLElBQUksRUFBRSxPQUFPLENBQUMsQ0FBQztLQUNsRDtJQUNELE9BQU8sU0FBUyxDQUFDLE9BQU8sQ0FBQyxhQUFhLENBQUMsSUFBSSxFQUFFLE9BQU8sQ0FBQyxDQUFDO0FBQ3hELENBQUM7QUFMRCxzQ0FLQztBQUVELFNBQWdCLGVBQWUsQ0FBQyxPQUFlLEVBQUUsT0FBZ0I7SUFDL0QsSUFBSSx5QkFBYyxDQUFDLE9BQU8sQ0FBQyxJQUFJLGtCQUFPLENBQUMsT0FBTyxDQUFDLEVBQUU7UUFDL0MsT0FBTyxZQUFZLENBQUMsZUFBZSxDQUFDLE9BQU8sQ0FBQyxDQUFDO0tBQzlDO0lBQ0QsT0FBTyxTQUFTLENBQUMsT0FBTyxDQUFDLGVBQWUsQ0FBQyxPQUFPLENBQUMsQ0FBQztBQUNwRCxDQUFDO0FBTEQsMENBS0M7QUFFWSxLQUEyQixTQUFTLENBQUMsT0FBTyxFQUExQyxrQkFBVSxrQkFBRSxnQkFBUSxlQUF1QiIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCAqIGFzIGJpdGNvaW5qcyBmcm9tICdiaXRjb2luanMtbGliJztcbmltcG9ydCB7IEJhc2U1OENoZWNrUmVzdWx0LCBCZWNoMzJSZXN1bHQgfSBmcm9tICdiaXRjb2luanMtbGliL3NyYy9hZGRyZXNzJztcblxuaW1wb3J0ICogYXMgemNhc2hBZGRyZXNzIGZyb20gJy4uL3NyYy9iaXRnby96Y2FzaC9hZGRyZXNzJztcbmltcG9ydCB7IGlzVmFsaWROZXR3b3JrLCBpc1pjYXNoLCBOZXR3b3JrIH0gZnJvbSAnLi9uZXR3b3Jrcyc7XG5pbXBvcnQgeyBwMnRyUGF5bWVudHMgfSBmcm9tICcuL2luZGV4JztcblxuZXhwb3J0IGZ1bmN0aW9uIGZyb21PdXRwdXRTY3JpcHQob3V0cHV0U2NyaXB0OiBCdWZmZXIsIG5ldHdvcms6IE5ldHdvcmspOiBzdHJpbmcge1xuICBpZiAoaXNWYWxpZE5ldHdvcmsobmV0d29yaykgJiYgaXNaY2FzaChuZXR3b3JrKSkge1xuICAgIHJldHVybiB6Y2FzaEFkZHJlc3MuZnJvbU91dHB1dFNjcmlwdChvdXRwdXRTY3JpcHQsIG5ldHdvcmspO1xuICB9XG5cbiAgLy8gV2UgYWRkZWQgcDJ0ciBwYXltZW50cyBmcm9tIG91ciBmb3JrZWQgYml0Y29pbmpzLWxpYiB0byB1dHhvLWxpYiBpbnN0ZWFkLiBPdXIgYml0Y29pbmpzIGZvcmsgd2lsbCBubyBsb25nZXIgaGF2ZVxuICAvLyBwMnRyIHN1cHBvcnQgc28gdXR4by1saWIgc2hvdWxkIHRha2UgY2FyZSBvZiByZXRyaWV2aW5nIGEgcDJ0ciBhZGRyZXNzIGZyb20gb3V0cHV0U2NyaXB0IGFuZCBiaXRjb2luanMtbGliIGNhblxuICAvLyBoYW5kbGUgdGhlIG90aGVyIHR5cGUgb2YgcGF5bWVudHMuXG4gIHRyeSB7XG4gICAgcmV0dXJuIHAydHJQYXltZW50cy5wMnRyKHsgb3V0cHV0OiBvdXRwdXRTY3JpcHQsIG5ldHdvcmsgfSkuYWRkcmVzcyBhcyBzdHJpbmc7XG4gIH0gY2F0Y2ggKGUpIHtcbiAgICAvLyBub29wLiB0cnkgdGhlIGJpdGNvaW5qcyBtZXRob2RcbiAgfVxuXG4gIHJldHVybiBiaXRjb2luanMuYWRkcmVzcy5mcm9tT3V0cHV0U2NyaXB0KG91dHB1dFNjcmlwdCwgbmV0d29yayBhcyBiaXRjb2luanMuTmV0d29yayk7XG59XG5cbmV4cG9ydCBmdW5jdGlvbiB0b091dHB1dFNjcmlwdChhZGRyZXNzOiBzdHJpbmcsIG5ldHdvcms6IE5ldHdvcmspOiBCdWZmZXIge1xuICBpZiAoaXNWYWxpZE5ldHdvcmsobmV0d29yaykgJiYgaXNaY2FzaChuZXR3b3JrKSkge1xuICAgIHJldHVybiB6Y2FzaEFkZHJlc3MudG9PdXRwdXRTY3JpcHQoYWRkcmVzcywgbmV0d29yayk7XG4gIH1cbiAgcmV0dXJuIGJpdGNvaW5qcy5hZGRyZXNzLnRvT3V0cHV0U2NyaXB0KGFkZHJlc3MsIG5ldHdvcmsgYXMgYml0Y29pbmpzLk5ldHdvcmspO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gdG9CYXNlNThDaGVjayhoYXNoOiBCdWZmZXIsIHZlcnNpb246IG51bWJlciwgbmV0d29yazogTmV0d29yayk6IHN0cmluZyB7XG4gIGlmIChpc1ZhbGlkTmV0d29yayhuZXR3b3JrKSAmJiBpc1pjYXNoKG5ldHdvcmspKSB7XG4gICAgcmV0dXJuIHpjYXNoQWRkcmVzcy50b0Jhc2U1OENoZWNrKGhhc2gsIHZlcnNpb24pO1xuICB9XG4gIHJldHVybiBiaXRjb2luanMuYWRkcmVzcy50b0Jhc2U1OENoZWNrKGhhc2gsIHZlcnNpb24pO1xufVxuXG5leHBvcnQgZnVuY3Rpb24gZnJvbUJhc2U1OENoZWNrKGFkZHJlc3M6IHN0cmluZywgbmV0d29yazogTmV0d29yayk6IEJhc2U1OENoZWNrUmVzdWx0IHtcbiAgaWYgKGlzVmFsaWROZXR3b3JrKG5ldHdvcmspICYmIGlzWmNhc2gobmV0d29yaykpIHtcbiAgICByZXR1cm4gemNhc2hBZGRyZXNzLmZyb21CYXNlNThDaGVjayhhZGRyZXNzKTtcbiAgfVxuICByZXR1cm4gYml0Y29pbmpzLmFkZHJlc3MuZnJvbUJhc2U1OENoZWNrKGFkZHJlc3MpO1xufVxuXG5leHBvcnQgY29uc3QgeyBmcm9tQmVjaDMyLCB0b0JlY2gzMiB9ID0gYml0Y29pbmpzLmFkZHJlc3M7XG5cbmV4cG9ydCB7IEJhc2U1OENoZWNrUmVzdWx0LCBCZWNoMzJSZXN1bHQgfTtcbiJdfQ==