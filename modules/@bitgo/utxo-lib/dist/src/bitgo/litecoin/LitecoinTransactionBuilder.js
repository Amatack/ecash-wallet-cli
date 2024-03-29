"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LitecoinTransactionBuilder = void 0;
const UtxoTransactionBuilder_1 = require("../UtxoTransactionBuilder");
const LitecoinTransaction_1 = require("./LitecoinTransaction");
class LitecoinTransactionBuilder extends UtxoTransactionBuilder_1.UtxoTransactionBuilder {
    static newTransactionBuilder(network, tx) {
        return new LitecoinTransactionBuilder(network, tx);
    }
    createInitialTransaction(network, tx) {
        return new LitecoinTransaction_1.LitecoinTransaction(network, tx);
    }
}
exports.LitecoinTransactionBuilder = LitecoinTransactionBuilder;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiTGl0ZWNvaW5UcmFuc2FjdGlvbkJ1aWxkZXIuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi9zcmMvYml0Z28vbGl0ZWNvaW4vTGl0ZWNvaW5UcmFuc2FjdGlvbkJ1aWxkZXIudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7O0FBRUEsc0VBQW1FO0FBR25FLCtEQUE0RDtBQUU1RCxNQUFhLDBCQUFxRSxTQUFRLCtDQUd6RjtJQUNXLE1BQU0sQ0FBQyxxQkFBcUIsQ0FDcEMsT0FBZ0IsRUFDaEIsRUFBNEI7UUFFNUIsT0FBTyxJQUFJLDBCQUEwQixDQUFVLE9BQU8sRUFBRSxFQUFFLENBQUMsQ0FBQztJQUM5RCxDQUFDO0lBRVMsd0JBQXdCLENBQ2hDLE9BQWdCLEVBQ2hCLEVBQW1DO1FBRW5DLE9BQU8sSUFBSSx5Q0FBbUIsQ0FBVSxPQUFPLEVBQUUsRUFBa0MsQ0FBQyxDQUFDO0lBQ3ZGLENBQUM7Q0FDRjtBQWpCRCxnRUFpQkMiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgKiBhcyBiaXRjb2luanMgZnJvbSAnYml0Y29pbmpzLWxpYic7XG5cbmltcG9ydCB7IFV0eG9UcmFuc2FjdGlvbkJ1aWxkZXIgfSBmcm9tICcuLi9VdHhvVHJhbnNhY3Rpb25CdWlsZGVyJztcbmltcG9ydCB7IE5ldHdvcmsgfSBmcm9tICcuLi8uLi9uZXR3b3Jrcyc7XG5pbXBvcnQgeyBVdHhvVHJhbnNhY3Rpb24gfSBmcm9tICcuLi9VdHhvVHJhbnNhY3Rpb24nO1xuaW1wb3J0IHsgTGl0ZWNvaW5UcmFuc2FjdGlvbiB9IGZyb20gJy4vTGl0ZWNvaW5UcmFuc2FjdGlvbic7XG5cbmV4cG9ydCBjbGFzcyBMaXRlY29pblRyYW5zYWN0aW9uQnVpbGRlcjxUTnVtYmVyIGV4dGVuZHMgbnVtYmVyIHwgYmlnaW50ID0gbnVtYmVyPiBleHRlbmRzIFV0eG9UcmFuc2FjdGlvbkJ1aWxkZXI8XG4gIFROdW1iZXIsXG4gIExpdGVjb2luVHJhbnNhY3Rpb248VE51bWJlcj5cbj4ge1xuICBwcm90ZWN0ZWQgc3RhdGljIG5ld1RyYW5zYWN0aW9uQnVpbGRlcjxUTnVtYmVyIGV4dGVuZHMgbnVtYmVyIHwgYmlnaW50PihcbiAgICBuZXR3b3JrOiBOZXR3b3JrLFxuICAgIHR4OiBVdHhvVHJhbnNhY3Rpb248VE51bWJlcj5cbiAgKTogTGl0ZWNvaW5UcmFuc2FjdGlvbkJ1aWxkZXI8VE51bWJlcj4ge1xuICAgIHJldHVybiBuZXcgTGl0ZWNvaW5UcmFuc2FjdGlvbkJ1aWxkZXI8VE51bWJlcj4obmV0d29yaywgdHgpO1xuICB9XG5cbiAgcHJvdGVjdGVkIGNyZWF0ZUluaXRpYWxUcmFuc2FjdGlvbihcbiAgICBuZXR3b3JrOiBOZXR3b3JrLFxuICAgIHR4PzogYml0Y29pbmpzLlRyYW5zYWN0aW9uPFROdW1iZXI+XG4gICk6IExpdGVjb2luVHJhbnNhY3Rpb248VE51bWJlcj4ge1xuICAgIHJldHVybiBuZXcgTGl0ZWNvaW5UcmFuc2FjdGlvbjxUTnVtYmVyPihuZXR3b3JrLCB0eCBhcyBMaXRlY29pblRyYW5zYWN0aW9uPFROdW1iZXI+KTtcbiAgfVxufVxuIl19