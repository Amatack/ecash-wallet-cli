import { UtxoPsbt } from './UtxoPsbt';
export declare function getTransactionAmountsFromPsbt(psbt: UtxoPsbt): {
    inputCount: number;
    outputCount: number;
    inputAmount: bigint;
    outputAmount: bigint;
    fee: bigint;
};
//# sourceMappingURL=transactionAmounts.d.ts.map