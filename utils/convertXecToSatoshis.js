/**
 * Converts an amount from XEC to satoshis
 *
 * @param {number} xecAmount the amount in XECs
 * @returns {number} amountInSats the amount converted to satoshis
 */
function convertXecToSatoshis(xecAmount) {
    // XEC currently uses 2 decimal points
    const ECASH_DECIMALS = 2;
    const amountInSats = xecAmount * 10 ** ECASH_DECIMALS;
    return amountInSats;
}

module.exports = convertXecToSatoshis