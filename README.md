# eCash wallet CLI



## Installing eCash Wallet

...

## Cloning eCash Wallet

```
git clone https://github.com/Amatack/ecash-wallet-cli.git
cd ./ecash-wallet-cli
npm install
mkdir data
hdwallet
```

## Running Your First eCash Wallet from CLI


```
hdwallet start generate

```

## Commands of general purpose
Usage: hdwallet [options] [command]

eCash Wallet CLI v0.0.1

Options:
  -V, --version       output the version number
  -a, --allAddresses  select all your Addresses to your action of the command
  -h, --help          display help for command

Commands:
  start               Configure Mnemonic of your wallet.
  add                 Add a new address to your wallet.
  balance             Get your balance from your selected address.
  totalAddresses      Total number of addresses generated and registered.
  sendXec             send eCash from your selected address
  help [command]      display help for command



