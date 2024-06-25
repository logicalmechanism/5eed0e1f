#!/bin/bash
set -e

# create directories if dont exist
mkdir -p contracts
mkdir -p hashes

# remove old files
rm contracts/* || true
rm hashes/* || true
rm -fr build/ || true

# build out the entire script
echo -e "\033[1;34m\nBuilding Contracts \033[0m"

# remove all traces
# aiken build --trace-level silent --filter-traces user-defined

# keep the traces for testing if required
aiken build --trace-level verbose --filter-traces all

ran="04"
ran_cbor=$(python3 -c "import cbor2;hex_string='${ran}';data = bytes.fromhex(hex_string);encoded = cbor2.dumps(data);print(encoded.hex())")

echo -e "\033[1;33m\nBuilding Pointer Contract \033[0m"
aiken blueprint apply -o plutus.json -v pointer.params "${ran_cbor}"
aiken blueprint convert -v pointer.params > contracts/pointer_contract.plutus
cardano-cli conway transaction policyid --script-file contracts/pointer_contract.plutus > hashes/pointer.hash
echo -e "\033[1;33m Pointer Contract Hash: $(cat hashes/pointer.hash) \033[0m"

echo -e "\033[1;33m\nBuilding Wallet Contract \033[0m"
aiken blueprint convert -v wallet.params > contracts/wallet_contract.plutus
cardano-cli conway transaction policyid --script-file contracts/wallet_contract.plutus > hashes/wallet.hash
echo -e "\033[1;33m Wallet Contract Hash: $(cat hashes/wallet.hash) \033[0m"

# end of build
echo -e "\033[1;32m\nBuilding Complete! \033[0m"

###############################################################################
######### THIS WILL BE REMOVED WHEN AIKEN MOVES TO V3 #########################
###############################################################################
echo -e "\033[1;34m\nV3 HACK! \033[0m"
jq \
'.type="PlutusScriptV3"' \
./contracts/pointer_contract.plutus | sponge ./contracts/pointer_contract.plutus
aiken build --uplc
sed -i '1s/.*/(program/; 2s/.*/  1.1.0/' artifacts/pointer.params.uplc
pointer_cbor=$(aiken uplc encode artifacts/pointer.params.uplc --cbor --hex)
pointer_cbor_cbor=$(python3 -c "import cbor2;hex_string='${pointer_cbor}';data = bytes.fromhex(hex_string);encoded = cbor2.dumps(data);print(encoded.hex())")

jq \
--arg cbor "$pointer_cbor_cbor" \
'.cborHex=$cbor
' \
./contracts/pointer_contract.plutus | sponge ./contracts/pointer_contract.plutus

pointer_hash=$(python3 -c "import hashlib;hex_string='03${pointer_cbor}';data = hashlib.blake2b(bytes.fromhex(hex_string), digest_size=28).digest().hex();print(data)")
echo -n "${pointer_hash}" > hashes/pointer.hash

jq \
'.type="PlutusScriptV3"' \
./contracts/wallet_contract.plutus | sponge ./contracts/wallet_contract.plutus
aiken build --uplc
sed -i '1s/.*/(program/; 2s/.*/  1.1.0/' artifacts/wallet.params.uplc
wallet_cbor=$(aiken uplc encode artifacts/wallet.params.uplc --cbor --hex)
wallet_cbor_cbor=$(python3 -c "import cbor2;hex_string='${wallet_cbor}';data = bytes.fromhex(hex_string);encoded = cbor2.dumps(data);print(encoded.hex())")

jq \
--arg cbor "$wallet_cbor_cbor" \
'.cborHex=$cbor
' \
./contracts/wallet_contract.plutus | sponge ./contracts/wallet_contract.plutus

wallet_hash=$(python3 -c "import hashlib;hex_string='03${wallet_cbor}';data = hashlib.blake2b(bytes.fromhex(hex_string), digest_size=28).digest().hex();print(data)")
echo -n "${wallet_hash}" > hashes/wallet.hash