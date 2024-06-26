#!/bin/bash
set -e

# SET UP VARS HERE
source ../.env

mkdir -p ./addrs

# get params
${cli} conway query protocol-parameters ${network} --out-file ../tmp/protocol.json

# user
user="user-1"
user_address=$(cat ../wallets/${user}-wallet/payment.addr)
user_pkh=$(${cli} conway address key-hash --payment-verification-key-file ../wallets/${user}-wallet/payment.vkey)

# wallet script
wallet_script_path="../../contracts/wallet_contract.plutus"
wallet_script_address=$(${cli} conway address build --payment-script-file ${wallet_script_path} ${network})

# pointer script
pointer_script_path="../../contracts/pointer_contract.plutus"

# collat
collat_address=$(cat ../wallets/collat-wallet/payment.addr)
collat_pkh=$(${cli} conway address key-hash --payment-verification-key-file ../wallets/collat-wallet/payment.vkey)

# the personal tag in ascii
if [[ $# -eq 0 ]] ; then
    echo -e "\n \033[0;31m Personal String Is Empty \033[0m \n"
    msg=""
else
    msg=$(echo -n "${1}" | xxd -ps | tr -d '\n' | cut -c 1-30)
fi

# get user utxo
echo -e "\033[0;36m Gathering UTxO Information  \033[0m"
${cli} conway query utxo \
    ${network} \
    --address ${user_address} \
    --out-file ../tmp/user_utxo.json

TXNS=$(jq length ../tmp/user_utxo.json)
if [ "${TXNS}" -eq "0" ]; then
   echo -e "\n \033[0;31m NO UTxOs Found At ${user_address} \033[0m \n";
   exit;
fi
alltxin=""
TXIN=$(jq -r --arg alltxin "" 'keys[] | . + $alltxin + " --tx-in"' ../tmp/user_utxo.json)
user_tx_in=${TXIN::-8}

user_starting_lovelace=$(jq '[.[] | .value.lovelace] | add' ../tmp/user_utxo.json)

echo "UTxO:" $user_tx_in
first_utxo=$(jq -r 'keys[0]' ../tmp/user_utxo.json)
string=${first_utxo}
IFS='#' read -ra array <<< "$string"

# the ordering here for the first utxo is lexicographic
prefix="5eed0e1f"
# personalize this to whatever you want but the max hex length is 30 characters
echo Personal Msg: ${msg}
jq --arg variable "${msg}" '.bytes=$variable' ../data/pointer/pointer-redeemer.json | sponge ../data/pointer/pointer-redeemer.json

# generate the token
pointer_name=$(python3 -c "
import sys;
sys.path.append('../py/');
from get_token_name import personal;
t = personal('${array[0]}', ${array[1]}, '${prefix}', '${msg}');
print(t)
")

# generate the random secret and build the datum
python3 -c "
import sys;
sys.path.append('../py/');
import bls12_381 as bls;
c = bls.create_token();
bls.write_token_to_file(c, 'addrs/', '${pointer_name}')
"

token_file_name="${pointer_name}.json"
echo -e "\033[0;33m\nCreating Seed Elf: $pointer_name\n\033[0m"

jq --arg variable "$(jq -r '.a' ./addrs/${token_file_name})" '.fields[0].bytes=$variable' ../data/wallet/wallet-datum.json | sponge ../data/wallet/wallet-datum.json
jq --arg variable "$(jq -r '.b' ./addrs/${token_file_name})" '.fields[1].bytes=$variable' ../data/wallet/wallet-datum.json | sponge ../data/wallet/wallet-datum.json

# the minting script policy
policy_id=$(cat ../../hashes/pointer.hash)

mint_token="1 ${policy_id}.${pointer_name}"
# required_lovelace=$(${cli} conway transaction calculate-min-required-utxo \
#     --protocol-params-file ../tmp/protocol.json \
#     --tx-out-inline-datum-file ../data/wallet/wallet-datum.json \
#     --tx-out="${wallet_script_address} + 5000000 + ${mint_token}" | tr -dc '0-9')

wallet_script_out="${wallet_script_address} + ${user_starting_lovelace} + ${mint_token}"
echo "Wallet: "${wallet_script_out}
#
# exit
#
# collat info
echo -e "\033[0;36m Gathering Collateral UTxO Information  \033[0m"
${cli} conway query utxo \
    ${network} \
    --address ${collat_address} \
    --out-file ../tmp/collat_utxo.json

TXNS=$(jq length ../tmp/collat_utxo.json)
if [ "${TXNS}" -eq "0" ]; then
   echo -e "\n \033[0;31m NO UTxOs Found At ${collat_address} \033[0m \n";
   exit;
fi
collat_tx_in=$(jq -r 'keys[0]' ../tmp/collat_utxo.json)

pointer_ref_utxo=$(${cli} conway transaction txid --tx-file ../tmp/utxo-pointer_contract.plutus.signed)

# echo -e "\033[0;36m Building Tx \033[0m"
# FEE=$(${cli} conway transaction build \
#     --out-file ../tmp/tx.draft \
#     --change-address ${user_address} \
#     --tx-in-collateral ${collat_tx_in} \
#     --tx-in ${user_tx_in} \
#     --tx-out="${wallet_script_out}" \
#     --tx-out-inline-datum-file ../data/wallet/wallet-datum.json \
#     --required-signer-hash ${user_pkh} \
#     --required-signer-hash ${collat_pkh} \
#     --mint="${mint_token}" \
#     --mint-tx-in-reference="${pointer_ref_utxo}#1" \
#     --mint-plutus-script-v3 \
#     --mint-reference-tx-in-redeemer-file ../data/pointer/pointer-redeemer.json \
#     --policy-id="${policy_id}" \
#     ${network})

# Build Raw test
execution_unts="(0, 0)"
echo -e "\033[0;36m Building Tx \033[0m"
${cli} conway transaction build-raw \
    --out-file ../tmp/tx.draft \
    --protocol-params-file ../tmp/protocol.json \
    --tx-in-collateral ${collat_tx_in} \
    --tx-in ${user_tx_in} \
    --tx-out="${wallet_script_out}" \
    --tx-out-inline-datum-file ../data/wallet/wallet-datum.json \
    --required-signer-hash ${user_pkh} \
    --required-signer-hash ${collat_pkh} \
    --mint="${mint_token}" \
    --mint-tx-in-reference="${pointer_ref_utxo}#1" \
    --mint-plutus-script-v3 \
    --mint-reference-tx-in-redeemer-file ../data/pointer/pointer-redeemer.json \
    --mint-reference-tx-in-execution-units="${execution_unts}" \
    --policy-id="${policy_id}" \
    --fee 0

cpu=550000000
mem=2000000

pointer_execution_unts="(${cpu}, ${mem})"
pointer_computation_fee=$(echo "0.0000721*${cpu} + 0.0577*${mem}" | bc)
pointer_computation_fee_int=$(printf "%.0f" "$pointer_computation_fee")
#
# exit
#
FEE=$(${cli} conway transaction calculate-min-fee --tx-body-file ../tmp/tx.draft ${network} --protocol-params-file ../tmp/protocol.json --reference-script-size 10000 --tx-in-count 3 --tx-out-count 3 --witness-count 2)
fee=$(echo $FEE | rev | cut -c 9- | rev)

total_fee=$((${fee} + ${pointer_computation_fee_int} + 250000))
echo Tx Fee: $total_fee
change_value=$((${user_starting_lovelace} - ${total_fee}))
wallet_script_out="${wallet_script_address} + ${change_value} + ${mint_token}"
echo "Without Fee: Wallet OUTPUT: "${wallet_script_out}

#
# exit
#

${cli} conway transaction build-raw \
    --out-file ../tmp/tx.draft \
    --protocol-params-file ../tmp/protocol.json \
    --tx-in-collateral ${collat_tx_in} \
    --tx-in ${user_tx_in} \
    --tx-out="${wallet_script_out}" \
    --tx-out-inline-datum-file ../data/wallet/wallet-datum.json \
    --required-signer-hash ${user_pkh} \
    --required-signer-hash ${collat_pkh} \
    --mint="${mint_token}" \
    --mint-tx-in-reference="${pointer_ref_utxo}#1" \
    --mint-plutus-script-v3 \
    --mint-reference-tx-in-redeemer-file ../data/pointer/pointer-redeemer.json \
    --mint-reference-tx-in-execution-units="${pointer_execution_unts}" \
    --policy-id="${policy_id}" \
    --fee ${total_fee}

# IFS=':' read -ra VALUE <<< "${FEE}"
# IFS=' ' read -ra FEE <<< "${VALUE[1]}"
# FEE=${FEE[1]}
# echo -e "\033[1;32m Fee: \033[0m" $FEE
#
# exit
#
echo -e "\033[0;36m Signing \033[0m"
${cli} conway transaction sign \
    --signing-key-file ../wallets/${user}-wallet/payment.skey \
    --signing-key-file ../wallets/collat-wallet/payment.skey \
    --tx-body-file ../tmp/tx.draft \
    --out-file ../tmp/tx.signed \
    ${network}
#
# exit
#
echo -e "\033[0;36m Submitting \033[0m"
${cli} conway transaction submit \
    ${network} \
    --tx-file ../tmp/tx.signed

tx=$(${cli} conway transaction txid --tx-file ../tmp/tx.signed)
echo "Tx Hash:" $tx
