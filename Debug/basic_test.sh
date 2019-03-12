#!/bin/bash

echo "-------------------------------------------"
echo "submit svn txn"
echo "-------------------------------------------"
sudo private-txn-generator create_batch -f txn_gen_svn.json 
private-txn-generator load

echo "-------------------------------------------"
echo "submit add user txn"
echo "-------------------------------------------"
sudo private-txn-generator create_batch -f txn_add_user.json 
private-txn-generator load
sleep 2s
echo "-------------------------------------------"
echo "submit balance txn"
echo "-------------------------------------------"
sudo private-txn-generator create_batch -f txn_balance.json 
private-txn-generator load
sleep 2s
echo "-------------------------------------------"
echo "submit bunny txn"
echo "-------------------------------------------"
sudo private-txn-generator create_batch -f txn_add_bunny.json 
private-txn-generator load
sleep 2s
echo "-------------------------------------------"
echo "submit add_couple txn"
echo "-------------------------------------------"
sudo private-txn-generator create_batch -f txn_add_couple.json 
private-txn-generator load
sleep 2s
echo "-------------------------------------------"
echo "sawtooth state list"
echo "-------------------------------------------"
sleep 1s
sawtooth state list
echo "-------------------------------------------"
echo "reading address"
echo "-------------------------------------------"
cd client_reader
python3 read_request.py bb563a4d49384b794f7a35656453656347354f6b4558666b6f70475279383200000000 -K ../admin_keys/
python3 read_request.py bb563a4d49384b794f7a35656453656347354f6b4558666b6f70475279383201000000 -K ../admin_keys/
python3 read_request.py bb563a4d49384b794f7a35656453656347354f6b4558666b6f70475279383202123450 -K ../admin_keys/
python3 read_request.py bb563a4d49384b794f7a35656453656347354f6b4558666b6f70475279383202123250 -K ../admin_keys/
python3 read_request.py bb563a4d49384b794f7a35656453656347354f6b4558666b6f70475279383203123450 -K ../admin_keys/
cd ../Debug
