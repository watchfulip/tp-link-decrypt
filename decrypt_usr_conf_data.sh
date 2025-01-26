#!/bin/bash

#
# 1) Find usr_conf_data
#
echo "Searching for 'usr_conf_data' in subdirectories..."
USR_CONF_PATH="$(find . -type f -name 'usr_conf_data' | head -n 1)"

if [ -z "$USR_CONF_PATH" ]; then
  echo "ERROR: 'usr_conf_data' not found in any subdirectory."
  exit 1
fi

echo "Found: $USR_CONF_PATH"

#
# 2) Extract the last (or first) 'Hex value key' from DES_key_n_hex.txt
#
# - tail -1 берёт последнюю найденную строку с 'Hex value key:'
#   Если нужно брать первую, замените на 'head -n 1'
#
HEX_KEY="$(grep 'Hex value key:' DES_key_n_hex.txt | tail -n 1 | awk '{print $4}')"

if [ -z "$HEX_KEY" ]; then
  echo "ERROR: Could not find 'Hex value key:' line in DES_key_n_hex.txt."
  exit 1
fi

echo "Using hex key from file: $HEX_KEY"

#
# 3) Decrypt using openssl des-ecb
#
echo "Decrypting $USR_CONF_PATH -> usr_conf_data_dec ..."
openssl enc -d -des-ecb -nopad -K "$HEX_KEY" -in "$USR_CONF_PATH" -out usr_conf_data_dec -provider legacy

if [ $? -ne 0 ]; then
  echo "ERROR: openssl decryption failed."
  exit 1
fi

echo "Decryption complete: usr_conf_data_dec"

#
# 4) Run binwalk -e
#
echo "Running binwalk -e on usr_conf_data_dec ..."
binwalk -e usr_conf_data_dec

