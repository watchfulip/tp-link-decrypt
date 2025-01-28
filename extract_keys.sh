#!/bin/bash

# Watchful_IP - Find RSA KEYs in TP-Link firmware and write them to include dir
# VERSION=0.0.3
# VDATE=03-01-25

CORRECT_SHA256="0a7857d40fb02ff1b8d3cbce769e6c402a82a8094b4af553c54e4ffbdc4b6e64"
LOG_FILE="rsa_key_extractor.log"

# Colors for output
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
RESET="\e[0m"

log_message() {
  echo -e "$1" | tee -a "$LOG_FILE"
}

log_info() {
  log_message "${GREEN}[INFO]${RESET} $1"
}

log_warn() {
  log_message "${YELLOW}[WARNING]${RESET} $1"
}

log_error() {
  log_message "${RED}[ERROR]${RESET} $1"
  exit 1
}

BINWALK=$(which binwalk)
if [ -z "$BINWALK" ]; then
  log_error "binwalk is not installed. Please install it and try again."
fi

[ ! -d include ] && mkdir include
TMP_DIR="tmp.fwextract"
[ -d "$TMP_DIR" ] && rm -rf "$TMP_DIR"
mkdir "$TMP_DIR"
cd "$TMP_DIR"

if [ ! -d fw ]; then
  mkdir -p fw
  cd fw
  wget -nc 'http://download.tplinkcloud.com/firmware/ax6000v2-up-ver1-1-2-P1[20230731-rel41066]_1024_nosign_2023-07-31_11.26.17_1693471186048.bin.rollback'
  wget -nc 'http://download.tplinkcloud.com/firmware/Tapo_C210v1_en_1.3.1_Build_221218_Rel.73283n_u_1679534600836.bin'
  cd ..
fi

log_info "Do you want to run binwalk in quiet mode? [yes/no]"
read -r QUIET_MODE
if [[ "$QUIET_MODE" == "yes" ]]; then
  log_info "Extracting ../fw/ax6000v2-up-ver1-1-2-P1[20230731-rel41066]_1024_nosign_2023-07-31_11.26.17_1693471186048.bin.rollback..."
  if [ "$EUID" -eq 0 ]; then
    binwalk -e -C 1 --run-as=root fw/ax6000v2-up-ver1-1-2-P1[20230731-rel41066]_1024_nosign_2023-07-31_11.26.17_1693471186048.bin.rollback 2>/dev/null
  else
    binwalk -e -C 1 fw/ax6000v2-up-ver1-1-2-P1[20230731-rel41066]_1024_nosign_2023-07-31_11.26.17_1693471186048.bin.rollback 2>/dev/null
  fi
  RSAKEY_1=$(find -type f -name nvrammanager | head -n 1 | xargs strings | grep BgIAAAwk)
  if [ -z "$RSAKEY_1" ]; then
    log_error "Failed to extract RSAKEY_1."
  fi

  log_info "RSAKEY_1: $RSAKEY_1"

  log_info "Extracting ../fw/Tapo_C210v1_en_1.3.1_Build_221218_Rel.73283n_u_1679534600836.bin..."
  if [ "$EUID" -eq 0 ]; then
    binwalk -e -C 0 --run-as=root fw/Tapo_C210v1_en_1.3.1_Build_221218_Rel.73283n_u_1679534600836.bin 2>/dev/null
  else
    binwalk -e -C 0 fw/Tapo_C210v1_en_1.3.1_Build_221218_Rel.73283n_u_1679534600836.bin 2>/dev/null
  fi
  RSAKEY_0=$(find -type f -name slpupgrade | head -n 1 | xargs strings | grep BgIAAAwk)
  if [ -z "$RSAKEY_0" ]; then
    log_error "Failed to extract RSAKEY_0."
  fi
else
  log_info "Extracting ../fw/ax6000v2-up-ver1-1-2-P1[20230731-rel41066]_1024_nosign_2023-07-31_11.26.17_1693471186048.bin.rollback..."
  if [ "$EUID" -eq 0 ]; then
    binwalk -e -C 1 --run-as=root fw/ax6000v2-up-ver1-1-2-P1[20230731-rel41066]_1024_nosign_2023-07-31_11.26.17_1693471186048.bin.rollback
  else
    binwalk -e -C 1 fw/ax6000v2-up-ver1-1-2-P1[20230731-rel41066]_1024_nosign_2023-07-31_11.26.17_1693471186048.bin.rollback
  fi
  RSAKEY_1=$(find -type f -name nvrammanager | head -n 1 | xargs strings | grep BgIAAAwk)
  if [ -z "$RSAKEY_1" ]; then
    log_error "Failed to extract RSAKEY_1."
  fi

  log_info "RSAKEY_1: $RSAKEY_1"

  log_info "Extracting ../fw/Tapo_C210v1_en_1.3.1_Build_221218_Rel.73283n_u_1679534600836.bin..."
  if [ "$EUID" -eq 0 ]; then
    binwalk -e -C 0 --run-as=root fw/Tapo_C210v1_en_1.3.1_Build_221218_Rel.73283n_u_1679534600836.bin
  else
    binwalk -e -C 0 fw/Tapo_C210v1_en_1.3.1_Build_221218_Rel.73283n_u_1679534600836.bin
  fi
  RSAKEY_0=$(find -type f -name slpupgrade | head -n 1 | xargs strings | grep BgIAAAwk)
  if [ -z "$RSAKEY_0" ]; then
    log_error "Failed to extract RSAKEY_0."
  fi
fi

log_info "RSAKEY_0: $RSAKEY_0"

CALC_SHA256=$(echo -n "$RSAKEY_0 $RSAKEY_1" | sha256sum | awk '{print $1}')
if [ "$CORRECT_SHA256" != "$CALC_SHA256" ]; then
  log_error "Extracted RSA keys do not match the expected data. Exiting."
else
  log_info "Extracted RSA keys match the expected data."
  echo -n "$RSAKEY_0" > RSA_0
  xxd -i RSA_0 > ../include/RSA_0.h
  echo -n "$RSAKEY_1" > RSA_1
  xxd -i RSA_1 > ../include/RSA_1.h
  log_info "RSA keys written to include directory. Ready for make."
fi

cd ..

# Cleanup
log_info "You can remove the temporary directory with: rm -rf $TMP_DIR"
