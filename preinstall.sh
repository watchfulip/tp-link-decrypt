#!/bin/bash

RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
RESET="\e[0m"

# Function for logging messages
log_message() {
  echo -e "${GREEN}[INFO]${RESET} $1"
}

log_warning() {
  echo -e "${YELLOW}[WARNING]${RESET} $1"
}

log_error() {
  echo -e "${RED}[ERROR]${RESET} $1"
  exit 1
}

# Function to install a package with logging
install_package() {
  local package=$1
  log_message "Installing $package..."
  sudo apt install -y "$package" && log_message "$package installed." || log_warning "Failed to install $package. Skipping."
}

# Function to verify installed components
verify_component() {
  local component=$1
  echo -n "$component: "
  if command -v "$component" > /dev/null 2>&1; then
    log_message "$component installed."
  else
    log_warning "$component not found."
  fi
}

log_message "Detecting Linux distribution..."
DISTRO=$(lsb_release -is | tr '[:upper:]' '[:lower:]')
RELEASE=$(lsb_release -rs | cut -d. -f1)

log_message "Distribution: $DISTRO, Version: $RELEASE"

log_message "Updating package list..."
sudo apt update || log_error "Failed to update package list. Check your internet connection."

log_message "Installing required dependencies..."
install_package wget
install_package build-essential
install_package python3
install_package python3-pip
install_package python3-setuptools
install_package git
install_package gcc
install_package make
install_package cmake
install_package g++

if [[ "$DISTRO" == "debian" || "$DISTRO" == "ubuntu" || "$DISTRO" == "kali" ]]; then
  install_package xxd
  install_package binwalk

  log_message "Installing Python library ubi_reader..."
  pip3 install ubi-reader --break-system-packages && log_message "ubi_reader installed." || log_warning "Failed to install ubi_reader. Skipping."

  log_message "Verifying installed components..."
  verify_component xxd
  verify_component binwalk
  verify_component git
  verify_component gcc
  verify_component make
  verify_component cmake
  verify_component g++
  
  echo -n "ubi_reader: "
  if python3 -c "import ubireader" > /dev/null 2>&1; then
    log_message "ubi_reader installed."
  else
    log_warning "ubi_reader not found."
  fi

  log_message "Installation completed!"
else
  log_error "Distribution $DISTRO is not supported by this script."
fi

