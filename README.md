# Wii_extract_certs

Extract Wii certificates from `00000011.app` Wii NAND file

Source code is from this page: https://dolphin-emu.org/docs/guides/wii-network-guide/

## Usage

`./extract_certs 00000011.app`

## Compile error on Linux

Compile with command: `g++ extract_certs.cpp -o extract_certs -std=gnu++0x` to prevent error `'GLIBCXX_3.4.26' not found`
