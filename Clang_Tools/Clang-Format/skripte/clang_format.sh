#!/bin/bash

clang-format --style=LLVM -dump-config > .clang-format
python3 run_clang_format.py ../../../04-slagalica/src
