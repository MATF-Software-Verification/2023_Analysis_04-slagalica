#!/bin/bash

# ucitavanje aliasa (putanja do qmake)
shopt -s expand_aliases
source ~/.bash_aliases


# generisanje Makefile-a u build direktorijumu
qmake -o ../../build_dir/Makefile ../../04-slagalica/src/game.pro

# ulazak u build_dir
cd ../../build_dir

# build projekta
make

# postavljanje promenljive okruzenja za nalazenje deljene biblioteke u runtime-u
export LD_LIBRARY_PATH=./serialization

# pokretanje testova
./tests/tests
