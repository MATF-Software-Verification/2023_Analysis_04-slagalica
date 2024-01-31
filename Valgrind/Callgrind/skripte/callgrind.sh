#!/bin/bash


cd ../../../build-game-Desktop_Qt_6_6_1_GCC_64bit-Profile

export LD_LIBRARY_PATH=./serialization

valgrind --tool=callgrind --log-file="report_callgrind_server" ./server/server &
valgrind --tool=callgrind --log-file="report_callgrind_client1" ./slagalica/slagalica &
valgrind --tool=callgrind --log-file="report_callgrind_client2" ./slagalica/slagalica &
