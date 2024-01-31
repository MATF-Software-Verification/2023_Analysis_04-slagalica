#!/bin/bash


cd ../../../build-game-Desktop_Qt_6_6_1_GCC_64bit-Profile

export LD_LIBRARY_PATH=./serialization

valgrind --show-leak-kinds=all --leak-check=full --track-origins=yes --log-file="report_memcheck_server" ./server/server &
valgrind --show-leak-kinds=all --leak-check=full --track-origins=yes --log-file="report_memcheck_client1" ./slagalica/slagalica &
valgrind --show-leak-kinds=all --leak-check=full --track-origins=yes --log-file="report_memcheck_client2" ./slagalica/slagalica &
