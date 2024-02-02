#!/bin/bash

# pokretanje bez simulacije keš memorije:
# ./callgrind.sh

# pozivanje sa simulacijom keš memorije:
# ./callgrind.sh cache


cd ../../../build-game-Desktop_Qt_6_6_1_GCC_64bit-Profile

export LD_LIBRARY_PATH=./serialization

PATH_SERVER_LOG='../Valgrind/Callgrind/server/log_callgrind_server'
PATH_CLIENT1_LOG='../Valgrind/Callgrind/client/log_callgrind_client1'
PATH_CLIENT2_LOG='../Valgrind/Callgrind/client/log_callgrind_client2'

PATH_SERVER_REPORT='../Valgrind/Callgrind/server/report_callgrind_server'
PATH_CLIENT1_REPORT='../Valgrind/Callgrind/client/report_callgrind_client1'
PATH_CLIENT2_REPORT='../Valgrind/Callgrind/client/report_callgrind_client2'

# ako je prvi argument komandne linije 'cache' alat se pokreće sa simulacijom keš memorije (dodatno usporenje izvršavanja programa)
if [[ $1 = 'cache' ]]; then
	echo -e '\033[1mCallgrind se pokreće sa simulacijom keš memorije!\033[0m'
	valgrind --cache-sim=yes --tool=callgrind --log-file=$PATH_SERVER_LOG --callgrind-out-file=$PATH_SERVER_REPORT ./server/server &
	valgrind --cache-sim=yes --tool=callgrind --log-file=$PATH_CLIENT1_LOG --callgrind-out-file=$PATH_CLIENT1_REPORT ./slagalica/slagalica &
	valgrind --cache-sim=yes --tool=callgrind --log-file=$PATH_CLIENT2_LOG --callgrind-out-file=$PATH_CLIENT2_REPORT ./slagalica/slagalica &
# u suprotnom se pokreće bez simulacije keš memorije
else
	echo -e '\033[1mCallgrind se pokreće bez simulacije keš memorije!\033[0m'
	valgrind --tool=callgrind --log-file=$PATH_SERVER_LOG --callgrind-out-file=$PATH_SERVER_REPORT ./server/server &
	valgrind --tool=callgrind --log-file=$PATH_CLIENT1_LOG --callgrind-out-file=$PATH_CLIENT1_REPORT ./slagalica/slagalica &
	valgrind --tool=callgrind --log-file=$PATH_CLIENT2_LOG --callgrind-out-file=$PATH_CLIENT2_REPORT ./slagalica/slagalica &
fi
