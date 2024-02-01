#!/bin/bash

# pokretanje za standardan izvestaj:
# ./memcheck.sh

# pozivanje za detaljan izvestaj:
# ./memcheck.sh detailed


cd ../../../build-game-Desktop_Qt_6_6_1_GCC_64bit-Profile

export LD_LIBRARY_PATH=./serialization

PATH_SERVER_REPORT='../Valgrind/Memcheck/izvestaji/report_memcheck_server'
PATH_CLIENT1_REPORT='../Valgrind/Memcheck/izvestaji/report_memcheck_client1'
PATH_CLIENT2_REPORT='../Valgrind/Memcheck/izvestaji/report_memcheck_client2'

# ako je prvi argument komandne linije 'detailed' ukljucuju se dodatne opcije (dodatno usporenje izvrsavanja programa)
if [[ $1 = 'detailed' ]]; then
	echo -e '\033[1mOdabran detaljan izvestaj!\033[0m'
	valgrind --show-leak-kinds=all --leak-check=full --track-origins=yes --verbose --log-file=$PATH_SERVER_REPORT ./server/server &
	valgrind --show-leak-kinds=all --leak-check=full --track-origins=yes --verbose --log-file=$PATH_CLIENT1_REPORT ./slagalica/slagalica &
	valgrind --show-leak-kinds=all --leak-check=full --track-origins=yes --verbose --log-file=$PATH_CLIENT2_REPORT ./slagalica/slagalica &
# u suprotnom se sprovodi samo standardna analiza
else
	echo -e '\033[1mOdabran standardni izvestaj!\033[0m'
	valgrind --log-file=$PATH_SERVER_REPORT ./server/server &
	valgrind --log-file=$PATH_CLIENT1_REPORT ./slagalica/slagalica &
	valgrind --log-file=$PATH_CLIENT2_REPORT ./slagalica/slagalica &
fi
