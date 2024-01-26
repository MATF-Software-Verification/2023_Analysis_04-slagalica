#!/bin/bash

# pozivanje bez filtriranja: 
# ./coverage.sh

# pozivanje sa filtriranjem:
# ./coverage.sh filter


# ucitavanje aliasa (putanja do qmake)
shopt -s expand_aliases
source ~/.bash_aliases


# generisanje Makefile-a u build direktorijumu
qmake -o ../../build_dir/Makefile ../../04-slagalica/src/game.pro CONFIG+=debug CONFIG+=qml_debug

# ulazak u build_dir
cd ../../build_dir

# build projekta
make

# postavljanje promenljive okruzenja za nalazenje deljene biblioteke u runtime-u
export LD_LIBRARY_PATH=./serialization

# pokretanje testova
./tests/tests


# generisanje izvestaja na osnovu .gcno i .gcda fajlova
lcov --rc lcov_branch_coverage=1 --capture --directory . -o coverage.info

COV='coverage.info'

# opciono filtriranje izvestaja
if [ $1 = 'filter' ]; then
    echo -e '\033[1mOdabrana opcija sa filtriranjem izvestaja!\033[0m'
    sleep 5
    lcov -r --rc lcov_branch_coverage=1 "coverage.info" "*Qt*.framework*" "*.h" "*/tests/*" "*Xcode.app*" "*.moc" "*moc_*.cpp"  "/usr/*" "/opt/*"  "*/test/*" "*/build*/*" -o "coverage-filtered.info"
    COV='coverage-filtered.info'
else
    echo -e '\033[1mOdabrana opcija bez filtriranja izvestaja!\033[0m'
    sleep 5
fi


# generisanje html prikaza
genhtml --rc lcov_branch_coverage=1 -o Reports $COV


# otvaranje u browser-u
firefox Reports/index.html
