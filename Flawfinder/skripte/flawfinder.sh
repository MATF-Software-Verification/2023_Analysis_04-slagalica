#!/bin/bash


# pozivanje bez zadavanja minimalnog nivoa rizika
# ./flawfinder.sh

# pozivanje sa zadavanjem minimalnog nivoa rizika (broj od 0 do 5)
# ./flawfinder.sh nivo_rizika


# moze se zadati minimalni nivo rizika trazenih upozorenja kao argument
if [ $# -ge 1 ]; then
    printf '\033[1mMinimalni nivo rizika je %d!\n\033[0m' $1
    # generisanje izvestaja 
    flawfinder --html --minlevel=$1 ../../04-slagalica/src/serialization ../../04-slagalica/src/server ../../04-slagalica/src/slagalica > flawfinder_report.html    
else
    # ako se ne zada eksplicitno uzima se nivo 2 
    printf '\033[1mMinimalni nivo rizika je 2!\n\033[0m'
    # generisanje izvestaja
    flawfinder --html --minlevel=2 ../../04-slagalica/src/serialization ../../04-slagalica/src/server ../../04-slagalica/src/slagalica > flawfinder_report.html
fi

# otvaranje izvestaja u browser-u
firefox flawfinder_report.html
