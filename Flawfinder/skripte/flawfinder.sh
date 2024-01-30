#!/bin/bash


# generisanje izvestaja
flawfinder --html --minlevel=2 ../../04-slagalica/src/serialization ../../04-slagalica/src/server ../../04-slagalica/src/slagalica > flawfinder_report.html


# otvaranje izvestaja u browser-u
firefox flawfinder_report.html
