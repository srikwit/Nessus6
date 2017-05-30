#!/bin/bash
nmap -sS -sV -sC -O -vv --system-dns --traceroute --reason -oA scan -iL targets.txt
./gimme_some_shells.py
