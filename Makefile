all: torrentlog

torrentlog: torrentlog.c
	gcc -o torrentlog torrentlog.c -lpcap
