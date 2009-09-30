all: torrentlog

torrentlog: torrentlog.c
	gcc `pkg-config --cflags glib-2.0` -Imysql -o torrentlog torrentlog.c -lpcap -lmysqlclient `pkg-config --libs glib-2.0`
