all: torrentlog

torrentlog: torrentlog.c
	gcc `pkg-config --cflags --libs glib-2.0` -Imysql -lmysqlclient -lpcap -o torrentlog torrentlog.c
