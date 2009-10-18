CFLAGS = $(shell pkg-config --cflags glib-2.0 libcurl) -g
LDLIBS = $(shell pkg-config --libs glib-2.0 libcurl) -lpcap -lmysqlclient
torrentlog:
