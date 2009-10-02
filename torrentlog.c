#include <stdlib.h>
#include <stdio.h>
#include <mysql/mysql.h>
#include <mysql/errmsg.h>
#include <glib.h>
#include <glob.h>
#include <libgen.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <strings.h>
#include <glib/gprintf.h>
#include <string.h>
#include <curl/curl.h>
#include <arpa/inet.h>

void myexit( const char * msg ) {
	fprintf( stderr, "%s\n", msg );
	exit(EXIT_FAILURE);
}

unsigned long insertTracker( MYSQL * db, char * hostname ) {
	static MYSQL_STMT *stmt;
	static MYSQL_BIND bind;
	static my_bool is_null;
	static my_bool stmterror;
	static int prepared = 0;
	static char input_hostname[256];
	static unsigned long inlen;
	if( prepared == 0 ) {
		stmt = mysql_stmt_init(db);
		char * query = "INSERT INTO trackers(url) VALUES(?)";
		if( mysql_stmt_prepare( stmt, query, strlen(query) ) ) {
			myexit( mysql_stmt_error(stmt) );
		}
		memset(&bind, 0, sizeof(bind));
		bind.buffer_type = MYSQL_TYPE_STRING;
		bind.buffer = input_hostname;
		bind.buffer_length = 256;
		bind.length = &inlen;
		bind.is_null = &is_null;
		is_null = 0;
		bind.error = &stmterror;
		if( mysql_stmt_bind_param(stmt, &bind) ) {
			mysql_stmt_error(stmt);
		}
		prepared = 1;
	}
	strncpy( input_hostname, hostname, 256 );
	inlen = strlen(input_hostname);
	if( mysql_stmt_execute(stmt) ) {
		myexit( mysql_stmt_error(stmt) );
	}
	return (unsigned long)mysql_stmt_insert_id(stmt);
}

unsigned long insertTorrent( MYSQL * db, char * infohash ) {
	static MYSQL_STMT *stmt;
	static MYSQL_BIND bind;
	static my_bool is_null;
	static my_bool stmterror;
	static int prepared = 0;
	static char input_infohash[20];
	static unsigned long inlen = 20;
	if( prepared == 0 ) {
		stmt = mysql_stmt_init(db);
		char * query = "INSERT INTO torrents(infohash) VALUES(?)";
		if( mysql_stmt_prepare( stmt, query, strlen(query) ) ) {
			myexit( mysql_stmt_error(stmt) );
		}
		memset(&bind, 0, sizeof(bind));
		bind.buffer_type = MYSQL_TYPE_BLOB;
		bind.buffer = input_infohash;
		bind.buffer_length = 20;
		bind.length = &inlen;
		bind.is_null = &is_null;
		is_null = 0;
		bind.error = &stmterror;
		if( mysql_stmt_bind_param(stmt, &bind) ) {
			mysql_stmt_error(stmt);
		}
		prepared = 1;
	}
	memcpy( input_infohash, infohash, 20 );
	if( mysql_stmt_execute(stmt) ) {
		myexit( mysql_stmt_error(stmt) );
	}
	return (unsigned long)mysql_stmt_insert_id(stmt);
}

void insertHandshake( MYSQL * db, unsigned int torrentid, unsigned int sip, unsigned int dip ) {
	static MYSQL_STMT *stmt;
	static MYSQL_BIND bind[3];
	static my_bool is_null[3];
	static my_bool is_unsigned[3];
	static my_bool stmterror[3];
	static int prepared = 0;
	static unsigned int input_torrentid;
	static unsigned int input_sip;
	static unsigned int input_dip;
	if( prepared == 0 ) {
		stmt = mysql_stmt_init(db);
		char * query = "INSERT INTO handshakes(torrentid, sip, dip) VALUES(?,?,?)";
		if( mysql_stmt_prepare( stmt, query, strlen(query) ) ) {
			myexit( mysql_stmt_error(stmt) );
		}
		memset(&bind, 0, sizeof(bind));
		bind[0].buffer_type = MYSQL_TYPE_LONG;
		bind[0].buffer = &input_torrentid;
		bind[0].buffer_length = sizeof(input_torrentid);
		bind[0].is_null = (my_bool*)0;
		bind[0].is_unsigned = 1;
		bind[0].error = &stmterror[0];
		bind[1].buffer_type = MYSQL_TYPE_LONG;
		bind[1].buffer = &input_sip;
		bind[1].buffer_length = sizeof(input_sip);
		bind[1].is_null = (my_bool*)0;
		bind[1].is_unsigned = 1;
		bind[1].error = &stmterror[1];
		bind[2].buffer_type = MYSQL_TYPE_LONG;
		bind[2].buffer = &input_dip;
		bind[2].buffer_length = sizeof(input_dip);
		bind[2].is_null = (my_bool*)0;
		bind[2].is_unsigned = 1;
		bind[2].error = &stmterror[2];
		if( mysql_stmt_bind_param(stmt, bind) ) {
			mysql_stmt_error(stmt);
		}
		prepared = 1;
	}
	input_torrentid = torrentid;
	input_sip = sip;
	input_dip = dip;
	int status = mysql_stmt_execute(stmt);
	switch (status) {
		case 0:
			break;
		case CR_COMMANDS_OUT_OF_SYNC:
			printf("out of sync\n");
			break;
		case CR_OUT_OF_MEMORY:
			printf("out of memory\n");
			break;
		case CR_SERVER_GONE_ERROR:
			printf("server gone\n");
			break;
		case CR_SERVER_LOST:
			printf("server lost\n");
			break;
		case CR_UNKNOWN_ERROR:
			myexit( mysql_stmt_error(stmt) );
			break;
		case 1: //duplicate key exists. found by testing, not documented by mysql
			break;
		default:
			printf("status: %u\n", status);
			myexit( mysql_stmt_error(stmt) );
			break;

	}
}

void insertAnnounce( MYSQL * db, unsigned int trackerid, unsigned int torrentid ) {
	static MYSQL_STMT *stmt;
	static MYSQL_BIND bind[2];
	static my_bool stmterror[2];
	static int prepared = 0;
	static unsigned int input_trackerid;
	static unsigned int input_torrentid;
	if( prepared == 0 ) {
		stmt = mysql_stmt_init(db);
		char * query = "INSERT INTO announces(trackerid, torrentid) VALUES(?,?)";
		if( mysql_stmt_prepare( stmt, query, strlen(query) ) ) {
			myexit( mysql_stmt_error(stmt) );
		}
		memset(&bind, 0, sizeof(bind));
		bind[0].buffer_type = MYSQL_TYPE_LONG;
		bind[0].buffer = &input_trackerid;
		bind[0].buffer_length = sizeof(input_trackerid);
		bind[0].is_null = (my_bool*)0;
		bind[0].is_unsigned = 1;
		bind[0].error = &stmterror[0];
		bind[1].buffer_type = MYSQL_TYPE_LONG;
		bind[1].buffer = &input_torrentid;
		bind[1].buffer_length = sizeof(input_torrentid);
		bind[1].is_null = (my_bool*)0;
		bind[1].is_unsigned = 1;
		bind[1].error = &stmterror[1];
		if( mysql_stmt_bind_param(stmt, bind) ) {
			mysql_stmt_error(stmt);
		}
		prepared = 1;
	}
	input_trackerid = trackerid;
	input_torrentid = torrentid;
	int status = mysql_stmt_execute(stmt);
	switch (status) {
		case 0:
			break;
		case CR_COMMANDS_OUT_OF_SYNC:
			printf("out of sync\n");
			break;
		case CR_OUT_OF_MEMORY:
			printf("out of memory\n");
			break;
		case CR_SERVER_GONE_ERROR:
			printf("server gone\n");
			break;
		case CR_SERVER_LOST:
			printf("server lost\n");
			break;
		case CR_UNKNOWN_ERROR:
			myexit( mysql_stmt_error(stmt) );
			break;
		case 1: //duplicate key exists. found by testing, not documented by mysql
			break;
		default:
			printf("status: %u\n", status);
			myexit( mysql_stmt_error(stmt) );
			break;

	}
}

unsigned int selectTracker( MYSQL * db, char * hostname ) {
	static MYSQL_STMT *stmt;
	static MYSQL_BIND bind[2];
	static int prepared = 0;
	unsigned int trackerid;
	char input_hostname[256];
	static my_bool is_null[2];
	static my_bool stmterror[2];
	static unsigned long inlen;
	if( prepared == 0 ) {
		stmt = mysql_stmt_init(db);
		char * query = "SELECT trackerid FROM trackers WHERE url = ?";
		if( mysql_stmt_prepare( stmt, query, strlen(query) ) ) {
			myexit( mysql_stmt_error(stmt) );
		}
		memset(bind, 0, sizeof(bind));
		bind[0].buffer_type = MYSQL_TYPE_LONG;
		bind[0].buffer = &trackerid;
		bind[0].buffer_length = sizeof(trackerid);
		bind[0].is_null = &is_null[0];
		bind[0].error = &stmterror[0];
		if( mysql_stmt_bind_result( stmt, &bind[0] ) ) {
			myexit( mysql_error(db) );
		}

		bind[1].buffer_type =  MYSQL_TYPE_STRING;
		bind[1].buffer = input_hostname;
		bind[1].buffer_length = 256;
		bind[1].length = &inlen;
		bind[1].is_null = &is_null[1];
		is_null[1] = 0;
		bind[1].error = &stmterror[1];
		if( mysql_stmt_bind_param( stmt, &bind[1] ) ) {
			mysql_stmt_error(stmt);
		}
		prepared = 1;
	}
	strncpy( input_hostname, hostname, 256 );
	inlen = strlen(input_hostname);
	if( mysql_stmt_execute(stmt) ) {
		myexit( mysql_stmt_error(stmt) );
	}
	int result = mysql_stmt_fetch(stmt);
	switch ( result ) {
		case 0:
			break;
		case 1:
			trackerid = 0;
			break;
		case MYSQL_NO_DATA:
			trackerid = 0;
			break;
		case MYSQL_DATA_TRUNCATED:
			return 0;
			break;
	}
	mysql_stmt_free_result(stmt);
	return trackerid;
}

unsigned int selectTorrent( MYSQL * db, char * infohash ) {
	static MYSQL_STMT *stmt;
	static MYSQL_BIND bind[2];
	static int prepared = 0;
	unsigned int torrentid;
	char input_infohash[256];
	static my_bool is_null[2];
	static my_bool stmterror[2];
	unsigned long inlen = 20;
	if( prepared == 0 ) {
		stmt = mysql_stmt_init(db);
		char * query = "SELECT torrentid FROM torrents WHERE infohash = ?";
		if( mysql_stmt_prepare( stmt, query, strlen(query) ) ) {
			myexit( mysql_stmt_error(stmt) );
		}
		memset(bind, 0, sizeof(bind));
		bind[0].buffer_type = MYSQL_TYPE_LONG;
		bind[0].buffer = &torrentid;
		bind[0].buffer_length = sizeof(torrentid);
		bind[0].is_null = &is_null[0];
		bind[0].error = &stmterror[0];
		if( mysql_stmt_bind_result( stmt, &bind[0] ) ) {
			myexit( mysql_error(db) );
		}

		bind[1].buffer_type =  MYSQL_TYPE_BLOB;
		bind[1].buffer = input_infohash;
		bind[1].buffer_length = 20;
		bind[1].length = &inlen;
		bind[1].is_null = &is_null[1];
		is_null[1] = 0;
		bind[1].error = &stmterror[1];
		if( mysql_stmt_bind_param( stmt, &bind[1] ) ) {
			mysql_stmt_error(stmt);
		}
		prepared = 1;
	}
	memcpy( input_infohash, infohash, 20 );
	if( mysql_stmt_execute(stmt) ) {
		myexit( mysql_stmt_error(stmt) );
	}
	int result = mysql_stmt_fetch(stmt);
	switch ( result ) {
		case 0:
			break;
		case 1:
			torrentid = 0;
			break;
		case MYSQL_NO_DATA:
			torrentid = 0;
			break;
		case MYSQL_DATA_TRUNCATED:
			return 0;
			break;
	}
	mysql_stmt_free_result(stmt);
	return torrentid;
}

unsigned int getTrackerID( MYSQL * db, char *hostname ) {
	unsigned int trackerid = selectTracker( db, hostname );
	if( trackerid == 0 ) {
		trackerid = insertTracker( db, hostname );
	}
	return trackerid;
}

guint hashinfohash( gconstpointer v1 ) {
	char * infohash = (char*)v1;
	return (guint)infohash[0];
}

gboolean infohashequal( gconstpointer v1, gconstpointer v2 ) {
	return memcmp( v1, v2, 20 );
}

unsigned int getTorrentID( MYSQL * db, char *infohash ) {
	unsigned int torrentid = selectTorrent( db, infohash );
	if( torrentid == 0 ) {
		torrentid = insertTorrent( db, infohash );
	}
	return torrentid;
}

void logHandshake( MYSQL *db, unsigned int sip, unsigned int dip, char *infohash ) {
	unsigned int torrentid = getTorrentID( db, infohash );
	insertHandshake( db, torrentid, ntohl(sip), ntohl(dip) );
}

void logAnnounce( MYSQL *db, char *infohash, char *hostname ) {
	unsigned int trackerid = getTrackerID( db, hostname );
	unsigned int torrentid = getTorrentID( db, infohash );
	insertAnnounce( db, trackerid, torrentid );
}

unsigned int readpcap( pcap_t * in, unsigned int prevcount, MYSQL *db ) {
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *packetdata;
	unsigned int curcount = 0;
	CURL *curlobj = curl_easy_init();
	//loop over packets
	while( pcap_next_ex( in, &header, &packetdata ) == 1 ) {
		curcount++;
		if( curcount <= prevcount) {
			continue;
		}
		struct ether_header* eheader = (struct ether_header*)packetdata;
		if( eheader->ether_type =! 0x0008 ) {
			continue;
		}
		struct iphdr* ipheader = (struct iphdr*)(packetdata + sizeof(struct ether_header));
		if( ipheader->version != 4 ) {
			continue;
		}
		if( ipheader->protocol != 6 ) {
			continue;
		}
		int ipHeaderLen = (ipheader->ihl) * 4;
		struct tcphdr* tcpheader = (struct tcphdr*)(packetdata + sizeof(struct ether_header) + ipHeaderLen);
		int tcpHeaderLen = (tcpheader->doff * 4);
		int totalHeaderLen = sizeof(struct ether_header) + ipHeaderLen + tcpHeaderLen;
		const u_char* tcpdata = packetdata + totalHeaderLen;
		int tcpdatalen = header->len - totalHeaderLen;
		if( *tcpdata == 19 ) {
			if( strncmp((char*)tcpdata+1, "BitTorrent protocol", 19) != 0 ) {
				continue;
			}
			//insert to DB
			char *infohash = (char*)tcpdata + 28;
			logHandshake( db, ipheader->saddr, ipheader->daddr, infohash );
		} else if( *tcpdata == 'G' ) {
			char * newline = index(tcpdata, '\r');
			int linelen = (int)newline - (int)tcpdata;
			int outlen;
			char* realurl = curl_easy_unescape(curlobj, tcpdata, linelen, &outlen);
			char* infohashbegin = g_strstr_len( realurl, outlen, "info_hash") + 10;
			char *hostname = g_strstr_len( tcpdata, tcpdatalen, "Host: ") + 6;
			newline = index(hostname, 0x0D);
			*newline = '\0';
			logAnnounce( db, infohashbegin, hostname );
			curl_free(realurl);
		}
	}
	curl_easy_cleanup(curlobj);
	return curcount;
}

MYSQL * initdb ( GKeyFile * conf ) {
	GError *confError = NULL;
	char *host, *user, *passwd, *dbname;
	host = g_key_file_get_string( conf, "database", "host", &confError );
	if( confError != NULL ) {
		myexit( confError->message );
	}
	user = g_key_file_get_string( conf, "database", "user", &confError );
	if( confError != NULL ) {
		myexit( confError->message );
	}
	passwd = g_key_file_get_string( conf, "database", "passwd", &confError );
	if( confError != NULL ) {
		myexit( confError->message );
	}
	dbname = g_key_file_get_string( conf, "database", "dbname", &confError );
	if( confError != NULL ) {
		myexit( confError->message );
	}


	//connect to DB
	if( mysql_library_init(0, NULL, NULL) ) {
		myexit( "Could not init mysql library" );
	}
	MYSQL *db = mysql_init( NULL );
	if( db == NULL ) {
		myexit( "Not enough memory to init MYSQL object" );
	}
	if( !mysql_real_connect( db, host, user, passwd, dbname, 0, NULL, 0 ) ) {
		myexit( mysql_error(db) );
	}
	return db;
}

int main( int argc, char* argv[] ) {
	int status;
	//read config file
	if( argc < 2 ) {
		myexit( "No conf file" );
	}
	GKeyFile *conf = g_key_file_new();
	GError *confError = NULL;
	if( !g_key_file_load_from_file( conf, argv[1], G_KEY_FILE_KEEP_COMMENTS, &confError ) ) {
		myexit( confError->message );
	}

	MYSQL * db = initdb( conf );

	//get list of files
	char *filepattern = g_key_file_get_string( conf, "global", "files", &confError );
	glob_t globbuf;
	status = glob( filepattern, GLOB_TILDE, NULL, &globbuf );
	if( status != 0 ) {
		myexit( "glob failed" );
	}

	//loop over files
	int curfile;
	for( curfile = 0; curfile < globbuf.gl_pathc; curfile++ ) {
		char *filename = globbuf.gl_pathv[curfile];
		char *base = basename(filename);
		//get filepos from conf
		unsigned int prevcount = 0;
		if( g_key_file_has_key( conf, "logs", base, &confError ) ) {
			prevcount = g_key_file_get_integer( conf, "logs", base, &confError );
		}

		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t* in = pcap_open_offline( filename, errbuf );
		unsigned int curcount = readpcap( in, prevcount, db );
		//update filepos in conf
		g_key_file_set_integer( conf, "logs", base, curcount );

	}
	globfree( &globbuf );


	//cleanup
	FILE *confout = fopen( argv[1], "w" );
	fputs( g_key_file_to_data(conf, NULL, NULL), confout );
	fclose(confout);
	g_key_file_free( conf );
	mysql_close( db );
	mysql_library_end();
	return EXIT_SUCCESS;
}
