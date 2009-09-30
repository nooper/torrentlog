#include <stdlib.h>
#include <stdio.h>
#include <mysql/mysql.h>
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

void myexit( const char * msg ) {
	fprintf( stderr, "%s\n", msg );
	exit(EXIT_FAILURE);
}

void logHandshake( MYSQL *db, unsigned int sip, unsigned int dip, char *infohash ) {
}

void logAnnounce( MYSQL *db, char *infohash, char *hostname ) {
}

unsigned int readpcap( pcap_t * in, unsigned int prevcount, MYSQL *db ) {
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *packetdata;
	unsigned int curcount = 0;
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
		switch ( *tcpdata ) {
			case 0x13:
				if( strncmp((char*)tcpdata+1, "BitTorrent protocol", 19) != 0 ) {
					continue;
				}

				//insert to DB
				printf("%s -> ", inet_ntoa(ipheader->saddr));
				printf("%s      \t", inet_ntoa(ipheader->daddr));
				char *infohash = (char*)tcpdata + 28;
				logHandshake( db, ipheader->saddr, ipheader->daddr, infohash );
				char *peerid = infohash + 20;
				printf("infohash: ");
				int count = 0;
				while(count < 20) {
					printf("%.2hhX", infohash[count++]);
				}
				if( tcpdatalen >= 68 ) {
					printf(" ");
					fwrite(peerid, 8, 1, stdout);
				}
				printf("\n");
				break;

			case 0x47:
				3;
				char * newline = index(tcpdata, '\r');
				int linelen = (int)newline - (int)tcpdata;
				CURL *curlobj = curl_easy_init();
				int outlen;
				char* realurl = curl_easy_unescape(curlobj, tcpdata, linelen, &outlen);
				curl_free(realurl);
				curl_easy_cleanup(curlobj);
				char* infohashbegin = g_strstr_len( realurl, outlen, "info_hash") + 10;
				printf("infohash: ");
				count = 0;
				while(count < 20) {
					printf("%.2hhX", infohashbegin[count++]);
				}
				printf(" ");
				char *hostname = g_strstr_len( tcpdata, tcpdatalen, "Host: ");
				newline = index(hostname, 0x0D);
				linelen = (int)newline - (int)hostname;
				fwrite(hostname, linelen, 1, stdout);
				printf("\n");
				break;
		}
	}
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
