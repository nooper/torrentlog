#include <stdlib.h>
#include <stdio.h>
#include <mysql/mysql.h>
#include <glib.h>
#include <glob.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

void myexit( const char * msg ) {
	fprintf( stderr, "%s\n", msg );
	exit(EXIT_FAILURE);
}

int main( int argc, char* argv[] ) {
	int status;
	//read config file
	if( argc < 2 ) {
		myexit( "No conf file" );
	}
	GKeyFile *conf = g_key_file_new();
	GError *confError = NULL;
	GKeyFileFlags confFlags = G_KEY_FILE_NONE;
	if( !g_key_file_load_from_file( conf, argv[1], G_KEY_FILE_NONE, &confError ) ) {
		myexit( confError->message );
	}
	char *host, *user, *passwd, *dbname;
	host = g_key_file_get_string( conf, "global", "host", &confError );
	if( confError != NULL ) {
		myexit( confError->message );
	}
	user = g_key_file_get_string( conf, "global", "user", &confError );
	if( confError != NULL ) {
		myexit( confError->message );
	}
	passwd = g_key_file_get_string( conf, "global", "passwd", &confError );
	if( confError != NULL ) {
		myexit( confError->message );
	}
	dbname = g_key_file_get_string( conf, "global", "dbname", &confError );
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
		printf("%s\n", filename);
	}
	globfree( &globbuf );



	//get filepos from DB
	//loop over packets
	//insert to DB
	//update filepos in DB
	//cleanup
	g_key_file_free( conf );
	mysql_close( db );
	mysql_library_end();
	return EXIT_SUCCESS;
}
