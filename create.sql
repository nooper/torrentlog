create table trackers (
	trackerid int unsigned auto_increment primary key,
	url varchar(255) unique
);

create table torrents (
	torrentid int unsigned auto_increment primary key,
	infohash binary(20) unique
);

create table announces (
	trackerid int unsigned,
	torrentid int unsigned,
	Unique(trackerid, torrentid)
);

create table handshakes (
	torrentid int unsigned,
	sip int unsigned,
	dip int unsigned,
	peerid binary(20),
	Unique(torrentid, sip, dip, peerid)
);
