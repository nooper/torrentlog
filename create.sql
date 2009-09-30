create table trackers (
	trackerid int unsigned auto_increment primary key,
	url varchar(255) unique
);

create table torrents (
	torrentid int unsigned auto_increment primary key,
	infohash char(20) unique
);

create table announces (
	trackerid int unsigned,
	torrentid int unsigned,
	Unique(trackerid, torrentid)
);

create table handshakes (
	torrentid int unsigned,
	ip int unsigned,
	Unique(torrentid, ip)
);
