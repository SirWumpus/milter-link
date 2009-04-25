#!/usr/bin/perl
#
# Contributed by Chris M. Miller.
#
# milter-gris / milter-sender cache dump
#

use Fcntl;
use DB_File;

tie %db, 'DB_File', $ARGV[0], O_RDONLY, 0666, $DB_HASH
        or die "Cannot open file $ARGV[0]: $! \n" ;

my %statii = (
	-1 => "UNKNOWN",
	-2 => "GREYTEMP",
	-3 => "GREYCONT",
	0 => "CONTINUE",
	1 => "REJECT",
	2 => "DISCARD",
	3 => "ACCEPT",
	4 => "TEMPFAIL"
);

print
"Last Connected  Status     # Email Key\n".
"--------------- -------- --- -------------------------------------------------\n";

while (($key, $value) = each %db) {
	($stat, $date, $count) = unpack("i8L8L8",$value);
	$dateStr = substr(localtime($date), 4);
	$dkey = substr($key,0,length($key)-1);
	printf("%-16.15s%-9.8s%3i %s\n",$dateStr,$statii{$stat},$count,$dkey);
}

untie %db;

exit 0;
