#!/usr/bin/perl
#
# Contributed by Anthony Howe
#

use Getopt::Std;
getopts('f:t:');

if (defined($opt_f)) {
	$pattern = "sendmail\\[\\d+\\]: ([^:]+): from=<$opt_f>";
} elsif (defined($opt_t)) {
	$pattern = "sendmail\\[\\d+\\]: ([^:]+): to=<$opt_t>";
} else {
	print STDERR <<EOT;
Usage
-----
	maillog -f email log...
	maillog -t email log...

Options
-------
-f	From envelope pattern to find.
-t	To envelope pattern to find.


Arguments
---------
log	One or more log files to search.

EOT
	exit 2;
}

@ARGV_COPY = ( @ARGV );

my %id = ();

while (<>) {
	if (/$pattern/i) {
		push(@{ $id{$ARGV} }, $1 );
	}
}

# Treat files in command-line order.
for $file (@ARGV_COPY) {
	# Only process files which have a result.
	next unless exists $id{$file};

	next unless open(FILE, $file);

	while (<FILE>) {
		foreach $id (@{ $id{$file} }) {
			if (/$id/) {
				print($_);
				last;
			}
		}
	}

	close(FILE);
}

exit(0);

__END__
