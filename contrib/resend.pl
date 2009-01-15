#!/usr/bin/perl
#
# Contributed by Anthony Howe
#

$opt_r = 0;

use Getopt::Std;
getopts('r:sf:vF:');

unless ((defined $opt_f || defined $opt_s) && $opt_r =~ /^\d+$/) {
	print STDERR <<EOT;
Usage
-----
	resend [-v][-F resent-from] -f email mbox...
	resend [-v][-F resent-from][-r level] -s mbox...

Options
-------
-f	Forwards the specified mail-boxes to another email
	address.
	
-F	Resent-From address to use. Default is <postmaster>.

-s	Resend all messages from the specified mail-boxes.

-r	Ignore the first N Received: headers when looking for a
	destination address. If none found, fall back on the 
	To: or X-Original-Recipient: headers.

-v	Verbose

Arguments
---------
mbox	The full path name to the mailbox file(s) to be processed

EOT
	exit 2;
}

if (defined $opt_f && defined $opt_s) {
	print STDERR "forward: cannot use -f and -s together.\n";
	exit 2;
}

$env[LANG]='C';
open(DATE, "date +'%e %b %Y %H:%M %z'|");
$date = <DATE>;
close(DATE);

my $to;
my $skip;
my $count = 0;
my $mailto = \*MAILTO;
my $postmaster = 'postmaster';

my $resent_from = defined $opt_F ? $opt_F : $postmaster;

while (<ARGV>) {
	undef $to;
	undef $for;
	undef $recipients;
	my $received = 0;
	if (/^From (\S+)/) {
		close($mailto);
		undef $skip;

		my ($subject, $to, $recipients);
		my $header = '';
		my $headers = '';

		# Process headers until empty line.
		until (/^$/) {
			chomp;

			# Start of a new header.
			$header = $_;

			# Get next line...
			while (<ARGV>) {
				# ...which is a new header...
				last if /^\S/ || /^$/;

				# ...or is part of the current header.
				chomp;
				s/^\s+/ /;
				$header .= $_;
			}

			next if $header =~ /^From /;

			# Filter extra X- headers, in particular all the
			# X-Spam headers and other X- headers that might
			# re-trigger SPAM rules.
			next if $header !~ /X-Original-Recipient/ && $header =~ /^X-/;

			# And get the subject without a SPAM tag.
			if ($header =~ /^Subject: (?:\[SPAM])?(.*)/i) {
				$subject = $1;
				$headers .= "Subject:$subject\n";
			} elsif ($header =~ /X-Original-Recipient: \<?(.+)\>?/) {
				# Do not add this header to the list of headers.
				$recipients .= "$1 ";
			} else {
				# Add current header to list of headers.
				$headers .= $header . "\n";
			}

			# Get the destination address.
			$from = $1 if $header =~ /^Return-Path: <([^>]*)>/i;
			$to = $1 if $header =~ /^To: (.*)/i;

			if (!defined $for && $header =~ /^Received:/i && $opt_r < ++$received) {
				($for) = ($header =~ /^Received:.+for <(.*)>/i);
			}
		}

		$headers = "Resent-From: \<$resent_from\>\nResent-To: $to\nResent-Date: "
			. $date . $headers
			."X-Mailer: Shell Script\n";

		$skip = 1 and next unless defined $from && defined $to;

		if ($opt_f) {
			open($mailto, "|sendmail -f$from $opt_f");
#$mailto = \*STDOUT;
			print $mailto "To: $opt_f\nSubject: Fw: $subject\n\n";
			print $mailto $headers;
			print $mailto "\n";

			$count++;
			if ($opt_v) {
				print "-- $count --\n";
				print "From: $from\n";
				print "To: $opt_f\n";
				print "Subject: Fw: $subject\n";
			}
		} elsif ($opt_s) {
			# Override destination with more targeted one.
			if (defined $recipients) {
				$to = $recipients;
			} elsif (defined $for) {
				$to = $for;
			}

			open($mailto, "|sendmail -f$from $to");
#$mailto = \*STDOUT;
			print $mailto $headers;
			print $mailto "\n";

			$count++;
			if ($opt_v) {
				print "-- $count --\n";
				print "From: $from\n";
				print "To: $to\n";
				print "Subject: $subject\n";
			}
		}
		next;
	} elsif (/^From /) {
		print $mailto ">", $_;
		next;
	}

	print $mailto $_ unless $skip;
}
close($mailto);

exit(0);
