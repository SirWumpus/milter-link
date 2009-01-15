Here are working files for POP-b4-SMTP inclusion in the SnertSoft milters.
Below are three software packages that perform the same functionality, 
so the .mc and .m4 have been written to work with all three.  Only one
package is needed.

-------------------------------------------------------------------------
http://mail.cc.umanitoba.ca/drac/ dracd RPC damon, 
This program works by adding hooks into the POP3 and IMAP daemons
that call the RPC DRACd daemon so it can update a database of 
active IP during the login time.  It is nice, since the dracd.db
file is updated during the user login portion of the POP3/IMAP 
transaction so that the sendmail process can see the update immediately.
Ie. race avoidance.

To use you would add the following to the sendmail.mc file, and place the
attached dracd.m4 in the .../sendmail/cf/hack/ directory.

define(`_POPAUTH_')dnl 		 	Turns on POPb4SMTP via IP
define(`_POPAUTH_DB_', `btree /usr/local/etc/dracd')dnl database to read
define(`_X_POPAUTH_INFO_')dnl	 	Sets the sendmail macro
dnl					Allows milter to read the macro
define(`confMILTER_MACROS_ENVRCPT', confMILTER_MACROS_ENVRCPT`, {popauth_info}')dnl
HACK(dracd)

Simple list: 
1) get http://mail.cc.umanitoba.ca/drac/
   make configure 
   set Berkley DB versions for includes & lib  (libsnert hates 1.85)
   make install
2) get qpopper from ftp://ftp.qualcomm.com/eudora/servers/unix/popper/
   compile qpopper with WITH_DRAC=yes and install
3) get imap-uw from ftp://ftp.cac.washington.edu/imap/
   compile imap-uw with WITH_DRAC=yes and install
4) add the above to your sendmail.mc and remake

-------------------------------------------------------------------------

Another POP-b4-SMTP solution that works by screening log entries 
instead of hooking the inbound mail program itself is 
http://www.cynic.net/~cjs/computer/sendmail/poprelay.html
which has moved to http://poprelay.sourceforge.net/.
Easier to install, but can lead to race conditions when SMTP
immediately follows POP3.

The .mc lines above and the dracd.m4 should work to produce the
same results.  I have not tested this.

-------------------------------------------------------------------------

An upgrade to the poprelay program is one that includes the 
username@ip in the database.  The dracd.m4 has options to handle
this.  To use the http://w3.man.torun.pl/~makler/prog/poprelayd/,
you would add the following to the sendmail.mc file and rebuild. 

define(`_POPAUTH_')dnl 		 	Turns on POPb4SMTP via IP
define(`_POPAUTH_USER_')dnl 	 	Turns on POPb4SMTP via user@IP
dnl 					Where to search for valid users	
define(`_LOCALUSER_SEQUENCE_',`passwd alias')dnl 	
define(`_POPAUTH_DB_', `btree /usr/local/etc/dracd')dnl database to read
define(`_X_POPAUTH_INFO_')dnl	 	Sets the sendmail macro
dnl					Allows milter to read the macro
define(`confMILTER_MACROS_ENVRCPT', confMILTER_MACROS_ENVRCPT`, {popauth_info}')dnl
HACK(dracd)

Of course, comments after the dnl's can be removed.  I have only placed 
them there for clarity.  

-Mike Elliott
