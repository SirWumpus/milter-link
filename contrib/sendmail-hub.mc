divert(-1)
#
# Copyright (c) 1998 Sendmail, Inc.  All rights reserved.
# Copyright (c) 1983 Eric P. Allman.  All rights reserved.
# Copyright (c) 1988, 1993
# The Regents of the University of California.  All rights reserved.
#
# By using this file, you agree to the terms and conditions set
# forth in the LICENSE file which can be found at the top level of
# the sendmail distribution.
#

divert(0)dnl
OSTYPE(linux)dnl

dnl
dnl Enable this for debug output from Sendmail. See Bat Book 3e 24.9.56
dnl

dnl define(`confLOG_LEVEL', `14')

dnl
dnl A web server only need to listen for local mail connections
dnl in order to process sending of forms and web-based mail.
dnl A web server never needs to receive mail.
dnl

DAEMON_OPTIONS(`Family=inet, Name=mta, Port=smtp, Address=127.0.0.1')dnl
dnl DAEMON_OPTIONS(`Family=inet, Name=msp, Port=submission, Addr=127.0.0.1')dnl    

dnl
dnl Disable the Mail Submission Agent (MSA) and just use the
dnl historical setup using the Mail Transfer Agent (MTA) on
dnl port 25.
dnl

FEATURE(`no_default_msa')dnl

dnl 
dnl Disable IDENT support. Few sites support it and the information
dnl cannot be trusted.
dnl

define(`confTO_IDENT', `0s')

dnl
dnl Outgoing mail from a workstation will appear to be from this mail
dnl server or domain.
dnl

dnl MASQUERADE_AS(`snert.example')dnl
dnl FEATURE(`masquerade_envelope')dnl
FEATURE(always_add_domain)dnl

dnl Choice 1.
dnl
dnl Enable this line to forward all local mail to a central hub.
dnl Sets $H macro.  See Bat Book 3e section 4.5.7.
dnl 

dnl define(MAIL_HUB, `relay:hub.snert.example.')dnl

dnl Choice 2.
dnl
dnl Enable this line to forward mail via a gateway.
dnl Sets $S macro. See Bat Book 3e section 4.3.3.6.
dnl

dnl define(SMART_HOST, `relay:gw.snert.example')dnl

dnl Choice 3.
dnl
dnl Enable this line to forward all mail to a central hub or gateway.
dnl Be sure to disable/remove MAILER(`smtp') and MAILER(`local') lines.
dnl Sets both $H and $S macros. See Bat Book 3e section 4.8.33.
dnl

dnl FEATURE(`nullclient', `mx.snert.example')dnl

dnl
dnl For an internal central hub/gateway you want to specify your
dnl network that you are willing to relay mail for. Doing this 
dnl here removes the need for FEATURE(`access') and an access.db
dnl entry, unless you prefer doing it that way.
dnl

RELAY_DOMAIN(`192.168.1')dnl

LOCAL_DOMAIN(`this.host.snert.example')dnl
LOCAL_USER(`root')dnl

dnl
dnl Disable these mailers for FEATURE(`nullclient').
dnl

MAILER(smtp)dnl
MAILER(local)dnl

dnl Choice 4.
dnl 
dnl Similar to using SMART_HOST and FEATURE(`mailertable'), but as
dnl a set of specific rules. See Bat Book 3e section 4.3.3.7 and
dnl 4.8.24.
dnl

dnl LOCAL_NET_CONFIG
dnl R $* <@ $+.> $*	$#relay $@ some.snert.example $: $1 <@ $2 > $3
