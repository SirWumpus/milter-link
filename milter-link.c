/*
 * milter-link.c
 *
 * Copyright 2003, 2015 by Anthony Howe. All rights reserved.
 *
 * The following should be added to the sendmail.mc file:
 *
 *	INPUT_MAIL_FILTER(
 *		`milter-link',
 *		`S=unix:/var/run/milter/milter-link.socket, T=C:10s;R:1m;E:5m'
 *	)dnl
 */

/* "milter-link has the most complete and flexible URL lookup feature
 *  set making it the ideal tool to make the most of URIBL.com's data
 *  sets. Its ease of use and rock solid performance has made it an
 *  invaluable tool on our high traffic trap servers."
 *  - URIBL.com Admin Team
 */

/***********************************************************************
 *** Leave this header alone. Its generate from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 *** You can change the stuff below if the configure script doesn't work.
 ***********************************************************************/

#ifndef RUN_AS_USER
#define RUN_AS_USER			"milter"
#endif

#ifndef RUN_AS_GROUP
#define RUN_AS_GROUP			"milter"
#endif

#ifndef MILTER_CF
#define MILTER_CF			"/etc/mail/" MILTER_NAME ".cf"
#endif

#ifndef PID_FILE
#define PID_FILE			"/var/run/milter/" MILTER_NAME ".pid"
#endif

#ifndef SOCKET_FILE
#define SOCKET_FILE			"/var/run/milter/" MILTER_NAME ".socket"
#endif

#ifndef WORK_DIR
#define WORK_DIR			"/var/tmp"
#endif

#ifndef SUBJECT_TAG
#define SUBJECT_TAG			"[SPAM]"
#endif

#ifndef BLACK_LISTED_URL_FORMAT
#define BLACK_LISTED_URL_FORMAT		"black listed URL host %s by %s"	/* 1st URL domain, 2nd list name */
#endif

#ifndef BLACK_LISTED_MAIL_FORMAT
#define BLACK_LISTED_MAIL_FORMAT	"black listed <%s> by %s"		/* 1st mail address, 2nd list name */
#endif

/***********************************************************************
 *** No configuration below this point.
 ***********************************************************************/

/* Re-assert this macro just in case. May cause a compiler warning. */
#define _REENTRANT	1

#include <com/snert/lib/version.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SYS_TYPE_H
# include <sys/types.h>
#endif

#ifdef __sun__
# define _POSIX_PTHREAD_SEMANTICS
#endif
#include <signal.h>

#ifndef __MINGW32__
# if defined(HAVE_SYSLOG_H)
#  include <syslog.h>
# endif
#endif

#ifdef HAVE_SQLITE3_H
# include <sqlite3.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include <com/snert/lib/sys/Time.h>
#include <com/snert/lib/io/socket2.h>
#include <com/snert/lib/mail/limits.h>
#include <com/snert/lib/mail/smf.h>
#include <com/snert/lib/mail/tlds.h>
#include <com/snert/lib/mail/smdb.h>
#include <com/snert/lib/net/dnsList.h>
#include <com/snert/lib/net/network.h>
#include <com/snert/lib/util/Text.h>
#include <com/snert/lib/util/getopt.h>
#include <com/snert/lib/util/uri.h>
#include <com/snert/lib/util/convertDate.h>
#include <com/snert/lib/sys/sysexits.h>

#if LIBSNERT_MAJOR < 1 || LIBSNERT_MINOR < 75
# error "LibSnert 1.75.41 or better is required"
#endif

# define MILTER_STRING	MILTER_NAME "/" MILTER_VERSION

/***********************************************************************
 *** Constants
 ***********************************************************************/

#define	TAG_FORMAT		"%05d %s: "
#define	TAG_ARGS		data->work.cid, data->work.qid

#define X_SCANNED_BY		"X-Scanned-By"
#define X_MILTER_PASS		"X-" MILTER_NAME "-Pass"
#define X_MILTER_REPORT		"X-" MILTER_NAME "-Report"

#define POLICY_UNDEFINED	'\0'
#define POLICY_QUARANTINE	'q'
#define POLICY_DISCARD		'd'
#define POLICY_REJECT		'r'
#define POLICY_TAG		't'

/***********************************************************************
 *** Global Variables
 ***********************************************************************/

static smfInfo milter;

typedef struct {
	smfWork work;
	int policy;				/* per message */
	int hasDate;				/* per message */
	int hasPass;				/* per message */
	int hasReport;				/* per message */
	int hasSubject;				/* per message */
	int stop_uri_scanning;			/* per message */
	int stop_mail_scanning;			/* per message */
	sfsistat uri_found_rc;			/* per message */
	char line[SMTP_TEXT_LINE_LENGTH+1];	/* general purpose */
	char subject[SMTP_TEXT_LINE_LENGTH+1];	/* per message */
	const char *mime_string_name;		/* per string (headers, body) */

	PDQ *pdq;				/* per connection */
	Mime *mime;				/* per connection, reset per message */
	Vector senders;				/* per connection, reset per message */
	Vector recipients;			/* per connection, reset per message */
	Vector ns_tested;			/* per connection, reset per message */
	Vector uri_tested;			/* per connection, reset per message */
	Vector mail_tested;			/* per connection */
	char reply[SMTP_TEXT_LINE_LENGTH+1];	/* per message */
} *workspace;


static const char black_listed_url_format[] = BLACK_LISTED_URL_FORMAT;
static const char black_listed_mail_format[] = BLACK_LISTED_MAIL_FORMAT;

static Option optIntro		= { "",			NULL,			"\n# " MILTER_NAME "/" MILTER_VERSION "\n#\n# " MILTER_COPYRIGHT "\n#\n" };
static Option opt_subject_tag	= { "subject-tag",	SUBJECT_TAG,		"Subject tag for messages identified as spam." };

static const char usage_links_policy[] =
  "Policy to apply if message contains a broken URL found by +test-links.\n"
"# Specify one of none, tag, quarantine, reject, or discard.\n"
"#"
;
static Option opt_links_policy	= { "links-policy",	"tag",			usage_links_policy };

static Option opt_links_test	= { "links-test",	"-",			"Verify HTTP links are valid and find origin server." };

static Option opt_links_timeout	= { "links-timeout",	"60",			"Socket timeout used when testing HTTP links." };

static const char usage_date_required[] =
  "Set to one (1) to require a Date header; two (2) requires the header\n"
"# and that it conform to the RFC 5322 date-time format.  Zero (0) disables\n"
"# the requirement (default).\n"
"#"
;
static Option opt_date_required	= { "date-required",	"0",			usage_date_required };

static const char usage_date_policy[] =
  "Policy applied when date-required fails. Specify one of none, tag,\n"
"# quarantine, reject, or discard.\n"
"#"
;
static Option opt_date_policy	= { "date-policy",	"reject",		usage_date_policy };

static const char usage_domain_bl[] =
  "A list of domain black list suffixes to consult, like .dbl.spamhaus.org.\n"
"# The host or domain name found in a URI is checked against these DNS black\n"
"# lists. These black lists are assumed to use wildcards entries, so only a\n"
"# single lookup is done. IP-as-domain in a URI are ignored. See uri-bl-policy.\n"
"#"
;
static Option opt_domain_bl	= { "domain-bl",	"dbl.spamhaus.org",	usage_domain_bl };

static const char usage_uri_bl[] =
  "A list of domain name black list suffixes to consult, like .multi.surbl.org.\n"
"# The domain name found in a URI is checked against these DNS black lists.\n"
"#"
;
static Option opt_uri_bl	= { "uri-bl",		".multi.surbl.org;.black.uribl.com",	usage_uri_bl };

static const char usage_uri_bl_headers[] =
  "A list of mail headers to parse for URI and check using the uri-bl,\n"
"# uri-a-bl, and uri-ns-bl options. Specify the empty list to disable.\n"
"#"
;
static Option opt_uri_bl_headers = { "uri-bl-headers",	"X-Originating-IP",	usage_uri_bl_headers };

static const char usage_uri_bl_helo[] =
  "Test the HELO/EHLO argument using the uri-bl, uri-a-bl, and uri-ns-bl\n"
"# options. Reject the command if black listed.\n"
"#"
;
static Option opt_uri_bl_helo	= { "uri-bl-helo",	"-",			usage_uri_bl_helo };

static const char usage_uri_max_test[] =
  "Maximum number of unique URI to check. Specify zero for unlimited."
;
Option opt_uri_max_test		= { "uri-max-test",	"0",			usage_uri_max_test };

static const char usage_uri_bl_sub_domains[] =
  "When querying against name based black lists, like .multi.surbl.org\n"
"# or .black.uribl.com, first test the registered domain, then any \n"
"# sub-domains from right-to-left. Typically sub-domains are not listed.\n"
"#"
;
static Option opt_uri_bl_sub_domains = { "uri-bl-sub-domains", "-",		usage_uri_bl_sub_domains };

static const char usage_uri_a_bl[] =
  "A list of IP black list suffixes to consult, like zen.spamhaus.org.\n"
"# The host or domain name found in a URI is used to find its DNS A record\n"
"# and IP address, which is then checked against these IP DNS black lists.\n"
"#"
;
static Option opt_uri_a_bl	= { "uri-a-bl",		"",			usage_uri_a_bl };

static const char usage_uri_ns_bl[] =
  "A list of host name and/or domain name black list suffixes to consult. The\n"
"# domain name found in a URI is used to find its DNS NS records; the NS host\n"
"# names are checked against these host name and/or domain name DNS black\n"
"# lists.\n"
"#"
;
static Option opt_uri_ns_bl	= { "uri-ns-bl",	"",			usage_uri_ns_bl };

static const char usage_uri_ns_a_bl[] =
  "A comma or semi-colon separated list of IP black list suffixes to consult.\n"
"# The host or domain name found in a URI is used to find its DNS NS records\n"
"# and IP address, which are then checked against these IP black lists.\n"
"#"
;
static Option opt_uri_ns_a_bl	= { "uri-ns-a-bl",	"",			usage_uri_ns_a_bl };

static const char usage_uri_bl_policy[] =
  "Policy to apply if message contains a black listed URI found by uri-bl,\n"
"# uri-a-bl, uri-ns-bl. Specify one of none, tag, quarantine, reject, or\n"
"# discard.\n"
"#"
;
static Option opt_uri_bl_policy	= { "uri-bl-policy",	"reject",		usage_uri_bl_policy };

static const char usage_mail_bl[] =
  "A list of mail address black list suffixes to consult. The MAIL FROM:\n"
"# address and mail addresses found in select headers and the message are MD5\n"
"# hashed, which are then checked against these black lists.\n"
"# "
;
Option opt_mail_bl		= { "mail-bl",		"",			usage_mail_bl };

static const char usage_mail_bl_headers[] =
  "A list of mail headers to parse for mail addresses and check against\n"
"# one or more mail address black lists. Specify the empty list to disable.\n"
"#"
;
Option opt_mail_bl_headers	= { "mail-bl-headers",	"From;Reply-To;Sender",	usage_mail_bl_headers };

static const char usage_mail_bl_max[] =
  "Maximum number of unique mail addresses to check. Specify zero for\n"
"# unlimited.\n"
"#"
;
Option opt_mail_bl_max		= { "mail-bl-max",	"10",			usage_mail_bl_max };

static const char usage_mail_bl_policy[] =
  "Check if the message contains a black listed mail address found by\n"
"# mail-bl.  Specify one of none, tag, quarantine, reject, or discard.\n"
"#"
;
Option opt_mail_bl_policy	= { "mail-bl-policy",	"reject",		usage_mail_bl_policy };

static const char usage_mail_bl_domains[] =
  "A list of domain glob-like patterns for which to test against mail-bl,\n"
"# typically free mail services. This reduces the load on public BLs.\n"
"# Specify * to test all domains, empty list to disable.\n"
"#"
;
Option opt_mail_bl_domains	= {
	"mail-bl-domains",

	 "gmail.*"
	";hotmail.*"
	";live.*"
	";yahoo.*"
	";aol.*"
	";aim.com"
	";cantv.net"
	";centrum.cz"
	";centrum.sk"
	";googlemail.com"
	";gmx.*"
	";inmail24.com"
	";jmail.co.za"
	";libero.it"
	";luckymail.com"
	";mail2world.com"
	";msn.com"
	";rediff.com"
	";rediffmail.com"
	";rocketmail.com"
	";she.com"
	";shuf.com"
	";sify.com"
	";terra.com"
	";tiscali.it"
	";tom.com"
	";virgilio.it"
	";voila.fr"
	";vsnl.*"
	";walla.com"
	";wanadoo.*"
	";windowslive.com"
	";y7mail.com"
	";yeah.net"
	";ymail.com"

	, usage_mail_bl_domains
};

static const char usage_uri_bl_port_list[] =
  "A list of port numbers corresponding to protocols to test. Some sites\n"
"# prefer to focus on web and/or email related URI. This option provides\n"
"# a means to restrict the scope of testing to a specific subset of URI\n"
"# by port number. An empty list means all URI are tested.\n"
"#"
;
static Option opt_uri_bl_port_list = { "uri-bl-port-list",	"",		usage_uri_bl_port_list };

Option opt_version		= { "version",			NULL,		"Show version and copyright." };

static const char usage_info[] =
  "Write the configuration and compile time options to standard output\n"
"# and exit.\n"
"#"
;
Option opt_info			= { "info", 			NULL,		usage_info };

static const char usage_access_check_headers[] =
  "When enabled, this option will perform extra access-db lookups\n"
"# with the Sender, From, To, and Cc headers using milter-link-from:\n"
"# milter-link-to:, and combo tags, as described by access-db. This\n"
"# allows special B/W list configurations.\n"
"#"
;
Option opt_access_check_headers	= { "access-check-headers",	"-",		usage_access_check_headers };

static const char usage_access_check_body[] =
  "When enabled, this option will perform supplemental milter-link-body\n"
"# combo tag lookups for each URI, IP, domain, or mail address found in\n"
"# the message body. This allows special B/W list configurations.\n"
"#"
;
Option opt_access_check_body	= { "access-check-body",	"-",		usage_access_check_body };


#ifdef DROPPED_ADD_HEADERS
static Option optAddHeaders	= { "add-headers",	"-",			"Add extra informational headers when message passes." };
#endif

static Option *optTable[] = {
	&optIntro,
	&opt_access_check_headers,
	&opt_access_check_body,
#ifdef DROPPED_ADD_HEADERS
	&optAddHeaders,
#endif
	&opt_date_policy,
	&opt_date_required,
	DNS_LIST_OPTIONS_TABLE,
	PDQ_OPTIONS_TABLE,
	&opt_domain_bl,
	&opt_info,
	&opt_mail_bl,
	&opt_mail_bl_domains,
	&opt_mail_bl_headers,
	&opt_mail_bl_max,
	&opt_mail_bl_policy,
	&opt_links_policy,
	&opt_links_test,
	&opt_links_timeout,
	&opt_subject_tag,
	&opt_uri_a_bl,
	&opt_uri_bl,
	&opt_uri_bl_headers,
	&opt_uri_bl_helo,
	&opt_uri_bl_policy,
	&opt_uri_bl_port_list,
	&opt_uri_bl_sub_domains,
	&opt_uri_max_test,
	&opt_uri_ns_bl,
	&opt_uri_ns_a_bl,
	&opt_version,
	NULL
};

/***********************************************************************
 *** Stats
 ***********************************************************************/

typedef struct {
	const char *name;
	unsigned long count;
} Stat;

static pthread_mutex_t stat_mutex;

#define STAT_DECLARE(name)	\
static const char stat_name_##name[] = #name; \
static Stat stat_##name = { stat_name_##name }

#define STAT_POINTER(name)	&stat_##name

STAT_DECLARE(start_time);
#ifdef HAVE_SMFI_VERSION
STAT_DECLARE(run_time);
#endif
STAT_DECLARE(connect_active);
STAT_DECLARE(connect_total);
STAT_DECLARE(connect_error);
STAT_DECLARE(transactions);
STAT_DECLARE(access_bl);
STAT_DECLARE(access_wl);
STAT_DECLARE(access_other);
STAT_DECLARE(helo_fail);
STAT_DECLARE(link_fail);
STAT_DECLARE(mail_fail);
STAT_DECLARE(origin_fail);
STAT_DECLARE(uri_fail);
STAT_DECLARE(tag);
STAT_DECLARE(error);
STAT_DECLARE(reject);
STAT_DECLARE(discard);
STAT_DECLARE(tempfail);
#ifdef HAVE_SMFI_QUARANTINE
STAT_DECLARE(quarantine);
#endif

#define SMF_MAX_MULTILINE_REPLY		32

#ifdef HAVE_SMFI_VERSION
static Stat *stat_table[SMF_MAX_MULTILINE_REPLY] = {
	&stat_start_time,
	&stat_run_time,
	&stat_connect_active,
	&stat_connect_total,
	&stat_connect_error,
	&stat_transactions,
	&stat_tag,
	&stat_error,
	&stat_reject,
	&stat_discard,
	&stat_tempfail,
#ifdef HAVE_SMFI_QUARANTINE
	&stat_quarantine,
#endif
	&stat_access_bl,
	&stat_access_wl,
	&stat_access_other,
	&stat_link_fail,
	&stat_helo_fail,
	&stat_mail_fail,
	&stat_origin_fail,
	&stat_uri_fail,
	NULL
};
#endif /* HAVE_SMFI_VERSION */

void
statInit(void)
{
	(void) pthread_mutex_init(&stat_mutex, NULL);
	(void) time((time_t *) &stat_start_time.count);
}

void
statFini(void)
{
	(void) pthreadMutexDestroy(&stat_mutex);
}

void
statGet(Stat *stat, Stat *out)
{
	if (!pthread_mutex_lock(&stat_mutex)) {
		*out = *stat;
		(void) pthread_mutex_unlock(&stat_mutex);
	} else {
		(void) memset(out, 0, sizeof (*out));
	}
}

void
statSetValue(Stat *stat, unsigned long value)
{
	if (!pthread_mutex_lock(&stat_mutex)) {
		stat->count = value;
		(void) pthread_mutex_unlock(&stat_mutex);
	}
}

void
statAddValue(Stat *stat, long value)
{
	if (!pthread_mutex_lock(&stat_mutex)) {
		stat->count += value;
		(void) pthread_mutex_unlock(&stat_mutex);
	}
}

void
statCount(Stat *stat)
{
	statAddValue(stat, 1);
}

/***********************************************************************
 ***
 ***********************************************************************/

DnsList *d_bl_list;
DnsList *ip_bl_list;
DnsList *ns_bl_list;
DnsList *ns_ip_bl_list;
DnsList *uri_bl_list;
DnsList *mail_bl_list;
Vector uri_bl_headers;
Vector mail_bl_headers;
Vector mail_bl_domains;
Vector port_list;
long *ports;

static sfsistat
testMail(workspace data, const char *mail)
{
	sfsistat rc;
	const char *list_name;

	rc = SMFIS_CONTINUE;

	if (data->policy != POLICY_UNDEFINED)
		return SMFIS_CONTINUE;

	if (0 < opt_mail_bl_max.value
	&& opt_mail_bl_max.value <= VectorLength(data->mail_tested)) {
		if (!data->stop_mail_scanning)
			smfLog(SMF_LOG_INFO, TAG_FORMAT "mail-bl-max reached", TAG_ARGS);
		data->stop_mail_scanning = 1;
		return SMFIS_CONTINUE;
	}

	if ((list_name = dnsListQueryMail(mail_bl_list, data->pdq, mail_bl_domains, data->mail_tested, mail)) != NULL) {
		(void) snprintf(data->reply, sizeof (data->reply), black_listed_mail_format, mail, list_name);
		dnsListLog(data->work.qid, mail, list_name);
		data->policy = *opt_mail_bl_policy.string;
		rc = data->policy == POLICY_REJECT ? SMFIS_REJECT : SMFIS_CONTINUE;
		statCount(&stat_mail_fail);
	}

	smfLog(SMF_LOG_DEBUG, TAG_FORMAT "testMail(%lx, \"%s\") rc=%d policy=%x reply='%s'", TAG_ARGS, (long) data, mail, rc, data->policy, data->reply);

	return rc;
}

static sfsistat
testMailUri(workspace data, URI *uri)
{
	return testMail(data, uri->uriDecoded);
}

void
mime_test_mail_uri(URI *uri, void *_data)
{
	workspace data = _data;
	data->uri_found_rc = testMailUri(data, uri);
}

static sfsistat
access_mail(workspace data, const char *value, long parseFlags)
{
	smdb_code access;

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "%s(%p, %s, 0x%lx)", TAG_ARGS, __func__, data, TextNull(value), parseFlags);

	access = smfAccessMail2(&data->work, MILTER_NAME "-from:", value, parseFlags, SMDB_ACCESS_UNKNOWN);

	switch (access) {
	case SMDB_ACCESS_ERROR:
	case SMDB_ACCESS_REJECT:
		data->policy = POLICY_REJECT;
		statCount(&stat_access_bl);
		(void) TextCopy(data->reply, sizeof (data->reply), "sender blocked");
		return smfReply(&data->work, 550, "5.7.1", data->reply);

	case SMDB_ACCESS_TEMPFAIL:
		data->policy = POLICY_TAG;
		statCount(&stat_tempfail);
		(void) TextCopy(data->reply, sizeof (data->reply), "sender blocked");
		return smfReply(&data->work, 450, "4.7.1", data->reply);

	case SMDB_ACCESS_DISCARD:
		data->policy = POLICY_DISCARD;
		statCount(&stat_discard);
		smfLog(SMF_LOG_INFO, TAG_FORMAT "sender %s discard", TAG_ARGS, value);
		return SMFIS_DISCARD;

	case SMDB_ACCESS_OK:
		data->work.skipMessage = 1;
		smfLog(SMF_LOG_INFO, TAG_FORMAT "sender %s white listed", TAG_ARGS, value);
		statCount(&stat_access_wl);
		return SMFIS_ACCEPT;

	default:
		statCount(&stat_access_other);
		smfLog(SMF_LOG_DEBUG, TAG_FORMAT "sender %s unknown access value", TAG_ARGS, value);
		break;
	}

	return SMFIS_CONTINUE;
}

static sfsistat
access_rcpt(workspace data, const char *value, long parseFlags)
{
	smdb_code access;

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "%s(%p, %s, 0x%lX)", TAG_ARGS, __func__, data, TextNull(value), parseFlags);

	access = smfAccessRcpt2(&data->work, MILTER_NAME "-to:", value, parseFlags);

	switch (access) {
	case SMDB_ACCESS_ERROR:
	case SMDB_ACCESS_REJECT:
		data->policy = POLICY_REJECT;
		statCount(&stat_access_bl);
		(void) TextCopy(data->reply, sizeof (data->reply), "blocked");
		return smfReply(&data->work, 550, "5.7.1", "recipient blocked");

	case SMDB_ACCESS_TEMPFAIL:
		data->policy = POLICY_TAG;
		statCount(&stat_tempfail);
		(void) TextCopy(data->reply, sizeof (data->reply), "blocked");
		return smfReply(&data->work, 450, "4.7.1", "recipient blocked");

	case SMDB_ACCESS_DISCARD:
		data->policy = POLICY_DISCARD;
		statCount(&stat_discard);
		smfLog(SMF_LOG_INFO, TAG_FORMAT "recipient %s discard", TAG_ARGS, value);
		return SMFIS_DISCARD;

	case SMDB_ACCESS_OK:
		data->work.skipMessage = 1;
		statCount(&stat_access_wl);
		smfLog(SMF_LOG_INFO, TAG_FORMAT "recipient %s white listed", TAG_ARGS, value);
		return SMFIS_ACCEPT;

	default:
		smfLog(SMF_LOG_DEBUG, TAG_FORMAT "recipient %s unknown access value", TAG_ARGS, value);
		statCount(&stat_access_other);
		break;
	}

	return SMFIS_CONTINUE;
}

static sfsistat
access_body_combo(workspace data, const char *ip, const char *host, const char *tag, const char *mail)
{
	char *copy;
	const char *uri;
	smdb_code access;

	smfLog(
		SMF_LOG_TRACE, TAG_FORMAT "%s(%p, %s, %s, %s, %s)", TAG_ARGS,
		__func__, data, TextNull(ip), TextNull(host), tag, mail
	);

	if (ip != NULL) {
		uri = ip;
		access = smdbIpMail(smdbAccess, MILTER_NAME "-body:", ip, tag, mail, NULL, NULL);
	} else if (host != NULL) {
		uri = host;
		access = smdbDomainMail(smdbAccess, MILTER_NAME "-body:", host, tag, mail, NULL, NULL);
	} else {
		return SMFIS_CONTINUE;
	}

	switch (access) {
	case SMDB_ACCESS_OK:
		smfLog(SMF_LOG_INFO, TAG_FORMAT "URI \"%s\" ignored", TAG_ARGS, uri);
		/* Only mark as seen ignored URI from combo tags so as
		 * not to retest the URI by the simple milter-link-body:
		 * tag.  The message is not white listed, only that URI
		 *(host/domian) is white listed/ignored.
		 */
		if ((copy = strdup(uri)) != NULL && VectorAdd(data->uri_tested, copy))
			free(copy);
		/* Accept here does not accept message, simply indicates
		 * we found an entry and can stop further combo lookups.
		 */
		return SMFIS_ACCEPT;

	case SMDB_ACCESS_REJECT:
		(void) snprintf(data->reply, sizeof (data->reply), "URI \"%s\" blocked", uri);
		data->policy = POLICY_REJECT;
		return SMFIS_REJECT;

	case SMDB_ACCESS_DISCARD:
		(void) snprintf(data->reply, sizeof (data->reply), "discarded for URI \"%s\"", uri);
		data->policy = POLICY_DISCARD;
		return SMFIS_DISCARD;

	case SMDB_ACCESS_TEMPFAIL:
		data->policy = POLICY_TAG;
		break;
		
	default:
		smfLog(SMF_LOG_DEBUG, TAG_FORMAT "URI \"%s\" unknown access value", TAG_ARGS, uri);
		break;
	}

	return SMFIS_CONTINUE;
}

void
mime_collect_headers_mail(URI *uri, void *_data)
{
	char *copy;
	workspace data = _data;

	smfLog(
		SMF_LOG_TRACE, TAG_FORMAT "%s(\"%s\", %p)",
		TAG_ARGS, __func__, uri->uriDecoded, _data
	);

	if ((copy = strdup(uri->uriDecoded)) != NULL && VectorAdd(data->senders, copy))
		free(copy);
}

void
mime_collect_headers_rcpt(URI *uri, void *_data)
{
	char *copy;
	workspace data = _data;

	smfLog(
		SMF_LOG_TRACE, TAG_FORMAT "%s(\"%s\", %p)",
		TAG_ARGS, __func__, uri->uriDecoded, _data
	);

	if ((copy = strdup(uri->uriDecoded)) != NULL && VectorAdd(data->recipients, copy))
		free(copy);
}

static sfsistat
testString(workspace data, const char *name, const char *value, UriMimeHook test_fn)
{
	Mime *mime;
	UriMime *uri_mime;

	smfLog(
		SMF_LOG_TRACE, TAG_FORMAT "%s(%p, '%s', '%s', %p)",
		TAG_ARGS, __func__, data, TextNull(name), TextNull(value), test_fn
	);

	if (name == NULL || value == NULL)
		return SMFIS_CONTINUE;

	if ((mime = mimeCreate()) == NULL)
		return SMFIS_CONTINUE;

	if ((uri_mime = uriMimeInit(test_fn, 1, data)) == NULL) {
		free(mime);
		return SMFIS_CONTINUE;
	}

	data->mime_string_name = name;
	mimeHooksAdd(mime, (MimeHooks *) uri_mime);
	mimeHeadersFirst(mime, 0);

	for ( ; data->uri_found_rc == SMFIS_CONTINUE && *value != '\0'; value++) {
		if (mimeNextCh(mime, *value))
			break;
	}
	(void) mimeNextCh(mime, EOF);

	mimeFree(mime);

	return data->uri_found_rc;
}

static sfsistat
testURI(workspace data, URI *uri)
{
	long i;
	const char *error;
	URI *origin = NULL;
	char *host, *ip, *copy;
	const char *list_name = NULL;
	sfsistat rc = SMFIS_REJECT;
	smdb_code access;

	if (uri == NULL || uri->host == NULL)
		return SMFIS_CONTINUE;

	if (ports != NULL) {
		long *p;
		for (p = ports; 0 <= *p; p++) {
			if (uriGetSchemePort(uri) == *p)
				break;
		}

		if (*p < 0)
			return SMFIS_CONTINUE;
	}

	if (0 < opt_uri_max_test.value
	&& opt_uri_max_test.value <= VectorLength(data->uri_tested)) {
		if (!data->stop_uri_scanning)
			smfLog(SMF_LOG_INFO, TAG_FORMAT "uri-max-test reached", TAG_ARGS);
		data->stop_uri_scanning = 1;
		return SMFIS_CONTINUE;
	}

	/* Session cache for previously PASSED hosts/domains. */
	for (i = 0; i < VectorLength(data->uri_tested); i++) {
		if ((host = VectorGet(data->uri_tested, i)) == NULL)
			continue;

		if (TextInsensitiveCompare(uri->host, host) == 0)
			return SMFIS_CONTINUE;
	}

	/* Be sure to apply the correct access lookup. */
	if (0 < spanIP((unsigned char *) uri->host)) {
		ip = uri->host;
		host = NULL;
	} else {
		ip = NULL;
		host = uri->host;
	}

	if (opt_access_check_body.value) {
		ParsePath *saved_mail;
		const char **table, **sender;

		for (table = (const char **) VectorBase(data->senders); *table != NULL; table++) {
			if (access_body_combo(data, ip, host, ":from:", *table) != SMFIS_CONTINUE)
				goto error0;
		}

		saved_mail = data->work.mail;
		for (sender = (const char **) VectorBase(data->senders); *sender != NULL; sender++) {
			ParsePath *path;
			if ((error = parsePath(*sender, 0, 0, &path)) != NULL) {
				/* Sender parse errors found in the headers
				 * will have already been reported during
				 * filterEndHeaders().
				 */
				smfLog(LOG_DEBUG, TAG_FORMAT "sender %s parse error: %s", TAG_ARGS, *sender, error);
				continue;
			}
			data->work.mail = path;
			for (table = (const char **) VectorBase(data->recipients); *table != NULL; table++) {
				if (access_body_combo(data, ip, host, ":to:", *table) != SMFIS_CONTINUE)
					goto error0;
			}
			free(path);
		}
		data->work.mail = saved_mail;
	}

	/* Simply single tag. */
	access = smfAccessClient(&data->work, MILTER_NAME "-body:", host, ip, NULL, NULL);
	switch (access) {
	case SMDB_ACCESS_OK:
		smfLog(SMF_LOG_INFO, TAG_FORMAT "URI \"%s\" ignored", TAG_ARGS, uri->uri);
		return SMFIS_CONTINUE;

	case SMDB_ACCESS_REJECT:
		(void) snprintf(data->reply, sizeof (data->reply), "rejected URL host %s", uri->host);
		data->policy = POLICY_REJECT;
		rc = SMFIS_REJECT;
		goto error0;

	case SMDB_ACCESS_DISCARD:
		(void) snprintf(data->reply, sizeof (data->reply), "discarded for \"%s\"", uri->uri);
		data->policy = POLICY_DISCARD;
		rc = SMFIS_DISCARD;
		goto error0;

	default:
		smfLog(SMF_LOG_DEBUG, TAG_FORMAT "URI \"%s\" unknown access value", TAG_ARGS, uri->uri);
		break;
	}

	if ((copy = strdup(uri->host)) != NULL && VectorAdd(data->uri_tested, copy))
		free(copy);

	if ((list_name = dnsListQueryName(d_bl_list, data->pdq, NULL, uri->host)) != NULL
	||  (list_name = dnsListQueryDomain(uri_bl_list, data->pdq, NULL, opt_uri_bl_sub_domains.value, uri->host)) != NULL
	||  (list_name = dnsListQueryNs(ns_bl_list, ns_ip_bl_list, data->pdq, data->ns_tested, uri->host)) != NULL
	||  (list_name = dnsListQueryIP(ip_bl_list, data->pdq, NULL, uri->host)) != NULL) {
		(void) snprintf(data->reply, sizeof (data->reply), black_listed_url_format, uri->host, list_name);
		dnsListLog(data->work.qid, uri->host, list_name);
		data->policy = *opt_uri_bl_policy.string;
		statCount(&stat_uri_fail);
		goto error0;
	}

	dnsListLog(data->work.qid, uri->host, NULL);

	/* Test and follow redirections so verify that the link returns something valid. */
	if (opt_links_test.value && (error = uriHttpOrigin(uri->uri, &origin)) == uriErrorLoop) {
		(void) snprintf(data->reply, sizeof (data->reply), "broken URL \"%s\": %s", uri->uri, error);
		data->policy = *opt_links_policy.string;
		statCount(&stat_link_fail);
		goto error0;
	}

	if (origin != NULL && origin->host != NULL && strcmp(uri->host, origin->host) != 0) {
		if ((list_name = dnsListQueryName(d_bl_list, data->pdq, NULL, origin->host)) != NULL
		||  (list_name = dnsListQueryDomain(uri_bl_list, data->pdq, NULL, opt_uri_bl_sub_domains.value, origin->host)) != NULL
		||  (list_name = dnsListQueryNs(ns_bl_list, ns_ip_bl_list, data->pdq, data->ns_tested, origin->host)) != NULL
		||  (list_name = dnsListQueryIP(ip_bl_list, data->pdq, NULL, origin->host)) != NULL) {
			(void) snprintf(data->reply, sizeof (data->reply), black_listed_url_format, origin->host, list_name);
			dnsListLog(data->work.qid, origin->host, list_name);
			data->policy = *opt_uri_bl_policy.string;
			statCount(&stat_origin_fail);
			goto error1;
		}

		if ((copy = strdup(origin->host)) != NULL && VectorAdd(data->uri_tested, copy))
			free(copy);

		dnsListLog(data->work.qid, origin->host, NULL);
	}

	rc = SMFIS_CONTINUE;
error1:
	free(origin);
error0:
	smfLog(SMF_LOG_DEBUG, TAG_FORMAT "testURI(%lx, \"%s\") rc=%d reply='%s'", TAG_ARGS, (long) data, uri->uri, rc, data->reply);

	return rc;
}

void
mime_test_uri(URI *uri, void *_data)
{
	workspace data = _data;
	data->uri_found_rc = testURI(data, uri);
}

static sfsistat
testList(workspace data, char *query, const char *delim)
{
	URI *uri;
	int i, rc;
	Vector args;
	char *arg, *ptr;

	if (query == NULL)
		return SMFIS_CONTINUE;

	args = TextSplit(query, delim, 0);

	for (rc = i = 0; rc == 0 && i < VectorLength(args); i++) {
		if ((arg = VectorGet(args, i)) == NULL)
			continue;

		/* Skip leading symbol name and equals sign. */
		for (ptr = arg; *ptr != '\0'; ptr++) {
			if (!isalnum(*ptr) && *ptr != '_') {
				if (*ptr == '=')
					arg = ptr+1;
				break;
			}
		}

		/* Consider current URL trend for shorter strings using
		 * single dot domains, eg. http://twitter.com/
		 */
		uri = uriParse2(arg, -1, 1);
		rc = testURI(data, uri);
		free(uri);
	}

	VectorDestroy(args);

	return rc;
}

void
process_uri(URI *uri, void *_data)
{
	sfsistat rc;
	workspace data = _data;

	smfLog(SMF_LOG_DIALOG, TAG_FORMAT "checking uri=%s", TAG_ARGS, TextNull(uri->host));

	if ((rc = testURI(data, uri)) == SMFIS_CONTINUE) {
		if (uri->query == NULL)
			rc = testList(data, uri->path, "&");
		else if ((rc = testList(data, uri->query, "&")) == SMFIS_CONTINUE)
			rc = testList(data, uri->query, "/");
		if (rc == SMFIS_CONTINUE)
			rc = testList(data, uri->path, "/");
	}

	if (rc == SMFIS_CONTINUE && uriGetSchemePort(uri) == SMTP_PORT) {
		rc = testMail(data, uri->uriDecoded);
	}

	data->uri_found_rc = rc;
}

/***********************************************************************
 *** Handlers
 ***********************************************************************/

/*
 * Open and allocate per-connection resources.
 */
static sfsistat
filterOpen(SMFICTX *ctx, char *client_name, _SOCK_ADDR *raw_client_addr)
{
	workspace data;
	smdb_code access;
	UriMime *uri_mime;

	statCount(&stat_connect_total);

	if (raw_client_addr == NULL) {
		smfLog(SMF_LOG_TRACE, "filterOpen() got NULL socket address, accepting connection");
		goto error0;
	}

	if (raw_client_addr->sa_family != AF_INET
#ifdef HAVE_STRUCT_SOCKADDR_IN6
	&& raw_client_addr->sa_family != AF_INET6
#endif
	) {
		smfLog(SMF_LOG_TRACE, "filterOpen() unsupported socket address type, accepting connection");
		goto error0;
	}

	if ((data = calloc(1, sizeof *data)) == NULL)
		goto error0;

	smfProlog(&data->work, ctx, client_name, raw_client_addr);
	data->work.info = &milter;

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterOpen(%lx, '%s', [%s])", TAG_ARGS, (long) ctx, data->work.client_name, data->work.client_addr);

	if ((data->pdq = pdqOpen()) == NULL)
		goto error1;

	/* Currently we ignore URI found in headers. This might change
	 * based on demand (see uri CLI and BarricadeMX which support
	 * testing URI foundin headers).
	 */
	if ((data->mime = mimeCreate()) == NULL)
		goto error2;

	if ((uri_mime = uriMimeInit(process_uri, 0, data)) == NULL)
		goto error3;
	mimeHooksAdd(data->mime, (MimeHooks *) uri_mime);

	if ((data->uri_tested = VectorCreate(10)) == NULL)
		goto error3;
	VectorSetDestroyEntry(data->uri_tested, free);

	if ((data->ns_tested = VectorCreate(10)) == NULL)
		goto error4;
	VectorSetDestroyEntry(data->ns_tested, free);

	if ((data->mail_tested = VectorCreate(10)) == NULL)
		goto error5;
	VectorSetDestroyEntry(data->mail_tested, free);

	if ((data->senders = VectorCreate(3)) == NULL)
		goto error6;
	VectorSetDestroyEntry(data->senders, free);

	if ((data->recipients = VectorCreate(10)) == NULL)
		goto error7;
	VectorSetDestroyEntry(data->recipients, free);

	if (smfi_setpriv(ctx, (void *) data) == MI_FAILURE) {
		syslog(LOG_ERR, TAG_FORMAT "failed to save workspace", TAG_ARGS);
		goto error8;
	}

	access = smfAccessHost(&data->work, MILTER_NAME "-connect:", client_name, data->work.client_addr, SMDB_ACCESS_OK);

	switch (access) {
	case SMDB_ACCESS_ERROR:
		statCount(&stat_error);
		return SMFIS_REJECT;

	case SMDB_ACCESS_REJECT:
		/* Report this mail error ourselves, because sendmail/milter API
		 * fails to report xxfi_connect handler rejections.
		 */
		statCount(&stat_access_bl);
		smfLog(SMF_LOG_ERROR, TAG_FORMAT "client %s [%s] blocked", TAG_ARGS, client_name, data->work.client_addr);
		return smfReply(&data->work, 550, "5.7.1", "connection %s [%s] blocked", client_name, data->work.client_addr);

	case SMDB_ACCESS_OK:
		statCount(&stat_access_wl);
		statAddValue(&stat_connect_active, 1);
		smfLog(SMF_LOG_INFO, TAG_FORMAT "client %s [%s] white listed", TAG_ARGS, client_name, data->work.client_addr);
		data->work.skipConnection = 1;

		/* Don't use SMFIS_ACCEPT, otherwise we can't do STAT
		 * from localhost.
		 */
		return SMFIS_CONTINUE;

	case SMDB_ACCESS_TEMPFAIL:
		statCount(&stat_tempfail);
		smfLog(SMF_LOG_ERROR, TAG_FORMAT "client %s [%s] temp.failed", TAG_ARGS, client_name, data->work.client_addr);
		return smfReply(&data->work, 450, "4.7.1", "connection %s [%s] blocked", client_name, data->work.client_addr);

	case SMDB_ACCESS_DISCARD:
		smfLog(SMF_LOG_INFO, TAG_FORMAT "client %s [%s] discard", TAG_ARGS, client_name, data->work.client_addr);
		statCount(&stat_discard);
		return SMFIS_DISCARD;

	default:
		smfLog(SMF_LOG_DEBUG, TAG_FORMAT "client %s [%s] unknown access value", TAG_ARGS, client_name, data->work.client_addr);
		statCount(&stat_access_other);
		break;
	}

	statAddValue(&stat_connect_active, 1);

	return SMFIS_CONTINUE;
error8:
	VectorDestroy(data->recipients);
error7:
	VectorDestroy(data->senders);
error6:
	VectorDestroy(data->mail_tested);
error5:
	VectorDestroy(data->ns_tested);
error4:
	VectorDestroy(data->uri_tested);
error3:
	mimeFree(data->mime);
error2:
	pdqClose(data->pdq);
error1:
	free(data);
error0:
	statCount(&stat_connect_error);

	return SMFIS_ACCEPT;
}

static sfsistat
filterHelo(SMFICTX * ctx, char *helohost)
{
	workspace data;
	smdb_code access;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterHelo");

	/* Reset this again. A HELO/EHLO is treated like a RSET command,
	 * which means we arrive here after the connection but also after
	 * MAIL or RCPT, in which case $i (data->work.qid) is invalid.
	 * This could be handled in filterAbort(), but most of my milters
	 * don't use filterAbort().
	 */
	data->work.qid = smfNoQueue;

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterHelo(%lx, '%s')", TAG_ARGS, (long) ctx, TextNull(helohost));

	access = smfAccessClient(&data->work, MILTER_NAME "-helo:", helohost, NULL, NULL, NULL);
	switch (access) {
	case SMDB_ACCESS_ERROR:
		statCount(&stat_error);
		return SMFIS_REJECT;

	case SMDB_ACCESS_REJECT:
		/* Report this mail error ourselves, because sendmail/milter API
		 * fails to report xxfi_connect handler rejections.
		 */
		statCount(&stat_access_bl);
		smfLog(SMF_LOG_ERROR, TAG_FORMAT "HELO %s blocked", TAG_ARGS, helohost);
		return smfReply(&data->work, 550, "5.7.1", "HELO %s blocked", helohost);

	case SMDB_ACCESS_OK:
		statCount(&stat_access_wl);
		smfLog(SMF_LOG_INFO, TAG_FORMAT "HELO %s white listed", TAG_ARGS, helohost);
		data->work.skipConnection = 1;

		/* Don't use SMFIS_ACCEPT, otherwise we can't do STAT
		 * from localhost.
		 */
		return SMFIS_CONTINUE;

	case SMDB_ACCESS_TEMPFAIL:
		statCount(&stat_tempfail);
		smfLog(SMF_LOG_ERROR, TAG_FORMAT "HELO %s temp.failed", TAG_ARGS, helohost);
		return smfReply(&data->work, 450, "4.7.1", "HELO %s blocked", helohost);

	case SMDB_ACCESS_DISCARD:
		smfLog(SMF_LOG_INFO, TAG_FORMAT "HELO %s discard", TAG_ARGS, helohost);
		statCount(&stat_discard);
		return SMFIS_DISCARD;

	default:
		smfLog(SMF_LOG_DEBUG, TAG_FORMAT "HELO %s unknown access value", TAG_ARGS, helohost);
		statCount(&stat_access_other);
		break;
	}

	if (opt_uri_bl_helo.value && testString(data, "HELO", helohost, mime_test_uri) == SMFIS_REJECT) {
		statAddValue(&stat_helo_fail, 1);
		return smfReply(&data->work, 550, NULL, "%s", data->reply);
	}

	return SMFIS_CONTINUE;
}

static sfsistat
filterMail(SMFICTX *ctx, char **args)
{
	sfsistat rc;
	workspace data;
	smdb_code access;
	char *auth_authen, *copy;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterMail");

	if ((data->work.qid = smfi_getsymval(ctx, "i")) == NULL)
		data->work.qid = smfNoQueue;

	data->hasDate = 0;
	data->hasPass = 0;
	data->hasReport = 0;
	data->hasSubject = 0;
	data->policy = POLICY_UNDEFINED;
	data->reply[0] = '\0';
	data->subject[0] = '\0';
	data->stop_uri_scanning = 0;
	data->stop_mail_scanning = 0;
	data->uri_found_rc = SMFIS_CONTINUE;
	VectorRemoveAll(data->senders);
	VectorRemoveAll(data->recipients);
	VectorRemoveAll(data->ns_tested);
	VectorRemoveAll(data->uri_tested);

	mimeReset(data->mime);
	data->work.skipMessage = data->work.skipConnection;
	auth_authen = smfi_getsymval(ctx, smMacro_auth_authen);

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterMail(%lx, %lx) MAIL='%s' auth='%s'", TAG_ARGS, (long) ctx, (long) args, args[0], TextEmpty(auth_authen));

	if ((rc = access_mail(data, args[0], smfFlags)) != SMFIS_CONTINUE)
		return rc;

	if ((copy = strdup(data->work.mail->address.string)) != NULL && VectorAdd(data->senders, copy))
		free(copy);

	access = smfAccessAuth(&data->work, MILTER_NAME "-auth:", auth_authen, args[0], NULL, NULL);

	switch (access) {
	case SMDB_ACCESS_ERROR:
		statCount(&stat_error);
		return SMFIS_REJECT;

	case SMDB_ACCESS_REJECT:
		statCount(&stat_access_bl);
		return smfReply(&data->work, 550, "5.7.1", "sender blocked");

	case SMDB_ACCESS_OK:
		statCount(&stat_access_wl);
		smfLog(SMF_LOG_INFO, TAG_FORMAT "authenticated id <%s> white listed", TAG_ARGS, TextNull(auth_authen));
		data->work.skipMessage = 1;
		return SMFIS_ACCEPT;

	case SMDB_ACCESS_TEMPFAIL:
		statCount(&stat_tempfail);
		smfLog(SMF_LOG_ERROR, TAG_FORMAT "authenticated id <%s> temp.failed", TAG_ARGS, TextNull(auth_authen));
		return smfReply(&data->work, 450, "4.7.1", "sender blocked");

	case SMDB_ACCESS_DISCARD:
		smfLog(SMF_LOG_INFO, TAG_FORMAT "authenticated id <%s> discard", TAG_ARGS, TextNull(auth_authen));
		statCount(&stat_discard);
		return SMFIS_DISCARD;

	default:
		smfLog(SMF_LOG_DEBUG, TAG_FORMAT "authenticated id <%s> unknown access value", TAG_ARGS, TextNull(auth_authen));
		statCount(&stat_access_other);
		break;
	}

	return SMFIS_CONTINUE;
}

static sfsistat
filterRcpt(SMFICTX *ctx, char **args)
{
	char *copy;
	sfsistat rc;
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterRcpt");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterRcpt(%lx, %lx) RCPT='%s'", TAG_ARGS, (long) ctx, (long) args, args[0]);

	if ((rc = access_rcpt(data, args[0], smfFlags)) != SMFIS_CONTINUE)
		return rc;

	if ((copy = strdup(data->work.rcpt->address.string)) != NULL && VectorAdd(data->recipients, copy))
		free(copy);

	if (testMail(data, data->work.mail->address.string) == SMFIS_REJECT)
		return smfReply(&data->work, 550, NULL, "%s", data->reply);

	return SMFIS_CONTINUE;
}

static sfsistat
filterHeader(SMFICTX *ctx, char *name, char *value)
{
	char *s;
	workspace data;
	const char **table;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterHeader");

	/* Postfix doesn't set the queue-id until DATA is reached. */
	if ((data->work.qid = smfi_getsymval(ctx, "i")) == NULL)
		data->work.qid = smfNoQueue;

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "%s(%p, '%s', '%s')", TAG_ARGS, __func__, ctx, name, value);

	if (TextMatch(name, "Subject", -1, 1)) {
		TextCopy(data->subject, sizeof (data->subject), value);
		data->hasSubject = 1;
	} else if (TextMatch(name, X_MILTER_PASS, -1, 1)) {
		data->hasPass = 1;
	} else if (TextMatch(name, X_MILTER_REPORT, -1, 1)) {
		data->hasReport = 1;
	} else if (TextMatch(name, "Date", -1, 1)) {
		time_t gmt;
		const char *stop;

		/* convertDate parses several formats: RFC 5322, ctime, ISO 8601.
		 * The last two and their variants are invalid for a Date header,
		 * but allowed for our needs, which is a parsable Date header is
		 * present.
		 */
		stop = value;
		data->hasDate++;
		if (convertDate(value, &gmt, &stop) == 0 && *stop == '\0')
			data->hasDate++;
	}

	/* Feed the header to the MIME parser in order to setup state. */
	for (s = name; *s != '\0'; s++)
		(void) mimeNextCh(data->mime, *s);
	(void) mimeNextCh(data->mime, ':');
	(void) mimeNextCh(data->mime, ' ');

	for (s = value; *s != '\0'; s++)
		(void) mimeNextCh(data->mime, *s);
	(void) mimeNextCh(data->mime, '\r');
	(void) mimeNextCh(data->mime, '\n');

	if (opt_access_check_headers.value) {
		/* Parse and collect senders and recipients. */
		if (TextInsensitiveCompare(name, "From") == 0
		|| TextInsensitiveCompare(name, "Sender") == 0) {
			(void) testString(data, name, value, mime_collect_headers_mail);
		}

		else if (TextInsensitiveCompare(name, "To") == 0
		|| TextInsensitiveCompare(name, "Cc") == 0) {
			(void) testString(data, name, value, mime_collect_headers_rcpt);
		}
	}

	for (table = (const char **) VectorBase(uri_bl_headers); *table != NULL; table++) {
		if (TextInsensitiveCompare(name, *table) == 0
		&& testString(data, name, value, mime_test_uri) != SMFIS_CONTINUE)
			break;
	}

	for (table = (const char **) VectorBase(mail_bl_headers); *table != NULL; table++) {
		if (TextInsensitiveCompare(name, *table) == 0
		&& testString(data, name, value, mime_test_mail_uri) != SMFIS_CONTINUE)
			break;
	}

	return SMFIS_CONTINUE;
}

static void
vector_append_copy(Vector a, Vector b)
{
	char **item, *copy;
	
	for (item = (char **)VectorBase(b); *item != NULL; item++) {
		if ((copy = strdup(*item)) != NULL && VectorAdd(a, copy))
			free(copy);
	}
}

/*
 * Reverse a mail address for comparison by domain then local-part.
 * This allows for sorting by TLD first, then user names.
 *
 * 1. anthony.howe@host.example.com
 *
 * =>	moc.elpmaxe.tsoh@ewoh.ynohtna
 * => 	com.elpmaxe.tsoh@ewoh.ynohtna
 * => 	com.example.tsoh@ewoh.ynohtna
 * => 	com.example.host@ewoh.ynohtna
 * => 	com.example.host@howe.anthony
 *
 * 2. host.example.com
 *
 * =>	moc.elpmaxe.tsoh
 * => 	com.elpmaxe.tsoh
 * => 	com.example.tsoh
 * => 	com.example.host
 */
static void
reverse_mail_in_place(char *s)
{
	int span;
	char *label = s;

	/* Reverse whole address; swaps local-part and domain. */	
	TextReverse(label, -1);

	/* Reverse each domain label, so that it reads normally, but
	 * from TLD to host label.  Any dot separated local-part, ie.
	 * first-name.last-name@ will result in @last-name.first-name.
	 */
	for (span = strcspn(label, ".@"); label[span] != '\0'; span = strcspn(label, ".@")) {
		TextReverse(label, span);
		label += span + 1;
	}
	TextReverse(label, span);
}

static int
compare_tld_to_local(const void *_a, const void *_b)
{
	int diff;
	char *a, *b;
	
	if (_a == NULL && _b != NULL)
		return 1;
	if (_a != NULL && _b == NULL)
		return -1;
	if (_a == NULL && _b == NULL)
		return 0;
		
	if ((a = strdup(*(char **)_a)) == NULL) {
		return 0;
	}
	if ((b = strdup(*(char **)_b)) == NULL) {
		free(a);
		return -1;
	}

//	smfLog(SMF_LOG_TRACE, "%s: %s %s", __func__, a, b);

	reverse_mail_in_place(a);
	reverse_mail_in_place(b);
	
	diff = TextInsensitiveCompare(a, b);
	smfLog(SMF_LOG_TRACE, "%s: %s %c %s", __func__, a, diff == 0 ? '=' : diff < 0 ? '<' : '>', b);
	
	free(b);
	free(a);
	
	return diff;
}

static int
compare_mail(const void *_a, const void *_b)
{
	smfLog(SMF_LOG_TRACE, "%s: %s %s", __func__, *(char **)_a, *(char **)_b);
	return TextInsensitiveCompare(*(char **)_a, *(char **)_b);
}

static sfsistat
filterEndHeaders(SMFICTX *ctx)
{
	workspace data;
	const char *error;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterEndHeaders");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "%s(%p)", TAG_ARGS, __func__, ctx);

	/* Force the header to body state transition. */
	(void) mimeNextCh(data->mime, '\r');
	(void) mimeNextCh(data->mime, '\n');

	if (opt_access_check_headers.value) {
		ParsePath *saved_mail;
		const char **table, **sender;

		VectorSort(data->senders, compare_tld_to_local);
		VectorUniq(data->senders, compare_mail);		
		for (table = (const char **) VectorBase(data->senders); *table != NULL; table++) {
			if (access_mail(data, *table, 0) != SMFIS_CONTINUE)
				return SMFIS_CONTINUE;
		}

		saved_mail = data->work.mail;
		VectorSort(data->recipients, compare_tld_to_local);
		VectorUniq(data->recipients, compare_mail);		
		for (sender = (const char **) VectorBase(data->senders); *sender != NULL; sender++) {
			ParsePath *path;
			if ((error = parsePath(*sender, 0, 0, &path)) != NULL) {
				smfLog(LOG_ERR, TAG_FORMAT "sender %s parse error: %s", TAG_ARGS, *sender, error);
				continue;
			}
			data->work.mail = path;
			for (table = (const char **) VectorBase(data->recipients); *table != NULL; table++) {
				if (access_rcpt(data, *table, 0) != SMFIS_CONTINUE)
					return SMFIS_CONTINUE;
			}
			free(path);
		}
		data->work.mail = saved_mail;
	}

	return SMFIS_CONTINUE;
}

static sfsistat
filterBody(SMFICTX *ctx, unsigned char *chunk, size_t size)
{
	workspace data;
	unsigned char *stop;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterBody");

	if (size == 0)
		chunk = (unsigned char *) "";
	else if (size < 20)
		chunk[--size] = '\0';

	/* Postfix doesn't set the queue-id until DATA is reached. */
	if ((data->work.qid = smfi_getsymval(ctx, "i")) == NULL)
		data->work.qid = smfNoQueue;

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterBody(%lx, '%.20s...', %lu)", TAG_ARGS, (long) ctx, chunk, size);

	if (data->work.skipMessage) {
		smfLog(SMF_LOG_TRACE, TAG_FORMAT "white listed, skipping", TAG_ARGS);
		return SMFIS_CONTINUE;
	}

	/* Do we already have a response? */
	if (data->policy != POLICY_UNDEFINED || data->stop_uri_scanning) {
		smfLog(SMF_LOG_TRACE, TAG_FORMAT "relpy set or scan limit reached, skipping", TAG_ARGS);
		return SMFIS_CONTINUE;
	}

	for (stop = chunk + size; chunk < stop; chunk++) {
		if (mimeNextCh(data->mime, *chunk))
			break;
		if (data->uri_found_rc != SMFIS_CONTINUE)
			break;
	}

	return SMFIS_CONTINUE;
}

static sfsistat
filterEndMessage(SMFICTX *ctx)
{
	workspace data;

	statCount(&stat_transactions);

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterEndMessage");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterEndMessage(%lx)", TAG_ARGS, (long) ctx);

	if (data->work.skipMessage)
		return SMFIS_CONTINUE;

	/* Terminate MIME parsing. */
	if (!data->stop_uri_scanning)
		(void) mimeNextCh(data->mime, EOF);

	if (data->policy == POLICY_UNDEFINED && data->hasDate < opt_date_required.value) {
		data->policy = *opt_date_policy.string;
		switch (data->hasDate) {
		case 1:
			(void) snprintf(data->reply, sizeof (data->reply), "invalid RFC 5322 Date header");
			break;
		case 0:
			(void) snprintf(data->reply, sizeof (data->reply), "missing Date header, required by RFC 5322 section 3.6");
			break;
		default:
			/* We should never reach this case. */
			(void) snprintf(data->reply, sizeof (data->reply), "Date header error (%d)", data->hasDate);
			break;
		}
	}

	switch (data->policy) {
	case POLICY_REJECT:
		statCount(&stat_reject);
		return smfReply(&data->work, 550, NULL, "%s", data->reply);

	case POLICY_DISCARD:
		statCount(&stat_discard);
		return SMFIS_DISCARD;

#ifdef HAVE_SMFI_QUARANTINE
	case POLICY_QUARANTINE:
		if (smfi_quarantine(ctx, data->reply) == MI_SUCCESS) {
			statCount(&stat_quarantine);
			return SMFIS_CONTINUE;
		}
		/*@fallthrough@*/
#endif
	case POLICY_TAG:
		if (TextInsensitiveStartsWith(data->subject, opt_subject_tag.string) < 0) {
			(void) snprintf(data->line, sizeof (data->line), "%s %s", opt_subject_tag.string, data->subject);
			(void) smfHeaderSet(ctx, "Subject", data->line, 1, data->hasSubject);
			statCount(&stat_tag);
		}
		break;
	}

	(void) smfHeaderSet(ctx, X_MILTER_REPORT, data->reply, 1, data->hasReport);

#ifdef DROPPED_ADD_HEADERS
	if (optAddHeaders.value) {
		long length;
		const char *if_name, *if_addr;

		if ((if_name = smfi_getsymval(ctx, "{if_name}")) == NULL)
			if_name = smfUndefined;
		if ((if_addr = smfi_getsymval(ctx, "{if_addr}")) == NULL)
			if_addr = "0.0.0.0";

		/* Add trace to the message. There can be many of these, one
		 * for each filter/host that looks at the message.
		 */
		length = snprintf(data->line, sizeof (data->line), MILTER_STRING " (%s [%s]); ", if_name, if_addr);
		length += TimeStampAdd(data->line + length, sizeof (data->line) - length);
		(void) smfi_addheader(ctx, X_SCANNED_BY, data->line);

		(void) smfHeaderSet(ctx, X_MILTER_PASS, data->reply[0] == '\0' ? "YES" : "NO", 1, data->hasPass);
	}
#endif
	return SMFIS_CONTINUE;
}

/*
 * Close and release per-connection resources.
 */
static sfsistat
filterClose(SMFICTX *ctx)
{
	workspace data;
	unsigned short cid = 0;

	if ((data = (workspace) smfi_getpriv(ctx)) != NULL) {
		cid = smfCloseEpilog(&data->work);
		VectorDestroy(data->mail_tested);
		VectorDestroy(data->uri_tested);
		VectorDestroy(data->ns_tested);
		VectorDestroy(data->recipients);
		VectorDestroy(data->senders);
		mimeFree(data->mime);
		pdqClose(data->pdq);
		free(data);
	}

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterClose(%lx)", cid, smfNoQueue, (long) ctx);

	statAddValue(&stat_connect_active, -1);

	return SMFIS_CONTINUE;
}

#ifdef HAVE_SMFI_VERSION
static sfsistat
filterUnknown(SMFICTX * ctx, const char *command)
{
	sfsistat rc;
	Stat **stat;
	Vector words;
	workspace data;
	char stamp[40];
	struct tm local;
	unsigned long age, d, h, m, s;
	size_t buffer_length, line_length;
	char buffer[2048], *lines[SMF_MAX_MULTILINE_REPLY], **line;

	rc = SMFIS_CONTINUE;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterUnknown");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterUnknown(%lx, '%s')", TAG_ARGS, (long) ctx, command);

	/* Only localhost can query the status for security. */
	if (!isReservedIP(data->work.client_addr, IS_IP_LOOPBACK|IS_IP_LOCALHOST))
		return SMFIS_REJECT;

	if ((words = TextSplit(command, " \t", 0)) == NULL)
		goto error0;
	if (VectorLength(words) != 2)
		goto error1;
	if (TextInsensitiveCompare("STAT", VectorGet(words, 0)) != 0)
		goto error1;
	if (TextInsensitiveCompare(MILTER_NAME, VectorGet(words, 1)) != 0)
		goto error1;

	line = lines;
	buffer_length = 0;

	(void) localtime_r((time_t *) &stat_start_time.count, &local);
	(void) strftime(stamp, sizeof (stamp), "%a, %d %b %Y %H:%M:%S %z", &local);
	line_length = snprintf(buffer+buffer_length, sizeof (buffer)-buffer_length, "%s=%s", stat_start_time.name, stamp);
	*line++ = buffer + buffer_length;
	buffer_length += line_length+1;

	age = s = (unsigned long) (time(NULL) - (time_t) stat_start_time.count);
	d = s / 86400;
	s -= d * 86400;
	h = s / 3600;
	s -= h * 3600;
	m = s / 60;
	s -= m * 60;

	line_length = snprintf(buffer+buffer_length, sizeof (buffer)-buffer_length, "%s=%lu (%.2lu %.2lu:%.2lu:%.2lu)", stat_run_time.name, age, d, h, m, s);
	*line++ = buffer + buffer_length;
	buffer_length += line_length+1;

	for (stat = stat_table+2; *stat != NULL; stat++) {
		line_length = snprintf(buffer+buffer_length, sizeof (buffer)-buffer_length, "%s=%lu", (*stat)->name, (*stat)->count);
		*line++ = buffer + buffer_length;
		buffer_length += line_length+1;
	}
	*line = NULL;

	(void) smfMultiLineReplyA(&data->work, 411, "4.0.0", lines);
	rc = SMFIS_TEMPFAIL;
error1:
	VectorDestroy(words);
error0:
	return rc;
}
#endif /* HAVE_SMFI_VERSION */

/***********************************************************************
 ***  Milter Definition Block
 ***********************************************************************/

static smfInfo milter = {
	MILTER_MAJOR,
	MILTER_MINOR,
	MILTER_BUILD,
	MILTER_NAME,
	MILTER_AUTHOR,
	MILTER_COPYRIGHT,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	SMF_STDIO_CLOSE,

	/* struct smfiDesc */
	{
		MILTER_NAME,		/* filter name */
		SMFI_VERSION,		/* version code -- do not change */
		0,			/* flags */
		filterOpen,		/* connection info filter */
		filterHelo,		/* SMTP HELO command filter */
		filterMail,		/* envelope sender filter */
		filterRcpt,		/* envelope recipient filter */
		filterHeader,		/* header filter */
		filterEndHeaders,	/* end of header */
		filterBody,		/* body block filter */
		filterEndMessage,	/* end of message */
		NULL,			/* message aborted */
		filterClose		/* connection cleanup */
#if SMFI_VERSION > 2
		, filterUnknown		/* Unknown/unimplemented commands */
#endif
#if SMFI_VERSION > 3
		, NULL			/* SMTP DATA command */
#endif
	}
};

/***********************************************************************
 *** Startup
 ***********************************************************************/

void
atExitCleanUp()
{
	dnsListLogClose();
	dnsListFree(ip_bl_list);
	dnsListFree(uri_bl_list);
	dnsListFree(mail_bl_list);
	dnsListFree(ns_ip_bl_list);
	dnsListFree(ns_bl_list);
	dnsListFree(d_bl_list);

	VectorDestroy(mail_bl_domains);
	VectorDestroy(mail_bl_headers);
	VectorDestroy(uri_bl_headers);
	VectorDestroy(port_list);
	free(ports);

	smdbClose(smdbAccess);
	smfAtExitCleanUp();
	statFini();
}

void
printVersion(void)
{
	printf(MILTER_NAME " " MILTER_VERSION " " MILTER_COPYRIGHT "\n");
	printf("LibSnert %s %s", LIBSNERT_VERSION, LIBSNERT_COPYRIGHT "\n");
#ifdef _BUILT
	printf("Built on " _BUILT "\n");
#endif
#ifdef HAVE_SMFI_VERSION
{
	unsigned major, minor, patch;
	(void) smfi_version(&major, &minor, &patch);
	printf("libmilter version %d.%d.%d\n", major, minor, patch);
}
#else
	printf("libmilter version %d\n", SMFI_VERSION);
#endif
}

void
printInfo(void)
{
#ifdef MILTER_NAME
	printVar(0, "MILTER_NAME", MILTER_NAME);
#endif
#ifdef MILTER_VERSION
	printVar(0, "MILTER_VERSION", MILTER_VERSION);
#endif
#ifdef MILTER_COPYRIGHT
	printVar(0, "MILTER_COPYRIGHT", MILTER_COPYRIGHT);
#endif
#ifdef MILTER_CONFIGURE
	printVar(LINE_WRAP, "MILTER_CONFIGURE", MILTER_CONFIGURE);
#endif
#ifdef _BUILT
	printVar(0, "MILTER_BUILT", _BUILT);
#endif
#ifdef LIBSNERT_VERSION
	printVar(0, "LIBSNERT_VERSION", LIBSNERT_VERSION);
#endif
#ifdef LIBSNERT_BUILD_HOST
	printVar(LINE_WRAP, "LIBSNERT_BUILD_HOST", LIBSNERT_BUILD_HOST);
#endif
#ifdef LIBSNERT_CONFIGURE
	printVar(LINE_WRAP, "LIBSNERT_CONFIGURE", LIBSNERT_CONFIGURE);
#endif
#ifdef SQLITE_VERSION
	printVar(0, "SQLITE3_VERSION", SQLITE_VERSION);
#endif
#ifdef MILTER_CFLAGS
	printVar(LINE_WRAP, "CFLAGS", MILTER_CFLAGS);
#endif
#ifdef MILTER_LDFLAGS
	printVar(LINE_WRAP, "LDFLAGS", MILTER_LDFLAGS);
#endif
#ifdef MILTER_LIBS
	printVar(LINE_WRAP, "LIBS", MILTER_LIBS);
#endif
}

int
main(int argc, char **argv)
{
	int argi;

	/* Default is OFF. */
	smfOptSmtpAuthOk.initial = "-";

	smfOptFile.initial = MILTER_CF;
	smfOptPidFile.initial = PID_FILE;
	smfOptRunUser.initial = RUN_AS_USER;
	smfOptRunGroup.initial = RUN_AS_GROUP;
	smfOptWorkDir.initial = WORK_DIR;
	smfOptMilterSocket.initial = "unix:" SOCKET_FILE;

	/* Parse command line options looking for a file= option. */
	optionInit(optTable, smfOptTable, NULL);
	argi = optionArrayL(argc, argv, optTable, smfOptTable, NULL);

	/* Parse the option file followed by the command line options again. */
	if (smfOptFile.string != NULL && *smfOptFile.string != '\0') {
		/* Do NOT reset this option. */
		smfOptFile.initial = smfOptFile.string;
		smfOptFile.string = NULL;

		optionInit(optTable, smfOptTable, NULL);
		(void) optionFile(smfOptFile.string, optTable, smfOptTable, NULL);
		(void) optionArrayL(argc, argv, optTable, smfOptTable, NULL);
	}

	if (opt_version.string != NULL) {
		printVersion();
		exit(EX_USAGE);
	}
	if (opt_info.string != NULL) {
		printInfo();
		exit(EX_USAGE);
	}
	if (smfOptHelp.string != NULL) {
		optionUsageL(optTable, smfOptTable, NULL);
		exit(EX_USAGE);
	}

	if (smfOptQuit.string != NULL) {
		/* Use SIGQUIT signal in order to avoid delays
		 * caused by libmilter's handling of SIGTERM.
		 * smfi_stop() takes too long since it waits
		 * for connections to terminate, which could
		 * be a several minutes or longer.
		 */
		exit(pidKill(smfOptPidFile.string, SIGQUIT) != 0);
	}

	if (smfOptRestart.string != NULL) {
		(void) pidKill(smfOptPidFile.string, SIGQUIT);
		sleep(2);
	}

	(void) smfi_settimeout((int) smfOptMilterTimeout.value);
	(void) smfSetLogDetail(smfOptVerbose.string);

	uriSetTimeout(opt_links_timeout.value * 1000);

	d_bl_list = dnsListCreate(opt_domain_bl.string);
	ns_bl_list = dnsListCreate(opt_uri_ns_bl.string);
	ns_ip_bl_list = dnsListCreate(opt_uri_ns_a_bl.string);
	ip_bl_list = dnsListCreate(opt_uri_a_bl.string);
	uri_bl_list = dnsListCreate(opt_uri_bl.string);
	uri_bl_headers = TextSplit(opt_uri_bl_headers.string, ";, ", 0);
	mail_bl_list = dnsListCreate(opt_mail_bl.string);
	mail_bl_headers = TextSplit(opt_mail_bl_headers.string, ";, ", 0);
	mail_bl_domains = TextSplit(opt_mail_bl_domains.string, ";, ", 0);
	port_list = TextSplit(opt_uri_bl_port_list.string, ";, ", 0);

	if (0 < VectorLength(port_list)) {
		int i;
		ports = malloc(sizeof (long) * (VectorLength(port_list) + 1));

		for (i = 0; i < VectorLength(port_list); i++) {
			char *port = VectorGet(port_list, i);
			ports[i] = strtol(port, NULL, 10);
		}
		ports[i] = -1;
	}

	switch (*opt_uri_bl_policy.string) {
#ifdef HAVE_SMFI_QUARANTINE
	case POLICY_QUARANTINE:
		milter.handlers.xxfi_flags |= SMFIF_QUARANTINE;
		/*@fallthrough@*/
#endif
	case POLICY_TAG:
		/* Going to change the Subject: header and add a report. */
		milter.handlers.xxfi_flags |= SMFIF_ADDHDRS|SMFIF_CHGHDRS;
		break;
	}

	switch (*opt_links_policy.string) {
#ifdef HAVE_SMFI_QUARANTINE
	case POLICY_QUARANTINE:
		milter.handlers.xxfi_flags |= SMFIF_QUARANTINE;
		/*@fallthrough@*/
#endif
	case POLICY_TAG:
		/* Going to change the Subject: header and add a report. */
		milter.handlers.xxfi_flags |= SMFIF_ADDHDRS|SMFIF_CHGHDRS;
		break;
	}

	switch (*opt_mail_bl_policy.string) {
#ifdef HAVE_SMFI_QUARANTINE
	case POLICY_QUARANTINE:
		milter.handlers.xxfi_flags |= SMFIF_QUARANTINE;
		/*@fallthrough@*/
#endif
	case POLICY_TAG:
		/* Going to change the Subject: header and add a report. */
		milter.handlers.xxfi_flags |= SMFIF_ADDHDRS|SMFIF_CHGHDRS;
		break;
	}

	openlog(MILTER_NAME, LOG_PID, LOG_MAIL);

	if (smfOptDaemon.value && smfStartBackgroundProcess())
		return EX_SOFTWARE;

	if (atexit(atExitCleanUp)) {
		syslog(LOG_ERR, "atexit() failed\n");
		return EX_SOFTWARE;
	}

	if (*smfOptAccessDb.string != '\0') {
		SMDB_OPTIONS_SETTING((smfLogDetail & SMF_LOG_DATABASE) ? 2 : 0);

		if ((smdbAccess = smdbOpen(smfOptAccessDb.string, 1)) == NULL) {
			syslog(LOG_ERR, "failed to open \"%s\"", smfOptAccessDb.string);
			return EX_NOINPUT;
		}
	}

	if (smfLogDetail & SMF_LOG_DIALOG)
		uriSetDebug(1);
	if (smfLogDetail & SMF_LOG_DEBUG)
		uriSetDebug(2);

	if (smfLogDetail & SMF_LOG_SOCKET_ALL)
		socketSetDebug(10);
	else if (smfLogDetail & SMF_LOG_SOCKET_FD)
		socketSetDebug(1);

	if (socketInit()) {
		syslog(LOG_ERR, "socketInit() error\n");
		return EX_SOFTWARE;
	}

	DNS_LIST_OPTIONS_SETTING((smfLogDetail & SMF_LOG_DNS) == SMF_LOG_DNS);

	PDQ_OPTIONS_SETTING((smfLogDetail & SMF_LOG_DNS) == SMF_LOG_DNS);
	if (pdqInit()) {
		fprintf(stderr, "pdqInit() failed\n");
		return 1;
	}

	statInit();

	return smfMainStart(&milter);
}
