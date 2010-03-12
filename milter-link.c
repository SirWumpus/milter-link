/*
 * milter-link.c
 *
 * Copyright 2003, 2010 by Anthony Howe. All rights reserved.
 *
 * The following should be added to the sendmail.mc file:
 *
 *	INPUT_MAIL_FILTER(
 *		`milter-link',
 *		`S=unix:/var/lib/milter-link/socket, T=S:10s;R:10s'
 *	)dnl
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

#include <sys/types.h>
#include <ctype.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

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
#include <com/snert/lib/sys/sysexits.h>

#if LIBSNERT_MAJOR < 1 || LIBSNERT_MINOR < 73 || LIBSNERT_BUILD < 17
# error "LibSnert 1.73.17 or better is required"
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

/***********************************************************************
 *** Global Variables
 ***********************************************************************/

static smfInfo milter;

typedef struct {
	smfWork work;
	int policy;				/* per message */
	int hasPass;				/* per message */
	int hasReport;				/* per message */
	int hasSubject;				/* per message */
	char line[SMTP_TEXT_LINE_LENGTH+1];	/* general purpose */
	char subject[SMTP_TEXT_LINE_LENGTH+1];	/* per message */

	PDQ *pdq;				/* per connection */
	Mime *mime;				/* per connection, reset per message */
	Vector ns_tested;			/* per connection */
	Vector uri_tested;			/* per connection */
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


static const char usage_domain_bl[] =
  "A list of domain black list suffixes to consult, like .dbl.spamhaus.org.\n"
"# The host or domain name found in a URI is checked against these DNS black\n"
"# lists. These black lists are assumed to use wildcards entries, so only a\n"
"# single lookup is done. IP-as-domain in a URI are ignored.\n"
"#"
;
static Option opt_domain_bl	= { "domain-bl",	"",			usage_domain_bl };

static const char usage_uri_bl[] =
  "A list of domain name black list suffixes to consult, like .multi.surbl.org.\n"
"# The domain name found in a URI is checked against these DNS black lists.\n"
"# Aggregate lists are supported using suffix/mask. Without a /mask, suffix\n"
"# is the same as suffix/0x00FFFFFE.\n"
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
"# Aggregate lists are supported using suffix/mask. Without a /mask, suffix\n"
"# is the same as suffix/0x00FFFFFE.\n"
"#"
;
static Option opt_uri_a_bl	= { "uri-a-bl",		"",			usage_uri_a_bl };

static const char usage_uri_ns_bl[] =
  "A list of host name and/or domain name black list suffixes to consult. The\n"
"# domain name found in a URI is used to find its DNS NS records; the NS host\n"
"# names are checked against these host name and/or domain name DNS black\n"
"# lists. Aggregate lists are supported using suffix/mask. Without a /mask,\n"
"# suffix is the same as suffix/0x00FFFFFE.\n"
"#"
;
static Option opt_uri_ns_bl	= { "uri-ns-bl",	"",			usage_uri_ns_bl };

static const char usage_uri_ns_a_bl[] =
  "A comma or semi-colon separated list of IP black list suffixes to consult.\n"
"# The host or domain name found in a URI is used to find its DNS NS records\n"
"# and IP address, which are then checked against these IP black lists.\n"
"# Aggregate lists are supported using suffix/mask. Without a /mask, suffix\n"
"# is the same as suffix/0x00FFFFFE.\n"
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
"# hashed, which are then checked against these black lists. Aggregate lists\n"
"# are supported using suffix/mask. Without a /mask, suffix is the same as\n"
"# suffix/0x00FFFFFE.\n"
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
	";inmail24.com"
	";jmail.co.za"
	";libero.it"
	";luckymail.com"
	";mail2world.com"
	";msn.com"
	";rocketmail.com"
	";she.com"
	";shuf.com"
	";sify.com"
	";terra.es"
	";tiscali.it"
	";tom.com"
	";ubbi.com"
	";virgilio.it"
	";voila.fr"
	";walla.com"
	";wanadoo.fr"
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

#ifdef DROPPED_ADD_HEADERS
static Option optAddHeaders	= { "add-headers",	"-",			"Add extra informational headers when message passes." };
#endif

static Option *optTable[] = {
	&optIntro,
#ifdef DROPPED_ADD_HEADERS
	&optAddHeaders,
#endif
	DNS_LIST_OPTIONS_TABLE,
	PDQ_OPTIONS_TABLE,
	&opt_info,
	&opt_domain_bl,
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
STAT_DECLARE(run_time);
STAT_DECLARE(connect_active);
STAT_DECLARE(connect_total);
STAT_DECLARE(connect_error);
STAT_DECLARE(transactions);
STAT_DECLARE(access_bl);
STAT_DECLARE(access_wl);
STAT_DECLARE(access_other);
STAT_DECLARE(link_fail);
STAT_DECLARE(mail_fail);
STAT_DECLARE(origin_fail);
STAT_DECLARE(uri_fail);
STAT_DECLARE(tag);
STAT_DECLARE(reject);
STAT_DECLARE(discard);
STAT_DECLARE(quarantine);

#define SMF_MAX_MULTILINE_REPLY		32

static Stat *stat_table[SMF_MAX_MULTILINE_REPLY] = {
	&stat_start_time,
	&stat_run_time,
	&stat_connect_active,
	&stat_connect_total,
	&stat_connect_error,
	&stat_transactions,
	&stat_tag,
	&stat_reject,
	&stat_discard,
	&stat_quarantine,
	&stat_access_bl,
	&stat_access_wl,
	&stat_access_other,
	&stat_link_fail,
	&stat_mail_fail,
	&stat_origin_fail,
	&stat_uri_fail,
	NULL
};

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

	if (data->policy == '\0' && VectorLength(data->mail_tested) < opt_mail_bl_max.value
	&& (list_name = dnsListQueryMail(mail_bl_list, data->pdq, mail_bl_domains, data->mail_tested, mail)) != NULL) {
		snprintf(data->reply, sizeof (data->reply), black_listed_mail_format, mail, list_name);
		dnsListLog(data->work.qid, mail, list_name);
		data->policy = *opt_mail_bl_policy.string;
		rc = data->policy == 'r' ? SMFIS_REJECT : SMFIS_CONTINUE;
		statCount(&stat_mail_fail);
	}

	smfLog(SMF_LOG_DEBUG, TAG_FORMAT "testMail(%lx, \"%s\") rc=%d policy=%x reply='%s'", TAG_ARGS, (long) data, mail, rc, data->policy, data->reply);

	return rc;
}

sfsistat
testMailUri(workspace data, URI *uri)
{
	return testMail(data, uri->uriDecoded);
}

static sfsistat
testString(workspace data, const char *value, sfsistat (*test_fn)(workspace, URI *))
{
	int rc;
	URI *uri;
	Mime *mime;

	if (value == NULL || (mime = uriMimeCreate(0)) == NULL)
		return SMFIS_CONTINUE;

	mimeHeadersFirst(mime, 0);

	for (rc = SMFIS_CONTINUE; rc == SMFIS_CONTINUE && *value != '\0'; value++) {
		if (mimeNextCh(mime, *value))
			break;

		if ((uri = uriMimeGetUri(mime)) != NULL) {
			rc = (*test_fn)(data, uri);
			uriMimeFreeUri(mime);
		}
	}

	uriMimeFree(mime);

	return rc;
}

static sfsistat
testURI(workspace data, URI *uri)
{
	long i;
	const char *error;
	URI *origin = NULL;
	char *host, *ip, *copy;
	const char *list_name = NULL;
	int access, rc = SMFIS_REJECT;

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

	/* Session cache for previously PASSED hosts/domains. */
	for (i = 0; i < VectorLength(data->uri_tested); i++) {
		if ((host = VectorGet(data->uri_tested, i)) == NULL)
			continue;

		if (TextInsensitiveCompare(uri->host, host) == 0)
			return SMFIS_CONTINUE;
	}

	/* Be sure to apply the correct access lookup. */
	if (0 < spanIP(uri->host)) {
		ip = uri->host;
		host = NULL;
	} else {
		ip = NULL;
		host = uri->host;
	}

	access = smfAccessClient(&data->work, MILTER_NAME "-body:", host, ip, NULL, NULL);
	switch (access) {
	case SMDB_ACCESS_OK:
		smfLog(SMF_LOG_INFO, TAG_FORMAT "URI <%s> OK", TAG_ARGS, uri->uri);
		return SMFIS_CONTINUE;

	case SMDB_ACCESS_REJECT:
		snprintf(data->reply, sizeof (data->reply), "rejected URL host %s", uri->host);
		data->policy = 'r';
		rc = SMFIS_REJECT;
		goto error0;
	}

	if ((list_name = dnsListQueryName(d_bl_list, data->pdq, NULL, uri->host)) != NULL
	||  (list_name = dnsListQueryDomain(uri_bl_list, data->pdq, NULL, opt_uri_bl_sub_domains.value, uri->host)) != NULL
	||  (list_name = dnsListQueryNs(ns_bl_list, ns_ip_bl_list, data->pdq, data->ns_tested, uri->host)) != NULL
	||  (list_name = dnsListQueryIP(ip_bl_list, data->pdq, NULL, uri->host)) != NULL) {
		snprintf(data->reply, sizeof (data->reply), black_listed_url_format, uri->host, list_name);
		dnsListLog(data->work.qid, uri->host, list_name);
		data->policy = *opt_uri_bl_policy.string;
		statCount(&stat_uri_fail);
		goto error0;
	}

	if (VectorAdd(data->uri_tested, copy = strdup(uri->host)))
		free(copy);

	dnsListLog(data->work.qid, uri->host, NULL);

	/* Test and follow redirections so verify that the link returns something valid. */
	if (opt_links_test.value && (error = uriHttpOrigin(uri->uri, &origin)) == uriErrorLoop) {
		snprintf(data->reply, sizeof (data->reply), "broken URL \"%s\": %s", uri->uri, error);
		data->policy = *opt_links_policy.string;
		statCount(&stat_link_fail);
		goto error0;
	}

	if (origin != NULL && origin->host != NULL && strcmp(uri->host, origin->host) != 0) {
		if ((list_name = dnsListQueryName(d_bl_list, data->pdq, NULL, origin->host)) != NULL
		||  (list_name = dnsListQueryDomain(uri_bl_list, data->pdq, NULL, opt_uri_bl_sub_domains.value, origin->host)) != NULL
		||  (list_name = dnsListQueryNs(ns_bl_list, ns_ip_bl_list, data->pdq, data->ns_tested, origin->host)) != NULL
		||  (list_name = dnsListQueryIP(ip_bl_list, data->pdq, NULL, origin->host)) != NULL) {
			snprintf(data->reply, sizeof (data->reply), black_listed_url_format, origin->host, list_name);
			dnsListLog(data->work.qid, origin->host, list_name);
			data->policy = *opt_uri_bl_policy.string;
			statCount(&stat_origin_fail);
			goto error1;
		}

		if (VectorAdd(data->uri_tested, copy = strdup(origin->host)))
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

/***********************************************************************
 *** Handlers
 ***********************************************************************/

/*
 * Open and allocate per-connection resources.
 */
static sfsistat
filterOpen(SMFICTX *ctx, char *client_name, _SOCK_ADDR *raw_client_addr)
{
	int access;
	workspace data;

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
	if ((data->mime = uriMimeCreate(0)) == NULL)
		goto error2;

	if ((data->uri_tested = VectorCreate(10)) == NULL)
		goto error3;
	VectorSetDestroyEntry(data->uri_tested, free);

	if ((data->ns_tested = VectorCreate(10)) == NULL)
		goto error4;
	VectorSetDestroyEntry(data->ns_tested, free);

	if ((data->mail_tested = VectorCreate(10)) == NULL)
		goto error5;
	VectorSetDestroyEntry(data->mail_tested, free);

	if (smfi_setpriv(ctx, (void *) data) == MI_FAILURE) {
		syslog(LOG_ERR, TAG_FORMAT "failed to save workspace", TAG_ARGS);
		goto error6;
	}

	access = smfAccessHost(&data->work, MILTER_NAME "-connect:", client_name, data->work.client_addr, SMDB_ACCESS_OK);

	switch (access) {
	case SMDB_ACCESS_REJECT:
		/* Report this mail error ourselves, because sendmail/milter API
		 * fails to report xxfi_connect handler rejections.
		 */
		statCount(&stat_access_bl);
		smfLog(SMF_LOG_ERROR, TAG_FORMAT "connection %s [%s] blocked", TAG_ARGS, client_name, data->work.client_addr);
		return smfReply(&data->work, 550, "5.7.1", "connection %s [%s] blocked", client_name, data->work.client_addr);

	case SMDB_ACCESS_ERROR:
		statCount(&stat_access_other);
		return SMFIS_REJECT;

	case SMDB_ACCESS_OK:
		statCount(&stat_access_wl);
		statAddValue(&stat_connect_active, 1);
		smfLog(SMF_LOG_TRACE, TAG_FORMAT "client %s [%s] white listed", TAG_ARGS, client_name, data->work.client_addr);
		data->work.skipConnection = 1;

		/* Don't use SMFIS_ACCEPT, otherwise we can't do STAT
		 * from localhost.
		 */
		return SMFIS_CONTINUE;
	}

	statAddValue(&stat_connect_active, 1);

	return SMFIS_CONTINUE;
error6:
	VectorDestroy(data->mail_tested);
error5:
	VectorDestroy(data->ns_tested);
error4:
	VectorDestroy(data->uri_tested);
error3:
	uriMimeFree(data->mime);
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

	if (opt_uri_bl_helo.value && testString(data, helohost, testURI) == SMFIS_REJECT)
		return smfReply(&data->work, 550, NULL, "%s", data->reply);

	return SMFIS_CONTINUE;
}

static sfsistat
filterMail(SMFICTX *ctx, char **args)
{
	int access;
	workspace data;
	char *auth_authen;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterMail");

	if ((data->work.qid = smfi_getsymval(ctx, "i")) == NULL)
		data->work.qid = smfNoQueue;

	data->hasPass = 0;
	data->hasSubject = 0;
	data->policy = '\0';
	data->reply[0] = '\0';
	data->subject[0] = '\0';

	mimeReset(data->mime);
	data->work.skipMessage = data->work.skipConnection;
	auth_authen = smfi_getsymval(ctx, smMacro_auth_authen);

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterMail(%lx, %lx) MAIL='%s' auth='%s'", TAG_ARGS, (long) ctx, (long) args, args[0], TextEmpty(auth_authen));

	access = smfAccessMail(&data->work, MILTER_NAME "-from:", args[0], SMDB_ACCESS_UNKNOWN);

	switch (access) {
	case SMDB_ACCESS_REJECT:
		statCount(&stat_access_bl);
		return smfReply(&data->work, 550, "5.7.1", "sender blocked");

	case SMDB_ACCESS_OK:
		statCount(&stat_access_wl);
		smfLog(SMF_LOG_TRACE, TAG_FORMAT "sender <%s> white listed", TAG_ARGS, data->work.mail->address.string);
		data->work.skipMessage = 1;
		return SMFIS_ACCEPT;

	/* smfAccessMail failure cases. */
	case SMDB_ACCESS_TEMPFAIL:
		smfLog(SMF_LOG_ERROR, TAG_FORMAT "sender <%s> temp.failed", TAG_ARGS, data->work.mail->address.string);
		statCount(&stat_access_other);
		return SMFIS_TEMPFAIL;

	case SMDB_ACCESS_ERROR:
		smfLog(SMF_LOG_ERROR, TAG_FORMAT "sender <%s> unknown error", TAG_ARGS, data->work.mail->address.string);
		statCount(&stat_access_other);
		return SMFIS_REJECT;
	}

	access = smfAccessAuth(&data->work, MILTER_NAME "-auth:", auth_authen, args[0], NULL, NULL);

	switch (access) {
	case SMDB_ACCESS_REJECT:
		statCount(&stat_access_bl);
		return smfReply(&data->work, 550, "5.7.1", "sender blocked");

	case SMDB_ACCESS_OK:
		statCount(&stat_access_wl);
		smfLog(SMF_LOG_TRACE, TAG_FORMAT "authenticated id <%s> white listed", TAG_ARGS, auth_authen);
		data->work.skipMessage = 1;
		return SMFIS_ACCEPT;

	/* smfAccessAuth failure cases. */
	case SMDB_ACCESS_TEMPFAIL:
		smfLog(SMF_LOG_ERROR, TAG_FORMAT "authenticated id <%s> temp.failed", TAG_ARGS, auth_authen);
		statCount(&stat_access_other);
		return SMFIS_TEMPFAIL;

	case SMDB_ACCESS_ERROR:
		smfLog(SMF_LOG_ERROR, TAG_FORMAT "authenticated id <%s> unknown error", TAG_ARGS, auth_authen);
		statCount(&stat_access_other);
		return SMFIS_REJECT;
	}

	return SMFIS_CONTINUE;
}

static sfsistat
filterRcpt(SMFICTX *ctx, char **args)
{
	int access;
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterRcpt");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterRcpt(%lx, %lx) RCPT='%s'", TAG_ARGS, (long) ctx, (long) args, args[0]);

	access = smfAccessRcpt(&data->work, MILTER_NAME "-to:", args[0]);

	switch (access) {
	case SMDB_ACCESS_REJECT:
		statCount(&stat_access_bl);
		return smfReply(&data->work, 550, "5.7.1", "recipient blocked");

	case SMDB_ACCESS_OK:
		statCount(&stat_access_wl);
		smfLog(SMF_LOG_TRACE, TAG_FORMAT "recipient <%s> white listed", TAG_ARGS, args[0]);
		data->work.skipMessage = 1;
		return SMFIS_ACCEPT;

	/* smfAccessRcpt failure cases. */
	case SMDB_ACCESS_TEMPFAIL:
		smfLog(SMF_LOG_ERROR, TAG_FORMAT "recipient <%s> temp.failed", TAG_ARGS, args[0]);
		statCount(&stat_access_other);
		return SMFIS_TEMPFAIL;

	case SMDB_ACCESS_ERROR:
		smfLog(SMF_LOG_ERROR, TAG_FORMAT "recipient <%s> unknown error", TAG_ARGS, args[0]);
		statCount(&stat_access_other);
		return SMFIS_REJECT;
	}

	if (testMail(data, data->work.mail->address.string) == SMFIS_REJECT)
		return smfReply(&data->work, 550, NULL, "%s", data->reply);

	return SMFIS_CONTINUE;
}

static sfsistat
filterHeader(SMFICTX *ctx, char *name, char *value)
{
	char *s;
	sfsistat rc;
	workspace data;
	const char **table;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterHeader");

	/* Postfix doesn't set the queue-id until DATA is reached. */
	if ((data->work.qid = smfi_getsymval(ctx, "i")) == NULL)
		data->work.qid = smfNoQueue;

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterHeader(%lx, '%s', '%.20s...')", TAG_ARGS, (long) ctx, name, value);

	if (TextMatch(name, "Subject", -1, 1)) {
		TextCopy(data->subject, sizeof (data->subject), value);
		data->hasSubject = 1;
	} else if (TextMatch(name, X_MILTER_PASS, -1, 1)) {
		data->hasPass = 1;
	} else if (TextMatch(name, X_MILTER_REPORT, -1, 1)) {
		data->hasReport = 1;
	}

	/* Feed the header to the MIME parser in order to setup state. */
	for (s = name; *s != '\0'; s++)
		(void) mimeNextCh(data->mime, *s);
	(void) mimeNextCh(data->mime, ':');

	for (s = value; *s != '\0'; s++)
		(void) mimeNextCh(data->mime, *s);
	(void) mimeNextCh(data->mime, '\r');
	(void) mimeNextCh(data->mime, '\n');

	for (table = (const char **) VectorBase(uri_bl_headers); *table != NULL; table++) {
		if (TextInsensitiveCompare(name, *table) == 0 && (rc = testString(data, value, testURI)) != SMFIS_CONTINUE)
			break;
	}

	for (table = (const char **) VectorBase(mail_bl_headers); *table != NULL; table++) {
		if (TextInsensitiveCompare(name, *table) == 0 && (rc = testString(data, value, testMailUri)) != SMFIS_CONTINUE)
			break;
	}

	return SMFIS_CONTINUE;
}

static sfsistat
filterEndHeaders(SMFICTX *ctx)
{
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterEndHeaders");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterEndHeaders(%lx)", TAG_ARGS, (long) ctx);

	/* Force the header to body state transition. */
	(void) mimeNextCh(data->mime, '\r');
	(void) mimeNextCh(data->mime, '\n');

	return SMFIS_CONTINUE;
}

static sfsistat
filterBody(SMFICTX *ctx, unsigned char *chunk, size_t size)
{
	URI *uri;
	sfsistat rc;
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
	if (data->reply[0] != '\0')
		return SMFIS_CONTINUE;

	for (stop = chunk + size; chunk < stop; chunk++) {
		if (mimeNextCh(data->mime, *chunk))
			break;

		if ((uri = uriMimeGetUri(data->mime)) != NULL) {
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

			uriMimeFreeUri(data->mime);
			if (rc != SMFIS_CONTINUE)
				break;
		}
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
	if (mimeNextCh(data->mime, EOF) == 0) {
		URI *uri;
		sfsistat rc;

		if ((uri = uriMimeGetUri(data->mime)) != NULL) {
			smfLog(SMF_LOG_DIALOG, TAG_FORMAT "checking uri=%s", TAG_ARGS, TextNull(uri->host));

			if ((rc = testURI(data, uri)) == SMFIS_CONTINUE) {
				if (uri->query == NULL)
					rc = testList(data, uri->path, "&");
				else if ((rc = testList(data, uri->query, "&")) == 0)
					rc = testList(data, uri->query, "/");
				if (rc == SMFIS_CONTINUE)
					rc = testList(data, uri->path, "/");
			}

			if (rc == SMFIS_CONTINUE && uriGetSchemePort(uri) == 25) {
				rc = testMail(data, uri->uriDecoded);
			}

			uriMimeFreeUri(data->mime);
		}
	}

	if (data->reply[0] != '\0') {
		smfLog(SMF_LOG_INFO, TAG_FORMAT "%s", TAG_ARGS, data->reply);

		switch (data->policy) {
		case 'd':
			statCount(&stat_discard);
			return SMFIS_DISCARD;
		case 'r':
			statCount(&stat_reject);
			return smfReply(&data->work, 550, NULL, "%s", data->reply);
#ifdef HAVE_SMFI_QUARANTINE
		case 'q':
			if (smfi_quarantine(ctx, data->reply) == MI_SUCCESS) {
				statCount(&stat_quarantine);
				return SMFIS_CONTINUE;
			}
			/*@fallthrough@*/
#endif
		case 't':
			if (TextInsensitiveStartsWith(data->subject, opt_subject_tag.string) < 0) {
				(void) snprintf(data->line, sizeof (data->line), "%s %s", opt_subject_tag.string, data->subject);
				(void) smfHeaderSet(ctx, "Subject", data->line, 1, data->hasSubject);
				statCount(&stat_tag);
			}
			break;
		}

		(void) smfHeaderSet(ctx, X_MILTER_REPORT, data->reply, 1, data->hasReport);
	}

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
		uriMimeFree(data->mime);
		pdqClose(data->pdq);
		free(data);
	}

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterClose(%lx)", cid, smfNoQueue, (long) ctx);

	statAddValue(&stat_connect_active, -1);

	return SMFIS_CONTINUE;
}

static sfsistat
filterUnknown(SMFICTX * ctx, const char *command)
{
	Stat **stat;
	Vector words;
	workspace data;
	char stamp[40];
	struct tm local;
	unsigned long age, d, h, m, s;
	size_t buffer_length, line_length;
	char buffer[2048], *lines[SMF_MAX_MULTILINE_REPLY], **line;

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
error1:
	VectorDestroy(words);
error0:
	return SMFIS_TEMPFAIL;
}

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
}

#define LINE_WRAP 70

void
printVar(int columns, const char *name, const char *value)
{
	int length;
	Vector list;
	const char **args;

	if (columns <= 0)
		printf("%s=\"%s\"\n",  name, value);
	else if ((list = TextSplit(value, " \t", 0)) != NULL && 0 < VectorLength(list)) {
		args = (const char **) VectorBase(list);

		length = printf("%s=\"'%s'", name, *args);
		for (args++; *args != NULL; args++) {
			/* Line wrap. */
			if (columns <= length + strlen(*args) + 4) {
				(void) printf("\n\t");
				length = 8;
			}
			length += printf(" '%s'", *args);
		}
		if (columns <= length + 1) {
			(void) printf("\n");
		}
		(void) printf("\"\n");

		VectorDestroy(list);
	}
}

void
printInfo(void)
{
#ifdef MILTER_NAME
	printVar(0, "_NAME", MILTER_NAME);
#endif
#ifdef MILTER_VERSION
	printVar(0, "_VERSION", MILTER_VERSION);
#endif
#ifdef MILTER_COPYRIGHT
	printVar(0, "_COPYRIGHT", MILTER_COPYRIGHT);
#endif
#ifdef _BUILT
	printVar(0, "_BUILT", _BUILT);
#endif
#ifdef _CONFIGURE
	printVar(LINE_WRAP, "_CONFIGURE", _CONFIGURE);
#endif
#ifdef LIBSNERT_VERSION
	printVar(0, "LIBSNERT_VERSION", LIBSNERT_VERSION);
#endif
#ifdef LIBSNERT_CONFIGURE
	printVar(LINE_WRAP, "LIBSNERT_CONFIGURE", LIBSNERT_CONFIGURE);
#endif
#ifdef _CFLAGS
	printVar(LINE_WRAP, "CFLAGS", _CFLAGS);
#endif
#ifdef _LDFLAGS
	printVar(LINE_WRAP, "LDFLAGS", _LDFLAGS);
#endif
#ifdef _LIBS
	printVar(LINE_WRAP, "LIBS", _LIBS);
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
		exit(2);
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
	case 'q':
		milter.handlers.xxfi_flags |= SMFIF_QUARANTINE;
		/*@fallthrough@*/
#endif
	case 't':
		/* Going to change the Subject: header and add a report. */
		milter.handlers.xxfi_flags |= SMFIF_ADDHDRS|SMFIF_CHGHDRS;
		break;
	}

	switch (*opt_links_policy.string) {
#ifdef HAVE_SMFI_QUARANTINE
	case 'q':
		milter.handlers.xxfi_flags |= SMFIF_QUARANTINE;
		/*@fallthrough@*/
#endif
	case 't':
		/* Going to change the Subject: header and add a report. */
		milter.handlers.xxfi_flags |= SMFIF_ADDHDRS|SMFIF_CHGHDRS;
		break;
	}

	switch (*opt_mail_bl_policy.string) {
#ifdef HAVE_SMFI_QUARANTINE
	case 'q':
		milter.handlers.xxfi_flags |= SMFIF_QUARANTINE;
		/*@fallthrough@*/
#endif
	case 't':
		/* Going to change the Subject: header and add a report. */
		milter.handlers.xxfi_flags |= SMFIF_ADDHDRS|SMFIF_CHGHDRS;
		break;
	}

	openlog(MILTER_NAME, LOG_PID, LOG_MAIL);

	if (smfOptDaemon.value && smfStartBackgroundProcess())
		return 1;

	if (atexit(atExitCleanUp)) {
		syslog(LOG_ERR, "atexit() failed\n");
		return 1;
	}

	if (*smfOptAccessDb.string != '\0') {
		if (smfLogDetail & SMF_LOG_DATABASE)
			smdbSetDebugMask(SMDB_DEBUG_ALL);

		if ((smdbAccess = smdbOpen(smfOptAccessDb.string, 1)) == NULL) {
			syslog(LOG_ERR, "failed to open \"%s\"", smfOptAccessDb.string);
			return 1;
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
		return 1;
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
