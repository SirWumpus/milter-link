/*
 * milter-link.c
 *
 * Copyright 2003, 2005 by Anthony Howe. All rights reserved.
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
#include <com/snert/lib/util/Text.h>
#include <com/snert/lib/util/getopt.h>
#include <com/snert/lib/util/uri.h>

#if LIBSNERT_MAJOR < 1 || LIBSNERT_MINOR < 71
# error "LibSnert/1.71 or better is required"
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

typedef struct {
	smfWork work;
	int policy;				/* per message */
	int hasPass;				/* per message */
	int hasReport;				/* per message */
	int hasSubject;				/* per message */
	char line[SMTP_TEXT_LINE_LENGTH+1];	/* general purpose */
	char subject[SMTP_TEXT_LINE_LENGTH+1];	/* per message */
	char client_name[SMTP_DOMAIN_LENGTH+1];	/* per connection */
	char client_addr[IPV6_TAG_LENGTH+IPV6_STRING_LENGTH];	/* per connection */

	PDQ *pdq;				/* per connection */
	Mime *mime;				/* per connection, reset per message */
	Vector ns_tested;			/* per connection */
	Vector uri_tested;			/* per connection */
	Vector mail_tested;			/* per connection */
	char reply[SMTP_TEXT_LINE_LENGTH+1];	/* per message */
} *workspace;

static const char usage_test_sub_domains[] =
  "When querying against name based black lists, like .multi.surbl.org\n"
"# or .black.uribl.com, first test the registered domain, then any \n"
"# sub-domains from right-to-left. Typically sub-domains are not listed.\n"
"#"
;

static const char usage_policy_bl[] =
  "Policy to apply if message contains a black listed URI found by dns-bl\n"
"# or uri-bl. Specify one of none, tag, quarantine, reject, or discard.\n"
"#"
;

static const char usage_policy_links[] =
  "Policy to apply if message contains a broken URL found by +test-links.\n"
"# Specify one of none, tag, quarantine, reject, or discard.\n"
"#"
;

static const char usage_dns_bl[] =
  "A list of IP based DNS BL suffixes to consult, like sbl-xbl.spamhaus.org.\n"
"# Aggregate lists are supported using suffix/mask. Without a /mask, suffix\n"
"# is the same as suffix/0x00FFFFFE.\n"
"#"
;

static const char usage_ns_bl[] =
  "A list of name based NS BL suffixes to consult. Aggregate lists are\n"
"# supported using suffix/mask. Without a /mask, suffix is the same as\n"
"# suffix/0x00FFFFFE.\n"
"#"
;

static const char usage_uri_bl[] =
  "A list of name based DNS BL suffixes to consult, like .multi.surbl.org.\n"
"# Aggregate lists are supported using suffix/mask. Without a /mask, suffix\n"
"# is the same as suffix/0x00FFFFFE.\n"
"#"
;

static const char usage_test_helo[] =
  "Test the HELO/EHLO argument using the uri-bl and dns-bl options\n"
"# Reject the command if black listed.\n"
"#"
;

static Option optIntro		= { "",			NULL,			"\n# " MILTER_NAME "/" MILTER_VERSION "\n#\n# " MILTER_COPYRIGHT "\n#\n" };
static Option optDnsBL		= { "dns-bl",		"",			usage_dns_bl };
static Option optHttpTimeout	= { "http-timeout",	"60",			"Socket timeout used when testing HTTP links." };
static Option optPolicyBL	= { "policy",		"reject",		usage_policy_bl };
static Option optPolicyLinks	= { "policy-links",	"tag",			usage_policy_links };
static Option optSubjectTag	= { "subject-tag",	SUBJECT_TAG,		"Subject tag for messages identified as spam." };
static Option optTestHelo	= { "test-helo",	"-",			usage_test_helo };
static Option optTestLinks	= { "test-links",	"-",			"Verify HTTP links are valid and find origin server." };
static Option optTestSubDomains = { "test-sub-domains", "-",                    usage_test_sub_domains };
static Option optNsBL		= { "ns-bl",		"",			usage_ns_bl };
static Option optUriBL		= { "uri-bl",		".multi.surbl.org",	usage_uri_bl };

static const char usage_mail_bl[] =
  "A list of name based MAIL BL suffixes to consult. Aggregate lists are\n"
"# supported using suffix/mask. Without a /mask, suffix is the same as\n"
"# suffix/0x00FFFFFE.\n"
"#"
;
Option optMailBl		= { "mail-bl",		"",			usage_mail_bl };

static const char usage_mail_bl_headers[] =
  "A list of mail headers to parse for mail addresses and check against\n"
"# one or more MAIL BL. Specify the empty list to disable.\n"
"#"
;
Option optMailBlHeaders		= { "mail-bl-headers",	"From;Reply-To",	usage_mail_bl_headers };

static const char usage_mail_bl_max[] =
  "Maximum number of unique mail addresses to check. Specify zero for\n"
"# unlimited.\n"
"#"
;
Option optMailBlMax		= { "mail-bl-max",	"10",			usage_mail_bl_max };

static const char usage_mail_bl_policy[] =
  "Check if the message contains a black listed mail address found by\n"
"# mail-bl.  Specify one of none, tag, quarantine, reject, or discard.\n"
"#"
;
Option optMailBlPolicy		= { "mail-bl-policy",	"reject",		usage_mail_bl_policy };

static const char usage_mail_bl_domains[] =
  "A list of domain glob-like patterns for which to test against mail-bl,\n"
"# typically free mail services. This reduces the load on public BLs.\n"
"# Specify * to test all domains, empty list to disable.\n"
"#"
;
Option optMailBlDomains		= {
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

#ifdef DROPPED_ADD_HEADERS
static Option optAddHeaders	= { "add-headers",	"-",			"Add extra informational headers when message passes." };
#endif

static Option *optTable[] = {
	&optIntro,
#ifdef DROPPED_ADD_HEADERS
	&optAddHeaders,
#endif
	&optDnsBL,
	DNS_LIST_OPTIONS_TABLE,
	PDQ_OPTIONS_TABLE,
	&optHttpTimeout,
	&optMailBl,
	&optMailBlDomains,
	&optMailBlHeaders,
	&optMailBlMax,
	&optMailBlPolicy,
	&optNsBL,
	&optPolicyBL,
	&optPolicyLinks,
	&optSubjectTag,
	&optTestHelo,
	&optTestLinks,
	&optTestSubDomains,
	&optUriBL,
	NULL
};

/***********************************************************************
 ***
 ***********************************************************************/

DnsList *ip_bl_list;
DnsList *ns_bl_list;
DnsList *uri_bl_list;
DnsList *mail_bl_list;
Vector mail_bl_headers;
Vector mail_bl_domains;

sfsistat
testMail(workspace data, const char *mail)
{
	sfsistat rc;
	const char *list_name;

	rc = SMFIS_CONTINUE;

	if (data->policy == '\0' && VectorLength(data->mail_tested) < optMailBlMax.value
	&& (list_name = dnsListQueryMail(mail_bl_list, data->pdq, mail_bl_domains, data->mail_tested, mail)) != NULL) {
		snprintf(data->reply, sizeof (data->reply), BLACK_LISTED_MAIL_FORMAT, mail, list_name);
		dnsListLog(data->work.qid, mail, list_name);
		data->policy = *optMailBlPolicy.string;
		rc = data->policy == 'r' ? SMFIS_REJECT : SMFIS_CONTINUE;
	}

	smfLog(SMF_LOG_DEBUG, TAG_FORMAT "testMail(%lx, \"%s\") rc=%d policy=%x reply='%s'", TAG_ARGS, (long) data, mail, rc, data->policy, data->reply);

	return rc;
}

static sfsistat
testMailString(workspace data, const char *value)
{
	int rc;
	URI *uri;
	Mime *mime;

	if ((mime = uriMimeCreate(0)) == NULL)
		return SMFIS_CONTINUE;

	mimeHeadersFirst(mime, 0);

	for (rc = SMFIS_CONTINUE; rc == SMFIS_CONTINUE && *value != '\0'; value++) {
		if (mimeNextCh(mime, *value))
			break;

		if ((uri = uriMimeGetUri(mime)) != NULL) {
			rc = testMail(data, uri->uriDecoded);
			uriMimeFreeUri(mime);
		}
	}

	uriMimeFree(mime);

	return rc;
}

static int
testURI(workspace data, URI *uri)
{
	long i;
	char *host, *ip;
	const char *error;
	URI *origin = NULL;
	const char *list_name = NULL;
	int are_different, access, rc = -1;

	if (uri == NULL)
		return 0;

	if (uri->host == NULL)
		goto ignore0;

	/* Session cache for previously PASSED hosts/domains. */
	for (i = 0; i < VectorLength(data->uri_tested); i++) {
		if ((host = VectorGet(data->uri_tested, i)) == NULL)
			continue;

		if (TextInsensitiveCompare(uri->host, host) == 0)
			goto ignore0;
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
	case SMDB_ACCESS_ERROR:
		break;
	case SMDB_ACCESS_REJECT:
		snprintf(data->reply, sizeof (data->reply), "rejected URL host %s", uri->host);
		data->policy = 'r';
		goto error0;
	case SMDB_ACCESS_OK:
		smfLog(SMF_LOG_INFO, TAG_FORMAT "URI <%s> OK", TAG_ARGS, uri->uri);
#ifdef URL_WHITE_LISTS_MESSAGE
/* Only ignore the URL for a white list entry rather than white
 * list the whole message. Consider text/html messages that often
 * contain a DOCTYPE line with a URL to http://www.w3c.org. If
 * you white list w3c.org, you really just want to ignore/skip the
 * DNS BL lookup, because otherwise it would be too simple for
 * spammers to find typical white listed domains and include them
 * to by-pass filters.
 */
		data->work.skipMessage = 1;
#endif
		goto ignore1;
	}

	/* Test and follow redirections so verify that the link returns something valid. */
	if (optTestLinks.value && (error = uriHttpOrigin(uri->uri, &origin)) != NULL) {
		if (error == uriErrorNotHttp || error == uriErrorPort)
			goto ignore0;

		snprintf(data->reply, sizeof (data->reply), "broken URL \"%s\": %s", uri->uri, error);
		data->policy = *optPolicyLinks.string;
		goto error0;
	}

	are_different = origin != NULL && origin->host != NULL && strcmp(uri->host, origin->host) != 0;

	if ((list_name = dnsListQuery(uri_bl_list, data->pdq, NULL, optTestSubDomains.value, uri->host)) != NULL) {
		snprintf(data->reply, sizeof (data->reply), BLACK_LISTED_URL_FORMAT, uri->host, list_name);
		dnsListLog(data->work.qid, uri->host, list_name);
		data->policy = *optPolicyBL.string;
		goto error1;
	}
	if (are_different && (list_name = dnsListQuery(uri_bl_list, data->pdq, NULL, optTestSubDomains.value, origin->host)) != NULL) {
		snprintf(data->reply, sizeof (data->reply), BLACK_LISTED_URL_FORMAT, origin->host, list_name);
		dnsListLog(data->work.qid, origin->host, list_name);
		data->policy = *optPolicyBL.string;
		goto error1;
	}

	if ((list_name = dnsListQueryIP(ip_bl_list, data->pdq, NULL, uri->host)) != NULL) {
		snprintf(data->reply, sizeof (data->reply), BLACK_LISTED_URL_FORMAT, uri->host, list_name);
		dnsListLog(data->work.qid, uri->host, list_name);
		data->policy = *optPolicyBL.string;
		goto error1;
	}
	if (are_different && (list_name = dnsListQueryIP(ip_bl_list, data->pdq, NULL, origin->host)) != NULL) {
		snprintf(data->reply, sizeof (data->reply), BLACK_LISTED_URL_FORMAT, origin->host, list_name);
		dnsListLog(data->work.qid, origin->host, list_name);
		data->policy = *optPolicyBL.string;
		goto error1;
	}

	dnsListLog(data->work.qid, uri->host, NULL);
ignore1:
	(void) VectorAdd(data->uri_tested, strdup(uri->host));
ignore0:
	rc = 0;
error1:
	free(origin);
error0:
	smfLog(SMF_LOG_DEBUG, TAG_FORMAT "testURI(%lx, \"%s\") rc=%d reply='%s'", TAG_ARGS, (long) data, uri->uri, rc, data->reply);

	return rc;
}

static int
testNS(workspace data, const char *host)
{
	const char *list_name;

	if ((list_name = dnsListQueryNs(ns_bl_list, data->pdq, data->ns_tested, host)) != NULL) {
		snprintf(data->reply, sizeof (data->reply), BLACK_LISTED_URL_FORMAT, host, list_name);
		data->policy = *optPolicyBL.string;
		return 1;
	}

	return 0;
}

static int
testList(workspace data, char *query, const char *delim)
{
	URI *uri;
	int i, rc;
	Vector args;
	char *arg, *ptr;

	if (query == NULL)
		return 0;

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

		uri = uriParse(arg, -1);
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

	data->work.ctx = ctx;
	data->work.qid = smfNoQueue;
	data->work.cid = smfOpenProlog(ctx, client_name, raw_client_addr, data->client_addr, sizeof (data->client_addr));

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterOpen(%lx, '%s', [%s])", TAG_ARGS, (long) ctx, client_name, data->client_addr);

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

	access = smfAccessHost(&data->work, MILTER_NAME "-connect:", client_name, data->client_addr, SMDB_ACCESS_OK);

	switch (access) {
#ifdef ENABLE_BLACKLIST
	case SMDB_ACCESS_REJECT:
		/* Report this mail error ourselves, because sendmail/milter API
		 * fails to report xxfi_connect handler rejections.
		 */
		smfLog(SMF_LOG_ERROR, TAG_FORMAT "connection %s [%s] blocked", TAG_ARGS, client_name, data->client_addr);
		return smfReply(&data->work, 550, "5.7.1", "connection %s [%s] blocked", client_name, data->client_addr);
#endif
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
	}

	TextCopy(data->client_name, sizeof (data->client_name), client_name);

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
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
#ifdef ENABLE_BLACKLIST
	case SMDB_ACCESS_REJECT:
		return smfReply(&data->work, 550, "5.7.1", "sender blocked");
#endif
	}

	access = smfAccessAuth(&data->work, MILTER_NAME "-auth:", auth_authen, args[0], NULL, NULL);

	switch (access) {
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
#ifdef ENABLE_BLACKLIST
	case SMDB_ACCESS_REJECT:
		return smfReply(&data->work, 550, "5.7.1", "sender blocked");
#endif
	case SMDB_ACCESS_OK:
		return SMFIS_ACCEPT;
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
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
#ifdef ENABLE_BLACKLIST
	case SMDB_ACCESS_REJECT:
		return smfReply(&data->work, 550, "5.7.1", "recipient blocked");
#endif
	case SMDB_ACCESS_OK:
		data->work.skipMessage = 1;
		return SMFIS_CONTINUE;
	}

	if (testMail(data, data->work.mail->address.string) == SMFIS_REJECT)
		return smfReply(&data->work, 550, NULL, "%s", data->reply);

	return SMFIS_CONTINUE;
}

static sfsistat
filterHeader(SMFICTX *ctx, char *name, char *value)
{
	char *s;
	URI *uri;
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

	/* Currently we ignore URI found in headers. This might change
	 * based on demand (see uri CLI and BarricadeMX which support
	 * testing URI foundin headers).
	 */
	if ((uri = uriMimeGetUri(data->mime)) != NULL) {
		smfLog(SMF_LOG_DIALOG, TAG_FORMAT "clearing uri buffer=%s", TAG_ARGS, TextNull(uri->host));
		uriMimeFreeUri(data->mime);
	}

	for (table = (const char **) VectorBase(mail_bl_headers); *table != NULL; table++) {
		if (TextInsensitiveCompare(name, *table) == 0 && (rc = testMailString(data, value)) != SMFIS_CONTINUE)
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
	int rc;
	URI *uri;
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

			if ((rc = testURI(data, uri)) == 0 && (rc = testNS(data, uri->host)) == 0) {
				if (uri->query == NULL)
					rc = testList(data, uri->path, "&");
				else if ((rc = testList(data, uri->query, "&")) == 0)
					rc = testList(data, uri->query, "/");
				if (rc == 0)
					rc = testList(data, uri->path, "/");
			}

			if (rc == 0 && uriGetSchemePort(uri) == 25) {
				smfLog(SMF_LOG_DEBUG, TAG_FORMAT "checking <%s>...", TAG_ARGS, uri->uriDecoded);
				rc = testMail(data, uri->uriDecoded);
			}

			uriMimeFreeUri(data->mime);
			if (rc != 0)
				break;
		}
	}

	return SMFIS_CONTINUE;
}

static sfsistat
filterEndMessage(SMFICTX *ctx)
{
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterEndMessage");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterEndMessage(%lx)", TAG_ARGS, (long) ctx);

	if (data->work.skipMessage)
		return SMFIS_CONTINUE;

	/* Terminate MIME parsing. */
	if (mimeNextCh(data->mime, EOF) == 0) {
		int rc;
		URI *uri;
		if ((uri = uriMimeGetUri(data->mime)) != NULL) {
			smfLog(SMF_LOG_DIALOG, TAG_FORMAT "checking uri=%s", TAG_ARGS, TextNull(uri->host));

			if ((rc = testURI(data, uri)) == 0 && (rc = testNS(data, uri->host)) == 0) {
				if (uri->query == NULL)
					rc = testList(data, uri->path, "&");
				else if ((rc = testList(data, uri->query, "&")) == 0)
					rc = testList(data, uri->query, "/");
				if (rc == 0)
					rc = testList(data, uri->path, "/");
			}

			if (rc == 0 && uriGetSchemePort(uri) == 25) {
				smfLog(SMF_LOG_DEBUG, TAG_FORMAT "checking <%s>...", TAG_ARGS, uri->uriDecoded);
				rc = testMail(data, uri->uriDecoded);
			}

			uriMimeFreeUri(data->mime);
		}
	}

	if (data->reply[0] != '\0') {
		smfLog(SMF_LOG_INFO, TAG_FORMAT "%s", TAG_ARGS, data->reply);

		switch (data->policy) {
		case 'd':
			return SMFIS_DISCARD;
		case 'r':
			return smfReply(&data->work, 550, NULL, "%s", data->reply);
#ifdef HAVE_SMFI_QUARANTINE
		case 'q':
			if (smfi_quarantine(ctx, data->reply) == MI_SUCCESS)
				return SMFIS_CONTINUE;
			/*@fallthrough@*/
#endif
		case 't':
			if (TextInsensitiveStartsWith(data->subject, optSubjectTag.string) < 0) {
				(void) snprintf(data->line, sizeof (data->line), "%s %s", optSubjectTag.string, data->subject);
				(void) smfHeaderSet(ctx, "Subject", data->line, 1, data->hasSubject);
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

	return SMFIS_CONTINUE;
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
		, NULL			/* Unknown/unimplemented commands */
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
	dnsListFree(ns_bl_list);

	VectorDestroy(mail_bl_domains);
	VectorDestroy(mail_bl_headers);

	smdbClose(smdbAccess);
	smfAtExitCleanUp();
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

	/* Show them the funny farm. */
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

	uriSetTimeout(optHttpTimeout.value * 1000);

	ns_bl_list = dnsListCreate(optNsBL.string);
	ip_bl_list = dnsListCreate(optDnsBL.string);
	uri_bl_list = dnsListCreate(optUriBL.string);
	mail_bl_list = dnsListCreate(optMailBl.string);
	mail_bl_headers = TextSplit(optMailBlHeaders.string, ";, ", 0);
	mail_bl_domains = TextSplit(optMailBlDomains.string, ";, ", 0);

	switch (*optPolicyBL.string) {
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

	switch (*optPolicyLinks.string) {
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

	switch (*optMailBlPolicy.string) {
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

	return smfMainStart(&milter);
}
