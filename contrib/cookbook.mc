dnl -------------------------------------------------------------------
dnl A Sendmail Cookbook
dnl
dnl A collection of assorted Sendmail rules.
dnl
dnl Contributed by Anthony Howe
dnl -------------------------------------------------------------------
dnl 1.

dnl LOCAL_RULESETS
dnl #
dnl # Used for testing checkrelay and check_compact, since it is not possible
dnl # to type a $| during testing.  So to test these rulesets say:
dnl #
dnl #	Start,checkrelay host $| addr
dnl #
dnl SStart
dnl R$* $$| $*			$: $1 $| $2

dnl -------------------------------------------------------------------
dnl 2.

dnl LOCAL_RULESETS
dnl #
dnl # Implement a default GreetPause: rule.
dnl #
dnl SLocal_greet_pause
dnl R<$*><?> $| $*   		$: $1
dnl R$+ $| $+        		$: $>D < $1 > <?> <! GreetPause> < $2 >
dnl R   $| $+        		$: $>A < $1 > <?> <! GreetPause> <>
dnl R<?> <$+>        		$: $>A < $1 > <?> <! GreetPause> <>
dnl R<?> <$*>			$: < $( access GreetPause: $: ? $) > < $1 >
dnl R<?> <$*>			$@
dnl R<$+> <$*>			$# $1

dnl -------------------------------------------------------------------
dnl 3.

dnl LOCAL_RULESETS
dnl #
dnl # Discard all bounced mail instead of rejecting. If you reject the
dnl # null address <>, then you could end up being black listed on
dnl # rfc-ignorant.org and/or being rejected by milter-sender machines.
dnl #
dnl SLocal_check_mail
dnl R$*				$: $>canonify $1
dnl R<@>			$#discard $: discard

dnl -------------------------------------------------------------------
dnl 4.

dnl LOCAL_CONFIG
dnl # map for DNS based blacklist lookups
dnl Kdnsbl dns -R A -T<TMP>

dnl LOCAL_RULESETS
dnl # Defer sbl-xbl.spamhaus.org check until after authentication
dnl #
dnl # DNS based IP address spam list sbl-xbl.spamhaus.org
dnl #
dnl SLocal_check_mail
dnl R$*                     $: < $&{auth_authen} >
dnl R< >                    $: $&{client_addr}
dnl R$-.$-.$-.$-            $: <?> $(dnsbl $4.$3.$2.$1.sbl-xbl.spamhaus.org. $: OK $)
dnl R<?>OK                  $: OKSOFAR
dnl R<?>$+<TMP>             $: TMPOK
dnl R<?>$+                  $#error $@ 5.7.1 $: "rejecting mail from " $&{client_addr} "; see http://www.spamhaus.org/"

dnl -------------------------------------------------------------------
dnl 5.

dnl LOCAL_CONFIG
dnl KhasShell user -vshell
dnl KisAlias hash -m /etc/mail/aliases
dnl
dnl LOCAL_RULESETS
dnl #
dnl # If the sender claims to be within a domain we handle, then
dnl # is it a local user account with a shell from /bin, a virtual
dnl # user mapping, or an alias. Reject if its none of the above.
dnl #
dnl SLocal_check_mail
dnl R$*					$: $1 $| $>canonify $1
dnl R$* $| $+ <@ $* $=w .>		$: $1 $| $2 <@ $3 $4 .> $(access From:$2 @ $3 $4 $: $)
dnl R$* $| $+ <@ $* $=w .>		$: $1 $| $2 <@ $3 $4 .> $(access $2 @ $3 $4 $)
dnl R$* $| $+ <@ $* $=w .> OK $*	$: $1		white listed
dnl R$* $| $+ <@ $* $=w .> RELAY $*	$: $1		white listed
dnl R$* $| $+ <@ $* $=w .> $*		$: $1 $| $2 <@ $3 $4 .> $(hasShell $2 $)
dnl R$* $| $+ <@ $* $=w .> /bin $+	$: $1		is local shell account
dnl R$* $| $+ <@ $* $=w .> $*		$: $1 $| $2 <@ $3 $4 .> $(virtuser $2 @ $3 $4 $: .NOMATCH $)
dnl R$* $| $+ <@ $* $=w .> .NOMATCH	$: $1 $| $2 <@ $3 $4 .> $(isAlias $2 $: .NOMATCH $)
dnl R$* $| $+ <@ $* $=w .> .NOMATCH	$#error $@ 5.7.1 $: "Sender unknown"
dnl R$* $| $*				$: $1		a valid or remote address
dnl # fall through to any other local rules.

dnl -------------------------------------------------------------------
dnl 6.

dnl LOCAL_RULESETS
dnl #
dnl # A variant of FEATURE(`relay_mail_from'), which relays mail based
dnl # on an entry in the virtusertable. This can be abused by spammers.
dnl #
dnl SLocal_check_rcpt
dnl R$*				$: $>canonify $&f
dnl R$+ < @ $=w . >		$: <RESULT: $( virtuser $1 @ $2 $: $) >
dnl R<RESULT: $+ >		$# OK

dnl -------------------------------------------------------------------
dnl 7.

dnl LOCAL_CONFIG
dnl Kassign macro
dnl
dnl LOCAL_RULESETS
dnl #
dnl # Save the envelope recipient (RCPT TO) argument. This may be
dnl # different from {rcpt_addr}.
dnl #
dnl SLocal_check_rcpt
dnl R$*				$: $(assign {rcpt_to} $@ $1 $)
dnl
dnl #
dnl # Relay if the recipient's domain appears in mailertable.
dnl # This rule is appended to the end of ruleset `Relay_ok'.
dnl #
dnl # *** NOTE *** This rule set breaks open relay protection.
dnl # In particular this form of the %-hack will slip through
dnl # this rule set.
dnl #
dnl # 	RCPT TO:<"user%other.example.com"@our.domain.com>
dnl #
dnl # The quotes protect the % from normal detection. Snert
dnl # milters catch this as of this writing. If you use this
dnl # rule set to forward to an internal mail store as it was
dnl # intended, make sure the internal machine does not allow
dnl # the %-hack or use a milter to filter it at the gateway.
dnl #
dnl SRelay_ok
dnl R$*				$: $>canonify $&{rcpt_to}
dnl R$* % $* < @ $+ . >		$#error $@ 5.7.1 $: "550 routed address relaying denied"
dnl R$+ < @ $+ . >		$: $( mailertable $2 $)
dnl R$+ < @ $+ . $+ . >		$: $( mailertable . $3 $)
dnl Resmtp: $+			$@ RELAY

dnl -------------------------------------------------------------------
dnl 8.

dnl LOCAL_CONFIG
dnl RELAY_DOMAIN(`127.0.0.1')dnl
dnl LOCAL_DOMAIN(`[127.0.0.1]')dnl
dnl
dnl LOCAL_RULESETS
dnl #
dnl # Sendmail rules for a "claims to be us" test.
dnl #
dnl # 	http://www.cs.niu.edu/~rickert/cf/bad-ehlo.html
dnl #
dnl # Client software is often broken.  We don't want to reject
dnl # our own users client connections.  Therefore we attempt
dnl # to allow our users to pass the checks.  Otherwise, block
dnl # sites with a HELO/EHLO hostname that is unqualified, or
dnl # is one of our own names
dnl #
dnl # Note that I had to at "127.0.0.1" to class $=R, so that
dnl # local client software would bypass these tests.  I also
dnl # added "[127.0.0.1]" to class $=w, so that the localhost
dnl # IP would count as one of our IPs.
dnl #
dnl SLocal_check_rcpt
dnl R$*				$:$1 $| <$&{auth_authen}>	Get auth info
dnl # Bypass the test for users who have authenticated.
dnl R$* $| <$+>			$:$1				skip if auth
dnl R$* $| <$*>			$:$1 $| <$&{client_addr}>[$&s]	Get connection info
dnl # Bypass for local clients -- IP address starts with $=R
dnl R$* $| <$=R $*>[$*]		$:$1				skip if local client
dnl R$* $| <$&{if_addr}>[$*]	$:$1                            skip if local client
dnl # Bypass a "sendmail -bs" session, which use 0 for client ip address
dnl R$* $| <0>[$*]		$:$1				skip if sendmail -bs
dnl # Reject our IP - assumes "[ip]" is in class $=w
dnl R$* $| <$*> $=w		$#error $@5.7.1 $:"550 bogus HELO name used: " $&s
dnl # Reject our hostname
dnl R$* $| <$*> [$=w]		$#error $@5.7.1 $:"550 bogus HELO name used: " $&s
dnl # Pass anything else with a "." in the domain parameter
dnl R$* $| <$*> [$+.$+]		$:$1				qualified domain ok
dnl # Reject if there was no "." or only an initial or final "."
dnl R$* $| <$*> [$*]		$#error $@5.7.1 $:"550 bogus HELO name used: " $&s
dnl # fall through to any other local rules.

dnl -------------------------------------------------------------------
dnl 9.

dnl SLocal_check_rcpt
dnl #
dnl # Sendmail rules for disabling the %-hack used for routed addresses.
dnl # A RCPT address of the form <user%destination.com@your.domain.com>
dnl # can be relayed if certain FEATURE macros are enabled or the server
dnl # uses catch all address for some domains.
dnl #
dnl R$* % $* @ $+	$#error $@ 5.7.1 $: "550 routed address relaying denied"
dnl # fall through to any other local rules.

dnl -------------------------------------------------------------------
dnl 10.

dnl LOCAL_CONFIG
dnl KsetMacro macro
dnl KgetUid user -vuid
dnl Kdomainuser hash -o /etc/mail/domainuser
dnl
dnl LOCAL_RULESETS
dnl #
dnl # Verify that recipient is valid user-id or address for domain. The
dnl # domainuser is a hash table keyed by domain. The value for each key
dnl # is a space separated list of valid local-parts that can prefix
dnl # the domain.
dnl #
dnl SLocal_check_rcpt
dnl R$*					$: $1 $| $>canonify $1
dnl R$* $| $-				$: $1 $| $2 .  $(getUid $2 $: NOMATCH $)
dnl R$* $| $* . NOMATCH			$#error $@5.7.1 $: "unknown unqualified user " $2
dnl R$* $| $- . $-			$: $1
dnl R$* $| $+ <@ $+ .>			$: $1 $| $2 <@ $3 .> $(domainuser $3 $: .NOMATCH $)
dnl R$* $| $* . NOMATCH			$#error $@5.7.1 $: "unknown domain"
dnl R$* $| $+ <@ $+ .> $+		$: $1 $| $2 <@ $3 .> $>inlist $2 $| $4
dnl R$* $| $+ <@ $+ .>			$#error $@5.7.1 $: "unknown address"
dnl R$* $| $*				$: $1
dnl # fall through to any other local rules.
dnl
dnl Sinlist
dnl R$+ $|				$@
dnl R$+ $| $- $*			$: $(setMacro {is_member} $@ $1 $) < $2 > $3
dnl R< $&{is_member} > $*		$@ $&{is_member}
dnl R< $+ > $*				$: $>inlist $&{is_member} $| $2

dnl -------------------------------------------------------------------
dnl 11.

dnl UNTESTED

dnl LOCAL_RULESETS
dnl #
dnl # Implement missing PTR rejection with IP white list lookup in access.db.
dnl #
dnl # $1 client_name
dnl # $2 client_addr
dnl #
dnl SLocal_greet_pause
dnl R$* $| $+      		$: $>A < $2 > <?> <! NoPtr> < $&{client_resolve} >
dnl R<?> < FAIL >		$#error $@ 5.7.1 $: "No PTR for " $&{client_addr} " found"


dnl -------------------------------------------------------------------
dnl 12.

dnl LOCAL_CONFIG
dnl # This hash file contains full IP address for keys and OK for the
dnl # value. Any other value will cause the IP to be ignored.
dnl # eg. 192.168.1.33		OK
dnl #     192.168.1.1		NO
dnl Kallowed_ip hash -o /etc/mail/allowed-ip
dnl
dnl # This hash file contains domain names or email address for the keys
dnl # and OK for the value. Any other value will cause the record to be
dnl # ignored.
dnl # eg. example.com           OK
dnl #     user@other.com        OK
dnl #     other.com             NO
dnl Kallowed_domain hash -o /etc/mail/allowed-domain
dnl
dnl LOCAL_RULESETS
dnl # Accept recipients for domains that lastspam handles and comes from
dnl # lastspam mail servers. If the recipient domain is one lastspam is
dnl # responsible for but comes from some unknown IP, reject the recipient.
dnl # Any other domain/IP combinations are handled normally.
dnl SLocal_check_rcpt
dnl R$*                        	$: $1 $| $>canonify $1
dnl R$* $| $+ <@ $+ .>         	$: $1 $| $2 <@ $3 .> $(allowed_domain $2@$3 $: $)
dnl R$* $| $+ <@ $+ .>         	$: $1 $| $2 <@ $3 .> $(allowed_domain $3 $: $)
dnl R$* $| $+ <@ $+ .> OK      	$: $1 $| OK $&{client_addr}
dnl R$* $| OK $+               	$: $1 $| OK $(allowed_ip $2 $: $)
dnl R$* $| OK OK               	$#OK
dnl R$* $| OK $*               	$#error $@ 5.7.1 $: $&{client_addr} " not responsible for domain"
dnl R$* $| $*                  	$: $1
