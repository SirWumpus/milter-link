LOCAL_CONFIG
Kpopauth hash -a<OK> /etc/mail/popauth
C{allowed_client_names} cst.net cyberstation.net
C{allowed_rcpt_domains} designworksgroup.com

LOCAL_RULESETS
SLocal_check_rcpt
R$*                                         TAB $: $>canonify $1
R$* <@ $* $={allowed_rcpt_domains} . >      TAB $@ OK
R$*                         TAB $: $(popauth $&{client_addr} $: <?> $)
R$*<OK>                     TAB $# OK
R<?>                        TAB $: $&{client_name}
R$* $={allowed_client_names}TAB $@ OK
R$*                         TAB $: $&{client_addr}
R127 . $+                   TAB $@ OK
R$*                         TAB $#error $@ 5.4.0 $: "connections from " $&{client_name} " [" $&{client_addr} "] denied"

#
# Used for testing, since it is not possible to type a $| during testing.
# So to test these rulesets say:
#
#       Start,Local_check_relay host $| addr
#
SStart
R$* $$| $*                  TAB $: $1 $| $2
R   $$| $*                  TAB $:    $| $1
R$* $$|                     TAB $: $1 $|
