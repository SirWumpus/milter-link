divert(-1)dnl
#
# Copyright (c) 1997-2000 Jan Kr"uger <jk@digitalanswers.de>
#  Stripped down to just the necessary functions for dracd.db
#  usage in 2005 by Mike Elliott <elliott@msen.com>.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# Further information can be found at http://www.gnu.org/.
# 
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
divert(0)dnl
VERSIONID(`dracd.m4  $Revision: 1.25 $ $Date: 2005/07/30 18:02:29 $ (elliott@msen.com)')
LOCAL_CONFIG
# ================== DATABASE =================================
# database definitions
# =============================================================
ifdef(`_CL_STORAGE_DEFINED_', `dnl', `dnl
define(`_CL_STORAGE_DEFINED_')dnl
Kstorage macro
')
ifdef(`DATABASE_MAP_TYPE',, `define(`DATABASE_MAP_TYPE', `hash')')dnl
dnl * we need the local_senduser ruleset for two options
ifdef(`_POPAUTH_USER_', `define(`_LOCAL_SENDUSER_')')dnl
ifdef(`_CHECK_LOCALUSER_', `define(`_LOCAL_SENDUSER_')')dnl
dnl *
ifdef(`_LOCAL_SENDUSER_', `dnl
# definition of local user check map
Kpasswd user -vname
Kalias implicit ALIAS_FILE
Klocal_user sequence _LOCALUSER_SEQUENCE_
', `dnl')
ifdef(`_POPAUTH_DB_',dnl
# definition of popauth
Kpopauth ifelse(_POPAUTH_DB_, `',
DATABASE_MAP_TYPE` /etc/mail/popauth', `_POPAUTH_DB_')
, `dnl')
# ================== ENVELOPE =================================
ifdef(`_X_POPAUTH_INFO_', `dnl
# macro for header field X-Popauth-Info
H?${popauth_info}?X-Popauth-Info: ${popauth_info}
', `dnl')
ifdef(`_X_CLIENT_INFO_', `dnl
# macro for header field X-Client-Info
H?${client_info}?X-Client-Info: ${client_info}
', `dnl')
LOCAL_RULESETS
# ================== ENVELOPE =================================
# Local_check_rcpt
# =============================================================
SLocal_check_rcpt
# check for deferred delivery mode, repeated early to preserve order
R$*		$: < ${deliveryMode} > $1
R< d > $*	$@ deferred
R< $* > $*	$: $2

ifdef(`_POPAUTH_', `dnl
# check the client_addr against the popauth-database
R$* 			$: $1 $| <$&{client_addr}>
ifdef(`_POPAUTH_DB_', `dnl
R$* $| <$+>		$: $1 $| <$(popauth $2 $: ? $)> <$2>', 
`R$* $| <$+>		$: $1 $| $>SearchList <!popauth> $| <$2> <>')
ifdef(`_POPAUTH_USER_', `dnl
# check sender@client_addr against popauth.db
R$* $| <?> 		$: $1 $| <?> $| $>Local_senduser $&f
ifdef(`_POPAUTH_DB_', `dnl
R$* $| <?>  $| $+	$: $1 $| <$(popauth $2@$&{client_addr} $: ? $)>',
`R$* $| <?>  $| $+	$: $1 $| $>SearchList <!popauth> $| <$2@$&{client_addr}> <>')', `dnl')
R$* $| <?> $*		$: $1
ifdef(`_X_POPAUTH_INFO_', `dnl
# add the RHS of the popauth.db to the header-field X-Popauth-Info
R$* $| <@NOINFO> $*	$: $1 $| <>
R$* $| <$+> $*		$: $1 $| <$(storage {popauth_info} $@ $2 $)>', `dnl')	
R$* $| <$*> $*		$#OK
R$* $| $*		$: $1', `dnl')

ifdef(`_LOCAL_SENDUSER_',`dnl
# ================== ENVELOPE =================================
# Local_senduser
# =============================================================
SLocal_senduser
R$*		$: $>Parse0 $>3 $1  
R$*<@$=w.>$*	$>3 $1 $3
R$+ + $*	$: $1     
R$+		$: $(local_user $1 $: ?UNKNOWN $)
', `dnl')
