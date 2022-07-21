#!/bin/bash

if [[ $EUID -ne 0 ]]; then
	echo "Please run this script as root" 1>&2
	exit 1
fi

### Functions ###

install_postfix_dovecot() {
	echo "Installing Dependicies"
	
	read -p "Enter your mail server's domain: " -r primary_domain
	read -p "Enter IP's to allow Relay (if none just hit enter): " -r relay_ip
	echo "Configuring Postfix"

	cat <<-EOF > /etc/postfix/main.cf
	smtpd_banner = \$myhostname ESMTP \$mail_name (Debian/GNU)
	biff = no
	append_dot_mydomain = no
	readme_directory = no
	smtpd_tls_cert_file=/etc/letsencrypt/live/${primary_domain}/fullchain.pem
	smtpd_tls_key_file=/etc/letsencrypt/live/${primary_domain}/privkey.pem
	smtpd_tls_security_level = may
	smtp_tls_security_level = encrypt
	smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache
	smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache
	smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
	myhostname = ${primary_domain}
	alias_maps = hash:/etc/aliases
	alias_database = hash:/etc/aliases
	myorigin = /etc/mailname
	mydestination = ${primary_domain}, localhost.com, , localhost
	relayhost =
	mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128 ${relay_ip}
	mailbox_command = procmail -a "\$EXTENSION"
	mailbox_size_limit = 0
	recipient_delimiter = +
	inet_interfaces = all
	inet_protocols = ipv4
	milter_default_action = accept
	milter_protocol = 6
	smtpd_milters = inet:12301,inet:localhost:54321
	non_smtpd_milters = inet:12301,inet:localhost:54321
	EOF

	cat <<-EOF >> /etc/postfix/master.cf
	submission inet n       -       -       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_wrappermode=no
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_recipient_restrictions=permit_mynetworks,permit_sasl_authenticated,reject
  -o milter_macro_daemon_name=ORIGINATING
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth
	EOF

	echo "Configuring Opendkim"

	mkdir -p "/etc/opendkim/keys/${primary_domain}"
	cp /etc/opendkim.conf /etc/opendkim.conf.orig

	cat <<-EOF > /etc/opendkim.conf
	domain								*
	AutoRestart						Yes
	AutoRestartRate				10/1h
	Umask									0002
	Syslog								Yes
	SyslogSuccess					Yes
	LogWhy								Yes
	Canonicalization			relaxed/simple
	ExternalIgnoreList		refile:/etc/opendkim/TrustedHosts
	InternalHosts					refile:/etc/opendkim/TrustedHosts
	KeyFile								/etc/opendkim/keys/${primary_domain}/mail.private
	Selector							mail
	Mode									sv
	PidFile								/var/run/opendkim/opendkim.pid
	SignatureAlgorithm		rsa-sha256
	UserID								opendkim:opendkim
	Socket								inet:12301@localhost
	EOF

	cat <<-EOF > /etc/opendkim/TrustedHosts
	127.0.0.1
	localhost
	${primary_domain}
	${relay_ip}
	EOF

	cd "/etc/opendkim/keys/${primary_domain}" || exit
	opendkim-genkey -s mail -d "${primary_domain}"
	echo 'SOCKET="inet:12301"' >> /etc/default/opendkim
	chown -R opendkim:opendkim /etc/opendkim

	echo "Configuring opendmarc"

	cat <<-EOF > /etc/opendmarc.conf
	AuthservID ${primary_domain}
	PidFile /var/run/opendmarc.pid
	RejectFailures false
	Syslog true
	TrustedAuthservIDs ${primary_domain}
	Socket  inet:54321@localhost
	UMask 0002
	UserID opendmarc:opendmarc
	IgnoreHosts /etc/opendmarc/ignore.hosts
	HistoryFile /var/run/opendmarc/opendmarc.dat
	EOF

	mkdir "/etc/opendmarc/"
	echo "localhost" > /etc/opendmarc/ignore.hosts
	chown -R opendmarc:opendmarc /etc/opendmarc

	echo 'SOCKET="inet:54321"' >> /etc/default/opendmarc

	echo "Configuring Dovecot"

	cat <<-EOF > /etc/dovecot/dovecot.conf
	disable_plaintext_auth = no
	mail_privileged_group = mail
	mail_location = mbox:~/mail:INBOX=/var/mail/%u

	userdb {
	  driver = passwd
	}

	passdb {
	  args = %s
	  driver = pam
	}

	protocols = " imap"

	protocol imap {
	  mail_plugins = " autocreate"
	}

	plugin {
	  autocreate = Trash
	  autocreate2 = Sent
	  autosubscribe = Trash
	  autosubscribe2 = Sent
	}

	service imap-login {
	  inet_listener imap {
	    port = 0
	  }
	  inet_listener imaps {
	    port = 993
	  }
	}

	service auth {
	  unix_listener /var/spool/postfix/private/auth {
	    group = postfix
	    mode = 0660
	    user = postfix
	  }
	}

	ssl=required
	ssl_cert = </etc/letsencrypt/live/${primary_domain}/fullchain.pem
	ssl_key = </etc/letsencrypt/live/${primary_domain}/privkey.pem
	EOF

	read -p "What user would you like to assign to recieve email for Root: " -r user_name
	echo "${user_name}: root" >> /etc/aliases
	echo "Root email assigned to ${user_name}"

	echo "Restarting Services"
	service postfix restart
	service opendkim restart
	service opendmarc restart
	service dovecot restart

	echo "Checking Service Status"
	service postfix status
	service opendkim status
	service opendmarc status
	service dovecot status
}

function get_dns_entries(){
	extip=$(ifconfig|grep 'Link encap\|inet '|awk '!/Loopback|:127./'|tr -s ' '|grep 'inet'|tr ':' ' '|cut -d" " -f4)
	domain=$(ls /etc/opendkim/keys/ | head -1)
	fields=$(echo "${domain}" | tr '.' '\n' | wc -l)
	dkimrecord=$(cut -d '"' -f 2 "/etc/opendkim/keys/${domain}/mail.txt" | tr -d "[:space:]")

	if [[ $fields -eq 2 ]]; then
		cat <<-EOF > dnsentries.txt
		DNS Entries for ${domain}:

		====================================================================
		Namecheap - Enter under Advanced DNS

		Record Type: A
		Host: @
		Value: ${extip}
		TTL: 5 min

		Record Type: TXT
		Host: @
		Value: v=spf1 ip4:${extip} -all
		TTL: 5 min

		Record Type: TXT
		Host: mail._domainkey
		Value: ${dkimrecord}
		TTL: 5 min

		Record Type: TXT
		Host: ._dmarc
		Value: v=DMARC1; p=reject
		TTL: 5 min

		Change Mail Settings to Custom MX and Add New Record
		Record Type: MX
		Host: @
		Value: ${domain}
		Priority: 10
		TTL: 5 min
		EOF
		cat dnsentries.txt
	else
		prefix=$(echo "${domain}" | rev | cut -d '.' -f 3- | rev)
		cat <<-EOF > dnsentries.txt
		DNS Entries for ${domain}:

		====================================================================
		Namecheap - Enter under Advanced DNS

		Record Type: A
		Host: ${prefix}
		Value: ${extip}
		TTL: 5 min

		Record Type: TXT
		Host: ${prefix}
		Value: v=spf1 ip4:${extip} -all
		TTL: 5 min

		Record Type: TXT
		Host: mail._domainkey.${prefix}
		Value: ${dkimrecord}
		TTL: 5 min

		Record Type: TXT
		Host: ._dmarc
		Value: v=DMARC1; p=reject
		TTL: 5 min

		Change Mail Settings to Custom MX and Add New Record
		Record Type: MX
		Host: ${prefix}
		Value: ${domain}
		Priority: 10
		TTL: 5 min
		EOF
		cat dnsentries.txt
	fi

}

PS3="Server Setup Script - Pick an option: "
options=("Install Mail Server" "Get DNS Entries")
select opt in "${options[@]}" "Quit"; do

    case "$REPLY" in

    #Prep

		1) install_postfix_dovecot;;

		2) get_dns_entries;;


    $(( ${#options[@]}+1 )) ) echo "Goodbye!"; break;;
    *) echo "Invalid option. Try another one.";continue;;

    esac

done
