#!/bin/bash
#################################################
# phpmyadmin installer for Centmin Mod centminmod.com
# written by George Liu (eva2000) vbtechsupport.com
#################################################
VER='0.0.1'
#################################################
UPDATEDIR='/root/tools'
BASEDIR='/usr/local/nginx/html'
DIRNAME=$(echo "${RANDOM}_mysqladmin${RANDOM}")

SALT=$(openssl rand 8 -base64)
USER=$(echo "admin${SALT}")
PASS=$(openssl rand 20 -base64)
BLOWFISH=$(openssl rand 30 -base64)
CURRENTIP=$(echo $SSH_CLIENT | awk '{print $1}')
USERNAME='phpmyadmin'

SSLHNAME=$(uname -n)

VERSIONALLOW='1.2.3-eva2000.04'
#################################################
# Setup Colours
black='\E[30;40m'
red='\E[31;40m'
green='\E[32;40m'
yellow='\E[33;40m'
blue='\E[34;40m'
magenta='\E[35;40m'
cyan='\E[36;40m'
white='\E[37;40m'

boldblack='\E[1;30;40m'
boldred='\E[1;31;40m'
boldgreen='\E[1;32;40m'
boldyellow='\E[1;33;40m'
boldblue='\E[1;34;40m'
boldmagenta='\E[1;35;40m'
boldcyan='\E[1;36;40m'
boldwhite='\E[1;37;40m'

Reset="tput sgr0"      #  Reset text attributes to normal
                       #+ without clearing screen.

cecho ()                     # Coloured-echo.
                             # Argument $1 = message
                             # Argument $2 = color
{
message=$1
color=$2
echo -e "$color$message" ; $Reset
return
}
#################################################
VERCHECK=$(cat /etc/centminmod-release)

if [[ "$VERCHECK" != "$VERSIONALLOW" ]]; then
	cecho "---------------------------------------------------------------" $boldgreen
	cecho "$0 script requires centmin.sh from" $boldyellow
	cecho "  Centmin Mod version: $VERSIONALLOW" $boldyellow
	cecho "  And recompiling PHP via menu option #5" $boldyellow
	cecho "  Aborting script..." $boldyellow
	cecho "---------------------------------------------------------------" $boldgreen
	exit
fi

if [[ ! -f /usr/local/nginx/conf/phpmyadmin_check && "$1" = 'install' ]]; then
	echo "phpmyadmin_install='y'" > /usr/local/nginx/conf/phpmyadmin_check
elif [[ -f /usr/local/nginx/conf/phpmyadmin_check ]]; then
	cecho "---------------------------------------------------------------" $boldyellow
	cecho "detected phpmyadmin install that already exists" $boldgreen
	cecho "aborting..." $boldgreen
	cecho "---------------------------------------------------------------" $boldyellow
	exit
fi
#################################################
usercreate() {

	useradd -s /sbin/nologin -d /home/${USERNAME}/ -G nginx ${USERNAME}
	USERID=$(id ${USERNAME})
	cecho "---------------------------------------------------------------" $boldgreen
	cecho "Create User: $USERNAME" $boldyellow
	cecho "$USERID" $boldyellow
	cecho "---------------------------------------------------------------" $boldgreen
	echo ""

}

#################################################
myadmininstall() {

if [[ ! -f /usr/bin/git ]]; then
	cecho "---------------------------------------------------------------" $boldyellow
	cecho "Installing git..." $boldgreen
	cecho "---------------------------------------------------------------" $boldyellow
	cecho "yum -q -y install git --disablerepo=CentALT" $boldgreen
	yum -q -y install git --disablerepo=CentALT
	echo ""
fi

cd $BASEDIR
git clone --depth=1 git://github.com/phpmyadmin/phpmyadmin.git $DIRNAME
cd $DIRNAME
git checkout -t origin/STABLE

cp config.sample.inc.php config.inc.php
chmod o-rw config.inc.php

replace 'a8b7c6d' "${BLOWFISH}" -- config.inc.php

sed -i 's/?>//g' config.inc.php
echo "\$cfg['ForceSSL'] = 'true';" >> config.inc.php
echo "\$cfg['ExecTimeLimit'] = '7200';" >> config.inc.php
echo "\$cfg['MemoryLimit'] = '256M';" >> config.inc.php
echo "\$cfg['ShowDbStructureCreation'] = 'true';" >> config.inc.php
echo "\$cfg['ShowDbStructureLastUpdate'] = 'true';" >> config.inc.php
echo "\$cfg['ShowDbStructureLastCheck'] = 'true';" >> config.inc.php
echo "?>" >> config.inc.php

chown ${USERNAME}:nginx ${BASEDIR}/${DIRNAME}
chown -R ${USERNAME}:nginx ${BASEDIR}/${DIRNAME}
chmod g+s ${BASEDIR}/${DIRNAME}

if [[ ! -f "/usr/local/nginx/conf/phpmyadmin.conf" ]]; then

	cecho "---------------------------------------------------------------" $boldyellow
	cecho "Setup /usr/local/nginx/conf/phpmyadmin.conf ..." $boldgreen
	cecho "---------------------------------------------------------------" $boldyellow

cecho "---------------------------------------------------------------" $boldyellow
cecho "python /usr/local/nginx/conf/htpasswd.py -c -b /usr/local/nginx/conf/htpassphpmyadmin $USER $PASS" $boldgreen
cecho "---------------------------------------------------------------" $boldyellow
python /usr/local/nginx/conf/htpasswd.py -c -b /usr/local/nginx/conf/htpassphpmyadmin $USER $PASS 

history -d $((HISTCMD-2))

echo ""
echo "\cp -af /usr/local/nginx/conf/php.conf /usr/local/nginx/conf/php_${DIRNAME}.conf"
\cp -af /usr/local/nginx/conf/php.conf /usr/local/nginx/conf/php_${DIRNAME}.conf

sed -i 's/fastcgi_pass   127.0.0.1:9000/#fastcgi_pass   127.0.0.1:9001/g' /usr/local/nginx/conf/php_${DIRNAME}.conf

replace '#fastcgi_param HTTPS on;' 'fastcgi_param HTTPS on;' -- /usr/local/nginx/conf/php_${DIRNAME}.conf

sed -i 's/#fastcgi_pass   unix:\/tmp\/php5-fpm.sock/fastcgi_pass   unix:\/tmp\/phpfpm_myadmin.sock/g' /usr/local/nginx/conf/php_${DIRNAME}.conf

cat > "/usr/local/nginx/conf/phpmyadmin.conf" <<EOF
location ^~ /${DIRNAME}/ {
	rewrite ^/(.*) https://${SSLHNAME}/\$1 permanent;
}
EOF

sed -i "s/include \/usr\/local\/nginx\/conf\/staticfiles.conf;/include \/usr\/local\/nginx\/conf\/phpmyadmin.conf;\ninclude \/usr\/local\/nginx\/conf\/staticfiles.conf;/g" /usr/local/nginx/conf/conf.d/virtual.conf

cecho "---------------------------------------------------------------" $boldyellow

cat /usr/local/nginx/conf/conf.d/virtual.conf

cecho "---------------------------------------------------------------" $boldyellow

cat > "/usr/local/nginx/conf/phpmyadmin_https.conf" <<END
location ^~ /${DIRNAME}/ {
	#try_files \$uri \$uri/ /${DIRNAME}/index.php?\$args;
	include /usr/local/nginx/conf/php_${DIRNAME}.conf;

	auth_basic      "Private Access";
	auth_basic_user_file  /usr/local/nginx/conf/htpassphpmyadmin;
	allow 127.0.0.1;
	allow ${CURRENTIP};
	deny all;
}
END

	cecho "---------------------------------------------------------------" $boldyellow
	cecho "cat /usr/local/nginx/conf/phpmyadmin.conf" $boldgreen
	cecho "---------------------------------------------------------------" $boldyellow

cat /usr/local/nginx/conf/phpmyadmin.conf

	cecho "---------------------------------------------------------------" $boldyellow
	cecho "cat /usr/local/nginx/conf/phpmyadmin_https.conf" $boldgreen
	cecho "---------------------------------------------------------------" $boldyellow

cat /usr/local/nginx/conf/phpmyadmin_https.conf

	cecho "---------------------------------------------------------------" $boldyellow

# php-fpm pool setup

if [[ ! -f /usr/local/nginx/conf/phpfpmd/phpfpm_myadmin.conf ]]; then
	echo ""
	cecho "touch /usr/local/nginx/conf/phpfpmd/phpfpm_myadmin.conf" $boldgreen
	touch /usr/local/nginx/conf/phpfpmd/phpfpm_myadmin.conf
	echo ""

CHECKPOOLDIR=$(grep ';include=\/usr\/local\/nginx\/conf\/phpfpmd\/\*.conf' /usr/local/etc/php-fpm.conf)

if [[ ! -z "$CHECKPOOLDIR" ]]; then
	sed -i 's/;include=\/usr\/local\/nginx\/conf\/phpfpmd\/\*.conf/include=\/usr\/local\/nginx\/conf\/phpfpmd\/\*.conf/g' /usr/local/etc/php-fpm.conf
fi

CHECKPOOL=$(grep '\[phpmyadmin\]' /usr/local/nginx/conf/phpfpmd/phpfpm_myadmin.conf)

if [[ -z "$CHECKPOOL" ]]; then

cat >> "/usr/local/nginx/conf/phpfpmd/phpfpm_myadmin.conf" <<EOF
[phpmyadmin]
user = phpmyadmin
group = nginx

;listen = 127.0.0.1:9001
listen = /tmp/phpfpm_myadmin.sock
listen.allowed_clients = 127.0.0.1

pm = ondemand
pm.max_children = 5
; Default Value: min_spare_servers + (max_spare_servers - min_spare_servers) / 2
pm.start_servers = 1
pm.min_spare_servers = 1
pm.max_spare_servers = 3
pm.max_requests = 500

pm.process_idle_timeout = 10s;

rlimit_files = 65536
rlimit_core = 0

; The timeout for serving a single request after which the worker process will
; be killed. This option should be used when the 'max_execution_time' ini option
; does not stop script execution for some reason. A value of '0' means 'off'.
; Available units: s(econds)(default), m(inutes), h(ours), or d(ays)
; Default Value: 0
;request_terminate_timeout = 0
;request_slowlog_timeout = 0
slowlog = /var/log/php-fpm/www-slowmyadmin.log

security.limit_extensions = .php .php3 .php4 .php5

php_admin_value[open_basedir] = ${BASEDIR}/${DIRNAME}:/tmp
EOF

fi # CHECKPOOL

fi # /usr/local/nginx/conf/phpfpmd/phpfpm_myadmin.conf

service nginx restart
service php-fpm restart

fi

}

sslvhost() {

cecho "---------------------------------------------------------------" $boldyellow
cecho "SSL Vhost Setup..." $boldgreen
cecho "---------------------------------------------------------------" $boldyellow
echo ""

mkdir -p /usr/local/nginx/conf/ssl
cd /usr/local/nginx/conf/ssl

cecho "---------------------------------------------------------------" $boldyellow
cecho "Generating self signed SSL certificate..." $boldgreen
sleep 10
cecho "Just hit enter at each of the prompts" $boldgreen
cecho "---------------------------------------------------------------" $boldyellow
echo ""
sleep 10

openssl genrsa -out ${SSLHNAME}.key 1024
openssl req -new -key ${SSLHNAME}.key -out ${SSLHNAME}.csr
openssl x509 -req -days 36500 -in ${SSLHNAME}.csr -signkey ${SSLHNAME}.key -out ${SSLHNAME}.crt

cat > "/usr/local/nginx/conf/conf.d/phpmyadmin_ssl.conf"<<SSLEOF
# https SSL SPDY phpmyadmin
server {
        listen 443 ssl spdy;
            server_name ${SSLHNAME};
            root   html;

        ssl_certificate      /usr/local/nginx/conf/ssl/${SSLHNAME}.crt;
        ssl_certificate_key  /usr/local/nginx/conf/ssl/${SSLHNAME}.key;
        ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;
        ssl_session_cache      shared:SSL:10m;
        ssl_session_timeout  10m;
        ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-RC4-SHA:ECDHE-RSA-AES128-SHA:AES128-GCM-SHA256:RC4:HIGH:!MD5:!aNULL:!EDH:!CAMELLIA;
        ssl_prefer_server_ciphers   on;
        add_header Alternate-Protocol  443:npn-spdy/2;

  # limit_conn limit_per_ip 16;
  # ssi  on;

        access_log              /var/log/nginx/localhost.access.log     main buffer=32k;
        error_log               /var/log/nginx/localhost.error.log      error;

# ngx_pagespeed & ngx_pagespeed handler
#include /usr/local/nginx/conf/pagespeed.conf;
#include /usr/local/nginx/conf/pagespeedhandler.conf;
#include /usr/local/nginx/conf/pagespeedstatslog.conf;

  location / {


  }
  include /usr/local/nginx/conf/phpmyadmin_https.conf;
  include /usr/local/nginx/conf/staticfiles.conf;
  include /usr/local/nginx/conf/php.conf;
  include /usr/local/nginx/conf/drop.conf;
  include /usr/local/nginx/conf/errorpage.conf;
}
SSLEOF

service nginx restart
service php-fpm restart

}

#################################################
myadminupdater() {

if [[ ! -d "$UPDATEDIR" ]]; then
	mkdir -p $UPDATEDIR
fi

if [[ ! -f "/root/tools/phpmyadmin_update.sh" ]]; then
cecho "---------------------------------------------------------------" $boldyellow
cecho "Create update script:" $boldgreen
cecho "/root/tools/phpmyadmin_update.sh" $boldgreen
cecho "---------------------------------------------------------------" $boldyellow

cat > "/root/tools/phpmyadmin_update.sh" <<EOF
#!/bin/bash
cd ${BASEDIR}/${DIRNAME}
git pull -q

chown ${USERNAME}:nginx ${BASEDIR}/${DIRNAME}
chown -R ${USERNAME}:nginx ${BASEDIR}/${DIRNAME}
EOF

chmod 0700 /root/tools/phpmyadmin_update.sh

fi

}

#################################################
myadminmsg() {

echo ""
cecho "---------------------------------------------------------------" $boldyellow
cecho "Password protected ${DIRNAME}" $boldgreen
cecho "at path ${BASEDIR}/${DIRNAME}" $boldgreen
cecho "  WEB url: " $boldgreen
echo ""
cecho "  https://${SSLHNAME}/${DIRNAME}" $boldgreen
echo ""
cecho "Login with your MySQL root username / password" $boldgreen
cecho "---------------------------------------------------------------" $boldyellow
echo ""
cecho "Username: $USER" $boldgreen
cecho "Password: $PASS" $boldgreen
cecho "Allowed IP address: ${CURRENTIP}" $boldgreen
echo ""
cecho "---------------------------------------------------------------" $boldyellow
cecho "SSL vhost: /usr/local/nginx/conf/conf.d/phpmyadmin_ssl.conf" $boldgreen
cecho "php-fpm includes: /usr/local/nginx/conf/php_${DIRNAME}.conf" $boldgreen
cecho "php-fpm pool conf: /usr/local/nginx/conf/phpfpmd/phpfpm_myadmin.conf" $boldgreen
cecho "---------------------------------------------------------------" $boldyellow
echo ""

}
#################################################
case "$1" in
install)
	usercreate
	myadmininstall
	sslvhost
	myadminupdater
	myadminmsg
;;
*)
	echo "$0 install"
;;
esac
exit