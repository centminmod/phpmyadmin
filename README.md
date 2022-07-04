phpmyadmin.sh auto installer for Centmin Mod LEMP stack only

Currently in beta testing. Install instructions at http://centminmod.com/addon_phpmyadmin.html

Related log files for troubleshooting & diagnostics

* /var/log/php-fpm/www-slowmyadmin.log
* /var/log/php_myadmin_error.log
* /var/log/nginx/localhost_ssl.access.log
* /var/log/nginx/localhost_ssl.error.log

### Uninstall phpmyadmin.sh previously installed phpmyadmin instance

```
/root/tools/phpmyadmin_uninstall.sh
```

### To Uninstall phpmyadmin.sh installed phpmyadmin & reinstall phpmyadmin latest 5.0.x stable version

```
# uninstall existing phpmyadmin install
/root/tools/phpmyadmin_uninstall.sh

# download phpmyadmin.sh
cd /usr/local/src/centminmod/addons
wget --no-check-certificate https://github.com/centminmod/phpmyadmin/raw/master/phpmyadmin.sh -O phpmyadmin.sh

# permissions
chmod 0700 /usr/local/src/centminmod/addons/phpmyadmin.sh

# install phpmyadmin lastest stable
./phpmyadmin.sh install
```