# Apache

## Executable PHP extensions

Check which extensions is executing the Apache server. To search them you can execute:

```bash
 grep -R -B1 "httpd-php" /etc/apache2
```

Also, some places where you can find this configuration is:

```bash
/etc/apache2/mods-available/php5.conf
/etc/apache2/mods-enabled/php5.conf
/etc/apache2/mods-available/php7.3.conf
/etc/apache2/mods-enabled/php7.3.conf
```

