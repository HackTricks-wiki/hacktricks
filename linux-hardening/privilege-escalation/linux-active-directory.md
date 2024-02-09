# Linux Active Directory

<details>

<summary><strong>Aprende hacking de AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Equipos Rojos de AWS de HackTricks)</strong></a><strong>!</strong></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión del PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

Una máquina Linux también puede estar presente dentro de un entorno de Active Directory.

Una máquina Linux en un AD podría estar **almacenando diferentes tickets CCACHE dentro de archivos. Estos tickets pueden ser utilizados y abusados como cualquier otro ticket Kerberos**. Para leer estos tickets, necesitarás ser el propietario de usuario del ticket o **root** dentro de la máquina.

## Enumeración

### Enumeración de AD desde Linux

Si tienes acceso a un AD en Linux (o bash en Windows) puedes probar [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) para enumerar el AD.

También puedes consultar la siguiente página para aprender **otras formas de enumerar AD desde Linux**:

{% content-ref url="../../network-services-pentesting/pentesting-ldap.md" %}
[pentesting-ldap.md](../../network-services-pentesting/pentesting-ldap.md)
{% endcontent-ref %}

### FreeIPA

FreeIPA es una **alternativa** de código abierto a Microsoft Windows **Active Directory**, principalmente para entornos **Unix**. Combina un **directorio LDAP completo** con un Centro de Distribución de Claves MIT **Kerberos** para la gestión similar a Active Directory. Utilizando el Sistema de Certificados Dogtag para la gestión de certificados CA y RA, admite la autenticación **multifactor**, incluidas las tarjetas inteligentes. SSSD está integrado para procesos de autenticación Unix. Aprende más al respecto en:

{% content-ref url="../freeipa-pentesting.md" %}
[freeipa-pentesting.md](../freeipa-pentesting.md)
{% endcontent-ref %}

## Jugando con tickets

### Pasar el Ticket

En esta página encontrarás diferentes lugares donde podrías **encontrar tickets Kerberos dentro de un host Linux**, en la siguiente página puedes aprender cómo transformar estos formatos de tickets CCache a Kirbi (el formato que necesitas usar en Windows) y también cómo realizar un ataque PTT:

{% content-ref url="../../windows-hardening/active-directory-methodology/pass-the-ticket.md" %}
[pass-the-ticket.md](../../windows-hardening/active-directory-methodology/pass-the-ticket.md)
{% endcontent-ref %}

### Reutilización de tickets CCACHE desde /tmp

Los archivos CCACHE son formatos binarios para **almacenar credenciales Kerberos** que suelen almacenarse con permisos 600 en `/tmp`. Estos archivos se pueden identificar por su **formato de nombre, `krb5cc_%{uid}`,** que se correlaciona con el UID del usuario. Para la verificación del ticket de autenticación, la **variable de entorno `KRB5CCNAME`** debe establecerse en la ruta del archivo de ticket deseado, lo que permite su reutilización.

Lista el ticket actual utilizado para la autenticación con `env | grep KRB5CCNAME`. El formato es portable y el ticket puede ser **reutilizado configurando la variable de entorno** con `export KRB5CCNAME=/tmp/ticket.ccache`. El formato del nombre del ticket Kerberos es `krb5cc_%{uid}` donde uid es el UID del usuario.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### Reutilización de tickets CCACHE desde el llavero

**Los tickets de Kerberos almacenados en la memoria de un proceso pueden ser extraídos**, especialmente cuando la protección ptrace de la máquina está deshabilitada (`/proc/sys/kernel/yama/ptrace_scope`). Una herramienta útil para este propósito se encuentra en [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), la cual facilita la extracción al inyectarse en sesiones y volcar los tickets en `/tmp`.

Para configurar y utilizar esta herramienta, se siguen los siguientes pasos:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Este procedimiento intentará inyectarse en varias sesiones, indicando el éxito al almacenar los tickets extraídos en `/tmp` con una convención de nombres de `__krb_UID.ccache`.

### Reutilización de tickets CCACHE desde SSSD KCM

SSSD mantiene una copia de la base de datos en la ruta `/var/lib/sss/secrets/secrets.ldb`. La clave correspondiente se almacena como un archivo oculto en la ruta `/var/lib/sss/secrets/.secrets.mkey`. Por defecto, la clave solo es legible si tienes permisos de **root**.

Invocar **`SSSDKCMExtractor`** con los parámetros --database y --key analizará la base de datos y **descifrará los secretos**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
El **blob de caché de credenciales Kerberos se puede convertir en un archivo CCache de Kerberos** utilizable que se puede pasar a Mimikatz/Rubeus.

### Reutilización de tickets CCACHE desde keytab
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Extraer cuentas de /etc/krb5.keytab

Las claves de cuentas de servicio, esenciales para servicios que operan con privilegios de root, se almacenan de forma segura en archivos **`/etc/krb5.keytab`**. Estas claves, similares a contraseñas para servicios, requieren estricta confidencialidad.

Para inspeccionar el contenido del archivo keytab, se puede utilizar **`klist`**. Esta herramienta está diseñada para mostrar detalles de las claves, incluido el **NT Hash** para autenticación de usuario, especialmente cuando se identifica el tipo de clave como 23.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Para los usuarios de Linux, **`KeyTabExtract`** ofrece la funcionalidad para extraer el hash RC4 HMAC, que puede ser aprovechado para reutilizar el hash NTLM.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
En macOS, **`bifrost`** sirve como una herramienta para el análisis de archivos keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Utilizando la información de cuenta y hash extraída, se pueden establecer conexiones a servidores utilizando herramientas como **`crackmapexec`**.
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## Referencias
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión del PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
