# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

Las versiones recientes de Windows introdujeron **compatibilidad del cliente SMB con puertos TCP alternativos**. Esta función puede abusarse para convertir la **autenticación NTLM local** en una **escalada de privilegios local a SYSTEM** cuando el atacante puede:<sup>[[1]](#references)</sup>

1. Abrir una conexión SMB a un listener controlado por el atacante en un **puerto distinto de 445**
2. Mantener activa esa conexión TCP
3. Forzar a un **cliente local privilegiado** a acceder a la **misma ruta de recurso compartido SMB**
4. Relay de la **autenticación NTLM local** resultante de vuelta al servicio SMB real de la máquina

Esta es la primitive detrás de **CVE-2026-24294**, parcheada en **marzo de 2026**.<sup>[[1]](#references)[[4]](#references)</sup>

## Por qué funciona

El antiguo truco de reflection CMTI / serialized-SPN se describe aquí:

{{#ref}}
../ntlm/README.md
{{#endref}}

Esta variante más reciente **no** necesita un hostname marshalled. En su lugar, abusa de dos comportamientos del cliente SMB:<sup>[[1]](#references)</sup>

- **Compatibilidad con puertos alternativos** en **Windows 11 24H2** y **Windows Server 2025**, expuesta a los usuarios mediante `net use \\host\share /tcpport:<port>`
- **Reutilización / multiplexing de conexiones SMB**, donde varias sesiones autenticadas pueden utilizar la misma conexión TCP

Esto significa que un usuario con pocos privilegios puede crear primero una conexión TCP desde el cliente SMB hacia un servidor SMB del atacante en un puerto alto y, después, forzar a un servicio privilegiado a acceder a la **misma ruta UNC exacta**. Si Windows decide reutilizar la conexión TCP existente, el intercambio NTLM privilegiado se envía a través del transporte controlado por el atacante y puede hacerse relay al servidor SMB local.<sup>[[1]](#references)</sup>

## Prerrequisitos

- El objetivo admite puertos SMB alternativos:<sup>[[2]](#references)</sup>
- **Windows 11 24H2** o posterior
- **Windows Server 2025** o posterior
- El atacante puede ejecutar un servidor SMB local o remoto en un puerto alto elegido
- El atacante puede forzar a un servicio privilegiado a acceder a una ruta UNC
- La autenticación privilegiada debe ser **autenticación NTLM local**
- El objetivo debe permitir relay:<sup>[[1]](#references)</sup>
- Synacktiv informó que funcionaba de forma predeterminada en **Windows Server 2025**
- Su chain **no** funcionó en **Windows 11 24H2** porque el SMB saliente signing está aplicado de forma predeterminada

## Userland e internals

Desde la línea de comandos, la función parece sencilla:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Programáticamente, el cliente usa `WNetAddConnection4W` con datos `lpUseOptions` no documentados. La opción relevante es `TraP` (parámetros de transporte), que finalmente llega al cliente SMB del kernel mediante un FSCTL y es analizada por `mrxsmb`.<sup>[[1]](#references)[[3]](#references)</sup>

Notas prácticas importantes:<sup>[[1]](#references)</sup>

- **La sintaxis UNC sigue sin tener un campo de puerto**
- **`net use` es por sesión de inicio de sesión**
- El bypass sigue funcionando porque **la conexión TCP y la sesión SMB son objetos independientes**
- Reutilizar **la misma ruta del recurso compartido** es obligatorio si el exploit depende de que el cliente SMB reutilice la conexión TCP creada anteriormente

## Flujo de explotación

### 1. Crear el transporte SMB controlado por el atacante

Ejecuta un servidor SMB en un puerto alto y haz que Windows se conecte a él:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
El servidor puede aceptar cualquier par de credenciales que controles, por ejemplo `user:user`. El objetivo de este paso todavía no es la escalada de privilegios, sino únicamente hacer que el cliente Windows SMB abra y mantenga una conexión TCP reutilizable con tu listener.<sup>[[1]](#references)</sup>

### 2. Forzar a un servicio privilegiado a usar la misma ruta UNC

Usa un primitive de coercion como **PetitPotam** contra la **misma** ruta `\\192.168.56.3\share`. Si el cliente forzado tiene privilegios y el nombre de destino es local (`localhost` o una IP/host local), Windows realiza una **autenticación NTLM local**.

Como la conexión TCP se reutiliza, ese intercambio NTLM privilegiado viaja al servicio SMB del atacante en lugar de dirigirse directamente al servidor SMB local real.<sup>[[1]](#references)</sup>

### 3. Relay de la autenticación privilegiada hacia el SMB local

El servicio SMB controlado por el atacante reenvía el intercambio NTLM privilegiado a `ntlmrelayx.py`, que hace relay hacia el listener SMB real de la máquina y obtiene una sesión como `NT AUTHORITY\SYSTEM`.<sup>[[1]](#references)</sup>

Herramientas típicas del writeup público:<sup>[[1]](#references)</sup>

- `smbserver.py` en un puerto personalizado para recibir la autenticación privilegiada mediante la conexión TCP reutilizada
- `ntlmrelayx.py` para hacer relay del NTLM capturado hacia el SMB local
- `PetitPotam.exe` u otro primitive de coercion para forzar la autenticación privilegiada

## Notas del operador

- Esta es una técnica de **escalada de privilegios local**, no un truco genérico de relay remoto<sup>[[1]](#references)</sup>
- El servicio SMB controlado por el atacante debe gestionar la autenticación privilegiada en la **misma conexión TCP** utilizada originalmente para montar el recurso compartido<sup>[[1]](#references)</sup>
- Si el acceso forzado llega a una **ruta de recurso compartido diferente**, Windows puede establecer una conexión distinta y la cadena se interrumpe<sup>[[1]](#references)</sup>
- Los requisitos de SMB signing pueden impedir el relay incluso cuando el paso del puerto arbitrario funciona<sup>[[1]](#references)</sup>
- Si solo tienes material de Kerberos o no puedes forzar NTLM local, esta variante exacta no es suficiente<sup>[[1]](#references)</sup>

## Detección y hardening

- Aplica el parche de **CVE-2026-24294** de **March 2026 Patch Tuesday**<sup>[[4]](#references)</sup>
- Supervisa el uso de `net use` o `New-SmbMapping` con **puertos SMB no predeterminados**<sup>[[1]](#references)</sup>
- Genera alertas ante SMB saliente inusual desde workstations o servidores hacia **puertos TCP altos**<sup>[[1]](#references)</sup>
- Revisa las oportunidades de coercion, como los triggers de tipo **EFSRPC / PetitPotam**<sup>[[1]](#references)</sup>
- Aplica SMB signing cuando sea posible; Synacktiv señala específicamente que esto bloqueó su relay en Windows 11 24H2<sup>[[1]](#references)</sup>

## Referencias

- [1] [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [2] [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [3] [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [4] [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
