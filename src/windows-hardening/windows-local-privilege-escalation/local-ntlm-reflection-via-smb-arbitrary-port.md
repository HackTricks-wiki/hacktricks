# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

Las compilaciones recientes de Windows introdujeron **SMB client support for alternative TCP ports**. Esa funcionalidad puede abusarse para convertir la **local NTLM authentication** en una **SYSTEM local privilege escalation** cuando el atacante puede:

1. Abrir una conexión SMB a un listener controlado por el atacante en un **non-445 port**
2. Mantener esa conexión TCP viva
3. Coaccionar a un **privileged local client** para que acceda al **mismo SMB share path**
4. Relayar la **local NTLM authentication** resultante de vuelta al verdadero servicio SMB de la máquina

Esta es la primitiva detrás de **CVE-2026-24294**, parcheada en **March 2026**.

## Why it works

El antiguo truco de reflexión CMTI / serialized-SPN está cubierto aquí:

{{#ref}}
../ntlm/README.md
{{#endref}}

Esta variante más nueva no necesita un marshalled hostname. En su lugar, abusa de dos comportamientos del SMB client:

- **Alternative port support** en **Windows 11 24H2** y **Windows Server 2025**, expuesto a usuarios con `net use \\host\share /tcpport:<port>`
- **SMB connection reuse / multiplexing**, donde múltiples authenticated sessions pueden viajar sobre la misma conexión TCP

Eso significa que un usuario con pocos privilegios puede primero crear una conexión TCP desde el SMB client hacia un attacker SMB server en un puerto alto, y luego coaccionar a un servicio privilegiado a acceder al **exact same UNC path**. Si Windows decide reutilizar la conexión TCP existente, el intercambio NTLM privilegiado se envía a través del transporte controlado por el atacante y puede ser relayado al local SMB server.

## Preconditions

- Target soporta SMB alternative ports:
- **Windows 11 24H2** o posterior
- **Windows Server 2025** o posterior
- El atacante puede ejecutar un local o remote SMB server en un high port elegido
- El atacante puede coaccionar a un servicio privilegiado para acceder a un UNC path
- La privileged authentication debe ser **NTLM local authentication**
- El target debe ser relayable:
- Synacktiv informó que funcionaba por defecto en **Windows Server 2025**
- Su cadena no funcionó en **Windows 11 24H2** porque outbound SMB signing se impone allí por defecto

## Userland and internals

Desde la línea de comandos, la funcionalidad parece simple:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Programáticamente, el cliente usa `WNetAddConnection4W` con datos no documentados de `lpUseOptions`. La opción relevante es `TraP` (transport parameters), que eventualmente llega al cliente SMB del kernel a través de un FSCTL y es analizada por `mrxsmb`.

Notas prácticas importantes:

- **La sintaxis UNC sigue sin tener campo de puerto**
- **`net use` es por sesión de inicio de sesión**
- El bypass sigue funcionando porque **la conexión TCP y la sesión SMB son objetos separados**
- Reutilizar la **misma ruta de share** es obligatorio si el exploit depende de que el cliente SMB reutilice la conexión TCP creada previamente

## Flujo de explotación

### 1. Crear el transporte SMB controlado por el atacante

Ejecuta un servidor SMB en un puerto alto y haz que Windows se conecte a él:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
El servidor puede aceptar cualquier par de credenciales que controles, por ejemplo `user:user`. El objetivo de este paso todavía no es la elevación de privilegios, solo hacer que el cliente SMB de Windows abra y mantenga una conexión TCP reutilizable hacia tu listener.

### 2. Coerce a privileged service to the same UNC path

Usa un primitive de coercion como **PetitPotam** contra la **misma** ruta `\\192.168.56.3\share`. Si el cliente forzado es privilegiado y el nombre de destino es local (`localhost` o una IP/host local), Windows realiza **NTLM local authentication**.

Como la conexión TCP se reutiliza, ese intercambio NTLM privilegiado viaja al servicio SMB del atacante en lugar de ir directamente al servidor SMB local real.

### 3. Relay the privileged authentication back to local SMB

El servicio SMB controlado por el atacante reenvía el intercambio NTLM privilegiado a `ntlmrelayx.py`, que lo relaya al listener SMB real de la máquina y obtiene una sesión como `NT AUTHORITY\SYSTEM`.

Herramientas típicas de la publicación pública:

- `smbserver.py` en un puerto personalizado para recibir la auth privilegiada sobre la conexión TCP reutilizada
- `ntlmrelayx.py` para relay del NTLM capturado a local SMB
- `PetitPotam.exe` u otro primitive de coercion para forzar la autenticación privilegiada

## Operator notes

- Esta es una técnica de **local privilege escalation**, no un truco genérico de remote relay
- El servicio SMB controlado por el atacante debe manejar la autenticación privilegiada en la **misma conexión TCP** usada originalmente para montar el share
- Si el acceso forzado golpea una **ruta de share diferente**, Windows puede establecer una conexión distinta y la cadena se rompe
- Los requisitos de SMB signing pueden matar el relay incluso cuando el paso de arbitrary-port funciona
- Si solo tienes material Kerberos o no puedes forzar local NTLM, esta variante exacta no es suficiente

## Detection and hardening

- Parchea **CVE-2026-24294** de **March 2026 Patch Tuesday**
- Vigila `net use` o `New-SmbMapping` usando **non-default SMB ports**
- Alerta sobre SMB saliente inusual desde workstations o servers hacia **high TCP ports**
- Revisa oportunidades de coercion como triggers de **EFSRPC / PetitPotam-style**
- Aplica SMB signing donde sea posible; Synacktiv señala específicamente que esto bloqueó su relay en Windows 11 24H2

## References

- [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [Project Zero - Windows Exploitation Tricks: Trapping Virtual Memory Access (2025 Update)](https://projectzero.google/2025/01/windows-exploitation-tricks-trapping.html)
- [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}
