# Mythic

{{#include ../banners/hacktricks-training.md}}

## ¿Qué es Mythic?

Mythic es un framework de command and control (C2) de código abierto, modular y colaborativo, diseñado para red teaming. Permite a los operadores gestionar e implementar agents (payloads) en diferentes sistemas operativos, incluidos Windows, Linux y macOS. Mythic ofrece una interfaz web para tasking multi-operator, gestión de archivos, gestión de SOCKS/rpfwd y generación de payloads.

A diferencia de los frameworks monolíticos, el propio repositorio de Mythic **no** incluye tipos de payload ni perfiles C2. Los agents, wrappers y perfiles C2 suelen instalarse como componentes externos y pueden actualizarse de forma independiente del núcleo de Mythic.

### Instalación

Para instalar Mythic, sigue las instrucciones en el **[Mythic repo](https://github.com/its-a-feature/Mythic)** oficial. Un bootstrap común desde el directorio de Mythic es:
```bash
sudo make
sudo ./mythic-cli start
```
Si Mythic ya está en ejecución, normalmente puedes añadir un nuevo agent o profile con `./mythic-cli install github ...` y luego reiniciar Mythic o simplemente iniciar directamente el nuevo componente.

### Agents

Mythic soporta múltiples agents, que son los **payloads que realizan tareas en los sistemas comprometidos**. Cada agent puede adaptarse a necesidades específicas y puede ejecutarse en distintos sistemas operativos.

Por defecto, Mythic no tiene ningún agent instalado. Los agents de la comunidad open-source están en [**https://github.com/MythicAgents**](https://github.com/MythicAgents), y la [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) es útil para comprobar rápidamente los sistemas operativos soportados, formatos de payload, wrappers y perfiles C2.

Para instalar un agent de esa organización puedes ejecutar:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
La forma `sudo -E` es útil cuando estás instalando desde un entorno que no es root. Puedes añadir nuevos agents con el comando anterior incluso si Mythic ya se está ejecutando.

### C2 Profiles

Los C2 profiles en Mythic definen **cómo los agents se comunican con el servidor de Mythic**. Especifican el protocolo de comunicación, los métodos de cifrado y otros ajustes. Puedes crear y administrar C2 profiles a través de la interfaz web de Mythic.

De forma predeterminada, Mythic se instala sin profiles; sin embargo, es posible descargar algunos profiles desde el repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) ejecutando:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): tráfico básico asíncrono GET/POST.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): tráfico HTTP más flexible con múltiples callback domains, rotación fail-over/round-robin, encabezados/parámetros de query personalizados y transformaciones de mensaje (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) colocadas en cookies, encabezados, parámetros de query o cuerpo.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): modelado de mensajes HTTP impulsado por JSON/TOML cuando el perfil estático `http` es demasiado reconocible.

### Current platform notes

- Muchos agentes y perfiles públicos ahora se instalan con imágenes remotas de contenedor preconstruidas.
Si bifurcas un componente o lo parcheas localmente y Mythic sigue usando el comportamiento antiguo, inspecciona las entradas `.env` generadas para `*_REMOTE_IMAGE`, `*_USE_BUILD_CONTEXT` y `*_USE_VOLUME`; habilitar
`*_USE_BUILD_CONTEXT="true"` suele ser lo que hace que Mythic recomponga desde tu
contexto Docker local en lugar de reutilizar silenciosamente la imagen remota.
- Los scripts de navegador son una de las funciones de mayor valor de Mythic en cuanto a calidad de vida para operadores: pueden convertir la salida bruta de comandos en tablas, visores de capturas de pantalla, enlaces de descarga y botones que emiten tasking de seguimiento directamente desde la UI. Esto es especialmente útil para flujos de trabajo repetitivos de `ls`, `ps`, triage y file-browser.
- Las versiones más nuevas de Mythic también soportan interactive tasking y patrones Push C2 que reducen la necesidad de sondeo `sleep 0` durante operaciones intensivas de PTY/SOCKS/rpfwd. Cuando un agent/profile lo soporta, esto suele tener menos sobrecarga que machacar el servidor con check-ins constantes solo para mantener usable un canal interactivo.

### Wrapper payloads

Wrapper payloads te permiten mantener la misma lógica de agent mientras cambias la representación en disco que se entrega o se persiste.

- `service_wrapper`: convierte otro payload en un Windows service executable, lo cual es útil cuando la ruta de ejecución requiere un binary de servicio válido.
- `scarecrow_wrapper`: envuelve shellcode compatible con el loader ScareCrow para generar salidas respaldadas por loader como EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo es un agent de Windows escrito en C# usando el 4.0 .NET Framework diseñado para usarse en SpecterOps training offerings.

Install it with:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Current build/profile notes

- Apollo puede emitir actualmente payloads `WinExe`, `Shellcode`, `Service` y `Source`.
- Los perfiles de Apollo más usados son `http`, `httpx`, `smb`, `tcp` y `websocket`.
- `httpx` suele ser la opción más flexible cuando necesitas rotación de dominios, soporte de proxy, colocación personalizada de mensajes y transforms de mensajes en lugar del perfil `http` estático más antiguo.
- Apollo soporta wrapper payloads como `service_wrapper` y `scarecrow_wrapper`.
- `register_file` y `register_assembly` son las primitivas de staging para `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` y `powerpick`. En las compilaciones actuales de Apollo, esos artefactos staged se almacenan en caché del lado del cliente como blobs AES256 protegidos por DPAPI.
- Los resultados de `ls` y `ps` se integran especialmente bien con los browser scripts de Mythic y con el browser de archivos/procesos, lo que hace que el triage del operador sea notablemente más rápido en operaciones colaborativas.
- Los jobs fork-and-run de Apollo heredan su sacrificial process settings de
`spawnto_x86` / `spawnto_x64`, heredan la selección del padre de `ppid`, y
después usan la primitva de inyección actualmente seleccionada. En la práctica, esto significa
que el ajuste de OPSEC para un comando a menudo afecta a `execute_assembly`,
`powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` y `spawn` al
mismo tiempo.
- Los backends de inyección documentados actualmente para Apollo incluyen `CreateRemoteThread`,
`QueueUserAPC` (estilo early-bird), y `NtCreateThreadEx` vía syscalls. Usa
`get_injection_techniques` antes de un post-exploitation ruidoso y
`set_injection_technique` si necesitas cambiar desde una primitiva que
choque con el target o con el comando que quieres ejecutar.
- `blockdlls` solo afecta a los sacrificial processes creados para jobs de post-exploitation.
Combinado con un `spawnto_x64` menos sospechoso que el `rundll32.exe` vacío por defecto, esta es una de las formas más fáciles de cambiar en Apollo antes de ejecutar tasking pesado en assembly/PowerShell.

This agent has a lot of commands that makes it very similar to Cobalt Strike's Beacon with some extras. Among them, it supports:

### Common actions

- `cat`: Imprimir el contenido de un archivo
- `cd`: Cambiar el directorio de trabajo actual
- `cp`: Copiar un archivo de una ubicación a otra
- `ls`: Listar archivos y directorios en el directorio actual o en la ruta especificada
- `ifconfig`: Obtener adaptadores e interfaces de red
- `netstat`: Obtener información de conexiones TCP y UDP
- `pwd`: Imprimir el directorio de trabajo actual
- `ps`: Listar los procesos en ejecución en el sistema objetivo (con info añadida)
- `jobs`: Listar todos los jobs en ejecución asociados con tasking de larga duración
- `download`: Descargar un archivo desde el sistema objetivo a la máquina local
- `upload`: Subir un archivo desde la máquina local al sistema objetivo
- `reg_query`: Consultar claves y valores del registro en el sistema objetivo
- `reg_write_value`: Escribir un nuevo valor en una clave de registro especificada
- `sleep`: Cambiar el intervalo de sueño del agente, que determina con qué frecuencia se comunica con el servidor Mythic
- Y muchos otros, usa `help` para ver la lista completa de comandos disponibles.

### Privilege escalation

- `getprivs`: Habilitar tantos privilegios como sea posible en el token del hilo actual
- `getsystem`: Abrir un handle a winlogon y duplicar el token, escalando efectivamente los privilegios a nivel SYSTEM
- `make_token`: Crear una nueva sesión de inicio de sesión y aplicarla al agente, permitiendo la suplantación de otro usuario
- `steal_token`: Robar un token primario de otro proceso, permitiendo que el agente suplante al usuario de ese proceso
- `pth`: Ataque Pass-the-Hash, que permite al agente autenticarse como un usuario usando su hash NTLM sin necesidad de la contraseña en texto claro
- `mimikatz`: Ejecutar comandos de Mimikatz para extraer credenciales, hashes y otra información sensible de la memoria o de la base de datos SAM
- `rev2self`: Revertir el token del agente a su token primario, bajando efectivamente los privilegios de vuelta al nivel original
- `ppid`: Cambiar el proceso padre para jobs de post-exploitation especificando un nuevo ID de proceso padre, permitiendo un mejor control del contexto de ejecución del job
- `printspoofer`: Ejecutar comandos de PrintSpoofer para eludir las medidas de seguridad del spooler de impresión, permitiendo escalada de privilegios o ejecución de código
- `dcsync`: Sincronizar las claves Kerberos de un usuario a la máquina local, permitiendo cracking offline de contraseñas o ataques adicionales
- `ticket_cache_add`: Añadir un ticket Kerberos a la sesión de inicio de sesión actual o a una especificada, permitiendo reutilización de tickets o suplantación

### Process execution

- `assembly_inject`: Permite inyectar un cargador de assembly .NET en un proceso remoto
- `blockdlls`: Bloquear la carga de DLLs no firmadas por Microsoft en jobs de post-exploitation
- `execute_assembly`: Ejecuta un assembly .NET en el contexto del agente
- `execute_coff`: Ejecuta un archivo COFF en memoria, permitiendo la ejecución en memoria de código compilado
- `execute_pe`: Ejecuta un ejecutable no administrado (PE)
- `keylog_inject`: Inyecta un keylogger en otro proceso y transmite las pulsaciones de teclas de vuelta a la vista de keylog de Mythic
- `screenshot` / `screenshot_inject`: Capturar el escritorio actual directamente o
inyectando un assembly de captura de pantalla en un proceso/sesión objetivo
- `get_injection_techniques`: Mostrar las técnicas de inyección disponibles y la actualmente seleccionada
- `inline_assembly`: Ejecuta un assembly .NET en un AppDomain desechable, permitiendo la ejecución temporal de código sin afectar al proceso principal del agente
- `register_assembly`: Registrar un assembly .NET para su ejecución posterior
- `register_file`: Registrar un archivo en la caché del agente para posterior tasking `execute_*` o PowerShell
- `run`: Ejecuta un binario en el sistema objetivo, usando el PATH del sistema para encontrar el ejecutable
- `set_injection_technique`: Cambiar la primitiva de inyección usada por jobs de post-exploitation
- `shinject`: Inyecta shellcode en un proceso remoto, permitiendo la ejecución en memoria de código arbitrario
- `inject`: Inyecta shellcode del agente en un proceso remoto, permitiendo la ejecución en memoria del código del agente
- `spawn`: Inicia una nueva sesión del agente en el ejecutable especificado, permitiendo la ejecución de shellcode en un proceso nuevo
- `spawnto_x64` and `spawnto_x86`: Cambiar el binario predeterminado usado en jobs de post-exploitation a una ruta especificada en lugar de usar `rundll32.exe` sin parámetros, que es muy ruidoso.

### Mythic Forge

Esto permite **cargar archivos COFF/BOF** desde Mythic Forge, que es un repositorio de payloads y herramientas precompilados que pueden ejecutarse en el sistema objetivo. Con todos los comandos que se pueden cargar será posible realizar acciones comunes ejecutándolos en el proceso actual del agente como BOFs (normalmente con mejor OPSEC que iniciar un proceso separado).

Empieza a instalarlos con:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Entonces, usa `forge_collections` para mostrar los módulos COFF/BOF de Mythic Forge y poder seleccionarlos y cargarlos en la memoria del agente para su ejecución. Por defecto, se agregan las siguientes 2 colecciones en Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Después de cargar un módulo, aparecerá en la lista como otro comando, por ejemplo `forge_bof_sa-whoami` o `forge_bof_sa-netuser`.

Para BOFs, recuerda que Forge **no** pasa solo una cadena plana de argumentos a Apollo. Mapea los parámetros del BOF al formato de array tipado de Mythic y luego los reenvía al flujo `execute_coff` de Apollo. Si un BOF cargado desde Forge se comporta de forma extraña, revisa los tipos de argumentos esperados del BOF / el punto de entrada, en lugar de solo la línea de comandos que escribiste.

### Ejecución de PowerShell y scripting

- `powershell_import`: Importa un nuevo script de PowerShell (.ps1) en la caché del agente para su ejecución posterior
- `powershell`: Ejecuta un comando de PowerShell en el contexto del agente, permitiendo scripting avanzado y automatización
- `powerpick`: Inyecta una assembly cargadora de PowerShell en un proceso sacrificial y ejecuta un comando de PowerShell (sin logging de PowerShell).
- `psinject`: Ejecuta PowerShell en un proceso especificado, permitiendo la ejecución dirigida de scripts en el contexto de otro proceso
- `shell`: Ejecuta un comando de shell en el contexto del agente, similar a ejecutar un comando en cmd.exe

### Movimiento lateral

- `jump_psexec`: Usa la técnica PsExec para moverse lateralmente a un nuevo host copiando primero el ejecutable del agente Apollo (apollo.exe) y ejecutándolo.
- `jump_wmi`: Usa la técnica WMI para moverse lateralmente a un nuevo host copiando primero el ejecutable del agente Apollo (apollo.exe) y ejecutándolo.
- `link` y `unlink`: Crean y eliminan enlaces P2P (por ejemplo, sobre SMB/TCP) entre callbacks.
- `wmiexecute`: Ejecuta un comando en el sistema local o en el remoto especificado usando WMI, con credenciales opcionales para suplantación.
- `net_dclist`: Recupera una lista de controladores de dominio para el dominio especificado, útil para identificar posibles objetivos de movimiento lateral.
- `net_localgroup`: Lista los grupos locales en el equipo especificado; por defecto usa localhost si no se especifica ningún equipo.
- `net_localgroup_member`: Recupera la membresía de un grupo local para un grupo específico en el equipo local o remoto, permitiendo enumerar usuarios en grupos concretos.
- `net_shares`: Lista los recursos compartidos remotos y su accesibilidad en el equipo especificado, útil para identificar posibles objetivos de movimiento lateral.
- `socks`: Habilita un proxy compatible con SOCKS 5 en la red objetivo, permitiendo tunelizar tráfico a través del host comprometido. Compatible con herramientas como proxychains.
- `rpfwd`: Empieza a escuchar en un puerto especificado en el host objetivo y reenvía el tráfico a través de Mythic hacia una IP y puerto remotos, permitiendo acceso remoto a servicios en la red objetivo.
- `listpipes`: Lista todos los named pipes del sistema local, lo que puede ser útil para movimiento lateral o escalada de privilegios al interactuar con mecanismos IPC.

Para los primitivos de ejecución WMI de nivel inferior usados internamente por `jump_wmi` o `wmiexecute`, consulta [WmiExec](lateral-movement/wmiexec.md). Para patrones de pivoting más amplios, consulta [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Comandos varios
- `help`: Muestra información detallada sobre comandos específicos o información general sobre todos los comandos disponibles en el agente.
- `clear`: Marca tareas como 'cleared' para que los agentes no puedan recogerlas. Puedes especificar `all` para limpiar todas las tareas o `task Num` para limpiar una tarea específica.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon es un agente en Golang que compila en ejecutables para **Linux y macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Notas actuales de build/profile

- Las builds actuales de Poseidon apuntan a Linux y macOS en `x86_64` y `arm64`.
- Los formatos de salida compatibles incluyen ejecutables nativos además de salidas estilo shared-library como `dylib` y `so`.
- Poseidon soporta `http`, `websocket`, `tcp`, y `dynamichttp`, y los builders actuales exponen ajustes multi-egress como `egress_order` y umbrales de failover.
- Opciones de build como `proxy_bypass` y `garble` merecen revisarse cuando necesitas un comportamiento de red más limpio o más ofuscación del binario Go.
- `pty` es uno de los comandos nuevos más útiles de calidad de vida para operaciones en Linux/macOS porque abre un PTY interactivo y puede exponer un puerto del lado de Mythic para una interacción de terminal más completa sin recurrir al antiguo workaround de `sleep 0` + SOCKS.
- La documentación actual de Poseidon es especialmente interesante para tradecraft centrado en macOS: `jxa` ejecuta JavaScript for Automation en memoria, `screencapture` captura el escritorio de la sesión iniciada, `clipboard_monitor` transmite cambios del pasteboard, `execute_library` carga un dylib local y llama a una función de él, y `libinject` fuerza a un proceso remoto a cargar un dylib en disco.
- Para trabajos de larga duración, recuerda que Poseidon ejecuta el post-exploitation work en goroutines/threads que son cooperativas en lugar de no matables. La documentación también indica explícitamente que actualmente no hay ofuscación del agente integrada, así que el tradecraft a nivel de build/profile importa más que con implants comerciales fuertemente ofuscados.

Para tradecraft específico de macOS en operaciones respaldadas por Mythic, abuso de JAMF, o ideas de MDM-as-C2, revisa [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Cuando se usa en Linux o macOS tiene algunos comandos interesantes:

### Common actions

- `cat`: Imprime el contenido de un archivo
- `cd`: Cambia el directorio de trabajo actual
- `chmod`: Cambia los permisos de un archivo
- `config`: Ver la config actual y la información del host
- `cp`: Copia un archivo de una ubicación a otra
- `curl`: Ejecuta una única web request con headers y método opcionales
- `upload`: Sube un archivo al target
- `download`: Descarga un archivo del sistema target a la máquina local
- Y muchos más

### Search Sensitive Information

- `triagedirectory`: Encuentra archivos interesantes dentro de un directorio en un host, como archivos sensibles o credentials.
- `getenv`: Obtiene todas las variables de entorno actuales.

### macOS-specific tradecraft

- `jxa`: Ejecuta JavaScript for Automation en memoria mediante `OSAScript`, lo que es útil para post-exploitation nativo en macOS sin dejar caer archivos de script separados.
- `clipboard_monitor`: Interroga el pasteboard e informa los cambios de vuelta a Mythic, lo cual es útil para workflows de robo de credentials/tokens que dependen de copy/paste.
- `screencapture`: Captura el escritorio del usuario en macOS.
- `execute_library`: Carga un dylib desde disco y llama a una función exportada específica.
- `libinject`: Inyecta un shellcode stub que fuerza a otro proceso de macOS a cargar un dylib desde disco.
- `persist_launchd`: Crea persistencia de LaunchAgent / LaunchDaemon directamente desde el agente.

### Move laterally

- `ssh`: Conéctate por SSH al host usando las credentials designadas y abre un PTY sin invocar ssh.
- `sshauth`: Conéctate por SSH al/los host(s) especificados usando las credentials designadas. También puedes usar esto para ejecutar un comando específico en los hosts remotos vía SSH o para usarlo para SCP files.
- `link_tcp`: Enlaza con otro agente sobre TCP, permitiendo comunicación directa entre agentes.
- `link_webshell`: Enlaza con un agente usando el perfil webshell P2P, permitiendo acceso remoto a la interfaz web del agente.
- `rpfwd`: Inicia o detiene un Reverse Port Forward, permitiendo acceso remoto a servicios en la red target.
- `socks`: Inicia o detiene un proxy SOCKS5 en la red target, permitiendo tunelizar tráfico a través del host comprometido. Compatible con tools como proxychains.
- `portscan`: Escanea host(s) en busca de puertos abiertos, útil para identificar targets potenciales para movimiento lateral u otros ataques.

### Process execution

- `shell`: Ejecuta un único shell command mediante /bin/sh, permitiendo la ejecución directa de comandos en el sistema target.
- `run`: Ejecuta un comando desde disco con argumentos, permitiendo la ejecución de binarios o scripts en el sistema target.
- `pty`: Abre un PTY interactivo, permitiendo interacción directa con el shell en el sistema target.




## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
{{#include ../banners/hacktricks-training.md}}
