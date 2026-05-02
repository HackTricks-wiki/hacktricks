# Mythic

{{#include ../banners/hacktricks-training.md}}

## ¿Qué es Mythic?

Mythic es un framework de command and control (C2) de código abierto, modular y colaborativo, diseñado para red teaming. Permite a los operadores gestionar y desplegar agents (payloads) en diferentes sistemas operativos, incluidos Windows, Linux y macOS. Mythic proporciona una interfaz web para tasking multi-operator, manejo de archivos, gestión de SOCKS/rpfwd y generación de payloads.

A diferencia de los frameworks monolíticos, el propio repositorio de Mythic **no** incluye payload types ni C2 profiles. Los agents, wrappers y C2 profiles suelen instalarse como componentes externos y pueden actualizarse de forma independiente del core de Mythic.

### Instalación

Para instalar Mythic, sigue las instrucciones en el **[Mythic repo](https://github.com/its-a-feature/Mythic)** oficial. Un bootstrap común desde el directorio de Mythic es:
```bash
sudo make
sudo ./mythic-cli start
```
Si Mythic ya está en ejecución, normalmente puedes agregar un nuevo agent o profile con `./mythic-cli install github ...` y luego reiniciar Mythic o simplemente iniciar el nuevo componente directamente.

### Agents

Mythic soporta múltiples agents, que son los **payloads que realizan tareas en los sistemas comprometidos**. Cada agent puede adaptarse a necesidades específicas y puede ejecutarse en diferentes sistemas operativos.

Por defecto Mythic no tiene ningún agent instalado. Los agents de la comunidad open-source están en [**https://github.com/MythicAgents**](https://github.com/MythicAgents), y la [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html) es útil para comprobar rápidamente los sistemas operativos soportados, formatos de payload, wrappers y perfiles C2.

Para instalar un agent de esa org puedes ejecutar:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
El formulario `sudo -E` es útil cuando estás instalando desde un entorno sin root. Puedes añadir nuevos agents con el comando anterior incluso si Mythic ya está ejecutándose.

### C2 Profiles

Los C2 profiles en Mythic definen **cómo los agents se comunican con el servidor Mythic**. Especifican el protocolo de comunicación, los métodos de cifrado y otros ajustes. Puedes crear y gestionar C2 profiles a través de la interfaz web de Mythic.

Por defecto Mythic se instala sin profiles, sin embargo, es posible descargar algunos profiles desde el repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) ejecutando:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): tráfico básico asíncrono GET/POST.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): tráfico HTTP más flexible con múltiples callback domains, fail-over/round-robin rotation, headers y parámetros de consulta personalizados, y transforms de mensajes (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) colocados en cookies, headers, query parameters o body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): shapeado de mensajes HTTP guiado por JSON/TOML cuando el perfil estático `http` es demasiado reconocible.

### Wrapper payloads

Wrapper payloads te permiten mantener la misma lógica del agent mientras cambias la representación en disco que se entrega o persiste.

- `service_wrapper`: convierte otro payload en un Windows service executable, lo cual es útil cuando la ruta de ejecución requiere un service binary válido.
- `scarecrow_wrapper`: envuelve shellcode compatible con el loader ScareCrow para generar salidas respaldadas por loader como EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo es un agente de Windows escrito en C# usando el 4.0 .NET Framework diseñado para ser usado en SpecterOps training offerings.

Install it with:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Current build/profile notes

- Apollo puede emitir actualmente payloads `WinExe`, `Shellcode`, `Service` y `Source`.
- Los perfiles de Apollo de uso común son `http`, `httpx`, `smb`, `tcp` y `websocket`.
- `httpx` suele ser la opción más flexible cuando necesitas rotación de dominios, soporte de proxy, colocación personalizada de mensajes y transforms de mensajes en lugar del perfil `http` estático más antiguo.
- Apollo soporta wrapper payloads como `service_wrapper` y `scarecrow_wrapper`.
- `register_file` y `register_assembly` son las primitivas de staging para `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` y `powerpick`. En las builds actuales de Apollo, esos staged artifacts se almacenan en caché del lado del cliente como blobs AES256 protegidos con DPAPI.
- Los resultados de `ls` y `ps` se integran especialmente bien con los browser scripts y el file/process browser de Mythic, lo que hace que el triage del operador sea notablemente más rápido en operaciones colaborativas.

Este agent tiene muchos commands que lo hacen muy similar a Beacon de Cobalt Strike con algunos extras. Entre ellos, soporta:

### Common actions

- `cat`: Muestra el contenido de un archivo
- `cd`: Cambia el directorio de trabajo actual
- `cp`: Copia un archivo de una ubicación a otra
- `ls`: Lista archivos y directorios en el directorio actual o en la ruta especificada
- `ifconfig`: Obtiene los adaptadores e interfaces de red
- `netstat`: Obtiene información de conexiones TCP y UDP
- `pwd`: Muestra el directorio de trabajo actual
- `ps`: Lista los procesos en ejecución en el sistema objetivo (con info adicional)
- `jobs`: Lista todos los jobs en ejecución asociados con tasking de larga duración
- `download`: Descarga un archivo del sistema objetivo a la máquina local
- `upload`: Sube un archivo desde la máquina local al sistema objetivo
- `reg_query`: Consulta claves y valores del registro en el sistema objetivo
- `reg_write_value`: Escribe un nuevo valor en una clave de registro especificada
- `sleep`: Cambia el intervalo de sleep del agent, lo que determina con qué frecuencia se conecta al Mythic server
- Y muchos otros, usa `help` para ver la lista completa de commands disponibles.

### Privilege escalation

- `getprivs`: Habilita tantos privileges como sea posible en el token del thread actual
- `getsystem`: Abre un handle a winlogon y duplica el token, escalando efectivamente privileges a nivel SYSTEM
- `make_token`: Crea una nueva sesión de logon y la aplica al agent, permitiendo la impersonation de otro usuario
- `steal_token`: Roba un primary token de otro proceso, permitiendo al agent impersonar al usuario de ese proceso
- `pth`: Ataque Pass-the-Hash, permitiendo al agent autenticarse como un usuario usando su hash NTLM sin necesitar la contraseña en texto plano
- `mimikatz`: Ejecuta commands de Mimikatz para extraer credentials, hashes y otra información sensible de la memoria o de la base de datos SAM
- `rev2self`: Revierte el token del agent a su token primario, bajando efectivamente los privileges de vuelta al nivel original
- `ppid`: Cambia el proceso padre para jobs de post-exploitation especificando un nuevo ID de proceso padre, permitiendo mejor control sobre el contexto de ejecución del job
- `printspoofer`: Ejecuta commands de PrintSpoofer para evadir las medidas de seguridad del print spooler, permitiendo privilege escalation o code execution
- `dcsync`: Sincroniza las Kerberos keys de un usuario con la máquina local, permitiendo cracking offline de contraseñas o ataques adicionales
- `ticket_cache_add`: Añade un Kerberos ticket a la sesión de logon actual o a una especificada, permitiendo reutilización de tickets o impersonation

### Process execution

- `assembly_inject`: Permite inyectar un .NET assembly loader en un proceso remoto
- `blockdlls`: Bloquea la carga de DLLs no firmadas por Microsoft en jobs de post-exploitation
- `execute_assembly`: Ejecuta un .NET assembly en el contexto del agent
- `execute_coff`: Ejecuta un archivo COFF en memoria, permitiendo ejecución en memoria de código compilado
- `execute_pe`: Ejecuta un ejecutable unmanaged (PE)
- `get_injection_techniques`: Muestra las injection techniques disponibles y la seleccionada actualmente
- `inline_assembly`: Ejecuta un .NET assembly en un AppDomain desechable, permitiendo ejecución temporal de código sin afectar el proceso principal del agent
- `register_assembly`: Registra un .NET assembly para su ejecución posterior
- `register_file`: Registra un archivo en la caché del agent para posterior `execute_*` o tasking de PowerShell
- `run`: Ejecuta un binary en el sistema objetivo, usando el PATH del sistema para encontrar el ejecutable
- `set_injection_technique`: Cambia la primitive de inyección usada por los jobs de post-exploitation
- `shinject`: Inyecta shellcode en un proceso remoto, permitiendo ejecución en memoria de código arbitrario
- `inject`: Inyecta el shellcode del agent en un proceso remoto, permitiendo ejecución en memoria del código del agent
- `spawn`: Inicia una nueva sesión del agent en el ejecutable especificado, permitiendo la ejecución de shellcode en un proceso nuevo
- `spawnto_x64` y `spawnto_x86`: Cambian el binary predeterminado usado en jobs de post-exploitation a una ruta especificada en lugar de usar `rundll32.exe` sin params, lo cual genera mucho ruido.

### Mythic Forge

Esto permite **cargar archivos COFF/BOF** desde Mythic Forge, que es un repositorio de payloads y tools precompilados que pueden ejecutarse en el sistema objetivo. Con todos los commands que se pueden cargar, será posible realizar acciones comunes ejecutándolos en el proceso actual del agent como BOFs (normalmente con mejor OPSEC que iniciar un proceso separado).

Empieza a instalarlos con:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Luego, usa `forge_collections` para mostrar los módulos COFF/BOF de Mythic Forge para poder seleccionarlos y cargarlos en la memoria del agent para su ejecución. Por defecto, las siguientes 2 collections se añaden en Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Después de cargar un módulo, aparecerá en la lista como otro command, como `forge_bof_sa-whoami` o `forge_bof_sa-netuser`.

### PowerShell & scripting execution

- `powershell_import`: Importa un nuevo script de PowerShell (.ps1) en la caché del agent para su ejecución posterior
- `powershell`: Ejecuta un command de PowerShell en el contexto del agent, permitiendo scripting avanzado y automatización
- `powerpick`: Inyecta una assembly de carga de PowerShell en un proceso sacrificial y ejecuta un command de PowerShell (sin powershell logging).
- `psinject`: Ejecuta PowerShell en un proceso especificado, permitiendo la ejecución dirigida de scripts en el contexto de otro proceso
- `shell`: Ejecuta un command de shell en el contexto del agent, similar a ejecutar un command en cmd.exe

### Lateral Movement

- `jump_psexec`: Usa la técnica PsExec para moverse lateralmente a un nuevo host copiando primero el ejecutable del agent Apollo (apollo.exe) y ejecutándolo.
- `jump_wmi`: Usa la técnica WMI para moverse lateralmente a un nuevo host copiando primero el ejecutable del agent Apollo (apollo.exe) y ejecutándolo.
- `link` and `unlink`: Crea y elimina enlaces P2P (por ejemplo, sobre SMB/TCP) entre callbacks.
- `wmiexecute`: Ejecuta un command en el sistema local o remoto especificado usando WMI, con credenciales opcionales para impersonation.
- `net_dclist`: Recupera una lista de domain controllers para el domain especificado, útil para identificar posibles targets para lateral movement.
- `net_localgroup`: Lista los grupos locales en el computer especificado, por defecto localhost si no se especifica ningún computer.
- `net_localgroup_member`: Recupera la pertenencia a grupos locales para un grupo especificado en el computer local o remoto, permitiendo la enumeración de usuarios en grupos específicos.
- `net_shares`: Lista las shares remotas y su accesibilidad en el computer especificado, útil para identificar posibles targets para lateral movement.
- `socks`: Habilita un proxy compatible con SOCKS 5 en la red del target, permitiendo tunelizar tráfico a través del host comprometido. Compatible con tools como proxychains.
- `rpfwd`: Comienza a escuchar en un port especificado en el host del target y reenvía el tráfico a través de Mythic hacia una IP y port remotos, permitiendo acceso remoto a services en la red del target.
- `listpipes`: Lista todos los named pipes en el sistema local, lo que puede ser útil para lateral movement o privilege escalation interactuando con mecanismos IPC.

Para los primitivas de ejecución WMI de nivel inferior usadas debajo de `jump_wmi` o `wmiexecute`, consulta [WmiExec](lateral-movement/wmiexec.md). Para patrones más amplios de pivoting, consulta [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Miscellaneous Commands
- `help`: Muestra información detallada sobre commands específicos o información general sobre todos los commands disponibles en el agent.
- `clear`: Marca tasks como 'cleared' para que no puedan ser tomadas por agents. Puedes especificar `all` para limpiar todas las tasks o `task Num` para limpiar una task específica.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon es un agent de Golang que se compila en ejecutables de **Linux y macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Notas actuales de build/profile

- Las builds actuales de Poseidon apuntan a Linux y macOS en ambos `x86_64` y `arm64`.
- Los formatos de salida compatibles incluyen ejecutables nativos además de salidas estilo biblioteca compartida como `dylib` y `so`.
- Poseidon soporta `http`, `websocket`, `tcp`, y `dynamichttp`, y los builders actuales exponen ajustes de multi-egress como `egress_order` y umbrales de failover.
- Opciones de build-time como `proxy_bypass` y `garble` merecen revisarse cuando necesites un comportamiento de red más limpio o una ofuscación extra del binario Go.

Para tradecraft específico de macOS en operaciones respaldadas por Mythic, abuso de JAMF, o ideas de MDM-as-C2, revisa [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Cuando se usa en Linux o macOS tiene algunos comandos interesantes:

### Acciones comunes

- `cat`: Imprime el contenido de un archivo
- `cd`: Cambia el directorio de trabajo actual
- `chmod`: Cambia los permisos de un archivo
- `config`: Muestra la config actual y la información del host
- `cp`: Copia un archivo de una ubicación a otra
- `curl`: Ejecuta una sola petición web con headers y método opcionales
- `upload`: Sube un archivo al target
- `download`: Descarga un archivo del sistema target a la máquina local
- Y muchos más

### Buscar información sensible

- `triagedirectory`: Encuentra archivos interesantes dentro de un directorio en un host, como archivos sensibles o credentials.
- `getenv`: Obtiene todas las variables de entorno actuales.

### Movimiento lateral

- `ssh`: SSH al host usando las credentials designadas y abre un PTY sin lanzar ssh.
- `sshauth`: SSH a uno o varios host(s) especificados usando las credentials designadas. También puedes usarlo para ejecutar un comando específico en los hosts remotos vía SSH o para usarlo para SCP archivos.
- `link_tcp`: Enlaza a otro agent por TCP, permitiendo comunicación directa entre agents.
- `link_webshell`: Enlaza a un agent usando el perfil P2P de webshell, permitiendo acceso remoto a la interfaz web del agent.
- `rpfwd`: Inicia o detiene un Reverse Port Forward, permitiendo acceso remoto a servicios en la red target.
- `socks`: Inicia o detiene un proxy SOCKS5 en la red target, permitiendo tunelizar tráfico a través del host comprometido. Compatible con herramientas como proxychains.
- `portscan`: Escanea host(s) en busca de puertos abiertos, útil para identificar targets potenciales para movimiento lateral o ataques posteriores.

### Ejecución de procesos

- `shell`: Ejecuta un solo comando de shell vía /bin/sh, permitiendo la ejecución directa de comandos en el sistema target.
- `run`: Ejecuta un comando desde disco con argumentos, permitiendo la ejecución de binaries o scripts en el sistema target.
- `pty`: Abre un PTY interactivo, permitiendo interacción directa con la shell en el sistema target.




## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
{{#include ../banners/hacktricks-training.md}}
