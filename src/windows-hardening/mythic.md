# Mythic

{{#include ../banners/hacktricks-training.md}}

## ¿Qué es Mythic?

Mythic es un framework de command and control (C2) modular, colaborativo y de código abierto diseñado para red teaming. Permite a los operadores gestionar y desplegar agentes (payloads) en distintos sistemas operativos, incluidos Windows, Linux y macOS. Mythic proporciona una interfaz de navegador para la asignación de tareas entre varios operadores, la gestión de archivos, la gestión de SOCKS/rpfwd y la generación de payloads.

A diferencia de los frameworks monolíticos, el repositorio de Mythic no incluye directamente tipos de payload ni perfiles de C2. Los agentes, wrappers y perfiles de C2 suelen instalarse como componentes externos y pueden actualizarse independientemente del núcleo de Mythic.

### Instalación

Para instalar Mythic, sigue las instrucciones del **[repositorio de Mythic](https://github.com/its-a-feature/Mythic)** oficial. Un procedimiento de bootstrap habitual desde el directorio de Mythic es:
```bash
sudo make
sudo ./mythic-cli start
```
Si Mythic ya está ejecutándose, normalmente puedes añadir un nuevo agent o profile con `./mythic-cli install github ...` y después reiniciar Mythic o iniciar directamente el nuevo componente.

### Agents

Mythic admite varios agents, que son los **payloads que realizan tareas en los sistemas comprometidos**. Cada agent puede adaptarse a necesidades específicas y ejecutarse en distintos sistemas operativos.

De forma predeterminada, Mythic no tiene ningún agent instalado. Los agents de la comunidad open source se encuentran en [**https://github.com/MythicAgents**](https://github.com/MythicAgents), y la [**matriz de funcionalidades de la comunidad**](https://mythicmeta.github.io/overview/agent_matrix.html) resulta útil para comprobar rápidamente los sistemas operativos compatibles, los formatos de payload, los wrappers y los perfiles C2.

Para instalar un agent de esa organización, puedes ejecutar:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
La forma `sudo -E` es útil cuando estás instalando desde un entorno que no es root. Puedes añadir nuevos agentes con el comando anterior incluso si Mythic ya está en ejecución.

### Perfiles C2

Los perfiles C2 en Mythic definen **cómo se comunican los agentes con el servidor de Mythic**. Especifican el protocolo de comunicación, los métodos de cifrado y otras configuraciones. Puedes crear y administrar perfiles C2 mediante la interfaz web de Mythic.

De forma predeterminada, Mythic se instala sin perfiles; sin embargo, es posible descargar algunos perfiles del repositorio [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) ejecutando:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Perfiles relevantes para el operador que debes tener en cuenta:

- [`http`](https://github.com/MythicC2Profiles/http): tráfico GET/POST asíncrono básico.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): tráfico HTTP más flexible con múltiples dominios de callback, rotación de fail-over/round-robin, headers/parámetros de consulta personalizados y transforms de mensajes (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) colocados en cookies, headers, parámetros de consulta o body.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): configuración de mensajes HTTP basada en JSON/TOML cuando el profile estático `http` resulta demasiado reconocible.

### Notas actuales sobre la plataforma

- Muchos agents y profiles públicos ahora se instalan con imágenes de contenedor remotas precompiladas.
Si haces fork de un componente o lo modificas localmente y Mythic sigue usando el comportamiento anterior, inspecciona las entradas `.env` generadas para `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT` y `*_USE_VOLUME`; habilitar
`*_USE_BUILD_CONTEXT="true"` suele hacer que Mythic reconstruya usando tu
contexto Docker local en lugar de reutilizar silenciosamente la imagen remota.
- Los browser scripts son una de las funcionalidades de mayor valor de Mythic para mejorar la experiencia de los operadores: pueden convertir el output sin procesar de los comandos en tablas, visores de screenshots, enlaces de descarga, enlaces de búsqueda y botones que emiten tasking posterior directamente desde la UI. Las versiones actuales de Mythic permiten que cada operador conserve sus propios scripts, los active o desactive globalmente o por task, y ofrecen mejores resultados cuando los agents devuelven JSON estructurado en lugar de plaintext. Esto resulta especialmente útil para workflows repetitivos de `ls`, `ps`, triage y exploración de archivos.
- Las versiones más recientes de Mythic también admiten interactive tasking y patrones Push C2 que reducen la necesidad de realizar polling con `sleep 0` durante operaciones con mucho uso de PTY/SOCKS/rpfwd. Cuando un agent/profile lo admite, normalmente genera menos overhead que bombardear el servidor con check-ins constantes solo para mantener usable un canal interactivo.
- Los builders actuales de Mythic de la era 3.4 tienen más conocimiento del contexto de lo que sugieren los writeups antiguos: ahora los parámetros de build pueden agruparse u ocultarse según el OS seleccionado u otras opciones de build, los payload types pueden declarar si admiten múltiples C2 profiles o múltiples instancias del mismo C2 en un único build, y las desviaciones de parámetros de C2 permiten que un agent oculte campos que realmente no implementa. Esto es importante cuando alternas entre `http`, `httpx`, `smb`,
`tcp` y `websocket`, porque la superficie de build segura/válida ya no es un formulario estático plano.
- Si estás creando un par personalizado de agent/profile y no quieres que el formato de mensajes JSON de Mythic ni el crypto predeterminado aparezcan en el wire, utiliza un
`translation_container`: Mythic elimina el UUID, entrega el blob cifrado y el material de key al translator mediante gRPC y espera recibir bytes nativos del agent. Esta es la forma adecuada de admitir protocolos binarios, framing personalizado o cifrado del lado del agent sin reescribir todo el servidor.
- Recuerda que los callbacks linked/P2P no solo transportan tasking. El flujo `get_tasking` de Mythic también puede transportar responses, además de datos de `delegates`, `socks`,
`rpfwd` e `interactive`. En la práctica, un callback de egress puede atender callbacks internos y canales de pivot en el mismo polling loop; si los child agents realizan sus propios check-ins periódicos, `get_delegate_tasks=false` evita que el parent consuma accidentalmente los jobs en cola del callback interno.

### Wrapper payloads

Los wrapper payloads permiten conservar la misma lógica del agent mientras cambias la representación en disco que se entrega o persiste.

- `service_wrapper`: convierte otro payload en un ejecutable de Windows service, lo que resulta útil cuando la ruta de ejecución requiere un binario de servicio válido.
- `scarecrow_wrapper`: envuelve shellcode compatible con el loader ScareCrow para generar outputs respaldados por un loader, como EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo es un agent para Windows escrito en C# usando .NET Framework 4.0, diseñado para utilizarse en las ofertas de training de SpecterOps.

Instálalo con:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Notas actuales sobre build/profile

- Apollo actualmente puede emitir payloads `WinExe`, `Shellcode`, `Service` y `Source`.
- Los profiles de Apollo más utilizados son `http`, `httpx`, `smb`, `tcp` y `websocket`.
- `httpx` suele ser la opción más flexible cuando necesitas rotación de dominios, compatibilidad con proxies, colocación de mensajes personalizada y transforms de mensajes, en lugar del antiguo profile estático `http`.
- Apollo es uno de los agentes comunitarios con más funcionalidades y actualmente expone integraciones del lado de Mythic como browser scripts, vistas del navegador de archivos/procesos, screenshots, keylogging, SOCKS, rpfwd, Push C2 y routing P2P.
- Apollo admite wrapper payloads como `service_wrapper` y `scarecrow_wrapper`.
- Apollo admite la carga dinámica de comandos, por lo que puedes mantener ligero el payload inicial y cargar comandos o módulos Forge adicionales posteriormente, en lugar de compilar todas las capacidades de post-exploitation en el primer build.
- Al generar salida shellcode, el builder actual de Apollo también expone opciones de formato Donut (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) y comportamiento de bypass de Donut (`None`, `Abort on fail`, `Continue on fail`). Esto resulta útil si el objetivo final es volver a envolver el shellcode con `service_wrapper`, `scarecrow_wrapper` o un loader personalizado.
- `register_file` y `register_assembly` son las primitivas de staging para `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` y `powerpick`. En los builds actuales de Apollo, esos artefactos staged se almacenan en caché del lado del cliente como blobs AES256 protegidos con DPAPI.
- Los resultados de `ls` y `ps` se integran especialmente bien con los browser scripts y el navegador de archivos/procesos de Mythic, lo que agiliza notablemente el triage del operador en operaciones colaborativas.
- Los jobs fork-and-run heredan la configuración de sus procesos sacrificiales de
`spawnto_x86` / `spawnto_x64`, heredan la selección del proceso padre de `ppid` y
después utilizan la primitive de injection seleccionada actualmente. En la práctica, esto significa que
tu ajuste de OPSEC para un comando suele afectar simultáneamente a
`execute_assembly`, `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` y `spawn`.
- Los backends de injection de Apollo documentados actualmente incluyen `CreateRemoteThread`,
`QueueUserAPC` (estilo early-bird) y `NtCreateThreadEx` mediante syscalls. Utiliza
`get_injection_techniques` antes de realizar post-exploitation ruidosa y
`set_injection_technique` si necesitas cambiar una primitive que entre en conflicto con el objetivo o con el comando que quieres ejecutar.
- `blockdlls` solo afecta a los procesos sacrificiales creados para jobs de post-exploitation. Combinado con un objetivo `spawnto_x64` menos sospechoso que el `rundll32.exe` básico predeterminado, este es uno de los cambios más sencillos que se pueden realizar en Apollo antes de ejecutar tasking intensivo en assembly/PowerShell.

Este agente tiene muchos comandos que lo hacen muy similar al Beacon de Cobalt Strike, con algunas funciones adicionales. Entre ellos, admite:

### Acciones comunes

- `cat`: Mostrar el contenido de un archivo
- `cd`: Cambiar el directorio de trabajo actual
- `cp`: Copiar un archivo de una ubicación a otra
- `ls`: Enumerar archivos y directorios del directorio actual o de la ruta especificada
- `ifconfig`: Obtener los adaptadores e interfaces de red
- `netstat`: Obtener información sobre conexiones TCP y UDP
- `pwd`: Mostrar el directorio de trabajo actual
- `ps`: Enumerar los procesos en ejecución en el sistema objetivo (con información adicional)
- `jobs`: Enumerar todos los jobs en ejecución asociados con tasking de larga duración
- `download`: Descargar un archivo del sistema objetivo a la máquina local
- `upload`: Subir un archivo de la máquina local al sistema objetivo
- `reg_query`: Consultar claves y valores del registro en el sistema objetivo
- `reg_write_value`: Escribir un nuevo valor en una clave de registro especificada
- `sleep`: Cambiar el intervalo de sleep del agente, que determina con qué frecuencia se comunica con el servidor Mythic
- Y muchos otros; utiliza `help` para ver la lista completa de comandos disponibles.

### Escalada de privilegios

- `getprivs`: Habilitar tantos privilegios como sea posible en el token del thread actual
- `getsystem`: Abrir un handle a winlogon y duplicar el token, escalando efectivamente los privilegios al nivel SYSTEM
- `make_token`: Crear una nueva sesión de logon y aplicarla al agente, permitiendo la impersonation de otro usuario
- `steal_token`: Robar un token primario de otro proceso, permitiendo al agente impersonar al usuario de ese proceso
- `pth`: Ataque Pass-the-Hash, que permite al agente autenticarse como un usuario utilizando su hash NTLM sin necesitar la contraseña en texto plano
- `mimikatz`: Ejecutar comandos de Mimikatz para extraer credenciales, hashes y otra información sensible de la memoria o de la base de datos SAM
- `rev2self`: Revertir el token del agente a su token primario, eliminando efectivamente los privilegios y volviendo al nivel original
- `ppid`: Cambiar el proceso padre de los jobs de post-exploitation especificando un nuevo ID de proceso padre, lo que permite un mayor control sobre el contexto de ejecución del job
- `printspoofer`: Ejecutar comandos de PrintSpoofer para omitir las medidas de seguridad del print spooler, permitiendo la escalada de privilegios o la ejecución de código
- `dcsync`: Sincronizar las claves Kerberos de un usuario con la máquina local, permitiendo el cracking offline de contraseñas u otros ataques
- `ticket_cache_add`: Añadir un ticket Kerberos a la sesión de logon actual o a una sesión especificada, permitiendo reutilizar el ticket o realizar impersonation

### Ejecución de procesos

- `assembly_inject`: Permite inyectar un loader de assembly .NET en un proceso remoto
- `blockdlls`: Bloquear la carga de DLLs sin firma de Microsoft en jobs de post-exploitation
- `execute_assembly`: Ejecutar un assembly .NET en el contexto del agente
- `execute_coff`: Ejecutar un archivo COFF en memoria, permitiendo la ejecución en memoria de código compilado
- `execute_pe`: Ejecutar un ejecutable no gestionado (PE)
- `keylog_inject`: Inyectar un keylogger en otro proceso y transmitir las pulsaciones a la vista de keylog de Mythic
- `screenshot` / `screenshot_inject`: Capturar el escritorio actual directamente o
inyectando un assembly de screenshot en un proceso/sesión objetivo
- `get_injection_techniques`: Mostrar las técnicas de injection disponibles y la seleccionada actualmente
- `inline_assembly`: Ejecutar un assembly .NET en un AppDomain desechable, permitiendo la ejecución temporal de código sin afectar al proceso principal del agente
- `register_assembly`: Registrar un assembly .NET para ejecutarlo posteriormente
- `register_file`: Registrar un archivo en la caché del agente para usarlo posteriormente con `execute_*` o tasking de PowerShell
- `run`: Ejecutar un binario en el sistema objetivo utilizando el `PATH` del sistema para localizar el ejecutable
- `set_injection_technique`: Cambiar la primitive de injection utilizada por los jobs de post-exploitation
- `shinject`: Inyectar shellcode en un proceso remoto, permitiendo la ejecución en memoria de código arbitrario
- `inject`: Inyectar shellcode del agente en un proceso remoto, permitiendo la ejecución en memoria del código del agente
- `spawn`: Crear una nueva sesión del agente en el ejecutable especificado, permitiendo ejecutar shellcode en un proceso nuevo
- `spawnto_x64` y `spawnto_x86`: Cambiar el binario predeterminado utilizado en los jobs de post-exploitation por una ruta especificada, en lugar de utilizar `rundll32.exe` sin parámetros, que genera mucho ruido.

### Mythic Forge

Esto permite **cargar** archivos **COFF/BOF** desde Mythic Forge, que es un repositorio de payloads y herramientas precompilados que pueden ejecutarse en el sistema objetivo. Con todos los comandos que se pueden cargar, será posible realizar acciones comunes ejecutándolos en el proceso actual del agente como BOFs (normalmente con mejor OPSEC que al crear un proceso separado).

Empieza a instalarlos con:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Luego, usa `forge_collections` para mostrar los módulos COFF/BOF de Mythic Forge, de modo que puedas seleccionarlos y cargarlos en la memoria del agente para su ejecución. De forma predeterminada, las siguientes 2 colecciones se añaden en Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Después de cargar un módulo, aparecerá en la lista como otro comando, como `forge_bof_sa-whoami` o `forge_bof_sa-netuser`.

Para los BOF, recuerda que Forge **no** simplemente pasa una única cadena plana de argumentos a Apollo. Mapea los parámetros del BOF al formato de array tipado de Mythic y, después, los reenvía al flujo `execute_coff` de Apollo. Si un BOF cargado desde Forge se comporta de forma extraña, comprueba los tipos de argumentos / entrypoint esperados del BOF en lugar de revisar únicamente la línea de comandos que escribiste. Ten en cuenta también que el loader de BOF más reciente de Apollo cambió el manejo de argumentos con respecto a las versiones mucho más antiguas de la era 2.3.1, por lo que los BOF obsoletos o las colecciones antiguas pueden fallar simplemente porque cambiaron las expectativas de marshaling.

### Ejecución de PowerShell y scripting

- `powershell_import`: Importa un nuevo script de PowerShell (.ps1) en la caché del agente para ejecutarlo posteriormente
- `powershell`: Ejecuta un comando de PowerShell en el contexto del agente, permitiendo scripting y automatización avanzados
- `powerpick`: Inyecta un assembly loader de PowerShell en un proceso sacrificial y ejecuta un comando de PowerShell (sin logging de PowerShell).
- `psinject`: Ejecuta PowerShell en un proceso especificado, permitiendo la ejecución dirigida de scripts en el contexto de otro proceso
- `shell`: Ejecuta un comando de shell en el contexto del agente, de forma similar a ejecutar un comando en cmd.exe

### Movimiento lateral

- `jump_psexec`: Utiliza la técnica PsExec para realizar un movimiento lateral a un nuevo host, copiando primero el ejecutable del agente Apollo (apollo.exe) y ejecutándolo.
- `jump_wmi`: Utiliza la técnica WMI para realizar un movimiento lateral a un nuevo host, copiando primero el ejecutable del agente Apollo (apollo.exe) y ejecutándolo.
- `link` y `unlink`: Crean y desmantelan enlaces P2P (por ejemplo, mediante SMB/TCP) entre callbacks.
- `wmiexecute`: Ejecuta un comando en el sistema local o remoto especificado mediante WMI, con credenciales opcionales para la suplantación.
- `net_dclist`: Recupera una lista de controladores de dominio del dominio especificado, lo que resulta útil para identificar posibles objetivos para el movimiento lateral.
- `net_localgroup`: Muestra los grupos locales del equipo especificado; de forma predeterminada, usa localhost si no se especifica ningún equipo.
- `net_localgroup_member`: Recupera la pertenencia a grupos locales de un grupo especificado en el equipo local o remoto, permitiendo enumerar usuarios de grupos específicos.
- `net_shares`: Muestra los recursos compartidos remotos y su accesibilidad en el equipo especificado, lo que resulta útil para identificar posibles objetivos para el movimiento lateral.
- `socks`: Habilita un proxy compatible con SOCKS 5 en la red objetivo, permitiendo tunelizar el tráfico a través del host comprometido. Compatible con herramientas como proxychains.
- `rpfwd`: Comienza a escuchar en un puerto especificado del host objetivo y reenvía el tráfico a través de Mythic hacia una IP y un puerto remotos, permitiendo el acceso remoto a servicios de la red objetivo.
- `listpipes`: Muestra todas las named pipes del sistema local, lo que puede resultar útil para el movimiento lateral o la escalada de privilegios mediante la interacción con mecanismos IPC.

Para consultar las primitivas de ejecución WMI de nivel inferior utilizadas internamente por `jump_wmi` o `wmiexecute`, revisa [WmiExec](lateral-movement/wmiexec.md). Para consultar patrones de pivoting más amplios, revisa [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Comandos varios
- `help`: Muestra información detallada sobre comandos específicos o información general sobre todos los comandos disponibles en el agente.
- `clear`: Marca las tareas como 'cleared' para que los agentes no puedan recogerlas. Puedes especificar `all` para borrar todas las tareas o `task Num` para borrar una tarea específica.


## [Agente Poseidon](https://github.com/MythicAgents/poseidon)

Poseidon es un agente de Golang que compila en ejecutables para **Linux y macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Notas actuales de build/profile

- Los builds actuales de Poseidon están dirigidos a Linux y macOS en `x86_64` y `arm64`.
- Los formatos de salida compatibles incluyen ejecutables nativos y salidas de tipo shared-library, como `dylib` y `so`.
- Poseidon es compatible con `http`, `websocket`, `tcp` y `dynamichttp`, y los builders actuales exponen configuraciones multi-egress como `egress_order` y umbrales de failover.
- Los metadatos actuales de capabilities de Poseidon también anuncian browser scripts, integración con file/process browser, interactive tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd y P2P, por lo que puede funcionar como un nodo pivot real de Linux/macOS y no solo como un remote shell simple.
- Vale la pena revisar las opciones de build como `proxy_bypass` y `garble` cuando necesites un comportamiento de red más limpio o una ofuscación adicional del binario Go.
- `pty` es uno de los comandos más útiles incorporados recientemente para las operaciones de Linux/macOS, porque abre un PTY interactivo y puede exponer un puerto del lado de Mythic para una interacción de terminal más completa, sin recurrir al antiguo workaround de `sleep 0` + SOCKS.
- La documentación actual de Poseidon es especialmente interesante para tradecraft centrado en macOS: `jxa` ejecuta JavaScript for Automation en memoria, `screencapture` captura el desktop del usuario conectado, `clipboard_monitor` transmite los cambios del pasteboard, `execute_library` carga un dylib local y llama a una función, y `libinject` obliga a un proceso remoto a cargar un dylib almacenado en disco.
- Para jobs de larga duración, recuerda que Poseidon ejecuta el trabajo de post-exploitation en goroutines/threads cooperativos que no se pueden detener de forma forzada. La documentación también señala explícitamente que actualmente no existe una ofuscación integrada del agent, por lo que el tradecraft a nivel de build/profile es más importante que con implants comerciales fuertemente ofuscados.

Para el tradecraft específico de macOS relacionado con operaciones respaldadas por Mythic, abuso de JAMF o ideas de MDM-as-C2, consulta [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Cuando se utiliza en Linux o macOS, cuenta con algunos comandos interesantes:

### Acciones comunes

- `cat`: Mostrar el contenido de un archivo
- `cd`: Cambiar el directorio de trabajo actual
- `chmod`: Cambiar los permisos de un archivo
- `config`: Ver la configuración actual y la información del host
- `cp`: Copiar un archivo de una ubicación a otra
- `curl`: Ejecutar una única web request con headers y método opcionales
- `upload`: Subir un archivo al target
- `download`: Descargar un archivo del target al equipo local
- Y muchos más

### Buscar información sensible

- `triagedirectory`: Buscar archivos interesantes dentro de un directorio en un host, como archivos sensibles o credenciales.
- `getenv`: Obtener todas las variables de entorno actuales.

### Tradecraft específico de macOS

- `jxa`: Ejecutar JavaScript for Automation en memoria mediante `OSAScript`, lo que resulta útil para la post-exploitation nativa de macOS sin dejar archivos de script separados.
- `clipboard_monitor`: Consultar el pasteboard y enviar los cambios a Mythic, lo que resulta práctico para workflows de robo de credenciales/tokens que dependen de copiar y pegar.
- `screencapture`: Capturar el desktop del usuario en macOS.
- `execute_library`: Cargar un dylib desde el disco y llamar a una función exportada específica.
- `libinject`: Inyectar un stub de shellcode que obliga a otro proceso de macOS a cargar un dylib desde el disco.
- `persist_launchd`: Crear persistencia mediante LaunchAgent / LaunchDaemon directamente desde el agent.

### Movimiento lateral

- `ssh`: Conectarse por SSH a un host usando las credenciales designadas y abrir un PTY sin generar ssh.
- `sshauth`: Conectarse por SSH a los hosts especificados usando las credenciales designadas. También puedes utilizarlo para ejecutar un comando específico en los hosts remotos mediante SSH o para usar SCP con archivos.
- `link_tcp`: Enlazar con otro agent mediante TCP, permitiendo la comunicación directa entre agents.
- `link_webshell`: Enlazar con un agent utilizando el perfil P2P de webshell, permitiendo el acceso remoto a la interfaz web del agent.
- `rpfwd`: Iniciar o detener un Reverse Port Forward, permitiendo el acceso remoto a servicios de la red target.
- `socks`: Iniciar o detener un proxy SOCKS5 en la red target, permitiendo tunelizar tráfico a través del host comprometido. Compatible con herramientas como proxychains.
- `portscan`: Escanear host(s) en busca de puertos abiertos, útil para identificar posibles targets para el movimiento lateral u otros ataques.

### Ejecución de procesos

- `shell`: Ejecutar un único comando de shell mediante /bin/sh, permitiendo la ejecución directa de comandos en el sistema target.
- `run`: Ejecutar un comando desde el disco con argumentos, permitiendo la ejecución de binarios o scripts en el sistema target.
- `pty`: Abrir un PTY interactivo, permitiendo la interacción directa con el shell del sistema target.






## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [Mythic 3.3->3.4 Updates](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [Transforming Red Team Ops with Mythic’s Hidden Gems: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
{{#include ../banners/hacktricks-training.md}}
