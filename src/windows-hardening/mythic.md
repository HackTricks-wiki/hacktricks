# Mythic

## ¿Qué es Mythic?

Mythic es un marco de comando y control (C2) modular y de código abierto diseñado para red teaming. Permite a los profesionales de la seguridad gestionar y desplegar varios agentes (payloads) en diferentes sistemas operativos, incluyendo Windows, Linux y macOS. Mythic proporciona una interfaz web fácil de usar para gestionar agentes, ejecutar comandos y recopilar resultados, lo que lo convierte en una herramienta poderosa para simular ataques del mundo real en un entorno controlado.

### Instalación

Para instalar Mythic, sigue las instrucciones en el **[repositorio oficial de Mythic](https://github.com/its-a-feature/Mythic)**.

### Agentes

Mythic soporta múltiples agentes, que son los **payloads que realizan tareas en los sistemas comprometidos**. Cada agente puede ser adaptado a necesidades específicas y puede ejecutarse en diferentes sistemas operativos.

Por defecto, Mythic no tiene ningún agente instalado. Sin embargo, ofrece algunos agentes de código abierto en [**https://github.com/MythicAgents**](https://github.com/MythicAgents).

Para instalar un agente de ese repositorio, solo necesitas ejecutar:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/apfell
```
Puedes agregar nuevos agentes con el comando anterior incluso si Mythic ya está en funcionamiento.

### Perfiles de C2

Los perfiles de C2 en Mythic definen **cómo se comunican los agentes con el servidor Mythic**. Especifican el protocolo de comunicación, los métodos de cifrado y otras configuraciones. Puedes crear y gestionar perfiles de C2 a través de la interfaz web de Mythic.

Por defecto, Mythic se instala sin perfiles, sin embargo, es posible descargar algunos perfiles del repositorio [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) ejecutando:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo es un agente de Windows escrito en C# utilizando el .NET Framework 4.0 diseñado para ser utilizado en las ofertas de capacitación de SpecterOps.

Instálalo con:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
Este agente tiene muchos comandos que lo hacen muy similar al Beacon de Cobalt Strike con algunos extras. Entre ellos, soporta:

### Acciones comunes

- `cat`: Imprimir el contenido de un archivo
- `cd`: Cambiar el directorio de trabajo actual
- `cp`: Copiar un archivo de una ubicación a otra
- `ls`: Listar archivos y directorios en el directorio actual o en la ruta especificada
- `pwd`: Imprimir el directorio de trabajo actual
- `ps`: Listar procesos en ejecución en el sistema objetivo (con información adicional)
- `download`: Descargar un archivo del sistema objetivo a la máquina local
- `upload`: Subir un archivo de la máquina local al sistema objetivo
- `reg_query`: Consultar claves y valores del registro en el sistema objetivo
- `reg_write_value`: Escribir un nuevo valor en una clave del registro especificada
- `sleep`: Cambiar el intervalo de sueño del agente, que determina con qué frecuencia se comunica con el servidor Mythic
- Y muchos otros, usa `help` para ver la lista completa de comandos disponibles.

### Escalación de privilegios

- `getprivs`: Habilitar tantos privilegios como sea posible en el token del hilo actual
- `getsystem`: Abrir un manejador a winlogon y duplicar el token, escalando efectivamente los privilegios al nivel de SYSTEM
- `make_token`: Crear una nueva sesión de inicio de sesión y aplicarla al agente, permitiendo la suplantación de otro usuario
- `steal_token`: Robar un token primario de otro proceso, permitiendo que el agente suplante al usuario de ese proceso
- `pth`: Ataque Pass-the-Hash, permitiendo que el agente se autentique como un usuario usando su hash NTLM sin necesidad de la contraseña en texto plano
- `mimikatz`: Ejecutar comandos de Mimikatz para extraer credenciales, hashes y otra información sensible de la memoria o de la base de datos SAM
- `rev2self`: Revertir el token del agente a su token primario, efectivamente reduciendo los privilegios al nivel original
- `ppid`: Cambiar el proceso padre para trabajos de post-explotación especificando un nuevo ID de proceso padre, permitiendo un mejor control sobre el contexto de ejecución del trabajo
- `printspoofer`: Ejecutar comandos de PrintSpoofer para eludir las medidas de seguridad del spooler de impresión, permitiendo la escalación de privilegios o la ejecución de código
- `dcsync`: Sincronizar las claves Kerberos de un usuario a la máquina local, permitiendo el cracking de contraseñas fuera de línea o ataques adicionales
- `ticket_cache_add`: Agregar un ticket Kerberos a la sesión de inicio de sesión actual o a una especificada, permitiendo la reutilización de tickets o la suplantación

### Ejecución de procesos

- `assembly_inject`: Permite inyectar un cargador de ensamblado .NET en un proceso remoto
- `execute_assembly`: Ejecuta un ensamblado .NET en el contexto del agente
- `execute_coff`: Ejecuta un archivo COFF en memoria, permitiendo la ejecución en memoria de código compilado
- `execute_pe`: Ejecuta un ejecutable no administrado (PE)
- `inline_assembly`: Ejecuta un ensamblado .NET en un AppDomain desechable, permitiendo la ejecución temporal de código sin afectar el proceso principal del agente
- `run`: Ejecuta un binario en el sistema objetivo, utilizando el PATH del sistema para encontrar el ejecutable
- `shinject`: Inyecta shellcode en un proceso remoto, permitiendo la ejecución en memoria de código arbitrario
- `inject`: Inyecta shellcode del agente en un proceso remoto, permitiendo la ejecución en memoria del código del agente
- `spawn`: Genera una nueva sesión de agente en el ejecutable especificado, permitiendo la ejecución de shellcode en un nuevo proceso
- `spawnto_x64` y `spawnto_x86`: Cambiar el binario predeterminado utilizado en trabajos de post-explotación a una ruta especificada en lugar de usar `rundll32.exe` sin parámetros, lo cual es muy ruidoso.

### Mithic Forge

Esto permite **cargar archivos COFF/BOF** desde el Mythic Forge, que es un repositorio de cargas útiles y herramientas precompiladas que se pueden ejecutar en el sistema objetivo. Con todos los comandos que se pueden cargar, será posible realizar acciones comunes ejecutándolos en el proceso actual del agente como BOFs (más sigilosos generalmente).

Comienza a instalarlos con:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Luego, usa `forge_collections` para mostrar los módulos COFF/BOF del Mythic Forge para poder seleccionarlos y cargarlos en la memoria del agente para su ejecución. Por defecto, las siguientes 2 colecciones se añaden en Apollo:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Después de que se cargue un módulo, aparecerá en la lista como otro comando como `forge_bof_sa-whoami` o `forge_bof_sa-netuser`.

### Ejecución de Powershell y scripting

- `powershell_import`: Importa un nuevo script de PowerShell (.ps1) en la caché del agente para su ejecución posterior.
- `powershell`: Ejecuta un comando de PowerShell en el contexto del agente, permitiendo scripting y automatización avanzados.
- `powerpick`: Inyecta un ensamblado cargador de PowerShell en un proceso sacrificial y ejecuta un comando de PowerShell (sin registro de PowerShell).
- `psinject`: Ejecuta PowerShell en un proceso especificado, permitiendo la ejecución dirigida de scripts en el contexto de otro proceso.
- `shell`: Ejecuta un comando de shell en el contexto del agente, similar a ejecutar un comando en cmd.exe.

### Movimiento Lateral

- `jump_psexec`: Usa la técnica PsExec para moverse lateralmente a un nuevo host copiando primero el ejecutable del agente Apollo (apollo.exe) y ejecutándolo.
- `jump_wmi`: Usa la técnica WMI para moverse lateralmente a un nuevo host copiando primero el ejecutable del agente Apollo (apollo.exe) y ejecutándolo.
- `wmiexecute`: Ejecuta un comando en el sistema local o remoto especificado usando WMI, con credenciales opcionales para suplantación.
- `net_dclist`: Recupera una lista de controladores de dominio para el dominio especificado, útil para identificar posibles objetivos para el movimiento lateral.
- `net_localgroup`: Lista grupos locales en la computadora especificada, predeterminando a localhost si no se especifica ninguna computadora.
- `net_localgroup_member`: Recupera la membresía de grupos locales para un grupo especificado en la computadora local o remota, permitiendo la enumeración de usuarios en grupos específicos.
- `net_shares`: Lista recursos compartidos remotos y su accesibilidad en la computadora especificada, útil para identificar posibles objetivos para el movimiento lateral.
- `socks`: Habilita un proxy compatible con SOCKS 5 en la red objetivo, permitiendo el túnel de tráfico a través del host comprometido. Compatible con herramientas como proxychains.
- `rpfwd`: Comienza a escuchar en un puerto especificado en el host objetivo y reenvía tráfico a través de Mythic a una IP y puerto remotos, permitiendo el acceso remoto a servicios en la red objetivo.
- `listpipes`: Lista todos los pipes nombrados en el sistema local, lo que puede ser útil para el movimiento lateral o la escalada de privilegios al interactuar con mecanismos IPC.

### Comandos Varios
- `help`: Muestra información detallada sobre comandos específicos o información general sobre todos los comandos disponibles en el agente.
- `clear`: Marca tareas como 'limpiadas' para que no puedan ser recogidas por los agentes. Puedes especificar `all` para limpiar todas las tareas o `task Num` para limpiar una tarea específica.


## [Poseidon Agent](https://github.com/MythicAgents/Poseidon)

Poseidon es un agente de Golang que se compila en ejecutables de **Linux y macOS**.
```bash
./mythic-cli install github https://github.com/MythicAgents/Poseidon.git
```
Cuando el usuario está en Linux, tiene algunos comandos interesantes:

### Acciones comunes

- `cat`: Imprimir el contenido de un archivo
- `cd`: Cambiar el directorio de trabajo actual
- `chmod`: Cambiar los permisos de un archivo
- `config`: Ver la configuración actual y la información del host
- `cp`: Copiar un archivo de una ubicación a otra
- `curl`: Ejecutar una sola solicitud web con encabezados y método opcionales
- `upload`: Subir un archivo al objetivo
- `download`: Descargar un archivo del sistema objetivo a la máquina local
- Y muchos más

### Buscar información sensible

- `triagedirectory`: Encontrar archivos interesantes dentro de un directorio en un host, como archivos sensibles o credenciales.
- `getenv`: Obtener todas las variables de entorno actuales.

### Moverse lateralmente

- `ssh`: SSH al host usando las credenciales designadas y abrir un PTY sin iniciar ssh.
- `sshauth`: SSH a los host(s) especificados usando las credenciales designadas. También puedes usar esto para ejecutar un comando específico en los hosts remotos a través de SSH o usarlo para SCP archivos.
- `link_tcp`: Enlazar a otro agente a través de TCP, permitiendo la comunicación directa entre agentes.
- `link_webshell`: Enlazar a un agente usando el perfil P2P de webshell, permitiendo el acceso remoto a la interfaz web del agente.
- `rpfwd`: Iniciar o detener un reenvío de puerto inverso, permitiendo el acceso remoto a servicios en la red objetivo.
- `socks`: Iniciar o detener un proxy SOCKS5 en la red objetivo, permitiendo el túnel de tráfico a través del host comprometido. Compatible con herramientas como proxychains.
- `portscan`: Escanear host(s) en busca de puertos abiertos, útil para identificar posibles objetivos para movimiento lateral o ataques adicionales.

### Ejecución de procesos

- `shell`: Ejecutar un solo comando de shell a través de /bin/sh, permitiendo la ejecución directa de comandos en el sistema objetivo.
- `run`: Ejecutar un comando desde el disco con argumentos, permitiendo la ejecución de binarios o scripts en el sistema objetivo.
- `pty`: Abrir un PTY interactivo, permitiendo la interacción directa con el shell en el sistema objetivo.
