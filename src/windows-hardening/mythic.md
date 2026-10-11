# Mythic

{{#include ../banners/hacktricks-training.md}}

## ¿Qué es Mythic?

Mythic es un framework de command and control (C2) modular, colaborativo y de código abierto, diseñado para red teaming. Permite a los operadores gestionar e implementar agentes (payloads) en distintos sistemas operativos, incluidos Windows, Linux y macOS. Mythic ofrece una interfaz de usuario en el navegador para la asignación de tareas entre varios operadores, la gestión de archivos, la administración de SOCKS/rpfwd y la generación de payloads.

A diferencia de los frameworks monolíticos, el repositorio de Mythic no incluye tipos de payloads ni perfiles C2. Los agentes, wrappers y perfiles C2 suelen instalarse como componentes externos y pueden actualizarse de forma independiente del núcleo de Mythic.

### Instalación

Para instalar Mythic, sigue las instrucciones del **[repositorio oficial de Mythic](https://github.com/its-a-feature/Mythic)**. Un proceso de inicio común desde el directorio de Mythic es:

```bash
sudo make
sudo ./mythic-cli start
```

Si Mythic ya está en ejecución, normalmente puedes añadir un nuevo agent o profile con `./mythic-cli install github ...` y luego reiniciar Mythic o iniciar directamente el nuevo componente.

### Agents

Mythic admite varios agentes, que son los **payloads que realizan tareas en los sistemas comprometidos**. Cada agente se puede adaptar a necesidades específicas y puede ejecutarse en distintos sistemas operativos.

De forma predeterminada, Mythic no tiene ningún agente instalado. Los agentes de la comunidad de código abierto están en [**https://github.com/MythicAgents**](https://github.com/MythicAgents), y la [**matriz de características de la comunidad**](https://mythicmeta.github.io/overview/agent_matrix.html) es útil para comprobar rápidamente los sistemas operativos, formatos de payload, wrappers y perfiles C2 compatibles.<sup>[[1]](#references)</sup>

Para instalar un agente de esa organización, puedes ejecutar:

```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

La forma `sudo -E` es útil cuando instalas desde un entorno que no es root. Puedes añadir nuevos agents con el comando anterior incluso si Mythic ya está en ejecución.

### C2 Profiles

Los C2 profiles de Mythic definen **cómo se comunican los agents con el servidor Mythic**. Especifican el protocolo de comunicación, los métodos de cifrado y otros ajustes. Puedes crear y administrar C2 profiles a través de la interfaz web de Mythic.

De forma predeterminada, Mythic se instala sin profiles; sin embargo, es posible descargar algunos profiles del repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles) ejecutando:

```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```

Perfiles actuales relevantes para el operador que conviene tener en cuenta:

- [`http`](https://github.com/MythicC2Profiles/http): tráfico GET/POST asíncrono básico.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): tráfico HTTP más flexible, con varios dominios de callback, rotación por fail-over/round-robin, headers/parámetros de query personalizados y transformaciones de mensajes (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`) ubicadas en cookies, headers, parámetros de query o el cuerpo.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): configuración de mensajes HTTP mediante JSON/TOML cuando el perfil `http` estático resulta demasiado reconocible.

### Notas actuales sobre la plataforma

- Muchos agentes y perfiles públicos ahora se instalan con imágenes de contenedor remotas precompiladas.
  Si haces un fork de un componente o aplicas un parche local y Mythic sigue usando el comportamiento anterior, inspecciona las entradas `.env` generadas para `*_REMOTE_IMAGE`,
  `*_USE_BUILD_CONTEXT` y `*_USE_VOLUME`; habilitar
  `*_USE_BUILD_CONTEXT="true"` suele hacer que Mythic reconstruya desde tu contexto Docker local en vez de reutilizar silenciosamente la imagen remota.
- Los scripts de navegador son una de las funciones de calidad de vida más valiosas de Mythic para los operadores: pueden convertir la salida sin procesar de los comandos en tablas, visores de capturas de pantalla, enlaces de descarga, enlaces de búsqueda y botones que emiten nuevas tareas directamente desde la UI. Las versiones actuales de Mythic permiten que cada operador tenga sus propios scripts, los active o desactive globalmente o por tarea, y ofrecen mejores resultados cuando los agentes devuelven JSON estructurado en lugar de texto sin formato. Esto resulta especialmente útil para los flujos de trabajo repetitivos de `ls`, `ps`, triage y exploración de archivos.<sup>[[4]](#references)[[6]](#references)</sup>
- Las versiones más recientes de Mythic también admiten patrones de interactive tasking y Push C2, que reducen la necesidad de sondeo con `sleep 0` durante operaciones con mucho uso de PTY/SOCKS/rpfwd. Cuando un agente/perfil lo admite, normalmente genera menos sobrecarga que bombardear el servidor con check-ins constantes solo para mantener utilizable un canal interactivo.<sup>[[3]](#references)</sup>
- Los builders actuales de Mythic de la era 3.4 tienen más en cuenta el contexto de lo que dan a entender los textos antiguos: los parámetros de build ahora se pueden agrupar u ocultar según el SO seleccionado u otras opciones de build; los tipos de payload pueden declarar si admiten varios perfiles C2 o varias instancias del mismo C2 en un solo build; y las desviaciones de parámetros C2 permiten que un agente oculte los campos que no implementa realmente. Esto importa cuando alternas entre `http`, `httpx`, `smb`,
  `tcp` y `websocket`, porque las opciones de build seguras/válidas ya no se presentan en un formulario estático y uniforme.<sup>[[5]](#references)</sup>
- Si estás creando un par personalizado de agente/perfil y no quieres que Mythic use su formato de mensaje JSON ni su cifrado predeterminado en el wire, usa un
  `translation_container`: Mythic elimina el UUID, entrega el blob cifrado y el material de clave al traductor mediante gRPC y espera recibir bytes nativos del agente. Esta es la forma adecuada de admitir protocolos binarios, framing personalizado o cifrado del lado del agente sin reescribir todo el servidor.
- Recuerda que los callbacks vinculados/P2P no se limitan a transportar tareas. El flujo `get_tasking` de Mythic también puede transportar respuestas y datos de `delegates`, `socks`,
  `rpfwd` e `interactive`. En la práctica, un callback de egress puede atender callbacks internos y canales de pivot en el mismo bucle de sondeo; si los agentes secundarios realizan sus propios check-ins periódicos, `get_delegate_tasks=false` evita que el padre consuma accidentalmente los trabajos en cola del callback interno.

### Payloads wrapper

Los payloads wrapper permiten conservar la misma lógica del agente y cambiar la representación en disco que se entrega o persiste.

- `service_wrapper`: convierte otro payload en un ejecutable de servicio de Windows, lo que resulta útil cuando la ruta de ejecución requiere un binario de servicio válido.
- `scarecrow_wrapper`: envuelve shellcode compatible con el loader ScareCrow para generar salidas respaldadas por un loader, como EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo es un agente de Windows escrito en C# con .NET Framework 4.0, diseñado para usarse en las ofertas de formación de SpecterOps.<sup>[[2]](#references)</sup>

Instálalo con:

```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

### Notas actuales de compilación/perfiles

- Apollo actualmente puede generar payloads `WinExe`, `Shellcode`, `Service` y `Source`.
- Los perfiles de Apollo más usados son `http`, `httpx`, `smb`, `tcp` y `websocket`.
- `httpx` suele ser la opción más flexible cuando necesitas rotación de dominios, compatibilidad con proxies, ubicación personalizada de mensajes y transformaciones de mensajes, en lugar del perfil `http` estático más antiguo.
- Apollo es uno de los agentes comunitarios con más funciones y actualmente ofrece integraciones del lado de Mythic, como scripts de navegador, vistas del explorador de archivos/procesos, capturas de pantalla, keylogging, SOCKS, rpfwd, Push C2 y enrutamiento P2P.
- Apollo admite payloads wrapper como `service_wrapper` y `scarecrow_wrapper`.
- Apollo admite la carga dinámica de comandos, por lo que puedes mantener ligero el payload inicial y cargar comandos adicionales o módulos Forge más adelante, en lugar de compilar todas las capacidades de post-explotación en la primera compilación.
- Al generar salida de shellcode, el builder actual de Apollo también ofrece opciones de formato Donut (`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`) y comportamientos de bypass de Donut (`None`, `Abort on fail`, `Continue on fail`). Esto resulta útil si el objetivo final es volver a envolver el shellcode con `service_wrapper`, `scarecrow_wrapper` o un loader personalizado.
- `register_file` y `register_assembly` son las primitivas de staging para `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` y `powerpick`. En las compilaciones actuales de Apollo, esos artefactos preparados se almacenan en caché en el cliente como blobs AES256 protegidos con DPAPI.
- Los resultados de `ls` y `ps` se integran especialmente bien con los scripts de navegador y el explorador de archivos/procesos de Mythic, lo que agiliza notablemente el triage del operador en operaciones colaborativas.
- Los trabajos fork-and-run de Apollo heredan la configuración del proceso sacrificial de
  `spawnto_x86` / `spawnto_x64`, heredan la selección del proceso padre de `ppid` y
  luego usan la primitiva de inyección seleccionada actualmente. En la práctica, esto significa
  que el ajuste de OPSEC para un comando suele afectar a `execute_assembly`,
  `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` y `spawn` al
  mismo tiempo.
- Los backends de inyección de Apollo documentados actualmente incluyen `CreateRemoteThread`,
  `QueueUserAPC` (estilo early-bird) y `NtCreateThreadEx` mediante syscalls. Usa
  `get_injection_techniques` antes de ejecutar post-explotación ruidosa y
  `set_injection_technique` si necesitas cambiar una primitiva que
  entre en conflicto con el objetivo o con el comando que quieras ejecutar.
- `blockdlls` solo afecta a los procesos sacrificiales creados para trabajos de post-explotación.
  Si lo combinas con un objetivo `spawnto_x64` menos sospechoso que el `rundll32.exe` básico predeterminado,
  es uno de los cambios más sencillos que puedes hacer del lado de Apollo
  antes de ejecutar tareas con mucho uso de assembly/PowerShell.

### Pipeline de compilación de agentes .NET con detección en mente

Un fork de Apollo con detección en mente debe tratarse como un **problema de todo el sistema de compilación**, no como un paso final de `obfuscate.exe`. Este caso de estudio complementa la [metodología general de evasión de AV](av-bypass.md) y las [herramientas de inspección de .NET](../reversing/reversing-tools-basic-methods/README.md): los cambios en los identificadores del protocolo, los metadatos de IL, el empaquetado de dependencias, la reflexión y las tareas compiladas dinámicamente forman un único límite de compatibilidad.<sup>[[8]](#references)</sup>

#### Mutación del protocolo consciente de YARA

Audita las reglas públicas de archivos/memoria antes de cambiar el código. Por ejemplo, `Multi_Trojan_Mythic_4beb7e17` de Elastic genera una coincidencia cuando están presentes **7 de 11** cadenas JSON/de acción de Mythic, incluidas `task_id`, `post_response`, `c2_profile`, `get_tasking` y `get_delegate_tasks`. Cambiar el nombre de suficientes campos puede superar ese umbral, pero estos son valores del protocolo, no símbolos cosméticos: el agente y la implementación correspondiente del servidor/perfil deben cambiarse a la vez.<sup>[[7]](#references)[[8]](#references)</sup>

Esto solo elimina un conjunto de características estáticas. La periodicidad del check-in, la estructura de los mensajes, el flujo de tareas/respuestas y la reconstrucción de cadenas en tiempo de ejecución pueden seguir siendo indicadores de comportamiento o de memoria; por tanto, valida tanto el artefacto compilado como un callback ejecutado, en lugar de considerar que un análisis de cadenas limpio es suficiente.<sup>[[8]](#references)</sup>

#### Fusiona antes de aplicar transformaciones globales

La incrustación de recursos con herramientas como Costura deja los ensamblados complementarios como recursos comprimidos. Por eso, un ofuscador que solo procesa el módulo externo no detecta sus nombres de tipos ni sus metadatos; en cambio, ofuscar cada DLL por separado puede asignar nombres incompatibles a contratos entre ensamblados. Primero fusiona las salidas de compilación en el nivel de IL (por ejemplo, con [ILRepack](https://github.com/gluck/il-repack)) y luego aplica un único mapa de renombrado al módulo resultante.<sup>[[8]](#references)</sup>

```text
agent.exe + dependency DLLs
          -> ILRepack -> merged.exe
          -> dnlib IL/metadata transforms
          -> AsmResolver PE/resource patching
          -> final payload
```

Un pass personalizado puede usar [dnlib](https://github.com/0xd4d/dnlib) para transformaciones de IL/metadata administrados y [AsmResolver](https://github.com/Washi1337/AsmResolver) para aplicar parches posteriores a la escritura en PE/recursos. En el caso de estudio, las instrucciones `ldstr` aptas se convirtieron en llamadas a un decryptor con token entero, respaldado por una clave rolling-XOR nueva de 16 bytes, mientras que los símbolos y espacios de nombres se asignaron a nombres verosímiles de estilo empresarial en lugar de identificadores secuenciales cortos. Otros passes eliminaron atributos seleccionados del compilador/depurador, limpiaron referencias de merger/embedding, cambiaron el nombre de los recursos y aplicaron parches a la información de versión. Vuelve a generar los nombres, el código muerto y el material de cifrado en cada build independiente: cambiar el texto cifrado elimina los bytes estables, pero un decryptor estable o un patrón de transformación reconocible son en sí mismos una firma.<sup>[[8]](#references)</sup>

#### Mantener sincronizadas las tareas dinámicas con el payload

Apollo puede compilar el código fuente de las tareas en el servidor, enviar los bytes de la DLL y cargarlos con `Assembly.Load()`. Una vez que se cambian los nombres de los tipos públicos del agente base, las tareas posteriores compiladas contra la API original ya no se resuelven. Trata el mapa de renombrado exportado como un artefacto ABI específico del payload:<sup>[[8]](#references)</sup>

1. Vincula el mapa y el contexto de tipos al identificador exacto del payload/build.
2. Para cada build de tarea, recupera ese mapa y reescribe un árbol de código fuente temporal.
3. Reescribe únicamente las referencias resueltas a espacios de nombres, tipos, tipos anidados/genéricos, campos y propiedades; después, compila contra el assembly combinado ofuscado.
4. Rechaza los mapas ausentes o que no coincidan antes de entregar la tarea, y ejecuta una prueba de inicialización después de la compilación.

La sustitución global a ciegas no es segura porque un identificador también puede aparecer en una cadena, una declaración local, un acceso a miembro, un tipo de framework o un espacio de nombres no relacionado. Si se conserva un reescritor de texto/regex, protege explícitamente esos contextos y pruébalo para detectar regresiones cada vez que cambie el esquema del mapa o un pass de renombrado.<sup>[[8]](#references)</sup>

#### Hacer que los contratos de reflection sean independientes del espacio de nombres

El código de descubrimiento que comprueba `t.FullName.StartsWith("Tasks.")` depende del espacio de nombres y falla tras reasignar los espacios de nombres. En su lugar, descubre los tipos mediante una relación de tipos estable, conservando los nombres de las clases de comandos si el dispatch sigue usando `t.Name`:<sup>[[8]](#references)</sup>

```csharp
foreach (Type t in _tasksAsm.GetExportedTypes())
{
    if (t.IsSubclassOf(typeof(Tasking)) && !t.IsAbstract)
        _loadedTaskTypes[t.Name] = t;
}
```

Mantén una allowlist explícita de nombres visibles mediante reflection, campos del serializer, entry points y APIs entre assemblies que no deben renombrarse. Por último, descompila el resultado con ILSpy/dnSpy, analiza las representaciones tanto en archivos como en memoria y prueba todas las rutas de comandos y loaders en un laboratorio de EDR; una compilación que se inicia correctamente aún puede contener tareas que fallen por el renombrado o comportamientos que solo se detecten durante la ejecución.<sup>[[8]](#references)</sup>

Este agent tiene muchos comandos, lo que lo hace muy similar al Beacon de Cobalt Strike, aunque con algunos extras. Entre ellos, admite:

### Acciones comunes

- `cat`: Mostrar el contenido de un archivo
- `cd`: Cambiar el directorio de trabajo actual
- `cp`: Copiar un archivo de una ubicación a otra
- `ls`: Mostrar los archivos y directorios del directorio actual o de la ruta especificada
- `ifconfig`: Obtener adaptadores e interfaces de red
- `netstat`: Obtener información sobre las conexiones TCP y UDP
- `pwd`: Mostrar el directorio de trabajo actual
- `ps`: Mostrar los procesos en ejecución en el sistema objetivo (con información adicional)
- `jobs`: Mostrar todos los jobs en ejecución asociados a tareas de larga duración
- `download`: Descargar un archivo del sistema objetivo al equipo local
- `upload`: Subir un archivo del equipo local al sistema objetivo
- `reg_query`: Consultar claves y valores del registro en el sistema objetivo
- `reg_write_value`: Escribir un nuevo valor en una clave del registro especificada
- `sleep`: Cambiar el intervalo de espera del agent, que determina con qué frecuencia se comunica con el servidor Mythic
- Y muchos otros; usa `help` para ver la lista completa de comandos disponibles.

### Escalada de privilegios

- `getprivs`: Habilitar tantos privilegios como sea posible en el token del thread actual
- `getsystem`: Abrir un handle a winlogon y duplicar el token, elevando efectivamente los privilegios al nivel SYSTEM
- `make_token`: Crear una nueva sesión de inicio de sesión y aplicarla al agent, lo que permite suplantar a otro usuario
- `steal_token`: Robar un token principal de otro proceso, lo que permite al agent suplantar al usuario de ese proceso
- `pth`: Ataque Pass-the-Hash, que permite al agent autenticarse como un usuario mediante su hash NTLM, sin necesitar la contraseña en texto plano
- `mimikatz`: Ejecutar comandos de Mimikatz para extraer credenciales, hashes y otra información confidencial de la memoria o de la base de datos SAM
- `rev2self`: Revertir el token del agent a su token principal, eliminando efectivamente los privilegios y volviendo al nivel original
- `ppid`: Cambiar el proceso padre de los jobs de post-exploitation especificando un nuevo ID de proceso padre, lo que permite controlar mejor el contexto de ejecución del job
- `printspoofer`: Ejecutar comandos de PrintSpoofer para eludir las medidas de seguridad del print spooler, lo que permite escalar privilegios o ejecutar código
- `dcsync`: Sincronizar las claves Kerberos de un usuario con el equipo local, lo que permite descifrar contraseñas offline o realizar otros ataques
- `ticket_cache_add`: Añadir un ticket Kerberos a la sesión de inicio de sesión actual o a una especificada, lo que permite reutilizar tickets o suplantar identidades

### Ejecución de procesos

- `assembly_inject`: Permite inyectar un loader de .NET assembly en un proceso remoto
- `blockdlls`: Bloquear la carga de DLL no firmadas por Microsoft en los jobs de post-exploitation
- `execute_assembly`: Ejecutar un .NET assembly en el contexto del agent
- `execute_coff`: Ejecutar un archivo COFF en memoria, lo que permite ejecutar código compilado en memoria
- `execute_pe`: Ejecutar un ejecutable PE no administrado
- `keylog_inject`: Inyectar un keylogger en otro proceso y transmitir las pulsaciones de teclas a la vista de keylog de Mythic
- `screenshot` / `screenshot_inject`: Capturar el escritorio actual directamente o
  inyectando un assembly de captura de pantalla en un proceso/sesión objetivo
- `get_injection_techniques`: Mostrar las técnicas de inyección disponibles y la seleccionada actualmente
- `inline_assembly`: Ejecutar un .NET assembly en un AppDomain desechable, lo que permite ejecutar código temporalmente sin afectar al proceso principal del agent
- `register_assembly`: Registrar un .NET assembly para ejecutarlo más adelante
- `register_file`: Registrar un archivo en la caché del agent para usarlo después en tareas `execute_*` o de PowerShell
- `run`: Ejecutar un binario en el sistema objetivo, usando el PATH del sistema para encontrar el ejecutable
- `set_injection_technique`: Cambiar la primitiva de inyección que utilizan los jobs de post-exploitation
- `shinject`: Inyectar shellcode en un proceso remoto, lo que permite ejecutar código arbitrario en memoria
- `inject`: Inyectar shellcode del agent en un proceso remoto, lo que permite ejecutar el código del agent en memoria
- `spawn`: Crear una nueva sesión del agent en el ejecutable especificado, lo que permite ejecutar shellcode en un proceso nuevo
- `spawnto_x64` y `spawnto_x86`: Cambiar el binario predeterminado usado en los jobs de post-exploitation por una ruta especificada, en lugar de usar `rundll32.exe` sin parámetros, que genera mucho ruido.

### Mythic Forge

Esto permite **cargar** archivos COFF/BOF desde Mythic Forge, un repositorio de payloads y herramientas precompilados que se pueden ejecutar en el sistema objetivo. Con todos los comandos que se pueden cargar, será posible realizar acciones comunes ejecutándolos como BOF en el proceso actual del agent (por lo general, con mejor OPSEC que al crear un proceso separado).

Empieza instalándolos con:

```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```

Luego, usa `forge_collections` para mostrar los módulos COFF/BOF de Mythic Forge, de modo que puedas seleccionarlos y cargarlos en la memoria del agente para ejecutarlos. De forma predeterminada, en Apollo se añaden las siguientes 2 colecciones:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

Una vez cargado un módulo, aparecerá en la lista como otro comando, por ejemplo `forge_bof_sa-whoami` o `forge_bof_sa-netuser`.

Para los BOF, recuerda que Forge **no** pasa simplemente una cadena plana de argumentos a Apollo. Asigna los parámetros de BOF al formato typed-array de Mythic y luego los reenvía al flujo `execute_coff` de Apollo. Si un BOF cargado desde Forge se comporta de forma extraña, comprueba los tipos de argumentos o el punto de entrada esperados por el BOF, en lugar de revisar únicamente la línea de comandos que escribiste. Ten en cuenta también que el cargador de BOF más reciente de Apollo cambió la gestión de argumentos con respecto a las compilaciones mucho más antiguas de la época de la versión 2.3.1, por lo que los BOF obsoletos o las colecciones antiguas pueden fallar simplemente porque cambiaron las expectativas de serialización.

### Ejecución de PowerShell y scripts

- `powershell_import`: Importa un nuevo script de PowerShell (.ps1) a la caché del agente para ejecutarlo más adelante
- `powershell`: Ejecuta un comando de PowerShell en el contexto del agente, lo que permite usar scripting avanzado y automatización
- `powerpick`: Inyecta un assembly cargador de PowerShell en un proceso sacrificial y ejecuta un comando de PowerShell (sin el registro de PowerShell).
- `psinject`: Ejecuta PowerShell en un proceso especificado, lo que permite ejecutar scripts de forma dirigida en el contexto de otro proceso
- `shell`: Ejecuta un comando de shell en el contexto del agente, de forma similar a ejecutar un comando en cmd.exe

### Movimiento lateral

- `jump_psexec`: Usa la técnica PsExec para moverse lateralmente a un nuevo host; primero copia el ejecutable del agente Apollo (apollo.exe) y luego lo ejecuta.
- `jump_wmi`: Usa la técnica WMI para moverse lateralmente a un nuevo host; primero copia el ejecutable del agente Apollo (apollo.exe) y luego lo ejecuta.
- `link` y `unlink`: Crean y cierran enlaces P2P (por ejemplo, mediante SMB/TCP) entre callbacks.
- `wmiexecute`: Ejecuta un comando en el sistema local o en el sistema remoto especificado mediante WMI, con credenciales opcionales para suplantación.
- `net_dclist`: Obtiene una lista de controladores de dominio del dominio especificado, útil para identificar posibles objetivos de movimiento lateral.
- `net_localgroup`: Enumera los grupos locales del equipo especificado; si no se especifica ningún equipo, usa localhost.
- `net_localgroup_member`: Obtiene los miembros de un grupo local en el equipo local o remoto, lo que permite enumerar usuarios de grupos específicos.
- `net_shares`: Enumera los recursos compartidos remotos y su accesibilidad en el equipo especificado, útil para identificar posibles objetivos de movimiento lateral.
- `socks`: Habilita un proxy compatible con SOCKS 5 en la red objetivo, lo que permite tunelizar el tráfico a través del host comprometido. Compatible con herramientas como proxychains.
- `rpfwd`: Empieza a escuchar en un puerto especificado del host objetivo y reenvía el tráfico a través de Mythic a una IP y un puerto remotos, lo que permite acceder de forma remota a servicios de la red objetivo.
- `listpipes`: Enumera todas las named pipes del sistema local, lo que puede ser útil para el movimiento lateral o la escalada de privilegios mediante la interacción con mecanismos IPC.

Para consultar las primitivas de ejecución WMI de bajo nivel que se usan internamente en `jump_wmi` o `wmiexecute`, consulta [WmiExec](lateral-movement/wmiexec.md). Para conocer patrones más generales de pivoting, consulta [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md).

### Comandos varios
- `help`: Muestra información detallada sobre comandos específicos o información general sobre todos los comandos disponibles en el agente.
- `clear`: Marca las tareas como «cleared» para que los agentes no puedan recogerlas. Puedes especificar `all` para borrar todas las tareas o `task Num` para borrar una tarea concreta.  


## [Agente Poseidon](https://github.com/MythicAgents/poseidon)

Poseidon es un agente de Golang que se compila en ejecutables para **Linux y macOS**.

```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```

### Notas actuales sobre builds/perfiles

- Los builds actuales de Poseidon tienen como objetivo Linux y macOS en `x86_64` y `arm64`.
- Los formatos de salida compatibles incluyen ejecutables nativos y salidas de tipo biblioteca compartida, como `dylib` y `so`.
- Poseidon es compatible con `http`, `websocket`, `tcp` y `dynamichttp`, y los builders actuales ofrecen ajustes de egress múltiple, como `egress_order` y umbrales de failover.
- Los metadatos actuales de capacidades de Poseidon también anuncian browser scripts, integración del browser con archivos/procesos, tasking interactivo, keylogging, capturas de pantalla, Push C2, SOCKS, rpfwd y P2P, por lo que puede funcionar como un verdadero nodo pivot de Linux/macOS y no solo como una shell remota básica.
- Conviene revisar opciones de build como `proxy_bypass` y `garble` cuando necesites un comportamiento de red más limpio o una ofuscación adicional del binario Go.
- `pty` es uno de los comandos nuevos más útiles para mejorar la calidad de vida en operaciones de Linux/macOS, porque abre un PTY interactivo y puede exponer un puerto del lado de Mythic para una interacción más completa con la terminal, sin recurrir a la antigua solución alternativa `sleep 0` + SOCKS.
- La documentación actual de Poseidon es especialmente interesante para tradecraft centrado en macOS: `jxa` ejecuta JavaScript for Automation en memoria, `screencapture` captura el escritorio del usuario conectado, `clipboard_monitor` transmite los cambios del pasteboard, `execute_library` carga una dylib local y llama a una función de esta, y `libinject` fuerza a un proceso remoto a cargar una dylib desde el disco.
- Para tareas de larga duración, recuerda que Poseidon ejecuta el trabajo de post-exploitation en goroutines/hilos cooperativos que no se pueden terminar a la fuerza. La documentación también señala explícitamente que actualmente no hay ofuscación integrada del agent, por lo que el tradecraft a nivel de build/perfil importa más que con implants comerciales muy ofuscados.

Para consultar tradecraft específico de macOS en operaciones basadas en Mythic, abuso de JAMF o ideas de MDM-as-C2, revisa [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md).

Cuando se usa en Linux o macOS, cuenta con algunos comandos interesantes:

### Acciones comunes

- `cat`: Imprimir el contenido de un archivo
- `cd`: Cambiar el directorio de trabajo actual
- `chmod`: Cambiar los permisos de un archivo
- `config`: Ver la configuración actual y la información del host
- `cp`: Copiar un archivo de una ubicación a otra
- `curl`: Ejecutar una solicitud web individual con encabezados y método opcionales
- `upload`: Subir un archivo al objetivo
- `download`: Descargar un archivo del sistema objetivo al equipo local
- Y muchos más

### Buscar información sensible

- `triagedirectory`: Buscar archivos interesantes dentro de un directorio de un host, como archivos sensibles o credenciales.
- `getenv`: Obtener todas las variables de entorno actuales.

### Tradecraft específico de macOS

- `jxa`: Ejecutar JavaScript for Automation en memoria mediante `OSAScript`, lo que resulta
  útil para realizar post-exploitation nativa en macOS sin dejar archivos de script
  por separado.
- `clipboard_monitor`: Consultar el pasteboard y enviar los cambios a Mythic,
  algo útil para workflows de robo de credenciales/tokens que dependen de copiar y pegar.
- `screencapture`: Capturar el escritorio del usuario en macOS.
- `execute_library`: Cargar una dylib desde el disco y llamar a una función exportada específica.
- `libinject`: Inyectar un stub de shellcode que fuerza a otro proceso de macOS a cargar una dylib desde el disco.
- `persist_launchd`: Crear persistencia de LaunchAgent / LaunchDaemon directamente desde el agent.

### Movimiento lateral

- `ssh`: Conectarse por SSH a un host usando las credenciales designadas y abrir un PTY sin iniciar ssh.
- `sshauth`: Conectarse por SSH a los hosts especificados usando las credenciales designadas. También se puede usar para ejecutar un comando específico en los hosts remotos mediante SSH o para copiar archivos con SCP.
- `link_tcp`: Enlazarse con otro agent mediante TCP, lo que permite la comunicación directa entre agents.
- `link_webshell`: Enlazarse con un agent usando el perfil P2P de webshell, lo que permite el acceso remoto a la interfaz web del agent.
- `rpfwd`: Iniciar o detener un Reverse Port Forward, que permite el acceso remoto a servicios de la red objetivo.
- `socks`: Iniciar o detener un proxy SOCKS5 en la red objetivo, lo que permite tunelizar el tráfico a través del host comprometido. Compatible con herramientas como proxychains.
- `portscan`: Analizar hosts en busca de puertos abiertos, lo que resulta útil para identificar posibles objetivos de movimiento lateral o ataques posteriores.

### Ejecución de procesos

- `shell`: Ejecutar un único comando de shell mediante /bin/sh, lo que permite ejecutar comandos directamente en el sistema objetivo.
- `run`: Ejecutar un comando desde el disco con argumentos, lo que permite ejecutar binarios o scripts en el sistema objetivo.
- `pty`: Abrir un PTY interactivo, lo que permite interactuar directamente con la shell del sistema objetivo.

## References

- [1] [Matriz de características de agents de la comunidad Mythic](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [README de Apollo](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Novedades de Mythic v3.2: tasking interactivo, Push C2 y explorador dinámico de archivos](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser Scripts - Documentación de Mythic](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Actualizaciones de Mythic 3.3->3.4](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Transformando las operaciones de Red Team con las joyas ocultas de Mythic: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
- [7] [Elastic protections-artifacts: reglas YARA de Multi_Trojan_Mythic](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Mythic.yar)
- [8] [De fork a framework: lo que aprendimos sobre la invasión de agents al modificar Apollo](https://bishopfox.com/blog/from-fork-to-framework-what-modifying-apollo-taught-us-about-agent-invasion)
{{#include ../banners/hacktricks-training.md}}
