# Ejecución de payloads virtualizados y evasión mediante VM personalizada

{{#include ../banners/hacktricks-training.md}}

La virtualización de payloads compila la lógica ofensiva para un conjunto de instrucciones invitado y la ejecuta con un intérprete nativo. A diferencia de un packer, que tarde o temprano debe exponer las instrucciones nativas originales en memoria, un payload virtualizado puede mantener la lógica protegida como bytecode durante toda su vida útil. Esto elimina esa ventana específica de desempaquetado, pero **no** oculta comportamientos visibles en el host, como las llamadas al sistema, la actividad de red o el límite entre la VM y el código nativo.<sup>[[2]](#references)[[3]](#references)</sup>

## Re-hosting de WebAssembly para evadir el análisis estático

En lugar de modificar una herramienta Go con muchas firmas, se puede compilar como un invitado `wasip1` e incrustarla en un loader nativo independiente. El invitado se compila con un GOROOT parcheado, donde las operaciones no compatibles, como `net.Dial`, `net.Listen`, `os/exec` y `os.Pipe`, se delegan mediante `//go:wasmimport`; después, un módulo host de Wazero implementa sockets, operaciones de procesos, llamadas a Win32 y llamadas a frameworks de macOS. Esto mantiene intacto el uso de la API Go del proyecto original, a la vez que traslada la mayor parte de su lógica a un módulo WASM cifrado que las herramientas estáticas para PE quizá no entiendan.<sup>[[4]](#references)</sup>

### Puente entre la memoria lineal y las API nativas

Un puntero del invitado es un desplazamiento de 32 bits dentro de la memoria lineal de WASM, no una dirección virtual del host. Antes de una llamada nativa, el puente puede traducir un argumento solo si está marcado como puntero local y se encuentra dentro del rango `0x10000 <= value < wasmMemorySize`; entonces produce `wasmMemoryBase + value`. El límite inferior evita reescribir handles, flags y `nil` de valor reducido; las máscaras por API generadas a partir de `win32metadata` distinguen los punteros reales de los handles, tamaños y direcciones de procesos remotos, con ajustes para los metadatos imprecisos o ambiguos.<sup>[[4]](#references)</sup>

Las API nativas también pueden devolver punteros del host mediante buffers de salida del invitado. Una tabla espejo puede asignar representaciones en la memoria del invitado a esos objetos y mantener una correspondencia inversa con la dirección original del host. COM requiere reflejar tanto la interfaz como su vtable: se pueden seguir y reflejar los punteros de datos, mientras que los punteros ejecutables en regiones `MEM_IMAGE` deben permanecer como tokens opacos, ya que WASM no puede ejecutar instrucciones nativas. Este modelo no admite directamente las API de callback del host al invitado, como `EnumWindows` o `SetWindowsHookEx`.<sup>[[4]](#references)</sup>

### Polimorfismo de la VM WASM en cada build

El runtime y el payload se pueden transformar juntos en cada build: se puede barajar la tabla de opcode a handler, reescribir cada opcode del invitado según la nueva correspondencia, aleatorizar los identificadores de sección, reemplazar el marcador mágico estándar `\0asm` por un marcador específico del build y cambiar el marcador mágico de la caché del runtime. Así, un mismo código fuente genera módulos distintos byte a byte, y las herramientas WASM habituales no pueden analizar el payload hasta que el analista recupere la correspondencia y el encuadre personalizados del loader del host.<sup>[[4]](#references)</sup>

Para la ingeniería inversa, empieza por el host nativo en vez de buscar únicamente `\0asm`: identifica el marcador compilado, la ruta de descifrado del módulo, la tabla de despacho de opcodes y los registros de funciones host de `env`; luego reconstruye un módulo estándar o instrumenta el límite de importación. El puente sigue siendo un punto de control conductual útil, porque las llamadas de red, creación de procesos, acceso al registro, carga dinámica y despacho genérico de Win32 lo atraviesan, incluso cuando el bytecode incrustado cambia entre builds.<sup>[[4]](#references)</sup>

### Camuflar el ejecutable Go externo

Cambiar solo el invitado sigue dejando un loader reconocible. Las transformaciones demostradas insertan perfiles de símbolos densos, recopilados de proyectos Go legítimos, en `gopclntab`, rotan un conjunto reducido y plausible de imports DLL y varían `VERSIONINFO` del PE más las cadenas de identidad de Authenticode. Estas transformaciones apuntan a las características estáticas y de machine learning del contenedor; no eliminan el comportamiento del runtime expuesto por los shims del host.<sup>[[4]](#references)</sup>

## Modelo de ejecución

Un loader virtualizado compacto puede dividir la ejecución en las siguientes capas.<sup>[[3]](#references)</sup>

1. Compilar C freestanding, código fuente BOF o bibliotecas de runtime mediante LLVM para una ISA de bytecode personalizada.
2. Iniciar un intérprete nativo pequeño e inicializar una correspondencia de opcodes específica del build.
3. Ejecutar el propio loader del linker de PE como bytecode: analizar encabezados, mapear secciones, aplicar reubicaciones, resolver imports y rellenar la IAT.
4. Mantener las llamadas entre invitados dentro del intérprete. Enrutar los destinos fuera de la región de bytecode, como las funciones de DLL importadas, mediante un thunk de llamadas al host nativo.
5. Trasladar las funciones de soporte, como el encuadre HTTP, TLS y partes del runtime de C, al mismo límite de interpretación.

Este modelo evita asignar una región de código nativo independiente para cada plugin e impide que el payload original aparezca como un flujo de instrucciones x86-64 reconocible. Sigue siendo un límite de evasión/ofuscación, no un límite de seguridad: el intérprete nativo y todos los efectos externos siguen siendo observables.<sup>[[2]](#references)[[3]](#references)</sup>

## Puente de memoria compartida con el host

Una VM aislada representa los punteros como desplazamientos dentro de un buffer del invitado, por lo que cada cruce a una API del host requiere traducir punteros y tratar de forma especial los parámetros de salida. En cambio, una VM de memoria compartida hace que las direcciones del invitado sean direcciones válidas del proceso host. Así, las lecturas y escrituras pueden usar operaciones del tipo `memcpy`, y el bytecode puede desreferenciar directamente un puntero devuelto por una ECALL de asignación nativa. RISC-Y Business demostró que este diseño puede reducir el puente a obtener el PEB y emitir llamadas arbitrarias al host.<sup>[[1]](#references)</sup>

En Windows x64, el archivo de registros virtuales puede reflejar la ABI: coloca los primeros cuatro argumentos enteros o punteros en `RCX`, `RDX`, `R8` y `R9`, y los argumentos posteriores y el espacio sombra en la pila. Cuando una `CALL` virtual se resuelve fuera del rango del bytecode, un thunk universal organiza ese estado para una llamada nativa y copia el valor de retorno de vuelta a la VM. Esto permite llamadas a la IAT, asignación de heap y operaciones de socket sin corregir punteros.<sup>[[2]](#references)[[3]](#references)</sup>

La contrapartida es la pérdida total del aislamiento. La corrupción de memoria del invitado puede afectar directamente al host, las funciones nativas pueden conservar o modificar punteros del invitado, y el intérprete debe tratar el bytecode como totalmente confiable. Los callbacks de nativo a VM también necesitan un puente inverso; una VM que solo admita llamadas salientes no puede satisfacer directamente API basadas en callbacks, como `EnumWindows`.<sup>[[1]](#references)[[3]](#references)</sup>

## Polimorfismo de ISA en cada build

Una ISA personalizada de ancho fijo simplifica la decodificación, el despacho, la reubicación y la asignación de registros virtuales. Centurion usa un formato de instrucciones de 18 bytes inspirado en x86-64, que sacrifica densidad de código a cambio de un análisis predecible y también deja abierta la posibilidad de traducir artefactos x86-64 existentes a bytecode.<sup>[[3]](#references)</sup>

Aleatorizar la correspondencia de opcode a handler en cada build hace que la misma lógica del invitado produzca secuencias de bytes diferentes. Cifrar la tabla de correspondencias y recuperarla solo durante el runtime elimina aún más cualquier diccionario estable de opcodes en disco. Esto dificulta las firmas fijas y las reglas reutilizables de desensamblado, pero no transforma automáticamente de forma polimórfica el dispatcher nativo, la rutina de descifrado de la tabla ni el límite de llamadas al host.<sup>[[3]](#references)</sup>

## Incorporar el entorno de ejecución a la VM

El proceso host puede reducirse a primitivas de memoria, llamadas al sistema y sockets, mientras que las bibliotecas freestanding proporcionan servicios de nivel superior dentro de la VM. Por ejemplo, FreeRTOS coreHTTP puede implementar el encuadre HTTP y mbedTLS puede implementar TLS sin llamar a WinHTTP ni a una API de TLS del sistema operativo. Los sockets sin procesar mediante `afd.sys` o una interfaz similar se convierten entonces en el límite nativo de red más reducido.<sup>[[3]](#references)</sup>

Este diseño de **Bring Your Own Execution Environment (BYOEE)** también puede colocar la carga de PE, el soporte del runtime y un sistema de archivos en memoria detrás del intérprete. Reduce las implementaciones nativas reconocibles, pero no elimina la telemetría: las operaciones de socket sin procesar siguen siendo visibles, y los entornos que requieren proxies explícitos o inspección TLS pueden impedir que funcione el diseño de red.<sup>[[3]](#references)</sup>

## Aceleración nativa selectiva

Interpretar cada instrucción resulta especialmente costoso en la criptografía de clave pública. Una división práctica utiliza los hooks `MBEDTLS_ALT` de mbedTLS como interfaz de coprocesador de software: conserva el estado TLS, el análisis de certificados, la negociación, la asignación de memoria y el código bignum de alto nivel en bytecode, pero despacha los kernels aritméticos más utilizados de `bignum_core.c` mediante ECALLs nativas. En el prototipo de Centurion, `bignum.c`, `bignum_mod.c` y `bignum_mod_raw.c` permanecieron virtualizados mientras los bucles internos se ejecutaban de forma nativa, reduciendo un handshake ECDHE de minutos a segundos.<sup>[[3]](#references)</sup>

Haz que los aceleradores sean opcionales para que los payloads que no necesitan TLS omitan los puntos de entrada nativos adicionales. Este patrón se generaliza a cualquier carga de trabajo de intérprete: primero perfila y luego expón la primitiva nativa más pequeña posible, en lugar de sacar de la VM todo un subsistema.<sup>[[3]](#references)</sup>

Centurion validó la cadena completa con una bind shell TLS 1.2: el loader de bytecode mapeó el PE, las llamadas a sockets atravesaron el thunk universal, mbedTLS gestionó el protocolo dentro de la VM y las ECALLs nativas aceleraron la aritmética ECDHE. Así, el intérprete nativo de aproximadamente 18 KB admitió un canal de comandos cifrado sin materializar el payload como código x86-64 nativo.<sup>[[3]](#references)</sup>

## Puntos de referencia para la ingeniería inversa y la detección

Los siguientes son puntos de análisis prácticos deducidos de la arquitectura; la virtualización cambia dónde observan los analistas el comportamiento, pero no lo elimina.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Identifica el bucle de búsqueda/decodificación/despacho, el contador de programa virtual, el archivo de registros y el avance repetido de instrucciones de ancho fijo.
- Vuelca la tabla de opcodes después del descifrado en runtime y asocia las direcciones de los handlers con operaciones semánticas, en lugar de buscar bytecode cifrado en disco.
- Pon un breakpoint en el thunk universal o en el dispatcher de ECALL para registrar el destino nativo, los registros de argumentos virtuales, los argumentos en la pila y el valor de retorno.
- Rastrea el acceso al PEB, la resolución de exports, el análisis de encabezados PE, las escrituras de reubicación y el llenado de la IAT, incluso cuando la propia implementación del loader sea bytecode.
- Correlaciona la creación de sockets y el tráfico de `afd.sys` con la ausencia de llamadas esperadas a WinHTTP o a TLS nativo; la falta de imports de alto nivel es una pista, no una prueba de comportamiento benigno.
- Trata los aceleradores aritméticos nativos como puntos de control semánticos: sus llamadores pueden revelar el intercambio de claves y la actividad de validación de certificados, mientras la máquina de estados TLS circundante permanece virtualizada.

Para flujos de análisis que parten del dispatcher en lugar del grafo de flujo de control original, consulta la [guía de análisis de malware para virtualizar packers](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation).

## Restricciones operativas

La virtualización añade sobrecarga de interpretación, aumenta la complejidad de la cadena de herramientas y la ABI, y no resuelve la detección basada en el comportamiento. La memoria compartida es insegura por diseño, la red mediante sockets sin procesar puede fallar tras proxies obligatorios y las API de Win32 con muchos callbacks requieren trampolines de nativo a VM. El intérprete, el puente de llamadas al sistema y los aceleradores nativos también siguen formando una huella nativa convencional que los defensores pueden identificar mediante firmas o instrumentar.<sup>[[2]](#references)[[3]](#references)</sup>

## Páginas relacionadas

Para analizar el empaquetado de VMProtect 3.x, consulta [desempaquetado emulado y reparación de imports](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#vmprotect-3x-emulated-unpacking-and-import-repair).

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: Construcción de una máquina virtual RISC-V para la ofuscación de payloads](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: Red Teaming en la era de EDR: evasión mediante la virtualización de malware](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion: trae tu propio entorno de ejecución](https://praetorian.com/blog/virtualized-loader-centurion/)
- [4] [Praetorian: Entra en WasmForge: compilar Sliver en WebAssembly](https://praetorian.com/blog/wasmforge-sliver-webassembly)
{{#include ../banners/hacktricks-training.md}}
