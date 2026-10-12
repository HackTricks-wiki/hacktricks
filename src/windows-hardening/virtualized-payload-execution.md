# Ejecución de payloads virtualizados y evasión con VM personalizada

{{#include ../banners/hacktricks-training.md}}

La virtualización de payloads compila la lógica ofensiva en un conjunto de instrucciones invitado y la ejecuta con un intérprete nativo. A diferencia de un packer, que tarde o temprano debe exponer las instrucciones nativas originales en memoria, un payload virtualizado puede mantener la lógica protegida como bytecode durante toda su ejecución. Esto elimina esa ventana específica de desempaquetado, pero **no** oculta comportamientos visibles para el host, como las llamadas al sistema, la actividad de red o el límite entre la VM y las llamadas nativas.<sup>[[2]](#references)[[3]](#references)</sup>

## Modelo de ejecución

Un loader virtualizado compacto puede dividir la ejecución en las siguientes capas.<sup>[[3]](#references)</sup>

1. Compilar C independiente, código fuente BOF o bibliotecas de runtime mediante LLVM en una ISA de bytecode personalizada.
2. Iniciar un intérprete nativo pequeño e inicializar una asignación de opcodes específica de la compilación.
3. Ejecutar el propio PE linker-loader como bytecode: analizar los headers, mapear las secciones, aplicar relocations, resolver imports y completar la IAT.
4. Mantener las llamadas de invitado a invitado dentro del intérprete. Enrutar los destinos fuera de la región de bytecode, como las funciones de DLL importadas, mediante un thunk de llamada al host nativo.
5. Incorporar las instalaciones auxiliares, como el framing HTTP, TLS y partes del runtime de C, tras el mismo límite de interpretación.

Este modelo evita asignar una región de código nativo independiente para cada plugin e impide que el payload original aparezca como un flujo de instrucciones x86-64 reconocible. Sigue siendo un límite de evasión/ofuscación, no un límite de seguridad: el intérprete nativo y todos los efectos externos siguen siendo observables.<sup>[[2]](#references)[[3]](#references)</sup>

## Puente de memoria compartida con el host

Una VM aislada representa los punteros como offsets en un buffer invitado, por lo que cada cruce a una API del host requiere traducir punteros y tratar de forma especial los parámetros de salida. En cambio, una VM de memoria compartida hace que las direcciones invitadas sean direcciones válidas del proceso host. Por lo tanto, las lecturas y escrituras pueden usar operaciones al estilo de `memcpy`, y el bytecode puede desreferenciar directamente un puntero devuelto por una ECALL de asignación nativa. RISC-Y Business demostró que este diseño puede reducir el puente a obtener el PEB y emitir llamadas arbitrarias al host.<sup>[[1]](#references)</sup>

En Windows x64, el conjunto de registros virtuales puede reflejar la ABI: colocar los primeros cuatro argumentos enteros o de puntero en `RCX`, `RDX`, `R8` y `R9`, y los argumentos posteriores y el espacio shadow en la pila. Cuando un `CALL` virtual resuelve fuera del rango de bytecode, un thunk universal ordena ese estado para una llamada nativa y copia el valor devuelto de vuelta a la VM. Esto permite llamadas a la IAT, asignación de heap y operaciones de socket sin corregir punteros.<sup>[[2]](#references)[[3]](#references)</sup>

La contrapartida es la pérdida total de aislamiento. La corrupción de la memoria invitada puede afectar directamente al host, los callees nativos pueden conservar o modificar punteros invitados y el intérprete debe tratar el bytecode como totalmente confiable. Las callbacks de nativo a VM también necesitan un puente inverso; una VM que solo admite llamadas salientes no puede satisfacer directamente APIs basadas en callbacks, como `EnumWindows`.<sup>[[1]](#references)[[3]](#references)</sup>

## Polimorfismo de ISA por compilación

Una ISA personalizada de ancho fijo simplifica la decodificación, el dispatch, la reubicación y la asignación de registros virtuales. Centurion usa un formato de instrucciones de 18 bytes inspirado en x86-64, que sacrifica densidad de código a cambio de un análisis predecible y también deja abierta la posibilidad de traducir artefactos x86-64 existentes a bytecode.<sup>[[3]](#references)</sup>

Aleatorizar la asignación de opcode a handler para cada compilación hace que una misma lógica invitada produzca secuencias de bytes diferentes. Cifrar la tabla de asignaciones y recuperarla solo en runtime elimina aún más la posibilidad de usar un diccionario de opcodes estable en disco. Esto dificulta las firmas fijas y las reglas de desensamblado reutilizables, pero no cambia automáticamente el polimorfismo del dispatcher nativo, la rutina de descifrado de la tabla ni el límite de llamadas al host.<sup>[[3]](#references)</sup>

## Incorporar el entorno de ejecución a la VM

El proceso host puede reducirse a primitivas de memoria, syscalls y sockets, mientras que las bibliotecas independientes proporcionan servicios de nivel superior dentro de la VM. Por ejemplo, FreeRTOS coreHTTP puede implementar el framing HTTP y mbedTLS puede implementar TLS sin llamar a WinHTTP ni a una API TLS del sistema operativo. Los sockets sin procesar mediante `afd.sys` o una interfaz similar se convierten entonces en el límite nativo y acotado de red.<sup>[[3]](#references)</sup>

Este diseño **Bring Your Own Execution Environment (BYOEE)** también puede situar el PE loading, el soporte de runtime y un sistema de archivos en memoria tras el intérprete. Reduce las implementaciones nativas reconocibles, pero no elimina la telemetría: las operaciones de socket sin procesar siguen siendo visibles, y los entornos que requieren proxies explícitos o interceptación TLS pueden impedir que el diseño de red funcione.<sup>[[3]](#references)</sup>

## Aceleración nativa selectiva

Interpretar cada instrucción resulta especialmente costoso en criptografía de clave pública. Una división práctica usa los hooks `MBEDTLS_ALT` de mbedTLS como interfaz de coprocesador de software: mantener el estado TLS, el análisis de certificados, la negociación, la asignación de memoria y el código bignum de alto nivel en bytecode, pero ejecutar los kernels aritméticos más intensivos de `bignum_core.c` mediante ECALLs nativas. En el prototipo Centurion, `bignum.c`, `bignum_mod.c` y `bignum_mod_raw.c` permanecieron virtualizados mientras los bucles internos se ejecutaban de forma nativa, lo que redujo un handshake ECDHE de minutos a segundos.<sup>[[3]](#references)</sup>

Haz que los aceleradores sean opcionales para que los payloads que no necesiten TLS omitan los puntos de entrada nativos adicionales. Este patrón se generaliza a cualquier carga de trabajo de intérprete: primero perfila y, después, expón la primitiva nativa más pequeña posible en lugar de trasladar un subsistema entero fuera de la VM.<sup>[[3]](#references)</sup>

Centurion validó toda la cadena con una bind shell TLS 1.2: el loader de bytecode mapeó el PE, las llamadas a sockets cruzaron el thunk universal, mbedTLS gestionó el protocolo dentro de la VM y las ECALLs nativas aceleraron la aritmética ECDHE. Por lo tanto, el intérprete nativo de aproximadamente 18 KB permitió un canal de comandos cifrado sin materializar el payload como código x86-64 nativo.<sup>[[3]](#references)</sup>

## Análisis inverso y puntos de referencia para la detección

Los siguientes son puntos de referencia prácticos para el análisis, inferidos de la arquitectura; la virtualización cambia dónde observan el comportamiento los analistas, pero no elimina el comportamiento en sí.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

- Identifica el bucle de fetch/decode/dispatch, el contador de programa virtual, el conjunto de registros y el avance repetido por instrucciones de ancho fijo.
- Vuelca la tabla de opcodes después del descifrado en runtime y relaciona las direcciones de los handlers con operaciones semánticas, en lugar de buscar coincidencias en el bytecode cifrado en disco.
- Pon un breakpoint en el thunk universal o en el dispatcher de ECALL para registrar el destino nativo, los registros virtuales de argumentos, los argumentos en la pila y el valor devuelto.
- Rastrea el acceso al PEB, la resolución de exports, el análisis de headers PE, las escrituras de relocations y la carga de la IAT, aunque la implementación del loader sea bytecode.
- Correlaciona la creación de sockets y el tráfico de `afd.sys` con la ausencia de llamadas esperadas a WinHTTP o a TLS nativo; la falta de imports de alto nivel es una pista, no una prueba de comportamiento benigno.
- Trata los aceleradores aritméticos nativos como puntos de estrangulamiento semánticos: sus callers pueden revelar el intercambio de claves y la actividad de validación de certificados mientras la máquina de estados TLS circundante sigue virtualizada.

Para flujos de análisis que parten del dispatcher en lugar del grafo de flujo de control original, consulta la [guía de análisis de malware para virtualizar packers](../generic-methodologies-and-resources/basic-forensic-methodology/malware-analysis.md#virtualizing-packers-and-no-labels-obfuscation).

## Restricciones operativas

La virtualización añade sobrecarga de interpretación, aumenta la complejidad de las toolchains y las ABI, y no resuelve la detección basada en el comportamiento. La memoria compartida es insegura por diseño, la conectividad de red mediante sockets sin procesar puede fallar detrás de proxies obligatorios y las APIs Win32 con muchas callbacks requieren trampolines de nativo a VM. El intérprete, el puente de syscalls y los aceleradores nativos también siguen siendo una huella nativa convencional que los defensores pueden identificar mediante firmas o instrumentar.<sup>[[2]](#references)[[3]](#references)</sup>

## Páginas relacionadas

{{#ref}}
../reversing/common-api-used-in-malware.md
{{#endref}}

{{#ref}}
../generic-hacking/reverse-shells/README.md
{{#endref}}

## References

- [1] [RISC-Y Business: Cómo crear una máquina virtual RISC-V para la ofuscación de payloads](https://secret.club/2023/12/24/riscy-business.html)
- [2] [Fox-IT: Red teaming en la era de EDR: evasión mediante virtualización de malware](https://blog.fox-it.com/2024/09/25/red-teaming-in-the-age-of-edr-evasion-of-endpoint-detection-through-malware-virtualisation/)
- [3] [Praetorian: Centurion: trae tu propio entorno de ejecución](https://praetorian.com/blog/virtualized-loader-centurion/)
{{#include ../banners/hacktricks-training.md}}
