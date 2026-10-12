# ARM64/ARM64e Call-Stack Spoofing

{{#include ../../../banners/hacktricks-training.md}}

## Por qué se puede suplantar el unwinding basado en metadatos

Algunas herramientas de seguridad de macOS delegan la recopilación de stacks de hilos a `/usr/sbin/spindump` o, de otro modo, confían en un unwinder convencional basado en metadatos. Un implant puede aprovechar ese límite de confianza colocando en su stack registros sintéticos que respetan el ABI, de modo que parezca que se llegó a una API sensible a través de funciones elegidas por el atacante en dyld y en frameworks de Apple cargados, en lugar de desde código de un implant sin respaldo. Esto es un engaño de telemetría, no un cambio en el ejecutable ni en sus metadatos de unwinding.<sup>[[1]](#references)</sup>

Consulta [stackshots de macOS y `spindump`](../macos-apps-inspecting-debugging-and-fuzzing/#stackshot--microstackshots) para ver el contexto de la recopilación.

Un unwinder no demuestra que un prólogo generado por el compilador haya creado un registro. Usa repetidamente el `PC` actual para elegir una receta de Mach-O, aplica esa receta a `SP`, `x29`, `x30`, la memoria del stack y cualquier registro no volátil declarado, y usa el `PC` del caller recuperado para elegir la siguiente receta. Si la memoria controlada por el atacante satisface todas las recetas seleccionadas, la cadena resultante puede ser estructuralmente válida y tener símbolos, aunque esas llamadas nunca hayan ocurrido.<sup>[[1]](#references)</sup>

## Estado del frame ARM64

La [descripción general del ensamblador ARM64](../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md) cubre los roles de los registros y la convención de llamada. Para un frame convencional creado con `stp x29, x30, [sp, #-16]!` seguido de `mov x29, sp`, la Dirección Canónica del Frame (CFA), que representa el `SP` del caller al entrar, es `FP+0x10`:<sup>[[1]](#references)[[4]](#references)</sup>

```text
higher addresses
FP + 0x10   caller SP / CFA
FP + 0x08   saved LR / caller PC
FP + 0x00   previous FP
FP - 0x08   saved x19 (when declared)
FP - 0x10   saved x20 (when declared)
lower addresses
```

Los registros de frame forman una lista enlazada mediante `[FP]`, pero seguir esa lista a ciegas no es suficiente: las funciones hoja pueden no tener frame, las llamadas de cola pueden eliminar transiciones lógicas y los diseños inusuales usan DWARF CFI. La receta que selecciona la dirección actual determina si el unwinder lee la cadena de FP.<sup>[[1]](#references)[[4]](#references)</sup>

## Selección de una receta de unwind de Mach-O

Las imágenes enlazadas finales almacenan datos compactos de unwind en `__TEXT,__unwind_info`. El encabezado de la sección apunta a un índice de funciones de primer nivel; cada rango del índice apunta a una página de segundo nivel regular (`kind=2`) o comprimida (`kind=3`). Los diseños que el compact unwind no puede describir usan un FDE e instrucciones de call frame en `__eh_frame`.<sup>[[1]](#references)[[2]](#references)</sup>

Para cada PC de ejecución candidato:<sup>[[1]](#references)[[2]](#references)</sup>

1. Elimina o normaliza los bits PAC de ARM64e solo para la búsqueda.
2. Busca el Mach-O cargado cuyo rango ejecutable `__TEXT` contiene la dirección.
3. Calcula `functionOffset = normalizedPC - loadedImageBase` y rechaza los resultados negativos o superiores a `UINT32_MAX`.
4. Selecciona el rango de primer nivel que cumpla `index[i].functionOffset <= functionOffset < index[i+1].functionOffset`.
5. Analiza la página de segundo nivel referenciada, elige la entrada más cercana cuyo inicio no supere el offset y verifica que la dirección sea inferior a la siguiente entrada o al final del rango de primer nivel.
6. Decodifica esa entrada y construye el estado exacto que describe.

Cuando una dirección proviene de un LR guardado, la búsqueda puede usar `PC-1` para que una dirección inmediatamente posterior a una llamada siga estando dentro del rango cubierto por el caller. Esto cambia la selección de la receta, no ningún offset de la pila.<sup>[[1]](#references)</sup>

Un parser debe comprobar los límites de cada encabezado y array, exigir que la versión de la sección sea `1`, tener en cuenta el sentinel final de primer nivel, rechazar un offset de página de segundo nivel igual a cero y distinguir entre páginas regulares y comprimidas. En una página regular, `entryPageOffset` es relativo al inicio de esa página, mientras que el offset de página de primer nivel es relativo al inicio de `__unwind_info`.<sup>[[1]](#references)[[2]](#references)</sup>

El modo general es `encoding & 0x0F000000`. Las definiciones actuales de LLVM incluyen los siguientes modos; un parser no debe tratar todos los valores que no sean DWARF como un frame clásico:<sup>[[1]](#references)[[2]](#references)</sup>

| Modo | Valor | Recuperación del caller |
| --- | --- | --- |
| Sin receta compacta | `0x00000000` | Detenerse o usar un fallback independiente. |
| Sin frame | `0x02000000` | Sumar el tamaño de pila codificado al `SP` actual; el PC del caller es el LR activo. |
| DWARF | `0x03000000` | Ejecutar el FDE/CFI identificado por los 24 bits inferiores. |
| Frame | `0x04000000` | Leer el registro de frame convencional de `x29`. |
| Frame arm64e con rango de LR autenticado | `0x05000000` | Gestionar `UNWIND_ARM64_MODE_FRAME_PAUTH_LR`; su campo de offset localiza `pacibsppc` dentro del rango cubierto. |

En el modo sin frame, `stackSize = ((encoding & 0x00FFF000) >> 12) * 16`. En el modo frame, los cinco bits inferiores indican pares contiguos de GPR guardados, de `x19/x20` a `x27/x28`; los bits `0x100-0x800` indican de forma similar los pares `d8-d15`. Puede que esos registros guardados no sean necesarios para encontrar el siguiente PC, pero un estado virtual de caller creíble debe satisfacer todos los campos que reconstruya el consumidor.<sup>[[1]](#references)[[2]](#references)</sup>

## Construcción de registros sintéticos en modo frame

El proceso de construcción invierte el funcionamiento del unwinder, en lugar de buscar en la pila valores que parezcan direcciones:<sup>[[1]](#references)</sup>

1. Elige un PC ejecutable real en una imagen cargada actualmente.
2. Decodifica la receta que cubre ese PC preciso o la dirección del sitio de llamada.
3. Reserva un registro sintético con la alineación y la relación CFA necesarias.
4. Guarda el siguiente FP sintético en `[FP]`, el PC del caller guardado de ese frame en `[FP+8]` y cada GPR/FPR guardado que indique la codificación por debajo de FP.
5. Enlaza varios registros y coloca el primer registro en el `x29` activo.
6. Organiza el LR activo y la ruta de retorno de la API para que el unwind entre en la cadena elegida y la ejecución pueda restaurarse de forma segura.

Por ejemplo, `0x04000001` significa modo frame más el par `x19/x20`. La transformación de estado correspondiente y la memoria necesaria son:<sup>[[1]](#references)[[2]](#references)</sup>

```text
[FP - 0x10] = caller x20
[FP - 0x08] = caller x19
[FP + 0x00] = caller FP
[FP + 0x08] = caller PC
caller SP    = FP + 0x10
```

Por lo tanto, no basta con que una dirección parezca legítima. Cada PC recuperado se convierte en la clave para la siguiente búsqueda, así que una sola dirección cuya codificación no coincida con el diseño fabricado rompe la cadena o hace que el consumidor reconstruya un estado de registros incoherente.<sup>[[1]](#references)</sup>

## Requisitos de PAC en ARM64e

PAC almacena un valor de integridad con clave en bits del puntero que, de otro modo, no se usarían; no cifra la dirección. El esquema de direcciones de retorno arm64e de Clang usa la clave de instrucción B y el puntero de pila al entrar en la función como discriminador. En un frame convencional, ese `SP` de entrada es el CFA, por lo que el LR guardado en `[FP+8]` queda vinculado a `FP+0x10`.<sup>[[1]](#references)[[3]](#references)</sup>

```text
modifier = syntheticFP + 0x10
signedLR = PACIB(rawReturnPC, modifier)

# Authentication must recover the original PC:
AUTIB(signedLR, modifier) == rawReturnPC
```

Cada LR sintético debe firmarse de forma independiente, porque mover un LR ya firmado a un frame con un CFA distinto cambia el discriminador y hace que falle la autenticación. `ptrauth_strip()` sirve para normalizar direcciones y buscar símbolos, pero **no** garantiza la autenticidad; cualquier retorno real o branch indirecto autenticado debe usar la clave y el modificador esperados en esa transición exacta.<sup>[[1]](#references)[[3]](#references)</sup>

Una función arm64e típica que no es hoja firma LR antes de guardarlo y lo autentica después de restaurar el SP de entrada:<sup>[[1]](#references)[[3]](#references)</sup>

```asm
pacibsp
stp x29, x30, [sp, #-16]!
mov x29, sp
; function body
ldp x29, x30, [sp], #16
retab
```

## Trampoline y puente de restauración

Los registros sintéticos solo necesitan satisfacer al unwinder; no contienen un contexto de ejecución completo. Volver desde la API sensible directamente a los llamadores fabricados normalmente provocaría un fallo. Por tanto, el diseño práctico coloca un frame de gadget justo debajo de la API: la API retorna a código ejecutable de un framework cargado, y ese gadget salta, mediante un registro controlado preservado por el callee, a un puente de restauración en el implant.<sup>[[1]](#references)</sup>

Un gadget útil preserva LR y transfiere el control mediante un registro controlado, por ejemplo, con una secuencia `br`, `braa` o `brab` adecuada. El puente de restauración debe recuperar los valores originales de `x19-x30` y `SP` antes de reanudar la ejecución del implant. En arm64e, cada retorno o salto autenticado de la ruta API-gadget, gadget-puente y puente-implant requiere un puntero firmado para la clave y el discriminador que utilice esa instrucción.<sup>[[1]](#references)</sup>

```text
implant -> synthetic state -> sensitive API
                              |
                              v
                     signed gadget in image
                              |
                              v
                 restore x19-x30 and original SP
                              |
                              v
                           implant
```

El resultado es un fallo importante en los límites de confianza de las detecciones basadas en la pila: una cadena puede contener únicamente PCs de frameworks de Apple mapeados y simbolizables, y aun así no representar el flujo de control real. Por lo tanto, la salida de unwind debe corroborarse con evidencia independiente sobre la procedencia de la memoria ejecutable del thread y las transiciones reales alrededor de la API sensible, en lugar de tratarse como un rastro de ejecución.<sup>[[1]](#references)</sup>

## References

- [1] [MDSec - Internos de la pila ARM64 y ofuscación en Apple Silicon](https://mdsec.co.uk/2026/08/arm64-stack-internals-and-obfuscation-on-apple-silicon/)
- [2] [LLVM - Definiciones de codificación compact unwind de Mach-O](https://github.com/llvm/llvm-project/blob/main/libunwind/include/mach-o/compact_unwind_encoding.h)
- [3] [Clang - Autenticación de punteros](https://clang.llvm.org/docs/PointerAuthentication.html)
- [4] [Arm - Estándar de llamada a procedimientos para la arquitectura Arm de 64 bits](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)
{{#include ../../../banners/hacktricks-training.md}}
