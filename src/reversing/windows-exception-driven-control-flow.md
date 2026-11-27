# Flujo de control basado en excepciones y anti-debugging en Windows

{{#include ../banners/hacktricks-training.md}}

Un programa de Windows protegido puede usar una excepción intencional como una rama: la instrucción que produce el fallo solo es la entrada a un manejador que selecciona la siguiente dirección del código de usuario. Esto oculta conexiones en el desensamblado lineal y traslada el siguiente paso al despacho de excepciones.<sup>[[1]](#references)</sup>

## El despacho importa

Un depurador conectado al proceso recibe una excepción de **primera oportunidad** antes que los manejadores de la aplicación. Si la marca como no controlada, Windows busca los manejadores del proceso; si no hay ningún manejador para la excepción, esta vuelve al depurador como excepción de **última oportunidad**. Por tanto, un depurador que consume un evento de breakpoint o de ejecución paso a paso puede alterar si se ejecuta el manejador del programa.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` registra un VEH de todo el proceso al principio de la lista de manejadores vectoriales. Se ejecuta antes que el SEH basado en marcos, pero un registro posterior con prioridad máxima puede colocar otro manejador por delante. Devolver `EXCEPTION_CONTINUE_SEARCH` deja que otros manejadores procesen la excepción; `EXCEPTION_CONTINUE_EXECUTION` reanuda la ejecución desde el `CONTEXT` guardado, incluidos los cambios en los registros realizados por el manejador.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

El SEH clásico de x86 usa registros enlazados a la pila, que se pueden inspeccionar con `!exchain`. El x64 nativo usa entradas `RUNTIME_FUNCTION` en `.pdata` con datos de unwind en `.xdata`, no esa cadena de x86. No apliques el [flujo de trabajo de sobrescritura de SEH en x86](../binary-exploitation/stack-overflow/windows-seh-overflow.md) a un proceso x64 nativo.<sup>[[5]](#references)[[6]](#references)</sup>

## Convertir un fallo en una conexión del flujo de control

Por ejemplo, un divisor cero puede generar intencionalmente `EXCEPTION_INT_DIVIDE_BY_ZERO` en lugar de representar un error. El manejador debe reconocer la excepción y la dirección donde se produjo el fallo, y luego asignar a `ContextRecord->Rip` (o `Eip` en x86) una dirección de continuación válida antes de devolver `EXCEPTION_CONTINUE_EXECUTION`.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

El núcleo del handler de abajo supone que `fault_site` y `continuation` son direcciones conocidas dentro del mismo contexto de flujo de control. Una implementación real debe preservar la pila y los registros esperados, y no debe reanudar la ejecución en la misma instrucción que provocó el fallo o volverá a producirse el fallo.<sup>[[7]](#references)</sup>

```c
if (e->ExceptionRecord->ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO &&
    e->ExceptionRecord->ExceptionAddress == fault_site) {
#ifdef _M_X64
    e->ContextRecord->Rip = (DWORD64)continuation;
#else
    e->ContextRecord->Eip = (DWORD)continuation;
#endif
    return EXCEPTION_CONTINUE_EXECUTION;
}
return EXCEPTION_CONTINUE_SEARCH;
```

El mismo mecanismo puede consumir un `INT3`/`__debugbreak()` intencional (`EXCEPTION_BREAKPOINT`) y redirigir la ejecución. **No** incrementes `Rip` a ciegas para «omitir el breakpoint»: la dirección guardada y el ajuste necesario dependen de la trampa, la codificación de la instrucción y el comportamiento del debugger. Compara `ExceptionRecord->ExceptionAddress` con el puntero de instrucción guardado y desensambla los bytes antes de elegir la continuación.<sup>[[8]](#references)</sup> [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) es un ejemplo independiente de hardware-breakpoint que cambia el estado de retorno de una llamada al sistema del loader.

## Materialización de páginas impulsada por fallos

Un VEH puede convertir un fallo de página en un **loader bajo demanda**, no solo en un salto. Reserva un rango de imagen privado con páginas aún no confirmadas, o páginas mapeadas con protección de guardia, si se admite. Antes de ejecutar la imagen, indexa los sitios de reubicación y los thunks de IAT según la página de destino. Ante un fallo dentro de ese rango, el handler confirma la página afectada o le da permisos de escritura, copia los bytes de su sección, aplica las reubicaciones e importaciones de esa página, establece su protección final y devuelve `EXCEPTION_CONTINUE_EXECUTION`. Se vuelve a intentar la instrucción original; **no** avances `Rip` como en un handler que omite el fallo. Las páginas que nunca se usan no necesitan contener el payload en memoria.<sup>[[11]](#references)</sup>

En una violación de acceso, `ExceptionRecord->ExceptionAddress` identifica la **instrucción** que causó el fallo, mientras que `ExceptionInformation[1]` identifica la dirección a la que se accedió.<sup>[[10]](#references)</sup> Comprueba el código de excepción, el número de parámetros y el rango de la dirección a la que se accedió antes de materializar una página; de lo contrario, un fallo no relacionado podría confundirse con una solicitud del loader.<sup>[[10]](#references)[[11]](#references)</sup> `PAGE_GUARD` genera `STATUS_GUARD_PAGE_VIOLATION` (`0x80000001`) en el primer acceso y Windows borra automáticamente el bit de guardia, por lo que volver a activarlo es un paso aparte, no un hook continuo.<sup>[[12]](#references)</sup> Mantén el VEH y todos los metadatos que necesite accesibles durante el despacho.<sup>[[11]](#references)</sup> En x64, puede que los datos de unwind deban estar disponibles antes del primer fallo; el loader citado materializa páginas de forma anticipada antes de invocar `DllMain` para evitar condiciones de carrera durante la inicialización.<sup>[[11]](#references)</sup> Vacía la caché de instrucciones después de escribir código y antes de ejecutarlo.<sup>[[13]](#references)</sup>

Para recuperar este flujo al hacer reversing, detente en las violaciones de página de guardia y violaciones de acceso de primera oportunidad, inspecciona el registro de excepción y luego pasa el evento al handler de la aplicación con `gn`.<sup>[[14]](#references)[[16]](#references)[[17]](#references)</sup> Usa `!vprot` en la dirección a la que se accedió para inspeccionar la protección actual de la página.<sup>[[15]](#references)</sup>

```text
sxe 80000001
sxe av
.exr -1
!vprot <fault-address>
gn
```

Después de que el handler materialice la página, vuelca sus bytes y compáralos con la imagen del archivo.<sup>[[11]](#references)</sup> Un `!vprot` posterior al fault no puede demostrar que la página estuviera protegida con guard antes, porque el estado de guard es de un solo uso.<sup>[[11]](#references)[[12]](#references)</sup> Una vez conocida la región relevante de la imagen, acota los filtros de excepciones o los breakpoints del handler para evitar faults no relacionados.<sup>[[16]](#references)</sup> Consulta [WinDbg exception automation](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception) para configurar los filtros.<sup>[[16]](#references)</sup>

## Trap Flag como compuerta dependiente del debugger

El bit `0x100` de `EFLAGS`/`RFLAGS` es el Trap Flag (TF). Al activarlo, el límite de la siguiente instrucción genera `STATUS_SINGLE_STEP` (`0x80000004`). Una rama de VEH o SEH puede distinguir un evento de single-step que se pasa a la aplicación de uno que consume un debugger, pero esto es una **heurística controlada por la política de excepciones del debugger**, no una prueba fiable de que exista un debugger.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

Si el handler solo quiere un paso, borra `0x100` en `EFlags` del contexto reanudado antes de continuar. Distingue también los pasos impulsados por TF de los eventos de puntos de interrupción de hardware comprobando la dirección que los desencadena y el estado de depuración; ambos pueden aparecer como `EXCEPTION_SINGLE_STEP`.<sup>[[8]](#references)[[9]](#references)</sup> Para la configuración de primera y segunda oportunidad de `sxe`, `sxd` y `sxi` de WinDbg, consulta [Automatización de excepciones en WinDbg](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research - Anti-Debug: Excepciones](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Manejo de excepciones del depurador](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Manejo de excepciones vectorizadas](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - Manejo de excepciones x64](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Uso de un controlador de excepciones vectorizadas](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug: Instrucciones de ensamblador](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - Arquitectura x86](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
- [11] [Eidolon - Carga de imágenes impulsada por fallos](https://github.com/rafaelwdornelas/Eidolon)
- [12] [Microsoft Learn - Creación de páginas de guarda](https://learn.microsoft.com/en-us/windows/win32/memory/creating-guard-pages)
- [13] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [14] [Microsoft Learn - .exr (Mostrar registro de excepción)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exr--display-exception-record-)
- [15] [Microsoft Learn - !vprot](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-vprot)
- [16] [Microsoft Learn - Filtros de excepción sx](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [17] [Microsoft Learn - gn (Continuar con excepción no gestionada)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/gn--gn--go-with-exception-not-handled-)
{{#include ../banners/hacktricks-training.md}}
