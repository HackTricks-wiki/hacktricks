# Flujo de control basado en excepciones de Windows y anti-debugging

{{#include ../banners/hacktricks-training.md}}

Un programa protegido de Windows puede usar una excepción intencional como bifurcación: la instrucción que provoca el fallo solo es la entrada a un controlador que selecciona la siguiente dirección de código de usuario. Esto oculta conexiones en el desensamblado lineal y traslada el siguiente paso al despacho de excepciones.<sup>[[1]](#references)</sup>

## El despacho importa

Un debugger conectado al proceso recibe una excepción de **primera oportunidad** antes que los controladores de la aplicación. Si la pasa como no controlada, Windows busca los controladores del proceso; una excepción sin controlador vuelve al debugger como excepción de **última oportunidad**. Por lo tanto, un debugger que consume un evento de breakpoint o de ejecución paso a paso puede cambiar si se ejecuta el controlador del programa.<sup>[[2]](#references)</sup>

`AddVectoredExceptionHandler(1, handler)` registra un VEH para todo el proceso al principio de la lista de controladores vectored. Se ejecuta antes que SEH basado en marcos, pero un registro posterior con prioridad máxima puede colocar otro controlador antes que este. Devolver `EXCEPTION_CONTINUE_SEARCH` deja la excepción para otros controladores; `EXCEPTION_CONTINUE_EXECUTION` reanuda la ejecución desde el `CONTEXT` guardado, incluidos los cambios en registros que haya realizado el controlador.<sup>[[3]](#references)[[4]](#references)[[7]](#references)</sup>

El SEH clásico de x86 usa registros enlazados en la pila, que `!exchain` puede inspeccionar. El x64 nativo usa entradas `RUNTIME_FUNCTION` en `.pdata` con datos de unwind en `.xdata`, no esa cadena de x86. No apliques el [flujo de trabajo de sobrescritura de SEH de x86](../binary-exploitation/stack-overflow/windows-seh-overflow.md) a un proceso x64 nativo.<sup>[[5]](#references)[[6]](#references)</sup>

## Convertir un fallo en una conexión de flujo de control

Por ejemplo, un divisor igual a cero puede generar intencionalmente `EXCEPTION_INT_DIVIDE_BY_ZERO` en lugar de representar un bug. El controlador debe reconocer la excepción y la dirección del fallo, y luego establecer `ContextRecord->Rip` (o `Eip` en x86) en una continuación válida antes de devolver `EXCEPTION_CONTINUE_EXECUTION`.<sup>[[5]](#references)[[7]](#references)[[10]](#references)</sup>

```asm
xor ecx, ecx
div ecx                 ; deliberate fault, not a normal fall-through
```

El núcleo del handler que aparece a continuación supone que `fault_site` y `continuation` son direcciones conocidas dentro del mismo contexto de flujo de control. Una implementación real debe preservar la pila y los registros esperados, y no debe reanudar la ejecución en la misma instrucción que provocó el fallo, o volverá a producirse el fallo.<sup>[[7]](#references)</sup>

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

El mismo mecanismo puede consumir un `INT3`/`__debugbreak()` intencional (`EXCEPTION_BREAKPOINT`) y redirigir la ejecución. **No** incrementes `Rip` a ciegas para «omitir el breakpoint»: la dirección guardada y el ajuste necesario dependen de la trampa, la codificación de la instrucción y el comportamiento del debugger. Compara `ExceptionRecord->ExceptionAddress` con el puntero de instrucción guardado y desensambla los bytes antes de elegir la continuación.<sup>[[8]](#references)</sup> El [Vectored Overloading loader](../binary-exploitation/windows-vectored-overloading.md) es un ejemplo aparte de hardware-breakpoint que cambia el estado de retorno de un syscall del loader.

## Trap Flag como mecanismo de control dependiente del debugger

El bit `0x100` de `EFLAGS`/`RFLAGS` es el Trap Flag (TF). Al activarlo, el siguiente límite de instrucción genera `STATUS_SINGLE_STEP` (`0x80000004`). Una rama de VEH o SEH puede distinguir un evento de single-step enviado a la aplicación de uno consumido por un debugger, pero esto es una **heurística controlada por la política de excepciones del debugger**, no una prueba fiable de que exista un debugger.<sup>[[2]](#references)[[8]](#references)[[9]](#references)</sup>

```asm
pushfq
or qword ptr [rsp], 100h
popfq
```

Si el handler solo quiere un paso, limpia `0x100` en `EFlags` del contexto reanudado antes de continuar. Distingue también los pasos activados por TF de los eventos de puntos de interrupción de hardware comprobando la dirección que los activó y el estado de depuración; ambos pueden aparecer como `EXCEPTION_SINGLE_STEP`.<sup>[[8]](#references)[[9]](#references)</sup> Para la configuración de primera y segunda oportunidad de `sxe`, `sxd` y `sxi` de WinDbg, consulta [automatización de excepciones en WinDbg](reversing-tools-basic-methods/windbg-automation.md#start-at-a-useful-exception).

## References

- [1] [Check Point Research - Anti-Debug: Excepciones](https://anti-debug.checkpoint.com/techniques/exceptions.html)
- [2] [Microsoft Learn - Manejo de excepciones del debugger](https://learn.microsoft.com/en-us/windows/win32/debug/debugger-exception-handling)
- [3] [Microsoft Learn - AddVectoredExceptionHandler](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-addvectoredexceptionhandler)
- [4] [Microsoft Learn - Manejo de excepciones vectorizadas](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)
- [5] [Microsoft Learn - Manejo de excepciones x64](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
- [6] [Microsoft Learn - !exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain)
- [7] [Microsoft Learn - Uso de un handler de excepciones vectorizadas](https://learn.microsoft.com/en-us/windows/win32/debug/using-a-vectored-exception-handler)
- [8] [Check Point Research - Anti-Debug: Instrucciones de ensamblador](https://anti-debug.checkpoint.com/techniques/assembly.html)
- [9] [Microsoft Learn - Arquitectura x86](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/x86-architecture)
- [10] [Microsoft Learn - EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
