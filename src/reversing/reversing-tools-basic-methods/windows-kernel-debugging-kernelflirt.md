# Depuración del kernel de Windows con KernelFlirt

{{#include ../../banners/hacktricks-training.md}}

KernelFlirt es un debugger de Windows x64 para laboratorios controlados de ingeniería inversa. Una interfaz WPF del host o `KfConsole.exe` envía comandos a `KfRelay.exe` en una VM Windows con firma de prueba. El relay los traduce en solicitudes `DeviceIoControl` para `KernelFlirt.sys`, que proporciona operaciones de memoria, registros, breakpoints, control de ejecución y módulos del kernel. El driver también modifica la ruta de depuración del kernel con un inline hook `KdpStub`/`KdTrap`, así que úsalo solo en una VM desechable.<sup>[[1]](#references)</sup>

```text
Host UI / KfConsole
        |
        | TCP 31337 (CMD + debug-event channels)
        v
KfRelay.exe -- DeviceIoControl/IOCTL --> KernelFlirt.sys
        ^
        |
KfLoader.exe -- SCM load/unload/status
```

El relay es un límite de depuración privilegiado, no un servicio remoto normal. Mantén el puerto TCP `31337` en una red aislada solo de host y nunca expongas el driver firmado para pruebas ni el relay a una red no confiable.<sup>[[1]](#references)</sup>

Técnicas relacionadas de exploitation de Windows:

{{#ref}}
../../binary-exploitation/windows-exploiting-basic-guide-oscp-lvl.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/arbitrary-kernel-rw-token-theft.md
{{#endref}}

## Configuración del laboratorio y primera parada

Las compilaciones requieren Windows 10/11 x64, Visual Studio 2022 con C++, WDK 10.0.26100.0 o posterior y .NET 9. Carga el driver y el relay dentro de la VM y luego conéctate desde el host. La UI puede abrir un EXE o SYS remoto, y la vista **Kernel Modules** permite establecer breakpoints en drivers ya cargados.<sup>[[1]](#references)</sup>

```bat
:: VM
KfLoader.exe load
KfLoader.exe status
KfRelay.exe

:: Host
KernelFlirt.exe
:: Connect -> <VM-IP>
```

Usa `KfLoader.exe unload` cuando termines el lab. La consola admite un REPL sin conexión, acceso directo al dispositivo local y acceso mediante relay; solo el modo relay implementa el flujo de trabajo determinista `open` que se describe a continuación.<sup>[[2]](#references)</sup>

```bat
KfConsole.exe
KfConsole.exe local
KfConsole.exe 10.100.102.6
KfConsole.exe 10.100.102.6:31337
```

Un flujo de trabajo mínimo en la consola es:<sup>[[2]](#references)</sup>

```text
connect 10.100.102.6:31337
open C:\Temp\target.exe
bp ntdll!NtCreateFile if rcx != 0
g
u rip 8
dq rsp 8
r
detach
```

Las direcciones son expresiones. Los números sin prefijo son hexadecimales, y las expresiones pueden usar registros, operaciones aritméticas, desreferencias como `[rsp]` y símbolos como `ntdll!NtCreateFile`. Los breakpoints de símbolos deben añadirse solo después de que `open` o `attach` haya enumerado los módulos y cargado sus PDB.<sup>[[2]](#references)</sup>

## Captura determinista del punto de entrada con `EB FE`

El `open` del relay crea el proceso suspendido, guarda los bytes iniciales de su punto de entrada, escribe `EB FE`, reanuda el thread de entrada y consulta repetidamente hasta que su puntero de instrucción llega a esa dirección. `EB FE` es un salto corto de dos bytes hacia sí mismo, por lo que captura la ejecución sin depender de que se entregue una excepción de depuración en modo usuario. Entonces, el relay restaura los bytes originales y deja el proceso detenido en su punto de entrada.<sup>[[2]](#references)</sup>

Este patrón también resulta útil cuando se debe observar una ruta temprana del loader antes de que termine la configuración normal del debugger.<sup>[[2]](#references)</sup>

1. Crea el proceso suspendido y resuelve su punto de entrada real después de mapear la imagen.
2. Guarda los bytes originales del punto de entrada y los reemplaza por el bucle de dos bytes que salta a sí mismo.
3. Reanuda el thread de entrada y consulta su puntero de instrucción hasta que llega a la dirección modificada.
4. Suspende el proceso y restaura exactamente los bytes originales antes de continuar el análisis.

La técnica es deliberadamente intrusiva. Si el debugger o el relay termina antes de restaurar los bytes, el proceso puede quedarse en un bucle. El modo local de KernelFlirt no admite la modificación del punto de entrada desde el relay; inicia el proceso manualmente y usa `attach <pid>` en su lugar.<sup>[[2]](#references)</sup>

## Elegir el mecanismo de breakpoint

KernelFlirt ofrece varios mecanismos de breakpoint con diferentes efectos secundarios. Los siguientes comandos permiten al analista cambiar de mecanismo cuando el código empaquetado se reescribe, las páginas ejecutables son de solo lectura o se comprueba la integridad de los bytes de los breakpoints de software.<sup>[[1]](#references)[[2]](#references)</sup>

| Mecanismo | Comando | Mecanismo y uso |
| --- | --- | --- |
| Software | `bp <expr>` | `INT3` respaldado por MDL; permite instrumentar páginas `.text` RX |
| Software condicional | `bp <expr> if <condition>` | Evalúa cada vez que se activa y reanuda silenciosamente si la condición es falsa |
| Ejecución por hardware | `ba e1 <expr>` | Usa uno de DR0-DR3 sin modificar los bytes del código |
| Datos por hardware | `ba w4 <expr>` / `ba r8 <expr>` | Vigila escrituras o lecturas/escrituras de 1, 2, 4 u 8 bytes |
| Página de guarda | `bm <expr> [size]` | Usa `PAGE_GUARD` para establecer un breakpoint en un rango de memoria |
| Temporal | `g <expr>`, `p` u `o` | Breakpoint auxiliar para ejecutar hasta una dirección, ejecutar sobre una instrucción y salir de una función |

Usa `bl` para distinguir las entradas de software, hardware, memoria y temporales, y `bc <address|handle|all>` para eliminarlas. Las ranuras de hardware son limitadas y dependen del estado de los registros de depuración, mientras que las páginas de guarda cubren un rango mayor, pero se activan con accesos no relacionados a la misma página.

## Ejecución paso a paso en nativo x64 frente a WoW64

El paso único en x64 nativo activa la bandera de trampa del procesador mediante `IOCTL_KF_SINGLE_STEP`. Step Over decodifica la instrucción actual y coloca breakpoints temporales en sus posibles direcciones siguientes. Step Out lee la dirección de retorno desde la parte superior de la pila actual. En el prólogo de una función, esa suposición sobre la pila puede ser incorrecta, así que es preferible usar un breakpoint interno conocido.<sup>[[2]](#references)</sup>

El hook `KdTrap` no captura las excepciones de 32 bits de la misma manera. Para los procesos WoW64, el debugger decodifica la instrucción con Iced, escribe `EB FE` en la siguiente `EIP` calculada y consulta los punteros de instrucción de los threads. Por consiguiente, `g <address>` no está disponible en WoW64, y un `g` sin argumentos bloquea la consola hasta que se alcanza un breakpoint. Configura primero un breakpoint alcanzable y evita una ejecución indefinida, ya que `Ctrl+C` termina la consola en lugar de cancelar la consulta.<sup>[[2]](#references)</sup>

## Análisis asistido por memoria, registros y símbolos

La consola puede combinar una detención simbólica con la inspección de memoria y una modificación controlada. Las búsquedas aceptan comodines de bytes, ASCII o UTF-16, y están limitadas a 4 MB y a un máximo de 256 coincidencias notificadas. Los comandos de asignación, liberación y protección se corresponden con los IOCTL del driver para asignar, liberar y proteger memoria.<sup>[[2]](#references)</sup>

```text
s 7ff700000000 100000 48 8b ?? c3
s 7ff700000000 100000 "MZ"
d rip 40
r rax
r rip=module!Function+5
e rip 90 90
.alloc 1000 rwx
.protect <addr> 1000 rx
.free <addr>
```

La carga de PDB lee el directorio de depuración PE de cada módulo remoto, extrae su identificador RSDS, busca el PDB correspondiente mediante DbgHelp/SymSrv y verifica que se haya cargado como PDB. Coloca los PDB privados junto al objetivo en la máquina relay o añade su directorio a `_NT_SYMBOL_PATH` en el host.<sup>[[2]](#references)</sup>

## Cambios de estado anti-debug respaldados por el kernel

El acceso al kernel permite al debugger eliminar indicadores que un debugger en user-mode no puede ocultar de forma fiable. Aplica un cambio cada vez, confirma la comprobación del objetivo y revierte el hook correspondiente antes de terminar la sesión.<sup>[[2]](#references)</sup>

```text
!peb
ad clr_debug_port
ad clr_thread_hide
ad ntqsi on
ad spoof on
stats
ad spoof off
ad ntqsi off
```

- `clr_debug_port` limpia `EPROCESS.DebugPort`.
- `clr_thread_hide` elimina `HideFromDebugger` de los hilos objetivo.
- `ntqsi on` falsifica la clase `0x23` (`SystemKernelDebuggerInformation`) de `NtQuerySystemInformation`.
- `spoof on` hace que las lecturas desde user-mode de `KUSER_SHARED_DATA.KdDebuggerEnabled` devuelvan false, mientras conserva el estado del kernel necesario para el mecanismo de trampa.
- `stats` comprueba los contadores de hooks y el estado registrado de `KiDebugRoutine`, `KdpStub` y `KdTrap`.

Estas operaciones modifican el estado del proceso y del kernel. Un crash, un inline hook obsoleto, un offset de estructura incorrecto o una restauración incompleta de un parche pueden desestabilizar la VM; por eso son obligatorios los snapshots y un entorno aislado de test-signing.<sup>[[1]](#references)</sup>

## References

- [1] [Repositorio de KernelFlirt y documentación principal](https://github.com/AkaTorich/KernelFlirt)
- [2] [Referencia de la consola de KernelFlirt](https://github.com/AkaTorich/KernelFlirt/blob/main/docs/cli.md)
{{#include ../../banners/hacktricks-training.md}}
