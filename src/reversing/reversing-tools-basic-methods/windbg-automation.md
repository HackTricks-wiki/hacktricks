# Automatización de WinDbg para instrumentación dirigida

{{#include ../../banners/hacktricks-training.md}}

WinDbg y WinDbgX pueden ejecutar comandos del depurador al inicio, ante excepciones y cuando se activan puntos de interrupción. Esto permite que una sesión de fuzzing o reversing recopile el estado solo en torno a una ruta impulsada por la entrada, en lugar de detenerse manualmente en cada evento.<sup>[[1]](#references)</sup>

## Empezar con una excepción útil

`-c` ejecuta comandos en la parada inicial del depurador. Añade `;g` para reanudar después de la configuración. Para una ejecución desatendida de WinDbg Classic, `-logo` escribe la ventana de comandos en un registro, `-Q` desactiva el guardado automático del espacio de trabajo y `-G` ignora el punto de interrupción final, de modo que la sesión termina cuando sale el objetivo. WinDbgX también acepta `-c`; después ejecuta los comandos de inicio configurados.<sup>[[1]](#references)[[7]](#references)</sup>

```text
windbg.exe -c "sxd av;g" -logo C:\logs\triage.txt C:\path\target.exe
```

Para las infracciones de acceso, **`sxe av` se detiene en la primera oportunidad**, **`sxd av` omite la primera oportunidad, pero se detiene en la segunda si la excepción no se ha controlado**, y **`sxi av` ignora ambas oportunidades**. En este caso, las descripciones de `sxi`/`sxd` del artículo están invertidas: Microsoft documenta `sxd` como el filtro de segunda oportunidad y `sxi` como ignorar. Usa `-c` para un comando de primera oportunidad y `-c2` para uno de segunda oportunidad; un controlador `-c` de primera oportunidad no se convierte en un controlador de segunda oportunidad solo porque el filtro sea `sxd`. Confirma los filtros activos con `sx`.<sup>[[1]](#references)[[2]](#references)</sup>

```text
sxd -c2 "r;kv;!analyze -v" av
sxe -c "lm" ld
```

El primer comando recopila registros, un stack trace y el análisis de excepciones solo ante una access violation no controlada. El segundo ejecuta `lm` cuando se carga un módulo. Los eventos de breakpoint (`bp`), carga de módulo (`ld`) y access violation (`av`) tienen ciclos de vida distintos, así que no ignores globalmente `bp` si dependes de los breakpoints del debugger.<sup>[[1]](#references)[[2]](#references)</sup>

## Controla los breakpoints costosos con un trigger controlado

Elige una función visible para el script o controlada de otro modo mediante la entrada, que se pueda llamar justo antes de la ruta de interés. Instala **action breakpoints** en las llamadas al allocator, al parser o a las API que quieras inspeccionar. Desactívalos por ID con `bd`. Instala un **trigger breakpoint** con un comando asociado que habilite esos IDs mediante `be` y luego reanude la ejecución con `g`; un segundo trigger controlado puede volver a desactivarlos. Comprueba los IDs con `bl` antes de configurar el trigger, ya que dependen del orden en que se creen los breakpoints. Esto separa los puntos de control de bajo costo del tracing costoso y limita los cambios en la temporización y el layout del heap del objetivo.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Tras resolver los dos símbolos, el patrón de comandos es el siguiente. Sustituye los símbolos entre corchetes y el ID del action breakpoint que devuelve `bl`; no des por sentado que es cero.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```text
bp <action-symbol> "r;g"
bl
bd <action-id>
bp <trigger-symbol> "be <action-id>;g"
```

Los comandos de puntos de interrupción de acción pueden imprimir `@$ip` y `%y` (dirección simbolizada), volcar argumentos seleccionados o memoria y, después, continuar. Si un punto de interrupción condicional solo registra punteros dentro de un rango seleccionado, verifica primero que el rango realmente incluya la entrada de prueba; una condición incorrecta hace que se pierdan pruebas sin avisar.<sup>[[1]](#references)</sup>

### Encontrar un desencadenante con símbolos

Busca en todos los módulos cargados si se desconoce el módulo de implementación. `bm` establece puntos de interrupción en cada símbolo coincidente; invoca la función visible desde script e inspecciona qué punto de interrupción se activa. Por ejemplo, el código fuente ejecuta `Math.cos(0)` en el renderer que se está depurando, no en cualquier proceso del navegador.<sup>[[1]](#references)[[5]](#references)</sup>

```text
x *!*math*cos*
bm *edge*!*math*cos* ".printf \"%y called\n\", @$ip;g"
g
```

Una vez que un hit identifica la función exacta, usa `lm a <symbol>` para resolver la imagen que la contiene y `? <symbol> - <module>` para calcular un offset relativo al módulo. WinDbg puede mostrar el mismo nombre corto de módulo para un ejecutable y una DLL, así que verifica la ruta de la imagen antes de usar el offset en otro proceso. Restringe los breakpoints con comodines al símbolo verificado para evitar sobrecarga.<sup>[[1]](#references)</sup>

### Encontrar un candidato sin símbolos

El `corelan_trigscan.py`, basado en Frida y creado por Corelan, analiza un módulo de proceso seleccionado en busca de patrones de instrucciones de punto flotante, SSE, AVX y trigonométricas. Genera comandos de breakpoint de WinDbg en `corelan_trigscan.bps` y archivos `.bps` numerados más pequeños. Ejecútalo con Python y `frida-tools` contra el objetivo **sin tener otro debugger conectado**; después, conecta WinDbg al mismo proceso/módulo y carga un lote de breakpoints manejable.<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.5 --min-relevant 50 --min-total 20 --min-trig 1
$$><C:\logs\msedge.dll\corelan_trigscan_0001.bps
```

Para un desplazamiento relativo al módulo conocido, valida que supere los umbrales antes de importar todos los puntos de interrupción emitidos:<sup>[[1]](#references)[[6]](#references)</sup>

```text
py -3.9-64 corelan_trigscan.py -p msedge.exe -m msedge.dll --min-density 0.15 --min-relevant 8 --min-total 45 --check-offset 00e13dc0 --min-icall 1
```

`--min-density` es la densidad de instrucciones relevantes, `--min-relevant` y `--min-total` establecen mínimos de cantidad de instrucciones, y `--min-trig` requiere señales sólidas similares a las trigonométricas. Si no se detecta una función conocida, pasa su offset **relativo al módulo** a `--check-offset` para inspeccionar su prólogo, densidad, cantidad de instrucciones y llamadas indirectas. Un wrapper delgado puede tener baja densidad y ninguna instrucción trigonométrica. Reduce los umbrales y, si buscas wrappers, usa la opción real del script `--min-icall 1` (no `--min-ical`); se analizan las funciones llamadas directamente, pero no es posible seguir de forma fiable los destinos indirectos. Los lotes con un `--splitsize` menor ayudan cuando muchos breakpoints generados ralentizan WinDbg. Un candidato no está validado hasta que la entrada prevista hace que se active su breakpoint.<sup>[[1]](#references)[[6]](#references)</sup>

## Programas pequeños para el depurador y PyKD

Usa `.if` cuando una condición sea fiable, `.foreach` para iterar sobre la salida delimitada por espacios en blanco y `.for` con pseudo-registros para recorrer memoria o estructuras. `.foreach` **no** conserva las columnas: por ejemplo, la salida de ancho variable de `lm` es una entrada inadecuada, mientras que `lm 1m` produce un nombre de módulo por token. Registra primero los datos sin filtrar si una condición supuesta podría ocultar la ruta que falla.<sup>[[1]](#references)</sup>

```text
.foreach (mod { lm 1m }) { .echo ${mod} }
r $t0 = 0
.for ( ; @$t0 < 5 ; r $t0 = @$t0 + 1 ) { .printf "i = %d\n", @$t0 }
```

Los alias creados con `as name value` son sustituciones textuales, no variables tipadas. `al` los enumera, `ad name` elimina uno y `${name}` fuerza una expansión inequívoca. Evita nombres como `bp`, `x` o `r`, porque un alias puede ocultar un comando integrado. Las expresiones MASM son adecuadas para la aritmética de punteros, como `poi(@$t0)`; `@@c++(...)` permite acceder a campos tipados cuando hay símbolos disponibles, evitando offsets de estructura codificados a mano.<sup>[[1]](#references)</sup>

Coloca las secuencias de comandos más largas en un archivo de comandos. `$$><filename` une las líneas en un único bloque de comandos y permite añadir después un comando del debugger separado por punto y coma. Las estructuras de control multilínea pueden seguir siendo frágiles; mantén cada instrucción `.if` o `.for` en una sola línea. El mismo archivo se puede ejecutar desde `-c` al iniciar.<sup>[[1]](#references)[[8]](#references)</sup>

Para la lógica que resulta complicada en el lenguaje de comandos, PyKD expone estructuras tipadas, registros, memoria y la salida del debugger a Python. Por ejemplo, `pykd.typedVar("ntdll!_PEB", pykd.getCurrentProcess())` accede a los campos de PEB, `pykd.loadBytes(address, size)` lee la memoria y `pykd.dbgCommand("lm")` devuelve la salida del debugger para analizarla. Para datos que podrían no estar terminados en nulo, prefiere `loadChars`/`loadWChars` con límites en lugar de lecturas de cadenas sin límite. `disasm(address).asm(instruction)` de PyKD **escribe bytes ensamblados en esa dirección**, así que guarda y restaura la memoria original si lo usas para obtener opcodes en un proceso activo.<sup>[[1]](#references)</sup>

{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Corelan: Depuración - Automatización y scripting de WinDBG(X) - Parte 1](https://corelan.be/index.php/2026/04/17/debugging-windbgx-automation-scripting-part-1)
- [2] [Microsoft: sx, sxd, sxe, sxi, sxn, sxr, sx- (Configurar excepciones)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/sx--sxd--sxe--sxi--sxn--sxr--sx---set-exceptions-)
- [3] [Microsoft: be (Habilitar breakpoint)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/be--breakpoint-enable-)
- [4] [Microsoft: bd (Deshabilitar breakpoint)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bd--breakpoint-disable-)
- [5] [Microsoft: bp, bu, bm (Configurar breakpoint)](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/bp--bu--bm--set-breakpoint-)
- [6] [Código fuente de trigscan de Corelan](https://github.com/corelan/blogposts/blob/main/debugging/scripts/frida/corelan_trigscan.py)
- [7] [Microsoft: Opciones de la línea de comandos de WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/windbg-command-line-options)
- [8] [Microsoft: Ejecutar archivo de script](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-----------------------a---run-script-file-)
