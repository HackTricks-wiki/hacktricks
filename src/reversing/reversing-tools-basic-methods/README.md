# Herramientas de reversing y métodos básicos

{{#include ../../banners/hacktricks-training.md}}

## Herramientas de reversing basadas en ImGui

Software:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Depuración del kernel de Windows

{{#ref}}
windows-kernel-debugging-kernelflirt.md
{{#endref}}

## Descompilador de Wasm / compilador de Wat

En línea:

- Usa [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) para **descompilar** de wasm (binario) a wat (texto legible)
- Usa [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) para **compilar** de wat a wasm
- También puedes probar [web-wasmdec](https://wwwg.github.io/web-wasmdec/) para descompilar.

Software:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## Bytecode en caché de Node.js / V8

{{#ref}}
nodejs-v8-cached-bytecode.md
{{#endref}}

## Payloads virtualizados y máquinas virtuales personalizadas

{{#ref}}
../../windows-hardening/virtualized-payload-execution.md
{{#endref}}

## Descompilador de .NET

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek es un descompilador que **descompila y examina varios formatos**, incluidas **bibliotecas** (.dll), **archivos de metadatos de Windows** (.winmd) y **ejecutables** (.exe). Una vez descompilado, un ensamblado se puede guardar como un proyecto de Visual Studio (.csproj).

La ventaja es que, si se necesita recuperar el código fuente perdido a partir de un ensamblado heredado, esta herramienta puede ahorrar tiempo. Además, dotPeek ofrece una navegación práctica por el código descompilado, lo que lo convierte en una de las herramientas ideales para el **análisis de algoritmos de Xamarin**.

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

Con un completo modelo de complementos y una API que amplía la herramienta para adaptarla a tus necesidades específicas, .NET Reflector ahorra tiempo y simplifica el desarrollo. Veamos la gran variedad de funciones de reverse engineering que ofrece esta herramienta:

- Permite conocer cómo fluyen los datos por una biblioteca o componente
- Permite conocer la implementación y el uso de los lenguajes y frameworks de .NET
- Encuentra funciones no documentadas ni expuestas para sacar más provecho de las API y tecnologías utilizadas.
- Encuentra dependencias y distintos ensamblados
- Localiza exactamente los errores en tu código, componentes de terceros y bibliotecas.
- Depura el código fuente de todo el código .NET con el que trabajas.

### [ILSpy](https://github.com/icsharpcode/ILSpy) y [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Complemento de ILSpy para Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode): Puedes usarlo en cualquier sistema operativo (puedes instalarlo directamente desde VSCode; no hace falta descargar git. Haz clic en **Extensions** y **busca ILSpy**).\
Si necesitas **descompilar**, **modificar** y volver a **compilar**, puedes usar [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) o una bifurcación que se mantiene activamente, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases). (**Clic derecho -> Modify Method** para cambiar algo dentro de una función).

### Registro de DNSpy

Para que **DNSpy registre información en un archivo**, puedes usar este fragmento:

```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```

### Depuración con DNSpy

Para depurar código con DNSpy, debes:

Primero, cambiar los **atributos del ensamblado** relacionados con la **depuración**:

![Registro de DNSpy - Depuración con DNSpy: Primero, cambia los atributos del ensamblado relacionados con la depuración](<../../images/image (973).png>)

De:

```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```

Para:

```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```

Y haz clic en **compilar**:

![DNSpy Logging - DNSpy Debugging: Y haz clic en compilar](<../../images/image (314) (1).png>)

Luego guarda el archivo nuevo mediante _**File >> Save module...**_:

![DNSpy Logging - DNSpy Debugging: Luego guarda el archivo nuevo mediante File Save module](<../../images/image (602).png>)

Esto es necesario porque, si no lo haces, en **runtime** se aplicarán varias **optimizaciones** al código y es posible que, al depurar, nunca se alcance un **breakpoint** o que algunas **variables no existan**.

Luego, si tu aplicación .NET se está **ejecutando** en **IIS**, puedes **reiniciarla** con:

```
iisreset /noforce
```

Luego, para empezar a depurar, debes cerrar todos los archivos abiertos y seleccionar **Attach to Process...** en la **Debug Tab**:

![DNSpy Logging - DNSpy Debugging: Luego, para empezar a depurar, debes cerrar todos los archivos abiertos y seleccionar Attach to Process en la pestaña Debug](<../../images/image (318).png>)

A continuación, selecciona **w3wp.exe** para adjuntarte al **IIS server** y haz clic en **attach**:

![DNSpy Logging - DNSpy Debugging: A continuación, selecciona w3wp.exe para adjuntarte al IIS server y haz clic en attach](<../../images/image (113).png>)

Ahora que estamos depurando el proceso, es hora de detenerlo y cargar todos los módulos. Primero, haz clic en _Debug >> Break All_ y luego en _**Debug >> Windows >> Modules**_:

![DNSpy Logging - DNSpy Debugging: Ahora que estamos depurando el proceso, es hora de detenerlo y cargar todos los módulos. Primero, haz clic en Debug Break All y luego en Debug Windows Modules](<../../images/image (132).png>)

![DNSpy Logging - DNSpy Debugging: Ahora que estamos depurando el proceso, es hora de detenerlo y cargar todos los módulos. Primero, haz clic en Debug Break All y luego en Debug Windows Modules](<../../images/image (834).png>)

Haz clic en cualquier módulo de **Modules** y selecciona **Open All Modules**:

![DNSpy Logging - DNSpy Debugging: Haz clic en cualquier módulo de Modules y selecciona Open All Modules](<../../images/image (922).png>)

Haz clic con el botón derecho en cualquier módulo de **Assembly Explorer** y selecciona **Sort Assemblies**:

![DNSpy Logging - DNSpy Debugging: Haz clic con el botón derecho en cualquier módulo de Assembly Explorer y selecciona Sort Assemblies](<../../images/image (339).png>)

## Decompilador de Java

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Depuración de DLLs

### Con IDA

- **Carga rundll32** (64 bits en C:\Windows\System32\rundll32.exe y 32 bits en C:\Windows\SysWOW64\rundll32.exe)
- Selecciona el debugger **Windbg**
- Selecciona "**Suspend on library load/unload**"

![Debugging DLLs - Using IDA: Selecciona " Suspend on library load/unload "](<../../images/image (868).png>)

- Configura los **parámetros** de ejecución indicando la **ruta a la DLL** y la función que quieres llamar:

![Debugging DLLs - Using IDA: Configura los parámetros de ejecución indicando la ruta a la DLL y la función que quieres llamar](<../../images/image (704).png>)

Luego, al empezar a depurar, **la ejecución se detendrá cada vez que se cargue una DLL**. Por tanto, cuando rundll32 cargue tu DLL, la ejecución se detendrá.

Este método se detiene en los eventos de carga de módulos, pero llegar al punto de entrada de la DLL cargada es menos directo que con el flujo de trabajo de x64dbg que se describe a continuación.

### Con x64dbg/x32dbg

- **Carga rundll32** (64 bits en C:\Windows\System32\rundll32.exe y 32 bits en C:\Windows\SysWOW64\rundll32.exe)
- **Cambia la línea de comandos** ( _File --> Change Command Line_ ) e indica la ruta de la DLL y la función que quieres llamar, por ejemplo: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- Cambia _Options --> Settings_ y selecciona "**DLL Entry**".
- Luego **inicia la ejecución**. El debugger se detendrá en cada dll main y, en algún momento, te **detendrás en el Entry de tu DLL**. Desde ahí, solo tienes que buscar los puntos donde quieras poner un breakpoint.

Ten en cuenta que, cuando la ejecución se detiene por cualquier motivo en win64dbg, puedes ver **en qué código estás** mirando en la **parte superior de la ventana de win64dbg**:

![Using IDA - Using x64dbg/x32dbg: Ten en cuenta que, cuando la ejecución se detiene por cualquier motivo en win64dbg, puedes ver en qué código estás mirando en la parte superior de la ventana de win64dbg](<../../images/image (842).png>)

Este indicador confirma que la ejecución se ha detenido dentro de la DLL que quieres depurar.

## Aplicaciones GUI / videojuegos

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) es un programa útil para encontrar dónde se guardan valores importantes en la memoria de un juego en ejecución y modificarlos. Más información en:


{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) es una herramienta de front-end e ingeniería inversa para GNU Project Debugger (GDB), enfocada en juegos. Sin embargo, se puede usar para cualquier tarea relacionada con la ingeniería inversa.

[**Decompiler Explorer**](https://dogbolt.org/) es un front-end web para varios decompiladores. Este servicio web permite comparar los resultados de distintos decompiladores con ejecutables pequeños.

## ARM y MIPS


{{#ref}}
https://github.com/nongiach/arm_now
{{#endref}}

## Shellcodes

### Depurar un shellcode con blobrunner

[**BlobRunner**](https://github.com/OALabs/BlobRunner) asigna memoria para el **shellcode**, muestra su **dirección de memoria** y pausa la ejecución.\
Adjunta un debugger, como IDA o x64dbg, establece un breakpoint en la dirección mostrada y reanuda la ejecución para depurar el shellcode.

La página de releases de GitHub contiene archivos zip con las versiones compiladas: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
Puedes encontrar una versión ligeramente modificada de Blobrunner en el siguiente enlace. Para compilarla, solo tienes que **crear un proyecto de C/C++ en Visual Studio Code, copiar y pegar el código y compilarlo**.


{{#ref}}
blobrunner.md
{{#endref}}

### Depurar un shellcode con jmp2it

[**jmp2it**](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) es similar a BlobRunner. Asigna memoria para el shellcode y entra en un bucle infinito. Adjunta el debugger, reanuda la ejecución durante **2–5 segundos**, pausa dentro de ese bucle y avanza hasta la siguiente llamada que transfiere la ejecución al shellcode asignado.

![Debugger pausado en el bucle infinito de jmp2it, justo antes de la llamada al shellcode asignado](<../../images/image (509).png>)

Puedes descargar una versión compilada de [jmp2it en la página de releases](https://github.com/adamkramer/jmp2it/releases/).

### Depurar shellcode con Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) es la GUI de radare. Con Cutter puedes emular el shellcode e inspeccionarlo dinámicamente.

Ten en cuenta que Cutter permite «Open File» y «Open Shellcode». En mi caso, al abrir el shellcode como archivo lo decompiló correctamente, pero al abrirlo como shellcode no lo hizo:

![Cutter muestra distintos resultados de análisis al abrir los mismos bytes como archivo o como shellcode](<../../images/image (562).png>)

Para iniciar la emulación en el lugar que quieras, establece un bp allí; al parecer, Cutter iniciará automáticamente la emulación desde ese punto:

![Configuración de un breakpoint en el punto de entrada deseado del shellcode antes de iniciar la emulación en Cutter](<../../images/image (589).png>)

![Emulador de Cutter pausado en el breakpoint seleccionado del shellcode](<../../images/image (387).png>)

Por ejemplo, puedes ver la stack en un volcado hexadecimal:

![Visualización de la stack del shellcode emulado en el volcado hexadecimal de Cutter](<../../images/image (186).png>)

### Desofuscar shellcode y obtener las funciones ejecutadas

Prueba [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152).\
Te indicará cosas como **qué funciones** utiliza el shellcode y si se está **decodificando** en memoria.

```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```

scDbg también cuenta con un lanzador gráfico donde puedes seleccionar las opciones que quieras y ejecutar el shellcode

![Lanzador gráfico de scDbg para seleccionar opciones de emulación y trazado de shellcode](<../../images/image (258).png>)

La opción **Create Dump** volcará el shellcode final si se realiza algún cambio dinámico en el shellcode en memoria (útil para descargar el shellcode decodificado). **start offset** puede ser útil para iniciar el shellcode en un offset específico. La opción **Debug Shell** sirve para depurar el shellcode usando la terminal de scDbg (sin embargo, para esto me parece mejor cualquiera de las opciones explicadas antes, ya que podrás usar Ida o x64dbg).

### Desensamblar con CyberChef

Sube tu archivo de shellcode como entrada y usa la siguiente receta para desensamblarlo: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/index.html#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## Desofuscación de MBA obfuscation

La ofuscación **Mixed Boolean-Arithmetic (MBA)** oculta expresiones simples como `x + y` tras fórmulas que combinan operaciones aritméticas (`+`, `-`, `*`) y operadores bit a bit (`&`, `|`, `^`, `~`, desplazamientos). Lo importante es que estas identidades suelen ser correctas solo bajo **aritmética modular de ancho fijo**, por lo que los acarreos y los desbordamientos importan:

```c
(x ^ y) + 2 * (x & y) == x + y
```

Si simplificas este tipo de expresión con herramientas algebraicas genéricas, puedes obtener fácilmente un resultado incorrecto porque se ignoró la semántica del ancho de bits.<sup>[[1]](#references)</sup>

### Flujo de trabajo práctico

1. **Conserva el ancho de bits original** del código levantado, la IR o la salida del decompilador (`8/16/32/64` bits).
2. **Clasifica la expresión** antes de intentar simplificarla:
   - **Lineal**: sumas ponderadas de átomos bitwise
   - **Semilineal**: expresión lineal más máscaras constantes, como `x & 0xFF`
   - **Polinómica**: aparecen productos
   - **Mixta**: se intercalan productos y lógica bitwise, a menudo con subexpresiones repetidas
3. **Verifica cada reescritura candidata** con pruebas aleatorias o una demostración SMT. Si no se puede demostrar la equivalencia, conserva la expresión original en lugar de hacer conjeturas.

### Evita el flujo de control aplanado con un fragmento de ejecución acotado

A menudo no es necesario recuperar el grafo de flujo de control completo. Ante el aplanamiento del flujo de control, opaque predicates, dispatchers grandes o código con mucho MBA, sigue las referencias desde los blobs cifrados y los buffers de salida hasta la rutina más pequeña que los transforma. Luego, reproduce solo ese fragmento del flujo de datos o ejecútalo de forma independiente; el dispatcher no forma parte de la solución necesaria si el estado relevante se puede inicializar directamente.<sup>[[7]](#references)</sup>

Un flujo de trabajo práctico es:<sup>[[7]](#references)</sup>

1. Inventaría las secciones ejecutables y de datos, las relocations y las referencias cruzadas. Vuelca las tablas candidatas de `.rodata` conservando el orden de los bytes y el ancho de los elementos.
2. Identifica la última rutina que escribe el texto plano o el buffer de salida. Registra sus entradas, las tablas referenciadas, las llamadas importadas y el estado global necesario.
3. Levanta solo esas operaciones en un modelo Python de ancho fijo. Si el fragmento aún depende de demasiado estado, invoca la rutina con Unicorn, QEMU o un debugger, e intercepta las importaciones irrelevantes en lugar de emular todo el programa.
4. Valida que el extractor derive realmente su salida del binario proporcionado: elimina los fallbacks silenciosos, busca respuestas incrustadas y ejecútalo con compilaciones no vistas que tengan cadenas, claves, identificadores, layouts y semillas de ofuscación distintos.

Los siguientes comandos son útiles para una primera inspección:<sup>[[7]](#references)</sup>

```bash
readelf -SW target
objdump -s -j .rodata target > rodata.txt
objdump -d target | rg 'adrp|add|ldr|str'
```

#### Detectar expresiones MBA que ocultan constantes

Una expresión de byte que aparentemente depende de la entrada puede cancelar por completo dicha entrada. Tras extraer sus tablas, evalúa la expresión en todo el dominio de 8 bits; un conjunto de salidas unitario demuestra que ese byte es constante, sin necesidad de recuperar la máquina de estados circundante.<sup>[[7]](#references)</sup>

```python
def mba(a, b, c, d, e, x):
    return ((((a | (~x & 0xff)) & c) +
             ((x | b) & d)) ^ e) & 0xff

decoded = bytearray()
for row in zip(A, B, C, D, E):
    outputs = {mba(*row, x) for x in range(256)}
    if len(outputs) != 1:
        raise ValueError("expression depends on x")
    decoded.append(outputs.pop())
print(decoded)
```

Conserva la máscara final porque la suma original tiene desbordamiento modular al ancho de un byte. Para un dominio más amplio, pregunta a un SMT solver si `f(x1) != f(x2)` es satisfacible para dos entradas simbólicas del mismo ancho: `unsat` demuestra la invariancia, mientras que `sat` proporciona un contraejemplo y significa que no se puede descartar la entrada.<sup>[[7]](#references)</sup>

#### Reconocer la decodificación vinculada al entorno

Las comprobaciones anti-analysis no tienen por qué provocar un salto ni un fallo. Un decodificador puede mezclar el resultado de un sensor en un bit de la clave, una constante de opaque-predicate o el estado de un dispatcher aplanado, continuar normalmente y producir texto plano plausible pero falso en un emulador. Por lo tanto, parchear solo las ramas de fallo visibles no es suficiente; rastrea las dependencias de datos desde las sondas del entorno hasta el estado del decodificador, compara el mismo fragmento en el dispositivo auténtico y en el emulador, y prueba cómo cambia el búfer final al forzar cada resultado del sensor.<sup>[[7]](#references)</sup>

### CoBRA

[**CoBRA**](https://github.com/trailofbits/CoBRA) es un simplificador práctico de MBA para el análisis de malware y el reversing de binarios protegidos. Clasifica la expresión y la dirige a pipelines especializados, en lugar de aplicar una única pasada de reescritura genérica a todo.<sup>[[2]](#references)</sup>

Uso rápido:

```bash
# Recover arithmetic from a logic-heavy MBA
cobra-cli --mba "(x&y)+(x|y)"
# x + y

# Preserve fixed-width wraparound semantics
cobra-cli --mba "(x&0xFF)+(x&0xFF00)" --bitwidth 16
# x

# Ask CoBRA to prove the rewrite with Z3
cobra-cli --mba "(a^b)+(a&b)+(a&b)" --verify
```

Casos útiles:

- **Linear MBA**: CoBRA evalúa la expresión con entradas Booleanas, deriva una firma y ejecuta en paralelo varios métodos de recuperación, como la coincidencia de patrones, la conversión a ANF y la interpolación de coeficientes.
- **Semilinear MBA**: los átomos enmascarados por constantes se reconstruyen mediante una reconstrucción particionada por bits para que las regiones enmascaradas sigan siendo correctas.
- **Polynomial/Mixed MBA**: los productos se descomponen en núcleos y las subexpresiones repetidas pueden trasladarse a temporales antes de simplificar la relación externa.

Ejemplo de una identidad mixta que suele valer la pena intentar recuperar:

```c
(x & y) * (x | y) + (x & ~y) * (~x & y)
```

Esto se puede reducir a:

```c
x * y
```

### Notas de reversing

- Es preferible ejecutar CoBRA sobre **expresiones IR elevadas** o sobre la salida del decompilador, después de aislar el cálculo exacto.
- Usa `--bitwidth` explícitamente cuando la expresión provenga de aritmética enmascarada o de registros estrechos.
- Si necesitas un paso de prueba más sólido, consulta las notas locales sobre Z3 aquí:


{{#ref}}
satisfiability-modulo-theories-smt-z3.md
{{#endref}}

- CoBRA también incluye un plugin de paso de **LLVM** (`libCobraPass.so`), útil cuando quieres normalizar IR de LLVM con mucho MBA antes de ejecutar pasos de análisis posteriores.
- Los residuos mixtos entre dominios sensibles al acarreo que no sean compatibles deben tomarse como señal para conservar la expresión original y analizar manualmente la ruta del acarreo.

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

Este ofuscador reemplaza las operaciones del programa por secuencias de instrucciones basadas en `mov` y usa el manejo de señales/excepciones para alterar el flujo de control. Más detalles:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

Para los binarios compatibles, [demovfuscator](https://github.com/kirschju/demovfuscator) puede desofuscar el resultado. Tiene varias dependencias.

```
apt-get install libcapstone-dev
apt-get install libz3-dev
```

Y [instala keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

Si estás jugando a un **CTF, esta solución alternativa para encontrar la flag** podría ser muy útil: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

Para encontrar el **punto de entrada**, busca las funciones por `::main`, como en:

![Encontrar un punto de entrada de Rust en Ghidra buscando nombres de funciones con dos puntos dobles seguidos de main](<../../images/image (1080).png>)

En este caso, el binario se llamaba authenticator, así que es bastante obvio que esta es la función main interesante.\
Una vez que tengas los **nombres** de las **funciones** que se llaman, búscalos en **Internet** para conocer sus **entradas** y **salidas**.

### Recuperar cadenas de Rust desde firmware ELF

En los binarios **ELF de Rust**, muchas cadenas estáticas no se referencian mediante punteros terminados en NUL al estilo de C. Un diseño común de `rustc` es una **tupla de puntero/longitud** dentro de **`.data.rel.ro`** que apunta al bloque de cadenas real almacenado en **`.rodata`**:

```text
[8-byte little-endian pointer][8-byte little-endian length]
```

Esto significa que `strings` o el análisis predeterminado de Ghidra pueden combinar cadenas adyacentes o pasar por alto por completo las referencias cruzadas.<sup>[[3]](#references)</sup>

Flujo de trabajo rápido:

```bash
readelf -S <bin>
objdump -h <bin>
```

1. Obtén la dirección virtual y el tamaño de **`.rodata`**.
2. Enumera **`.data.rel.ro`** palabra por palabra.
3. Trata cualquier valor dentro del rango de direcciones de `.rodata` como un posible puntero a una cadena.
4. Trata la palabra siguiente como la longitud candidata.
5. Aplica filtros de validación (por ejemplo, conserva las longitudes entre **4** y **100** bytes).
6. Lee exactamente `length` bytes de `.rodata` en lugar de buscar hasta `0x00`.

Lógica mínima del extractor:

```python
for off in range(0, len(data_rel_ro), 8):
    ptr = u64(data_rel_ro[off:off+8])
    length = u64(data_rel_ro[off+8:off+16])
    if rodata_start <= ptr < rodata_end and 4 <= length <= 100:
        start = ptr - rodata_start
        print(rodata[start:start+length])
```

Esto es especialmente útil al hacer reversing de firmware, porque las cadenas recuperadas de Rust suelen revelar **rutas HTTP, nombres RPC, mensajes de registro, aserciones, nombres de archivo, claves de configuración, manejadores de comandos y lógica relacionada con la autenticación**.

Si Ghidra no detecta esas cadenas, ejecuta un script/plugin personalizado que aplique la misma heurística y cree datos de cadena en los offsets de `.rodata` referenciados. Las herramientas publicadas `rust-strings` y `RustStrings.py` de Pen Test Partners son buenas referencias para adaptar la idea a otros **tamaños de palabra, órdenes de bytes y diseños de secciones**.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

## **Delphi**

Para binarios compilados con Delphi, puedes usar [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR)

Si tienes que hacer reversing de un binario Delphi, te sugiero usar el plugin de IDA [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi)

Pulsa **Alt+F7** en IDA para cargar un plugin de Python y, después, selecciona el archivo del plugin.

Este plugin ejecutará el binario y resolverá dinámicamente los nombres de las funciones al iniciar la depuración. Después de iniciarla, vuelve a pulsar el botón Start (el verde o F9) y se activará un breakpoint al comienzo del código real.

Si pulsas un botón en la aplicación gráfica, el debugger puede detenerse en la función invocada por ese botón.

## Golang

Para los binarios Go normales, [IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) puede recuperar estructuras del runtime y mejorar los nombres de las funciones en IDA. Carga su plugin de Python con **Alt+F7**.

### Recuperar metadatos sin la tabla de símbolos

Un ejecutable Go stripped sigue necesitando metadatos del runtime para asignar contadores de programa a funciones. [GoReSym](https://github.com/mandiant/GoReSym) localiza y analiza estructuras como `pclntab` y `moduledata` mediante código derivado del runtime de Go. Esto permite recuperar límites de funciones, nombres, rutas de origen, tipos y detalles de compilación sin depender de la tabla de símbolos convencional.<sup>[[9]](#references)[[13]](#references)</sup>

```bash
GoReSym.exe -t -d -p /path/to/sample.exe > goresym.json
```

Un obfuscador puede dejar esas estructuras utilizables mientras reemplaza los nombres recuperados. Garble, por ejemplo, aplica hashes a los identificadores y las rutas de paquetes, y elimina la información de build, módulos y depuración.<sup>[[12]](#references)</sup> El token ofuscado del paquete debe ser consistente entre las funciones de ese paquete. Agrupa las funciones por el token repetido, infiere un paquete a partir de sus funciones llamadas, cadenas y APIs, y luego propaga esa etiqueta de paquete a todo el grupo.<sup>[[13]](#references)</sup>

### Recuperar nombres de Garble con GoResolver

[GoResolver](https://github.com/volexity/GoResolver) combina la extracción de símbolos del runtime con la generación de referencias limpias y la comparación de grafos de flujo de control (CFG). Sigue esta secuencia:<sup>[[10]](#references)[[13]](#references)</sup>

1. **Identifica la versión del compilador.** Prueba primero con `BuildInfo` y las cadenas de versión integradas. Si el ofuscador las eliminó, compara partes del runtime de Go incluido con runtimes de referencia versionados. En las pruebas de Volexity, aproximadamente el `2%` del runtime bastó para distinguir las versiones principales de Go. Tómalo como una optimización empírica, no como un umbral universal.<sup>[[13]](#references)</sup>
2. **Genera referencias compatibles.** Genera binarios limpios para la versión de Go identificada, la arquitectura objetivo y las bibliotecas probables. Usar una cadena de herramientas compatible reduce las diferencias en los CFG generados por el compilador.<sup>[[10]](#references)[[13]](#references)</sup>
3. **Compara funciones.** GoGrapher compara los CFG de las funciones y genera puntuaciones normalizadas de `0.0` a `1.0`. La comparación de bloques básicos se basa en una comparación ponderada de instrucciones similares. Las coincidencias de alta confianza asocian funciones aleatorizadas con la implementación limpia. Las coincidencias más débiles aún pueden identificar un paquete o módulo.<sup>[[8]](#references)[[11]](#references)[[13]](#references)</sup>
4. **Valida e importa.** Confirma los nombres propuestos mediante las relaciones entre llamadas, las constantes, las cadenas y los efectos secundarios; luego importa el informe JSON con el plugin de GoResolver para IDA o Ghidra.<sup>[[10]](#references)[[13]](#references)</sup>

Instala la cadena de herramientas y ejecuta el extractor y comparador de grafos combinados:<sup>[[10]](#references)</sup>

```bash
python3 -m venv goresolver-env
source goresolver-env/bin/activate
pip install goresolver

# Automatic Go-version detection and reference selection
goresolver resolve -o report.json /path/to/sample.exe

# Override the version/libraries and confidence threshold when known
goresolver resolve -v go1.23.4 -l os/exec net/http \
  -t 0.9 -o report.json /path/to/sample.exe
```

El umbral predeterminado de coincidencia significativa es `0.9`. Las opciones `--extract` y `--graph` permiten aislar cada etapa, mientras que, de forma predeterminada, se ejecutan ambas porque los metadatos recuperados del runtime y la evidencia del CFG se complementan entre sí.<sup>[[10]](#references)</sup> Las puntuaciones del CFG son heurísticas: el inlining, las opciones de compilación, la arquitectura y las diferencias entre versiones de bibliotecas pueden cambiar la forma del grafo, así que conserva las funciones sin resolver en lugar de asignarles nombres con baja confianza.<sup>[[13]](#references)</sup>

## Python compilado

En esta página puedes descubrir cómo obtener el código Python de un binario ELF/EXE compilado con Python:


{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - Game Boy Advance

Si obtienes el **binario** de un juego de GBA, puedes usar distintas herramientas para **emularlo** y **depurarlo**:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_Descarga la versión de depuración_) - Incluye un debugger con interfaz
- [**mgba** ](https://mgba.io)- Incluye un debugger de CLI
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Plugin de Ghidra
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Plugin de Ghidra

En [**no$gba**](https://problemkaputt.de/gba.htm), en _**Opciones --> Configuración de emulación --> Controles**_** ** puedes ver cómo pulsar los **botones** de Game Boy Advance

![Configuración de controles de no$gba con las asignaciones de botones de Game Boy Advance](<../../images/image (581).png>)

Al pulsarlas, cada **tecla tiene un valor** que la identifica:

```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```

Así que, en este tipo de programa, lo interesante será **cómo trata el programa la entrada del usuario**. En la dirección **0x4000130** encontrarás la función habitual: **KEYINPUT**.

![Vista de Ghidra de un binario de GBA que hace referencia a KEYINPUT en la dirección 0x4000130](<../../images/image (447).png>)

En la imagen anterior puedes ver que la función se llama desde **FUN_080015a8** (direcciones: _0x080015fa_ y _0x080017ac_).

En esa función, después de algunas operaciones de inicialización (sin importancia):

```c
void FUN_080015a8(void)

{
  ushort uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  ushort uVar4;
  int iVar5;
  ushort *puVar6;
  undefined *local_2c;

  DISPCNT = 0x1140;
  FUN_08000a74();
  FUN_08000ce4(1);
  DISPCNT = 0x404;
  FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
  FUN_08000354(&DAT_030000dc,0x3c);
  uVar4 = DAT_030004d8;
```

Se encontró este código:

```c
  do {
    DAT_030004da = uVar4; //This is the last key pressed
    DAT_030004d8 = KEYINPUT | 0xfc00;
    puVar6 = &DAT_0200b03c;
    uVar4 = DAT_030004d8;
    do {
      uVar2 = DAT_030004dc;
      uVar1 = *puVar6;
      if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```

El último if comprueba que **`uVar4`** está en las **últimas Keys** y que no es la tecla actual; esto también se conoce como soltar un botón (la tecla actual se almacena en **`uVar1`**).

```c
        if (uVar1 == 4) {
          DAT_030000d4 = 0;
          uVar3 = FUN_08001c24(DAT_030004dc);
          FUN_08001868(uVar2,0,uVar3);
          DAT_05000000 = 0x1483;
          FUN_08001844(&DAT_0200ba18);
          FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
          DAT_030000d8 = 0;
          uVar4 = DAT_030004d8;
        }
        else {
          if (uVar1 == 8) {
            if (DAT_030000d8 == 0xf3) {
              DISPCNT = 0x404;
              FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
              FUN_08000354(&DAT_030000dc,0x3c);
              uVar4 = DAT_030004d8;
            }
          }
          else {
            if (DAT_030000d4 < 8) {
              DAT_030000d4 = DAT_030000d4 + 1;
              FUN_08000864();
              if (uVar1 == 0x10) {
                DAT_030000d8 = DAT_030000d8 + 0x3a;
```

En el código anterior puedes ver que estamos comparando **uVar1** (donde está el **valor del botón pulsado**) con algunos valores:

- Primero, se compara con el **valor 4** (botón **SELECT**): en el challenge, este botón borra la pantalla.
- Luego, se compara el valor con **8** (botón **START**); en este challenge, esa ruta comprueba si el código introducido es válido.
  - En este caso, la variable **`DAT_030000d8`** se compara con 0xf3 y, si el valor coincide, se ejecuta cierto código.
- En cualquier otro caso, se comprueba e incrementa un contador (`DAT_030000d4`).\
  Mientras el contador sea menor que 8, los valores de las teclas pulsadas se acumulan en `DAT_030000d8`.

Así que, en este challenge, al conocer los valores de los botones, había que **pulsar una combinación de menos de 8 teclas cuya suma diera 0xf3.**

**Referencia para este tutorial:** [writeup archivado del challenge Nostalgia](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/).<sup>[[6]](#references)</sup>

## Game Boy


{{#ref}}
https://www.youtube.com/watch?v=VVbRe7wr3G4
{{#endref}}

## Cursos

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (Desofuscación de binarios)

## References

- [1] [Simplificación de la ofuscación MBA con CoBRA](https://blog.trailofbits.com/2026/04/03/simplifying-mba-obfuscation-with-cobra/)
- [2] [Repositorio CoBRA de Trail of Bits](https://github.com/trailofbits/CoBRA)
- [3] [Decodificación de cadenas de Rust - Pen Test Partners](https://www.pentestpartners.com/security-blog/decoding-rust-strings/)
- [4] [pentestpartners/reverse-engineering - cadenas de Rust](https://github.com/pentestpartners/reverse-engineering/blob/main/rust-strings)
- [5] [pentestpartners/reverse-engineering - RustStrings.py](https://github.com/pentestpartners/reverse-engineering/blob/main/RustStrings.py)
- [6] [Nostalgia - tutorial de reversing de GBA (archivado)](https://web.archive.org/web/20220328215728/https://exp.codes/Nostalgia/)
- [7] [Cómo derrotar el reverse engineering asistido por IA, o al menos intentarlo](http://blog.quarkslab.com/defeating-ai-assisted-reverse-engineering-or-at-least-trying-to.html)
- [8] [Un enfoque para comparar grafos de flujo de control basado en la correspondencia de bloques básicos](https://www.ijcse.com/docs/INDJCSE20-11-03-237.pdf)
- [9] [GoReSym de Mandiant](https://github.com/mandiant/GoReSym)
- [10] [GoResolver de Volexity](https://github.com/volexity/GoResolver)
- [11] [GoGrapher de Volexity](https://github.com/volexity/GoGrapher)
- [12] [Mecanismo de ofuscación de Garble](https://github.com/burrowers/garble#mechanism)
- [13] [GoResolver: uso de la similitud de grafos de flujo de control para desofuscar automáticamente binarios de Golang](https://volexity.com/blog/2025/04/01/goresolver-using-control-flow-graph-similarity-to-deobfuscate-golang-binaries-automatically)
{{#include ../../banners/hacktricks-training.md}}
