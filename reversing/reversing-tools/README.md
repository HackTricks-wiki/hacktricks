<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

# Guía de Descompilación de Wasm y Compilación de Wat

En el ámbito de **WebAssembly**, las herramientas de **descompilación** y **compilación** son esenciales para los desarrolladores. Esta guía presenta algunos recursos en línea y software para manejar archivos de **Wasm (binario de WebAssembly)** y **Wat (texto de WebAssembly)**.

## Herramientas en Línea

- Para **descompilar** Wasm a Wat, la herramienta disponible en [la demo de wasm2wat de Wabt](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) es útil.
- Para **compilar** Wat de nuevo a Wasm, [la demo de wat2wasm de Wabt](https://webassembly.github.io/wabt/demo/wat2wasm/) cumple el propósito.
- Otra opción de descompilación se puede encontrar en [web-wasmdec](https://wwwg.github.io/web-wasmdec/).

## Soluciones de Software

- Para una solución más robusta, [JEB de PNF Software](https://www.pnfsoftware.com/jeb/demo) ofrece características extensas.
- El proyecto de código abierto [wasmdec](https://github.com/wwwg/wasmdec) también está disponible para tareas de descompilación.

# Recursos de Descompilación de .Net

La descompilación de ensamblados .Net se puede lograr con herramientas como:

- [ILSpy](https://github.com/icsharpcode/ILSpy), que también ofrece un [complemento para Visual Studio Code](https://github.com/icsharpcode/ilspy-vscode), permitiendo su uso multiplataforma.
- Para tareas que involucran **descompilación**, **modificación** y **recompilación**, se recomienda ampliamente [dnSpy](https://github.com/0xd4d/dnSpy/releases). Al hacer clic derecho en un método y elegir **Modificar método**, se pueden realizar cambios en el código.
- [dotPeek de JetBrains](https://www.jetbrains.com/es-es/decompiler/) es otra alternativa para descompilar ensamblados .Net.

## Mejorando la Depuración y el Registro con DNSpy

### Registro con DNSpy
Para registrar información en un archivo usando DNSpy, incorpora el siguiente fragmento de código .Net:

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Contraseña: " + contraseña + "\n");
%%%

### Depuración con DNSpy
Para una depuración efectiva con DNSpy, se recomienda una secuencia de pasos para ajustar los **atributos de ensamblado** para la depuración, asegurando que se desactiven las optimizaciones que podrían dificultar la depuración. Este proceso incluye cambiar la configuración de `DebuggableAttribute`, recompilar el ensamblado y guardar los cambios.

Además, para depurar una aplicación .Net ejecutada por **IIS**, ejecutar `iisreset /noforce` reinicia IIS. Para adjuntar DNSpy al proceso de IIS para la depuración, la guía instruye seleccionar el proceso **w3wp.exe** dentro de DNSpy y comenzar la sesión de depuración.

Para obtener una vista completa de los módulos cargados durante la depuración, se aconseja acceder a la ventana de **Módulos** en DNSpy, seguido de abrir todos los módulos y ordenar los ensamblados para una navegación y depuración más sencillas.

Esta guía encapsula la esencia de la descompilación de WebAssembly y .Net, ofreciendo un camino para que los desarrolladores naveguen estas tareas con facilidad.

## **Descompilador de Java**
Para descompilar bytecode de Java, estas herramientas pueden ser muy útiles:
- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **Depuración de DLLs**
### Usando IDA
- **Rundll32** se carga desde rutas específicas para versiones de 64 bits y 32 bits.
- **Windbg** se selecciona como el depurador con la opción de suspender en la carga/descarga de bibliotecas habilitada.
- Los parámetros de ejecución incluyen la ruta de la DLL y el nombre de la función. Esta configuración detiene la ejecución en cada carga de DLL.

### Usando x64dbg/x32dbg
- Similar a IDA, **rundll32** se carga con modificaciones en la línea de comandos para especificar la DLL y la función.
- Se ajustan las configuraciones para detenerse en la entrada de la DLL, permitiendo establecer un punto de interrupción en el punto de entrada de la DLL deseado.

### Imágenes
- Se ilustran puntos de detención y configuraciones de ejecución a través de capturas de pantalla.

## **ARM & MIPS**
- Para emulación, [arm_now](https://github.com/nongiach/arm_now) es un recurso útil.

## **Shellcodes**
### Técnicas de Depuración
- **Blobrunner** y **jmp2it** son herramientas para asignar shellcodes en memoria y depurarlos con Ida o x64dbg.
- Blobrunner [versiones](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [versión compilada](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter** ofrece emulación e inspección de shellcodes basada en GUI, resaltando diferencias en el manejo de shellcodes como archivo versus shellcode directo.

### Deobfuscación y Análisis
- **scdbg** proporciona información sobre funciones de shellcode y capacidades de deobfuscación.
%%%bash
scdbg.exe -f shellcode # Información básica
scdbg.exe -f shellcode -r # Informe de análisis
scdbg.exe -f shellcode -i -r # Ganchos interactivos
scdbg.exe -f shellcode -d # Volcar shellcode decodificado
scdbg.exe -f shellcode /findsc # Encontrar desplazamiento de inicio
scdbg.exe -f shellcode /foff 0x0000004D # Ejecutar desde el desplazamiento
%%%

- **CyberChef** para desensamblar shellcode: [Receta de CyberChef](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**
- Un ofuscador que reemplaza todas las instrucciones con `mov`.
- Recursos útiles incluyen una [explicación en YouTube](https://www.youtube.com/watch?v=2VF_wPkiBJY) y [diapositivas en PDF](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf).
- **demovfuscator** podría revertir la ofuscación de movfuscator, requiriendo dependencias como `libcapstone-dev` y `libz3-dev`, e instalando [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md).

## **Delphi**
- Para binarios de Delphi, se recomienda [IDR](https://github.com/crypto2011/IDR).


# Cursos

* [https://github.com/0xZ0F/Z0FCourse\_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
* [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(Desofuscación binaria\)

</details>
