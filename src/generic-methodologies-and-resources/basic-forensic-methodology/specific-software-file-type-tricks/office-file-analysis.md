# Análisis de archivos de Office

{{#include ../../../banners/hacktricks-training.md}}

Para más información, consulta [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Esto es solo un resumen:<sup>[[4]](#references)</sup>

Los documentos de Microsoft Office suelen aparecer en formatos antiguos, como RTF y DOC, XLS y PPT basados en OLE/CFBF, o en formatos más nuevos de **Office Open XML (OOXML)**, como DOCX, XLSX y PPTX. Los documentos de Office pueden contener contenido activo, como macros, lo que los convierte en vectores habituales de phishing y malware. Los archivos OOXML son contenedores ZIP cuyo contenido XML y jerarquía de archivos se pueden inspeccionar descomprimiéndolos.<sup>[[3]](#references)[[4]](#references)</sup>

Se muestran el comando para descomprimir un documento y la estructura resultante, con el fin de explorar la estructura de los archivos OOXML. Se han documentado técnicas para ocultar datos en estos archivos, lo que demuestra que la ocultación de datos sigue evolucionando en los retos CTF.<sup>[[4]](#references)</sup>

Para el análisis, **oletools** y **OfficeDissector** ofrecen conjuntos completos de herramientas para examinar documentos OLE y OOXML. Estas herramientas ayudan a identificar y analizar macros incrustadas, que a menudo sirven como vectores para distribuir malware y suelen descargar y ejecutar cargas maliciosas adicionales. El análisis de macros VBA puede realizarse sin Microsoft Office mediante LibreOffice, que permite depurar con puntos de interrupción y variables de inspección.<sup>[[4]](#references)</sup>

La instalación y el uso de **oletools** son sencillos; se proporcionan comandos para instalarlo con pip y extraer macros de documentos. En Word, las macros automáticas incluyen `AutoExec` y `AutoOpen`, mientras que `Document_Open` es un procedimiento que se ejecuta al abrir el documento.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

Para documentos de Office cifrados con contraseña, consulta el [flujo de trabajo de recuperación offline basado en gramáticas](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

## Explotación de OLE Compound File: Autodesk Revit RFA: recálculo de ECC y gzip controlado

Los modelos Revit RFA se almacenan como [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (también conocido como CFBF). El modelo serializado está en el almacenamiento/flujo:<sup>[[1]](#references)[[3]](#references)</sup>

- Almacenamiento: `Global`
- Flujo: `Latest` → `Global\Latest`

Estructura clave de `Global\Latest` (observada en Revit 2025):

- Encabezado
- Contenido comprimido con GZIP (el grafo de objetos serializado real)
- Relleno de ceros
- Tráiler de código de corrección de errores (ECC)

Revit reparará automáticamente pequeñas alteraciones del flujo mediante el tráiler ECC y rechazará los flujos que no coincidan con el ECC. Por lo tanto, editar los bytes comprimidos sin más no conservará los cambios: se revertirán o se rechazará el archivo. Para controlar con precisión los bytes que recibe el deserializador, debes:<sup>[[1]](#references)</sup>

- Volver a comprimir con una implementación de gzip compatible con Revit (para que los bytes comprimidos que Revit genere o acepte coincidan con lo que espera).
- Recalcular el tráiler ECC sobre el flujo rellenado para que Revit acepte el flujo modificado sin repararlo automáticamente.

Flujo de trabajo práctico para modificar o fuzzear contenidos RFA:<sup>[[1]](#references)</sup>

1) Expandir el documento OLE compound.<sup>[[2]](#references)</sup>

```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```

2) Edita `Global\Latest` con disciplina de gzip/ECC

- Descompón `Global/Latest`: conserva el encabezado, descomprime el payload con gunzip, modifica los bytes y vuelve a comprimirlo con gzip usando parámetros deflate compatibles con Revit.
- Conserva el relleno con ceros y vuelve a calcular el tráiler ECC para que Revit acepte los nuevos bytes.
- Si necesitas una reproducción determinista byte por byte, crea un wrapper mínimo alrededor de las DLL de Revit para invocar sus rutas gzip/gunzip y el cálculo ECC (como se muestra en la investigación), o reutiliza cualquier helper disponible que replique esta semántica.

3) Reconstruye el documento compuesto OLE.<sup>[[2]](#references)</sup>

```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```

Notas:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool escribe storages/streams en el sistema de archivos y escapa los caracteres no válidos en los nombres de NTFS; la ruta del stream que buscas es exactamente `Global/Latest` en el árbol de salida.
- Al distribuir ataques a gran escala mediante plugins del ecosistema que obtienen RFAs de almacenamiento en la nube, asegúrate de que tu RFA parcheado supere primero las comprobaciones de integridad de Revit localmente (gzip/ECC correctos) antes de intentar una inyección de red.

Información sobre la explotación (para orientar qué bytes colocar en el payload gzip):<sup>[[1]](#references)</sup>

- El deserializador de Revit lee un índice de clase de 16 bits y construye un objeto. Algunos tipos no son polimórficos y carecen de vtables; abusar del manejo del destructor genera un type confusion en el que el motor ejecuta una llamada indirecta a través de un puntero controlado por el atacante.
- Elegir `AString` (índice de clase `0x1F`) coloca un puntero al heap controlado por el atacante en el offset 0 del objeto. Durante el bucle del destructor, Revit ejecuta, en la práctica:

```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```

- Coloca varios objetos de este tipo en el grafo serializado para que cada iteración del bucle del destructor ejecute un gadget («weird machine») y organiza un pivote de pila hacia una cadena ROP x64 convencional.

Consulta aquí los detalles sobre pivotes y construcción de gadgets para Windows x64:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

y aquí una guía general sobre ROP:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Herramientas:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) para expandir y reconstruir archivos compuestos OLE: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD para ingeniería inversa y análisis de taint; desactiva el page heap con TTD para mantener las trazas compactas.
- Un proxy local (p. ej., Fiddler) puede simular la entrega de la cadena de suministro sustituyendo archivos RFA en el tráfico del plugin para realizar pruebas.

## References

- [1] [Cómo crear un exploit RCE completo a partir de un crash al analizar archivos RFA de Autodesk Revit (blog de ZDI)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Documentación sobre archivos compuestos OLE (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Guía de campo de CTF de forense](https://trailofbits.github.io/ctf/forensics/)
- [5] [Documentación de olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Macros automáticas (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Evento Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
