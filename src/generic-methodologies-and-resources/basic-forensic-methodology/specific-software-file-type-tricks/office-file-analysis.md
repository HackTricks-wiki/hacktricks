# Análisis de archivos de Office

Para obtener más información, consulta [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Esto es solo un resumen:<sup>[[4]](#references)</sup>

Los documentos de Microsoft Office suelen aparecer como formatos antiguos, como RTF y DOC, XLS y PPT basados en OLE/CFBF, o como formatos más recientes **Office Open XML (OOXML)**, como DOCX, XLSX y PPTX. Los documentos de Office pueden contener active content, como macros, lo que los convierte en vectores comunes de phishing y malware. Los archivos OOXML son contenedores ZIP cuya jerarquía de archivos y contenido XML se pueden inspeccionar descomprimiéndolos.<sup>[[3]](#references)[[4]](#references)</sup>

Para explorar las estructuras de archivos OOXML, se proporcionan el comando para descomprimir un documento y la estructura de salida. Se han documentado técnicas para ocultar datos en estos archivos, lo que indica una innovación continua en la ocultación de datos dentro de los desafíos CTF.<sup>[[4]](#references)</sup>

Para el análisis, **oletools** y **OfficeDissector** ofrecen conjuntos de herramientas completos para examinar documentos OLE y OOXML. Estas herramientas ayudan a identificar y analizar macros integradas, que suelen servir como vectores para la distribución de malware, normalmente descargando y ejecutando payloads maliciosos adicionales. El análisis de macros VBA se puede realizar sin Microsoft Office utilizando Libre Office, que permite depurar con breakpoints y watch variables.<sup>[[4]](#references)</sup>

La instalación y el uso de **oletools** son sencillos, y se proporcionan comandos para instalarlo mediante pip y extraer macros de documentos. En Word, las macros automáticas incluyen `AutoExec` y `AutoOpen`, mientras que `Document_Open` es un procedimiento de evento de apertura.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Explotación de OLE Compound File: Autodesk Revit RFA – recomputación de ECC y gzip controlado

Los modelos RFA de Revit se almacenan como un [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (también conocido como CFBF). El modelo serializado se encuentra en storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Estructura principal de `Global\Latest` (observada en Revit 2025):

- Header
- Payload comprimido con GZIP (el grafo de objetos serializado real)
- Relleno de ceros
- Trailer de código de corrección de errores (ECC)

Revit reparará automáticamente pequeñas perturbaciones del stream utilizando el trailer ECC y rechazará los streams que no coincidan con el ECC. Por lo tanto, editar ingenuamente los bytes comprimidos no será persistente: los cambios se revierten o el archivo es rechazado. Para garantizar un control preciso a nivel de byte sobre lo que ve el deserializador debes:<sup>[[1]](#references)</sup>

- Recomprimir con una implementación de gzip compatible con Revit (para que los bytes comprimidos que Revit produzca/acepte coincidan con lo que espera).
- Recalcular el trailer ECC sobre el stream con padding para que Revit acepte el stream modificado sin repararlo automáticamente.

Flujo de trabajo práctico para patching/fuzzing de contenidos RFA:<sup>[[1]](#references)</sup>

1) Expandir el documento OLE compound.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Edita `Global/Latest` con disciplina de gzip/ECC

- Descompón `Global/Latest`: conserva el encabezado, descomprime el payload con gunzip, modifica los bytes y vuelve a comprimirlo con gzip usando parámetros deflate compatibles con Revit.
- Conserva el zero-padding y vuelve a calcular el tráiler ECC para que Revit acepte los nuevos bytes.
- Si necesitas una reproducción determinista byte por byte, crea un wrapper mínimo alrededor de las DLL de Revit para invocar sus rutas de gzip/gunzip y el cálculo de ECC (como se demuestra en la investigación), o reutiliza cualquier helper disponible que replique esta semántica.

3) Reconstruye el documento compuesto OLE.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notas:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool escribe storages/streams en el sistema de archivos aplicando escape a los caracteres no válidos en nombres de NTFS; la ruta del stream que buscas es exactamente `Global/Latest` en el árbol de salida.
- Al realizar ataques masivos mediante plugins del ecosistema que obtienen RFAs desde cloud storage, asegúrate primero de que tu RFA parcheado supera localmente las comprobaciones de integridad de Revit (gzip/ECC correctos) antes de intentar la inyección por red.

Información sobre la explotación (para orientar qué bytes colocar en el payload gzip):<sup>[[1]](#references)</sup>

- El deserializador de Revit lee un índice de clase de 16 bits y construye un objeto. Ciertos tipos no son polimórficos y carecen de vtables; abusar del manejo del destructor provoca una confusión de tipos en la que el engine ejecuta una llamada indirecta a través de un puntero controlado por el atacante.
- Elegir `AString` (índice de clase `0x1F`) coloca un puntero de heap controlado por el atacante en el offset 0 del objeto. Durante el bucle del destructor, Revit ejecuta efectivamente:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Coloca varios objetos de este tipo en el grafo serializado para que cada iteración del bucle del destructor ejecute un gadget (“weird machine”) y prepara un stack pivot hacia una cadena ROP x64 convencional.

Consulta aquí los detalles sobre pivots/gadgets de Windows x64:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

y aquí la guía general sobre ROP:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Herramientas:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) para expandir/reconstruir archivos compound OLE: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD para reverse engineering/taint; desactiva page heap con TTD para mantener las trazas compactas.
- Un proxy local (p. ej., Fiddler) puede simular la entrega de supply-chain intercambiando RFAs en el tráfico del plugin para realizar pruebas.

## References

- [1] [Creación de un exploit RCE completo a partir de un crash en el análisis de archivos RFA de Autodesk Revit (blog de ZDI)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Documentación de OLE Compound File (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Guía de campo de CTF forense](https://trailofbits.github.io/ctf/forensics/)
- [5] [Documentación de olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Macros automáticas (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Evento Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
