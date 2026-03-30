# Análisis de archivos Office

{{#include ../../../banners/hacktricks-training.md}}


Para más información consulta [https://trailofbits.github.io/ctf/forensics/]. Esto es solo un resumen:

Microsoft ha creado muchos formatos de documentos Office, con dos tipos principales: **OLE formats** (como RTF, DOC, XLS, PPT) y **Office Open XML (OOXML) formats** (por ejemplo DOCX, XLSX, PPTX). Estos formatos pueden incluir macros, por lo que son objetivos comunes de phishing y malware. Los archivos OOXML están estructurados como contenedores zip, lo que permite inspeccionarlos descomprimiéndolos y ver la jerarquía de archivos y carpetas y el contenido de los archivos XML.

Para explorar la estructura de archivos OOXML, se muestra el comando para descomprimir un documento y la estructura de salida. Se han documentado técnicas para ocultar datos en estos archivos, lo que indica una continua innovación en el ocultamiento de información en retos CTF.

Para el análisis, **oletools** y **OfficeDissector** ofrecen conjuntos de herramientas completos para examinar tanto documentos OLE como OOXML. Estas herramientas ayudan a identificar y analizar macros incrustadas, que a menudo sirven como vectores para la entrega de malware, normalmente descargando y ejecutando payloads maliciosos adicionales. El análisis de macros VBA se puede realizar sin Microsoft Office usando Libre Office, que permite depuración con breakpoints y watch variables.

La instalación y el uso de **oletools** son sencillos, con comandos para instalar vía pip y extraer macros de documentos. La ejecución automática de macros se activa mediante funciones como `AutoOpen`, `AutoExec` o `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA models are stored as an [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). The serialized model is under storage/stream:

- Almacenamiento: `Global`
- Stream: `Latest` → `Global\Latest`

Estructura clave de `Global\Latest` (observada en Revit 2025):

- Header
- GZIP-compressed payload (el grafo de objetos serializados real)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit autorepara pequeñas perturbaciones en el stream usando el trailer ECC y rechazará streams que no coincidan con el ECC. Por lo tanto, editar ingenuamente los bytes comprimidos no persistirá: tus cambios o bien se revierten o bien el archivo es rechazado. Para asegurar control byte-por-byte sobre lo que ve el deserializador debes:

- Recomprimir con una implementación de gzip compatible con Revit (para que los bytes comprimidos que Revit produce/acepta coincidan con lo que espera).
- Recalcular el trailer ECC sobre el stream rellenado para que Revit acepte el stream modificado sin autorepararlo.

Flujo de trabajo práctico para patching/fuzzing de contenidos RFA:

1) Expandir el documento compuesto OLE
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Edita `Global/Latest` con disciplina gzip/ECC

- Deconstruye `Global/Latest`: conserva el header, gunzip el payload, muta bytes, y luego gzip de nuevo usando parámetros deflate compatibles con Revit.
- Conserva el zero-padding y recomputa el ECC trailer para que los nuevos bytes sean aceptados por Revit.
- Si necesitas reproducción determinista byte-for-byte, construye un wrapper minimal alrededor de las DLLs de Revit para invocar sus rutas de gzip/gunzip y la computación de ECC (como se demuestra en la research), o reutiliza cualquier helper disponible que replique estas semánticas.

3) Reconstruir el documento compuesto OLE
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notas:

- CompoundFileTool escribe storages/streams en el sistema de archivos escapando caracteres inválidos para nombres NTFS; la ruta de stream que buscas es exactamente `Global/Latest` en el árbol de salida.
- Al entregar ataques masivos vía plugins del ecosistema que obtienen RFAs desde almacenamiento en la nube, asegúrate de que tu RFA parcheado pase las comprobaciones de integridad de Revit localmente primero (gzip/ECC correcto) antes de intentar la inyección por red.

Exploitation insight (to guide what bytes to place in the gzip payload):

- El deserializador de Revit lee un índice de clase de 16 bits y construye un objeto. Ciertos tipos son no‑polimórficos y carecen de vtables; abusar del manejo de destructores produce una type confusion donde el engine ejecuta una llamada indirecta a través de un puntero controlado por el atacante.
- Elegir `AString` (class index `0x1F`) coloca un puntero del heap controlado por el atacante en el offset 0 del objeto. Durante el bucle de destructores, Revit efectivamente ejecuta:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Coloca múltiples objetos de este tipo en el grafo serializado para que cada iteración del bucle destructor ejecute un gadget (“weird machine”), y organiza un stack pivot hacia una cadena ROP x64 convencional.

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Tooling:

- CompoundFileTool (OSS) para expandir/reconstruir OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD para reverse/taint; deshabilita page heap con TTD para mantener los trazos compactos.
- Un proxy local (p. ej., Fiddler) puede simular la entrega por cadena de suministro (supply-chain) intercambiando RFAs en el tráfico del plugin para pruebas.

## Referencias

- [Creación de un exploit RCE completo a partir de un crash en el procesamiento de archivos RFA de Autodesk Revit (blog ZDI)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [Documentación de OLE Compound File (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
