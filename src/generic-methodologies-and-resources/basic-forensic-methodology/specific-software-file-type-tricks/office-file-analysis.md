# Análisis de archivos Office

{{#include ../../../banners/hacktricks-training.md}}


Para más información, consulta [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Esto es solo un resumen:

Microsoft ha creado muchos formatos de documentos de Office, con dos tipos principales siendo **OLE formats** (como RTF, DOC, XLS, PPT) y **Office Open XML (OOXML) formats** (como DOCX, XLSX, PPTX). Estos formatos pueden incluir macros, lo que los convierte en objetivos de phishing y malware. Los archivos OOXML están estructurados como contenedores zip, lo que permite su inspección mediante descompresión, revelando la jerarquía de archivos y carpetas y el contenido de los archivos XML.

Para explorar la estructura de archivos OOXML, se muestra el comando para descomprimir un documento y la estructura de salida. Se han documentado técnicas para ocultar datos en estos archivos, lo que indica una innovación continua en el ocultamiento de datos dentro de los desafíos CTF.

Para el análisis, **oletools** y **OfficeDissector** ofrecen conjuntos de herramientas completos para examinar tanto documentos OLE como OOXML. Estas herramientas ayudan a identificar y analizar macros embebidos, que a menudo sirven como vectores para la entrega de malware, típicamente descargando y ejecutando cargas útiles maliciosas adicionales. El análisis de macros VBA se puede realizar sin Microsoft Office utilizando Libre Office, que permite depuración con breakpoints y watch variables.

La instalación y el uso de **oletools** son sencillos, con comandos proporcionados para instalar vía pip y extraer macros de documentos. La ejecución automática de macros se desencadena por funciones como `AutoOpen`, `AutoExec` o `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Explotación de OLE Compound File: Autodesk Revit RFA – Recomputación de ECC y gzip controlado

Revit RFA models are stored as an [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). The serialized model is under storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Estructura clave de `Global\Latest` (observado en Revit 2025):

- Header
- GZIP-compressed payload (the actual serialized object graph)
- Zero padding
- Tráiler de Error-Correcting Code (ECC)

Revit will auto-repair small perturbations to the stream using the ECC trailer and will reject streams that don’t match the ECC. Therefore, naïvely editing the compressed bytes won’t persist: your changes are either reverted or the file is rejected. To ensure byte-accurate control over what the deserializer sees you must:

- Recompress with a Revit-compatible gzip implementation (so the compressed bytes Revit produces/accepts match what it expects).
- Recompute the ECC trailer over the padded stream so Revit will accept the modified stream without auto-repairing it.

Practical workflow for patching/fuzzing RFA contents:

1) Expand the OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Edit Global\Latest with gzip/ECC discipline

- Desconstruir `Global/Latest`: conservar el encabezado, gunzip el payload, modificar bytes, luego gzip de nuevo usando parámetros deflate compatibles con Revit.
- Preservar el relleno de ceros y recalcular el trailer ECC para que los nuevos bytes sean aceptados por Revit.
- Si necesitas una reproducción determinista byte por byte, implementa un wrapper mínimo alrededor de las DLLs de Revit para invocar sus rutas gzip/gunzip y la computación ECC (como se demuestra en la investigación), o reutiliza cualquier helper disponible que replique estas semánticas.

3) Reconstruir el documento compuesto OLE
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notas:

- CompoundFileTool escribe storages/streams en el filesystem escapando caracteres inválidos para nombres NTFS; la ruta del stream que necesitas es exactamente `Global/Latest` en el árbol de salida.
- Al entregar ataques masivos mediante plugins del ecosistema que obtienen RFAs desde almacenamiento en la nube, asegúrate de que tu RFA parcheado pase las comprobaciones de integridad de Revit localmente primero (gzip/ECC correctos) antes de intentar network injection.

Información de explotación (para guiar qué bytes colocar en la gzip payload):

- El Revit deserializer lee un 16-bit class index y construye un objeto. Ciertos tipos son non‑polymorphic y carecen de vtables; abusar del manejo del destructor provoca un type confusion donde el engine ejecuta una llamada indirecta a través de un attacker-controlled pointer.
- Seleccionar `AString` (class index `0x1F`) coloca un attacker-controlled heap pointer en el object offset 0. Durante el destructor loop, Revit efectivamente ejecuta:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Coloca múltiples objetos de este tipo en el serialized graph para que cada iteración del destructor loop ejecute un gadget (“weird machine”), y organiza un stack pivot hacia una convencional x64 ROP chain.

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Tooling:

- CompoundFileTool (OSS) para expandir/reconstruir OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD para reverse/taint; desactiva page heap con TTD para mantener los trazos compactos.
- Un proxy local (p. ej., Fiddler) puede simular supply-chain delivery intercambiando RFAs en el tráfico del plugin para pruebas.

## References

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
