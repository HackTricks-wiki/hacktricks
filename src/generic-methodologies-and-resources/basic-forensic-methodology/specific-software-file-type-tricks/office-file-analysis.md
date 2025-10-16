# Análisis de archivos Office

{{#include ../../../banners/hacktricks-training.md}}


Para más información revisa [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Esto es solo un resumen:

Microsoft ha creado muchos formatos de documentos Office, con dos tipos principales siendo **OLE formats** (como RTF, DOC, XLS, PPT) y **Office Open XML (OOXML) formats** (tales como DOCX, XLSX, PPTX). Estos formatos pueden incluir macros, lo que los convierte en objetivos para phishing y malware. Los archivos OOXML están estructurados como contenedores zip, lo que permite inspeccionarlos descomprimiéndolos, revelando la jerarquía de archivos y carpetas y el contenido de los archivos XML.

Para explorar las estructuras de archivos OOXML, se proporciona el comando para descomprimir un documento y la estructura de salida. Se han documentado técnicas para ocultar datos en estos archivos, lo que indica una innovación continua en el ocultamiento de datos dentro de desafíos CTF.

Para el análisis, **oletools** y **OfficeDissector** ofrecen conjuntos de herramientas completos para examinar tanto documentos OLE como OOXML. Estas herramientas ayudan a identificar y analizar macros embebidas, que a menudo sirven como vectores para la entrega de malware, típicamente descargando y ejecutando cargas útiles adicionales maliciosas. El análisis de macros VBA puede realizarse sin Microsoft Office utilizando Libre Office, que permite depuración con breakpoints y watch variables.

La instalación y uso de **oletools** es sencillo, con comandos provistos para instalar vía pip y extraer macros de documentos. La ejecución automática de macros es activada por funciones como `AutoOpen`, `AutoExec`, o `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Explotación de OLE Compound File: Autodesk Revit RFA – recomputación de ECC y gzip controlado

Los modelos Revit RFA se almacenan como un [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). El modelo serializado está bajo storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Estructura clave de `Global\Latest` (observado en Revit 2025):

- Encabezado
- Carga comprimida con GZIP (el grafo de objetos serializado real)
- Relleno de ceros
- Tráiler de Código Corrector de Errores (ECC)

Revit reparará automáticamente pequeñas perturbaciones en el stream usando el tráiler ECC y rechazará streams que no coincidan con el ECC. Por lo tanto, editar ingenuamente los bytes comprimidos no persistirá: tus cambios o bien son revertidos o el archivo es rechazado. Para asegurar control byte-preciso sobre lo que ve el deserializador debes:

- Recomprimir con una implementación de gzip compatible con Revit (para que los bytes comprimidos que Revit produce/acepta coincidan con lo que espera).
- Recalcular el tráiler ECC sobre el stream con relleno para que Revit acepte el stream modificado sin autocorregirlo.

Flujo de trabajo práctico para patching/fuzzing del contenido RFA:

1) Expandir el documento compuesto OLE
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Edit Global\Latest with gzip/ECC discipline

- Descompón `Global/Latest`: conserva la cabecera, gunzip el payload, modifica los bytes y luego vuelve a gzip usando parámetros de deflate compatibles con Revit.
- Conserva el zero-padding y recalcula el trailer ECC para que los nuevos bytes sean aceptados por Revit.
- Si necesitas reproducción determinista byte-for-byte, construye un wrapper mínimo alrededor de las DLLs de Revit para invocar sus rutas de gzip/gunzip y la computación de ECC (como se demuestra en la investigación), o reutiliza cualquier helper disponible que replique estas semánticas.

3) Reconstruir el documento compuesto OLE
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notas:

- CompoundFileTool escribe storages/streams en el sistema de archivos con escaping para caracteres inválidos en nombres NTFS; la ruta del stream que quieres es exactamente `Global/Latest` en el árbol de salida.
- Al entregar ataques masivos vía plugins del ecosistema que obtienen RFAs desde cloud storage, asegúrate de que tu RFA parcheado pase las integrity checks de Revit localmente primero (gzip/ECC correct) antes de intentar la network injection.

Exploitation insight (to guide what bytes to place in the gzip payload):

- El deserializador de Revit lee un class index de 16 bits y construye un objeto. Ciertos tipos son non‑polymorphic y carecen de vtables; abusar del manejo de destructores produce una type confusion donde el engine ejecuta una indirect call a través de un attacker-controlled pointer.
- Elegir `AString` (class index `0x1F`) coloca un attacker-controlled heap pointer en el object offset 0. Durante el destructor loop, Revit efectivamente ejecuta:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Coloca múltiples objetos de este tipo en el grafo serializado para que cada iteración del bucle del destructor ejecute un gadget (“weird machine”), y organiza un stack pivot hacia una cadena ROP x64 convencional.

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Tooling:

- CompoundFileTool (OSS) para expandir/reconstruir archivos compuestos OLE: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD para reverse/taint; desactiva page heap con TTD para mantener las trazas compactas.
- Un proxy local (p. ej., Fiddler) puede simular la entrega supply-chain intercambiando RFAs en el tráfico del plugin para pruebas.

## References

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
