# Análisis de archivos de Office

{{#include ../../../banners/hacktricks-training.md}}


Para obtener más información, consulta [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Esto es solo un resumen:<sup>[[4]](#references)</sup>

Microsoft ha creado muchos formatos de documentos de Office, cuyos dos tipos principales son los formatos **OLE** (como RTF, DOC, XLS, PPT) y los formatos **Office Open XML (OOXML)** (como DOCX, XLSX, PPTX). Estos formatos pueden incluir macros, lo que los convierte en objetivos para phishing y malware. Los archivos OOXML están estructurados como contenedores zip, lo que permite inspeccionarlos mediante la descompresión y revelar la jerarquía de archivos y carpetas, así como el contenido de los archivos XML.

Para explorar las estructuras de archivos OOXML, se proporcionan el comando para descomprimir un documento y la estructura de salida. Se han documentado técnicas para ocultar datos en estos archivos, lo que indica una innovación continua en el ocultamiento de datos dentro de los desafíos CTF.

Para el análisis, **oletools** y **OfficeDissector** ofrecen conjuntos de herramientas completos para examinar documentos OLE y OOXML. Estas herramientas ayudan a identificar y analizar macros incrustadas, que a menudo sirven como vectores para la distribución de malware y normalmente descargan y ejecutan payloads maliciosos adicionales. El análisis de macros VBA puede realizarse sin Microsoft Office utilizando Libre Office, que permite depurar con breakpoints y observar variables.

La instalación y el uso de **oletools** son sencillos, y se proporcionan comandos para instalarlo mediante pip y extraer macros de documentos. La ejecución automática de macros se activa mediante funciones como `AutoOpen`, `AutoExec` o `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Explotación de archivos compuestos OLE: Autodesk Revit RFA – recomputación de ECC y gzip controlado

Los modelos RFA de Revit se almacenan como un [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (también conocido como CFBF). El modelo serializado se encuentra en storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Estructura clave de `Global\Latest` (observada en Revit 2025):

- Cabecera
- Payload comprimido con GZIP (el grafo de objetos serializado real)
- Relleno de ceros
- Trailer de Error-Correcting Code (ECC)

Revit repara automáticamente pequeñas perturbaciones en el stream utilizando el trailer ECC y rechaza los streams que no coinciden con el ECC. Por lo tanto, editar ingenuamente los bytes comprimidos no persistirá: los cambios se revierten o el archivo se rechaza. Para garantizar un control preciso a nivel de byte sobre lo que ve el deserializador debes:

- Volver a comprimir con una implementación de gzip compatible con Revit (para que los bytes comprimidos que Revit produce/acepta coincidan con lo que espera).
- Recalcular el trailer ECC sobre el stream con padding para que Revit acepte el stream modificado sin repararlo automáticamente.

Flujo de trabajo práctico para parchear/hacer fuzzing de contenidos RFA:<sup>[[1]](#references)</sup>

1) Expandir el documento compuesto OLE
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Editar `Global\Latest` con disciplina de gzip/ECC

- Desconstruir `Global/Latest`: conservar el encabezado, descomprimir el payload con gunzip, modificar los bytes y volver a comprimir con gzip usando parámetros de deflate compatibles con Revit.
- Conservar el relleno de ceros y recalcular el tráiler ECC para que Revit acepte los nuevos bytes.
- Si necesitas una reproducción determinista byte por byte, crea un wrapper mínimo alrededor de las DLL de Revit para invocar sus rutas de gzip/gunzip y el cálculo ECC (como se demuestra en la investigación), o reutiliza cualquier helper disponible que replique estas semánticas.

3) Reconstruir el documento compuesto OLE
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)</sup>

- CompoundFileTool escribe storages/streams en el sistema de archivos, aplicando escaping a los caracteres no válidos en nombres de NTFS; la ruta del stream que quieres es exactamente `Global/Latest` en el árbol de salida.
- Al realizar mass attacks mediante plugins del ecosistema que obtienen RFAs desde cloud storage, asegúrate de que tu RFA parcheado supere primero localmente las comprobaciones de integridad de Revit (gzip/ECC correctos) antes de intentar la inyección por red.

Exploitation insight (para indicar qué bytes colocar en el payload gzip):<sup>[[1]](#references)</sup>

- El deserializador de Revit lee un índice de clase de 16 bits y construye un objeto. Ciertos tipos no son polimórficos y carecen de vtables; abusar del manejo del destructor provoca una type confusion en la que el motor ejecuta una indirect call a través de un puntero controlado por el atacante.
- Elegir `AString` (índice de clase `0x1F`) coloca un puntero de heap controlado por el atacante en el offset 0 del objeto. Durante el bucle del destructor, Revit ejecuta efectivamente:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Coloca varios objetos de este tipo en el grafo serializado para que cada iteración del bucle del destructor ejecute un gadget (“weird machine”) y prepara un stack pivot hacia una cadena ROP x64 convencional.

Consulta aquí los detalles sobre pivots/gadgets x64 de Windows:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

y aquí una guía general sobre ROP:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Herramientas:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) para expandir/reconstruir archivos compound OLE: https://github.com/thezdi/CompoundFileTool<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD para reverse/taint; desactiva page heap con TTD para mantener los traces compactos.
- Un proxy local (p. ej., Fiddler) puede simular la entrega de supply-chain sustituyendo RFAs en el tráfico del plugin durante las pruebas.

## Referencias

- [1] [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
