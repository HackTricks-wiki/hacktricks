# Análisis de archivos de Office

{{#include ../../../banners/hacktricks-training.md}}


Para obtener más información, consulta [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Esto es solo un resumen:<sup>[[4]](#references)</sup>

Microsoft ha creado muchos formatos de documentos de Office, siendo los dos tipos principales los formatos **OLE** (como RTF, DOC, XLS y PPT) y los formatos **Office Open XML (OOXML)** (como DOCX, XLSX y PPTX). Estos formatos pueden incluir macros, lo que los convierte en objetivos para el phishing y el malware. Los archivos OOXML están estructurados como contenedores zip, lo que permite inspeccionarlos mediante su descompresión y revelar la jerarquía de archivos y carpetas, así como el contenido de los archivos XML.

Para explorar las estructuras de los archivos OOXML, se proporcionan el comando para descomprimir un documento y la estructura de salida. Se han documentado técnicas para ocultar datos en estos archivos, lo que indica una innovación continua en el ocultamiento de datos dentro de los desafíos CTF.

Para el análisis, **oletools** y **OfficeDissector** ofrecen conjuntos completos de herramientas para examinar documentos OLE y OOXML. Estas herramientas ayudan a identificar y analizar macros incrustadas, que suelen servir como vectores para la distribución de malware, normalmente descargando y ejecutando payloads maliciosos adicionales. El análisis de macros VBA puede realizarse sin Microsoft Office utilizando Libre Office, que permite depurar con puntos de interrupción y variables observadas.

La instalación y el uso de **oletools** son sencillos, y se proporcionan comandos para instalarlo mediante pip y extraer macros de documentos. La ejecución automática de macros se activa mediante funciones como `AutoOpen`, `AutoExec` o `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Explotación de archivos Compound OLE: Autodesk Revit RFA – recomputación de ECC y gzip controlado

Los modelos RFA de Revit se almacenan como un [archivo Compound OLE](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (también conocido como CFBF). El modelo serializado se encuentra en storage/stream:<sup>[[1]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Estructura clave de `Global\Latest` (observada en Revit 2025):

- Cabecera
- Payload comprimido con GZIP (el grafo de objetos serializado real)
- Relleno de ceros
- Tráiler de Error-Correcting Code (ECC)

Revit reparará automáticamente pequeñas alteraciones en el stream usando el tráiler ECC y rechazará los streams que no coincidan con el ECC. Por lo tanto, editar ingenuamente los bytes comprimidos no persistirá: los cambios se revierten o el archivo es rechazado. Para garantizar un control byte a byte sobre lo que ve el deserializador debes:

- Volver a comprimir con una implementación de gzip compatible con Revit (para que los bytes comprimidos que Revit produce/acepta coincidan con lo esperado).
- Volver a calcular el tráiler ECC sobre el stream con padding para que Revit acepte el stream modificado sin repararlo automáticamente.

Flujo de trabajo práctico para parchear/hacer fuzzing de contenidos RFA:<sup>[[1]](#references)</sup>

1) Expande el documento Compound OLE
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Editar `Global\Latest` con disciplina de gzip/ECC

- Deconstruye `Global/Latest`: conserva el encabezado, descomprime el payload con gunzip, modifica los bytes y vuelve a comprimirlo con gzip usando parámetros de deflate compatibles con Revit.
- Conserva el zero-padding y vuelve a calcular el tráiler ECC para que Revit acepte los nuevos bytes.
- Si necesitas una reproducción determinista byte por byte, crea un wrapper mínimo alrededor de las DLL de Revit para invocar sus rutas de gzip/gunzip y el cálculo ECC (como se demuestra en la investigación), o reutiliza cualquier helper disponible que replique estas semánticas.

3) Reconstruir el documento compuesto OLE
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notas:<sup>[[1]](#references)</sup>

- CompoundFileTool escribe storages/streams en el sistema de archivos, usando escaping para los caracteres no válidos en nombres de NTFS; la ruta del stream que buscas es exactamente `Global/Latest` en el árbol de salida.
- Al distribuir ataques masivos mediante plugins del ecosistema que obtienen RFAs desde almacenamiento en la nube, asegúrate primero de que tu RFA parcheado supera localmente las comprobaciones de integridad de Revit (gzip/ECC correctos) antes de intentar la inyección a través de la red.

Perspectiva de explotación (para orientar qué bytes colocar en el payload gzip):<sup>[[1]](#references)</sup>

- El deserializador de Revit lee un índice de clase de 16 bits y construye un objeto. Ciertos tipos no son polimórficos y carecen de vtables; abusar del manejo del destructor provoca una type confusion en la que el motor ejecuta una llamada indirecta mediante un puntero controlado por el atacante.
- Elegir `AString` (índice de clase `0x1F`) coloca un puntero de heap controlado por el atacante en el offset 0 del objeto. Durante el bucle del destructor, Revit ejecuta efectivamente:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Coloca varios objetos de este tipo en el grafo serializado para que cada iteración del bucle del destructor ejecute un gadget (“weird machine”) y prepara un stack pivot hacia una cadena ROP x64 convencional.

Consulta aquí los detalles sobre pivots/gadgets para Windows x64:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

y aquí la guía general sobre ROP:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Herramientas:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) para expandir y reconstruir archivos compound OLE: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD para reverse/taint; desactiva page heap con TTD para mantener las trazas compactas.
- Un proxy local (por ejemplo, Fiddler) puede simular la entrega mediante la cadena de suministro sustituyendo las RFA en el tráfico del plugin para realizar pruebas.

## Referencias

- [1] [Creación de un exploit RCE completo a partir de un crash en el análisis de archivos RFA de Autodesk Revit (blog de ZDI)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Documentación de archivos compound OLE (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Guía de campo de Forensics CTF](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
