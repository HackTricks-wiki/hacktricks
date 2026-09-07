# Análisis de archivos de Office

{{#include ../../../banners/hacktricks-training.md}}

Para más información, consulta [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Esto es solo un resumen:<sup>[[4]](#references)</sup>

Los documentos de Microsoft Office suelen aparecer como formatos antiguos, como RTF y DOC, XLS y PPT basados en OLE/CFBF, o como formatos más recientes de **Office Open XML (OOXML)**, como DOCX, XLSX y PPTX. Los documentos de Office pueden contener contenido activo, como macros, lo que los convierte en vectores comunes de phishing y malware. Los archivos OOXML son contenedores ZIP cuya jerarquía de archivos y contenido XML pueden inspeccionarse descomprimiéndolos.<sup>[[3]](#references)[[4]](#references)</sup>

Para explorar las estructuras de archivos OOXML, se proporciona el comando para descomprimir un documento y la estructura de salida. Se han documentado técnicas para ocultar datos en estos archivos, lo que indica una innovación continua en el ocultamiento de datos dentro de los desafíos CTF.<sup>[[4]](#references)</sup>

Para el análisis, **oletools** y **OfficeDissector** ofrecen conjuntos completos de herramientas para examinar documentos OLE y OOXML. Estas herramientas ayudan a identificar y analizar macros incrustadas, que suelen servir como vectores para la entrega de malware y normalmente descargan y ejecutan payloads maliciosos adicionales. El análisis de macros VBA puede realizarse sin Microsoft Office utilizando Libre Office, que permite depurar con puntos de interrupción y variables observadas.<sup>[[4]](#references)</sup>

La instalación y el uso de **oletools** son sencillos, y se proporcionan comandos para instalarlo mediante pip y extraer macros de documentos. En Word, las macros automáticas incluyen `AutoExec` y `AutoOpen`, mientras que `Document_Open` es un procedimiento de evento de apertura.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
For password-encrypted Office documents, see the [grammar-driven offline recovery workflow](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA models are stored as an [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). The serialized model is under storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Key layout of `Global\Latest` (observed on Revit 2025):

- Header
- GZIP-compressed payload (the actual serialized object graph)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit will auto-repair small perturbations to the stream using the ECC trailer and will reject streams that don’t match the ECC. Therefore, naïvely editing the compressed bytes won’t persist: your changes are either reverted or the file is rejected. To ensure byte-accurate control over what the deserializer sees you must:<sup>[[1]](#references)</sup>

- Recompress with a Revit-compatible gzip implementation (so the compressed bytes Revit produces/accepts match what it expects).
- Recompute the ECC trailer over the padded stream so Revit will accept the modified stream without auto-repairing it.

Practical workflow for patching/fuzzing RFA contents:<sup>[[1]](#references)</sup>

1) Expand the OLE compound document.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Editar `Global\Latest` con disciplina de gzip/ECC

- Deconstruye `Global/Latest`: conserva el encabezado, haz gunzip del payload, modifica los bytes y vuelve a hacer gzip usando parámetros deflate compatibles con Revit.
- Conserva el zero-padding y vuelve a calcular el tráiler ECC para que Revit acepte los nuevos bytes.
- Si necesitas una reproducción determinista byte por byte, crea un wrapper mínimo alrededor de las DLL de Revit para invocar sus rutas de gzip/gunzip y el cálculo ECC (como se demuestra en la investigación), o reutiliza cualquier helper disponible que replique esta semántica.

3) Reconstruir el documento compuesto OLE.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool escribe storages/streams en el sistema de archivos aplicando escaping a los caracteres no válidos en nombres de NTFS; la ruta del stream que necesitas es exactamente `Global/Latest` en el árbol de salida.
- Al realizar mass attacks mediante plugins del ecosistema que obtienen RFAs desde cloud storage, asegúrate primero de que tu RFA parcheado supera localmente las comprobaciones de integridad de Revit (gzip/ECC correctos) antes de intentar la network injection.

Exploitation insight (para orientar qué bytes colocar en el payload gzip):<sup>[[1]](#references)</sup>

- El deserializador de Revit lee un índice de clase de 16 bits y construye un objeto. Ciertos tipos no son polimórficos y carecen de vtables; abusar del manejo del destructor provoca una type confusion en la que el engine ejecuta una llamada indirecta a través de un puntero controlado por el atacante.
- Elegir `AString` (índice de clase `0x1F`) coloca un puntero de heap controlado por el atacante en el offset 0 del objeto. Durante el bucle del destructor, Revit ejecuta efectivamente:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Coloca múltiples objetos de este tipo en el grafo serializado para que cada iteración del bucle de destructor ejecute un gadget (“weird machine”), y organiza un stack pivot hacia una cadena ROP x64 convencional.

Consulta aquí los detalles sobre la creación de pivots/gadgets para Windows x64:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

y aquí una guía general sobre ROP:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Herramientas:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) para expandir/reconstruir archivos compuestos OLE: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD para reversing/taint; desactiva page heap con TTD para mantener las trazas compactas.
- Un proxy local (por ejemplo, Fiddler) puede simular la entrega de supply chain sustituyendo RFAs en el tráfico de plugins para realizar pruebas.

## References

- [1] [Creación de un exploit RCE completo a partir de un crash en el análisis de archivos RFA de Autodesk Revit (entrada de blog de ZDI)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Documentación de OLE Compound File (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Guía de campo de Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [5] [Documentación de olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Macros automáticas (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Evento Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
