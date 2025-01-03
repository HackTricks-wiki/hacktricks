# Análisis de archivos de Office

{{#include ../../../banners/hacktricks-training.md}}

Para más información, consulta [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Este es solo un resumen:

Microsoft ha creado muchos formatos de documentos de Office, siendo los dos tipos principales **formatos OLE** (como RTF, DOC, XLS, PPT) y **formatos Office Open XML (OOXML)** (como DOCX, XLSX, PPTX). Estos formatos pueden incluir macros, lo que los convierte en objetivos para phishing y malware. Los archivos OOXML están estructurados como contenedores zip, lo que permite la inspección a través de la descompresión, revelando la jerarquía de archivos y carpetas y el contenido de archivos XML.

Para explorar las estructuras de archivos OOXML, se proporciona el comando para descomprimir un documento y la estructura de salida. Se han documentado técnicas para ocultar datos en estos archivos, lo que indica una innovación continua en la ocultación de datos dentro de los desafíos CTF.

Para el análisis, **oletools** y **OfficeDissector** ofrecen conjuntos de herramientas completos para examinar tanto documentos OLE como OOXML. Estas herramientas ayudan a identificar y analizar macros incrustadas, que a menudo sirven como vectores para la entrega de malware, normalmente descargando y ejecutando cargas útiles maliciosas adicionales. El análisis de macros VBA se puede realizar sin Microsoft Office utilizando Libre Office, que permite la depuración con puntos de interrupción y variables de observación.

La instalación y el uso de **oletools** son sencillos, con comandos proporcionados para instalar a través de pip y extraer macros de documentos. La ejecución automática de macros se activa mediante funciones como `AutoOpen`, `AutoExec` o `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
{{#include ../../../banners/hacktricks-training.md}}
