# Stego

{{#include ../banners/hacktricks-training.md}}

Esta sección se centra en **encontrar y extraer datos ocultos** de archivos (imágenes/audio/vídeo/documentos/archivos comprimidos) y de la esteganografía basada en texto.

Si estás aquí por ataques criptográficos, ve a la sección **Crypto**.

## Punto de entrada

Aborda la esteganografía como un problema forense: identifica el contenedor real, enumera las ubicaciones con mayor probabilidad de contener información (metadatos, datos añadidos, archivos incrustados) y solo después aplica técnicas de extracción a nivel de contenido.

### Flujo de trabajo y triaje

Un flujo de trabajo estructurado que prioriza la identificación del contenedor, la inspección de metadatos/cadenas, el carving y la ramificación específica del formato.

{{#ref}}
workflow/README.md
{{#endref}}

### Imágenes

Donde se encuentra la mayor parte de la esteganografía de CTF: LSB/planos de bits (PNG/BMP), peculiaridades de chunks/formatos de archivo, herramientas para JPEG y trucos con GIF de múltiples frames.

{{#ref}}
images/README.md
{{#endref}}

### Audio

Los mensajes en espectrogramas, la incrustación LSB en muestras y los tonos del teclado telefónico (DTMF) son patrones recurrentes.

{{#ref}}
audio/README.md
{{#endref}}

### Texto

Si el texto se muestra normalmente, pero se comporta de forma inesperada, considera homoglifos Unicode, caracteres de ancho cero o codificación basada en espacios en blanco.

{{#ref}}
text/README.md
{{#endref}}

### Documentos

Los archivos PDF y Office son, ante todo, contenedores; los ataques suelen girar en torno a archivos/streams incrustados, grafos de objetos/relaciones y la extracción ZIP.

{{#ref}}
documents/README.md
{{#endref}}

### Esteganografía de malware y de tipo delivery

La entrega de payloads utiliza con frecuencia archivos con apariencia válida (por ejemplo, GIF/PNG) que contienen payloads de texto delimitados por marcadores, en lugar de ocultación a nivel de píxel.

{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
