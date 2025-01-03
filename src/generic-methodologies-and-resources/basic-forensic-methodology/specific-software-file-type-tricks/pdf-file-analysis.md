# Análisis de archivos PDF

{{#include ../../../banners/hacktricks-training.md}}

**Para más detalles, consulta:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

El formato PDF es conocido por su complejidad y su potencial para ocultar datos, lo que lo convierte en un punto focal para los desafíos de forense en CTF. Combina elementos de texto plano con objetos binarios, que pueden estar comprimidos o cifrados, y puede incluir scripts en lenguajes como JavaScript o Flash. Para entender la estructura de un PDF, se puede consultar el [material introductorio](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) de Didier Stevens, o utilizar herramientas como un editor de texto o un editor específico de PDF como Origami.

Para una exploración o manipulación profunda de PDFs, están disponibles herramientas como [qpdf](https://github.com/qpdf/qpdf) y [Origami](https://github.com/mobmewireless/origami-pdf). Los datos ocultos dentro de los PDFs pueden estar ocultos en:

- Capas invisibles
- Formato de metadatos XMP de Adobe
- Generaciones incrementales
- Texto del mismo color que el fondo
- Texto detrás de imágenes o imágenes superpuestas
- Comentarios no mostrados

Para un análisis personalizado de PDF, se pueden utilizar bibliotecas de Python como [PeepDF](https://github.com/jesparza/peepdf) para crear scripts de análisis a medida. Además, el potencial del PDF para el almacenamiento de datos ocultos es tan vasto que recursos como la guía de la NSA sobre riesgos y contramedidas de PDF, aunque ya no se encuentra alojada en su ubicación original, aún ofrecen valiosos conocimientos. Una [copia de la guía](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) y una colección de [trucos del formato PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) de Ange Albertini pueden proporcionar más lecturas sobre el tema.

{{#include ../../../banners/hacktricks-training.md}}
