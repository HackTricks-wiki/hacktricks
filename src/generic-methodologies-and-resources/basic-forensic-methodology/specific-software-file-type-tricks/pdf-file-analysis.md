# Análisis de archivos PDF

{{#include ../../../banners/hacktricks-training.md}}

**Para más detalles, consulta:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

El formato PDF es conocido por su complejidad y su potencial para ocultar datos, lo que lo convierte en un objetivo frecuente en los desafíos de forensics de CTF. Combina elementos de texto plano con objetos binarios, que pueden estar comprimidos o cifrados, e incluir scripts en lenguajes como JavaScript o Flash. Para comprender la estructura de un PDF, se puede consultar el [material introductorio](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) de Didier Stevens, o utilizar herramientas como un editor de texto o un editor específico para PDF, como Origami.

Para explorar o manipular PDFs en profundidad, existen herramientas como [qpdf](https://github.com/qpdf/qpdf) y [Origami](https://github.com/mobmewireless/origami-pdf). Los datos ocultos dentro de los PDFs pueden estar ocultos en:

- Capas invisibles
- Formato de metadatos XMP de Adobe
- Generaciones incrementales
- Texto con el mismo color que el fondo
- Texto detrás de imágenes o imágenes superpuestas
- Comentarios no mostrados

Para realizar análisis personalizados de PDFs, se pueden utilizar bibliotecas de Python como [PeepDF](https://github.com/jesparza/peepdf) para crear scripts de parsing a medida. Además, el potencial de los PDF para almacenar datos ocultos es tan amplio que recursos como la guía de la NSA sobre riesgos y contramedidas de PDF, aunque ya no esté alojada en su ubicación original, siguen ofreciendo información valiosa. Una [copia de la guía](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) y una colección de [trucos del formato PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) de Ange Albertini pueden proporcionar más material sobre el tema.<sup>[[4]](#references)[[5]](#references)</sup>

## Constructos maliciosos comunes

Los atacantes suelen abusar de objetos y acciones específicas de PDF que se ejecutan automáticamente cuando el documento se abre o se interactúa con él. Palabras clave que conviene buscar:

* **/OpenAction, /AA** – acciones automáticas ejecutadas al abrir el documento o ante eventos específicos.
* **/JS, /JavaScript** – JavaScript incrustado (a menudo ofuscado o dividido entre varios objetos).
* **/Launch, /SubmitForm, /URI, /GoToE** – lanzadores de procesos externos o URL.
* **/RichMedia, /Flash, /3D** – objetos multimedia que pueden ocultar payloads.
* **/EmbeddedFile /Filespec** – archivos adjuntos (EXE, DLL, OLE, etc.).
* **/ObjStm, /XFA, /AcroForm** – streams de objetos o formularios que suelen utilizarse de forma abusiva para ocultar shell-code.
* **Actualizaciones incrementales** – varios marcadores %%EOF o un desplazamiento **/Prev** muy grande pueden indicar datos añadidos después de la firma para evadir el AV.

Cuando alguno de los tokens anteriores aparece junto con strings sospechosos (powershell, cmd.exe, calc.exe, base64, etc.), el PDF merece un análisis más profundo.

---

## Guía rápida de análisis estático

Los ejemplos siguientes utilizan las interfaces de línea de comandos documentadas de `pdf-parser.py`, qpdf y pdfcpu.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>
```bash
# Fast triage – keyword statistics
pdfid.py suspicious.pdf

# Deep dive – pass supported streams through their declared filters
pdf-parser.py -f suspicious.pdf
pdf-parser.py -a suspicious.pdf                # automatic report

# Search for JavaScript and pretty-print it
pdf-parser.py -search "/JS" -raw suspicious.pdf | js-beautify -

# Dump embedded files
peepdf "open suspicious.pdf" "objects embeddedfile" "extract 15 16 17" -o dumps/

# Remove passwords / encryptions before processing with other tools
qpdf --password='secret' --decrypt suspicious.pdf clean.pdf

# Lint the file with a Go verifier (checks structure violations)
pdfcpu validate -mode strict clean.pdf
```
Proyectos adicionales útiles (mantenidos activamente entre 2023 y 2025):
* **pdfcpu** – biblioteca/CLI de Go capaz de validar, descifrar, extraer, optimizar y manipular PDFs.<sup>[[9]](#references)</sup>
* **pdf-inspector** – visualizador basado en navegador que renderiza el grafo de objetos y los streams.
* **PyMuPDF** – bindings de Python programables mediante scripts para inspeccionar PDFs y renderizar páginas como imágenes rasterizadas. Trata el parser/renderer como una attack surface de archivos no confiables y ejecútalo dentro de un entorno de análisis debidamente aislado.<sup>[[8]](#references)</sup>

---

## Técnicas de ataque recientes (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC informó sobre una técnica que añade un archivo MHT creado con Word y con macros VBA a un PDF, conservando la magic de PDF y permitiendo abrirlo también en Word. Las herramientas de análisis exclusivas para PDF, los sandboxes o los antivirus pueden pasar por alto la macro porque el comportamiento malicioso ocurre cuando se abre como Word; busca el marcador `<w:WordDocument>` junto con otros indicadores de MHT.<sup>[[2]](#references)</sup>
* **Shadow attacks on signed PDFs** – los atacantes pueden colocar contenido oculto en un PDF antes de firmarlo y, posteriormente, añadir una actualización incremental que cambia las referencias del catálogo o de los objetos para que los visores muestren el contenido oculto mientras la firma original sigue siendo válida. La técnica puede evadir los visores que clasifican dichas actualizaciones como inofensivas.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe califica esta vulnerabilidad crítica como un use-after-free que puede provocar la ejecución arbitraria de código; APSB24-29 se publicó el 14 de mayo de 2024.<sup>[[3]](#references)</sup>

---

## Plantilla rápida de regla YARA
```yara
rule Suspicious_PDF_AutoExec {
meta:
description = "Generic detection of PDFs with auto-exec actions and JS"
author      = "HackTricks"
last_update = "2025-07-20"
strings:
$pdf_magic = { 25 50 44 46 }          // %PDF
$aa        = "/AA" ascii nocase
$openact   = "/OpenAction" ascii nocase
$js        = "/JS" ascii nocase
condition:
$pdf_magic at 0 and ( all of ($aa, $openact) or ($openact and $js) )
}
```
---

## Consejos defensivos

1. **Aplicar parches rápidamente**: mantener Acrobat/Reader en el último canal Continuous; la mayoría de las cadenas RCE observadas in the wild aprovechan vulnerabilidades n-day corregidas meses antes.
2. **Eliminar el contenido activo en el gateway**: usar un sanitizer diseñado específicamente y controlado mediante políticas, o un producto CDR que elimine explícitamente JavaScript, archivos incrustados, acciones de lanzamiento, formularios y contenido multimedia. `qpdf --qdf` facilita la inspección de los objetos PDF, mientras que pdfcpu proporciona funciones de validación y manipulación; ninguno de los dos comandos por sí solo demuestra que se haya eliminado el contenido activo.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)**: convertir los PDF a imágenes (o PDF/A) en un host sandbox para conservar la fidelidad visual y descartar los objetos activos.
4. **Bloquear las funciones poco utilizadas**: la configuración empresarial “Enhanced Security” de Reader permite desactivar JavaScript, el contenido multimedia y la renderización 3D.
5. **Formación de los usuarios**: la ingeniería social (señuelos con facturas y currículums) sigue siendo el vector inicial; enseñar a los empleados a reenviar los archivos adjuntos sospechosos al equipo de IR.

## References

- [1] [Guía de campo de Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF: bypass de detección mediante la incrustación de un archivo Word malicioso en un archivo PDF](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Boletín de seguridad de Adobe: actualización de seguridad disponible para Adobe Acrobat y Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu: copia de la guía](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs: trucos del formato PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow Attacks: ocultación y sustitución de contenido en PDF firmados](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [Tutorial de PyMuPDF](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [Opciones de línea de comandos de qpdf](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
