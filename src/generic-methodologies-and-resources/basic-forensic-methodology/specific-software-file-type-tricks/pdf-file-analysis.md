# Análisis de archivos PDF

{{#include ../../../banners/hacktricks-training.md}}

**Para más detalles, consulta:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

El formato PDF es conocido por su complejidad y su potencial para ocultar datos, lo que lo convierte en un foco de los desafíos de forensics de CTF. Combina elementos de texto plano con objetos binarios, que pueden estar comprimidos o cifrados, e incluir scripts en lenguajes como JavaScript o Flash. Para entender la estructura de los PDF, se puede consultar el [material introductorio](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) de Didier Stevens o usar herramientas como un editor de texto o un editor específico para PDF, como Origami.

Para explorar o manipular PDF en profundidad, hay herramientas disponibles como [qpdf](https://github.com/qpdf/qpdf) y [Origami](https://github.com/mobmewireless/origami-pdf). Los datos ocultos en los PDF pueden estar disimulados en:

- Capas invisibles
- El formato de metadatos XMP de Adobe
- Generaciones incrementales
- Texto del mismo color que el fondo
- Texto detrás de imágenes o imágenes superpuestas
- Comentarios no mostrados

Para analizar PDF de forma personalizada, se pueden usar bibliotecas de Python como [PeepDF](https://github.com/jesparza/peepdf) para crear scripts de análisis a medida. Además, el potencial de los PDF para almacenar datos ocultos es tan amplio que recursos como la guía de la NSA sobre riesgos y contramedidas de PDF siguen ofreciendo información valiosa, aunque ya no esté alojada en su ubicación original. Una [copia de la guía](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) y una colección de [trucos del formato PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) de Ange Albertini ofrecen más información sobre el tema.<sup>[[4]](#references)[[5]](#references)</sup>

## Construcciones maliciosas comunes

Los atacantes suelen abusar de objetos y acciones específicos de PDF que se ejecutan automáticamente al abrir el documento o interactuar con él. Palabras clave que conviene buscar:

* **/OpenAction, /AA** – acciones automáticas que se ejecutan al abrir el documento o ante eventos específicos.
* **/JS, /JavaScript** – JavaScript incrustado (a menudo ofuscado o dividido entre varios objetos).
* **/Launch, /SubmitForm, /URI, /GoToE** – mecanismos para iniciar procesos externos o abrir URL.
* **/RichMedia, /Flash, /3D** – objetos multimedia que pueden ocultar payloads.
* **/EmbeddedFile /Filespec** – archivos adjuntos (EXE, DLL, OLE, etc.).
* **/ObjStm, /XFA, /AcroForm** – flujos de objetos o formularios que suelen usarse para ocultar shell-code.
* **Actualizaciones incrementales** – varios marcadores %%EOF o un desplazamiento **/Prev** muy grande pueden indicar que se añadieron datos después de firmar el documento para eludir el AV.

Si alguno de los tokens anteriores aparece junto con cadenas sospechosas (powershell, cmd.exe, calc.exe, base64, etc.), conviene analizar el PDF con más detenimiento.

---

## Guía rápida de análisis estático

Los ejemplos siguientes usan las interfaces de línea de comandos documentadas de `pdf-parser.py`, qpdf y pdfcpu.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>

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

Pixelar una imagen dentro de un PDF no elimina los píxeles subyacentes. Si un documento legible parece ocultar una credencial de esta manera, extrae la imagen incrustada para inspeccionarla offline con autorización; el resultado depende de la imagen y de contar con una referencia adecuada, y no se garantiza la recuperación visual. Una contraseña recuperada aún debe verificarse por separado con la cuenta cuyos privilegios importan. No incluyas una extracción de PDF ni una pasada de recuperación de imágenes en un escaneo rutinario de enumeración de hosts.

Proyectos adicionales útiles (con mantenimiento activo entre 2023 y 2025):
* **pdfcpu** – biblioteca/CLI de Go que permite validar, descifrar, extraer, optimizar y manipular PDFs.<sup>[[9]](#references)</sup>
* **pdf-inspector** – visualizador basado en navegador que representa el grafo de objetos y los streams.
* **PyMuPDF** – bindings de Python programables para inspeccionar PDFs y renderizar páginas como imágenes rasterizadas. Considera el parser/renderizador como una superficie de ataque de archivos no confiables y ejecútalo dentro de un entorno de análisis debidamente aislado.<sup>[[8]](#references)</sup>

---

## Técnicas de ataque recientes (2023-2025)

* **Polyglot MalDoc in PDF (2023)** – JPCERT/CC informó de una técnica que añade a un PDF un archivo MHT creado con Word y macros VBA, conservando la firma mágica de PDF y permitiendo también abrirlo en Word. Las herramientas de análisis exclusivas para PDF, los sandboxes o los antivirus pueden pasar por alto la macro porque el comportamiento malicioso ocurre al abrirlo como Word; busca el marcador `<w:WordDocument>` junto con otros indicadores de MHT.<sup>[[2]](#references)</sup>
* **Ataques Shadow contra PDFs firmados** – los atacantes pueden colocar contenido oculto en un PDF antes de firmarlo y, a continuación, añadir una actualización incremental que cambia las referencias al catálogo o a los objetos para que los visores muestren el contenido oculto mientras la firma original sigue siendo válida. La técnica puede evadir los visores que clasifican esas actualizaciones como inofensivas.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe califica esta vulnerabilidad crítica como un use-after-free que puede provocar la ejecución de código arbitrario; APSB24-29 se publicó el 14 de mayo de 2024.<sup>[[3]](#references)</sup>

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

1. **Aplicar parches rápidamente** – mantén Acrobat/Reader en la versión más reciente del canal Continuous; la mayoría de las cadenas de RCE observadas en la práctica aprovechan vulnerabilidades n-day corregidas meses antes.
2. **Eliminar contenido activo en la pasarela** – usa un sanitizador especializado y controlado por políticas, o un producto CDR que elimine explícitamente JavaScript, archivos incrustados, acciones de inicio, formularios y contenido multimedia. `qpdf --qdf` facilita la inspección de los objetos PDF, mientras que pdfcpu ofrece funciones de validación y manipulación; ninguno de los dos comandos, por sí solo, demuestra que se haya eliminado el contenido activo.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Desarme y reconstrucción de contenido (CDR)** – convierte los PDF en imágenes (o PDF/A) en un host aislado para conservar la fidelidad visual y descartar los objetos activos.
4. **Bloquear las funciones poco utilizadas** – la configuración empresarial de «Enhanced Security» de Reader permite desactivar JavaScript, el contenido multimedia y la renderización 3D.
5. **Capacitación de usuarios** – la ingeniería social (señuelos de facturas y currículums) sigue siendo el vector inicial; enseña a los empleados a reenviar los archivos adjuntos sospechosos al equipo de respuesta a incidentes (IR).

## References

- [1] [Guía de campo de CTF de análisis forense](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc en PDF: evasión de la detección mediante la incrustación de un archivo Word malicioso en un archivo PDF](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Boletín de seguridad de Adobe: actualización de seguridad disponible para Adobe Acrobat y Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - copia de la guía](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - trucos del formato PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Ataques Shadow: ocultar y reemplazar contenido en PDF firmados](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [Tutorial de PyMuPDF](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [Opciones de línea de comandos de qpdf](https://qpdf.readthedocs.io/en/stable/cli.html)
{{#include ../../../banners/hacktricks-training.md}}
