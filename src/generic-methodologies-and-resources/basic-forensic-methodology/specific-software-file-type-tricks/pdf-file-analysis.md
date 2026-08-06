# Análisis de archivos PDF

{{#include ../../../banners/hacktricks-training.md}}

**Para obtener más detalles, consulta:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)<sup>[[1]](#references)</sup>

El formato PDF es conocido por su complejidad y su potencial para ocultar datos, lo que lo convierte en un elemento central en los desafíos de forensics de CTF. Combina elementos de texto plano con objetos binarios, que pueden estar comprimidos o cifrados, y puede incluir scripts en lenguajes como JavaScript o Flash. Para comprender la estructura de los PDF, se puede consultar el [material introductorio](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) de Didier Stevens, o utilizar herramientas como un editor de texto o un editor específico para PDF, como Origami.

Para explorar o manipular PDF en profundidad, existen herramientas como [qpdf](https://github.com/qpdf/qpdf) y [Origami](https://github.com/mobmewireless/origami-pdf). Los datos ocultos dentro de los PDF pueden estar escondidos en:

- Capas invisibles
- Formato de metadatos XMP de Adobe
- Generaciones incrementales
- Texto del mismo color que el fondo
- Texto detrás de imágenes o imágenes superpuestas
- Comentarios no mostrados

Para realizar análisis personalizados de PDF, se pueden utilizar bibliotecas de Python como [PeepDF](https://github.com/jesparza/peepdf) para crear scripts de parsing a medida. Además, el potencial de los PDF para almacenar datos ocultos es tan amplio que recursos como la guía de la NSA sobre riesgos y contramedidas de PDF, aunque ya no está alojada en su ubicación original, siguen ofreciendo información valiosa. Una [copia de la guía](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) y una colección de [trucos del formato PDF](https://github.com/corkami/docs/blob/master/PDF/PDF.md) de Ange Albertini pueden proporcionar material adicional sobre el tema.

## Constructos maliciosos comunes

Los atacantes suelen abusar de objetos y acciones específicos de los PDF que se ejecutan automáticamente cuando el documento se abre o cuando se interactúa con él. Palabras clave que conviene buscar:

* **/OpenAction, /AA** – acciones automáticas ejecutadas al abrir el documento o ante eventos específicos.
* **/JS, /JavaScript** – JavaScript incrustado, a menudo ofuscado o dividido entre varios objetos.
* **/Launch, /SubmitForm, /URI, /GoToE** – lanzadores de procesos externos o URL.
* **/RichMedia, /Flash, /3D** – objetos multimedia que pueden ocultar payloads.
* **/EmbeddedFile /Filespec** – archivos adjuntos (EXE, DLL, OLE, etc.).
* **/ObjStm, /XFA, /AcroForm** – streams de objetos o formularios que suelen utilizarse para ocultar shell-code.
* **Actualizaciones incrementales** – varios marcadores %%EOF o un offset **/Prev** muy grande pueden indicar que se han añadido datos después de la firma para evadir AV.

Cuando alguno de los tokens anteriores aparece junto con strings sospechosos (powershell, cmd.exe, calc.exe, base64, etc.), el PDF merece un análisis más profundo.

---

## Guía rápida de análisis estático
```bash
# Fast triage – keyword statistics
pdfid.py suspicious.pdf

# Deep dive – decompress/inspect the object tree
pdf-parser.py -f suspicious.pdf                # interactive
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
* **pdfcpu** – biblioteca/CLI de Go capaz de hacer *lint*, *decrypt*, *extract*, *compress* y *sanitize* de PDFs.
* **pdf-inspector** – visualizador basado en navegador que representa el grafo de objetos y los streams.
* **PyMuPDF (fitz)** – motor Python programable que puede renderizar páginas de forma segura como imágenes para detonar JS embebido en un sandbox reforzado.

---

## Técnicas de ataque recientes (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC observó threat actors que añadían un documento Word basado en MHT con macros VBA después del **%%EOF** final, produciendo un archivo que es a la vez un PDF válido y un DOC válido. Los motores AV que analizan únicamente la capa PDF no detectan la macro. Las palabras clave estáticas del PDF están limpias, pero `file` aún muestra `%PDF`. Trata cualquier PDF que también contenga la cadena `<w:WordDocument>` como altamente sospechoso.<sup>[[2]](#references)</sup>
* **Shadow-incremental updates (2024)** – los adversarios abusan de la función de actualización incremental para insertar un segundo **/Catalog** con un `/OpenAction` malicioso mientras mantienen firmada la primera revisión benigna. Las herramientas que inspeccionan únicamente la primera tabla xref pueden ser evadidas.
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – se puede acceder a una función vulnerable de **CoolType.dll** mediante fuentes CIDType2 embebidas, lo que permite la ejecución remota de código con los privilegios del usuario una vez que se abre un documento manipulado. Corregido en APSB24-29, mayo de 2024.<sup>[[3]](#references)</sup>

---

## Plantilla rápida de regla de YARA
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

1. **Aplicar parches rápidamente** – mantén Acrobat/Reader en la última versión del canal Continuous; la mayoría de las cadenas de RCE observadas en la naturaleza aprovechan vulnerabilidades n-day corregidas meses antes.
2. **Eliminar el contenido activo en el gateway** – usa `pdfcpu sanitize` o `qpdf --qdf --remove-unreferenced` para eliminar JavaScript, archivos incrustados y acciones de lanzamiento de los PDF entrantes.
3. **Content Disarm & Reconstruction (CDR)** – convierte los PDF a imágenes (o PDF/A) en un host sandbox para conservar la fidelidad visual mientras descartas los objetos activos.
4. **Bloquear las funciones poco utilizadas** – la configuración empresarial “Enhanced Security” de Reader permite desactivar JavaScript, multimedia y la representación 3D.
5. **Formación de los usuarios** – la ingeniería social (señuelos con facturas y currículums) sigue siendo el vector inicial; enseña a los empleados a reenviar los archivos adjuntos sospechosos al equipo de IR.

## Referencias

- [1] [Guía de campo de Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Evasión de detección mediante la incrustación de un archivo Word malicioso en un archivo PDF](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Boletín de seguridad de Adobe – Actualización de seguridad disponible para Adobe Acrobat y Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)

{{#include ../../../banners/hacktricks-training.md}}
