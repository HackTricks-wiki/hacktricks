# PDF File analysis

{{#include ../../../banners/hacktricks-training.md}}

**For further details check:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

The PDF format is known for its complexity and potential for concealing data, making it a focal point for CTF forensics challenges. It combines plain-text elements with binary objects, which might be compressed or encrypted, and can include scripts in languages like JavaScript or Flash. To understand PDF structure, one can refer to Didier Stevens's [introductory material](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/), or use tools like a text editor or a PDF-specific editor such as Origami.

For in-depth exploration or manipulation of PDFs, tools like [qpdf](https://github.com/qpdf/qpdf) and [Origami](https://github.com/mobmewireless/origami-pdf) are available. Hidden data within PDFs might be concealed in:

- Invisible layers
- XMP metadata format by Adobe
- Incremental generations
- Text with the same color as the background
- Text behind images or overlapping images
- Non-displayed comments

For custom PDF analysis, Python libraries like [PeepDF](https://github.com/jesparza/peepdf) can be used to craft bespoke parsing scripts. Further, the PDF's potential for hidden data storage is so vast that resources like the NSA guide on PDF risks and countermeasures, though no longer hosted at its original location, still offer valuable insights. A [copy of the guide](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) and a collection of [PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) by Ange Albertini can provide further reading on the subject.

## Common Malicious Constructs

Attackers often abuse specific PDF objects and actions that automatically execute when the document is opened or interacted with. Keywords worth hunting for:

* **/OpenAction, /AA** – automatic actions executed on open or on specific events.
* **/JS, /JavaScript** – embedded JavaScript (often obfuscated or split across objects).
* **/Launch, /SubmitForm, /URI, /GoToE** – external process / URL launchers.
* **/RichMedia, /Flash, /3D** – multimedia objects that can hide payloads.
* **/EmbeddedFile /Filespec** – file attachments (EXE, DLL, OLE, etc.).
* **/ObjStm, /XFA, /AcroForm** – object streams or forms commonly abused to hide shell-code.
* **Incremental updates** – multiple %%EOF markers or a very large **/Prev** offset may indicate data appended after signing to bypass AV.

When any of the previous tokens appear together with suspicious strings (powershell, cmd.exe, calc.exe, base64, etc.) the PDF deserves deeper analysis.

---

## Static analysis cheat-sheet

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

Additional useful projects (actively maintained 2023-2025):
* **pdfcpu** – Go library/CLI able to *lint*, *decrypt*, *extract*, *compress* and *sanitize* PDFs.
* **pdf-inspector** – browser-based visualizer that renders the object graph and streams.
* **PyMuPDF (fitz)** – scriptable Python engine that can safely render pages to images to detonate embedded JS in a hardened sandbox.

---

## Recent attack techniques (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC observed threat actors appending an MHT-based Word document with VBA macros after the final **%%EOF**, producing a file that is both a valid PDF and a valid DOC. AV engines parsing just the PDF layer miss the macro. Static PDF keywords are clean, but `file` still prints `%PDF`. Treat any PDF that also contains the string `<w:WordDocument>` as highly suspicious.
* **Shadow-incremental updates (2024)** – adversaries abuse the incremental update feature to insert a second **/Catalog** with malicious `/OpenAction` while keeping the benign first revision signed. Tools that inspect only the first xref table are bypassed.
* **Font parsing UAF chain – CVE-2024-30284 (Acrobat/Reader)** – a vulnerable **CoolType.dll** function can be reached from embedded CIDType2 fonts, allowing remote code execution with the privileges of the user once a crafted document is opened. Patched in APSB24-29, May 2024.

---

## YARA quick rule template

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

## Defensive tips

1. **Patch fast** – keep Acrobat/Reader on the latest Continuous track; most RCE chains observed in the wild leverage n-day vulnerabilities fixed months earlier.
2. **Strip active content at the gateway** – use `pdfcpu sanitize` or `qpdf --qdf --remove-unreferenced` to drop JavaScript, embedded files and launch actions from inbound PDFs.
3. **Content Disarm & Reconstruction (CDR)** – convert PDFs to images (or PDF/A) on a sandbox host to preserve visual fidelity while discarding active objects.
4. **Block rarely-used features** – enterprise “Enhanced Security” settings in Reader allow disabling of JavaScript, multimedia and 3D rendering.
5. **User education** – social engineering (invoice & resume lures) remains the initial vector; teach employees to forward suspicious attachments to IR.

## References

* JPCERT/CC – “MalDoc in PDF – Detection bypass by embedding a malicious Word file into a PDF file” (Aug 2023)  
* Adobe – Security update for Acrobat and Reader (APSB24-29, May 2024)


{{#include ../../../banners/hacktricks-training.md}}



