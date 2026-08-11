# PDF File analysis

{{#include ../../../banners/hacktricks-training.md}}

**For further details check:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/).<sup>[[1]](#references)</sup>

The PDF format is known for its complexity and potential for concealing data, making it a focal point for CTF forensics challenges. It combines plain-text elements with binary objects, which might be compressed or encrypted, and can include scripts in languages like JavaScript or Flash. To understand PDF structure, one can refer to Didier Stevens's [introductory material](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/), or use tools like a text editor or a PDF-specific editor such as Origami.

For in-depth exploration or manipulation of PDFs, tools like [qpdf](https://github.com/qpdf/qpdf) and [Origami](https://github.com/mobmewireless/origami-pdf) are available. Hidden data within PDFs might be concealed in:

- Invisible layers
- XMP metadata format by Adobe
- Incremental generations
- Text with the same color as the background
- Text behind images or overlapping images
- Non-displayed comments

For custom PDF analysis, Python libraries like [PeepDF](https://github.com/jesparza/peepdf) can be used to craft bespoke parsing scripts. Further, the PDF's potential for hidden data storage is so vast that resources like the NSA guide on PDF risks and countermeasures, though no longer hosted at its original location, still offer valuable insights. A [copy of the guide](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) and a collection of [PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md) by Ange Albertini can provide further reading on the subject.<sup>[[4]](#references)[[5]](#references)</sup>

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

The examples below use the documented `pdf-parser.py`, qpdf, and pdfcpu command-line interfaces.<sup>[[7]](#references)[[9]](#references)[[10]](#references)</sup>

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

Additional useful projects (actively maintained 2023-2025):
* **pdfcpu** – Go library/CLI able to validate, decrypt, extract, optimize, and manipulate PDFs.<sup>[[9]](#references)</sup>
* **pdf-inspector** – browser-based visualizer that renders the object graph and streams.
* **PyMuPDF** – scriptable Python bindings for inspecting PDFs and rendering pages to raster images. Treat the parser/renderer as untrusted-file attack surface and run it inside an appropriately isolated analysis environment.<sup>[[8]](#references)</sup>

---

## Recent attack techniques (2023-2025)

* **MalDoc in PDF polyglot (2023)** – JPCERT/CC reported a technique that appends a Word-created MHT file with VBA macros to a PDF, leaving PDF magic while also opening in Word. PDF-only analysis tools, sandboxes, or antivirus may miss the macro because the malicious behavior occurs when opened as Word; look for the `<w:WordDocument>` marker alongside other MHT indicators.<sup>[[2]](#references)</sup>
* **Shadow attacks on signed PDFs** – attackers can place hidden content in a PDF before it is signed, then append an incremental update that changes catalog or object references so viewers display the hidden content while the original signature remains valid. The technique can evade viewers that classify such updates as harmless.<sup>[[6]](#references)</sup>
* **Use-after-free – CVE-2024-30284 (Acrobat/Reader)** – Adobe rates this critical vulnerability as a use-after-free that can lead to arbitrary code execution; APSB24-29 was published on May 14, 2024.<sup>[[3]](#references)</sup>

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
2. **Strip active content at the gateway** – use a purpose-built, policy-controlled sanitizer or CDR product that explicitly removes JavaScript, embedded files, launch actions, forms, and multimedia. `qpdf --qdf` makes PDF objects easier to inspect, while pdfcpu provides validation and manipulation features; neither command alone is proof that active content was removed.<sup>[[9]](#references)[[10]](#references)</sup>
3. **Content Disarm & Reconstruction (CDR)** – convert PDFs to images (or PDF/A) on a sandbox host to preserve visual fidelity while discarding active objects.
4. **Block rarely-used features** – enterprise “Enhanced Security” settings in Reader allow disabling of JavaScript, multimedia and 3D rendering.
5. **User education** – social engineering (invoice & resume lures) remains the initial vector; teach employees to forward suspicious attachments to IR.

## References

- [1] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [2] [MalDoc in PDF – Detection bypass by embedding a malicious Word file into a PDF file](https://blogs.jpcert.or.jp/en/2023/08/maldocinpdf.html)
- [3] [Adobe Security Bulletin – Security update available for Adobe Acrobat and Reader (APSB24-29)](https://helpx.adobe.com/security/products/acrobat/apsb24-29.html)
- [4] [itsecure.hu - copy of the guide](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)
- [5] [corkami/docs - PDF format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md)
- [6] [Shadow Attacks: Hiding and Replacing Content in Signed PDFs](https://www.pdf-insecurity.org/download/Shadow_Attacks__Hiding_and_Replacing_Content_in_Signed_PDFs.pdf)
- [7] [DidierStevensSuite: pdf-parser.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py)
- [8] [PyMuPDF Tutorial](https://pymupdf.readthedocs.io/en/latest/tutorial.html)
- [9] [pdfcpu](https://github.com/pdfcpu/pdfcpu)
- [10] [qpdf command-line options](https://qpdf.readthedocs.io/en/stable/cli.html)

{{#include ../../../banners/hacktricks-training.md}}
