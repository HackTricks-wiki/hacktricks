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

{{#include ../../../banners/hacktricks-training.md}}



