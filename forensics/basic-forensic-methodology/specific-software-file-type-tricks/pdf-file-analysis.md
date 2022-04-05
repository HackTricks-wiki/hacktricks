# PDF File analysis

From: [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

PDF is an extremely complicated document file format, with enough tricks and hiding places [to write about for years](https://www.sultanik.com/pocorgtfo/). This also makes it popular for CTF forensics challenges. The NSA wrote a guide to these hiding places in 2008 titled "Hidden Data and Metadata in Adobe PDF Files: Publication Risks and Countermeasures." It's no longer available at its original URL, but you can [find a copy here](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf). Ange Albertini also keeps a wiki on GitHub of [PDF file format tricks](https://github.com/corkami/docs/blob/master/PDF/PDF.md).

The PDF format is partially plain-text, like HTML, but with many binary "objects" in the contents. Didier Stevens has written [good introductory material](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) about the format. The binary objects can be compressed or even encrypted data, and include content in scripting languages like JavaScript or Flash. To display the structure of a PDF, you can either browse it with a text editor, or open it with a PDF-aware file-format editor like Origami.

[qpdf](https://github.com/qpdf/qpdf) is one tool that can be useful for exploring a PDF and transforming or extracting information from it. Another is a framework in Ruby called [Origami](https://github.com/mobmewireless/origami-pdf).

When exploring PDF content for hidden data, some of the hiding places to check include:

* non-visible layers
* Adobe's metadata format "XMP"
* the "incremental generation" feature of PDF wherein a previous version is retained but not visible to the user
* white text on a white background
* text behind images
* an image behind an overlapping image
* non-displayed comments

There are also several Python packages for working with the PDF file format, like [PeepDF](https://github.com/jesparza/peepdf), that enable you to write your own parsing scripts.

