# Stego

{{#include ../banners/hacktricks-training.md}}

This section focuses on **finding and extracting hidden data** from images, audio, video, documents, archives, and text. Steganography conceals the existence of a communication by embedding data inside other data.<sup>[[1]](#references)</sup>

If you're here for cryptographic attacks, go to the **Crypto** section.

## Entry Point

Approach steganography as a forensics problem: identify the real container, enumerate high-signal locations (metadata, appended data, embedded files), and only then apply content-level extraction techniques.

### Workflow & triage

A structured workflow that prioritizes container identification, metadata/string inspection, carving, and format-specific branching.

{{#ref}}
workflow/README.md
{{#endref}}

### Images

Where most CTF stego lives: LSB/bit-planes (PNG/BMP), chunk/file-format weirdness, JPEG tooling, and multi-frame GIF tricks.

{{#ref}}
images/README.md
{{#endref}}

### Audio

Spectrogram messages, sample LSB embedding, and telephone keypad tones (DTMF) are recurring patterns.

{{#ref}}
audio/README.md
{{#endref}}

### Text

If text renders normally but behaves unexpectedly, consider Unicode homoglyphs, zero-width characters, or whitespace-based encoding.

{{#ref}}
text/README.md
{{#endref}}

### Documents

PDFs and Office files are containers first; attacks usually revolve around embedded files/streams, object/relationship graphs, and ZIP extraction.

{{#ref}}
documents/README.md
{{#endref}}

### Malware and delivery-style steganography

Payload delivery can use valid-looking files, such as GIF or PNG images, that carry marker-delimited text payloads rather than hiding data in pixels.

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [NIST CSRC Glossary - Steganography](https://csrc.nist.gov/glossary/term/steganography)

{{#include ../banners/hacktricks-training.md}}
