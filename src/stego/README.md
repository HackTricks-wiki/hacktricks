# Stego

{{#include ../banners/hacktricks-training.md}}

यह section images, audio, video, documents, archives और text से **छिपे हुए data को खोजने और extract करने** पर केंद्रित है। Steganography, data को अन्य data के अंदर embed करके communication के अस्तित्व को छिपाती है।<sup>[[1]](#references)</sup>

यदि आप cryptographic attacks के लिए आए हैं, तो **Crypto** section पर जाएँ।

## Entry Point

Steganography को forensics problem की तरह approach करें: real container की पहचान करें, high-signal locations (metadata, appended data, embedded files) को enumerate करें, और उसके बाद ही content-level extraction techniques लागू करें।

### Workflow & triage

एक structured workflow, जो container identification, metadata/string inspection, carving और format-specific branching को प्राथमिकता देता है।

{{#ref}}
workflow/README.md
{{#endref}}

### Images

अधिकांश CTF stego यहीं मिलता है: LSB/bit-planes (PNG/BMP), chunk/file-format की विचित्रताएँ, JPEG tooling और multi-frame GIF tricks।

{{#ref}}
images/README.md
{{#endref}}

### Audio

Spectrogram messages, sample LSB embedding और telephone keypad tones (DTMF) बार-बार दिखाई देने वाले patterns हैं।

{{#ref}}
audio/README.md
{{#endref}}

### Text

यदि text सामान्य रूप से render होता है लेकिन अप्रत्याशित व्यवहार करता है, तो Unicode homoglyphs, zero-width characters या whitespace-based encoding पर विचार करें।

{{#ref}}
text/README.md
{{#endref}}

### Documents

PDFs और Office files पहले containers होते हैं; attacks आमतौर पर embedded files/streams, object/relationship graphs और ZIP extraction के इर्द-गिर्द होते हैं।

{{#ref}}
documents/README.md
{{#endref}}

### Malware and delivery-style steganography

Payload delivery में valid-looking files, जैसे GIF या PNG images, का उपयोग किया जा सकता है, जिनमें pixels के अंदर data छिपाने के बजाय marker-delimited text payloads होते हैं।

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [NIST CSRC Glossary - Steganography](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
