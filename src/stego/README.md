# Stego

{{#include ../banners/hacktricks-training.md}}

यह section files (images/audio/video/documents/archives) और text-based steganography से **hidden data खोजने और extract करने** पर केंद्रित है।

यदि आप cryptographic attacks के लिए यहां आए हैं, तो **Crypto** section पर जाएं।

## Entry Point

Steganography को forensics problem की तरह approach करें: real container की पहचान करें, high-signal locations (metadata, appended data, embedded files) को enumerate करें, और उसके बाद ही content-level extraction techniques लागू करें।

### Workflow & triage

एक structured workflow, जो container identification, metadata/string inspection, carving और format-specific branching को प्राथमिकता देता है।

{{#ref}}
workflow/README.md
{{#endref}}

### Images

यहीं अधिकांश CTF stego होता है: LSB/bit-planes (PNG/BMP), chunk/file-format की विचित्रताएं, JPEG tooling और multi-frame GIF tricks।

{{#ref}}
images/README.md
{{#endref}}

### Audio

Spectrogram messages, sample LSB embedding और telephone keypad tones (DTMF) recurring patterns हैं।

{{#ref}}
audio/README.md
{{#endref}}

### Text

यदि text सामान्य रूप से render होता है लेकिन unexpected तरीके से behave करता है, तो Unicode homoglyphs, zero-width characters या whitespace-based encoding पर विचार करें।

{{#ref}}
text/README.md
{{#endref}}

### Documents

PDFs और Office files पहले containers होते हैं; attacks आमतौर पर embedded files/streams, object/relationship graphs और ZIP extraction पर आधारित होते हैं।

{{#ref}}
documents/README.md
{{#endref}}

### Malware and delivery-style steganography

Payload delivery में अक्सर valid-looking files (जैसे GIF/PNG) का उपयोग किया जाता है, जिनमें pixel-level hiding के बजाय marker-delimited text payloads होते हैं।

{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
