# Stego

{{#include ../banners/hacktricks-training.md}}

This section focuses on **finding and extracting hidden data** from files (images/audio/video/documents/archives) and from text-based steganography.

If you're here for cryptographic attacks, go to the **Crypto** section.

## प्रवेश बिंदु

Approach steganography as a forensics problem: identify the real container, enumerate high-signal locations (metadata, appended data, embedded files), and only then apply content-level extraction techniques.

### वर्कफ़्लो और तिराज

एक संरचित वर्कफ़्लो जो container पहचान, metadata/string निरीक्षण, carving, और format-specific branching को प्राथमिकता देता है।
{{#ref}}
workflow/README.md
{{#endref}}

### इमेजेज

जहाँ अधिकतर CTF stego मिलता है: LSB/bit-planes (PNG/BMP), chunk/file-format weirdness, JPEG tooling, और multi-frame GIF tricks।
{{#ref}}
images/README.md
{{#endref}}

### ऑडियो

Spectrogram messages, sample LSB embedding, और telephone keypad tones (DTMF) आम तौर पर दोहराए जाने वाले पैटर्न हैं।
{{#ref}}
audio/README.md
{{#endref}}

### टेक्स्ट

यदि टेक्स्ट सामान्य रूप से प्रदर्शित होता है लेकिन अप्रत्याशित व्यवहार करता है, तो Unicode homoglyphs, zero-width characters, या whitespace-based encoding पर विचार करें।
{{#ref}}
text/README.md
{{#endref}}

### दस्तावेज़

PDFs और Office files पहले कंटेनर होते हैं; हमले आमतौर पर embedded files/streams, object/relationship graphs, और ZIP extraction के इर्द-गिर्द घूमते हैं।
{{#ref}}
documents/README.md
{{#endref}}

### Malware और delivery-style steganography

Payload delivery अक्सर valid-looking files (उदा., GIF/PNG) का उपयोग करता है जो marker-delimited text payloads रखते हैं, न कि pixel-level hiding।
{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
