# Stego

{{#include ../banners/hacktricks-training.md}}

यह सेक्शन images, audio, video, documents, archives और text से **छिपा हुआ डेटा ढूँढ़ने और निकालने** पर केंद्रित है। Steganography, डेटा के भीतर डेटा एम्बेड करके संचार के अस्तित्व को छिपाती है।<sup>[[1]](#references)</sup>

अगर आप cryptographic attacks के लिए यहाँ आए हैं, तो **Crypto** सेक्शन पर जाएँ।

## शुरुआती बिंदु

Steganography को फॉरेंसिक समस्या की तरह देखें: असली कंटेनर की पहचान करें, उच्च-सिग्नल वाली जगहों (metadata, जोड़ा गया डेटा, embedded files) की जाँच करें, और उसके बाद ही content-level extraction techniques लागू करें।

### कार्यप्रवाह और प्रारंभिक जाँच

एक व्यवस्थित कार्यप्रवाह, जिसमें कंटेनर की पहचान, metadata/string inspection, carving और format-specific branching को प्राथमिकता दी जाती है।

{{#ref}}
workflow/README.md
{{#endref}}

### Images

अधिकांश CTF stego यहीं मिलता है: LSB/bit-planes (PNG/BMP), chunk/file-format की विचित्रताएँ, JPEG tooling और multi-frame GIF tricks।

{{#ref}}
images/README.md
{{#endref}}

### Audio

Spectrogram messages, sample LSB embedding और telephone keypad tones (DTMF) बार-बार दिखने वाले पैटर्न हैं।

{{#ref}}
audio/README.md
{{#endref}}

### Text

अगर text सामान्य रूप से दिखता है, लेकिन अप्रत्याशित ढंग से व्यवहार करता है, तो Unicode homoglyphs, zero-width characters या whitespace-based encoding पर विचार करें।

{{#ref}}
text/README.md
{{#endref}}

### Documents

PDFs और Office files पहले कंटेनर होते हैं; हमले आमतौर पर embedded files/streams, object/relationship graphs और ZIP extraction के इर्द-गिर्द होते हैं।

{{#ref}}
documents/README.md
{{#endref}}

### Malware और delivery-style steganography

Payload delivery में GIF या PNG images जैसी सामान्य दिखने वाली files का उपयोग हो सकता है, जिनमें pixels के भीतर डेटा छिपाने के बजाय marker-delimited text payloads होते हैं।

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [NIST CSRC शब्दावली - Steganography](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
