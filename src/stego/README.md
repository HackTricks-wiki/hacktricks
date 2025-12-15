# Stego

{{#include ../banners/hacktricks-training.md}}

Ta sekcja koncentruje się na **znajdowaniu i wydobywaniu ukrytych danych** z plików (images/audio/video/documents/archives) oraz ze steganografii opartej na tekście.

Jeśli szukasz ataków kryptograficznych, przejdź do sekcji **Crypto**.

## Punkt wejścia

Traktuj steganografię jak problem z zakresu informatyki śledczej: zidentyfikuj rzeczywisty kontener, wymień lokalizacje o wysokim sygnale (metadata, appended data, embedded files), a dopiero potem zastosuj techniki ekstrakcji na poziomie zawartości.

### Workflow & triage

Ustrukturyzowany workflow, który priorytetyzuje identyfikację kontenera, inspekcję metadata/string, carving oraz rozgałęzianie specyficzne dla formatu.
{{#ref}}
workflow/README.md
{{#endref}}

### Images

Gdzie koncentruje się większość stego w CTF: LSB/bit-planes (PNG/BMP), chunk/file-format weirdness, JPEG tooling oraz sztuczki z multi-frame GIF.
{{#ref}}
images/README.md
{{#endref}}

### Audio

Powtarzające się wzorce: spectrogram messages, sample LSB embedding oraz telephone keypad tones (DTMF).
{{#ref}}
audio/README.md
{{#endref}}

### Text

Jeśli tekst wyświetla się normalnie, ale zachowuje się nieoczekiwanie, rozważ Unicode homoglyphs, zero-width characters lub whitespace-based encoding.
{{#ref}}
text/README.md
{{#endref}}

### Documents

PDFs i pliki Office są przede wszystkim kontenerami; ataki zwykle koncentrują się wokół embedded files/streams, object/relationship graphs oraz ZIP extraction.
{{#ref}}
documents/README.md
{{#endref}}

### Malware and delivery-style steganography

Dostarczanie payloadu często wykorzystuje pliki wyglądające na prawidłowe (np. GIF/PNG), które niosą marker-delimited text payloads, zamiast ukrywania na poziomie pikseli.
{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
