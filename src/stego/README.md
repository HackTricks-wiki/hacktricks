# Stego

{{#include ../banners/hacktricks-training.md}}

Ta sekcja koncentruje się na **znajdowaniu i wyodrębnianiu ukrytych danych** z plików (obrazów/audio/wideo/dokumentów/archiwów) oraz ze steganografii tekstowej.

Jeśli interesują Cię ataki kryptograficzne, przejdź do sekcji **Crypto**.

## Punkt wyjścia

Podchodź do steganografii jak do problemu z dziedziny forensics: zidentyfikuj rzeczywisty kontener, przeanalizuj lokalizacje o wysokiej wartości sygnału (metadane, dołączone dane, osadzone pliki), a dopiero potem stosuj techniki ekstrakcji na poziomie zawartości.

### Workflow i triage

Ustrukturyzowany workflow, który priorytetowo traktuje identyfikację kontenera, inspekcję metadanych/stringów, carving oraz rozgałęzienia zależne od formatu.

{{#ref}}
workflow/README.md
{{#endref}}

### Obrazy

To właśnie tutaj występuje większość stego w CTF: LSB/bit-planes (PNG/BMP), nietypowe elementy chunków/formatów plików, narzędzia do JPEG oraz sztuczki z wieloklatkowymi GIF-ami.

{{#ref}}
images/README.md
{{#endref}}

### Audio

Wiadomości w spectrogramach, osadzanie LSB w próbkach oraz tony klawiatur telefonicznych (DTMF) to powtarzające się wzorce.

{{#ref}}
audio/README.md
{{#endref}}

### Tekst

Jeśli tekst renderuje się normalnie, ale zachowuje się nieoczekiwanie, rozważ Unicode homoglyphs, znaki zero-width lub encoding oparty na whitespace.

{{#ref}}
text/README.md
{{#endref}}

### Dokumenty

PDF-y i pliki Office są przede wszystkim kontenerami; ataki zwykle koncentrują się na osadzonych plikach/strumieniach, grafach obiektów/relacji oraz ekstrakcji ZIP.

{{#ref}}
documents/README.md
{{#endref}}

### Steganografia malware i delivery-style

Delivery payloadów często wykorzystuje pliki wyglądające na prawidłowe (np. GIF/PNG), które zawierają tekstowe payloady rozdzielone markerami, zamiast ukrywania danych na poziomie pikseli.

{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
