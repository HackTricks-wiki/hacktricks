# Stego

{{#include ../banners/hacktricks-training.md}}

Ta sekcja koncentruje się na **znajdowaniu i wydobywaniu ukrytych danych** z obrazów, dźwięku, wideo, dokumentów, archiwów i tekstu. Steganografia ukrywa istnienie komunikacji, osadzając dane wewnątrz innych danych.<sup>[[1]](#references)</sup>

Jeśli szukasz ataków kryptograficznych, przejdź do sekcji **Crypto**.

## Punkt wejścia

Traktuj steganografię jak problem analizy kryminalistycznej: zidentyfikuj rzeczywisty kontener, przeanalizuj lokalizacje o wysokiej wartości sygnału (metadane, dołączone dane, osadzone pliki), a dopiero potem zastosuj techniki ekstrakcji na poziomie zawartości.

### Workflow i triage

Ustrukturyzowany workflow, który nadaje priorytet identyfikacji kontenera, inspekcji metadanych i ciągów znaków, carvingowi oraz rozgałęzieniom zależnym od formatu.

{{#ref}}
workflow/README.md
{{#endref}}

### Obrazy

To właśnie tutaj znajduje się większość stego w CTF: LSB/płaszczyzny bitowe (PNG/BMP), nietypowe elementy chunków i formatów plików, narzędzia do JPEG oraz sztuczki z wieloklatkowymi GIF-ami.

{{#ref}}
images/README.md
{{#endref}}

### Dźwięk

Komunikaty w spektrogramach, osadzanie w LSB próbek oraz tony klawiatur telefonicznych (DTMF) to powtarzające się wzorce.

{{#ref}}
audio/README.md
{{#endref}}

### Tekst

Jeśli tekst wyświetla się normalnie, ale zachowuje się nieoczekiwanie, rozważ homoglifы Unicode, znaki o zerowej szerokości lub kodowanie oparte na białych znakach.

{{#ref}}
text/README.md
{{#endref}}

### Dokumenty

PDF-y i pliki Office to przede wszystkim kontenery; ataki zwykle koncentrują się na osadzonych plikach/strumieniach, grafach obiektów i relacji oraz ekstrakcji ZIP.

{{#ref}}
documents/README.md
{{#endref}}

### Steganografia w malware i dostarczaniu payloadów

Dostarczanie payloadów może wykorzystywać pliki wyglądające na prawidłowe, takie jak obrazy GIF lub PNG, które zawierają tekstowe payloady oddzielone znacznikami, zamiast ukrywać dane w pikselach.

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [Glosariusz NIST CSRC - Steganografia](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
