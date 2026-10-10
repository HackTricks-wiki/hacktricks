# Stego

{{#include ../banners/hacktricks-training.md}}

Ta sekcja skupia się na **znajdowaniu i wyodrębnianiu ukrytych danych** z obrazów, dźwięku, wideo, dokumentów, archiwów i tekstu. Steganografia ukrywa istnienie komunikacji, osadzając dane w innych danych.<sup>[[1]](#references)</sup>

Jeśli szukasz ataków kryptograficznych, przejdź do sekcji **Crypto**.

## Punkt wejścia

Podejdź do steganografii jak do problemu z zakresu informatyki śledczej: zidentyfikuj właściwy kontener, sprawdź najważniejsze miejsca (metadane, dołączone dane, osadzone pliki), a dopiero potem zastosuj techniki wyodrębniania właściwe dla danego rodzaju zawartości.

### Przebieg pracy i wstępna analiza

Ustrukturyzowany przebieg pracy, który nadaje priorytet identyfikacji kontenera, analizie metadanych i ciągów znaków, carvingowi oraz rozgałęzieniu analizy zależnie od formatu.

{{#ref}}
workflow/README.md
{{#endref}}

### Obrazy

Większość stego z CTF: LSB/płaszczyzny bitowe (PNG/BMP), nietypowe cechy chunków i formatów plików, narzędzia do JPEG oraz sztuczki z wieloklatkowymi plikami GIF.

{{#ref}}
images/README.md
{{#endref}}

### Dźwięk

Wiadomości w spektrogramach, osadzanie w LSB próbek oraz tony klawiatury telefonicznej (DTMF) to często spotykane wzorce.

{{#ref}}
audio/README.md
{{#endref}}

### Tekst

Jeśli tekst wygląda normalnie, ale zachowuje się nieoczekiwanie, rozważ homoglify Unicode, znaki o zerowej szerokości lub kodowanie oparte na białych znakach.

{{#ref}}
text/README.md
{{#endref}}

### Dokumenty

PDF-y i pliki Office to przede wszystkim kontenery; ataki zwykle koncentrują się na osadzonych plikach/strumieniach, grafach obiektów i relacji oraz ekstrakcji ZIP.

{{#ref}}
documents/README.md
{{#endref}}

### Złośliwe oprogramowanie i steganografia w sposobie dostarczania

Do dostarczania ładunków można używać plików wyglądających na prawidłowe, takich jak obrazy GIF lub PNG, które zawierają tekstowe ładunki rozdzielone znacznikami, zamiast ukrywać dane w pikselach.

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [Słownik NIST CSRC - Steganografia](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
