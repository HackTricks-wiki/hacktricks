# Klonowanie strony internetowej

{{#include ../../banners/hacktricks-training.md}}

W ramach oceny phishingowej czasami przydatne może być całkowite **sklonowanie/zrzut strony internetowej**.

Pamiętaj, że do sklonowanej strony internetowej możesz również dodać payloady, takie jak hook BeEF, aby „kontrolować” kartę użytkownika.

W tym celu możesz użyć różnych narzędzi:

## wget

Poniższe polecenie korzysta z trybów mirrorowania, pobierania wymaganych elementów strony, konwersji linków i dostosowywania rozszerzeń w programie Wget, a następnie udostępnia pobrane pliki z bieżącego katalogu za pomocą modułu `http.server` programu Python na porcie 8000.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```
## goclone

Repozytorium goclone opisuje narzędzie jako pobierające stronę internetową do lokalnego katalogu przy zachowaniu struktury jej względnych odnośników oraz dokumentuje wywołanie `goclone <url>`.<sup>[[3]](#references)</sup>
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## Zestaw narzędzi inżynierii społecznej

Repozytorium Social-Engineer Toolkit określa SET jako open-source framework do pentestingu przeznaczony do autoryzowanych ocen z zakresu inżynierii społecznej.<sup>[[4]](#references)</sup>
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
## References

- [1] [Instrukcja GNU Wget](https://www.gnu.org/software/wget/manual/wget.html)
- [2] [Dokumentacja Python `http.server`](https://docs.python.org/3/library/http.server.html)
- [3] [Repozytorium goclone](https://github.com/imthaghost/goclone)
- [4] [Repozytorium Social-Engineer Toolkit](https://github.com/trustedsec/social-engineer-toolkit)
{{#include ../../banners/hacktricks-training.md}}
