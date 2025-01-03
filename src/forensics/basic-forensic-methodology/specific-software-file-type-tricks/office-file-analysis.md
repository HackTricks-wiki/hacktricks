# Analiza plików biurowych

{{#include ../../../banners/hacktricks-training.md}}

Aby uzyskać więcej informacji, sprawdź [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). To jest tylko podsumowanie:

Microsoft stworzył wiele formatów dokumentów biurowych, z dwoma głównymi typami będącymi **formatami OLE** (takimi jak RTF, DOC, XLS, PPT) oraz **formatami Office Open XML (OOXML)** (takimi jak DOCX, XLSX, PPTX). Te formaty mogą zawierać makra, co czyni je celem dla phishingu i złośliwego oprogramowania. Pliki OOXML są strukturalnie zorganizowane jako kontenery zip, co umożliwia inspekcję poprzez rozpakowanie, ujawniając hierarchię plików i folderów oraz zawartość plików XML.

Aby zbadać struktury plików OOXML, podano polecenie do rozpakowania dokumentu oraz strukturę wyjściową. Techniki ukrywania danych w tych plikach zostały udokumentowane, co wskazuje na ciągłą innowację w zakresie ukrywania danych w wyzwaniach CTF.

Do analizy, **oletools** i **OfficeDissector** oferują kompleksowe zestawy narzędzi do badania zarówno dokumentów OLE, jak i OOXML. Narzędzia te pomagają w identyfikacji i analizie osadzonych makr, które często służą jako wektory dostarczania złośliwego oprogramowania, zazwyczaj pobierając i uruchamiając dodatkowe złośliwe ładunki. Analiza makr VBA może być przeprowadzona bez Microsoft Office, wykorzystując Libre Office, co pozwala na debugowanie z punktami przerwania i zmiennymi obserwacyjnymi.

Instalacja i użycie **oletools** są proste, z podanymi poleceniami do instalacji za pomocą pip i ekstrakcji makr z dokumentów. Automatyczne uruchamianie makr jest wyzwalane przez funkcje takie jak `AutoOpen`, `AutoExec` lub `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
{{#include ../../../banners/hacktricks-training.md}}
