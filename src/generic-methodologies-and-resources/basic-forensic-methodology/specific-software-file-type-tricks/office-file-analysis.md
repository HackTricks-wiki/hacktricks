# Analiza plików Office

{{#include ../../../banners/hacktricks-training.md}}


Dalsze informacje znajdziesz pod adresem [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). To tylko podsumowanie:<sup>[[4]](#references)</sup>

Firma Microsoft stworzyła wiele formatów dokumentów Office, z których dwa główne typy to **formaty OLE** (takie jak RTF, DOC, XLS, PPT) oraz **formaty Office Open XML (OOXML)** (takie jak DOCX, XLSX, PPTX). Formaty te mogą zawierać makra, co czyni je celami phishingu i malware. Pliki OOXML mają strukturę kontenerów zip, dzięki czemu można je analizować poprzez rozpakowanie, ujawniając hierarchię plików i folderów oraz zawartość plików XML.

Aby poznać strukturę plików OOXML, przedstawiono polecenie rozpakowania dokumentu oraz wynikową strukturę. Udokumentowano techniki ukrywania danych w tych plikach, co wskazuje na ciągłe powstawanie nowych sposobów ukrywania danych w wyzwaniach CTF.

Do analizy **oletools** i **OfficeDissector** oferują kompleksowe zestawy narzędzi do badania zarówno dokumentów OLE, jak i OOXML. Narzędzia te pomagają identyfikować i analizować osadzone makra, które często służą jako wektory dostarczania malware, zazwyczaj pobierając i uruchamiając dodatkowe złośliwe payloady. Analizę makr VBA można przeprowadzać bez Microsoft Office, korzystając z Libre Office, który umożliwia debugowanie z użyciem breakpointów i zmiennych obserwowanych.

Instalacja i użycie **oletools** są proste. Dostępne są polecenia umożliwiające instalację za pomocą pip oraz wyodrębnianie makr z dokumentów. Automatyczne wykonywanie makr jest uruchamiane przez funkcje takie jak `AutoOpen`, `AutoExec` lub `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Exploitation OLE Compound File: Autodesk Revit RFA – ponowne obliczanie ECC i kontrolowane gzip

Modele Revit RFA są przechowywane jako [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (znany również jako CFBF). Zserializowany model znajduje się w storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Kluczowy układ `Global\Latest` (zaobserwowany w Revit 2025):

- Nagłówek
- Payload skompresowany za pomocą GZIP (właściwy zserializowany graf obiektów)
- Wypełnienie zerami
- Stopka Error-Correcting Code (ECC)

Revit automatycznie naprawia niewielkie modyfikacje strumienia za pomocą stopki ECC i odrzuca strumienie, które nie są zgodne z ECC. Dlatego naiwna edycja skompresowanych bajtów nie będzie trwała: zmiany zostaną cofnięte albo plik zostanie odrzucony. Aby zapewnić dokładną bajtowo kontrolę nad tym, co zobaczy deserializator, musisz:

- Ponownie skompresować dane za pomocą implementacji gzip zgodnej z Revit (aby skompresowane bajty generowane/akceptowane przez Revit odpowiadały temu, czego oczekuje).
- Ponownie obliczyć stopkę ECC dla wypełnionego strumienia, aby Revit zaakceptował zmodyfikowany strumień bez automatycznej naprawy.

Praktyczny workflow patchowania/fuzzingu zawartości RFA:<sup>[[1]](#references)</sup>

1) Rozwiń dokument OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Edytuj `Global\Latest`, zachowując zasady gzip/ECC

- Zdekonstruuj `Global/Latest`: zachowaj nagłówek, rozpakuj payload za pomocą gunzip, zmodyfikuj bajty, a następnie ponownie spakuj je za pomocą parametrów deflate zgodnych z Revit.
- Zachowaj wypełnienie zerami i przelicz trailer ECC, aby nowe bajty zostały zaakceptowane przez Revit.
- Jeśli potrzebujesz deterministycznego odtworzenia bajt po bajcie, zbuduj minimalny wrapper wokół bibliotek DLL Revit, aby wywoływać ścieżki gzip/gunzip oraz obliczanie ECC (zgodnie z demonstracją w research), albo ponownie użyj dostępnego helpera, który odtwarza tę semantykę.

3) Odbuduj dokument złożony OLE
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)</sup>

- CompoundFileTool zapisuje storages/streams w systemie plików, stosując escaping dla znaków nieprawidłowych w nazwach NTFS; ścieżka streamu, której potrzebujesz, to dokładnie `Global/Latest` w drzewie wynikowym.
- Podczas przeprowadzania masowych ataków za pośrednictwem ecosystem plugins, które pobierają RFA z cloud storage, upewnij się, że zmodyfikowany RFA lokalnie przechodzi najpierw integrity checks Revit (poprawne gzip/ECC), zanim podejmiesz próbę network injection.

Exploitation insight (aby wskazać, jakie bajty umieścić w gzip payload):<sup>[[1]](#references)</sup>

- Deserializer Revit odczytuje 16-bit class index i konstruuje obiekt. Niektóre typy nie są polymorphic i nie mają vtables; nadużycie obsługi destruktora prowadzi do type confusion, w wyniku którego engine wykonuje indirect call za pośrednictwem pointera kontrolowanego przez atakującego.
- Wybranie `AString` (class index `0x1F`) umieszcza kontrolowany przez atakującego heap pointer pod offsetem 0 obiektu. Podczas pętli destruktora Revit de facto wykonuje:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Umieść wiele takich obiektów w serializowanym grafie, aby każda iteracja pętli destruktora wykonywała jeden gadget („weird machine”), a następnie przygotuj stack pivot do konwencjonalnego łańcucha x64 ROP.

Szczegóły dotyczące Windows x64 pivot/gadget building znajdziesz tutaj:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

a ogólne wskazówki dotyczące ROP tutaj:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Narzędzia:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) do rozpakowywania i ponownego budowania plików złożonych OLE: https://github.com/thezdi/CompoundFileTool<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD do reverse engineeringu/taint analysis; wyłącz page heap z TTD, aby zachować kompaktowe trace'y.
- Lokalny proxy (np. Fiddler) może symulować dostarczanie przez supply chain, podmieniając pliki RFA w ruchu pluginu na potrzeby testów.

## References

- [1] [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
