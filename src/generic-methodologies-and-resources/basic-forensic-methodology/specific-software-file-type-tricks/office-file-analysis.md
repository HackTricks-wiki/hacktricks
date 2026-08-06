# Analiza plików Office

{{#include ../../../banners/hacktricks-training.md}}


Więcej informacji znajdziesz na stronie [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Poniżej znajduje się jedynie podsumowanie:<sup>[[4]](#references)</sup>

Firma Microsoft stworzyła wiele formatów dokumentów Office, z których dwa główne typy to **formaty OLE** (takie jak RTF, DOC, XLS, PPT) oraz **formaty Office Open XML (OOXML)** (takie jak DOCX, XLSX, PPTX). Formaty te mogą zawierać macros, przez co stają się celami phishingu i malware. Pliki OOXML mają strukturę kontenerów zip, co umożliwia ich inspekcję poprzez rozpakowanie i ujawnia hierarchię plików i folderów oraz zawartość plików XML.

Aby poznać struktury plików OOXML, przedstawiono polecenie rozpakowujące dokument oraz strukturę wynikową. Udokumentowano techniki ukrywania danych w tych plikach, co wskazuje na ciągłe innowacje w zakresie ukrywania danych w wyzwaniach CTF.

Do analizy **oletools** i **OfficeDissector** oferują kompleksowe zestawy narzędzi do badania zarówno dokumentów OLE, jak i OOXML. Narzędzia te pomagają identyfikować i analizować osadzone macros, które często służą jako wektory dostarczania malware, zazwyczaj pobierając i uruchamiając dodatkowe złośliwe payloads. Analizę VBA macros można przeprowadzać bez Microsoft Office, korzystając z Libre Office, który umożliwia debugowanie przy użyciu breakpointów i obserwowanych zmiennych.

Instalacja i użycie **oletools** są proste; dostępne są polecenia umożliwiające instalację za pomocą pip oraz wyodrębnianie macros z dokumentów. Automatyczne wykonywanie macros jest wyzwalane przez funkcje takie jak `AutoOpen`, `AutoExec` lub `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Eksploatacja OLE Compound File: Autodesk Revit RFA – recomputacja ECC i kontrolowany gzip

Modele Revit RFA są przechowywane jako [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (znany również jako CFBF). Zserializowany model znajduje się w storage/stream:<sup>[[1]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Kluczowy układ `Global\Latest` (zaobserwowany w Revit 2025):

- Nagłówek
- Payload skompresowany za pomocą GZIP (właściwy zserializowany graf obiektów)
- Wypełnienie zerami
- Trailer Error-Correcting Code (ECC)

Revit automatycznie naprawia niewielkie modyfikacje strumienia za pomocą trailera ECC i odrzuca strumienie, które nie są zgodne z ECC. Dlatego naiwna edycja skompresowanych bajtów nie będzie trwała: zmiany zostaną wycofane albo plik zostanie odrzucony. Aby zapewnić dokładną bajtowo kontrolę nad tym, co zobaczy deserializator, musisz:

- Ponownie skompresować dane za pomocą implementacji gzip kompatybilnej z Revit, aby skompresowane bajty generowane/akceptowane przez Revit odpowiadały temu, czego oczekuje.
- Ponownie obliczyć trailer ECC dla wypełnionego strumienia, aby Revit zaakceptował zmodyfikowany strumień bez automatycznej naprawy.

Praktyczny workflow patchowania/fuzzingu zawartości RFA:<sup>[[1]](#references)</sup>

1) Rozwiń dokument OLE compound
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Edytuj Global\Latest z zachowaniem zasad gzip/ECC

- Zdekonstruuj `Global/Latest`: zachowaj nagłówek, rozpakuj payload za pomocą gunzip, zmodyfikuj bajty, a następnie ponownie skompresuj za pomocą gzip, używając parametrów deflate zgodnych z Revit.
- Zachowaj wypełnienie zerami i ponownie oblicz trailer ECC, aby nowe bajty zostały zaakceptowane przez Revit.
- Jeśli potrzebujesz deterministycznego odtworzenia bajt po bajcie, zbuduj minimalny wrapper wokół bibliotek DLL Revit, aby wywołać ścieżki gzip/gunzip i obliczanie ECC (zgodnie z demonstracją w research), albo ponownie użyj dowolnego dostępnego helpera, który odwzorowuje tę semantykę.

3) Odbuduj złożony dokument OLE
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)</sup>

- CompoundFileTool zapisuje storages/streams w systemie plików, stosując escaping dla znaków nieprawidłowych w nazwach NTFS; ścieżka streamu, której potrzebujesz, to dokładnie `Global/Latest` w drzewie wyjściowym.
- Przy przeprowadzaniu masowych ataków za pośrednictwem ecosystem plugins, które pobierają RFA z cloud storage, przed podjęciem próby network injection upewnij się lokalnie, że poprawiony RFA przechodzi checks integralności Revit (prawidłowe gzip/ECC).

Exploitation insight (aby wskazać, jakie bajty umieścić w gzip payload):<sup>[[1]](#references)</sup>

- Deserializer Revit odczytuje 16-bitowy class index i konstruuje obiekt. Niektóre typy nie są polymorphic i nie mają vtables; nadużycie obsługi destruktora prowadzi do type confusion, w wyniku którego engine wykonuje indirect call przez pointer kontrolowany przez attackera.
- Wybranie `AString` (class index `0x1F`) umieszcza kontrolowany przez attackera heap pointer na offset 0 obiektu. Podczas pętli destruktora Revit efektywnie wykonuje:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Umieść wiele takich obiektów w serializowanym grafie, aby każda iteracja pętli destruktora wykonywała jeden gadget („weird machine”), a następnie przygotuj stack pivot do konwencjonalnego łańcucha ROP dla x64.

Szczegóły dotyczące pivotowania/gadgetów dla Windows x64 znajdziesz tutaj:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

a ogólne wskazówki dotyczące ROP tutaj:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Narzędzia:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) do rozpakowywania/odtwarzania plików złożonych OLE: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD do reverse engineeringu/taint analysis; wyłącz page heap wraz z TTD, aby zachować zwięzłość śladów.
- Lokalny proxy (np. Fiddler) może symulować dostarczanie w ramach supply chain, podmieniając pliki RFA w ruchu wtyczki na potrzeby testów.

## Referencje

- [1] [Tworzenie pełnego exploita RCE na podstawie crasha w analizie pliku Autodesk Revit RFA (blog ZDI)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Plik złożony OLE (CFBF) — dokumentacja](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
