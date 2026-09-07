# Analiza plików Office

{{#include ../../../banners/hacktricks-training.md}}

Więcej informacji można znaleźć na stronie [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). To tylko podsumowanie:<sup>[[4]](#references)</sup>

Dokumenty Microsoft Office często występują w starszych formatach, takich jak RTF i opartych na OLE/CFBF DOC, XLS oraz PPT, lub w nowszych formatach **Office Open XML (OOXML)**, takich jak DOCX, XLSX i PPTX. Dokumenty Office mogą zawierać aktywną zawartość, taką jak makra, co sprawia, że są często wykorzystywane do phishingu i przenoszenia malware. Pliki OOXML są kontenerami ZIP, których hierarchię plików i zawartość XML można analizować po ich rozpakowaniu.<sup>[[3]](#references)[[4]](#references)</sup>

Aby zbadać struktury plików OOXML, przedstawiono polecenie rozpakowania dokumentu oraz wynikową strukturę. Udokumentowano techniki ukrywania danych w tych plikach, co wskazuje na ciągły rozwój metod ukrywania danych w wyzwaniach CTF.<sup>[[4]](#references)</sup>

Do analizy **oletools** i **OfficeDissector** oferują kompleksowe zestawy narzędzi do badania zarówno dokumentów OLE, jak i OOXML. Narzędzia te pomagają identyfikować i analizować osadzone makra, które często służą jako wektory dostarczania malware, zazwyczaj pobierając i wykonując dodatkowe złośliwe payloady. Analizę makr VBA można przeprowadzać bez Microsoft Office, korzystając z Libre Office, który umożliwia debugowanie z użyciem breakpointów i obserwowanych zmiennych.<sup>[[4]](#references)</sup>

Instalacja i użycie **oletools** są proste — podano polecenia instalacji za pomocą pip oraz wyodrębniania makr z dokumentów. W programie Word makra automatyczne obejmują `AutoExec` i `AutoOpen`, natomiast `Document_Open` jest procedurą zdarzenia otwarcia.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
W przypadku dokumentów Office zaszyfrowanych hasłem zobacz [grammar-driven offline recovery workflow](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

## Wykorzystywanie OLE Compound File: Autodesk Revit RFA – ponowne obliczanie ECC i kontrolowany gzip

Modele Revit RFA są przechowywane jako [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (znany również jako CFBF). Serializowany model znajduje się w storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Najważniejszy układ `Global\Latest` (zaobserwowany w Revit 2025):

- Nagłówek
- Ładunek skompresowany za pomocą GZIP (właściwy serializowany graf obiektów)
- Wypełnienie zerami
- Trailer Error-Correcting Code (ECC)

Revit automatycznie naprawia niewielkie modyfikacje streamu przy użyciu trailera ECC i odrzuca streamy, które nie są zgodne z ECC. Dlatego naiwna edycja skompresowanych bajtów nie zostanie zachowana: zmiany zostaną cofnięte albo plik zostanie odrzucony. Aby zapewnić dokładną bajtowo kontrolę nad tym, co zobaczy deserializator, należy:<sup>[[1]](#references)</sup>

- Ponownie skompresować dane za pomocą implementacji gzip zgodnej z Revit (tak aby skompresowane bajty generowane/akceptowane przez Revit odpowiadały temu, czego oczekuje).
- Ponownie obliczyć trailer ECC dla wypełnionego streamu, aby Revit zaakceptował zmodyfikowany stream bez automatycznej naprawy.

Praktyczny workflow patchowania/fuzzingu zawartości RFA:<sup>[[1]](#references)</sup>

1) Rozwiń dokument OLE compound.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Edytuj `Global\Latest` z zachowaniem zasad gzip/ECC

- Zdekonstruuj `Global/Latest`: zachowaj nagłówek, rozpakuj payload za pomocą gunzip, zmodyfikuj bajty, a następnie ponownie skompresuj za pomocą parametrów deflate zgodnych z Revit.
- Zachowaj wypełnienie zerami i ponownie oblicz trailer ECC, aby nowe bajty zostały zaakceptowane przez Revit.
- Jeśli potrzebujesz deterministycznego odtworzenia bajt po bajcie, zbuduj minimalny wrapper wokół bibliotek DLL Revit, aby wywołać ścieżki gzip/gunzip i obliczanie ECC (jak pokazano w badaniach), albo użyj dostępnego helpera replikującego tę semantykę.

3) Odbuduj dokument złożony OLE.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Uwagi:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool zapisuje storages/streams w systemie plików, stosując escaping dla znaków nieprawidłowych w nazwach NTFS; żądana ścieżka streamu to dokładnie `Global/Latest` w drzewie wyjściowym.
- W przypadku przeprowadzania masowych ataków za pośrednictwem ecosystem plugins, które pobierają RFA z cloud storage, przed próbą network injection upewnij się lokalnie, że zmodyfikowany RFA przechodzi checks integralności Revit (poprawne gzip/ECC).

Wskazówka dotycząca exploitation (ułatwiająca określenie, jakie bajty umieścić w payloadzie gzip):<sup>[[1]](#references)</sup>

- Deserializer Revit odczytuje 16-bitowy class index i konstruuje obiekt. Niektóre typy nie są polymorphic i nie mają vtables; abuse obsługi destructora prowadzi do type confusion, w którym engine wykonuje indirect call za pośrednictwem pointera kontrolowanego przez atakującego.
- Wybranie `AString` (class index `0x1F`) umieszcza kontrolowany przez atakującego heap pointer pod offsetem 0 obiektu. Podczas pętli destructora Revit zasadniczo wykonuje:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Umieść wiele takich obiektów w serializowanym grafie, aby każda iteracja pętli destruktora wykonywała jeden gadget („weird machine”), a następnie zaaranżuj stack pivot do konwencjonalnego łańcucha x64 ROP.

Szczegóły dotyczące pivot/gadget building dla Windows x64 znajdziesz tutaj:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

a ogólne wskazówki dotyczące ROP tutaj:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Narzędzia:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) do rozpakowywania/ponownego tworzenia złożonych plików OLE: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD do reverse/taint; wyłącz page heap wraz z TTD, aby zachować kompaktowość śladów.
- Lokalny proxy (np. Fiddler) może symulować dostarczanie w ramach supply chain, podmieniając pliki RFA w ruchu pluginu na potrzeby testów.

## References

- [1] [Tworzenie kompletnego exploita RCE na podstawie crasha podczas parsowania pliku RFA Autodesk Revit (blog ZDI)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Złożony plik OLE (CFBF) — dokumentacja](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [5] [Dokumentacja olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Makra automatyczne (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Zdarzenie Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
