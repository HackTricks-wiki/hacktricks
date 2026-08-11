# Analiza plików Office

{{#include ../../../banners/hacktricks-training.md}}

Więcej informacji znajdziesz na stronie [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Poniżej znajduje się jedynie podsumowanie:<sup>[[4]](#references)</sup>

Dokumenty Microsoft Office często występują jako starsze formaty, takie jak RTF i DOC, XLS oraz PPT oparte na OLE/CFBF, lub jako nowsze formaty **Office Open XML (OOXML)**, takie jak DOCX, XLSX i PPTX. Dokumenty Office mogą zawierać aktywną zawartość, taką jak makra, przez co często są wykorzystywane w phishingu i jako nośniki malware. Pliki OOXML są kontenerami ZIP, których hierarchię plików i zawartość XML można analizować po ich rozpakowaniu.<sup>[[3]](#references)[[4]](#references)</sup>

Aby zbadać struktury plików OOXML, przedstawiono polecenie rozpakowania dokumentu oraz wynikową strukturę. Udokumentowano techniki ukrywania danych w tych plikach, co wskazuje na ciągły rozwój metod ukrywania danych w ramach wyzwań CTF.<sup>[[4]](#references)</sup>

Do analizy **oletools** i **OfficeDissector** oferują kompleksowe zestawy narzędzi do badania zarówno dokumentów OLE, jak i OOXML. Narzędzia te pomagają identyfikować i analizować osadzone makra, które często służą jako wektory dostarczania malware, zazwyczaj pobierając i uruchamiając dodatkowe złośliwe payloady. Analizę makr VBA można przeprowadzać bez Microsoft Office, korzystając z Libre Office, który umożliwia debugowanie z użyciem breakpointów i obserwowanych zmiennych.<sup>[[4]](#references)</sup>

Instalacja i użycie **oletools** są proste; dostępne są polecenia instalacji za pomocą pip oraz wyodrębniania makr z dokumentów. W programie Word makra automatyczne obejmują `AutoExec` i `AutoOpen`, natomiast `Document_Open` jest procedurą zdarzenia otwarcia.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Modele Revit RFA są przechowywane jako [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (znany również jako CFBF). Zserializowany model znajduje się w storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Kluczowy układ `Global\Latest` (zaobserwowany w Revit 2025):

- Header
- Payload skompresowany za pomocą GZIP (właściwy zserializowany object graph)
- Wypełnienie zerami
- Trailer Error-Correcting Code (ECC)

Revit automatycznie naprawi niewielkie zmiany w streamie za pomocą trailera ECC i odrzuci streamy, które nie są zgodne z ECC. Dlatego naiwna edycja skompresowanych bajtów nie będzie trwała: zmiany zostaną cofnięte albo plik zostanie odrzucony. Aby zapewnić dokładną co do bajtu kontrolę nad tym, co zobaczy deserializer, musisz:<sup>[[1]](#references)</sup>

- Ponownie skompresować dane za pomocą implementacji gzip kompatybilnej z Revit (aby skompresowane bajty generowane i akceptowane przez Revit były zgodne z oczekiwaniami).
- Ponownie obliczyć trailer ECC dla wypełnionego streamu, aby Revit zaakceptował zmodyfikowany stream bez automatycznej naprawy.

Praktyczny workflow patching/fuzzing zawartości RFA:<sup>[[1]](#references)</sup>

1) Rozwiń dokument OLE compound.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Edytuj `Global\Latest`, zachowując zasady gzip/ECC

- Rozłóż `Global/Latest`: zachowaj nagłówek, rozpakuj payload za pomocą gunzip, zmodyfikuj bajty, a następnie ponownie spakuj za pomocą gzip, używając parametrów deflate zgodnych z Revit.
- Zachowaj wypełnienie zerami i ponownie oblicz trailer ECC, aby nowe bajty zostały zaakceptowane przez Revit.
- Jeśli potrzebujesz deterministycznego odtworzenia bajt po bajcie, zbuduj minimalny wrapper wokół bibliotek DLL Revit, aby wywołać jego ścieżki gzip/gunzip i obliczanie ECC (jak pokazano w badaniach), albo ponownie użyj dostępnego helpera, który odwzorowuje tę semantykę.

3) Odtwórz dokument złożony OLE.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool zapisuje storages/streams w systemie plików, stosując escaping znaków nieprawidłowych w nazwach NTFS; ścieżka streamu, której potrzebujesz, to dokładnie `Global/Latest` w drzewie wyjściowym.
- Podczas przeprowadzania masowych ataków za pośrednictwem ecosystem plugins, które pobierają RFA z cloud storage, upewnij się, że zmodyfikowany RFA przechodzi lokalnie kontrole integralności Revit (poprawne gzip/ECC), zanim podejmiesz próbę network injection.

Wskazówka dotycząca exploitation (pomocna przy określaniu, jakie bajty umieścić w gzip payload):<sup>[[1]](#references)</sup>

- Deserializer Revit odczytuje 16-bitowy class index i konstruuje obiekt. Niektóre typy nie są polymorphic i nie mają vtable; abuse obsługi destruktora prowadzi do type confusion, w którym engine wykonuje indirect call za pośrednictwem pointera kontrolowanego przez attackera.
- Wybranie `AString` (class index `0x1F`) umieszcza kontrolowany przez attackera heap pointer pod offsetem 0 obiektu. W pętli destruktora Revit efektywnie wykonuje:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Umieść wiele takich obiektów w serializowanym grafie, aby każda iteracja pętli destruktora wykonywała jeden gadget („weird machine”), i zaaranżuj stack pivot do konwencjonalnego łańcucha x64 ROP.

Szczegóły dotyczące Windows x64 pivot/gadget building znajdziesz tutaj:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

a ogólne wskazówki dotyczące ROP tutaj:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Narzędzia:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) do rozwijania/odbudowywania plików złożonych OLE: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD do reverse/taint; wyłącz page heap z TTD, aby zachować kompaktowe ślady.
- Lokalny proxy (np. Fiddler) może symulować dostarczanie w łańcuchu dostaw, zamieniając RFA w ruchu pluginu na potrzeby testów.

## References

- [1] [Tworzenie kompletnego exploita RCE na podstawie crasha w analizie plików RFA programu Autodesk Revit (blog ZDI)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Dokumentacja plików złożonych OLE (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Przewodnik terenowy Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [5] [Dokumentacja olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Zdarzenie Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
