# Analiza plików Office

{{#include ../../../banners/hacktricks-training.md}}

Więcej informacji znajdziesz na stronie [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). To tylko podsumowanie:<sup>[[4]](#references)</sup>

Dokumenty Microsoft Office często występują w starszych formatach, takich jak RTF i DOC, XLS oraz PPT oparte na OLE/CFBF, lub w nowszych formatach **Office Open XML (OOXML)**, takich jak DOCX, XLSX i PPTX. Dokumenty Office mogą zawierać aktywną zawartość, taką jak makra, dlatego często są wykorzystywane do phishingu i przenoszenia malware. Pliki OOXML to kontenery ZIP, których hierarchię plików i zawartość XML można sprawdzić po rozpakowaniu.<sup>[[3]](#references)[[4]](#references)</sup>

Podano polecenie rozpakowujące dokument oraz strukturę wynikową, aby umożliwić eksplorację struktury plików OOXML. Udokumentowano techniki ukrywania danych w tych plikach, co wskazuje na nieustanny rozwój metod ukrywania danych w wyzwaniach CTF.<sup>[[4]](#references)</sup>

Do analizy **oletools** i **OfficeDissector** oferują kompleksowe zestawy narzędzi do badania dokumentów OLE i OOXML. Narzędzia te pomagają identyfikować i analizować osadzone makra, które często służą do dostarczania malware, zwykle pobierającego i uruchamiającego kolejne złośliwe payloady. Analizę makr VBA można przeprowadzić bez Microsoft Office, korzystając z LibreOffice, który umożliwia debugowanie z użyciem breakpointów i zmiennych obserwowanych.<sup>[[4]](#references)</sup>

Instalacja i używanie **oletools** są proste; podano polecenia instalacji za pomocą pip oraz wyodrębniania makr z dokumentów. W Wordzie automatyczne makra obejmują `AutoExec` i `AutoOpen`, a `Document_Open` jest procedurą zdarzenia otwarcia dokumentu.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

W przypadku dokumentów Office zaszyfrowanych hasłem zobacz [workflow odzyskiwania offline oparty na gramatyce](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

## Exploitation plików złożonych OLE: Autodesk Revit RFA – ponowne obliczanie ECC i kontrolowane użycie gzip

Modele Revit RFA są przechowywane jako [plik złożony OLE](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (czyli CFBF). Serializowany model znajduje się w magazynie/strumieniu:<sup>[[1]](#references)[[3]](#references)</sup>

- Magazyn: `Global`
- Strumień: `Latest` → `Global\Latest`

Układ `Global\Latest` (zaobserwowany w Revit 2025):

- Nagłówek
- Ładunek skompresowany za pomocą GZIP (właściwy serializowany graf obiektów)
- Wypełnienie zerami
- Końcówka z kodem korekcji błędów (ECC)

Revit automatycznie naprawia niewielkie modyfikacje strumienia za pomocą końcówki ECC i odrzuca strumienie niezgodne z ECC. Dlatego naiwna edycja skompresowanych bajtów nie zostanie zachowana: zmiany zostaną cofnięte albo plik zostanie odrzucony. Aby zapewnić dokładną kontrolę bajt po bajcie nad tym, co zobaczy deserializator, musisz:<sup>[[1]](#references)</sup>

- Ponownie skompresować dane przy użyciu implementacji gzip zgodnej z Revit (tak, aby skompresowane bajty generowane/akceptowane przez Revit były zgodne z oczekiwaniami programu).
- Ponownie obliczyć końcówkę ECC dla wypełnionego strumienia, aby Revit zaakceptował zmodyfikowany strumień bez automatycznej naprawy.

Praktyczny workflow modyfikowania/fuzzowania zawartości RFA:<sup>[[1]](#references)</sup>

1) Rozpakuj dokument złożony OLE.<sup>[[2]](#references)</sup>

```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```

2) Edytuj `Global\Latest`, zachowując zasady dotyczące gzip/ECC

- Rozłóż `Global/Latest`: zachowaj nagłówek, rozpakuj payload przez gunzip, zmodyfikuj bajty, a następnie ponownie spakuj przez gzip, używając parametrów deflate zgodnych z Revit.
- Zachowaj dopełnienie zerami i przelicz trailer ECC, aby Revit zaakceptował nowe bajty.
- Jeśli potrzebujesz deterministycznego odtworzenia bajt po bajcie, utwórz minimalny wrapper wokół bibliotek DLL Revit, który wywołuje jego ścieżki gzip/gunzip oraz obliczanie ECC (jak pokazano w badaniach), albo ponownie użyj dostępnego helpera, który odtwarza tę semantykę.

3) Odtwórz złożony dokument OLE.<sup>[[2]](#references)</sup>

```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```

Uwagi:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool zapisuje storage/streamy w systemie plików, stosując escaping dla znaków niedozwolonych w nazwach NTFS; ścieżka streamu, której szukasz, to dokładnie `Global/Latest` w drzewie wyjściowym.
- Przy przeprowadzaniu masowych ataków za pośrednictwem wtyczek ekosystemu, które pobierają RFA z cloud storage, upewnij się, że załatany plik RFA przechodzi lokalnie kontrolę integralności Revit (poprawne gzip/ECC), zanim podejmiesz próbę wstrzyknięcia przez sieć.

Wskazówki dotyczące exploita (jakie bajty umieścić w payloadzie gzip):<sup>[[1]](#references)</sup>

- Deserializator Revit odczytuje 16-bitowy indeks klasy i tworzy obiekt. Niektóre typy nie są polimorficzne i nie mają vtable; nadużycie obsługi destruktora powoduje type confusion, w wyniku którego silnik wykonuje wywołanie pośrednie przez wskaźnik kontrolowany przez atakującego.
- Wybór `AString` (indeks klasy `0x1F`) umieszcza kontrolowany przez atakującego wskaźnik sterty pod offsetem 0 obiektu. Podczas pętli destruktora Revit efektywnie wykonuje:

```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```

- Umieść wiele takich obiektów w serializowanym grafie, tak aby każda iteracja pętli destruktora wykonywała jeden gadget („weird machine”), i przygotuj stack pivot do konwencjonalnego łańcucha x64 ROP.

Szczegóły dotyczące pivotu/gadgetów w Windows x64 znajdziesz tutaj:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

Ogólne wskazówki dotyczące ROP znajdziesz tutaj:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Narzędzia:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) do rozpakowywania i ponownego składania złożonych plików OLE: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD do inżynierii wstecznej/śledzenia taint; wyłącz page heap w TTD, aby ślady były bardziej zwięzłe.
- Lokalny proxy (np. Fiddler) może symulować dostarczenie przez łańcuch dostaw, podmieniając pliki RFA w ruchu wtyczki na potrzeby testów.

## References

- [1] [Tworzenie pełnego exploita RCE na podstawie awarii podczas parsowania pliku Autodesk Revit RFA (blog ZDI)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Dokumentacja złożonego pliku OLE (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Przewodnik terenowy CTF z zakresu analizy śledczej](https://trailofbits.github.io/ctf/forensics/)
- [5] [Dokumentacja olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Makra automatyczne (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Zdarzenie Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
