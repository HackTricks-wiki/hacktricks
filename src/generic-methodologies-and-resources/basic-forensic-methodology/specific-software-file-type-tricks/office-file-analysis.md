# Analiza plików Office

{{#include ../../../banners/hacktricks-training.md}}


Aby uzyskać więcej informacji, zobacz [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). To jest tylko podsumowanie:

Microsoft stworzył wiele formatów dokumentów Office, z dwoma głównymi typami: **OLE formats** (np. RTF, DOC, XLS, PPT) oraz **Office Open XML (OOXML) formats** (np. DOCX, XLSX, PPTX). Formatów tych mogą zawierać makra, co czyni je celem phishingu i malware. Pliki OOXML mają strukturę kontenera zip, co umożliwia ich inspekcję przez rozpakowanie, ujawniając hierarchię plików i folderów oraz zawartość plików XML.

Aby badać strukturę plików OOXML, podawane są polecenia do rozpakowania dokumentu i przykładowa struktura wynikowa. Opisano techniki ukrywania danych w tych plikach, co wskazuje na ciągłą innowację w ukrywaniu danych w wyzwaniach CTF.

Do analizy **oletools** i **OfficeDissector** oferują kompleksowe zestawy narzędzi do badania zarówno dokumentów OLE, jak i OOXML. Narzędzia te pomagają w identyfikacji i analizie osadzonych makr, które często służą jako wektory dostarczania malware, zwykle pobierając i uruchamiając dodatkowe złośliwe payloady. Analizę makr VBA można przeprowadzić bez Microsoft Office, używając Libre Office, który pozwala na debugowanie z punktami przerwania i zmiennymi obserwowanymi.

Instalacja i użycie **oletools** są proste — dostępne są polecenia instalacji przez pip oraz do wyodrębniania makr z dokumentów. Automatyczne uruchamianie makr jest wyzwalane przez funkcje takie jak `AutoOpen`, `AutoExec`, lub `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Modele Revit RFA są przechowywane jako [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). Zserializowany model znajduje się pod storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Struktura `Global\Latest` (zaobserwowana w Revit 2025):

- Header
- GZIP-compressed payload (the actual serialized object graph)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit automatycznie naprawi drobne perturbacje w strumieniu przy użyciu stopki ECC i odrzuci strumienie, które nie pasują do ECC. Dlatego naiwnie edytowanie skompresowanych bajtów nie będzie trwałe: twoje zmiany zostaną albo cofnięte, albo plik zostanie odrzucony. Aby zapewnić kontrolę na poziomie bajtu nad tym, co widzi deserializator, musisz:

- Recompress with a Revit-compatible gzip implementation (so the compressed bytes Revit produces/accepts match what it expects).
- Recompute the ECC trailer over the padded stream so Revit will accept the modified stream without auto-repairing it.

Praktyczny workflow do patchowania/fuzzowania zawartości RFA:

1) Expand the OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Edytuj Global\Latest stosując zasady gzip/ECC

- Rozłóż `Global/Latest`: zachowaj nagłówek, rozkompresuj payload za pomocą gunzip, zmodyfikuj bajty, następnie ponownie spakuj gzip używając parametrów deflate kompatybilnych z Revit.
- Zachowaj wypełnienie zerami i ponownie oblicz trailer ECC, aby nowe bajty zostały zaakceptowane przez Revit.
- Jeśli potrzebujesz deterministycznej reprodukcji bajt-po-bajcie, zbuduj minimalny wrapper wokół Revit’s DLLs, aby wywołać jego ścieżki gzip/gunzip i obliczanie ECC (jak pokazano w badaniach), lub ponownie użyj dowolnego dostępnego narzędzia pomocniczego, które replikuje te semantyki.

3) Odbuduj złożony dokument OLE
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notatki:

- CompoundFileTool zapisuje storages/streams do systemu plików z escapowaniem znaków nieprawidłowych w nazwach NTFS; ścieżka streamu, której szukasz, to dokładnie `Global/Latest` w drzewie wyjściowym.
- Przy dostarczaniu masowych ataków przez ecosystem plugins, które pobierają RFAs z cloud storage, upewnij się, że załatany RFA przechodzi lokalnie kontrole integralności Revit (gzip/ECC correct) zanim spróbujesz wstrzyknięcia przez sieć.

Exploitation insight (to guide what bytes to place in the gzip payload):

- Deserializator Revit czyta 16-bitowy indeks klasy i konstruuje obiekt. Niektóre typy są nie‑polimorficzne i nie mają vtables; nadużycie obsługi destruktorów prowadzi do type confusion, w którym silnik wykonuje wywołanie pośrednie przez attacker-controlled pointer.
- Wybranie `AString` (class index `0x1F`) umieszcza attacker-controlled heap pointer na offset 0 obiektu. Podczas pętli destruktorów, Revit w praktyce wykonuje:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Umieść wiele takich obiektów w zserializowanym grafie tak, aby każda iteracja pętli destruktora wykonała jeden gadget (“weird machine”), i zaaranżuj stack pivot do konwencjonalnego x64 ROP chain.

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Narzędzia:

- CompoundFileTool (OSS) do rozpakowywania/odbudowy OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD do reverse/taint; wyłącz page heap w TTD, aby utrzymać ślady zwarte.
- Lokalny proxy (np. Fiddler) może symulować dostarczanie w łańcuchu dostaw przez zamianę RFAs w ruchu wtyczki do testów.

## Referencje

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
