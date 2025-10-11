# Analiza plików Office

{{#include ../../../banners/hacktricks-training.md}}


For further information check [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). To tylko podsumowanie:

Microsoft stworzył wiele formatów dokumentów Office, z dwoma głównymi typami będącymi **OLE formats** (np. RTF, DOC, XLS, PPT) oraz **Office Open XML (OOXML) formats** (takimi jak DOCX, XLSX, PPTX). Te formaty mogą zawierać macros, co czyni je celem phishingu i malware. Pliki OOXML mają strukturę kontenera zip, co pozwala na ich analizę przez rozpakowanie, ujawniając hierarchię plików i folderów oraz zawartość plików XML.

Aby zbadać strukturę plików OOXML, podane jest polecenie do rozpakowania dokumentu oraz wynikowa struktura. Techniki ukrywania danych w tych plikach zostały udokumentowane, co wskazuje na ciągłą innowację w ukrywaniu danych w wyzwaniach CTF.

Do analizy **oletools** i **OfficeDissector** oferują kompleksowy zestaw narzędzi do badania zarówno dokumentów OLE, jak i OOXML. Narzędzia te pomagają w identyfikacji i analizie osadzonych macros, które często służą jako wektory dostarczania malware, zazwyczaj pobierając i uruchamiając dodatkowe złośliwe payloady. Analizę macros VBA można przeprowadzić bez Microsoft Office, używając Libre Office, który umożliwia debugowanie z breakpointami i watch variables.

Instalacja i użycie **oletools** są proste — dostępne są polecenia instalacji przez pip oraz wyodrębniania macros z dokumentów. Automatyczne uruchamianie macros jest wywoływane przez funkcje takie jak `AutoOpen`, `AutoExec` lub `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Eksploatacja OLE Compound File: Autodesk Revit RFA – ponowne obliczenie ECC i kontrolowany gzip

Revit RFA models are stored as an [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). The serialized model is under storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Key layout of `Global\Latest` (observed on Revit 2025):

- Nagłówek
- GZIP-compressed payload (faktyczny zserializowany graf obiektów)
- Wypełnienie zerami
- Trailer z kodem korekcyjnym (Error-Correcting Code, ECC)

Revit will auto-repair small perturbations to the stream using the ECC trailer and will reject streams that don’t match the ECC. Therefore, naïvely editing the compressed bytes won’t persist: your changes are either reverted or the file is rejected. To ensure byte-accurate control over what the deserializer sees you must:

- Recompress with a Revit-compatible gzip implementation (so the compressed bytes Revit produces/accepts match what it expects).
- Recompute the ECC trailer over the padded stream so Revit will accept the modified stream without auto-repairing it.

Practical workflow for patching/fuzzing RFA contents:

1) Rozwiń dokument OLE compound
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Edytuj Global\Latest zgodnie z zasadami gzip/ECC

- Rozbij `Global/Latest`: zachowaj nagłówek, rozkompresuj payload (gunzip), zmodyfikuj bajty, a następnie ponownie skompresuj (gzip) używając parametrów deflate kompatybilnych z Revit.
- Zachowaj zero-padding i przelicz trailer ECC, aby nowe bajty były akceptowane przez Revit.
- Jeśli potrzebujesz deterministycznej reprodukcji bajt po bajcie, zbuduj minimalny wrapper wokół Revit’s DLLs, aby wywoływać jego ścieżki gzip/gunzip oraz obliczanie ECC (jak pokazano w badaniach), albo ponownie użyj dowolnego dostępnego helpera, który odtwarza te semantyki.

3) Odbuduj dokument złożony OLE
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Uwagi:

- CompoundFileTool zapisuje storages/streams w systemie plików, stosując escapowanie znaków nieprawidłowych w nazwach NTFS; ścieżka strumienia, której chcesz, to dokładnie `Global/Latest` w drzewie wyjściowym.
- Przy dostarczaniu masowych ataków przez pluginy ekosystemu, które pobierają RFAs z cloud storage, upewnij się najpierw lokalnie, że załatany RFA przechodzi kontrole integralności Revit (gzip/ECC poprawne), zanim spróbujesz wstrzyknięcia przez sieć.

Exploitation insight (to guide what bytes to place in the gzip payload):

- The Revit deserializer reads a 16-bit class index and constructs an object. Certain types are non‑polymorphic and lack vtables; abusing destructor handling yields a type confusion where the engine executes an indirect call through an attacker-controlled pointer.
- Picking `AString` (class index `0x1F`) places an attacker-controlled heap pointer at object offset 0. During the destructor loop, Revit effectively executes:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Umieść wiele takich obiektów w zserializowanym grafie, tak aby każda iteracja pętli destruktora wykonywała jeden gadget („weird machine”), i przygotuj stack pivot do konwencjonalnego x64 ROP chain.

Zobacz szczegóły dotyczące Windows x64 pivot/gadget tutaj:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

i ogólne wskazówki dotyczące ROP tutaj:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Narzędzia:

- CompoundFileTool (OSS) do rozpakowywania/odbudowy plików OLE Compound: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD do reverse/taint; wyłącz page heap przy użyciu TTD, aby utrzymać ślady zwarte.
- Lokalny proxy (np. Fiddler) może symulować dostawę w supply-chain, podmieniając RFAs w ruchu wtyczek do celów testowych.

## Odniesienia

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
