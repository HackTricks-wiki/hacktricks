# Office file analysis

{{#include ../../../banners/hacktricks-training.md}}


For further information check [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). This is just a sumary:

Microsoft has created many office document formats, with two main types being **OLE formats** (like RTF, DOC, XLS, PPT) and **Office Open XML (OOXML) formats** (such as DOCX, XLSX, PPTX). These formats can include macros, making them targets for phishing and malware. OOXML files are structured as zip containers, allowing inspection through unzipping, revealing the file and folder hierarchy and XML file contents.

To explore OOXML file structures, the command to unzip a document and the output structure are given. Techniques for hiding data in these files have been documented, indicating ongoing innovation in data concealment within CTF challenges.

For analysis, **oletools** and **OfficeDissector** offer comprehensive toolsets for examining both OLE and OOXML documents. These tools help in identifying and analyzing embedded macros, which often serve as vectors for malware delivery, typically downloading and executing additional malicious payloads. Analysis of VBA macros can be conducted without Microsoft Office by utilizing Libre Office, which allows for debugging with breakpoints and watch variables.

Installation and usage of **oletools** are straightforward, with commands provided for installing via pip and extracting macros from documents. Automatic execution of macros is triggered by functions like `AutoOpen`, `AutoExec`, or `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA models are stored as an [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). The serialized model is under storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Key layout of `Global\Latest` (observed on Revit 2025):

- Nagłówek
- Dane skompresowane GZIP (rzeczywisty zserializowany graf obiektów)
- Wypełnienie zerami
- Trailer ECC (Error-Correcting Code)

Revit automatycznie naprawi niewielkie zakłócenia strumienia przy użyciu traileru ECC i odrzuci strumienie, które nie zgadzają się z ECC. Dlatego naiwnie edytowanie skompresowanych bajtów nie przetrwa: twoje zmiany zostaną albo przywrócone, albo plik zostanie odrzucony. Aby zapewnić kontrolę na poziomie bajtów nad tym, co widzi deserializator, musisz:

- Ponownie skompresuj przy użyciu implementacji gzip kompatybilnej z Revit (tak, aby skompresowane bajty, które Revit produkuje/akceptuje, odpowiadały temu, czego oczekuje).
- Ponownie oblicz trailer ECC dla strumienia z wypełnieniem, aby Revit zaakceptował zmodyfikowany strumień bez automatycznej naprawy.

Praktyczny workflow dla patching/fuzzing zawartości RFA:

1) Rozwiń dokument OLE Compound
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Edytuj `Global\Latest` stosując procedurę gzip/ECC

- Dekonstruuj `Global/Latest`: zachowaj nagłówek, rozkompresuj payload (gunzip), zmodyfikuj bajty, a następnie skompresuj ponownie za pomocą gzip używając parametrów deflate zgodnych z Revit.
- Zachowaj zero-padding i ponownie oblicz trailer ECC, aby nowe bajty zostały zaakceptowane przez Revit.
- Jeśli potrzebujesz deterministycznej reprodukcji bajt po bajcie, zbuduj minimalny wrapper wokół DLLi Revita, aby wywołać jego ścieżki gzip/gunzip oraz obliczanie ECC (jak pokazano w badaniach), lub użyj dowolnego dostępnego narzędzia pomocniczego, które odwzorowuje te semantyki.

3) Odbuduj złożony dokument OLE
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Uwagi:

- CompoundFileTool zapisuje storages/streams w systemie plików z escapingiem dla znaków nieprawidłowych w nazwach NTFS; ścieżka strumienia, której potrzebujesz, to dokładnie `Global/Latest` w drzewie wyjściowym.
- Przy dostarczaniu masowych ataków przez ecosystem plugins, które pobierają RFA z cloud storage, upewnij się, że twoje załatane RFA najpierw lokalnie przechodzi kontrole integralności Revit (gzip/ECC correct) zanim spróbujesz injekcji przez sieć.

Wgląd w eksploatację (aby pokierować, jakie bajty umieścić w gzip payload):

- Deserializator Revit odczytuje 16-bitowy indeks klasy i konstruuje obiekt. Niektóre typy są nie‑polimorficzne i nie mają vtables; wykorzystanie obsługi destructora powoduje type confusion, w której silnik wykonuje wywołanie pośrednie przez wskaźnik kontrolowany przez atakującego.
- Wybranie `AString` (indeks klasy `0x1F`) umieszcza wskaźnik na heap kontrolowany przez atakującego na offsetcie obiektu 0. Podczas pętli destructora, Revit efektywnie wykonuje:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Umieść wiele takich obiektów w zserializowanym grafie, tak aby każda iteracja pętli destruktora wykonywała jeden gadget (“weird machine”), oraz przygotuj stack pivot do konwencjonalnego x64 ROP chain.

Zobacz szczegóły budowy Windows x64 pivot/gadget tutaj:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

oraz ogólne wskazówki dotyczące ROP tutaj:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Narzędzia:

- CompoundFileTool (OSS) do rozpakowywania/odtwarzania złożonych plików OLE: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD do reverse/taint; wyłącz page heap w TTD, aby ślady były kompaktowe.
- Lokalny proxy (np. Fiddler) może symulować supply-chain delivery przez podmienianie RFA w ruchu pluginów do testów.

## Referencje

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
