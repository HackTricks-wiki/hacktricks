# Analiza Office fajlova

{{#include ../../../banners/hacktricks-training.md}}


Za više informacija pogledajte [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Ovo je samo rezime:

Microsoft je kreirao mnogo Office formata dokumenata, sa dve glavne vrste: **OLE formats** (like RTF, DOC, XLS, PPT) i **Office Open XML (OOXML) formats** (such as DOCX, XLSX, PPTX). Ovi formati mogu sadržati makroe, zbog čega su česti ciljevi phishinga i malware. OOXML fajlovi su strukturirani kao zip kontejneri, što omogućava pregled raspakivanjem i otkrivanje hijerarhije fajlova i foldera kao i sadržaja XML fajlova.

Da biste istražili OOXML strukturu fajlova, dat je naredba za unzip dokumenta i izlazna struktura. Tehnike skrivanja podataka u ovim fajlovima su dokumentovane, što ukazuje na stalne inovacije u skrivanju podataka unutar CTF izazova.

Za analizu, **oletools** i **OfficeDissector** nude sveobuhvatan set alata za ispitivanje kako OLE tako i OOXML dokumenata. Ovi alati pomažu u identifikaciji i analizi ugrađenih makroa, koji često služe kao vektori za isporuku malvera, obično preuzimanjem i izvršavanjem dodatnih zlonamernih payload-a. Analiza VBA makroa može se izvršiti bez Microsoft Office koristeći Libre Office, koji omogućava debugging sa breakpoint-ima i watch varijablama.

Instalacija i upotreba **oletools** je jednostavna, sa komandama za instalaciju putem pip i izdvajanje makroa iz dokumenata. Automatsko izvršavanje makroa aktivira se funkcijama kao što su `AutoOpen`, `AutoExec`, ili `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File eksploatacija: Autodesk Revit RFA – ECC rekalkulacija i kontrolisani gzip

Revit RFA modeli se čuvaju kao [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). Serijalizovani model se nalazi u storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Ključna struktura `Global\Latest` (uočeno u Revit 2025):

- Zaglavlje
- GZIP-kompresovani payload (stvarni serijalizovani graf objekata)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit će automatski ispraviti male perturbacije u streamu koristeći ECC trailer i odbaciti streamove koji se ne poklapaju sa ECC-om. Dakle, naivno menjanje kompresovanih bajtova neće ostati: vaše izmene će biti ili poništene ili će fajl biti odbijen. Da biste obezbedili kontrolu tačnu na nivou bajta nad onim što deserializer vidi, morate:

- Ponovo kompresovati koristeći Revit-kompatibilnu gzip implementaciju (tako da kompresovani bajtovi koje Revit proizvodi/prihtvata odgovaraju onome što očekuje).
- Ponovo izračunati ECC trailer preko popunjenog streama tako da Revit prihvati izmenjeni stream bez automatske ispravke.

Praktičan tok rada za patching/fuzzing RFA sadržaja:

1) Raspakujte OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Izmenite Global\Latest koristeći gzip/ECC disciplinu

- Rasklopite `Global/Latest`: zadržite header, gunzip-ujte payload, mutirajte bytes, zatim ponovo gzip-ujte koristeći Revit-compatible deflate parameters.
- Sačuvajte zero-padding i ponovo izračunajte ECC trailer tako da Revit prihvati nove bytes.
- Ako vam treba deterministička byte-for-byte reprodukcija, napravite minimalan wrapper oko Revit’s DLLs da pozove njegove gzip/gunzip paths i ECC computation (kao što je demonstrirano u istraživanju), ili ponovo iskoristite bilo koji dostupan helper koji replicira ove semantike.

3) Ponovo izgradite OLE compound document
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Beleške:

- CompoundFileTool zapisuje storages/streams na filesystem sa escaping-om za karaktere nevažeće u NTFS imenima; stream path koji želite je tačno `Global/Latest` u izlaznom stablu.
- Prilikom isporuke masovnih napada preko ecosystem plugins koji preuzimaju RFAs iz cloud storage, osigurajte da vaš patched RFA prvo lokalno prođe Revit’s integrity checks (gzip/ECC correct) pre nego što pokušate network injection.

Exploitation insight (to guide what bytes to place in the gzip payload):

- The Revit deserializer reads a 16-bit class index and constructs an object. Certain types are non‑polymorphic and lack vtables; abusing destructor handling yields a type confusion where the engine executes an indirect call through an attacker-controlled pointer.
- Picking `AString` (class index `0x1F`) places an attacker-controlled heap pointer at object offset 0. During the destructor loop, Revit effectively executes:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Postavite više takvih objekata u serijalizovani graf tako da svaka iteracija destructor petlje izvrši po jedan gadget (“weird machine”), i obezbedite stack pivot u konvencionalni x64 ROP chain.

Pogledajte detalje o Windows x64 pivot/gadget building ovde:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

i opšte ROP smernice ovde:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Alati:

- CompoundFileTool (OSS) za rastavljanje/ponovno sastavljanje OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD za reverse/taint; onemogućite page heap sa TTD da bi trace-ovi ostali kompaktni.
- Lokalni proxy (npr. Fiddler) može simulirati isporuku u lancu snabdevanja zamenom RFAs u plugin traffic-u za testiranje.

## Reference

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
