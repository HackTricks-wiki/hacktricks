# Analiza Office fajlova

{{#include ../../../banners/hacktricks-training.md}}


Za više informacija proverite [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Ovo je samo rezime:

Microsoft je kreirao mnogo Office formata dokumenata, pri čemu su dve glavne vrste **OLE formats** (kao što su RTF, DOC, XLS, PPT) i **Office Open XML (OOXML) formats** (kao što su DOCX, XLSX, PPTX). Ovi formati mogu da uključuju makroe, zbog čega su mete za phishing i malware. OOXML fajlovi su strukturirani kao zip kontejneri, što omogućava inspekciju raspakivanjem, otkrivajući hijerarhiju fajlova i foldera i sadržaj XML fajlova.

Da biste istražili strukturu OOXML fajlova, dat je komand za raspakivanje dokumenta i izlazna struktura. Tehnike skrivanja podataka u ovim fajlovima su dokumentovane, što ukazuje na neprestanu inovaciju u skrivanju podataka u CTF izazovima.

Za analizu, **oletools** i **OfficeDissector** nude sveobuhvatan set alata za ispitivanje kako OLE tako i OOXML dokumenata. Ovi alati pomažu u identifikaciji i analizi ugrađenih makroa, koji često služe kao vektori za dostavu malware-a, obično preuzimanjem i izvršavanjem dodatnih zlonamernih payload-ova. Analiza VBA makroa može se obaviti bez Microsoft Office korišćenjem Libre Office, koji omogućava debugovanje sa breakpoints i watch variables.

Instalacija i upotreba **oletools** je jednostavna, sa komandama datim za instalaciju putem pip-a i ekstrakciju makroa iz dokumenata. Automatsko izvršavanje makroa se pokreće funkcijama kao što su `AutoOpen`, `AutoExec`, ili `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA modeli se čuvaju kao [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (poznato i kao CFBF). Serijalizovani model se nalazi pod storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Ključna struktura `Global\Latest` (uočeno na Revit 2025):

- Header
- GZIP-compressed payload (stvarni serijalizovani graf objekata)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit će automatski popravljati male perturbacije u stream-u koristeći ECC trailer i odbaciti stream-ove koji ne odgovaraju ECC-u. Dakle, naivno uređivanje kompresovanih bajtova se neće zadržati: vaše izmene će ili biti vraćene ili će fajl biti odbijen. Da biste obezbedili tačnu kontrolu po bajtu nad onim što deserializer vidi, morate:

- Ponovo kompresovati koristeći Revit-kompatibilnu gzip implementaciju (tako da kompresovani bajtovi koje Revit proizvodi/prihvata odgovaraju onome što očekuje).
- Ponovo izračunati ECC trailer preko popunjenog stream-a tako da Revit prihvati izmenjeni stream bez automatske popravke.

Praktičan tok rada za patching/fuzzing sadržaja RFA:

1) Ekstrahujte OLE compound dokument
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Izmeni Global\Latest uz gzip/ECC disciplinu

- Dekonstruiši `Global/Latest`: sačuvaj zaglavlje, izvrši gunzip na payload, mutiraj bajtove, zatim ponovo izvrši gzip koristeći Revit-kompatibilne deflate parametre.
- Sačuvaj popunjavanje nulama i ponovo izračunaj ECC trailer tako da novi bajtovi budu prihvaćeni od strane Revita.
- Ako ti treba deterministička bajt-po-bajt reprodukcija, izgradi minimalni wrapper oko Revit’s DLLs da pozove njegove gzip/gunzip putanje i ECC izračunavanje (kao što je demonstrirano u istraživanju), ili ponovo iskoristi bilo koji dostupan helper koji reprodukuje ove semantike.

3) Ponovo izgradi OLE složeni dokument
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Beleške:

- CompoundFileTool upisuje storages/streams na fajl sistem uz escapovanje karaktera nevažećih za NTFS imena; stream path koji želite je tačno `Global/Latest` u izlaznom stablu.
- Kada isporučujete mass attacks putem ecosystem plugins koji fetchuju RFAs iz cloud storage, osigurajte da vaš patched RFA prvo lokalno prođe Revit’s integrity checks (gzip/ECC correct) pre nego što pokušate network injection.

Uvid u eksploataciju (da usmeri koje bajtove staviti u gzip payload):

- Revit deserializer čita 16-bit class index i konstruiše objekat. Određeni tipovi su non‑polymorphic i nemaju vtables; zloupotreba rukovanja destruktorom dovodi do type confusion gde engine izvršava indirektan poziv kroz pointer koji kontroliše napadač.
- Izbor `AString` (class index `0x1F`) postavlja heap pointer kojim kontroliše napadač na offset objekta 0. Tokom petlje destruktora, Revit efektivno izvršava:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Postavite više takvih objekata u serijalizovani graf tako da svaka iteracija destructor loop izvrši jedan gadget (“weird machine”), i organizujte stack pivot u konvencionalni x64 ROP chain.

Pogledajte detalje o Windows x64 pivot/gadget izgradnji ovde:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

i opšte smernice za ROP ovde:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Alati:

- CompoundFileTool (OSS) za proširenje/rekonstrukciju OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD za reverse/taint; onemogućite page heap sa TTD kako biste tragove držali kompaktne.
- Lokalni proxy (npr. Fiddler) može simulirati isporuku kroz supply-chain zamenom RFAs u plugin saobraćaju za testiranje.

## References

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
