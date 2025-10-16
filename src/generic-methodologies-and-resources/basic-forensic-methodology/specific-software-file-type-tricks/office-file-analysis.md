# Analiza Office fajlova

{{#include ../../../banners/hacktricks-training.md}}


Za dodatne informacije pogledajte [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Ovo je samo sažetak:

Microsoft je napravio više Office formata dokumenata, pri čemu su dva glavna tipa **OLE formats** (kao RTF, DOC, XLS, PPT) i **Office Open XML (OOXML) formats** (npr. DOCX, XLSX, PPTX). Ovi formati mogu sadržavati macros, zbog čega su često meta za phishing i malware. OOXML fajlovi su strukturirani kao zip kontejneri, što omogućava njihovu inspekciju raspakivanjem i pregled hijerarhije fajlova/foldera i sadržaja XML datoteka.

Za istraživanje strukture OOXML fajlova, dat je komandni način za unzip dokumenta i izlazna struktura. Tehnike skrivanja podataka u ovim fajlovima su dokumentovane, što ukazuje na stalne inovacije u sakrivanju podataka u okviru CTF izazova.

Za analizu, **oletools** i **OfficeDissector** nude sveobuhvatan skup alata za ispitivanje kako OLE tako i OOXML dokumenata. Ovi alati pomažu u identifikaciji i analizi ugrađenih macros, koji često služe kao vektori za isporuku malware-a, obično preuzimajući i izvršavajući dodatne zlonamerne payload-e. Analiza VBA macros može se obaviti bez Microsoft Office koristeći Libre Office, koji omogućava debugovanje sa breakpoints i watch variables.

Instalacija i korišćenje **oletools** su jednostavni, sa komandama za instalaciju putem pip-a i za ekstrakciju macros iz dokumenata. Automatsko izvršavanje macros se pokreće funkcijama kao što su `AutoOpen`, `AutoExec`, ili `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA modeli su sačuvani kao [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). Serijalizovani model se nalazi u storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Osnovna struktura `Global\Latest` (zapaženo na Revit 2025):

- Zaglavlje
- GZIP-kompresovani payload (stvarni serijalizovani graf objekata)
- Popunjavanje nulama
- Error-Correcting Code (ECC) trailer

Revit će automatski popraviti male perturbacije u streamu koristeći ECC trailer i odbaciti streamove koji se ne poklapaju sa ECC. Dakle, naivno menjanje kompresovanih bajtova neće opstati: vaše izmene će biti ili vraćene ili će fajl biti odbijen. Da biste obezbedili kontrolu tačnu po bajtu nad onim što deserializer vidi, morate:

- Ponovo kompresovati pomoću Revit-kompatibilne gzip implementacije (tako da kompresovani bajtovi koje Revit proizvodi/prihvata odgovaraju onome što očekuje).
- Ponovo izračunati ECC trailer preko popunjenog streama tako da Revit prihvati izmenjeni stream bez automatskog popravljanja.

Praktičan workflow za patching/fuzzing sadržaja RFA:

1) Ekstraktujte OLE compound dokument
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Izmeni Global\Latest u skladu sa gzip/ECC disciplinom

- Dekonstruiši `Global/Latest`: zadrži header, gunzip payload, mutiraj bytes, zatim ponovo gzip koristeći Revit-compatible deflate parametre.
- Sačuvaj zero-padding i ponovo izračunaj ECC trailer tako da novi bytes budu prihvaćeni od strane Revita.
- Ako ti treba deterministička reprodukcija byte-for-byte, napravi minimalan wrapper oko Revit’s DLLs da pozove njegove gzip/gunzip paths i ECC computation (kako je demonstrirano u research), ili ponovo iskoristi bilo koji dostupan helper koji replicira ove semantics.

3) Ponovo izgradi OLE compound dokument
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Napomene:

- CompoundFileTool upisuje storages/streams na fajl‑sistem uz escapeovanje karaktera nevalidnih za NTFS imena; stream putanja koja vam treba je tačno `Global/Latest` u izlaznom stablu.
- Kada isporučujete masovne napade putem ecosystem plugins koji preuzimaju RFAs iz cloud storage, uverite se da vaš izmenjeni RFA lokalno prvo prolazi Revit‑ove provere integriteta (gzip/ECC correct) pre pokušaja mrežne injekcije.

Uvid u eksploataciju (da vas uputi koje bajtove staviti u gzip payload):

- Revit deserializer čita 16‑bitni class index i konstruiše objekat. Određeni tipovi su ne‑polimorfni i nemaju vtable; zloupotrebom rukovanja destruktorom nastaje type confusion gde engine izvršava indirektan poziv kroz attacker-controlled pointer.
- Izbor `AString` (class index `0x1F`) postavlja attacker-controlled heap pointer na offset 0 objekta. Tokom destruktor petlje, Revit efektivno izvršava:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Postavite više takvih objekata u serializovani graf tako da svaka iteracija petlje destruktora izvrši jedan gadget („weird machine“), i ostvarite stack pivot u konvencionalni x64 ROP lanac.

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
- IDA Pro + WinDBG TTD za reverse/taint; onemogućite page heap u TTD da biste održali tragove kompaktne.
- Lokalni proxy (npr. Fiddler) može simulirati isporuku kroz supply-chain zamenom RFAs u plugin saobraćaju radi testiranja.

## Reference

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
