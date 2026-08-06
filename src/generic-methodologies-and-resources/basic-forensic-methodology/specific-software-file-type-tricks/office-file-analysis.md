# Analiza Office datoteka

{{#include ../../../banners/hacktricks-training.md}}


Za dodatne informacije pogledajte [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Ovo je samo sažetak:<sup>[[4]](#references)</sup>

Microsoft je kreirao mnoge formate Office dokumenata, pri čemu su dva glavna tipa **OLE formati** (kao što su RTF, DOC, XLS, PPT) i **Office Open XML (OOXML) formati** (kao što su DOCX, XLSX, PPTX). Ovi formati mogu da sadrže makroe, zbog čega predstavljaju mete za phishing i malware. OOXML datoteke su strukturisane kao zip kontejneri, što omogućava njihovo pregledanje raspakivanjem i otkriva hijerarhiju datoteka i fascikli, kao i sadržaj XML datoteka.

Za istraživanje struktura OOXML datoteka navedeni su komanda za raspakivanje dokumenta i struktura izlaza. Tehnike za skrivanje podataka u ovim datotekama su dokumentovane, što ukazuje na kontinuirane inovacije u prikrivanju podataka u okviru CTF izazova.

Za analizu, **oletools** i **OfficeDissector** nude sveobuhvatne skupove alata za ispitivanje OLE i OOXML dokumenata. Ovi alati pomažu u identifikovanju i analizi ugrađenih makroa, koji često služe kao vektori za isporuku malware-a, obično preuzimajući i izvršavajući dodatne maliciozne payload-e. Analiza VBA makroa može se obaviti bez Microsoft Office-a korišćenjem Libre Office-a, koji omogućava debugging pomoću breakpoint-a i watch varijabli.

Instalacija i upotreba alata **oletools** su jednostavne, a navedene su i komande za instalaciju putem pip-a i izdvajanje makroa iz dokumenata. Automatsko izvršavanje makroa pokreću funkcije kao što su `AutoOpen`, `AutoExec` ili `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Exploitation OLE Compound File: Autodesk Revit RFA – ECC recomputation i kontrolisani gzip

Revit RFA modeli se čuvaju kao [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (poznat i kao CFBF). Serijalizovani model nalazi se u storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Ključni raspored u `Global\Latest` (uočeno u Revit 2025):

- Header
- GZIP-compressed payload (stvarni serijalizovani object graph)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit će automatski popraviti male perturbacije u stream-u koristeći ECC trailer i odbaciće stream-ove koji se ne podudaraju sa ECC-om. Zbog toga naivno uređivanje compressed bytes neće biti trajno: vaše izmene će biti vraćene ili će fajl biti odbačen. Da biste obezbedili byte-accurate kontrolu nad onim što deserializer vidi, morate:

- Recompress pomoću gzip implementacije kompatibilne sa Revit-om (kako bi se compressed bytes koje Revit proizvodi/prihvata podudarali sa onim što očekuje).
- Recompute ECC trailer preko padded stream-a kako bi Revit prihvatio izmenjeni stream bez automatskog popravljanja.

Praktičan workflow za patching/fuzzing RFA sadržaja:<sup>[[1]](#references)</sup>

1) Proširite OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Uredite Global\Latest uz gzip/ECC pravila

- Rastavite `Global/Latest`: sačuvajte zaglavlje, raspakujte payload pomoću gunzip, izmenite bajtove, a zatim ga ponovo zapakujte pomoću Revit-kompatibilnih deflate parametara.
- Sačuvajte nul-punjenje i ponovo izračunajte ECC trailer kako bi Revit prihvatio nove bajtove.
- Ako vam je potrebna deterministička reprodukcija bajt po bajt, napravite minimalni wrapper oko Revit DLL-ova za pozivanje njegovih gzip/gunzip putanja i izračunavanje ECC-a (kao što je pokazano u istraživanju) ili ponovo upotrebite dostupan helper koji reprodukuje ovu semantiku.

3) Ponovo izgradite OLE compound document
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)</sup>

- CompoundFileTool upisuje storages/streams u filesystem, uz escaping znakova koji nisu validni u NTFS imenima; putanja streama koja vam je potrebna je tačno `Global/Latest` u izlaznom stablu.
- Prilikom isporuke masovnih napada putem ecosystem plugins koji preuzimaju RFA datoteke iz cloud storage-a, uverite se da vaš izmenjeni RFA lokalno prvo prolazi Revit integrity checks (ispravan gzip/ECC) pre pokušaja network injection-a.

Exploitation insight (radi usmeravanja toga koje bajtove treba postaviti u gzip payload):<sup>[[1]](#references)</sup>

- Revit deserializer čita 16-bitni class index i konstruiše objekat. Određeni tipovi su non-polymorphic i nemaju vtables; zloupotreba destructor handling-a dovodi do type confusion-a, pri čemu engine izvršava indirektni poziv kroz attacker-controlled pointer.
- Izbor `AString` (class index `0x1F`) postavlja attacker-controlled heap pointer na offset 0 objekta. Tokom destructor loop-a, Revit efektivno izvršava:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Postavite više ovakvih objekata u serialized graph tako da svaka iteracija destructor loop izvršava po jedan gadget („weird machine“), i organizujte stack pivot u konvencionalni x64 ROP chain.

Detalje o Windows x64 pivot/gadget building pogledajte ovde:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

a opšte smernice za ROP ovde:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Alati:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) za proširivanje/ponovnu izgradnju OLE compound files: https://github.com/thezdi/CompoundFileTool<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD za reverse/taint; onemogućite page heap sa TTD-om kako bi trace-ovi ostali kompaktni.
- Lokalni proxy (npr. Fiddler) može simulirati supply-chain delivery zamenom RFA datoteka u plugin saobraćaju radi testiranja.

## Reference

- [1] [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
