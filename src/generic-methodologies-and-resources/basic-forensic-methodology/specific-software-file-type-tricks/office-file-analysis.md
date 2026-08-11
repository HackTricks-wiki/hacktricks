# Analiza Office fajlova

{{#include ../../../banners/hacktricks-training.md}}

Za dodatne informacije pogledajte [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Ovo je samo sažetak:<sup>[[4]](#references)</sup>

Microsoft Office dokumenti se često pojavljuju u legacy formatima kao što su RTF i OLE/CFBF-bazirani DOC, XLS i PPT, ili u novijim **Office Open XML (OOXML)** formatima kao što su DOCX, XLSX i PPTX. Office dokumenti mogu sadržati aktivni sadržaj, kao što su macros, zbog čega su česti nosioci phishing-a i malware-a. OOXML fajlovi su ZIP kontejneri čija se hijerarhija fajlova i XML sadržaj mogu pregledati tako što se raspakuju.<sup>[[3]](#references)[[4]](#references)</sup>

Za istraživanje struktura OOXML fajlova navedeni su command za raspakivanje dokumenta i izlazna struktura. Tehnike za skrivanje podataka u ovim fajlovima su dokumentovane, što ukazuje na kontinuirane inovacije u prikrivanju podataka u CTF izazovima.<sup>[[4]](#references)</sup>

Za analizu, **oletools** i **OfficeDissector** nude sveobuhvatne skupove alata za ispitivanje OLE i OOXML dokumenata. Ovi alati pomažu u identifikovanju i analizi ugrađenih macros-a, koji često služe kao vektori za isporuku malware-a, obično preuzimajući i izvršavajući dodatne zlonamerne payload-e. Analiza VBA macros-a može se obaviti bez Microsoft Office-a korišćenjem Libre Office-a, koji omogućava debugging pomoću breakpoints-a i watch promenljivih.<sup>[[4]](#references)</sup>

Instalacija i korišćenje **oletools**-a su jednostavni, uz commands za instaliranje pomoću pip-a i izdvajanje macros-a iz dokumenata. U Word-u, automatski macros-i uključuju `AutoExec` i `AutoOpen`, dok je `Document_Open` procedura koja se izvršava pri otvaranju dokumenta.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Exploitation OLE Compound File-a: Autodesk Revit RFA – ECC recomputation i kontrolisani gzip

Revit RFA modeli se čuvaju kao [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (poznat i kao CFBF). Serijalizovani model se nalazi u storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Ključni raspored u `Global\Latest` (uočeno u Revit 2025):

- Header
- GZIP-compressed payload (stvarni serijalizovani graf objekata)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit će automatski popraviti male izmene u stream-u koristeći ECC trailer i odbiće stream-ove koji se ne podudaraju sa ECC-om. Zbog toga naivno menjanje compressed bytes neće biti sačuvano: izmene će ili biti vraćene ili će fajl biti odbijen. Da biste obezbedili byte-accurate kontrolu nad onim što deserializer vidi, morate:<sup>[[1]](#references)</sup>

- Ponovo kompresovati pomoću Revit-compatible gzip implementacije (tako da se compressed bytes koje Revit proizvodi/prihvata podudaraju sa onim što očekuje).
- Ponovo izračunati ECC trailer preko padded stream-a kako bi Revit prihvatio izmenjeni stream bez automatske popravke.

Praktični workflow za patching/fuzzing RFA sadržaja:<sup>[[1]](#references)</sup>

1) Proširiti OLE compound document.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Uredi `Global\Latest` uz gzip/ECC disciplinu

- Rastavi `Global/Latest`: zadrži zaglavlje, raspakuj payload pomoću gunzip-a, izmeni bajtove, zatim ga ponovo spakuj pomoću deflate parametara kompatibilnih sa Revit-om.
- Sačuvaj zero-padding i ponovo izračunaj ECC trailer kako bi Revit prihvatio nove bajtove.
- Ako ti je potrebna deterministička reprodukcija bajt-po-bajt, napravi minimalni wrapper oko Revit DLL-ova kako bi pozvao njegove gzip/gunzip putanje i ECC computation (kao što je prikazano u istraživanju) ili ponovo upotrebi bilo koji dostupan helper koji reprodukuje ovu semantiku.

3) Ponovo izgradi OLE složeni dokument.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Napomene:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool upisuje storages/streams u filesystem, uz escaping znakova koji nisu validni u NTFS imenima; putanja streama koja vam je potrebna jeste tačno `Global/Latest` u izlaznom stablu.
- Prilikom izvođenja mass attacks putem ecosystem plugins koji preuzimaju RFA datoteke iz cloud storage-a, uverite se da vaš patched RFA lokalno prvo prolazi Revit integrity checks (gzip/ECC ispravni) pre pokušaja network injection-a.

Uvid u exploitation (za usmeravanje toga koje bytes treba postaviti u gzip payload):<sup>[[1]](#references)</sup>

- Revit deserializer čita 16-bit class index i konstruiše objekat. Određeni tipovi su non-polymorphic i nemaju vtables; zloupotreba destructor handling-a dovodi do type confusion-a, pri čemu engine izvršava indirect call kroz attacker-controlled pointer.
- Izborom `AString` (class index `0x1F`) attacker-controlled heap pointer se postavlja na object offset 0. Tokom destructor loop-a, Revit efektivno izvršava:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Postavite više takvih objekata u serialized graph tako da svaka iteracija destructor loop-a izvršava po jedan gadget („weird machine“), a zatim pripremite stack pivot u konvencionalni x64 ROP chain.

Detalje za Windows x64 pivot/gadget building pogledajte ovde:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

a opšte smernice za ROP ovde:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Alati:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) za proširivanje/ponovnu izgradnju OLE compound files: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD za reverse/taint; onemogućite page heap sa TTD-om kako bi trace-ovi ostali kompaktni.
- Lokalni proxy (npr. Fiddler) može simulirati supply-chain delivery zamenom RFA datoteka u plugin saobraćaju radi testiranja.

## References

- [1] [Izrada potpunog RCE exploit-a na osnovu crash-a u parsiranju Autodesk Revit RFA datoteke (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) dokumentacija](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF vodič na terenu](https://trailofbits.github.io/ctf/forensics/)
- [5] [olevba dokumentacija (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open event (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
