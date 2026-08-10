# Analiza Office datoteka

Za dodatne informacije pogledajte [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Ovo je samo sažetak:<sup>[[4]](#references)</sup>

Microsoft Office dokumenti se često pojavljuju kao nasleđeni formati, kao što su RTF i OLE/CFBF-bazirani DOC, XLS i PPT, ili kao noviji **Office Open XML (OOXML)** formati, kao što su DOCX, XLSX i PPTX. Office dokumenti mogu sadržati aktivni sadržaj, kao što su macros, zbog čega su česti nosioci phishing-a i malware-a. OOXML datoteke su ZIP kontejneri čija se hijerarhija datoteka i XML sadržaj mogu pregledati raspakivanjem.<sup>[[3]](#references)[[4]](#references)</sup>

Za istraživanje struktura OOXML datoteka navedeni su komanda za raspakivanje dokumenta i izlazna struktura. Tehnike za skrivanje podataka u ovim datotekama su dokumentovane, što ukazuje na kontinuirane inovacije u prikrivanju podataka unutar CTF izazova.<sup>[[4]](#references)</sup>

Za analizu, **oletools** i **OfficeDissector** nude sveobuhvatne skupove alata za ispitivanje OLE i OOXML dokumenata. Ovi alati pomažu u identifikovanju i analizi ugrađenih macros, koji često služe kao vektori za isporuku malware-a, obično preuzimajući i izvršavajući dodatne zlonamerne payload-e. Analiza VBA macros može se sprovesti bez Microsoft Office-a korišćenjem Libre Office-a, koji omogućava debugging pomoću breakpoint-a i watch promenljivih.<sup>[[4]](#references)</sup>

Instalacija i korišćenje **oletools** su jednostavni, a navedene su komande za instalaciju putem pip-a i ekstrakciju macros iz dokumenata. U Word-u, automatski macros uključuju `AutoExec` i `AutoOpen`, dok je `Document_Open` procedura open-event-a.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Iskorišćavanje OLE Compound File: Autodesk Revit RFA – ECC recomputation i kontrolisani gzip

Revit RFA modeli se čuvaju kao [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (poznat i kao CFBF). Serijalizovani model nalazi se u storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Ključni raspored datoteke `Global\Latest` (uočen u Revit 2025):

- Zaglavlje
- GZIP-compressed payload (stvarni serijalizovani object graph)
- Nul-bajtno popunjavanje
- ECC trailer

Revit će automatski popraviti male izmene stream-a koristeći ECC trailer i odbiće stream-ove koji ne odgovaraju ECC-u. Zato naivno uređivanje compressed bytes neće biti sačuvano: izmene će biti vraćene ili će datoteka biti odbijena. Da biste obezbedili preciznu kontrolu bajtova nad onim što deserializer vidi, morate:<sup>[[1]](#references)</sup>

- Ponovo kompresovati koristeći gzip implementation kompatibilnu sa Revit-om (kako bi compressed bytes koje Revit proizvede/prihvati odgovarali onome što očekuje).
- Ponovo izračunati ECC trailer nad popunjenim stream-om kako bi Revit prihvatio izmenjeni stream bez automatske popravke.

Praktični workflow za patching/fuzzing RFA sadržaja:<sup>[[1]](#references)</sup>

1) Proširiti OLE compound document.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Uredi `Global\Latest` uz gzip/ECC disciplinu

- Rastavi `Global/Latest`: zadrži zaglavlje, raspakuj payload pomoću gunzip-a, izmeni bajtove, a zatim ga ponovo zapakuj pomoću Revit-compatible deflate parametara.
- Sačuvaj zero-padding i ponovo izračunaj ECC trailer kako bi Revit prihvatio nove bajtove.
- Ako ti je potrebna deterministička reprodukcija bajt po bajt, napravi minimalni wrapper oko Revit DLL-ova da pozoveš njegove gzip/gunzip putanje i ECC computation, kao što je prikazano u istraživanju, ili ponovo upotrebi bilo koji dostupan helper koji reprodukuje ovu semantiku.

3) Ponovo izgradi OLE compound document.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Beleške:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool upisuje storages/streams u filesystem, uz escaping znakova koji nisu važeći u NTFS nazivima; putanja do stream-a koju želite je tačno `Global/Latest` u izlaznom stablu.
- Prilikom isporuke masovnih napada putem ecosystem plugins koji preuzimaju RFA datoteke iz cloud storage-a, uverite se da vaša izmenjena RFA datoteka lokalno prvo prolazi Revit integrity checks (gzip/ECC ispravni), pre pokušaja network injection-a.

Uvid u exploitation (za usmeravanje bajtova koje treba postaviti u gzip payload):<sup>[[1]](#references)</sup>

- Revit deserializer čita 16-bitni class index i konstruiše objekat. Određeni tipovi nisu polymorphic i nemaju vtable; zloupotreba destructor handling-a dovodi do type confusion-a, pri čemu engine izvršava indirect call preko pointer-a kojim upravlja napadač.
- Izborom `AString` (class index `0x1F`) attacker-controlled heap pointer se postavlja na offset 0 objekta. Tokom destructor loop-a, Revit efektivno izvršava:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Postavite više takvih objekata u serializovani graf tako da svaka iteracija petlje destruktora izvršava po jedan gadget („weird machine“), a zatim pripremite stack pivot u konvencionalni x64 ROP chain.

Detalje o Windows x64 pivot/gadget building pogledajte ovde:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

a opšta uputstva za ROP ovde:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Alati:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) za raspakivanje/ponovnu izgradnju OLE compound files: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD za reverse/taint; onemogućite page heap sa TTD kako bi trace-ovi ostali kompaktni.
- Lokalni proxy (npr. Fiddler) može simulirati supply-chain isporuku zamenom RFA datoteka u plugin saobraćaju radi testiranja.

## References

- [1] [Izrada potpunog RCE exploit-a na osnovu crash-a u parsiranju Autodesk Revit RFA datoteke (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) dokumentacija](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [5] [olevba dokumentacija (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open event (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
