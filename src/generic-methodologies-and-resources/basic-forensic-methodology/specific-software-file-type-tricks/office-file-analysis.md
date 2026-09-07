# Analiza Office datoteka

{{#include ../../../banners/hacktricks-training.md}}

Za dodatne informacije pogledajte [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Ovo je samo sažetak:<sup>[[4]](#references)</sup>

Microsoft Office dokumenti se često pojavljuju u legacy formatima kao što su RTF i OLE/CFBF-based DOC, XLS i PPT, ili u novijim **Office Open XML (OOXML)** formatima kao što su DOCX, XLSX i PPTX. Office dokumenti mogu sadržati active content kao što su macros, zbog čega su česti nosioci phishing sadržaja i malware-a. OOXML datoteke su ZIP kontejneri čija se hijerarhija datoteka i XML sadržaj mogu pregledati njihovim raspakivanjem.<sup>[[3]](#references)[[4]](#references)</sup>

Za istraživanje struktura OOXML datoteka navedeni su command za raspakivanje dokumenta i izlazna struktura. Tehnike za skrivanje podataka u ovim datotekama su dokumentovane, što ukazuje na stalne inovacije u prikrivanju podataka u CTF izazovima.<sup>[[4]](#references)</sup>

Za analizu, **oletools** i **OfficeDissector** nude sveobuhvatne toolset-e za ispitivanje OLE i OOXML dokumenata. Ovi alati pomažu u identifikovanju i analizi ugrađenih macros-a, koji često služe kao vektori za isporuku malware-a, obično preuzimajući i izvršavajući dodatne malicious payload-e. Analiza VBA macros-a može se obaviti bez Microsoft Office-a korišćenjem Libre Office-a, koji omogućava debugging pomoću breakpoints-a i watch variables-a.<sup>[[4]](#references)</sup>

Instalacija i korišćenje **oletools** su jednostavni, uz navedene command-e za instalaciju putem pip-a i izdvajanje macros-a iz dokumenata. U Word-u, automatski macros uključuju `AutoExec` i `AutoOpen`, dok je `Document_Open` procedura open-event-a.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
Za Office dokumente zaštićene lozinkom pogledajte [grammar-driven offline recovery workflow](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

## Eksploatacija OLE Compound File: Autodesk Revit RFA – ponovni proračun ECC-a i kontrolisani gzip

Revit RFA modeli se čuvaju kao [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (poznat i kao CFBF). Serijalizovani model nalazi se u storage/stream:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Ključni raspored u `Global\Latest` (uočen u Revit 2025):

- Zaglavlje
- GZIP-kompresovani payload (stvarni serijalizovani graf objekata)
- Nulto popunjavanje
- ECC trailer

Revit će automatski popraviti male izmene u streamu koristeći ECC trailer i odbiće streamove koji se ne podudaraju sa ECC-om. Zato naivno menjanje kompresovanih bajtova neće biti trajno: vaše izmene će biti vraćene ili će datoteka biti odbijena. Da biste obezbedili bajt-po-bajt kontrolu nad onim što deserializer obrađuje, morate:<sup>[[1]](#references)</sup>

- Ponovo kompresovati koristeći gzip implementaciju kompatibilnu sa Revitom (kako bi se kompresovani bajtovi koje Revit proizvodi/prihvata podudarali sa onim što očekuje).
- Ponovo izračunati ECC trailer preko popunjenog streama kako bi Revit prihvatio izmenjeni stream bez njegovog automatskog popravljanja.

Praktični workflow za patching/fuzzing RFA sadržaja:<sup>[[1]](#references)</sup>

1) Proširite OLE compound dokument.<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Uredi `Global\Latest` uz disciplinovanu upotrebu gzip/ECC-a

- Rastavi `Global/Latest`: zadrži zaglavlje, raspakuj payload pomoću gunzip-a, izmeni bajtove, a zatim ga ponovo zapakuj pomoću deflate parametara kompatibilnih sa Revit-om.
- Očuvaj dopunu nulama i ponovo izračunaj ECC trailer kako bi Revit prihvatio nove bajtove.
- Ako ti je potrebna deterministička reprodukcija bajt po bajt, napravi minimalni wrapper oko Revit-ovih DLL-ova da pozoveš njegove gzip/gunzip putanje i izračunavanje ECC-a (kao što je prikazano u istraživanju) ili ponovo upotrebi neki dostupan pomoćni alat koji replicira ovu semantiku.

3) Ponovo izgradi OLE složeni dokument.<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Napomene:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool upisuje storages/streams u fajl sistem, uz escaping znakova koji nisu važeći u NTFS imenima; putanja streama koja vam je potrebna jeste tačno `Global/Latest` u izlaznom stablu.
- Prilikom isporuke masovnih napada putem ecosystem plugins koji preuzimaju RFA datoteke iz cloud storage-a, prvo lokalno proverite da vaša zakrpljena RFA datoteka prolazi Revit integrity checks (ispravan gzip/ECC), pre pokušaja network injection-a.

Uvid u exploitation (kako biste znali koje bajtove da postavite u gzip payload):<sup>[[1]](#references)</sup>

- Revit deserializer čita 16-bitni indeks klase i konstruiše objekat. Određeni tipovi su nepolimorfni i nemaju vtables; zloupotreba obrade destruktora dovodi do type confusion-a, pri čemu engine izvršava indirektan poziv kroz pokazivač pod kontrolom napadača.
- Izborom `AString` (indeks klase `0x1F`) pokazivač na heap pod kontrolom napadača postavlja se na offset 0 objekta. Tokom petlje destruktora, Revit efektivno izvršava:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Postavite više takvih objekata u serializovani graf tako da svaka iteracija petlje destruktora izvršava po jedan gadget („weird machine“), i organizujte stack pivot u konvencionalni x64 ROP lanac.

Detalje o Windows x64 pivot/gadget izgradnji pogledajte ovde:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

a opšte smernice za ROP ovde:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Alati:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) za proširivanje/ponovnu izgradnju OLE compound files: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD za reverse/taint; onemogućite page heap sa TTD-om kako bi tragovi ostali kompaktni.
- Lokalni proxy (npr. Fiddler) može simulirati supply-chain isporuku zamenom RFA datoteka u plugin saobraćaju radi testiranja.

## References

- [1] [Izrada potpunog RCE exploit-a na osnovu crash-a pri parsiranju Autodesk Revit RFA datoteke (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) dokumentacija](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Terenski vodič za Forensics CTF](https://trailofbits.github.io/ctf/forensics/)
- [5] [olevba dokumentacija (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open događaj (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
