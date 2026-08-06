# Analiza Office datoteka

{{#include ../../../banners/hacktricks-training.md}}


Za dodatne informacije pogledajte [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Ovo je samo sažetak:<sup>[[4]](#references)</sup>

Microsoft je kreirao mnoge formate Office dokumenata, pri čemu su dva glavna tipa **OLE formati** (kao što su RTF, DOC, XLS, PPT) i **Office Open XML (OOXML) formati** (kao što su DOCX, XLSX, PPTX). Ovi formati mogu sadržati macros, zbog čega predstavljaju mete za phishing i malware. OOXML datoteke su strukturisane kao zip kontejneri, što omogućava njihovu analizu raspakivanjem i otkrivanjem hijerarhije datoteka i foldera, kao i sadržaja XML datoteka.

Za istraživanje strukture OOXML datoteka dati su komanda za raspakivanje dokumenta i izlazna struktura. Tehnike za skrivanje podataka u ovim datotekama su dokumentovane, što ukazuje na kontinuirane inovacije u prikrivanju podataka u CTF izazovima.

Za analizu, **oletools** i **OfficeDissector** nude sveobuhvatne skupove alata za ispitivanje OLE i OOXML dokumenata. Ovi alati pomažu u identifikovanju i analizi ugrađenih macros, koji često služe kao vektori za isporuku malware-a, obično preuzimajući i izvršavajući dodatne malicious payloads. Analiza VBA macros može se obaviti bez Microsoft Office-a korišćenjem Libre Office-a, koji omogućava debugging pomoću breakpoints i watch variables.

Instalacija i korišćenje alata **oletools** su jednostavni, a date su i komande za instalaciju putem pip-a i izdvajanje macros iz dokumenata. Automatsko izvršavanje macros pokreću funkcije kao što su `AutoOpen`, `AutoExec` ili `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## Eksploatacija OLE Compound File formata: Autodesk Revit RFA – ponovno izračunavanje ECC-a i kontrolisani gzip

Revit RFA modeli se čuvaju kao [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (poznat i kao CFBF). Serijalizovani model nalazi se u storage/stream:<sup>[[1]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Ključna struktura `Global\Latest` (uočena u Revit 2025):

- Zaglavlje
- GZIP-kompresovani payload (stvarni serijalizovani graf objekata)
- Nulto popunjavanje
- ECC trailer

Revit će automatski popraviti male izmene u streamu koristeći ECC trailer i odbiće streamove koji se ne podudaraju sa ECC-om. Zbog toga naivno uređivanje kompresovanih bajtova neće opstati: vaše izmene će biti vraćene ili će datoteka biti odbijena. Da biste obezbedili bajt-po-bajt kontrolu nad onim što deserializer učitava, morate:

- Ponovo kompresovati pomoću Revit-kompatibilne gzip implementacije (kako bi se kompresovani bajtovi koje Revit proizvodi/prihvata podudarali sa onim što očekuje).
- Ponovo izračunati ECC trailer nad popunjenim streamom kako bi Revit prihvatio izmenjeni stream bez automatske popravke.

Praktičan tok rada za patching/fuzzing RFA sadržaja:<sup>[[1]](#references)</sup>

1) Proširite OLE compound dokument
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Izmenite `Global\Latest` uz gzip/ECC disciplinu

- Rastavite `Global/Latest`: zadržite zaglavlje, raspakujte payload pomoću gunzip, izmenite bajtove, a zatim ponovo zapakujte pomoću gzip-a koristeći Revit-kompatibilne deflate parametre.
- Sačuvajte nul-popunu i ponovo izračunajte ECC trailer kako bi Revit prihvatio nove bajtove.
- Ako vam je potrebna deterministička reprodukcija bajt po bajt, napravite minimalni wrapper oko Revit DLL-ova da biste pozvali njegove gzip/gunzip putanje i ECC izračunavanje (kao što je prikazano u istraživanju) ili ponovo upotrebite bilo koji dostupan helper koji replicira ovu semantiku.

3) Ponovo izgradite OLE složeni dokument
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)</sup>

- CompoundFileTool upisuje storages/streams u filesystem, uz escaping znakova koji nisu validni u NTFS imenima; putanja streama koja vam je potrebna je tačno `Global/Latest` u izlaznom stablu.
- Kada isporučujete mass attacks putem ecosystem plugins koji preuzimaju RFA iz cloud storage-a, uverite se da vaš patched RFA lokalno prvo prolazi Revit integrity checks (gzip/ECC ispravni) pre pokušaja network injection-a.

Exploitation insight (za usmeravanje koje bajtove treba postaviti u gzip payload):<sup>[[1]](#references)</sup>

- Revit deserializer čita 16-bitni class index i konstruiše objekat. Određeni tipovi su non-polymorphic i nemaju vtables; zloupotreba destructor handling-a dovodi do type confusion-a, pri čemu engine izvršava indirect call kroz attacker-controlled pointer.
- Izbor `AString` (class index `0x1F`) postavlja attacker-controlled heap pointer na offsetu objekta 0. Tokom destructor loop-a, Revit efektivno izvršava:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Postavite više takvih objekata u serijalizovani graf tako da svaka iteracija petlje destruktora izvršava po jedan gadget („weird machine“), a zatim organizujte stack pivot ka konvencionalnom x64 ROP chain-u.

Detalje o Windows x64 pivot/gadget building-u pogledajte ovde:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

a opšte smernice za ROP ovde:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Alati:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) za proširivanje/ponovnu izgradnju OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD za reverse/taint analizu; onemogućite page heap sa TTD-om da bi trace-ovi ostali kompaktni.
- Lokalni proxy (npr. Fiddler) može da simulira supply-chain isporuku zamenom RFA fajlova u plugin saobraćaju radi testiranja.

## Reference

- [1] [Izrada kompletnog RCE exploita na osnovu crash-a pri parsiranju Autodesk Revit RFA fajla (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) dokumentacija](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF vodič](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
