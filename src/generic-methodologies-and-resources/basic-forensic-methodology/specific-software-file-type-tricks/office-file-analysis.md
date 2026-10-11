# Analiza Office datoteka

{{#include ../../../banners/hacktricks-training.md}}

Za više informacija pogledajte [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Ovo je samo sažetak:<sup>[[4]](#references)</sup>

Microsoft Office dokumenti se često pojavljuju u starijim formatima, kao što su RTF i DOC, XLS i PPT zasnovani na OLE/CFBF, ili u novijim formatima **Office Open XML (OOXML)**, kao što su DOCX, XLSX i PPTX. Office dokumenti mogu sadržati aktivni sadržaj, kao što su makroi, zbog čega se često koriste za phishing i prenos malvera. OOXML datoteke su ZIP kontejneri čija se hijerarhija datoteka i XML sadržaj mogu pregledati njihovim raspakivanjem.<sup>[[3]](#references)[[4]](#references)</sup>

Navedeni su komanda za raspakivanje dokumenta i struktura izlaza, kako bi se istražile strukture OOXML datoteka. Dokumentovane su tehnike za skrivanje podataka u ovim datotekama, što pokazuje da se u CTF izazovima neprestano razvijaju novi načini za prikrivanje podataka.<sup>[[4]](#references)</sup>

Za analizu, **oletools** i **OfficeDissector** nude sveobuhvatne skupove alata za pregled OLE i OOXML dokumenata. Ovi alati pomažu u otkrivanju i analizi ugrađenih makroa, koji često služe kao način za isporuku malvera — obično preuzimanjem i izvršavanjem dodatnog zlonamernog sadržaja. VBA makroi mogu se analizirati bez Microsoft Office-a pomoću LibreOffice-a, koji omogućava otklanjanje grešaka pomoću tačaka prekida i praćenih promenljivih.<sup>[[4]](#references)</sup>

Instaliranje i korišćenje alata **oletools** je jednostavno; navedene su komande za instalaciju pomoću pip-a i izdvajanje makroa iz dokumenata. U Word-u, automatski makroi uključuju `AutoExec` i `AutoOpen`, dok je `Document_Open` procedura koja se pokreće prilikom otvaranja dokumenta.<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

Za Office dokumente šifrovane lozinkom pogledajte [offline workflow za oporavak zasnovan na gramatici](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

## Eksploatacija OLE Compound File: Autodesk Revit RFA – ponovno izračunavanje ECC-a i kontrolisani gzip

Revit RFA modeli čuvaju se kao [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (poznat i kao CFBF). Serijalizovani model nalazi se u skladištu/stream-u:<sup>[[1]](#references)[[3]](#references)</sup>

- Skladište: `Global`
- Stream: `Latest` → `Global\Latest`

Raspored u `Global\Latest` (uočeno u Revit 2025):

- Zaglavlje
- GZIP-kompresovani sadržaj (stvarni serijalizovani graf objekata)
- Nule za popunjavanje
- ECC kontrolni zapis

Revit automatski popravlja mala odstupanja u stream-u pomoću ECC kontrolnog zapisa i odbacuje stream-ove koji se ne podudaraju sa ECC-om. Zato naivno uređivanje kompresovanih bajtova neće opstati: izmene će biti vraćene ili će datoteka biti odbačena. Da biste obezbedili preciznu kontrolu bajt po bajt nad onim što deserializator vidi, morate:<sup>[[1]](#references)</sup>

- Ponovo komprimovati pomoću gzip implementacije kompatibilne sa Revit-om (tako da se kompresovani bajtovi koje Revit proizvede/prihvata podudaraju sa očekivanim).
- Ponovo izračunati ECC kontrolni zapis nad popunjenim stream-om kako bi Revit prihvatio izmenjeni stream bez automatske popravke.

Praktični workflow za izmenu/fuzzing RFA sadržaja:<sup>[[1]](#references)</sup>

1) Raspakujte OLE compound dokument.<sup>[[2]](#references)</sup>

```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```

2) Uredite Global\Latest uz gzip/ECC disciplinu

- Rastavite `Global/Latest`: sačuvajte zaglavlje, raspakujte payload pomoću gunzip-a, izmenite bajtove, pa ga ponovo zapakujte pomoću gzip-a uz parametre deflate kompatibilne sa Revit-om.
- Sačuvajte nulto popunjavanje i ponovo izračunajte ECC trailer kako bi Revit prihvatio nove bajtove.
- Ako vam je potrebna deterministička reprodukcija bajt po bajt, napravite minimalni omotač oko Revit DLL-ova da biste pozvali njegove gzip/gunzip putanje i izračunavanje ECC-a (kao što je prikazano u istraživanju) ili ponovo upotrebite dostupan pomoćni alat koji oponaša tu semantiku.

3) Ponovo izgradite OLE složeni dokument.<sup>[[2]](#references)</sup>

```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```

Napomene:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool upisuje storage/stream-ove u fajl-sistem, uz escape-ovanje znakova koji nisu dozvoljeni u NTFS imenima; putanja stream-a koju tražite u izlaznom stablu je tačno `Global/Latest`.
- Prilikom isporuke masovnih napada preko dodataka u ekosistemu koji preuzimaju RFA fajlove iz cloud storage-a, proverite da vaša zakrpljena RFA datoteka lokalno prolazi Revit-ove provere integriteta (ispravan gzip/ECC) pre pokušaja mrežne injekcije.

Uvid u eksploataciju (za usmeravanje pri izboru bajtova koje treba smestiti u gzip payload):<sup>[[1]](#references)</sup>

- Revit-ov deserializer čita 16-bitni indeks klase i konstruiše objekat. Neki tipovi nisu polimorfni i nemaju vtable; zloupotreba obrade destruktora dovodi do zabune tipova, pri čemu engine izvršava indirektan poziv preko pokazivača koji kontroliše napadač.
- Izborom `AString` (indeks klase `0x1F`) na pomeraju objekta 0 smešta se pokazivač na heap koji kontroliše napadač. Tokom petlje destruktora, Revit efektivno izvršava:

```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```

- Postavite više takvih objekata u serijalizovani graf tako da svaka iteracija petlje destruktora izvršava po jedan gadget („weird machine“) i podesite pivotiranje steka ka konvencionalnom x64 ROP lancu.

Detalje o pivotiranju/gadget-ima za Windows x64 pogledajte ovde:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

a opšte smernice za ROP ovde:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Alati:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS) za raspakivanje/ponovnu izgradnju OLE složenih datoteka: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD za reverzni inženjering/taint analizu; pomoću TTD-a isključite page heap da bi tragovi ostali kompaktni.
- Lokalni proxy (npr. Fiddler) može da simulira isporuku kroz lanac snabdevanja tako što za testiranje zamenjuje RFA datoteke u saobraćaju dodatka.

## References

- [1] [Izrada kompletnog RCE exploita na osnovu pada pri parsiranju Autodesk Revit RFA datoteke (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [Dokumentacija za OLE složenu datoteku (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Priručnik za CTF forenziku](https://trailofbits.github.io/ctf/forensics/)
- [5] [Dokumentacija za olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Automatski makroi (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Događaj Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
