# Analiza Office datoteka

{{#include ../../../banners/hacktricks-training.md}}

Za više informacija pogledajte [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). Ovo je samo sažetak:<sup>[[2]](#references)</sup>

Microsoft Office dokumenti često se pojavljuju u zastarelim formatima kao što su RTF i DOC, XLS i PPT zasnovani na OLE/CFBF-u, ili u novijim formatima **Office Open XML (OOXML)** kao što su DOCX, XLSX i PPTX. Office dokumenti mogu sadržati aktivni sadržaj, kao što su makroi, zbog čega su česti prenosioci phishing napada i malware-a. OOXML datoteke su ZIP kontejneri čija se hijerarhija datoteka i XML sadržaj mogu pregledati njihovim raspakivanjem.<sup>[[1]](#references)[[2]](#references)</sup>

Prikazani su komanda za raspakivanje dokumenta i izlazna struktura, kako bi se istražila struktura OOXML datoteka. Dokumentovane su tehnike za skrivanje podataka u ovim datotekama, što ukazuje na stalne inovacije u prikrivanju podataka u CTF izazovima.<sup>[[2]](#references)</sup>

Za analizu, **oletools** i **OfficeDissector** nude sveobuhvatne skupove alata za ispitivanje OLE i OOXML dokumenata. Ovi alati pomažu u prepoznavanju i analizi ugrađenih makroa, koji često služe kao vektori za isporuku malware-a i obično preuzimaju i izvršavaju dodatne zlonamerne payload-ove. VBA makroi mogu se analizirati bez Microsoft Office-a pomoću LibreOffice-a, koji omogućava otklanjanje grešaka pomoću tačaka prekida i promenljivih za praćenje.<sup>[[2]](#references)</sup>

Instaliranje i korišćenje **oletools** je jednostavno; navedene su komande za instaliranje pomoću pip-a i izdvajanje makroa iz dokumenata. U Word-u, automatski makroi uključuju `AutoExec` i `AutoOpen`, dok je `Document_Open` procedura koja se pokreće prilikom otvaranja dokumenta.<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

## Analiza VBA makroa: besmisleni kod i UserForms

## Besmisleni kod

Makroi mogu da sadrže **nedostižan ili irelevantan kod** čija je namena da uspori analizu. Pre nego što utrošite vreme na reverzno analiziranje grane, utvrdite konstantne uslove i pratite tok izvršavanja dostupnog koda. Primer u nastavku koristi uslov `If` koji nikada ne može biti tačan da bi sakrio besmisleni kod.

![Word makro koji sadrži nedostižnu uslovnu granu s besmislenim kodom](<../../../images/image (369).png>)

## Obrasci makroa

VBA UserForms mogu da čuvaju podatke u kontrolama kao što su tekstualna polja. Pošto obrasci, okviri i stranice mogu da izlažu kolekciju `Controls`, analitičari treba da izlistaju celu hijerarhiju kontrola, a ne da se oslanjaju samo na ono što obrazac prikazuje. Primer u nastavku čuva skrivene podatke u preklopljenim tekstualnim poljima.<sup>[[6]](#references)</sup>

Tokom dinamičke analize, VBA funkcija `GetObject` može da dohvati Automation objekat iz datoteke ili da se poveže sa već pokrenutim Automation serverom. Makroi mogu da koriste taj pristup objektima kako bi došli do podataka koji nisu očigledni u vidljivom dokumentu; pregledajte i vraćeni objekat i stablo kontrola UserForm obrasca.<sup>[[7]](#references)</sup>

![UserForm makroa sa podacima skrivenim u preklopljenim tekstualnim poljima](<../../../images/image (344).png>)

Za Office dokumente šifrovane lozinkom pogledajte [tok oporavka van mreže zasnovan na gramatici](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example).

---

Za Revit RFA datoteke koje koriste OLE/CFBF pogledajte [ponovno izračunavanje ECC-a, kontrolisani gzip i iskorišćavanje deserijalizatora](../../../binary-exploitation/revit-rfa-ole-compound-file-exploitation.md); taj tok iskorišćavanja parsera odvojen je od trijaže Office dokumenata.

## References

- [1] [Dokumentacija za OLE Compound File (CFBF)](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [2] [Terenski vodič za CTF forenziku](https://trailofbits.github.io/ctf/forensics/)
- [3] [Dokumentacija za olevba (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [4] [Automatski makroi (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [5] [Događaj Document.Open (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
- [6] [Microsoft Learn - Kolekcije, kontrole i objekti (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [7] [Microsoft Learn - funkcija `GetObject`](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../../../banners/hacktricks-training.md}}
