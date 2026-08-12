# Word Macros

{{#include ../banners/hacktricks-training.md}}

## Junk Code

Makroi mogu sadržati **nedostižan ili nerelevantan kod** čija je namena da uspori analizu. Identifikujte konstantne uslove i pratite dostižno ponašanje pre nego što počnete da reverzujete granu. Primer u nastavku koristi `If` uslov koji nikada ne može biti ispunjen kako bi sakrio junk code.

![Word makro koji sadrži nedostižnu uslovnu granu sa junk code](<../images/image (369).png>)

## Obrasci makroa

VBA UserForms mogu čuvati podatke u kontrolama kao što su tekstualna polja. Pošto obrasci, okviri i stranice mogu izložiti sopstvenu kolekciju `Controls`, analitičari bi trebalo da nabroje celu hijerarhiju kontrola, umesto da se oslanjaju samo na ono što obrazac prikazuje. Primer u nastavku čuva skrivene podatke u preklapajućim tekstualnim poljima.<sup>[[1]](#references)</sup>

Tokom dinamičke analize, VBA funkcija `GetObject` može preuzeti Automation objekat iz datoteke ili se povezati sa već pokrenutim Automation serverom. Makroi mogu koristiti taj pristup objektu da dođu do podataka koji nisu očigledni u vidljivom dokumentu; ispitajte i vraćeni objekat i stablo kontrola UserForm obrasca.<sup>[[2]](#references)</sup>

![UserForm makro sa podacima skrivenim u preklapajućim tekstualnim poljima](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - Kolekcije, kontrole i objekti (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
- [2] [Microsoft Learn - Funkcija `GetObject`](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/getobject-function)
{{#include ../banners/hacktricks-training.md}}
