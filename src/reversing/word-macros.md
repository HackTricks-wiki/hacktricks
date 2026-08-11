# Word makroi

{{#include ../banners/hacktricks-training.md}}

## Junk Code

Makroi mogu sadržati **nedostižan ili nerelevantan kod** čija je svrha da uspori analizu. Identifikujte konstantne uslove i pratite dostižno ponašanje pre nego što utrošite vreme na reverse engineering grane. Primer u nastavku koristi `If` uslov koji nikada ne može biti ispunjen kako bi sakrio junk code.

![Word makro koji sadrži nedostižnu uslovnu granu sa junk code-om](<../images/image (369).png>)

## Macro Forms

VBA UserForms mogu čuvati podatke u kontrolama, kao što su tekstualna polja. Pošto forme, okviri i stranice mogu izlagati kolekciju `Controls`, analitičari bi trebalo da nabroje celu hijerarhiju kontrola, umesto da se oslanjaju samo na ono što forma prikazuje. Primer u nastavku čuva skrivene podatke u preklapajućim tekstualnim poljima.<sup>[[1]](#references)</sup>

![Macro UserForm sa podacima skrivenim u preklapajućim tekstualnim poljima](<../images/image (344).png>)

## References

- [1] [Microsoft Learn - Kolekcije, kontrole i objekti (Microsoft Forms)](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/objects-microsoft-forms)
{{#include ../banners/hacktricks-training.md}}
