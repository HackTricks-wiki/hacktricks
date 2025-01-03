# Word Macros

{{#include ../banners/hacktricks-training.md}}

### Junk Code

Veoma je uobičajeno pronaći **junk code koji se nikada ne koristi** kako bi se otežalo obrnuto inženjerstvo makroa.\
Na primer, na sledećoj slici možete videti da se If koji nikada neće biti tačan koristi za izvršavanje nekog junk i beskorisnog koda.

![](<../images/image (369).png>)

### Macro Forms

Korišćenjem **GetObject** funkcije moguće je dobiti podatke iz formi makroa. Ovo se može koristiti za otežavanje analize. Sledeća slika prikazuje makro formu koja se koristi za **sakrivanje podataka unutar tekstualnih okvira** (tekstualni okvir može sakriti druge tekstualne okvire):

![](<../images/image (344).png>)

{{#include ../banners/hacktricks-training.md}}
