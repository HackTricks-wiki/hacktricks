# Word Macros

{{#include ../banners/hacktricks-training.md}}

### Neupotrebljivi kod

Veoma je uobičajeno pronaći **neupotrebljivi kod koji se nikada ne koristi** kako bi se otežala analiza makroa.\
Na primer, na sledećoj slici možete videti da se koristi `If` za izvršavanje neupotrebljivog i beskorisnog koda, iako taj uslov nikada neće biti ispunjen.

![Word Macros - Neupotrebljivi kod: Na primer, na sledećoj slici možete videti da se koristi If za izvršavanje neupotrebljivog i beskorisnog koda, iako taj uslov nikada neće biti ispunjen](<../images/image (369).png>)

### Forme makroa

Korišćenjem funkcije **GetObject** moguće je dobiti podatke iz formi makroa. Ovo može otežati analizu. U nastavku je prikazana forma makroa koja se koristi za **skrivanje podataka unutar tekstualnih polja** (tekstualno polje može skrivati druga tekstualna polja):

![Neupotrebljivi kod - Forme makroa: Korišćenjem funkcije GetObject moguće je dobiti podatke iz formi makroa. Ovo može otežati analizu. U nastavku je prikazana fotografija...](<../images/image (344).png>)

{{#include ../banners/hacktricks-training.md}}
