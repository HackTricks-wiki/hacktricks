# Hash Length Extension Attack

{{#include ../banners/hacktricks-training.md}}

## Sažetak napada

Zamislite server koji **potpisuje** neke **podatke** tako što **dodaje** **tajnu** nekim poznatim čistim tekstualnim podacima i zatim hešira te podatke. Ako znate:

- **Dužinu tajne** (to se može takođe bruteforcovati iz datog opsega dužine)
- **Čiste tekstualne podatke**
- **Algoritam (i da je podložan ovom napadu)**
- **Padding je poznat**
- Obično se koristi podrazumevani, tako da ako su ispunjena druga 3 zahteva, ovo takođe važi
- Padding varira u zavisnosti od dužine tajne + podataka, zato je dužina tajne potrebna

Tada je moguće da **napadač** **doda** **podatke** i **generiše** važeći **potpis** za **prethodne podatke + dodate podatke**.

### Kako?

U suštini, ranjivi algoritmi generišu heš tako što prvo **heširaju blok podataka**, a zatim, **iz** **prethodno** kreiranog **heša** (stanja), **dodaju sledeći blok podataka** i **heširaju ga**.

Zamislite da je tajna "secret" a podaci su "data", MD5 od "secretdata" je 6036708eba0d11f6ef52ad44e8b74d5b.\
Ako napadač želi da doda string "append" može:

- Generisati MD5 od 64 "A"
- Promeniti stanje prethodno inicijalizovanog heša na 6036708eba0d11f6ef52ad44e8b74d5b
- Dodati string "append"
- Završiti heš i rezultantni heš će biti **važeći za "secret" + "data" + "padding" + "append"**

### **Alat**

{% embed url="https://github.com/iagox86/hash_extender" %}

### Reference

Ovaj napad je dobro objašnjen na [https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

{{#include ../banners/hacktricks-training.md}}
