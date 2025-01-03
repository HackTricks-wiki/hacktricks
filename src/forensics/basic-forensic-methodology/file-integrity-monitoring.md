{{#include ../../banners/hacktricks-training.md}}

# Osnovna linija

Osnovna linija se sastoji od pravljenja snimka određenih delova sistema kako bi se **uporedila sa budućim statusom radi isticanja promena**.

Na primer, možete izračunati i sačuvati hash svake datoteke u datotečnom sistemu kako biste mogli da saznate koje su datoteke modifikovane.\
To se takođe može uraditi sa korisničkim nalozima koji su kreirani, procesima koji se izvršavaju, servisima koji se izvršavaju i bilo čim drugim što ne bi trebalo da se mnogo menja, ili uopšte.

## Praćenje integriteta datoteka

Praćenje integriteta datoteka (FIM) je kritična bezbednosna tehnika koja štiti IT okruženja i podatke praćenjem promena u datotekama. Uključuje dva ključna koraka:

1. **Uporedna analiza osnovne linije:** Uspostavite osnovnu liniju koristeći atribute datoteka ili kriptografske heš vrednosti (kao što su MD5 ili SHA-2) za buduće uporedbe radi otkrivanja modifikacija.
2. **Obaveštavanje o promenama u realnom vremenu:** Dobijajte trenutna obaveštenja kada se datoteke pristupaju ili menjaju, obično putem ekstenzija jezgra OS-a.

## Alati

- [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
- [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

## Reference

- [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)

{{#include ../../banners/hacktricks-training.md}}
