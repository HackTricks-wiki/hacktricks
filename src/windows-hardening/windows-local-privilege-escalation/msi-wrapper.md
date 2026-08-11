# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper može da upakuje izvršni fajl ili skriptu kao Windows Installer (`.msi`) fajl. Preuzmite i pokrenite besplatno izdanje, a zatim izaberite izvršni fajl koji treba upakovati. Da biste pokrenuli niz komandi, izaberite `.bat` fajl kao ulaz, umesto da pakujete `cmd.exe`.<sup>[[1]](#references)</sup>

![Izbor izvornog izvršnog fajla ili batch skripte u MSI Wrapper-u](<../../images/image (417).png>)

Pažljivo konfigurišite kontekst izvršavanja i ostala svojstva installer-a:

![Konfigurisanje ID-ja aplikacije i bezbednosnog konteksta u MSI Wrapper-u](<../../images/image (312).png>)

![Konfigurisanje svojstava installer-a u MSI Wrapper-u](<../../images/image (346).png>)

![Pregled postavki izgradnje u MSI Wrapper-u](<../../images/image (1072).png>)

Ove vrednosti mogu da se promene prilikom pakovanja prilagođenog binarnog fajla.

Nastavite kroz preostale stranice čarobnjaka i izaberite **Build** da biste generisali installer.<sup>[[1]](#references)</sup>

> [!WARNING]
> Kreiranje MSI-ja samo po sebi ne dodeljuje povišene privilegije. Da li će instalacija biti pokrenuta sa povišenim privilegijama zavisi od Windows Installer politike, konteksta paketa i autorizacije korisnika. Microsoft upozorava da omogućavanje opcije `AlwaysInstallElevated` i za korisnika i za računar omogućava korisnicima koji nisu administratori da instaliraju pakete sa sistemskim privilegijama.<sup>[[2]](#references)</sup>

## References

- [1] [MSI Wrapper documentation - Getting started](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Installing a package with elevated privileges for a non-admin](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
{{#include ../../banners/hacktricks-training.md}}
