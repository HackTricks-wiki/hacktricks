# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper može da upakuje izvršnu datoteku ili skriptu kao Windows Installer (`.msi`) datoteku. Preuzmite i pokrenite besplatnu verziju, a zatim izaberite izvršnu datoteku za pakovanje.<sup>[[3]](#references)</sup> Da biste pokrenuli niz komandi, izaberite `.bat` datoteku kao ulaznu datoteku umesto pakovanja datoteke `cmd.exe`.<sup>[[1]](#references)</sup>

![Izbor izvorne izvršne datoteke ili batch skripte u alatu MSI Wrapper](<../../images/image (417).png>)

Pažljivo konfigurišite kontekst izvršavanja i ostala svojstva instalera:

![Konfigurisanje ID-a aplikacije i bezbednosnog konteksta u alatu MSI Wrapper](<../../images/image (312).png>)

![Konfigurisanje svojstava instalera u alatu MSI Wrapper](<../../images/image (346).png>)

![Pregled podešavanja za izgradnju u alatu MSI Wrapper](<../../images/image (1072).png>)

Ove vrednosti mogu da se promene prilikom pakovanja prilagođenog binarnog fajla.

Nastavite kroz preostale stranice čarobnjaka i izaberite **Build** da biste generisali installer.<sup>[[1]](#references)</sup>

> [!WARNING]
> Samo kreiranje MSI datoteke ne dodeljuje automatski povišene privilegije. Da li će instalacija biti pokrenuta sa povišenim privilegijama zavisi od Windows Installer politike, konteksta paketa i autorizacije korisnika. Microsoft upozorava da omogućavanje opcije `AlwaysInstallElevated` i za korisnika i za računar omogućava korisnicima koji nisu administratori da instaliraju pakete sa sistemskim privilegijama.<sup>[[2]](#references)</sup>

## References

- [1] [MSI Wrapper dokumentacija - Početak rada](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Instaliranje paketa sa povišenim privilegijama za korisnika koji nije administrator](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Preuzimanje](https://www.exemsi.com/download/)
{{#include ../../banners/hacktricks-training.md}}
