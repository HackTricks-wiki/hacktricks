# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper može da upakuje izvršnu datoteku ili skriptu kao Windows Installer (`.msi`) datoteku. Preuzmite i pokrenite besplatno izdanje, a zatim izaberite izvršnu datoteku koju želite da upakujete.<sup>[[3]](#references)</sup> Da biste pokrenuli niz komandi, za ulaz izaberite `.bat` datoteku umesto da pakujete `cmd.exe`.<sup>[[1]](#references)</sup>

![Biranje izvorne izvršne datoteke ili batch skripte u MSI Wrapper-u](<../../images/image (417).png>)

Pažljivo podesite kontekst izvršavanja i druga svojstva instalacionog programa:

![Podešavanje ID-a aplikacije i bezbednosnog konteksta u MSI Wrapper-u](<../../images/image (312).png>)

![Podešavanje svojstava instalacionog programa u MSI Wrapper-u](<../../images/image (346).png>)

![Pregled podešavanja za izradu u MSI Wrapper-u](<../../images/image (1072).png>)

Ove vrednosti mogu da se promene prilikom pakovanja prilagođene binarne datoteke.

Nastavite kroz preostale stranice čarobnjaka i izaberite **Build** da biste generisali instalacioni program.<sup>[[1]](#references)</sup>

## Proverite kontekst izvršavanja umotane komande

Za testni paket umotajte `.bat` datoteku koja beleži svoj token, umesto da pretpostavite da se podešavanje elevacije MSI-ja primenjuje i na njegov podređeni proces.<sup>[[4]](#references)</sup> U čarobnjaku izaberite bezbednosni kontekst **System**, a ne **User**, i odaberite instalaciju za ceo računar sa povišenim privilegijama ako je to željeni način instalacije.<sup>[[5]](#references)</sup> Opcija **System** ne zaobilazi autorizaciju: i korisniku koji nije administrator i dalje je potreban način pokretanja instalacije sa povišenim privilegijama, kao što je [pogrešna konfiguracija `AlwaysInstallElevated` sa dve smernice](index.html#alwaysinstallelevated) ili privilegovani tok instalacije.<sup>[[2]](#references)</sup> Ako umesto toga izaberete **User**, umotana komanda će se pokrenuti u kontekstu korisnika koji instalira program, što može biti neophodno za resurse specifične za korisnika ili mrežne resurse.<sup>[[5]](#references)</sup>

```bat
@echo off
whoami /all > "C:\Users\Public\msi-wrapper-context.txt"
exit /b 0
```

Napravite MSI koristeći ovu batch datoteku kao ulaz, zatim ga pokrenite na testnom hostu i proverite zabeleženi identitet i privilegije.<sup>[[4]](#references)</sup> MSI Wrapper mapira nenulti izlazni kod batch datoteke na grešku instalacije 1603, pa eksplicitna nula sprečava lažnu grešku nakon uspešnog testa.<sup>[[4]](#references)</sup> Izlazna datoteka je artefakt testa; nemojte zaključiti da je izvršavanje obavljeno kao SYSTEM samo na osnovu uspešnog izlaza komande `msiexec` ili tihe instalacije.<sup>[[5]](#references)[[6]](#references)</sup>

```cmd
msiexec.exe /i "C:\Users\Public\context-test.msi" /qn /norestart /L*V "C:\Users\Public\context-test.log"
type "C:\Users\Public\msi-wrapper-context.txt"
```

`/qn` utišava MSI UI, ali ne nužno i UI samog umotanog izvršnog fajla.<sup>[[6]](#references)[[7]](#references)</sup> Za umotani instalacioni program, podesite njegove podržane tihe argumente u čarobnjaku; dinamičko svojstvo `WRAPPED_ARGUMENTS` u MSI Wrapper-u dostupno je samo u PRO verziji.<sup>[[1]](#references)[[7]](#references)</sup> Pogledajte [pristup sa WiX custom-action](create-msi-with-wix.md) ako vam je potrebna direktna kontrola nad redosledom custom-action-a i impersonation-om.

> [!WARNING]
> Samo kreiranje MSI-ja ne dodeljuje povišene privilegije. Da li se instalacija izvršava sa povišenim privilegijama zavisi od Windows Installer politike, konteksta paketa i ovlašćenja korisnika. Microsoft upozorava da omogućavanje opcije `AlwaysInstallElevated` i za korisnika i za računar dozvoljava korisnicima koji nisu administratori da instaliraju pakete sa sistemskim privilegijama.<sup>[[2]](#references)</sup>



## References

- [1] [Dokumentacija za MSI Wrapper - Početak rada](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Instaliranje paketa sa povišenim privilegijama za korisnika koji nije administrator](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Preuzimanje](https://www.exemsi.com/download/)
- [4] [MSI Wrapper - Kreiranje MSI-ja iz batch datoteke](https://www.exemsi.com/documentation/create-msi-from-batch-file/)
- [5] [MSI Wrapper - Stranice čarobnjaka](https://www.exemsi.com/documentation/wizard-pages/)
- [6] [Microsoft Learn - Opcije komandne linije](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options)
- [7] [MSI Wrapper - Argumenti komandne linije](https://www.exemsi.com/documentation/command-line-arguments/)
{{#include ../../banners/hacktricks-training.md}}
