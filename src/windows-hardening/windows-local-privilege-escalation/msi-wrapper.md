# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper kan ’n uitvoerbare lêer of script as ’n Windows Installer-(`.msi`)-lêer verpak. Laai die gratis uitgawe af en begin dit, en kies dan die uitvoerbare lêer om te verpak.<sup>[[3]](#references)</sup> Om ’n reeks opdragte uit te voer, kies ’n `.bat`-lêer as die invoer eerder as om `cmd.exe` te verpak.<sup>[[1]](#references)</sup>

![Kies die bron-uitvoerbare lêer of bondelskrip in MSI Wrapper](<../../images/image (417).png>)

Stel die uitvoeringskonteks en ander installeerder-eienskappe noukeurig op:

![Konfigureer die toepassings-ID en sekuriteitskonteks in MSI Wrapper](<../../images/image (312).png>)

![Konfigureer installeerder-eienskappe in MSI Wrapper](<../../images/image (346).png>)

![Hersien die MSI Wrapper-bouinstellings](<../../images/image (1072).png>)

Hierdie waardes kan verander word wanneer ’n pasgemaakte binary verpak word.

Gaan voort deur die oorblywende wizard-bladsye en kies **Build** om die installeerder te genereer.<sup>[[1]](#references)</sup>

> [!WARNING]
> Die skep van ’n MSI verleen nie op sigself verhoogde privileges nie. Of die installasie verhoogde privileges het, hang af van Windows Installer-beleid, pakketkonteks en gebruikersmagtiging. Microsoft waarsku dat die aktivering van `AlwaysInstallElevated` vir beide die gebruiker en rekenaar nie-administrateurs toelaat om pakkette met stelselprivileges te installeer.<sup>[[2]](#references)</sup>

## References

- [1] [MSI Wrapper-dokumentasie - Aan die gang kom](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Installeer ’n pakket met verhoogde privileges vir ’n nie-administrateur](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Aflaai](https://www.exemsi.com/download/)
{{#include ../../banners/hacktricks-training.md}}
