# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper kan ’n uitvoerbare lêer of script as ’n Windows Installer (`.msi`)-lêer verpak. Laai die gratis weergawe af en begin dit, en kies dan die uitvoerbare lêer om te verpak. Om ’n reeks opdragte uit te voer, kies ’n `.bat`-lêer as die invoer in plaas daarvan om `cmd.exe` te verpak.<sup>[[1]](#references)</sup>

![Kies die bron-uitvoerbare lêer of bondelskrip in MSI Wrapper](<../../images/image (417).png>)

Stel die uitvoeringskonteks en ander installer-eienskappe noukeurig op:

![Konfigureer die toepassings-ID en sekuriteitskonteks in MSI Wrapper](<../../images/image (312).png>)

![Konfigureer installer-eienskappe in MSI Wrapper](<../../images/image (346).png>)

![Hersien die MSI Wrapper-bouinstellings](<../../images/image (1072).png>)

Hierdie waardes kan verander word wanneer ’n custom binary verpak word.

Gaan voort deur die oorblywende wizard-bladsye en kies **Build** om die installer te genereer.<sup>[[1]](#references)</sup>

> [!WARNING]
> Die skep van ’n MSI verleen nie op sigself verhoogde privileges nie. Of die installasie verhoog word, hang af van Windows Installer-beleid, pakketkonteks en gebruikerstoestemming. Microsoft waarsku dat die aktivering van `AlwaysInstallElevated` vir sowel die gebruiker as die rekenaar nie-administrateurs toelaat om pakkette met system privileges te installeer.<sup>[[2]](#references)</sup>

## References

- [1] [MSI Wrapper-dokumentasie - Aan die gang kom](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Installeer ’n pakket met verhoogde privileges vir ’n nie-admin](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
{{#include ../../banners/hacktricks-training.md}}
