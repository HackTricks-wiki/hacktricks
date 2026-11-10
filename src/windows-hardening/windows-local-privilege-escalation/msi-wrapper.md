# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper kan ’n uitvoerbare lêer of script as ’n Windows Installer (`.msi`)-lêer verpak. Laai die gratis uitgawe af en begin dit, en kies dan die uitvoerbare lêer om te verpak.<sup>[[3]](#references)</sup> Om ’n reeks opdragte uit te voer, kies ’n `.bat`-lêer as die invoer eerder as om `cmd.exe` te verpak.<sup>[[1]](#references)</sup>

![Selecting the source executable or batch script in MSI Wrapper](<../../images/image (417).png>)

Stel die uitvoeringskonteks en ander installeerder-eienskappe sorgvuldig op:

![Configuring the application ID and security context in MSI Wrapper](<../../images/image (312).png>)

![Configuring installer properties in MSI Wrapper](<../../images/image (346).png>)

![Reviewing the MSI Wrapper build settings](<../../images/image (1072).png>)

Hierdie waardes kan verander word wanneer ’n pasgemaakte binêre lêer verpak word.

Gaan voort deur die oorblywende towenaarbladsye en kies **Build** om die installeerder te genereer.<sup>[[1]](#references)</sup>

## Verifieer die uitvoeringskonteks van die ingeslote opdrag

Vir ’n toetspakket, sluit ’n `.bat`-lêer in wat sy token aanteken, eerder as om aan te neem dat die MSI se verhogingsinstelling op sy child process van toepassing is.<sup>[[4]](#references)</sup> Kies in die towenaar die **System**-sekuriteitskonteks eerder as **User**, en kies ’n per-masjien-installasie met verhoogde regte wanneer dit die bedoelde roete is.<sup>[[5]](#references)</sup> Die **System**-opsie omseil nie magtiging nie: ’n nie-administrateur het steeds ’n roete vir ’n installasie met verhoogde regte nodig, soos die [twee-beleid-`AlwaysInstallElevated`-wanopstelling](index.html#alwaysinstallelevated) of ’n bevoorregte installeerderwerkvloei.<sup>[[2]](#references)</sup> As **User** gekies word, loop die ingeslote opdrag eerder in die installerende gebruiker se konteks, wat dalk nodig is vir gebruikerspesifieke of netwerkhulpbronne.<sup>[[5]](#references)</sup>

```bat
@echo off
whoami /all > "C:\Users\Public\msi-wrapper-context.txt"
exit /b 0
```

Bou die MSI met hierdie batch-lêer as invoer, voer dit dan op die toetsgasheer uit en ondersoek die aangetekende identiteit en voorregte.<sup>[[4]](#references)</sup> MSI Wrapper koppel ’n nie-nul batch-uitgangskode aan installasiefout 1603, dus voorkom die eksplisiete nul dat ’n suksesvolle toets valslik as ’n mislukking aangedui word.<sup>[[4]](#references)</sup> Die uitvoerlêer is ’n toetsartefak; moenie SYSTEM-uitvoering aflei bloot omdat `msiexec` suksesvol geëindig het of die installasie stil verloop het nie.<sup>[[5]](#references)[[6]](#references)</sup>

```cmd
msiexec.exe /i "C:\Users\Public\context-test.msi" /qn /norestart /L*V "C:\Users\Public\context-test.log"
type "C:\Users\Public\msi-wrapper-context.txt"
```

`/qn` onderdruk die MSI UI, maar nie noodwendig die eie UI van die ingepakte uitvoerbare lêer nie.<sup>[[6]](#references)[[7]](#references)</sup> Stel vir ’n ingepakte installeerder sy ondersteunde stille argumente in die wizard in; MSI Wrapper se dinamiese `WRAPPED_ARGUMENTS`-eienskap is ’n PRO-funksie.<sup>[[1]](#references)[[7]](#references)</sup> Sien [die WiX custom-action-benadering](create-msi-with-wix.md) as jy direkte beheer oor die volgorde van custom actions en impersonation nodig het.

> [!WARNING]
> Die skep van ’n MSI verleen nie vanself verhoogde voorregte nie. Of die installasie verhoogde voorregte het, hang af van die Windows Installer-beleid, pakketkonteks en gebruikerstoestemming. Microsoft waarsku dat die aktivering van `AlwaysInstallElevated` vir beide die gebruiker en die rekenaar nie-administrateurs toelaat om pakkette met stelselvoorregte te installeer.<sup>[[2]](#references)</sup>



## References

- [1] [MSI Wrapper-dokumentasie - Aan die gang](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Installering van ’n pakket met verhoogde voorregte vir ’n nie-administrateur](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Aflaai](https://www.exemsi.com/download/)
- [4] [MSI Wrapper - Skep msi vanaf ’n batch-lêer](https://www.exemsi.com/documentation/create-msi-from-batch-file/)
- [5] [MSI Wrapper - Wizard-bladsye](https://www.exemsi.com/documentation/wizard-pages/)
- [6] [Microsoft Learn - Opdragreëlopsies](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options)
- [7] [MSI Wrapper - Opdragreëlargumente](https://www.exemsi.com/documentation/command-line-arguments/)
{{#include ../../banners/hacktricks-training.md}}
