# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper inaweza kufungasha executable au script kama faili la Windows Installer (`.msi`). Pakua na uanzishe toleo lisilolipishwa, kisha uchague executable ya kufungasha.<sup>[[3]](#references)</sup> Ili kutekeleza mfululizo wa amri, chagua faili la `.bat` kama ingizo badala ya kufungasha `cmd.exe`.<sup>[[1]](#references)</sup>

![Kuchagua executable ya chanzo au batch script katika MSI Wrapper](<../../images/image (417).png>)

Sanidi muktadha wa utekelezaji na sifa nyingine za installer kwa uangalifu:

![Kusanidi application ID na muktadha wa usalama katika MSI Wrapper](<../../images/image (312).png>)

![Kusanidi sifa za installer katika MSI Wrapper](<../../images/image (346).png>)

![Kukagua mipangilio ya build ya MSI Wrapper](<../../images/image (1072).png>)

Thamani hizi zinaweza kubadilishwa unapofungasha binary maalum.

Endelea kupitia kurasa zilizosalia za wizard na uchague **Build** ili kutengeneza installer.<sup>[[1]](#references)</sup>

## Thibitisha muktadha wa utekelezaji wa amri iliyofungashwa

Kwa kifurushi cha majaribio, fungasha faili la `.bat` linalorekodi token yake badala ya kudhani kuwa mpangilio wa elevation wa MSI unatumika kwa mchakato wake wa child.<sup>[[4]](#references)</sup> Katika wizard, chagua muktadha wa usalama wa **System** badala ya **User**, na uchague usakinishaji wa per-machine ulio na elevation ikiwa hiyo ndiyo njia inayokusudiwa.<sup>[[5]](#references)</sup> Chaguo la **System** halipiti authorization: mtumiaji asiye admin bado anahitaji njia ya usakinishaji iliyo na elevation, kama vile [usanidi usio salama wa sera mbili wa `AlwaysInstallElevated`](index.html#alwaysinstallelevated) au workflow ya installer yenye privileged.<sup>[[2]](#references)</sup> Kuchagua **User** badala yake hutekeleza amri iliyofungashwa katika muktadha wa mtumiaji anayesakinisha, jambo ambalo linaweza kuhitajika kwa rasilimali maalum za mtumiaji au za mtandao.<sup>[[5]](#references)</sup>

```bat
@echo off
whoami /all > "C:\Users\Public\msi-wrapper-context.txt"
exit /b 0
```

Tengeneza MSI kwa kutumia batch file hii kama ingizo, kisha iendeshe kwenye test host na ukague identity na privileges zilizorekodiwa.<sup>[[4]](#references)</sup> MSI Wrapper hubadilisha batch exit code isiyo sifuri kuwa installation error 1603, kwa hiyo exit code sifuri iliyoainishwa huepusha hitilafu ya uongo baada ya test kufanikiwa.<sup>[[4]](#references)</sup> Faili ya matokeo ni test artifact; usihitimishe kuwa ilitekelezwa kwa SYSTEM kwa kutegemea tu exit code iliyofanikiwa ya `msiexec` au usakinishaji wa kimya.<sup>[[5]](#references)[[6]](#references)</sup>

```cmd
msiexec.exe /i "C:\Users\Public\context-test.msi" /qn /norestart /L*V "C:\Users\Public\context-test.log"
type "C:\Users\Public\msi-wrapper-context.txt"
```

`/qn` hunyamazisha UI ya MSI, lakini si lazima UI ya executable iliyofungwa nayo.<sup>[[6]](#references)[[7]](#references)</sup> Kwa installer iliyofungwa, weka argument zake za silent zinazotumika kwenye wizard; property ya dynamic `WRAPPED_ARGUMENTS` ya MSI Wrapper ni kipengele cha PRO.<sup>[[1]](#references)[[7]](#references)</sup> Tazama [mbinu ya custom-action ya WiX](create-msi-with-wix.md) ikiwa unahitaji udhibiti wa moja kwa moja juu ya mpangilio wa custom-action na impersonation.

> [!WARNING]
> Kuunda MSI hakutoi elevated privileges kivyake. Ikiwa installation ina elevated privileges hutegemea sera ya Windows Installer, muktadha wa package na idhini ya mtumiaji. Microsoft inaonya kuwa kuwezesha `AlwaysInstallElevated` kwa mtumiaji na kompyuta kunawaruhusu wasiokuwa admins kusakinisha packages kwa system privileges.<sup>[[2]](#references)</sup>



## References

- [1] [MSI Wrapper documentation - Kuanza](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Kusakinisha package yenye elevated privileges kwa asiye admin](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Pakua](https://www.exemsi.com/download/)
- [4] [MSI Wrapper - Kuunda msi kutoka kwa batch file](https://www.exemsi.com/documentation/create-msi-from-batch-file/)
- [5] [MSI Wrapper - Kurasa za Wizard](https://www.exemsi.com/documentation/wizard-pages/)
- [6] [Microsoft Learn - Chaguo za Command-Line](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options)
- [7] [MSI Wrapper - Argument za Command Line](https://www.exemsi.com/documentation/command-line-arguments/)
{{#include ../../banners/hacktricks-training.md}}
