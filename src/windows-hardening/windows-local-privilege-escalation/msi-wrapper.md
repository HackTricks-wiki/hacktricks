# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper inaweza ku- package executable au script kama faili la Windows Installer (`.msi`). Pakua na uanzishe toleo lisilolipishwa, kisha uchague executable ya ku-package.<sup>[[3]](#references)</sup> Ili kuendesha mfululizo wa commands, chagua faili la `.bat` kama input badala ya ku-package `cmd.exe`.<sup>[[1]](#references)</sup>

![Kuchagua executable ya chanzo au batch script katika MSI Wrapper](<../../images/image (417).png>)

Sanidi execution context na sifa nyingine za installer kwa uangalifu:

![Kusanidi application ID na security context katika MSI Wrapper](<../../images/image (312).png>)

![Kusanidi sifa za installer katika MSI Wrapper](<../../images/image (346).png>)

![Kukagua build settings za MSI Wrapper](<../../images/image (1072).png>)

Thamani hizi zinaweza kubadilishwa wakati wa ku-package binary maalum.

Endelea kupitia kurasa zilizosalia za wizard na uchague **Build** ili kutengeneza installer.<sup>[[1]](#references)</sup>

> [!WARNING]
> Kuunda MSI hakutoi elevated privileges moja kwa moja. Ikiwa installation itakuwa elevated hutegemea Windows Installer policy, package context na user authorization. Microsoft inaonya kwamba kuwezesha `AlwaysInstallElevated` kwa user na computer kunawawezesha non-administrators ku-install packages kwa system privileges.<sup>[[2]](#references)</sup>

## References

- [1] [Nyaraka za MSI Wrapper - Kuanza](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Ku-install package yenye elevated privileges kwa non-admin](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - Kupakua](https://www.exemsi.com/download/)
{{#include ../../banners/hacktricks-training.md}}
