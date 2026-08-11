# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper inaweza kufunga executable au script kama faili la Windows Installer (`.msi`). Pakua na uanzishe toleo lisilolipishwa, kisha uchague executable ya kufungwa. Ili kutekeleza mfululizo wa amri, chagua faili la `.bat` kama ingizo badala ya kufunga `cmd.exe`.<sup>[[1]](#references)</sup>

![Kuchagua executable ya chanzo au batch script katika MSI Wrapper](<../../images/image (417).png>)

Sanidi kwa uangalifu muktadha wa utekelezaji na sifa nyingine za installer:

![Kusanidi kitambulisho cha programu na muktadha wa usalama katika MSI Wrapper](<../../images/image (312).png>)

![Kusanidi sifa za installer katika MSI Wrapper](<../../images/image (346).png>)

![Kukagua mipangilio ya build ya MSI Wrapper](<../../images/image (1072).png>)

Thamani hizi zinaweza kubadilishwa unapofunga binary maalum.

Endelea kupitia kurasa zilizobaki za wizard na uchague **Build** ili kutengeneza installer.<sup>[[1]](#references)</sup>

> [!WARNING]
> Kuunda MSI pekee hakutoi privileges zilizoinuliwa. Ikiwa installation itaendeshwa kwa privileges zilizoinuliwa hutegemea sera ya Windows Installer, muktadha wa package, na authorization ya mtumiaji. Microsoft inaonya kwamba kuwezesha `AlwaysInstallElevated` kwa mtumiaji na kompyuta huruhusu watumiaji wasio administrators kusakinisha packages kwa system privileges.<sup>[[2]](#references)</sup>

## References

- [1] [MSI Wrapper documentation - Kuanza](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Kusakinisha package kwa privileges zilizoinuliwa kwa mtumiaji asiye admin](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
{{#include ../../banners/hacktricks-training.md}}
