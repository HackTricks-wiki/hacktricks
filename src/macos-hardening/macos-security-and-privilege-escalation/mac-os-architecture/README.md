# macOS Kernel & System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

Die **kern van macOS is XNU**, wat staan vir "X is Not Unix". Hierdie kern is fundamenteel saamgestel uit die **Mach mikrokerne**l (wat later bespreek sal word), **en** elemente van Berkeley Software Distribution (**BSD**). XNU bied ook 'n platform vir **kern bestuurders via 'n stelsel genaamd die I/O Kit**. Die XNU-kern is deel van die Darwin open source projek, wat beteken **sy bronkode is vrylik beskikbaar**.

Vanuit die perspektief van 'n sekuriteitsnavorsers of 'n Unix-ontwikkelaar, kan **macOS** baie **soortgelyk** voel aan 'n **FreeBSD** stelsel met 'n elegante GUI en 'n verskeidenheid van pasgemaakte toepassings. Meeste toepassings wat vir BSD ontwikkel is, sal saamgecompileer en op macOS loop sonder dat aanpassings nodig is, aangesien die opdraglyn gereedskap wat bekend is aan Unix-gebruikers, almal in macOS teenwoordig is. egter, omdat die XNU-kern Mach inkorporeer, is daar 'n paar beduidende verskille tussen 'n tradisionele Unix-agtige stelsel en macOS, en hierdie verskille kan potensiële probleme veroorsaak of unieke voordele bied.

Open source weergawe van XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach is 'n **mikrokerne**l wat ontwerp is om **UNIX-compatibel** te wees. Een van sy sleutelontwerp beginsels was om die hoeveelheid **kode** wat in die **kern** ruimte loop te **minimaliseer** en eerder toe te laat dat baie tipiese kern funksies, soos lêerstelsels, netwerk, en I/O, as **gebruikersvlak take** loop.

In XNU is Mach **verantwoordelik vir baie van die kritieke laagvlak operasies** wat 'n kern tipies hanteer, soos prosessor skedulering, multitasking, en virtuele geheue bestuur.

### BSD

Die XNU **kern** inkorporeer ook 'n beduidende hoeveelheid kode wat afkomstig is van die **FreeBSD** projek. Hierdie kode **loop as deel van die kern saam met Mach**, in dieselfde adresruimte. egter, die FreeBSD kode binne XNU mag aansienlik verskil van die oorspronklike FreeBSD kode omdat aanpassings nodig was om sy kompatibiliteit met Mach te verseker. FreeBSD dra by tot baie kern operasies insluitend:

- Proses bestuur
- Sein hantering
- Basiese sekuriteitsmeganismes, insluitend gebruiker en groep bestuur
- Stelselskakel infrastruktuur
- TCP/IP stapel en sokkies
- Vuurmuur en pakketfiltrering

Om die interaksie tussen BSD en Mach te verstaan, kan kompleks wees, as gevolg van hul verskillende konseptuele raamwerke. Byvoorbeeld, BSD gebruik prosesse as sy fundamentele uitvoerende eenheid, terwyl Mach werk op grond van drade. Hierdie verskil word in XNU versoen deur **elke BSD-proses te assosieer met 'n Mach-taak** wat presies een Mach-draad bevat. Wanneer BSD se fork() stelselskakel gebruik word, gebruik die BSD kode binne die kern Mach funksies om 'n taak en 'n draadstruktuur te skep.

Boonop, **Mach en BSD handhaaf elk verskillende sekuriteitsmodelle**: **Mach se** sekuriteitsmodel is gebaseer op **poortregte**, terwyl BSD se sekuriteitsmodel werk op grond van **prosesbesit**. Verskille tussen hierdie twee modelle het af en toe gelei tot plaaslike voorreg-verhoging kwesbaarhede. Behalwe vir tipiese stelselskakels, is daar ook **Mach traps wat gebruikersvlak programme toelaat om met die kern te kommunikeer**. Hierdie verskillende elemente saam vorm die veelvlakkige, hibriede argitektuur van die macOS-kern.

### I/O Kit - Drivers

Die I/O Kit is 'n open-source, objek-georiënteerde **toestel-bestuurder raamwerk** in die XNU-kern, wat **dynamies gelaaide toestel bestuurders** hanteer. Dit laat modulaire kode toe om aan die kern bygevoeg te word terwyl dit loop, wat diverse hardeware ondersteun.

{{#ref}}
macos-iokit.md
{{#endref}}

### IPC - Inter Process Communication

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel Extensions

macOS is **baie beperkend om Kernel Extensions** (.kext) te laai weens die hoë voorregte wat kode sal loop. Trouens, standaard is dit feitlik onmoontlik (tenzij 'n omseiling gevind word).

Op die volgende bladsy kan jy ook sien hoe om die `.kext` te herstel wat macOS binne sy **kernelcache** laai:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS System Extensions

In plaas daarvan om Kernel Extensions te gebruik, het macOS die Stelsels Uitbreidings geskep, wat in gebruikersvlak API's bied om met die kern te kommunikeer. Op hierdie manier kan ontwikkelaars vermy om kern uitbreidings te gebruik.

{{#ref}}
macos-system-extensions.md
{{#endref}}

## References

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
