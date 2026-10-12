# Windows MDL-Mapped User Buffer Double-Fetch

{{#include ../../banners/hacktricks-training.md}}

Windows kernel driver pravi double-fetch kada proverava podatke u stranicama koje je obezbedio pozivalac, a zatim prosleđuje pokazivač na te iste stranice API-ju osetljivom na bezbednost. Zaključavanje i mapiranje stranica ne čini njihov sadržaj nepromenljivim. CVE-2025-55680 u `cldflt.sys` ilustruje ovaj obrazac: drajver je proverio relativno ime Cloud Files placeholder-a, a zatim kreirao objekat dok je i dalje koristio promenljivi bafer pozivaoca.<sup>[[1]](#references)[[3]](#references)</sup>

`CfCreatePlaceholders()` kreira datoteke ili direktorijume ispod registrovanog Cloud Files sync root-a. U ranjivoj putanji, promena imena nakon provere mogla je da preusmeri privilegovano kreiranje izvan tog root-a.<sup>[[1]](#references)[[2]](#references)</sup>

## Zašto zaključavanje stranica nije zaključalo podatke

Ranjiva putanja `HsmpOpCreatePlaceholders()` alocirala je MDL za payload pozivaoca, pozivala `ProbeForRead()` i `MmProbeAndLockPages()`, a zatim mapirala te stranice u kernel virtuelni adresni prostor. MDL opisuje i zaključava fizičke stranice kako bi ostale u memoriji. On **ne** pravi snimak njihovih bajtova. Zbog toga user mode može da izmeni istu fizičku memoriju dok je drajver čita preko sistemskog mapiranja.<sup>[[1]](#references)[[3]](#references)</sup>

Relevantna putanja zahteva i upotrebe bila je:<sup>[[1]](#references)</sup>

1. `cldapi.dll` je poslao Cloud Files kontrolni kod `0x903BC` sa oznakom `IO_REPARSE_TAG_CLOUD` (`0x9000001A`) i operacijom kreiranja placeholder-a `0xC0000001`.
2. Svaki zapis payload-a sadržao je parove 16-bitnih pomeraja i dužina za relativno ime i identitet datoteke. Većina fiksnih polja kopirana je u zapis na steku, ali je ime promenljive dužine ostalo u mapiranim korisničkim stranicama.
3. Drajver je pregledao UTF-16 ime i odbacivao obrnute kose crte ili dvotačke.
4. Zatim je napravio `UNICODE_STRING` čiji je `Buffer` i dalje pokazivao u mapirani payload i dodelio ga polju `OBJECT_ATTRIBUTES.ObjectName`.
5. `FltCreateFileEx2()` je ponovo pročitao taj pokazivač. Paralelni upisivač je zato mogao da učini da provera vidi jedan string, a kreiranje datoteke drugi.

Ovo je **double-fetch** iako oba čitanja koriste kernel virtuelnu adresu: bezbednosna granica zavisi od memorije koja je u pozadini, a ne od toga koju virtuelnu mapu drajver dereferencira.<sup>[[1]](#references)</sup>

## Raspored Cloud Files race-a

Objavljena strategija exploita koristila je ponavljane zahteve, mutator niti i junction kako bi double-fetch pretvorila u preusmeravanje putanje:<sup>[[1]](#references)</sup>

1. Registrujte direktorijum pod kontrolom napadača pomoću `CfRegisterSyncRoot()` i u njemu kreirajte `JUSTASTRING` kao junction ka zaštićenom odredištu.
2. Pripremite deljeni zapis placeholder-a sa ispravnim imenom jedne komponente `JUSTASTRINGDnewfile.dll`.
3. Neka mutator niti naizmenično menjaju UTF-16 kodnu jedinicu `D` između `D` i `\`. Drugi oblik je `JUSTASTRING\newfile.dll`.
4. Istovremeno, neka radne niti neprestano šalju zahteve za kreiranje placeholder-a koji upućuju na isti payload, dok nadzorna nit proverava zaštićeno odredište.
5. Uspešna iteracija proverava oblik bez separatora, a zatim prati junction kada kasnije kreiranje naiđe na oblik koji sadrži `\`.

Ovaj primitive omogućuje samo kreiranje zaštićene datoteke или direktorijuma. Da bi се ово претворило у извршавање кода, и даље су потребни контрола над садржајем креиране датотеке и привилеговани потрошач, као што је одговарајућа мета за DLL side-loading. Првобитна анализа користила је овај завршни тип ланца, али није објавила loader, payload нити потпун самосталан exploit.<sup>[[1]](#references)</sup>

За комплементарне технике које намерно проширују Windows трке у проналажењу путање, погледајте [Kernel Race Condition Exploitation via Object Manager Slow Paths](kernel-race-condition-object-manager-slowdown.md).

## References

- [1] [Exodus Intelligence - Microsoft Windows Cloud Files Minifilter TOCTOU ескалација привилегија](https://blog.exodusintel.com/2025/10/20/microsoft-windows-cloud-files-minifilter-toctou-privilege-escalation/)
- [2] [Microsoft Learn - функција CfCreatePlaceholders](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfcreateplaceholders)
- [3] [Microsoft Learn - функција MmProbeAndLockPages](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmprobeandlockpages)
{{#include ../../banners/hacktricks-training.md}}
