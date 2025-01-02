# macOS Kernel & System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## XNU Kernel

**Msingi wa macOS ni XNU**, ambayo inasimama kwa "X is Not Unix". Kernel hii kimsingi inajumuisha **Mach microkernel** (itaongelewa baadaye), **na** vipengele kutoka Berkeley Software Distribution (**BSD**). XNU pia inatoa jukwaa kwa **madereva ya kernel kupitia mfumo unaoitwa I/O Kit**. Kernel ya XNU ni sehemu ya mradi wa wazi wa chanzo wa Darwin, ambayo inamaanisha **kanuni yake ya chanzo inapatikana bure**.

Kutoka kwa mtazamo wa mtafiti wa usalama au mendelezo wa Unix, **macOS** inaweza kuonekana kuwa **kama** mfumo wa **FreeBSD** wenye GUI nzuri na idadi ya programu za kawaida. Programu nyingi zilizotengenezwa kwa BSD zitakusanywa na kuendesha kwenye macOS bila kuhitaji marekebisho, kwani zana za amri zinazojulikana kwa watumiaji wa Unix zipo zote kwenye macOS. Hata hivyo, kwa sababu kernel ya XNU inajumuisha Mach, kuna tofauti kubwa kati ya mfumo wa jadi wa Unix na macOS, na tofauti hizi zinaweza kusababisha matatizo ya uwezekano au kutoa faida za kipekee.

Toleo la wazi la XNU: [https://opensource.apple.com/source/xnu/](https://opensource.apple.com/source/xnu/)

### Mach

Mach ni **microkernel** iliyoundwa kuwa **UNIX-inayofaa**. Moja ya kanuni zake kuu za muundo ilikuwa **kupunguza** kiasi cha **kanuni** inayotumika katika **nafasi ya kernel** na badala yake kuruhusu kazi nyingi za kawaida za kernel, kama vile mfumo wa faili, mtandao, na I/O, **kufanya kazi kama kazi za ngazi ya mtumiaji**.

Katika XNU, Mach ni **responsible kwa shughuli nyingi muhimu za kiwango cha chini** ambazo kernel kwa kawaida inashughulikia, kama vile kupanga ratiba ya processor, multitasking, na usimamizi wa kumbukumbu ya virtual.

### BSD

Kernel ya XNU pia **inajumuisha** kiasi kikubwa cha kanuni inayotokana na mradi wa **FreeBSD**. Kanuni hii **inafanya kazi kama sehemu ya kernel pamoja na Mach**, katika nafasi moja ya anwani. Hata hivyo, kanuni ya FreeBSD ndani ya XNU inaweza kutofautiana kwa kiasi kikubwa na kanuni ya asili ya FreeBSD kwa sababu marekebisho yalihitajika kuhakikisha ufanisi wake na Mach. FreeBSD inachangia katika shughuli nyingi za kernel ikiwa ni pamoja na:

- Usimamizi wa mchakato
- Kushughulikia ishara
- Mekanismu za msingi za usalama, ikiwa ni pamoja na usimamizi wa mtumiaji na kikundi
- Miundombinu ya wito wa mfumo
- TCP/IP stack na soketi
- Firewall na kuchuja pakiti

Kuelewa mwingiliano kati ya BSD na Mach kunaweza kuwa ngumu, kutokana na mifumo yao tofauti ya dhana. Kwa mfano, BSD inatumia michakato kama kitengo chake cha msingi cha utekelezaji, wakati Mach inafanya kazi kwa msingi wa nyuzi. Tofauti hii inarekebishwa katika XNU kwa **kuunganisha kila mchakato wa BSD na kazi ya Mach** ambayo ina nyuzi moja tu ya Mach. Wakati wito wa mfumo wa fork() wa BSD unapotumika, kanuni ya BSD ndani ya kernel inatumia kazi za Mach kuunda kazi na muundo wa nyuzi.

Zaidi ya hayo, **Mach na BSD kila mmoja ina mifano tofauti za usalama**: mfano wa usalama wa **Mach** unategemea **haki za bandari**, wakati mfano wa usalama wa BSD unafanya kazi kwa msingi wa **umiliki wa mchakato**. Tofauti kati ya mifano hii miwili mara nyingine imesababisha udhaifu wa kupanda kwa haki za ndani. Mbali na wito wa kawaida wa mfumo, pia kuna **Mach traps zinazoruhusu programu za nafasi ya mtumiaji kuingiliana na kernel**. Vipengele hivi tofauti pamoja vinaunda usanifu wa kipekee, wa mchanganyiko wa kernel ya macOS.

### I/O Kit - Drivers

I/O Kit ni mfumo wa wazi, wa mwelekeo wa kitu **wa madereva ya kifaa** katika kernel ya XNU, inashughulikia **madereva ya kifaa yanayopakiwa kwa nguvu**. Inaruhusu kanuni za moduli kuongezwa kwenye kernel mara moja, ikisaidia vifaa mbalimbali.

{{#ref}}
macos-iokit.md
{{#endref}}

### IPC - Mawasiliano ya Mchakato

{{#ref}}
../macos-proces-abuse/macos-ipc-inter-process-communication/
{{#endref}}

## macOS Kernel Extensions

macOS ni **ya kukandamiza sana kupakia Extensions za Kernel** (.kext) kwa sababu ya haki kubwa ambazo kanuni hiyo itafanya kazi nazo. Kwa kweli, kwa kawaida haiwezekani (isipokuwa njia ya kupita ipatikane).

Katika ukurasa ufuatao unaweza pia kuona jinsi ya kurejesha `.kext` ambayo macOS inapakua ndani ya **kernelcache** yake:

{{#ref}}
macos-kernel-extensions.md
{{#endref}}

### macOS System Extensions

Badala ya kutumia Extensions za Kernel, macOS iliumba System Extensions, ambayo inatoa APIs za ngazi ya mtumiaji kuingiliana na kernel. Kwa njia hii, waendelezaji wanaweza kuepuka kutumia extensions za kernel.

{{#ref}}
macos-system-extensions.md
{{#endref}}

## Marejeleo

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)

{{#include ../../../banners/hacktricks-training.md}}
