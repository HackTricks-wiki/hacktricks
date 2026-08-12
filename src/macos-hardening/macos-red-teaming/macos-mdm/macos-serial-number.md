# Nambari ya Seriali ya macOS

{{#include ../../../banners/hacktricks-training.md}}

## Taarifa za Msingi

Usidhani kwamba kila Mac ina nambari ya seriali yenye herufi 12 inayoweza kufasiriwa. Muundo wa zamani wa Apple uliweka ndani yake taarifa za utengenezaji na usanidi, lakini Apple ilianza kutumia nambari za seriali zilizobadilishwa bila mpangilio katika bidhaa mpya mwaka 2021. Muundo huu wa kubadilishwa bila mpangilio hauonyeshi maelezo ya utengenezaji au usanidi.<sup>[[1]](#references)</sup>

### Muundo wa zamani wenye herufi 12

Kwa vifaa vingi vilivyotengenezwa kuanzia 2010 hadi kabla ya mabadiliko kwenda kwenye muundo wa kubadilishwa bila mpangilio, muundo wenye herufi 12 bado unaweza kutoa vidokezo muhimu vya inventory:<sup>[[3]](#references)</sup>

- Herufi 1–3 hubainisha eneo la utengenezaji.
- Herufi 4–5 huonyesha nusu ya mwaka na wiki ya uzalishaji.
- Herufi 6–8 hutofautisha vifaa vilivyotengenezwa katika eneo na wakati uleule.
- Herufi 9–12 hubainisha model au msimbo wa usanidi.

Kwa mfano, `C02L13ECF8J2` unafuata muundo huu wa zamani. Ramani za viwanda zinazodumishwa na jamii zinajumuisha viambishi kama `FC`, `F`, `XA`, `XB`, `QP`, na `G8` kwa maeneo ya Marekani; `RN` kwa Mexico; `CK` kwa Cork; `VM` kwa eneo la Foxconn nchini Jamhuri ya Czech; `SG` au `E` kwa Singapore; `MB` kwa Malaysia; `PT` au `CY` kwa Korea; na `EE`, `QT`, au `UV` kwa Taiwan. Viambishi vingi—ikiwemo `FK`, `F1`, `F2`, `W8`, `DL`, `DM`, `DN`, `YM`, `7J`, `1C`, `4H`, `WQ`, `F7`, `C0`, `C3`, na `C7`—vimehusishwa na vituo vya China; `RM` imehusishwa na vifaa vilivyorekebishwa.<sup>[[3]](#references)</sup>

Misimbo ya tarehe ya herufi ya nne huanzia `C` (nusu ya kwanza ya 2010) hadi `Z` (nusu ya pili ya 2019), kisha mfuatano huo hutumika tena. Kwa herufi ya tano, tarakimu `1`–`9` huwakilisha wiki 1–9, huku herufi `C`–`Y`, isipokuwa vokali na `S`, zikiwakilisha wiki 10–27; ongeza 26 wakati herufi ya nne inapoonyesha nusu ya pili ya mwaka.<sup>[[3]](#references)</sup>

Ramani hizi ni muhimu kwa triage ya vifaa vya muundo wa zamani, lakini si uthibitisho wa mamlaka wa asili, umri, au uhalisi. Thibitisha matokeo kupitia data ya inventory ya Apple.

Kwa utambuzi wa kuaminika, pata nambari ya seriali kutoka kwenye kifaa na utumie lookup ya Apple ya coverage au specifications za kiufundi badala ya kujaribu kubaini model kutokana na nafasi za herufi.<sup>[[2]](#references)</sup>

### Pata nambari ya seriali

Kiolesura cha picha huionyesha chini ya **Apple menu > About This Mac**.<sup>[[2]](#references)</sup> Kutoka kwenye shell, amri yoyote kati ya zifuatazo husoma nambari ya seriali ya platform:
```bash
system_profiler SPHardwareDataType | awk -F ': ' '/Serial Number/ {print $2}'
ioreg -rd1 -c IOPlatformExpertDevice | awk -F '"' '/IOPlatformSerialNumber/ {print $4}'
```
Chukulia nambari ya seriali kama kitambulishi, si authenticator: thibitisha kifaa kupitia mchakato husika wa Apple au MDM wa inventory kabla ya kufanya maamuzi kuhusu enrollment au umiliki.

## References

- [1] [MacRumors - Apple inaanza mabadiliko kuelekea nambari za seriali zilizobahatishwa](https://www.macrumors.com/2021/05/05/purple-iphone-12-randomized-serial-number/)
- [2] [Apple Support - Tafuta jina la modeli na nambari ya seriali ya Mac yako](https://support.apple.com/en-us/102767)
- [3] [Beetstech - Fafanua maana iliyo nyuma ya nambari ya seriali ya Apple](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)
{{#include ../../../banners/hacktricks-training.md}}
