# macOS Reeksnommer

{{#include ../../../banners/hacktricks-training.md}}

## Basiese Inligting

Moenie aanvaar dat elke Mac ’n dekodeerbare 12-karakter-reeksnommer het nie. Apple se ouer formaat het vervaardigings- en konfigurasie-inligting geënkodeer, maar Apple het in 2021 begin om ewekansige reeksnommers met nuwe produkte bekend te stel. Die ewekansige formaat stel nie vervaardigings- of konfigurasiebesonderhede bloot nie.<sup>[[1]](#references)</sup>

### Ouer 12-karakter-formaat

Vir baie toestelle wat van 2010 tot en met die oorgang na ewekansige reeksnommers vervaardig is, kan die 12-karakter-formaat steeds nuttige inventarisleidrade verskaf:<sup>[[3]](#references)</sup>

- Karakters 1–3 identifiseer die vervaardigingsligging.
- Karakters 4–5 enkodeer die produksiehalfjaar en -week.
- Karakters 6–8 onderskei eenhede wat op dieselfde ligging en tyd vervaardig is.
- Karakters 9–12 identifiseer die model- of konfigurasiekode.

Byvoorbeeld, `C02L13ECF8J2` volg hierdie ouer struktuur. Gemeenskapsonderhoude fabriekkarterings sluit voorvoegsels soos `FC`, `F`, `XA`, `XB`, `QP` en `G8` vir liggings in die Verenigde State in; `RN` vir Mexiko; `CK` vir Cork; `VM` vir ’n Foxconn-ligging in die Tsjeggiese Republiek; `SG` of `E` vir Singapoer; `MB` vir Maleisië; `PT` of `CY` vir Korea; en `EE`, `QT` of `UV` vir Taiwan. Talle voorvoegsels—insluitend `FK`, `F1`, `F2`, `W8`, `DL`, `DM`, `DN`, `YM`, `7J`, `1C`, `4H`, `WQ`, `F7`, `C0`, `C3` en `C7`—is met Chinese fasiliteite verbind; `RM` is met opgeknapte toestelle verbind.<sup>[[3]](#references)</sup>

Die datumkodes vir die vierde karakter strek van `C` (eerste helfte van 2010) tot `Z` (tweede helfte van 2019), waarna die volgorde hergebruik is. Vir die vyfde karakter verteenwoordig syfers `1`–`9` weke 1–9, terwyl letters `C`–`Y`, met uitsluiting van vokale en `S`, weke 10–27 verteenwoordig; tel 26 by wanneer die vierde karakter die tweede helfte van ’n jaar aandui.<sup>[[3]](#references)</sup>

Hierdie karterings is nuttig vir ouer triage, maar is nie gesaghebbende bewys van oorsprong, ouderdom of egtheid nie. Bevestig die resultaat deur Apple se inventarisdata te gebruik.

Vir betroubare identifikasie, haal die reeksnommer van die toestel af en gebruik Apple se dekking- of tegniese-spesifikasie-opsoek eerder as om die model uit karakterposisies te probeer aflei.<sup>[[2]](#references)</sup>

### Haal die reeksnommer af

Die grafiese koppelvlak vertoon dit onder **Apple-kieslys > About This Mac**.<sup>[[2]](#references)</sup> Vanuit ’n shell lees enige van die volgende opdragte die platform se reeksnommer:
```bash
system_profiler SPHardwareDataType | awk -F ': ' '/Serial Number/ {print $2}'
ioreg -rd1 -c IOPlatformExpertDevice | awk -F '"' '/IOPlatformSerialNumber/ {print $4}'
```
Behandel ’n reeksnommer as ’n identifiseerder, nie as ’n authentiseerder nie: bevestig die toestel deur die relevante Apple- of MDM-inventariswerkvloei voordat jy besluite oor inskrywing of eienaarskap neem.

## References

- [1] [MacRumors - Apple begin met die oorgang na gerandomiseerde reeksnommers](https://www.macrumors.com/2021/05/05/purple-iphone-12-randomized-serial-number/)
- [2] [Apple Support - Vind jou Mac-modelnaam en reeksnommer](https://support.apple.com/en-us/102767)
- [3] [Beetstech - Dekodeer die betekenis agter ’n Apple-reeksnommer](https://beetstech.com/blog/decode-meaning-behind-apple-serial-number)
{{#include ../../../banners/hacktricks-training.md}}
