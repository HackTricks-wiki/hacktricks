# Fault Injection Attacks

{{#include ../../banners/hacktricks-training.md}}

Fault injection namerno ometa uređaj dok radi, tako da izvrši pogrešan proračun. Korisna greška može preskočiti instrukciju, oštetiti podatke, zaobići bezbednosnu proveru ili proizvesti neispravan kriptografski izlaz iz kojeg se mogu izvesti tajne informacije.<sup>[[1]](#references)</sup>

Uobičajene tehnike manipulišu naponom napajanja ili taktom, ubacuju elektromagnetne smetnje ili koriste optičku odnosno lasersku stimulaciju.<sup>[[1]](#references)</sup> Njihova preciznost i invazivnost se razlikuju, ali uspešno testiranje uglavnom zahteva ponovljiv okidač i sistematsko skeniranje vremena, širine impulsa i intenziteta. Počnite sa stabilnom osnovnom konfiguracijom, zasebno beležite resetovanja i neispravne izlaze, a zatim menjajte jedan parametar po jedan.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Neinvazivni metod Fault Injection bez okidača zasnovan na namernim elektromagnetnim smetnjama](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [ChipWhisperer Documentation - Pregled i poređenje hardvera za snimanje](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
