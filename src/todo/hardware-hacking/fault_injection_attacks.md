# Napadi ubacivanjem greške

{{#include ../../banners/hacktricks-training.md}}

Ubacivanje greške — koje se u radu sa hardverskom bezbednošću često naziva **glitching** — namerno ometa uređaj dok radi, kako bi izvršio neispravan proračun. Korisna greška može preskočiti instrukciju, oštetiti podatke, zaobići bezbednosnu proveru ili proizvesti neispravan kriptografski izlaz iz kog se mogu izvesti tajne informacije.<sup>[[1]](#references)</sup>

Uobičajene tehnike menjaju napon napajanja ili takt, ubacuju elektromagnetne smetnje ili koriste optičku odnosno lasersku stimulaciju.<sup>[[1]](#references)</sup> Njihova preciznost i invazivnost se razlikuju, ali uspešno testiranje uglavnom zahteva ponovljiv okidač i sistematsko pretraživanje vremena, širine impulsa i intenziteta. Započnite sa stabilnom osnovnom konfiguracijom, zasebno beležite resetovanja i neispravne izlaze i menjajte jedan parametar u datom trenutku.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Metod ubacivanja greške bez fizičkog kontakta zasnovan na namernim elektromagnetnim smetnjama](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [ChipWhisperer Documentation - Pregled i poređenje hardvera za hvatanje](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
