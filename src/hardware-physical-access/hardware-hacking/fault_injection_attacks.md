# Fault Injection Attacks

{{#include ../../banners/hacktricks-training.md}}

Ubrizgavanje grešaka — koje se u oblasti hardverske bezbednosti često naziva **glitching** — namerno ometa uređaj dok radi, kako bi izvršio neispravno izračunavanje. Korisna greška može da preskoči instrukciju, ošteti podatke, zaobiđe bezbednosnu proveru ili proizvede neispravan kriptografski izlaz iz kog se mogu izvesti tajne informacije.<sup>[[1]](#references)</sup>

Uobičajene tehnike menjaju napon napajanja ili takt, ubacuju elektromagnetne smetnje ili koriste optičku ili lasersku stimulaciju.<sup>[[1]](#references)</sup> Razlikuju se po preciznosti i invazivnosti, ali uspešno testiranje uglavnom zahteva ponovljiv okidač i sistematsko ispitivanje različitih vremenskih parametara, širine impulsa i intenziteta. Počnite od stabilnog osnovnog stanja, zasebno beležite resetovanja i neispravne izlaze i menjajte po jedan parametar.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Neinvazivna metoda ubrizgavanja grešaka bez okidača zasnovana na namernim elektromagnetnim smetnjama](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [ChipWhisperer dokumentacija - Pregled i poređenje hardvera za hvatanje signala](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
