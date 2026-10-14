# Fault Injection Attacks

{{#include ../../banners/hacktricks-training.md}}

Fault injection—wat in hardeware-sekuriteitswerk dikwels **glitching** genoem word—ontwrig ’n toestel doelbewus terwyl dit werk, sodat dit ’n verkeerde berekening uitvoer. ’n Nuttige fout kan ’n instruksie oorslaan, data beskadig, ’n sekuriteitskontrole omseil of foutiewe kriptografiese uitvoer lewer waaruit geheime inligting afgelei kan word.<sup>[[1]](#references)</sup>

Algemene tegnieke manipuleer die toevoerspanning of clock, spuit elektromagnetiese steuring in of gebruik optiese of laserstimulasie.<sup>[[1]](#references)</sup> Die tegnieke verskil in presisie en indringendheid, maar suksesvolle toetsing vereis oor die algemeen ’n herhaalbare sneller en sistematiese verkenning van tydsberekening, pulswydte en intensiteit. Begin met ’n stabiele basislyn, teken herbeginsels en misvormde uitvoer afsonderlik aan en verander een parameter op ’n slag.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Nie-indringende foutinspuitingsmetode sonder sneller, gebaseer op doelbewuste elektromagnetiese steuring](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [ChipWhisperer Documentation - Oorsig en vergelyking van vaslegginghardeware](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
