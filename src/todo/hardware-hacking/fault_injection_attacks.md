# Fault Injection Attacks

{{#include ../../banners/hacktricks-training.md}}

Fault injection versteur ’n toestel doelbewus terwyl dit in werking is, sodat dit ’n verkeerde berekening uitvoer. ’n Nuttige fout kan ’n instruksie oorslaan, data korrupteer, ’n sekuriteitskontrole omseil, of foutiewe kriptografiese uitvoer lewer waaruit geheime inligting afgelei kan word.<sup>[[1]](#references)</sup>

Algemene tegnieke manipuleer die toevoerspanning of klok, spuit elektromagnetiese steuring in, of gebruik optiese of laserstimulasie.<sup>[[1]](#references)</sup> Die presisie en indringendheid daarvan verskil, maar suksesvolle toetsing vereis oor die algemeen ’n herhaalbare trigger en sistematiese sweeps oor tydsberekening, pulsbreedte en intensiteit. Begin met ’n stabiele basislyn, teken resets en misvormde uitvoer afsonderlik aan, en verander een parameter op ’n slag.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Nie-indringende trigger-vrye foutinspuitingsmetode gebaseer op opsetlike elektromagnetiese steuring](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [ChipWhisperer-dokumentasie - Oorsig en vergelyking van vaslegginghardeware](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
