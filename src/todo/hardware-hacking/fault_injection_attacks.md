# Fault Injection-aanvalle

{{#include ../../banners/hacktricks-training.md}}

Fault injection—dikwels **glitching** in hardeware-sekuriteitswerk genoem—versteur ’n toestel doelbewus terwyl dit werk, sodat dit ’n verkeerde berekening uitvoer. ’n Nuttige fault kan ’n instruksie oorslaan, data korrupteer, ’n sekuriteitskontrole omseil, of foutiewe kriptografiese uitvoer lewer waaruit geheime inligting afgelei kan word.<sup>[[1]](#references)</sup>

Algemene tegnieke manipuleer die toevoerspanning of klok, spuit elektromagnetiese interferensie in, of gebruik optiese of laserstimulasie.<sup>[[1]](#references)</sup> Die presisie en indringendheid daarvan verskil, maar suksesvolle toetsing vereis gewoonlik ’n herhaalbare trigger en sistematiese sweeps oor tydsberekening, pulswydte en intensiteit. Begin met ’n stabiele basislyn, teken resets en misvormde uitvoer afsonderlik aan, en verander een parameter op ’n slag.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Nie-indringende trigger-vrye Fault Injection-metode gebaseer op opsetlike elektromagnetiese interferensie](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [ChipWhisperer-dokumentasie - Oorsig en vergelyking van vaslegging-hardeware](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
