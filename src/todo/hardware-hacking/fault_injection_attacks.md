# Mashambulizi ya Fault Injection

{{#include ../../banners/hacktricks-training.md}}

Fault injection—ambayo mara nyingi huitwa **glitching** katika kazi za usalama wa hardware—huvuruga kifaa kwa makusudi kinapofanya kazi ili kifanye hesabu isiyo sahihi. Fault inayofaa inaweza kuruka instruction, kuharibu data, kupita ukaguzi wa usalama, au kutoa matokeo yenye hitilafu ya cryptographic ambayo taarifa za siri zinaweza kutolewa.<sup>[[1]](#references)</sup>

Mbinu za kawaida hudhibiti voltage ya supply au clock, huingiza electromagnetic interference, au hutumia optical au laser stimulation.<sup>[[1]](#references)</sup> Usahihi na kiwango cha uvamizi hutofautiana, lakini testing yenye mafanikio kwa kawaida huhitaji trigger inayoweza kurudiwa na sweeps za kimfumo za timing, pulse width, na intensity. Anza na baseline thabiti, rekodi resets na outputs zisizo sahihi kando, na badilisha parameter moja kwa wakati mmoja.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Mbinu ya Non-invasive Trigger-free Fault Injection inayotegemea Intentional Electromagnetic Interference](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [Nyaraka za ChipWhisperer - Muhtasari na Ulinganisho wa Capture Hardware](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
