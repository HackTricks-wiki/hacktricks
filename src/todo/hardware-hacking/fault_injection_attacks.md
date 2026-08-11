# Fault Injection Attacks

{{#include ../../banners/hacktricks-training.md}}

Fault injection huvuruga kifaa kwa makusudi kinapofanya kazi ili kifanye computation isiyo sahihi. Fault inayofaa inaweza kuruka instruction, kuharibu data, kupita security check, au kutoa cryptographic output yenye hitilafu ambayo secret information inaweza kutolewa kwayo.<sup>[[1]](#references)</sup>

Mbinu za kawaida hudhibiti supply voltage au clock, huingiza electromagnetic interference, au hutumia optical au laser stimulation.<sup>[[1]](#references)</sup> Usahihi na kiwango cha uvamizi hutofautiana, lakini testing yenye mafanikio kwa kawaida huhitaji trigger inayoweza kurudiwa na systematic sweeps za timing, pulse width, na intensity. Anza na baseline thabiti, rekodi resets na malformed outputs kando, na badilisha parameter moja kwa wakati mmoja.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Mbinu ya Fault Injection Isiyovamia Kulingana na Intentional Electromagnetic Interference](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [ChipWhisperer Documentation - Muhtasari na Ulinganisho wa Capture Hardware](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
