# Fault Injection Attacks

{{#include ../../banners/hacktricks-training.md}}

Fault injection—जिसे hardware-security कार्य में अक्सर **glitching** कहा जाता है—जानबूझकर किसी डिवाइस के संचालन के दौरान उसमें व्यवधान डालता है, ताकि वह गलत computation करे। उपयोगी fault किसी instruction को skip कर सकता है, data को corrupt कर सकता है, security check को bypass कर सकता है, या ऐसा faulty cryptographic output उत्पन्न कर सकता है जिससे secret information प्राप्त की जा सके।<sup>[[1]](#references)</sup>

सामान्य techniques supply voltage या clock में बदलाव करती हैं, electromagnetic interference inject करती हैं, या optical अथवा laser stimulation का उपयोग करती हैं।<sup>[[1]](#references)</sup> उनकी precision और invasiveness अलग-अलग होती हैं, लेकिन सफल testing के लिए आमतौर पर repeatable trigger और timing, pulse width तथा intensity पर systematic sweeps आवश्यक होते हैं। एक stable baseline से शुरू करें, resets और malformed outputs को अलग-अलग record करें, और एक समय में केवल एक parameter बदलें।<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Intentional Electromagnetic Interference पर आधारित Non-invasive Trigger-free Fault Injection Method](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [ChipWhisperer Documentation - Capture Hardware का Overview और Comparison](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
