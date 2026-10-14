# Fault Injection Attacks

{{#include ../../banners/hacktricks-training.md}}

Fault injection—जिसे hardware-security कार्य में अक्सर **glitching** कहा जाता है—में डिवाइस के काम करते समय जानबूझकर उसमें गड़बड़ी पैदा की जाती है, ताकि वह गलत गणना करे। उपयोगी fault किसी instruction को छोड़ सकता है, data को corrupt कर सकता है, security check को bypass कर सकता है, या ऐसा faulty cryptographic output दे सकता है जिससे secret information निकाली जा सके।<sup>[[1]](#references)</sup>

आम techniques में supply voltage या clock के साथ छेड़छाड़ करना, electromagnetic interference inject करना, या optical अथवा laser stimulation का उपयोग करना शामिल है।<sup>[[1]](#references)</sup> इनकी precision और invasiveness अलग-अलग होती है, लेकिन सफल testing के लिए आम तौर पर repeatable trigger और timing, pulse width तथा intensity की व्यवस्थित जाँच की आवश्यकता होती है। एक स्थिर baseline से शुरू करें, resets और malformed outputs को अलग-अलग दर्ज करें, और एक समय में केवल एक parameter बदलें।<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - जानबूझकर किए गए Electromagnetic Interference पर आधारित Non-invasive Trigger-free Fault Injection Method](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [ChipWhisperer Documentation - Capture Hardware का अवलोकन और तुलना](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}
