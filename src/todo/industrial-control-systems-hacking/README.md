# Industrial Control Systems Hacking

{{#include ../../banners/hacktricks-training.md}}

## इस अनुभाग के बारे में

यह अनुभाग industrial control system (ICS) components, architectures, protocols और security-assessment methods का परिचय देता है। ICS व्यापक operational technology (OT) domain का हिस्सा है: ऐसे programmable systems और devices जो physical processes की निगरानी करते हैं या उनमें परिवर्तन करते हैं। सामान्य उदाहरणों में supervisory control and data acquisition (SCADA) systems, distributed control systems (DCSs) और programmable logic controllers (PLCs) शामिल हैं।<sup>[[1]](#references)</sup>

इन environments में security work करते समय conventional IT से अलग requirements को ध्यान में रखना आवश्यक है, जिनमें process safety, reliability, availability, deterministic operation और equipment lifecycles शामिल हैं। कोई technically valid security control तब भी अनुपयुक्त हो सकता है यदि वह physical process में बाधा डालता है, इसलिए testing और remediation को system owner और operations personnel के साथ coordinate किया जाना चाहिए।<sup>[[1]](#references)</sup>

## Assessment Priorities

controlled process, system boundaries, network topology, assets, data flows, trust relationships और external connections को समझकर शुरुआत करें। समान device types अलग-अलग sites पर अलग functions कर सकते हैं, इसलिए यह मानने से बचें कि एक deployment की architecture या impact model दूसरे पर भी लागू होती है।<sup>[[1]](#references)</sup>

जहां संभव हो, passive discovery और existing engineering documentation को प्राथमिकता दें। कोई भी active scanning या exploitation ऐसे approved test plan का पालन करना चाहिए जिसमें safety constraints, maintenance windows, recovery procedures और stop conditions परिभाषित हों। Findings का मूल्यांकन cybersecurity impact और physical process पर संभावित effects, दोनों के लिए किया जाना चाहिए।<sup>[[1]](#references)</sup>

यही architectural knowledge asset inventory, network segmentation, monitoring, incident response और risk-based vulnerability management जैसी defensive activities को भी support करता है।<sup>[[1]](#references)</sup>

## References

- [1] [NIST SP 800-82 Rev. 3 - Operational Technology (OT) Security के लिए Guide](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../../banners/hacktricks-training.md}}
