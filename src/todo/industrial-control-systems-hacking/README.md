# Industrial Control Systems Hacking

{{#include ../../banners/hacktricks-training.md}}

## इस अनुभाग के बारे में

यह अनुभाग industrial control system (ICS) के components, architectures, protocols और security-assessment methods का परिचय देता है। ICS व्यापक operational technology (OT) domain का हिस्सा है: ऐसे programmable systems और devices जो physical processes की निगरानी करते हैं या उनमें परिवर्तन करते हैं। सामान्य उदाहरणों में supervisory control and data acquisition (SCADA) systems, distributed control systems (DCSs) और programmable logic controllers (PLCs) शामिल हैं।<sup>[[1]](#references)</sup>

इन environments में security work को conventional IT से अलग requirements को ध्यान में रखना चाहिए, जिनमें process safety, reliability, availability, deterministic operation और equipment lifecycles शामिल हैं। कोई technically valid security control फिर भी अनुपयुक्त हो सकता है यदि वह physical process में बाधा डालता है, इसलिए testing और remediation को system owner तथा operations personnel के साथ coordinate किया जाना चाहिए।<sup>[[1]](#references)</sup>

Compromise या accidental disruption production रोक सकता है, equipment को नुकसान पहुँचा सकता है, hazardous material release कर सकता है, environment को नुकसान पहुँचा सकता है या injury तथा loss of life का कारण बन सकता है। यह संभावित physical impact बताता है कि active testing से पहले controlled process और उसकी safe operating limits को समझना आवश्यक है।<sup>[[1]](#references)</sup>

कई OT deployments में legacy operating systems, applications और protocols अभी भी उपयोग किए जाते हैं, क्योंकि equipment की service life लंबी होती है और changes के लिए operational तथा safety testing आवश्यक होती है। कुछ protocols modern authentication या encryption के बिना design किए गए थे, और vendor support या maintenance windows के कारण patching सीमित हो सकती है; जहाँ direct upgrades feasible न हों, वहाँ segmentation, access control और monitoring का उपयोग करें।<sup>[[1]](#references)</sup>

## Assessment Priorities

सबसे पहले controlled process, system boundaries, network topology, assets, data flows, trust relationships और external connections को समझें। समान device types अलग-अलग sites पर अलग functions के लिए उपयोग किए जा सकते हैं, इसलिए यह मानने से बचें कि किसी एक deployment का architecture या impact model दूसरे deployment पर भी लागू होता है।<sup>[[1]](#references)</sup>

जहाँ संभव हो, passive discovery और मौजूदा engineering documentation को प्राथमिकता दें। किसी भी active scanning या exploitation को approved test plan का पालन करना चाहिए, जिसमें safety constraints, maintenance windows, recovery procedures और stop conditions परिभाषित हों। Findings का मूल्यांकन cybersecurity impact और physical process पर संभावित effects, दोनों के लिए किया जाना चाहिए।<sup>[[1]](#references)</sup>

यही architectural knowledge asset inventory, network segmentation, monitoring, incident response और risk-based vulnerability management जैसी defensive activities का भी समर्थन करता है।<sup>[[1]](#references)</sup>

## References

- [1] [NIST SP 800-82 Rev. 3 - Operational Technology (OT) Security के लिए मार्गदर्शिका](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
{{#include ../../banners/hacktricks-training.md}}
