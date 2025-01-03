{{#include ../../banners/hacktricks-training.md}}

# Baseline

एक बेसलाइन में सिस्टम के कुछ हिस्सों का स्नैपशॉट लेना शामिल होता है ताकि **भविष्य की स्थिति के साथ इसकी तुलना की जा सके और परिवर्तनों को उजागर किया जा सके**।

उदाहरण के लिए, आप फ़ाइल सिस्टम के प्रत्येक फ़ाइल का हैश निकाल सकते हैं और उसे स्टोर कर सकते हैं ताकि यह पता चल सके कि कौन सी फ़ाइलें संशोधित की गई हैं।\
यह उपयोगकर्ता खातों, चल रहे प्रक्रियाओं, चल रही सेवाओं और किसी भी अन्य चीज़ के साथ भी किया जा सकता है जो ज्यादा नहीं बदलनी चाहिए, या बिल्कुल नहीं।

## File Integrity Monitoring

File Integrity Monitoring (FIM) एक महत्वपूर्ण सुरक्षा तकनीक है जो IT वातावरण और डेटा की सुरक्षा करती है द्वारा फ़ाइलों में परिवर्तनों को ट्रैक करके। इसमें दो प्रमुख चरण शामिल हैं:

1. **Baseline Comparison:** फ़ाइल विशेषताओं या क्रिप्टोग्राफिक चेकसम (जैसे MD5 या SHA-2) का उपयोग करके एक बेसलाइन स्थापित करें ताकि संशोधनों का पता लगाने के लिए भविष्य की तुलना की जा सके।
2. **Real-Time Change Notification:** जब फ़ाइलों को एक्सेस या संशोधित किया जाता है, तो तुरंत अलर्ट प्राप्त करें, आमतौर पर OS कर्नेल एक्सटेंशन के माध्यम से।

## Tools

- [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
- [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

## References

- [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)

{{#include ../../banners/hacktricks-training.md}}
