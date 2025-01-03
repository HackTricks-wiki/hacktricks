# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**एक सुनहरे टिकट की तरह**, एक डायमंड टिकट एक TGT है जिसे **किसी भी सेवा तक किसी भी उपयोगकर्ता के रूप में पहुँचने के लिए** उपयोग किया जा सकता है। एक सुनहरा टिकट पूरी तरह से ऑफ़लाइन बनाया जाता है, उस डोमेन के krbtgt हैश के साथ एन्क्रिप्ट किया जाता है, और फिर उपयोग के लिए एक लॉगिन सत्र में पास किया जाता है। चूंकि डोमेन नियंत्रक TGTs को ट्रैक नहीं करते हैं जो उन्होंने वैध रूप से जारी किए हैं, वे खुशी-खुशी उन TGTs को स्वीकार करेंगे जो इसके अपने krbtgt हैश के साथ एन्क्रिप्टेड हैं।

सुनहरे टिकटों के उपयोग का पता लगाने के लिए दो सामान्य तकनीकें हैं:

- उन TGS-REQs की तलाश करें जिनका कोई संबंधित AS-REQ नहीं है।
- उन TGTs की तलाश करें जिनमें बेवकूफी के मान हैं, जैसे Mimikatz का डिफ़ॉल्ट 10-वर्षीय जीवनकाल।

एक **डायमंड टिकट** **एक वैध TGT के फ़ील्ड को संशोधित करके बनाया जाता है जो एक DC द्वारा जारी किया गया था**। यह **एक TGT का अनुरोध करके**, इसे डोमेन के krbtgt हैश के साथ **डीक्रिप्ट करके**, टिकट के इच्छित फ़ील्ड को **संशोधित करके**, फिर **इसे फिर से एन्क्रिप्ट करके** प्राप्त किया जाता है। यह **सुनहरे टिकट के दो उपरोक्त कमियों को पार करता है** क्योंकि:

- TGS-REQs के पास एक पूर्ववर्ती AS-REQ होगा।
- TGT एक DC द्वारा जारी किया गया था जिसका अर्थ है कि इसमें डोमेन की Kerberos नीति से सभी सही विवरण होंगे। हालांकि इन्हें सुनहरे टिकट में सटीक रूप से बनाया जा सकता है, यह अधिक जटिल है और गलतियों के लिए खुला है।
```bash
# Get user RID
powershell Get-DomainUser -Identity <username> -Properties objectsid

.\Rubeus.exe diamond /tgtdeleg /ticketuser:<username> /ticketuserid:<RID of username> /groups:512

# /tgtdeleg uses the Kerberos GSS-API to obtain a useable TGT for the user without needing to know their password, NTLM/AES hash, or elevation on the host.
# /ticketuser is the username of the principal to impersonate.
# /ticketuserid is the domain RID of that principal.
# /groups are the desired group RIDs (512 being Domain Admins).
# /krbkey is the krbtgt AES256 hash.
```
{{#include ../../banners/hacktricks-training.md}}
