{{#include ../banners/hacktricks-training.md}}

एक पिंग प्रतिक्रिया TTL:\
127 = Windows\
254 = Cisco\
बाकी, कुछ लिनक्स

$1$- md5\
$2$या $2a$ - Blowfish\
$5$- sha256\
$6$- sha512

यदि आप नहीं जानते कि किसी सेवा के पीछे क्या है, तो HTTP GET अनुरोध करने का प्रयास करें।

**UDP स्कैन**\
nc -nv -u -z -w 1 \<IP> 160-16

एक खाली UDP पैकेट एक विशिष्ट पोर्ट पर भेजा जाता है। यदि UDP पोर्ट खुला है, तो लक्ष्य मशीन से कोई उत्तर नहीं भेजा जाता है। यदि UDP पोर्ट बंद है, तो लक्ष्य मशीन से एक ICMP पोर्ट अप्राप्य पैकेट वापस भेजा जाना चाहिए।\
UDP पोर्ट स्कैनिंग अक्सर अविश्वसनीय होती है, क्योंकि फ़ायरवॉल और राउटर ICMP\
पैकेट्स को गिरा सकते हैं। इससे आपके स्कैन में झूठे सकारात्मक परिणाम हो सकते हैं, और आप नियमित रूप से देखेंगे\
UDP पोर्ट स्कैनिंग में सभी UDP पोर्ट्स को स्कैन की गई मशीन पर खुला दिखा रहा है।\
o अधिकांश पोर्ट स्कैनर सभी उपलब्ध पोर्ट्स को स्कैन नहीं करते हैं, और आमतौर पर एक पूर्व निर्धारित सूची होती है\
“दिलचस्प पोर्ट्स” की जो स्कैन की जाती है।

# CTF - Tricks

**Windows** में फ़ाइलों की खोज के लिए **Winzip** का उपयोग करें।\
**वैकल्पिक डेटा स्ट्रीम**: _dir /r | find ":$DATA"_
```
binwalk --dd=".*" <file> #Extract everything
binwalk -M -e -d=10000 suspicious.pdf #Extract, look inside extracted files and continue extracing (depth of 10000)
```
## Crypto

**featherduster**\

**Basae64**(6—>8) —> 0...9, a...z, A…Z,+,/\
**Base32**(5 —>8) —> A…Z, 2…7\
**Base85** (Ascii85, 7—>8) —> 0...9, a...z, A...Z, ., -, :, +, =, ^, !, /, \*, ?, &, <, >, (, ), \[, ], {, }, @, %, $, #\
**Uuencode** --> "_begin \<mode> \<filename>_" से शुरू करें और अजीब अक्षर\
**Xxencoding** --> "_begin \<mode> \<filename>_" से शुरू करें और B64\
\
**Vigenere** (आवृत्ति विश्लेषण) —> [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)\
**Scytale** (अक्षरों का ऑफसेट) —> [https://www.dcode.fr/scytale-cipher](https://www.dcode.fr/scytale-cipher)

**25x25 = QR**

factordb.com\
rsatool

Snow --> संदेशों को स्थान और टैब का उपयोग करके छिपाएं

# Characters

%E2%80%AE => RTL Character (पेलोड को उल्टा लिखता है)

{{#include ../banners/hacktricks-training.md}}
