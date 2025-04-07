# Linux Active Directory

{{#include ../../banners/hacktricks-training.md}}

एक लिनक्स मशीन भी एक Active Directory वातावरण के अंदर मौजूद हो सकती है।

एक AD में लिनक्स मशीन **फाइलों के अंदर विभिन्न CCACHE टिकटों को स्टोर कर सकती है। ये टिकट किसी अन्य kerberos टिकट की तरह उपयोग और दुरुपयोग किए जा सकते हैं**। इन टिकटों को पढ़ने के लिए, आपको टिकट के उपयोगकर्ता मालिक या मशीन के अंदर **root** होना आवश्यक है।

## Enumeration

### AD enumeration from linux

यदि आपके पास लिनक्स (या Windows में bash) में AD पर पहुंच है, तो आप AD को सूचीबद्ध करने के लिए [https://github.com/lefayjey/linWinPwn](https://github.com/lefayjey/linWinPwn) का प्रयास कर सकते हैं।

आप लिनक्स से AD को सूचीबद्ध करने के **अन्य तरीकों** के बारे में जानने के लिए निम्नलिखित पृष्ठ की भी जांच कर सकते हैं:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

### FreeIPA

FreeIPA एक ओपन-सोर्स **वैकल्पिक** है Microsoft Windows **Active Directory** के लिए, मुख्य रूप से **Unix** वातावरण के लिए। यह Active Directory के समान प्रबंधन के लिए एक पूर्ण **LDAP directory** को MIT **Kerberos** Key Distribution Center के साथ जोड़ता है। CA और RA प्रमाणपत्र प्रबंधन के लिए Dogtag **Certificate System** का उपयोग करते हुए, यह स्मार्टकार्ड सहित **multi-factor** प्रमाणीकरण का समर्थन करता है। Unix प्रमाणीकरण प्रक्रियाओं के लिए SSSD एकीकृत है। इसके बारे में अधिक जानें:

{{#ref}}
../freeipa-pentesting.md
{{#endref}}

## Playing with tickets

### Pass The Ticket

इस पृष्ठ पर आप विभिन्न स्थान पाएंगे जहाँ आप **एक लिनक्स होस्ट के अंदर kerberos टिकट पा सकते हैं**, अगले पृष्ठ पर आप जान सकते हैं कि इन CCache टिकटों के प्रारूपों को Kirbi (विंडोज़ में उपयोग करने के लिए आवश्यक प्रारूप) में कैसे परिवर्तित किया जाए और PTT हमले को कैसे किया जाए:

{{#ref}}
../../windows-hardening/active-directory-methodology/pass-the-ticket.md
{{#endref}}

### CCACHE ticket reuse from /tmp

CCACHE फ़ाइलें **Kerberos क्रेडेंशियल्स** को स्टोर करने के लिए बाइनरी प्रारूप हैं जो आमतौर पर `/tmp` में 600 अनुमतियों के साथ स्टोर की जाती हैं। इन फ़ाइलों की पहचान उनके **नाम प्रारूप, `krb5cc_%{uid}`,** द्वारा की जा सकती है, जो उपयोगकर्ता के UID से संबंधित है। प्रमाणीकरण टिकट सत्यापन के लिए, **पर्यावरण चर `KRB5CCNAME`** को इच्छित टिकट फ़ाइल के पथ पर सेट किया जाना चाहिए, जिससे इसका पुन: उपयोग सक्षम हो सके।

प्रमाणीकरण के लिए उपयोग किए जा रहे वर्तमान टिकट को `env | grep KRB5CCNAME` के साथ सूचीबद्ध करें। प्रारूप पोर्टेबल है और टिकट को **पर्यावरण चर सेट करके पुन: उपयोग किया जा सकता है** `export KRB5CCNAME=/tmp/ticket.ccache` के साथ। Kerberos टिकट नाम प्रारूप `krb5cc_%{uid}` है जहाँ uid उपयोगकर्ता UID है।
```bash
# Find tickets
ls /tmp/ | grep krb5cc
krb5cc_1000

# Prepare to use it
export KRB5CCNAME=/tmp/krb5cc_1000
```
### CCACHE टिकट पुन: उपयोग कीजिए की रिंग से

**किसी प्रक्रिया की मेमोरी में संग्रहीत Kerberos टिकटों को निकाला जा सकता है**, विशेष रूप से जब मशीन की ptrace सुरक्षा अक्षम होती है (`/proc/sys/kernel/yama/ptrace_scope`)। इस उद्देश्य के लिए एक उपयोगी उपकरण [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey) पर पाया जा सकता है, जो सत्रों में इंजेक्ट करके और टिकटों को `/tmp` में डंप करके निकासी की सुविधा प्रदान करता है।

इस उपकरण को कॉन्फ़िगर और उपयोग करने के लिए, नीचे दिए गए चरणों का पालन किया जाता है:
```bash
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release
/tmp/tickey -i
```
यह प्रक्रिया विभिन्न सत्रों में इंजेक्ट करने का प्रयास करेगी, सफलता को `/tmp` में `__krb_UID.ccache` नामकरण सम्मेलन के साथ निकाले गए टिकटों को संग्रहीत करके इंगित करेगी।

### CCACHE टिकट पुन: उपयोग SSSD KCM से

SSSD `/var/lib/sss/secrets/secrets.ldb` पथ पर डेटाबेस की एक प्रति बनाए रखता है। संबंधित कुंजी `/var/lib/sss/secrets/.secrets.mkey` पथ पर एक छिपी हुई फ़ाइल के रूप में संग्रहीत होती है। डिफ़ॉल्ट रूप से, कुंजी केवल तब पढ़ी जा सकती है जब आपके पास **root** अनुमतियाँ हों।

**`SSSDKCMExtractor`** को --database और --key पैरामीटर के साथ बुलाने से डेटाबेस को पार्स किया जाएगा और **गुप्त को डिक्रिप्ट** किया जाएगा।
```bash
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```
**क्रेडेंशियल कैश कर्बेरोस ब्लॉब को एक उपयोगी कर्बेरोस CCache** फ़ाइल में परिवर्तित किया जा सकता है जिसे Mimikatz/Rubeus को पास किया जा सकता है।

### CCACHE टिकट पुन: उपयोग कीजटैब से
```bash
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```
### Extract accounts from /etc/krb5.keytab

Service account keys, essential for services operating with root privileges, are securely stored in **`/etc/krb5.keytab`** files. These keys, akin to passwords for services, demand strict confidentiality.

To inspect the keytab file's contents, **`klist`** can be employed. The tool is designed to display key details, including the **NT Hash** for user authentication, particularly when the key type is identified as 23.
```bash
klist.exe -t -K -e -k FILE:C:/Path/to/your/krb5.keytab
# Output includes service principal details and the NT Hash
```
Linux उपयोगकर्ताओं के लिए, **`KeyTabExtract`** RC4 HMAC हैश निकालने की कार्यक्षमता प्रदान करता है, जिसे NTLM हैश पुन: उपयोग के लिए उपयोग किया जा सकता है।
```bash
python3 keytabextract.py krb5.keytab
# Expected output varies based on hash availability
```
macOS पर, **`bifrost`** कुंजीपट फ़ाइल विश्लेषण के लिए एक उपकरण के रूप में कार्य करता है।
```bash
./bifrost -action dump -source keytab -path /path/to/your/file
```
निकाली गई खाता और हैश जानकारी का उपयोग करते हुए, **`crackmapexec`** जैसे उपकरणों का उपयोग करके सर्वरों से कनेक्शन स्थापित किए जा सकते हैं।
```bash
crackmapexec 10.XXX.XXX.XXX -u 'ServiceAccount$' -H "HashPlaceholder" -d "YourDOMAIN"
```
## संदर्भ

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://github.com/TarlogicSecurity/tickey](https://github.com/TarlogicSecurity/tickey)
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#linux-active-directory)

{{#include ../../banners/hacktricks-training.md}}
