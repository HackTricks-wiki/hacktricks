# AD DNS Records

{{#include ../../banners/hacktricks-training.md}}

डिफ़ॉल्ट रूप से **कोई भी उपयोगकर्ता** Active Directory में **डोमेन या फॉरेस्ट DNS क्षेत्रों** में **सभी DNS रिकॉर्ड** की **सूची बना सकता है**, जो एक ज़ोन ट्रांसफर के समान है (उपयोगकर्ता AD वातावरण में DNS क्षेत्र के बाल वस्तुओं की सूची बना सकते हैं)।

उपकरण [**adidnsdump**](https://github.com/dirkjanm/adidnsdump) **सूची बनाने** और **आंतरिक नेटवर्क के पुनः प्राप्ति उद्देश्यों** के लिए क्षेत्र में **सभी DNS रिकॉर्ड** का **निर्यात** करने की अनुमति देता है।
```bash
git clone https://github.com/dirkjanm/adidnsdump
cd adidnsdump
pip install .

adidnsdump -u domain_name\\username ldap://10.10.10.10 -r
cat records.csv
```
अधिक जानकारी के लिए पढ़ें [https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/)

{{#include ../../banners/hacktricks-training.md}}
