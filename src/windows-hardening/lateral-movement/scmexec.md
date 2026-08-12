# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## यह कैसे काम करता है

Service Control Manager Remote Protocol (SCMR), किसी remote computer पर Windows services को configure और control करने के लिए RPC-based protocol है। पर्याप्त permissions होने पर, operator ऐसी service create या reconfigure कर सकता है जिसके binary path में कोई command हो, और फिर उस service को start करके command को remotely execute कर सकता है।<sup>[[1]](#references)</sup>

यदि कोई service account निर्दिष्ट नहीं किया जाता है, तो `CreateService` `LocalSystem` का उपयोग करता है, जिसके पास extensive local privileges होते हैं। यही सफल SCM execution के high impact को समझाता है। यह अपने-आप UAC या Microsoft Defender को disable नहीं करता: caller को अभी भी remote SCM rights की आवश्यकता होती है, और endpoint controls service या payload का inspection या blocking कर सकते हैं।<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

## Tools

**SharpMove**, SCM और कई अन्य Windows mechanisms के माध्यम से authenticated remote execution को support करता है। निम्न example इसके SCM action को select करता है, `WindowsDebug` नाम की service create करता है, और उसे remote host पर पहले से मौजूद payload की ओर point करता है।<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - Service Control Manager Remote Protocol का अवलोकन](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [3] [Microsoft Learn - LocalSystem account](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [4] [Microsoft Learn - `CreateService` function](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)
{{#include ../../banners/hacktricks-training.md}}
