# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## यह कैसे काम करता है

Service Control Manager Remote Protocol (SCMR), किसी remote computer पर Windows services को configure और control करने के लिए RPC-based protocol है। पर्याप्त permissions के साथ, operator ऐसी service create या reconfigure कर सकता है जिसके binary path में कोई command शामिल हो, और फिर उस service को start करके command को remotely execute कर सकता है।<sup>[[1]](#references)</sup>

## Tools

**SharpMove**, SCM और कई अन्य Windows mechanisms के माध्यम से authenticated remote execution को support करता है। निम्नलिखित example इसका SCM action select करता है, `WindowsDebug` नाम की service create करता है, और उसे remote host पर पहले से मौजूद payload की ओर point करता है।<sup>[[2]](#references)</sup>
```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```
## References

- [1] [Microsoft Open Specifications - Service Control Manager Remote Protocol का अवलोकन](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
{{#include ../../banners/hacktricks-training.md}}
