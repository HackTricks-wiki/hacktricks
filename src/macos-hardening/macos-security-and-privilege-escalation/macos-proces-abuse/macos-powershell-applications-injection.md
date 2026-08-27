# macOS PowerShell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `XDG_CONFIG_HOME` और PowerShell प्रोफाइल

macOS और Linux पर, PowerShell XDG configuration paths का उपयोग करता है और `pwsh` शुरू होने पर user profile scripts को execute करता है। `XDG_CONFIG_HOME` को redirect करने से `powershell/profile.ps1` और console-host-specific `powershell/Microsoft.PowerShell_profile.ps1` वाली directory बदल जाती है; इसलिए वहां मौजूद एक controlled file `-Command` payload से पहले execute हो सकती है।<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
यह PowerShell 6+ (`pwsh`) पर non-Windows platforms के लिए लागू होता है; Windows PowerShell अलग-अलग profile locations का उपयोग करता है। `pwsh -NoProfile` profile loading को रोकता है। `HOME` और host-specific profile names की भी जांच करें, क्योंकि अन्य PowerShell hosts अलग scripts चुन सकते हैं।

## References

- [1] [PowerShell environment variables और XDG paths](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [PowerShell profiles](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
{{#include ../../../banners/hacktricks-training.md}}
