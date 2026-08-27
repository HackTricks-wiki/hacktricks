# macOS PowerShell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `XDG_CONFIG_HOME` 및 PowerShell 프로필

macOS와 Linux에서 PowerShell은 XDG configuration paths를 사용하며 `pwsh`가 시작될 때 user profile scripts를 실행합니다. `XDG_CONFIG_HOME`을 redirect하면 `powershell/profile.ps1` 및 console-host-specific `powershell/Microsoft.PowerShell_profile.ps1`이 포함된 directory가 변경됩니다. 따라서 해당 위치에 있는 controlled file은 `-Command` payload보다 먼저 실행될 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
이는 Windows가 아닌 플랫폼의 PowerShell 6 이상(`pwsh`)에 적용됩니다. Windows PowerShell은 프로필 위치가 다릅니다. `pwsh -NoProfile`은 프로필 로드를 억제합니다. 또한 다른 PowerShell host가 서로 다른 스크립트를 선택할 수 있으므로 `HOME` 및 host별 프로필 이름도 확인하세요.

## References

- [1] [PowerShell 환경 변수 및 XDG 경로](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [PowerShell 프로필](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
{{#include ../../../banners/hacktricks-training.md}}
