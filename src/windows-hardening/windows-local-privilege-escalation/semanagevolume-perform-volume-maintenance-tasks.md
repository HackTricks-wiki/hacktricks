# SeManageVolumePrivilege: Volume-maintenance abuse and raw-access validation

{{#include ../../banners/hacktricks-training.md}}

## 概要

Windows のユーザー権利: ボリュームの保守タスクを実行する（定数: SeManageVolumePrivilege）。

この権利により、デフラグやボリュームの作成・削除などのボリューム保守操作が許可されます。Microsoft は、この権利の保持者が、他のデータを含むストレージへファイルを拡張し、取得したバイトを読み取ったり変更したりできる可能性があると警告しています。<sup>[[1]](#references)</sup>

`SeManageVolumePrivilege` の保有を、raw-disk access が保証されていることと同一視してはいけません。Microsoft のドキュメントによると、直接アクセスのために `CreateFile` を介して物理ディスクまたはボリュームを開くには管理者権限が必要であり、通常のオブジェクトおよびデバイスのアクセスチェックも引き続き適用されます。特定のビルドまたは製品では、任意のファイル読み取りを主張する前に、token、device ACL、requested access、share flags、volume state によって raw handle の取得が許可されるかをテストしてください。<sup>[[3]](#references)</sup>

デフォルト: サーバーおよびドメインコントローラーの Administrators。<sup>[[1]](#references)</sup>

## Abuse scenarios

- アカウントが実際に読み取り可能な raw-volume handle を取得できる場合、NTFS-aware parser によって per-file ACL をバイパスし、allocated clusters から保護されたファイルやロックされたファイルを復元できます。
- 標的になり得るものには、`C:\Windows\System32` 配下のロックされたコンテンツや ACL で保護されたコンテンツ、registry hives、DPAPI master keys、SAM、さらに snapshot または offline volume を介して別途アクセスできる場合の `ntds.dit` が含まれます。
- certificate services hosts では、ソフトウェアキーの有用な場所として `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` と `%ProgramData%\Microsoft\Crypto\Keys` があります。ファイルを復元できても、その key material が exportable であり、かつ復号も可能な場合にのみ有用です。<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- AD CS host では、正常に復元された **exportable/software-backed** CA private key により、Golden Certificate abuse が可能になります。Hardware-backed または non-exportable の key designs では、この経路が変わります。<sup>[[2]](#references)</sup>

注: helper tools に依存しない限り、NTFS structures 用の parser が必要です。多くの市販ツールは raw access を抽象化します。

## Practical techniques

- raw volume handle を開いて clusters を読み取る:

<details>
<summary>クリックして展開</summary>
```powershell
# Validation attempt: current Windows versions normally require an administrative token
$fs = [System.IO.File]::Open("\\.\\C:",[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite)
$buf = New-Object byte[] (1MB)
$null = $fs.Read($buf,0,$buf.Length)
$fs.Close()
[IO.File]::WriteAllBytes("C:\\temp\\c_first_mb.bin", $buf)
```

```csharp
// C# (compile with Add-Type) – read an arbitrary offset of \\.\nusing System;
using System.IO;
class R {
static void Main(string[] a){
using(var fs = new FileStream("\\\\.\\C:", FileMode.Open, FileAccess.Read, FileShare.ReadWrite)){
fs.Position = 0x100000; // seek
var buf = new byte[4096];
fs.Read(buf,0,buf.Length);
File.WriteAllBytes("C:\\temp\\blk.bin", buf);
}
}
}
```
</details>

- NTFS対応ツールを使用して、raw volumeから特定のファイルを復元する:
- RawCopy/RawCopy64（使用中のファイルをセクターレベルでコピー）
- FTK ImagerまたはThe Sleuth Kit（読み取り専用でイメージングし、その後ファイルをcarve）
- vssadmin/diskshadow + shadow copyを使用し、snapshotから対象ファイルをコピーする（VSSを作成できる場合。通常はadmin権限が必要だが、SeManageVolumePrivilegeを持つ同じオペレーターが利用できることが多い）

主なターゲットとなる機密パス:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY（local secrets）
- C:\Windows\NTDS\ntds.dit（domain controllers – shadow copy経由）
- C:\Windows\System32\CertSrv\CertEnroll\（CA certs/CRLs。private keysは上記のmachine key storeに保存される）

## AD CS tie‑in: Golden CertificateのForging

Enterprise CAのprivate keyをmachine key storeから読み取れる場合、任意のprincipal用のclient-auth certificatesをforgeし、PKINIT/Schannel経由でauthenticateできる。これはしばしばGolden Certificateと呼ばれる。<sup>[[2]](#references)</sup> See:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

（Section: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”）。

## Detection and hardening

- SeManageVolumePrivilege（Perform volume maintenance tasks）の割り当てを、信頼できるadminのみに厳しく制限する。
- Sensitive Privilege Useと、\\.\C:、\\.\PhysicalDrive0などのdevice objectsに対するprocess handle opensを監視する。
- 適切に構成されたHSMまたはTPM-backedでnon-exportableなCA keysを優先し、コピーされたkey-container fileだけでは使用可能なprivate-key materialを復元できないようにする。
- CA-key path以外のapplication secretsについては、DPAPIまたはDPAPI-NGにより、user、machine、group、その他のauthorized principalに保護することで、コピーされたdata fileだけでは不十分にできる。これは、compromised principalがすでにアクセス可能なplaintextを保護するものではない。<sup>[[4]](#references)</sup>
- uploads、temp、extraction pathsをnon-executableかつ分離された状態に保つ（このchain post‑exploitationと組み合わせることが多いweb context defense）。

## References

- [1] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` physical disks and volumes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - Cryptography API: Next Generation and DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
