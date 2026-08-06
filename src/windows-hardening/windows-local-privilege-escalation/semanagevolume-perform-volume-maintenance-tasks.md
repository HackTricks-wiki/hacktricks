# SeManageVolumePrivilege: 任意ファイル読み取りのための Raw volume access

{{#include ../../banners/hacktricks-training.md}}

## Overview

Windows ユーザー権利: Perform volume maintenance tasks（定数: SeManageVolumePrivilege）。

この権利を持つユーザーは、デフラグ、ボリュームの作成・削除、maintenance IO などの低レベルなボリューム操作を実行できます。攻撃者にとって特に重要なのは、この権利によって raw volume device handle（例: \\.\C:）を開き、NTFS file ACLs をバイパスする直接ディスク I/O を実行できる点です。raw access を使用すると、DACL によって拒否されている場合でも、filesystem structures を offline で解析したり、block/cluster level で読み取るツールを利用したりすることで、ボリューム上の任意のファイルのバイト列をコピーできます。

Default: servers と domain controllers 上の Administrators.<sup>[[1]](#references)</sup>

## Abuse scenarios

- ディスクデバイスを読み取ることで、ACLs をバイパスして任意のファイルを読み取る（例: %ProgramData%\Microsoft\Crypto\RSA\MachineKeys および %ProgramData%\Microsoft\Crypto\Keys 配下の machine private keys、registry hives、DPAPI masterkeys、SAM、VSS 経由の ntds.dit など、機密性の高い system-protected material を exfiltrate する）。
- raw device からバイト列を直接コピーすることで、locked/privileged paths（C:\Windows\System32\…）をバイパスする。
- AD CS environments では、CA の key material（machine key store）を exfiltrate して “Golden Certificates” を作成し、PKINIT 経由で任意の domain principal に impersonate する。以下の link を参照。<sup>[[2]](#references)</sup>

Note: helper tools に依存しない限り、NTFS structures 用の parser が必要です。多くの off-the-shelf tools は raw access を抽象化します。

## Practical techniques

- raw volume handle を開いて clusters を読み取る:

<details>
<summary>クリックして展開</summary>
```powershell
# PowerShell – read first MB from C: raw device (requires SeManageVolumePrivilege)
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

- raw volume から特定のファイルを復元するには、NTFS 対応ツールを使用します。
- RawCopy/RawCopy64（使用中のファイルをセクターレベルでコピー）
- FTK Imager または The Sleuth Kit（読み取り専用でイメージングし、その後ファイルを carve）
- vssadmin/diskshadow + shadow copy を使用し、snapshot から対象ファイルをコピー（VSS を作成できる場合。通常は admin が必要ですが、SeManageVolumePrivilege を保持する同じ operator が利用できることが多い）

標的にする代表的な機密パス:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY（local secrets）
- C:\Windows\NTDS\ntds.dit（domain controllers – shadow copy 経由）
- C:\Windows\System32\CertSrv\CertEnroll\（CA certs/CRLs。private keys は上記の machine key store に保存）

## AD CS tie‑in: Golden Certificate の Forging

Enterprise CA の private key を machine key store から読み取れる場合、任意の principal 用に client-auth certificates を forge し、PKINIT/Schannel 経由で authenticate できます。これは通常、Golden Certificate と呼ばれます。<sup>[[2]](#references)</sup> 以下を参照してください。

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

（セクション: “Stolen CA Certificates (Golden Certificate) を使用した Certificates の Forging – DPERSIST1”）。

## Detection and hardening

- SeManageVolumePrivilege (Perform volume maintenance tasks) の割り当てを、信頼できる admin のみに厳しく制限します。
- Sensitive Privilege Use と、\\.\C:、\\.\PhysicalDrive0 などの device objects に対する process handle opens を monitor します。
- HSM/TPM-backed CA keys または DPAPI-NG を優先し、raw file reads で key material を usable form のまま復元できないようにします。
- uploads、temp、extraction paths を non-executable にし、分離しておきます（この chain post‑exploitation と組み合わせることが多い web context defense）。

## References

- [1] [Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
