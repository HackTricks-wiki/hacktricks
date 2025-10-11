# SeManageVolumePrivilege: 任意ファイル読み取りのための生のボリュームアクセス

{{#include ../../banners/hacktricks-training.md}}

## 概要

Windows のユーザー権利: Perform volume maintenance tasks (定数: SeManageVolumePrivilege)。

保有者はデフラグ、ボリュームの作成/削除、メンテナンス IO のような低レベルのボリューム操作を実行できます。攻撃者にとって重要なのは、この権利により生のボリュームデバイスハンドル（例: \\.\C:）を開き、NTFS ファイル ACL をバイパスする直接的なディスク I/O を発行できることです。生のアクセスを使用すると、ファイルシステム構造をオフラインで解析するか、ブロック/クラスタレベルで読み取るツールを利用することで、DACL によって拒否されていてもボリューム上の任意のファイルのバイトをコピーできます。

デフォルト: サーバーおよびドメインコントローラーの Administrators。

## 悪用シナリオ

- ディスクデバイスを読み取ることで ACL を回避した任意ファイル読み取り（例: %ProgramData%\Microsoft\Crypto\RSA\MachineKeys や %ProgramData%\Microsoft\Crypto\Keys 配下のマシン秘密鍵、レジストリハイブ、DPAPI マスターキー、SAM、VSS 経由の ntds.dit などの機密なシステム保護データを流出させる）。
- 生のデバイスからバイトを直接コピーすることで、ロックされた/特権的なパス（C:\Windows\System32\…）を回避する。
- AD CS 環境では、CA の鍵素材（machine key store）を流出させて “Golden Certificates” を作成し、PKINIT を介して任意のドメイン主体を偽装する。下のリンクを参照。

注: ヘルパーツールに頼らない場合は NTFS 構造を解析するパーサーが必要です。市販のツールの多くは生のアクセスを抽象化しています。

## 実用的な手法

- 生のボリュームハンドルを開いてクラスタを読み取る:

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

- NTFS対応ツールを使って raw volume から特定のファイルを復元する:
- RawCopy/RawCopy64 (使用中ファイルのセクターレベルコピー)
- FTK Imager or The Sleuth Kit (読み取り専用でイメージングしてからファイルを復元)
- vssadmin/diskshadow + shadow copy, そのスナップショットからターゲットファイルをコピー (VSS を作成できる場合; 多くは管理者権限が必要だが SeManageVolumePrivilege を持つオペレータには一般的に利用可能)

狙うべき典型的な機密パス:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY (local secrets)
- C:\Windows\NTDS\ntds.dit (domain controllers – via shadow copy)
- C:\Windows\System32\CertSrv\CertEnroll\ (CA certs/CRLs; private keys live in the machine key store above)

## AD CS tie‑in: Forging a Golden Certificate

もし machine key store から Enterprise CA の private key を読み取ることができれば、任意のプリンシパル向けに client‑auth 証明書を偽造し、PKINIT/Schannel 経由で認証することが可能です。これはしばしば Golden Certificate と呼ばれます。参照:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(Section: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## 検出とハードニング

- SeManageVolumePrivilege (Perform volume maintenance tasks) の割り当ては信頼できる管理者のみに厳格に制限する。
- Sensitive Privilege Use と、\\.\C: や \\.\PhysicalDrive0 のようなデバイスオブジェクトへのプロセスハンドルのオープンを監視する。
- HSM/TPM バックの CA 鍵や DPAPI-NG を優先し、生のファイル読み取りから鍵素材が実用的な形で復元されないようにする。
- アップロード、テンポラリ、展開先のパスは実行不可かつ分離しておく（web コンテキスト防御で、しばしばこのチェーンの post‑exploitation と組み合わされる）。

## References

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
