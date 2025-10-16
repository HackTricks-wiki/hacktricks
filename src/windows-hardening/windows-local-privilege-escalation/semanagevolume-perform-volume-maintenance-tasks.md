# SeManageVolumePrivilege: 任意ファイルの読み取りのための生ボリュームアクセス

{{#include ../../banners/hacktricks-training.md}}

## 概要

Windows user right: Perform volume maintenance tasks (constant: SeManageVolumePrivilege).

権利保持者はデフラグ、ボリュームの作成/削除、メンテナンスI/O などの低レベルなボリューム操作を実行できます。攻撃者にとって重要なのは、この権利により生のボリュームデバイスハンドル（例: \\.\C:）を開き、NTFS ファイルの ACL をバイパスする直接的なディスク I/O を発行できる点です。生のアクセスを利用すると、ファイルシステム構造をオフラインで解析するか、ブロック/クラスター単位で読み取るツールを活用することで、DACL により拒否されていてもボリューム上の任意ファイルのバイトをコピーできます。

既定: サーバーおよびドメインコントローラー上の Administrators。

## 悪用シナリオ

- ディスクデバイスを読み取ることで ACL をバイパスして任意ファイルを読み出す（例: %ProgramData%\Microsoft\Crypto\RSA\MachineKeys や %ProgramData%\Microsoft\Crypto\Keys にあるマシン秘密鍵、レジストリハイブ、DPAPI masterkeys、SAM、VSS 経由の ntds.dit などの機密なシステム保護データを持ち出す）。
- ロックされた/特権的なパス (C:\Windows\System32\…) を、生デバイスから直接バイトをコピーして回避する。
- AD CS 環境では、CA のキー素材（machine key store）を持ち出して「Golden Certificates」を作成し、PKINIT を使って任意のドメイン主体を偽装する。詳細は下のリンクを参照。

注意: ヘルパーツールに頼らない限り、NTFS 構造を解析するパーサーが必要です。市販の多くのツールは生アクセスを抽象化しています。

## 実用的な手法

- 生ボリュームハンドルを開いてクラスターを読み取る:

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

- Use an NTFS-aware tool to recover specific files from raw volume:
- RawCopy/RawCopy64 (使用中ファイルのセクターレベルコピー)
- FTK Imager or The Sleuth Kit (読み取り専用イメージング、後でファイルをカービングして復元)
- vssadmin/diskshadow + shadow copy、スナップショットから対象ファイルをコピー（VSS を作成できる場合。多くは管理者権限が必要だが、SeManageVolumePrivilege を持つオペレータでは一般的に利用可能）

Typical sensitive paths to target:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY（ローカルの秘密情報）
- C:\Windows\NTDS\ntds.dit（ドメインコントローラ — シャドウコピー経由）
- C:\Windows\System32\CertSrv\CertEnroll\（CA 証明書/CRL；秘密鍵は上記の machine key store に格納）

## AD CS との関連: Forging a Golden Certificate

もし Enterprise CA の秘密鍵を machine key store から読み出せるなら、任意のプリンシパル向けに client-auth 証明書を偽造し、PKINIT/Schannel を使って認証できます。これは一般に Golden Certificate と呼ばれます。参照：

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

(セクション: “Forging Certificates with Stolen CA Certificates (Golden Certificate) – DPERSIST1”).

## 検出とハードニング

- SeManageVolumePrivilege (Perform volume maintenance tasks) の割当を信頼できる管理者のみに厳格に制限する。
- Sensitive Privilege Use と、プロセスが \\.\C:, \\.\PhysicalDrive0 のようなデバイスオブジェクトに対してハンドルを開く動作を監視する。
- 生ファイルの読み取りで鍵素材が利用可能な形で回復されないよう、HSM/TPM バックの CA 鍵や DPAPI-NG を利用することを推奨する。
- アップロード、テンポラリ、展開パスを実行不可かつ分離して保つ（Web コンテキストでの防御。ポストエクスプロイトでこのチェーンと組み合わせられることが多い）。

## References

- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege used to read CA key → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
