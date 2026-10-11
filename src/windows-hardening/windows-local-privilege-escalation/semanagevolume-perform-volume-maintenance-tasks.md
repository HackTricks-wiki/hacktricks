# SeManageVolumePrivilege: ボリュームメンテナンスの悪用と raw-access の検証

{{#include ../../banners/hacktricks-training.md}}

## 概要

Windows ユーザー権利: ボリュームメンテナンスタスクの実行 (定数: SeManageVolumePrivilege)。

この権利により、デフラグやボリュームの作成・削除などのボリュームメンテナンス操作が許可されます。Microsoft は、この権利を持つユーザーが、他のデータを含むストレージ領域までファイルを拡張し、取得したバイトを読み取ったり変更したりできる可能性があると警告しています。<sup>[[1]](#references)</sup>

`SeManageVolumePrivilege` を持っていれば raw-disk access が保証される、と考えてはいけません。Microsoft の説明では、`CreateFile` で物理ディスクまたはボリュームを開いて直接アクセスするには管理者権限が必要であり、通常のオブジェクトやデバイスのアクセスチェックも適用されます。特定のビルドや製品で任意のファイルを読み取れると主張する前に、トークン、デバイス ACL、要求するアクセス権、共有フラグ、ボリュームの状態によって raw handle を取得できるか検証してください。<sup>[[3]](#references)</sup>

デフォルト: サーバーおよびドメインコントローラーの Administrators。<sup>[[1]](#references)</sup>

## 悪用シナリオ

- アカウントが実際に読み取り可能な raw-volume handle を取得できる場合、NTFS 対応のパーサーを使ってファイルごとの ACL を回避し、割り当て済みクラスターから保護されたファイルやロックされたファイルを復元できます。
- 標的となり得るものには、`C:\Windows\System32` 内のロックまたは ACL で保護されたコンテンツ、レジストリハイブ、DPAPI master keys、SAM、そしてスナップショットやオフラインボリューム経由で別途アクセスできる場合の `ntds.dit` などがあります。
- 証明書サービスのホストでは、ソフトウェアキーの保存場所として `%ProgramData%\Microsoft\Crypto\RSA\MachineKeys` や `%ProgramData%\Microsoft\Crypto\Keys` が有用です。ただし、ファイルを復元できても、そのキーマテリアルがエクスポート可能であり、さらに復号できる場合に限り有効です。<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>
- AD CS ホストで、**エクスポート可能なソフトウェアベースの** CA 秘密鍵を正常に復元できれば、Golden Certificate の悪用が可能になります。ハードウェアベースまたはエクスポート不可の鍵設計では、この手順は変わります。<sup>[[2]](#references)</sup>
- 一部のボリュームメンテナンスツールは、許可されている場合に `FSCTL_SD_GLOBAL_CHANGE` を使ってファイルシステムの ACL エントリを置き換えます。これは raw block を受動的に読み取るのではなくアクセス制御を変更するもので、ボリュームの広範囲に影響する可能性があります。実際のトークンとデバイスの動作を確認してください。[ツールのソース](https://github.com/CsEnox/SeManageVolumeExploit)にはこの具体的な仕組みが示されています。この権利を持っているだけでは、成功するとは限りません。
- ACL の変更でファイルにアクセスできても、EFS で暗号化されたファイルが復号されるわけではありません。平文を得るには、対応するユーザーまたは回復用の秘密鍵が必要です。同様に、[`certutil -exportPFX`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil) を使ってソフトウェアベースの CA キーをエクスポートするには、そのキーがローカルにあり、エクスポート可能で、アクセス可能である必要があります。

注: 補助ツールに頼らない場合は、NTFS 構造を解析するパーサーも必要です。市販の多くのツールは raw access を抽象化します。

## 実践的な手法

- raw volume handle を開いてクラスターを読み取る:

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

- raw volume から特定のファイルを復元するには、NTFS 対応ツールを使用します。
  - RawCopy/RawCopy64（使用中のファイルをセクターレベルでコピー）
  - FTK Imager または The Sleuth Kit（読み取り専用でイメージを作成し、その後ファイルをカービング）
  - vssadmin/diskshadow と shadow copy を使い、スナップショットから対象ファイルをコピー（VSS を作成できる場合。通常は管理者権限が必要ですが、SeManageVolumePrivilege を持つ同じオペレーターが利用できることもよくあります）

主な標的となる機密パス:
- %ProgramData%\Microsoft\Crypto\RSA\MachineKeys\
- %ProgramData%\Microsoft\Crypto\Keys\
- C:\Windows\System32\config\SAM, SYSTEM, SECURITY（ローカルの秘密情報）
- C:\Windows\NTDS\ntds.dit（ドメインコントローラー – shadow copy 経由）
- C:\Windows\System32\CertSrv\CertEnroll\（CA 証明書/CRL。秘密鍵は上記のマシンキー ストアにあります）

## AD CS との関連: Golden Certificate の偽造

Enterprise CA の秘密鍵をマシンキー ストアから読み取れる場合、任意のプリンシパル向けにクライアント認証証明書を偽造し、PKINIT/Schannel 経由で認証できます。これは一般に Golden Certificate と呼ばれます。<sup>[[2]](#references)</sup> 詳細:

{{#ref}}
../active-directory-methodology/ad-certificates/domain-persistence.md
{{#endref}}

（セクション:「盗んだ CA 証明書による証明書の偽造（Golden Certificate）– DPERSIST1」）。

## 検知とハードニング

- SeManageVolumePrivilege（Perform volume maintenance tasks）の割り当ては、信頼できる管理者のみに厳しく制限します。
- Sensitive Privilege Use と、\\.\C: や \\.\PhysicalDrive0 のようなデバイス オブジェクトへのプロセスによるハンドルのオープンを監視します。
- 適切に構成した HSM または TPM ベースの、エクスポート不可な CA キーを優先します。これにより、キーコンテナー ファイルをコピーしただけでは、利用可能な秘密鍵マテリアルを復元できなくなります。
- CA キー以外のアプリケーション シークレットについては、DPAPI または DPAPI-NG を使うことで、ユーザー、マシン、グループ、その他の認可されたプリンシパルに保護対象を紐付け、データファイルをコピーしただけでは不十分な状態にできます。ただし、侵害されたプリンシパルがすでにアクセスできる平文は保護されません。<sup>[[4]](#references)</sup>
- アップロード、temp、展開先のパスは実行不可にし、分離しておきます（このチェーンの post-exploitation と併用されることの多い、Web コンテキストの防御策です）。

## References

- [1] [Microsoft – ボリュームのメンテナンス タスクを実行する（SeManageVolumePrivilege）](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [2] [0xdf – HTB: Certificate（SeManageVolumePrivilege を使って CA キーを読み取り → Golden Certificate）](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
- [3] [Microsoft - `CreateFile` の物理ディスクとボリューム](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#physical-disks-and-volumes)
- [4] [Microsoft - 暗号化 API: Next Generation と DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal)
{{#include ../../banners/hacktricks-training.md}}
