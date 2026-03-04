# AD Dynamic Objects (dynamicObject) アンチフォレンジック

{{#include ../../banners/hacktricks-training.md}}

## 動作と検出の基本

- 補助クラス **`dynamicObject`** で作成されたオブジェクトは **`entryTTL`**（秒のカウントダウン）と **`msDS-Entry-Time-To-Die`**（絶対的な有効期限）を持ちます。`entryTTL` が 0 になると **Garbage Collector が tombstone/recycle-bin を残さず削除** し、作成者やタイムスタンプを消して復旧を阻害します。
- TTL は `entryTTL` を更新してリフレッシュできます；最小/デフォルトは **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** で強制されます（1s〜1y をサポートしますが、一般的には 86,400s/24h がデフォルト）。Dynamic objects は **Configuration/Schema パーティションではサポートされません**。
- DC の稼働時間が短い (<24h) 環境では削除が数分遅れることがあり、属性をクエリ/バックアップするための狭い応答ウィンドウが残ります。新規オブジェクトに `entryTTL`/`msDS-Entry-Time-To-Die` が付与されていることをアラートし、孤立 SID／壊れたリンクと相関させて検出します。

## MAQ 回避：自己削除するコンピュータ

- デフォルトの **`ms-DS-MachineAccountQuota` = 10** により、認証済みユーザはコンピュータを作成できます。作成時に `dynamicObject` を追加すると、そのコンピュータは自己削除して **クォータ枠を解放** しつつ証拠を消去します。
- `New-MachineAccount` 内の Powermad トリック（objectClass リスト）:
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- 短い TTL（例：60s）は通常ユーザでは失敗することが多く、AD は **`DynamicObjectDefaultTTL`** にフォールバックします（例：86,400s）。ADUC は `entryTTL` を隠す場合がありますが、LDP/LDAP クエリで確認できます。

## ステルスな Primary Group メンバーシップ

- 動的なセキュリティグループを作成し、ユーザの **`primaryGroupID`** をそのグループの RID に設定すると、`memberOf` に表示されないが Kerberos / アクセストークンで有効なメンバーシップを得られます。
- TTL が切れると、primary-group の削除保護があってもグループは削除され、ユーザは存在しない RID を指す壊れた `primaryGroupID` を持ち、権限付与の痕跡を調査するためのトゥームストーンが残りません。

## AdminSDHolder の孤立 SID 汚染

- 短命な dynamic user/group の ACE を `CN=AdminSDHolder,CN=System,...` に追加します。TTL が切れると、その SID はテンプレート ACL 内で解決不能（“Unknown SID”）になり、**SDProp（約60分）** によりその孤立 SID が全ての保護された Tier-0 オブジェクトへ伝播します。
- プリンシパルが存在しないためフォレンジックで帰属が失われます（削除オブジェクトの DN はなし）。新しい dynamic プリンシパルと AdminSDHolder/特権 ACL 上の突然の孤立 SID を監視してください。

## 証拠を自己消滅させる Dynamic GPO 実行

- 悪意ある **`gPCFileSysPath`**（例：SMB シェア、GPODDITY 的手法）を持つ **dynamic `groupPolicyContainer`** オブジェクトを作成し、`gPLink` でターゲット OU にリンクします。
- クライアントはポリシーを処理して攻撃者の SMB からコンテンツを取得します。TTL が切れると GPO オブジェクト（および `gPCFileSysPath`）が消え、LDAP 上に残るのは壊れた `gPLink` の GUID のみとなり、実行されたペイロードの証拠が消えます。

## エフェメラルな AD 統合 DNS リダイレクション

- AD DNS レコードは DomainDnsZones/ForestDnsZones 内の **`dnsNode`** オブジェクトです。これらを dynamic objects として作成すると、一時的なホストリダイレクト（資格情報窃取/MITM）が可能になります。クライアントは悪意ある A/AAAA 応答をキャッシュし、その後レコードが自己削除されるためゾーンはクリーンに見えます（DNS Manager はビュー更新のためゾーンの再読み込みが必要な場合あり）。
- 検出策：レプリケーション／イベントログ経由で **`dynamicObject`/`entryTTL` を持つ DNS レコード** をアラートする。短命レコードは標準の DNS ログにはほとんど現れません。

## ハイブリッド Entra ID デルタ同期のギャップ（注意）

- Entra Connect のデルタ同期は削除検出に **tombstones** を利用します。オンプレの dynamic ユーザが Entra ID に同期され、期限切れで tombstone を残さず削除されると、デルタ同期はクラウドアカウントを削除しません。手動でフル同期を強制するまでアクティブな孤立 Entra ユーザが残ります。

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
