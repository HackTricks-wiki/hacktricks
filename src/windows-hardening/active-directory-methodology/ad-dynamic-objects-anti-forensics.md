# AD Dynamic Objects (dynamicObject) Anti-Forensics

{{#include ../../banners/hacktricks-training.md}}

## メカニズムと検知の基本

- 補助クラス **`dynamicObject`** で作成されたオブジェクトは **`entryTTL`**（秒単位のカウントダウン）と **`msDS-Entry-Time-To-Die`**（絶対期限）を持つ。`entryTTL` が 0 に到達すると **Garbage Collector が tombstone/recycle-bin なしで削除** し、作成者やタイムスタンプを消去して復旧を阻止する。
- TTL は `entryTTL` を更新することでリフレッシュできる；最小/デフォルト値は **Configuration\Services\NTDS Settings → `msDS-Other-Settings` → `DynamicObjectMinTTL` / `DynamicObjectDefaultTTL`** で強制される（1s–1y をサポートするが、一般的には 86,400s/24h がデフォルト）。Dynamic objects は **Configuration/Schema パーティションではサポートされない**。
- 稼働時間が短い DC（<24h）では削除が数分遅れることがあり、属性をクエリ/バックアップするための短い対応ウィンドウが残る。**`entryTTL`/`msDS-Entry-Time-To-Die` を持つ新規オブジェクトをアラート**し、孤立した SID／壊れたリンクと相関させて検知する。

## MAQ 回避（自己削除するコンピュータ）

- 既定の **`ms-DS-MachineAccountQuota` = 10** により、認証済みユーザはコンピュータを作成できる。作成時に `dynamicObject` を追加すると、コンピュータが自己削除して証拠を消しつつ **クォータスロットを解放** できる。
- Powermad の `New-MachineAccount`（objectClass リスト）内の調整:
```powershell
$request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", "dynamicObject", "Computer")) > $null
```
- 短い TTL（例: 60s）は通常ユーザでは失敗することが多く、AD は **`DynamicObjectDefaultTTL`** にフォールバックする（例: 86,400s）。ADUC は `entryTTL` を隠すことがあるが、LDP/LDAP クエリはそれを表示する。

## ステルス primary group メンバーシップ

- 動的なセキュリティグループを作成し、ユーザの **`primaryGroupID`** をそのグループの RID に設定すると、`memberOf` に表示されないが Kerberos/アクセス トークンでは有効なメンバーシップを得られる。
- TTL の期限切れにより **primary-group の削除保護があってもグループは削除され**、ユーザは存在しない RID を指す破損した `primaryGroupID` を残され、特権付与の調査に使える tombstone も存在しない。

## AdminSDHolder の孤立 SID 汚染

- 短命の dynamic user/group に対する ACE を **`CN=AdminSDHolder,CN=System,...`** に追加する。TTL が切れるとテンプレート ACL 内の SID は **解決不能（“Unknown SID”）** となり、**SDProp（約60分）** によりその孤立 SID が保護されたすべての Tier-0 オブジェクトに伝播する。
- 主体が消えるためフォレンジクスは帰属を失う（deleted-object DN がない）。**新しい dynamic principal と AdminSDHolder/特権 ACL 上の突然の孤立 SID** を監視する。

## 自己消滅する証拠を伴う Dynamic GPO 実行

- 悪意ある **`gPCFileSysPath`**（例: GPODDITY のような SMB 共有）を持つ **dynamic `groupPolicyContainer`** を作成し、対象 OU に **`gPLink`** 経由でリンクする。
- クライアントはポリシーを処理して攻撃者の SMB からコンテンツを取得する。TTL が切れると GPO オブジェクト（および `gPCFileSysPath`）は消滅し、残るのは壊れた **`gPLink`** の GUID のみとなり、実行されたペイロードの LDAP 証拠が失われる。

## 短命の AD 統合 DNS リダイレクション

- AD の DNS レコードは **`dnsNode`** オブジェクトで、**DomainDnsZones/ForestDnsZones** に存在する。これらを **dynamic objects** として作成すると、一時的なホストリダイレクト（資格情報窃取/MITM）が可能になる。クライアントは悪意ある A/AAAA レスポンスをキャッシュし、その後レコードが自己削除されるためゾーンはクリーンに見える（DNS Manager は表示更新のためにゾーン再読み込みが必要な場合がある）。
- 検知: レプリケーション/イベントログ経由で **`dynamicObject`/`entryTTL` を持つ任意の DNS レコード** をアラートする。短命レコードは標準の DNS ログに出ることは稀。

## Hybrid Entra ID Delta-Sync Gap（注意）

- Entra Connect の delta sync は削除検出に **tombstones** を利用する。**dynamic on-prem user** が Entra ID に同期され、期限切れで tombstone なしに削除されると、delta sync はクラウドアカウントを削除せず、手動で **full sync** を実行するまで **孤立したアクティブな Entra ユーザ** が残る。

## References

- [Dynamic Objects in Active Directory: The Stealthy Threat](https://www.tenable.com/blog/active-directory-dynamic-objects-stealthy-threat)

{{#include ../../banners/hacktricks-training.md}}
