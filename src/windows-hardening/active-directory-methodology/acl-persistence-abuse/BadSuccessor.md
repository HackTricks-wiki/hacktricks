# Active Directory ACLs/ACEsの悪用

{{#include ../../../banners/hacktricks-training.md}}

## 概要

委任された管理サービスアカウント（**dMSAs**）は、**Windows Server 2025**で導入された新しいADプリンシパルタイプです。これは、古いサービスアカウントを置き換えるために設計されており、古いアカウントのサービスプリンシパル名（SPN）、グループメンバーシップ、委任設定、さらには暗号鍵を新しいdMSAに自動的にコピーする「移行」をワンクリックで実行できるようにします。これにより、アプリケーションはシームレスに切り替えができ、Kerberoastingのリスクが排除されます。

Akamaiの研究者は、単一の属性—**`msDS‑ManagedAccountPrecededByLink`**—がdMSAが「継承」する古いアカウントをKDCに伝えることを発見しました。攻撃者がその属性を書き込むことができ（そして**`msDS‑DelegatedMSAState` → 2**を切り替えることができれば）、KDCは喜んで選択した被害者のすべてのSIDを継承するPACを構築します。これにより、dMSAはドメイン管理者を含む任意のユーザーを偽装することが可能になります。

## dMSAとは正確には何ですか？

* **gMSA**技術の上に構築されているが、新しいADクラス**`msDS‑DelegatedManagedServiceAccount`**として保存されます。
* **オプトイン移行**をサポート：`Start‑ADServiceAccountMigration`を呼び出すことで、dMSAが古いアカウントにリンクされ、古いアカウントに`msDS‑GroupMSAMembership`への書き込みアクセスが付与され、`msDS‑DelegatedMSAState`が1に切り替わります。
* `Complete‑ADServiceAccountMigration`の後、前のアカウントは無効になり、dMSAは完全に機能するようになります。以前に古いアカウントを使用していたホストは、自動的にdMSAのパスワードを取得する権限を持ちます。
* 認証中、KDCは**KERB‑SUPERSEDED‑BY‑USER**ヒントを埋め込むため、Windows 11/24H2クライアントはdMSAで透過的に再試行します。

## 攻撃の要件
1. **少なくとも1つのWindows Server 2025 DC**が必要で、dMSA LDAPクラスとKDCロジックが存在します。
2. **OUに対するオブジェクト作成または属性書き込み権限**（任意のOU） – 例：`Create msDS‑DelegatedManagedServiceAccount`または単に**Create All Child Objects**。Akamaiは、91％の実際のテナントが非管理者に対してこのような「無害な」OU権限を付与していることを発見しました。
3. Kerberosチケットを要求するために、ドメインに参加している任意のホストからツール（PowerShell/Rubeus）を実行する能力。
*被害者ユーザーに対する制御は必要ありません; 攻撃はターゲットアカウントに直接触れることはありません。*

## ステップバイステップ：BadSuccessor*特権昇格

1. **制御するdMSAを見つけるか作成する**
```bash
New‑ADServiceAccount Attacker_dMSA `
‑DNSHostName ad.lab `
‑Path "OU=temp,DC=lab,DC=local"
```

あなたが書き込むことができるOU内にオブジェクトを作成したため、あなたは自動的にそのすべての属性を所有します。

2. **2つのLDAP書き込みで「完了した移行」をシミュレートする**：
- `msDS‑ManagedAccountPrecededByLink = DN`を任意の被害者（例：`CN=Administrator,CN=Users,DC=lab,DC=local`）に設定します。
- `msDS‑DelegatedMSAState = 2`（移行完了）を設定します。

**Set‑ADComputer、ldapmodify**、または**ADSI Edit**などのツールが機能します; ドメイン管理者権限は必要ありません。

3. **dMSAのTGTを要求する** — Rubeusは`/dmsa`フラグをサポートしています：

```bash
Rubeus.exe asktgs /targetuser:attacker_dmsa$ /service:krbtgt/aka.test /dmsa /opsec /nowrap /ptt /ticket:<Machine TGT>
```

返されたPACには、SID 500（Administrator）およびDomain Admins/Enterprise Adminsグループが含まれています。

## すべてのユーザーのパスワードを収集する

正当な移行中、KDCは新しいdMSAが**切り替え前に古いアカウントに発行されたチケットを復号化する**ことを許可しなければなりません。ライブセッションを壊さないように、現在のキーと以前のキーの両方を**`KERB‑DMSA‑KEY‑PACKAGE`**という新しいASN.1ブロブに配置します。

私たちの偽の移行はdMSAが被害者を継承すると主張するため、KDCは被害者のRC4-HMACキーを**以前のキー**リストに忠実にコピーします—たとえdMSAが「以前の」パスワードを持っていなかったとしても。そのRC4キーはソルトされていないため、実質的に被害者のNTハッシュとなり、攻撃者に**オフラインクラッキングまたは「パス・ザ・ハッシュ」**の能力を与えます。

したがって、数千のユーザーを一括リンクすることで、攻撃者は「スケールで」ハッシュをダンプすることができ、**BadSuccessorは特権昇格と資格情報侵害の原始的な手段の両方に変わります**。

## ツール

- [https://github.com/akamai/BadSuccessor](https://github.com/akamai/BadSuccessor)
- [https://github.com/logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)
- [https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)

## 参考文献

- [https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)

{{#include ../../../banners/hacktricks-training.md}}
