# Windows サービストリガー: 列挙と悪用

{{#include ../../banners/hacktricks-training.md}}

Windows Service Triggers は、条件が発生したときに Service Control Manager (SCM) がサービスを開始/停止できるようにします（例：IP アドレスが利用可能になる、named pipe への接続が試みられる、ETW イベントが公開される）。ターゲットサービスに対して SERVICE_START 権限がなくても、トリガーを発火させることでサービスを開始できる場合があります。

このページは、攻撃者に優しい列挙方法と摩擦の少ない一般的なトリガーの起動方法に焦点を当てています。

> Tip: 特権を持つ組み込みサービス（例：RemoteRegistry、WebClient/WebDAV、EFS）を起動すると、新しい RPC/名前付きパイプのリスナーが露出し、さらに悪用チェーンが解放されることがあります。

## サービストリガーの列挙

- sc.exe (local)
- サービスのトリガーを一覧表示: `sc.exe qtriggerinfo <ServiceName>`
- Registry (local)
- トリガーは次に格納されている: `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo`
- 再帰的にダンプ: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\TriggerInfo /s`
- Win32 API (local)
- QueryServiceConfig2 を SERVICE_CONFIG_TRIGGER_INFO (8) で呼び出して SERVICE_TRIGGER_INFO を取得します。
- ドキュメント: QueryServiceConfig2[W/A] および SERVICE_TRIGGER/SERVICE_TRIGGER_SPECIFIC_DATA
- RPC over MS‑SCMR (remote)
- SCM はリモートでクエリしてトリガー情報を取得できます。TrustedSec の Titanis はこれを公開しています: `Scm.exe qtriggers`。
- Impacket は msrpc MS-SCMR 内の構造体を定義しているため、それらを使ってリモートクエリを実装できます。

## 価値の高いトリガー種類と起動方法

### Network Endpoint Triggers

これらはクライアントが IPC エンドポイントに接続しようとする際にサービスを開始します。SCM はクライアントが実際に接続する前にサービスを自動起動するため、低権限ユーザにとって有用です。

- Named pipe trigger
- 挙動: クライアントが \\.\pipe\<PipeName> に接続を試みると、SCM がサービスを起動してリッスンを開始させます。
- Activation (PowerShell):
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream('.', 'PipeNameFromTrigger', [System.IO.Pipes.PipeDirection]::InOut)
try { $pipe.Connect(1000) } catch {}
$pipe.Dispose()
```
- 参照: Named Pipe Client Impersonation による post-start の悪用。

- RPC endpoint trigger (Endpoint Mapper)
- 挙動: サービスに関連付けられたインターフェイス UUID を Endpoint Mapper (EPM, TCP/135) に問い合わせると、SCM がサービスを起動してエンドポイントを登録できるようにします。
- Activation (Impacket):
```bash
# Queries local EPM; replace UUID with the service interface GUID
python3 rpcdump.py @127.0.0.1 -uuid <INTERFACE-UUID>
```

### Custom (ETW) Triggers

サービスは ETW プロバイダ/イベントにバインドされたトリガーを登録できます。追加のフィルタ（keyword/level/binary/string）が設定されていない場合、そのプロバイダからの任意のイベントがサービスを開始します。

- 例 (WebClient/WebDAV): provider {22B6D684-FA63-4578-87C9-EFFCBE6643C7}
- トリガー一覧: `sc.exe qtriggerinfo webclient`
- プロバイダが登録されているか確認: `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`
- マッチするイベントを発行するには通常そのプロバイダにログを送るコードが必要ですが、フィルタがなければ任意のイベントで十分です。

### Group Policy Triggers

サブタイプ: Machine/User。対応するポリシーが存在するドメイン参加ホストでは、トリガーがブート時に実行されます。`gpupdate` 単独では変更がない限りトリガーは発動しませんが:

- Activation: `gpupdate /force`
- 関連するポリシータイプが存在する場合、これにより確実にトリガーが発火してサービスが開始されます。

### IP Address Available

最初の IP が取得されたとき（または最後の IP が失われたとき）に発火します。多くは起動時にトリガーされます。

- Activation: 接続を切り替えて再トリガー、例:
```cmd
netsh interface set interface name="Ethernet" admin=disabled
netsh interface set interface name="Ethernet" admin=enabled
```

### Device Interface Arrival

マッチするデバイスインターフェイスが到着したときにサービスを開始します。データアイテムが指定されていない場合、トリガーサブタイプ GUID に一致する任意のデバイスがトリガーを発火させます。ブート時およびホットプラグ時に評価されます。

- Activation: トリガーサブタイプで指定されたクラス/ハードウェア ID に一致するデバイス（物理または仮想）を接続/挿入します。

### Domain Join State

MSDN の表現は紛らわしいですが、これは起動時のドメイン状態を評価します:
- DOMAIN_JOIN_GUID → ドメイン参加している場合にサービスを開始
- DOMAIN_LEAVE_GUID → ドメイン未参加の場合にのみサービスを開始

### System State Change – WNF (undocumented)

一部のサービスは未文書化の WNF ベースのトリガー（SERVICE_TRIGGER_TYPE 0x7）を使用します。起動には関連する WNF state の publish が必要で、詳細は state 名に依存します。研究の背景: Windows Notification Facility の内部。

### Aggregate Service Triggers (undocumented)

Windows 11 の一部サービス（例: CDPSvc）で観測されます。集約設定は次に格納されます:

- HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents

サービスの Trigger 値は GUID であり、その GUID を名前とするサブキーが集約イベントを定義します。構成要素のいずれかのイベントをトリガーするとサービスが開始されます。

### Firewall Port Event (quirks and DoS risk)

特定のポート/プロトコルにスコープされたトリガーは、指定されたポートだけでなく任意のファイアウォールルールの変更（無効化/削除/追加）で開始されることが観測されています。さらに、プロトコル無しでポートを設定すると BFE の起動が再起動間で壊れ、多数のサービス障害を連鎖させてファイアウォール管理を破壊する可能性があります。扱いには極めて注意してください。

## 実用ワークフロー

1) 興味のあるサービス（RemoteRegistry, WebClient, EFS, …）のトリガーを列挙:
- `sc.exe qtriggerinfo <Service>`
- `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`

2) Network Endpoint トリガーが存在する場合:
- Named pipe → \\.\pipe\<PipeName> へのクライアントオープンを試みる
- RPC endpoint → インターフェイス UUID の Endpoint Mapper ルックアップを実行

3) ETW トリガーが存在する場合:
- `sc.exe qtriggerinfo` でプロバイダとフィルタを確認; フィルタがなければそのプロバイダの任意のイベントでサービスが開始されます

4) Group Policy/IP/Device/Domain トリガーの場合:
- 環境を操作: `gpupdate /force`、NIC を切り替え、デバイスをホットプラグ、など

## 関連

- After starting a privileged service via a Named Pipe trigger, you may be able to impersonate it:

{{#ref}}
named-pipe-client-impersonation.md
{{#endref}}

## クイックコマンドまとめ

- トリガー一覧 (local): `sc.exe qtriggerinfo <Service>`
- レジストリ表示: `reg query HKLM\SYSTEM\CurrentControlSet\Services\<Service>\TriggerInfo /s`
- Win32 API: `QueryServiceConfig2(..., SERVICE_CONFIG_TRIGGER_INFO, ...)`
- RPC remote (Titanis): `Scm.exe qtriggers`
- ETW プロバイダ確認 (WebClient): `logman query providers | findstr /I 22b6d684-fa63-4578-87c9-effcbe6643c7`

## 検出とハードニングの注意点

- サービス全体で TriggerInfo をベースライン化および監査してください。集約トリガーについては HKLM\SYSTEM\CurrentControlSet\Control\ServiceAggregatedEvents も確認してください。
- 特権サービスの UUID に対する疑わしい EPM ルックアップや、サービス起動に先行する名前付きパイプ接続試行を監視してください。
- サービストリガーを変更できるユーザを制限し、トリガー変更後の予期しない BFE 障害は疑わしいものとして扱ってください。

## References
- [There’s More than One Way to Trigger a Windows Service (TrustedSec)](https://trustedsec.com/blog/theres-more-than-one-way-to-trigger-a-windows-service)
- [QueryServiceConfig2 function (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryserviceconfig2a)
- [MS-SCMR: Service Control Manager Remote Protocol – QueryServiceConfig2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f)
- [TrustedSec Titanis (SCM trigger enumeration)](https://github.com/trustedsec/Titanis)
- [Cobalt Strike BOF example – sc_qtriggerinfo](https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/5d6f70be2e5023c340dc5f82303449504a9b7786/src/SA/sc_qtriggerinfo/entry.c#L56)

{{#include ../../banners/hacktricks-training.md}}
