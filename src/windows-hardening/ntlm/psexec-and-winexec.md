# PsExec/Winexec/ScExec

{{#include ../../banners/hacktricks-training.md}}

## どのように機能するか

プロセスは以下のステップで概説されており、サービスバイナリがどのように操作され、SMBを介してターゲットマシンでリモート実行を達成するかを示しています：

1. **ADMIN$共有にサービスバイナリをSMB経由でコピー**します。
2. **リモートマシン上にサービスを作成**し、バイナリを指します。
3. サービスが**リモートで開始**されます。
4. 終了時に、サービスは**停止され、バイナリは削除**されます。

### **PsExecを手動で実行するプロセス**

msfvenomで作成され、Veilを使用してウイルス対策検出を回避するように難読化された実行可能ペイロード「met8888.exe」を仮定すると、以下のステップが取られます：

- **バイナリのコピー**：実行可能ファイルはコマンドプロンプトからADMIN$共有にコピーされますが、ファイルシステムのどこにでも配置して隠すことができます。

- **サービスの作成**：Windowsの`sc`コマンドを利用して、リモートでWindowsサービスを照会、作成、削除することができ、「meterpreter」という名前のサービスがアップロードされたバイナリを指すように作成されます。

- **サービスの開始**：最終ステップはサービスを開始することで、バイナリが本物のサービスバイナリでないため、期待される応答コードを返さず「タイムアウト」エラーが発生する可能性があります。このエラーは、主な目的がバイナリの実行であるため、重要ではありません。

Metasploitリスナーを観察すると、セッションが正常に開始されたことがわかります。

[scコマンドの詳細を学ぶ](https://technet.microsoft.com/en-us/library/bb490995.aspx)。

詳細な手順については、こちらを参照してください: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

**Windows SysinternalsバイナリPsExec.exeを使用することもできます：**

![](<../../images/image (165).png>)

[**SharpLateral**](https://github.com/mertdas/SharpLateral)を使用することもできます：
```
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```
{{#include ../../banners/hacktricks-training.md}}
