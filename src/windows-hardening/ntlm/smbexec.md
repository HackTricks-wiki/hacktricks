# SmbExec/ScExec

{{#include ../../banners/hacktricks-training.md}}

## 仕組み

**Smbexec** は、Windows システムでのリモートコマンド実行に使用されるツールで、**Psexec** に似ていますが、ターゲットシステムに悪意のあるファイルを配置することを避けます。

### **SMBExec** に関する重要なポイント

- ターゲットマシン上に一時的なサービス（例えば、「BTOBTO」）を作成して、cmd.exe (%COMSPEC%) を介してコマンドを実行し、バイナリを落とさないように動作します。
- ステルスなアプローチにもかかわらず、実行された各コマンドのイベントログを生成し、非対話型の「シェル」の形式を提供します。
- **Smbexec** を使用して接続するためのコマンドは次のようになります:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### バイナリなしでコマンドを実行する

- **Smbexec** は、ターゲット上に物理的なバイナリが不要で、サービスの binPaths を通じて直接コマンドを実行することを可能にします。
- この方法は、Windows ターゲット上で一時的なコマンドを実行するのに便利です。たとえば、Metasploit の `web_delivery` モジュールと組み合わせることで、PowerShell 対象のリバース Meterpreter ペイロードを実行できます。
- 攻撃者のマシン上にリモートサービスを作成し、binPath を cmd.exe を通じて提供されたコマンドを実行するように設定することで、サービス応答エラーが発生しても、ペイロードを正常に実行し、Metasploit リスナーでコールバックとペイロードの実行を達成することが可能です。

### コマンドの例

サービスの作成と開始は、以下のコマンドで実行できます：
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
さらなる詳細については、[https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)を確認してください。

## 参考文献

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

{{#include ../../banners/hacktricks-training.md}}
