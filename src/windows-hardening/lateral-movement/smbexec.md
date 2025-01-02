# SmbExec/ScExec

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="/images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**あなたのウェブアプリ、ネットワーク、クラウドに対するハッカーの視点を得る**

**実際のビジネスに影響を与える重要で悪用可能な脆弱性を見つけて報告します。** 20以上のカスタムツールを使用して攻撃面をマッピングし、特権を昇格させるセキュリティ問題を見つけ、自動化されたエクスプロイトを使用して重要な証拠を収集し、あなたの努力を説得力のある報告書に変えます。

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## 仕組み

**Smbexec** は、Windowsシステムでのリモートコマンド実行に使用されるツールで、**Psexec** に似ていますが、ターゲットシステムに悪意のあるファイルを置くことを避けます。

### **SMBExec** に関する重要なポイント

- ターゲットマシン上に一時的なサービス（例えば、「BTOBTO」）を作成して、cmd.exe (%COMSPEC%) を介してコマンドを実行しますが、バイナリを落とすことはありません。
- ステルスなアプローチにもかかわらず、実行された各コマンドのイベントログを生成し、非対話型の「シェル」の形式を提供します。
- **Smbexec** を使用して接続するためのコマンドは次のようになります:
```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```
### バイナリなしでコマンドを実行する

- **Smbexec** は、ターゲット上に物理的なバイナリが不要なサービス binPaths を通じて直接コマンドを実行することを可能にします。
- この方法は、Windows ターゲット上で一時的なコマンドを実行するのに便利です。例えば、Metasploit の `web_delivery` モジュールと組み合わせることで、PowerShell 対象のリバース Meterpreter ペイロードを実行できます。
- 攻撃者のマシン上にリモートサービスを作成し、binPath を cmd.exe を通じて提供されたコマンドを実行するように設定することで、ペイロードを成功裏に実行し、サービス応答エラーが発生しても Metasploit リスナーでコールバックとペイロード実行を達成することが可能です。

### コマンドの例

サービスを作成して開始するには、以下のコマンドを使用できます：
```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
さらなる詳細は[https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)を確認してください。

## 参考文献

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<figure><img src="/images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**あなたのウェブアプリ、ネットワーク、クラウドに対するハッカーの視点を得る**

**実際のビジネスに影響を与える重大で悪用可能な脆弱性を見つけて報告します。** 攻撃面をマッピングし、特権を昇格させるセキュリティ問題を見つけるために、20以上のカスタムツールを使用し、自動化されたエクスプロイトを利用して重要な証拠を収集し、あなたの努力を説得力のある報告に変えます。

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{{#include ../../banners/hacktricks-training.md}}
