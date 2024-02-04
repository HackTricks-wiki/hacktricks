# SmbExec/ScExec

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦で私をフォローする [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **ハッキングトリックを共有するために、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する。

</details>

## How it Works

**Smbexec**は、悪意のある実行ファイルを使用せずに、被害者のシステム上の**cmd.exe**または**powershell.exe**をターゲットにしてバックドアの実行を行う**Psexec**と同様の方法で動作します。

## **SMBExec**
```bash
smbexec.py WORKGROUP/username:password@10.10.10.10
```
Smbexecの機能には、バイナリをドロップせずにコマンドを実行するためにターゲットマシン上に一時サービス（例：「BTOBTO」）を作成することが含まれます。このサービスは、cmd.exeのパス（%COMSPEC%）を介してコマンドを実行するために構築され、出力を一時ファイルにリダイレクトし、実行後に自体を削除します。この方法はステルス性がありますが、各コマンドごとにイベントログを生成し、攻撃者側から発行されたすべてのコマンドに対してこのプロセスを繰り返すことで、非対話的な「シェル」を提供します。

## バイナリを使用せずにコマンドを実行する

このアプローチにより、サービスのbinPathsを介した直接的なコマンド実行が可能となり、バイナリの必要性がなくなります。これは、Windowsターゲット上での一度限りのコマンド実行に特に有用です。たとえば、Metasploitの`web_delivery`モジュールを使用して、PowerShellを対象とする逆接続Meterpreterペイロードを使用して、必要な実行コマンドを提供するリスナーを確立できます。攻撃者のWindowsマシンで、binPathをcmd.exeを介してこのコマンドを実行するように設定したリモートサービスを作成して起動することで、潜在的なサービス応答エラーにもかかわらず、Metasploitリスナー側でのコールバックとペイロードの実行を実現できます。

### コマンドの例

次のコマンドを使用して、サービスの作成と開始を行うことができます。
```cmd
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```
# 参考文献
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じて、ゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks を PDF でダウンロードしたい** 場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式の PEASS & HackTricks スワッグ**](https://peass.creator-spring.com) を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* **💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) をフォローする。
* **HackTricks** と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の github リポジトリに PR を提出して、あなたのハッキングテクニックを共有してください。

</details>
