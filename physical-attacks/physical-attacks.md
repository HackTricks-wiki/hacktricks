# 物理攻撃

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>

## BIOSパスワード

### バッテリー

ほとんどの**マザーボード**には**バッテリー**があります。バッテリーを**30分間取り外す**と、BIOSの設定が**リセット**されます（パスワードも含まれます）。

### CMOSジャンパー

ほとんどの**マザーボード**には、設定をリセットできる**ジャンパー**があります。このジャンパーは、中央のピンと別のピンを接続します。これらのピンを接続すると、マザーボードがリセットされます。

### ライブツール

たとえば、Live CD/USBから**Kali** Linuxを実行できる場合、_**killCmos**_や_**CmosPWD**_（これはKaliに含まれています）などのツールを使用して、BIOSのパスワードを**回復**することができます。

### オンラインBIOSパスワードの回復

BIOSのパスワードを**3回間違える**と、BIOSは**エラーメッセージを表示**してブロックされます。\
[https://bios-pw.org](https://bios-pw.org)にアクセスし、BIOSに表示される**エラーコード**を入力すると、**有効なパスワード**（同じ検索でも異なるパスワードが表示される場合があり、複数のパスワードが有効になる場合があります）を取得できるかもしれません。

## UEFI

UEFIの設定を確認し、攻撃を行うためには、[chipsec](https://github.com/chipsec/chipsec/blob/master/chipsec-manual.pdf)を試してみる必要があります。\
このツールを使用すると、簡単にSecure Bootを無効にすることができます：
```
python chipsec_main.py -module exploits.secure.boot.pk
```
## RAM

### コールドブート

**RAMメモリは、コンピュータの電源が切れてから1〜2分間は持続的**です。もしメモリカードに**コールド**（例えば液体窒素）を適用すると、この時間を**最大10分間**まで延長することができます。

その後、**dd.exe、mdd.exe、Memoryze、win32dd.exe、DumpIt**などのツールを使用して、**メモリダンプ**を行い、メモリを分析することができます。

メモリを**volatility**を使用して分析する必要があります。

### [INCEPTION](https://github.com/carmaa/inception)

Inceptionは、PCIベースのDMAを利用した**物理的なメモリ操作**およびハッキングツールです。このツールは、**FireWire**、**Thunderbolt**、**ExpressCard**、PCカード、およびその他のPCI/PCIe HWインターフェースを介して攻撃することができます。\
自分のコンピュータを被害者のコンピュータにこれらの**インターフェース**のいずれかで接続し、**INCEPTION**が**物理メモリ**を**パッチ**して**アクセス**を提供しようとします。

**INCEPTIONが成功すると、入力されたパスワードは有効になります。**

**Windows10では動作しません。**

## Live CD/USB

### Sticky Keys およびその他

* **SETHC:** SHIFTキーが5回押されたときに_sethc.exe_が呼び出されます。
* **UTILMAN:** WINDOWS+Uを押すと_Utilman.exe_が呼び出されます。
* **OSK:** WINDOWS+Uを押し、その後オンスクリーンキーボードを起動すると_osk.exe_が呼び出されます。
* **DISP:** WINDOWS+Pを押すと_DisplaySwitch.exe_が呼び出されます。

これらのバイナリは_**C:\Windows\System32**_内にあります。これらのバイナリのいずれかを、同じフォルダにある**cmd.exe**のコピーに**変更**することができ、これらのバイナリを呼び出すたびに、**SYSTEM**としてのコマンドプロンプトが表示されます。

### SAMの変更

ツール_**chntpw**_を使用して、マウントされたWindowsファイルシステムの_**SAM**_ファイルを**変更**することができます。その後、例えばAdministratorユーザーのパスワードを変更することができます。\
このツールはKALIで利用可能です。
```
chntpw -h
chntpw -l <path_to_SAM>
```
**Linuxシステム内では、** _**/etc/shadow**_ **または** _**/etc/passwd**_ **ファイルを変更することができます。**

### **Kon-Boot**

**Kon-Boot**は、パスワードを知らずにWindowsにログインできる最高のツールの一つです。**システムBIOSにフックし、Windowsカーネルの内容を一時的に変更**することで動作します（新しいバージョンでは**UEFI**でも動作します）。その後、ログイン時に**任意のパスワードを入力**することができます。Kon-Bootなしでコンピュータを再起動すると、元のパスワードが復元され、一時的な変更は破棄され、システムは何も起こったかのように動作します。\
詳細はこちらを参照してください：[https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/)

これはライブCD/USBであり、メモリを**パッチ**することができるため、**ログインするためにパスワードを知る必要はありません**。\
Kon-Bootはまた、**StickyKeys**のトリックを実行するため、_**Shift**_ **を5回押すと管理者のコマンドプロンプトが表示されます**。

## **Windowsの実行**

### 初期のショートカット

### ブートのショートカット

* supr - BIOS
* f8 - リカバリーモード
* _supr_ - BIOS ini
* _f8_ - リカバリーモード
* _Shitf_（Windowsバナーの後） - 自動ログオンではなくログインページに移動する（自動ログオンを回避）

### **BAD USB**

#### **Rubber Duckyのチュートリアル**

* [チュートリアル1](https://github.com/hak5darren/USB-Rubber-Ducky/wiki/Tutorials)
* [チュートリアル2](https://blog.hartleybrody.com/rubber-ducky-guide/)

#### **Teensyduino**

* [ペイロードとチュートリアル](https://github.com/Screetsec/Pateensy)

**自分自身のBAD USBを作成する方法**についてのチュートリアルもたくさんあります。

### ボリュームシャドウコピー

管理者特権とPowerShellを使用して、SAMファイルのコピーを作成することができます。[このコードを参照してください](../windows-hardening/basic-powershell-for-pentesters/#volume-shadow-copy)。

## Bitlockerのバイパス

Bitlockerは**2つのパスワード**を使用します。ユーザーが使用するパスワードと**リカバリ**パスワード（48桁）です。

もし現在のWindowsセッション内に _**C:\Windows\MEMORY.DMP**_（メモリダンプ）というファイルが存在する場合、その中から**リカバリパスワードを検索**することができます。このファイルとファイルシステムの**コピーを取得**し、それから_Elcomsoft Forensic Disk Decryptor_を使用して内容を取得することができます（これはパスワードがメモリダンプ内に含まれている場合にのみ機能します）。また、_Sysinternals_の_NotMyFault_を使用してメモリダンプを**強制的に実行**することもできますが、これによりシステムが再起動され、管理者として実行する必要があります。

_Passware Kit Forensic_を使用して**ブルートフォース攻撃**を試すこともできます。

### ソーシャルエンジニアリング

最後に、ユーザーに管理者として実行させるように依頼し、新しいリカバリパスワードを追加させることもできます。
```bash
schtasks /create /SC ONLOGON /tr "c:/windows/system32/manage-bde.exe -protectors -add c: -rp 000000-000000-000000-000000-000000-000000-000000-000000" /tn tarea /RU SYSTEM /f
```
次回のログイン時に、新しいリカバリーキー（48個のゼロで構成される）が追加されます。

有効なリカバリーキーを確認するには、次のコマンドを実行します。
```
manage-bde -protectors -get c:
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
