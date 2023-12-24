# 物理的攻撃

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？**HackTricksで会社の広告を掲載**したいですか？または、**PEASSの最新バージョンにアクセス**したり、**HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください。

- [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加する**か、**Twitter**で私を**フォロー**してください [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのコツを共有するために、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>

## BIOSパスワード

### バッテリー

ほとんどの**マザーボード**には**バッテリー**があります。**30分間取り外す**と、BIOSの設定が**リセット**されます（パスワードも含む）。

### ジャンパーCMOS

ほとんどの**マザーボード**には、設定をリセットできる**ジャンパー**があります。このジャンパーは中央のピンと別のピンを接続します。**これらのピンを接続すると、マザーボードがリセットされます**。

### ライブツール

例えば**Kali** LinuxをLive CD/USBから**実行**できる場合、_**killCmos**_ や _**CmosPWD**_（この最後のものはKaliに含まれています）のようなツールを使用して、**BIOSのパスワードを回復**しようとすることができます。

### オンラインBIOSパスワード回復

BIOSのパスワードを**3回間違える**と、BIOSは**エラーメッセージを表示**し、ブロックされます。\
[https://bios-pw.org](https://bios-pw.org)のページを訪れて、BIOSによって表示された**エラーコードを入力**すると、運が良ければ**有効なパスワード**を得ることができます（**同じ検索で異なるパスワードが表示され、複数のパスワードが有効である可能性があります**）。

## UEFI

UEFIの設定を確認し、何らかの攻撃を試みるには、[chipsec](https://github.com/chipsec/chipsec/blob/master/chipsec-manual.pdf)を使用してみてください。\
このツールを使用すると、Secure Bootを簡単に無効にすることができます：
```
python chipsec_main.py -module exploits.secure.boot.pk
```
## RAM

### コールドブート

**RAMメモリはコンピュータの電源が切れてから1〜2分間データを保持します**。メモリカードに**冷却剤**（例えば液体窒素）を適用すると、この時間を**最大10分間**まで延長できます。

その後、メモリダンプ（dd.exe、mdd.exe、Memoryze、win32dd.exe、DumpItなどのツールを使用）を行い、メモリを分析できます。

メモリは**volatilityを使用して分析**するべきです。

### [INCEPTION](https://github.com/carmaa/inception)

InceptionはPCIベースのDMAを悪用する**物理メモリ操作**とハッキングツールです。このツールは**FireWire**、**Thunderbolt**、**ExpressCard**、PC Card、その他のPCI/PCIe HWインターフェースを介して攻撃が可能です。\
被害者のコンピュータにこれらの**インターフェース**のいずれかを介してコンピュータを**接続**し、**INCEPTION**は**物理メモリ**を**パッチ**して**アクセス**を得ようとします。

**INCEPTIONが成功すると、どんなパスワードも有効になります。**

**Windows10では機能しません。**

## ライブCD/USB

### スティッキーキーなど

* **SETHC:** _sethc.exe_ はSHIFTキーを5回押すと呼び出されます
* **UTILMAN:** _Utilman.exe_ はWINDOWS+Uを押すと呼び出されます
* **OSK:** _osk.exe_ はWINDOWS+Uを押した後、オンスクリーンキーボードを起動すると呼び出されます
* **DISP:** _DisplaySwitch.exe_ はWINDOWS+Pを押すと呼び出されます

これらのバイナリは _**C:\Windows\System32**_ 内にあります。これらのいずれかを**cmd.exe**の**コピー**（同じフォルダ内にもあります）に**変更**すると、これらのバイナリを呼び出すたびに**SYSTEM**としてのコマンドプロンプトが表示されます。

### SAMの変更

マウントされたWindowsファイルシステムの _**SAM**_ **ファイル**を**変更**するために、_**chntpw**_ ツールを使用できます。例えば、Administratorユーザーのパスワードを変更することができます。\
このツールはKALIで利用可能です。
```
chntpw -h
chntpw -l <path_to_SAM>
```
**Linuxシステム内では、** _**/etc/shadow**_ **または** _**/etc/passwd**_ **ファイルを変更することができます。**

### **Kon-Boot**

**Kon-Boot** は、パスワードを知らなくてもWindowsにログインできる最高のツールの一つです。これは、**システムのBIOSにフックして、起動時にWindowsカーネルの内容を一時的に変更する** ことで機能します（新しいバージョンは **UEFI** にも対応しています）。ログイン時に **任意のパスワードを入力することを許可します**。Kon-Bootなしで次回コンピュータを起動すると、元のパスワードが戻り、一時的な変更は破棄され、何も起こらなかったかのようにシステムは振る舞います。\
詳細はこちら: [https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/)

これはライブCD/USBであり、**メモリをパッチする** ことで、ログインするためにパスワードを知る必要が **ありません**。\
Kon-Bootは **StickyKeys** のトリックも実行し、_**Shift**_ **を5回押すと管理者のcmdが得られます**。

## **Windowsの実行**

### 初期のショートカット

### 起動のショートカット

* supr - BIOS
* f8 - リカバリーモード
* _supr_ - BIOS ini
* _f8_ - リカバリーモード
* _Shift_ (Windowsのバナーの後) - 自動ログオンの代わりにログインページに移動する（自動ログオンを避ける）

### **BAD USBs**

#### **Rubber Ducky チュートリアル**

* [チュートリアル1](https://github.com/hak5darren/USB-Rubber-Ducky/wiki/Tutorials)
* [チュートリアル2](https://blog.hartleybrody.com/rubber-ducky-guide/)

#### **Teensyduino**

* [ペイロードとチュートリアル](https://github.com/Screetsec/Pateensy)

また、**自分自身のbad USBを作成する方法**についてのチュートリアルもたくさんあります。

### ボリュームシャドウコピー

管理者権限とpowershellを使って、SAMファイルのコピーを作成できます。[このコードを見る](../windows-hardening/basic-powershell-for-pentesters/#volume-shadow-copy)。

## Bitlockerのバイパス

Bitlockerは **2つのパスワード** を使用します。**ユーザー** が使用するものと、**リカバリー** パスワード（48桁）です。

運が良ければ、現在のWindowsセッション内に _**C:\Windows\MEMORY.DMP**_ ファイル（メモリダンプ）が存在する場合、**リカバリーパスワードを検索する** ことができます。このファイルとファイルシステムのコピーを **取得し**、_Elcomsoft Forensic Disk Decryptor_ を使用して内容を取得できます（パスワードがメモリダンプ内にある場合にのみ機能します）。また、_Sysinternals_ の _**NotMyFault**_ を使用して **メモリダンプを強制的に行う** こともできますが、これはシステムを再起動させ、管理者として実行する必要があります。

**ブルートフォース攻撃** を試みることもできます。これには _**Passware Kit Forensic**_ を使用します。

### ソーシャルエンジニアリング

最後に、ユーザーに新しいリカバリーパスワードを追加させ、管理者として実行させることができます。
```bash
schtasks /create /SC ONLOGON /tr "c:/windows/system32/manage-bde.exe -protectors -add c: -rp 000000-000000-000000-000000-000000-000000-000000-000000" /tn tarea /RU SYSTEM /f
```
```
次のログインで新しいリカバリーキー（48個のゼロで構成）が追加されます。

有効なリカバリーキーを確認するには、次のコマンドを実行します：
```
```
manage-bde -protectors -get c:
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？**HackTricksで会社の広告を掲載**したいですか？または、**最新版のPEASSを入手**したり、**HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションです。

- [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- **[**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか、**Twitter**で私を**フォロー**してください [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。**

</details>
