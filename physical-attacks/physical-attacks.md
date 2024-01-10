# 物理的攻撃

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)や[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングテクニックを共有する。

</details>

## BIOSパスワード

### バッテリー

ほとんどの**マザーボード**には**バッテリー**があります。これを**30分間取り外す**と、BIOSの設定が**リセット**されます（パスワードも含む）。

### ジャンパーCMOS

ほとんどの**マザーボード**には、設定をリセットできる**ジャンパー**があります。このジャンパーは中央のピンと別のピンを接続します。**これらのピンを接続するとマザーボードがリセットされます**。

### ライブツール

例えば**Kali** LinuxをLive CD/USBから**実行**できる場合、_**killCmos**_ や _**CmosPWD**_（この最後のツールはKaliに含まれています）のようなツールを使用して、BIOSのパスワードを**回復**することができます。

### オンラインBIOSパスワード回復

BIOSのパスワードを**3回間違えて入力する**と、BIOSは**エラーメッセージを表示**し、ロックされます。\
[https://bios-pw.org](https://bios-pw.org) のページを訪れて、BIOSに表示されたエラーコードを**入力する**と、運が良ければ**有効なパスワード**を得ることができます（**同じ検索で異なるパスワードが表示され、複数のパスワードが有効である可能性があります**）。

## UEFI

UEFIの設定を確認し、何らかの攻撃を行うには、[chipsec](https://github.com/chipsec/chipsec/blob/master/chipsec-manual.pdf)を試してみるべきです。\
このツールを使用すると、Secure Bootを簡単に無効にすることができます：
```
python chipsec_main.py -module exploits.secure.boot.pk
```
## RAM

### コールドブート

**RAMメモリはコンピュータの電源が切れてから1〜2分間データが保持されます**。メモリカードに**冷却剤**（例えば液体窒素）を適用すると、この時間を**最大10分間**まで延長できます。

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

**Kon-Boot** は、パスワードを知らなくてもWindowsにログインできる最高のツールの一つです。これは、**システムBIOSにフックして、起動時にWindowsカーネルの内容を一時的に変更する**ことで機能します（新しいバージョンは**UEFI**にも対応しています）。ログイン時に**任意のパスワードを入力することを許可します**。Kon-Bootなしで次回コンピュータを起動すると、元のパスワードが戻り、一時的な変更は破棄され、何も起こらなかったかのようにシステムは振る舞います。\
詳細はこちら: [https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/)

これはライブCD/USBであり、**メモリをパッチする**ことで、**パスワードを知らなくてもログインできる**ようになります。\
Kon-Bootは**StickyKeys**のトリックも実行し、_**Shift**_ **を5回押すと管理者のcmdが得られます**。

## **Windowsの実行**

### 初期のショートカット

### 起動のショートカット

* supr - BIOS
* f8 - リカバリーモード
* _supr_ - BIOS ini
* _f8_ - リカバリーモード
* _Shift_ (Windowsバナーの後) - 自動ログオンの代わりにログインページに移動（自動ログオンを避ける）

### **BAD USBs**

#### **Rubber Ducky チュートリアル**

* [チュートリアル1](https://github.com/hak5darren/USB-Rubber-Ducky/wiki/Tutorials)
* [チュートリアル2](https://blog.hartleybrody.com/rubber-ducky-guide/)

#### **Teensyduino**

* [ペイロードとチュートリアル](https://github.com/Screetsec/Pateensy)

**自分のBAD USBを作成する方法**についてのチュートリアルもたくさんあります。

### ボリュームシャドウコピー

管理者権限とpowershellを使って、SAMファイルのコピーを作成できます。[このコードを見る](../windows-hardening/basic-powershell-for-pentesters/#volume-shadow-copy)。

## Bitlockerのバイパス

Bitlockerは**2つのパスワード**を使用します。**ユーザー**が使用するものと、**リカバリー**パスワード（48桁）です。

運が良ければ、現在のWindowsセッション内に _**C:\Windows\MEMORY.DMP**_ ファイル（メモリダンプ）が存在する場合、**リカバリーパスワードを検索する**ことができます。このファイルと**ファイルシステムのコピー**を**取得し**、_Elcomsoft Forensic Disk Decryptor_ を使用して内容を取得できます（パスワードがメモリダンプ内にある場合のみ機能します）。また、_Sysinternals_ の _**NotMyFault**_ を使用して**メモリダンプを強制的に行う**こともできますが、これはシステムを再起動させ、管理者として実行する必要があります。

**ブルートフォース攻撃**を試みることもできます。その場合は _**Passware Kit Forensic**_ を使用します。

### ソーシャルエンジニアリング

最後に、ユーザーに新しいリカバリーパスワードを追加させることで、管理者として実行させることができます。
```bash
schtasks /create /SC ONLOGON /tr "c:/windows/system32/manage-bde.exe -protectors -add c: -rp 000000-000000-000000-000000-000000-000000-000000-000000" /tn tarea /RU SYSTEM /f
```
```
これにより、次回のログイン時に新しいリカバリーキー（48個のゼロで構成）が追加されます。

有効なリカバリーキーを確認するには、以下を実行します：
```
```
manage-bde -protectors -get c:
```
<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい場合**、または**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
