# 物理攻撃

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を通じて、ゼロからヒーローまでAWSハッキングを学びましょう！</summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **Discordグループ**に参加する💬（https://discord.gg/hRep4RUj7f）または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**🐦で私たちをフォローする[**@carlospolopm**](https://twitter.com/hacktricks_live)。
- **HackTricks**（https://github.com/carlospolop/hacktricks）と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を活用した検索エンジンで、企業やその顧客が**盗難マルウェア**によって**侵害**されていないかをチェックする**無料**の機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃と戦うことです。

彼らのウェブサイトをチェックし、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

---

## BIOSパスワードの回復とシステムセキュリティ

**BIOSのリセット**はいくつかの方法で達成できます。ほとんどのマザーボードには、約**30分間**取り外すとBIOS設定（パスワードを含む）がリセットされる**バッテリー**が含まれています。また、マザーボード上の**ジャンパー**を調整して特定のピンを接続することで、これらの設定をリセットすることもできます。

ハードウェアの調整が不可能または実用的でない場合、**ソフトウェアツール**が解決策を提供します。**Kali Linux**などのディストリビューションを使用して**Live CD/USB**からシステムを実行すると、**_killCmos_**や**_CmosPWD_**などのツールにアクセスでき、BIOSパスワードの回復に役立ちます。

BIOSパスワードが不明な場合、それを**3回間違えて**入力すると通常、エラーコードが表示されます。このコードは、[https://bios-pw.org](https://bios-pw.org)のようなウェブサイトで使用して、使用可能なパスワードを取得する可能性があります。

### UEFIセキュリティ

従来のBIOSの代わりに**UEFI**を使用している現代のシステムでは、**chipsec**ツールを使用して、**Secure Boot**の無効化を含むUEFI設定の分析と変更が可能です。次のコマンドを使用してこれを実行できます：

`python chipsec_main.py -module exploits.secure.boot.pk`

### RAM分析とCold Boot攻撃

RAMは、通常**1〜2分**の間、電源が切断された後もデータを一時的に保持します。この持続性は、液体窒素などの冷却物質を適用することで**10分間**延長することができます。この拡張された期間中、**dd.exe**や**volatility**などのツールを使用して**メモリダンプ**を作成し、分析することができます。

### 直接メモリアクセス（DMA）攻撃

**INCEPTION**は、**FireWire**や**Thunderbolt**などのインターフェースと互換性があり、DMAを介した**物理メモリ操作**のためのツールです。これにより、メモリをパッチして任意のパスワードを受け入れることで、ログイン手順をバイパスすることができます。ただし、**Windows 10**システムに対しては効果がありません。

### システムアクセスのためのLive CD/USB

**_sethc.exe_**や**_Utilman.exe_**などのシステムバイナリを**_cmd.exe_**のコピーで変更することで、システム特権を持つコマンドプロンプトを提供できます。**chntpw**などのツールを使用して、Windowsインストールの**SAM**ファイルを編集してパスワードを変更できます。

**Kon-Boot**は、Windowsシステムにログインするのを容易にするツールで、WindowsカーネルやUEFIを一時的に変更することでパスワードを知らずにログインできます。詳細は[https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/)で確認できます。

### Windowsセキュリティ機能の取り扱い

#### ブートおよびリカバリのショートカット

- **Supr**: BIOS設定にアクセスします。
- **F8**: リカバリモードに入ります。
- Windowsバナーの後に**Shift**キーを押すと、自動ログオンをバイパスできます。

#### BAD USBデバイス

**Rubber Ducky**や**Teensyduino**などのデバイスは、悪意のあるUSBデバイスを作成するプラットフォームとして機能し、ターゲットコンピュータに接続されると事前定義されたペイロードを実行できます。

#### ボリュームシャドウコピー

管理者権限を使用すると、PowerShellを介して**SAM**ファイルなどの機密ファイルのコピーを作成できます。

### BitLocker暗号のバイパス

BitLocker暗号は、メモリダンプファイル（**MEMORY.DMP**）内で**回復パスワード**が見つかればバイパスできる可能性があります。この目的のために**Elcomsoft Forensic Disk Decryptor**や**Passware Kit Forensic**などのツールを利用できます。

### リカバリキーの追加のためのソーシャルエンジニアリング

ソーシャルエンジニアリングの戦術を使用して、ユーザーに新しいBitLockerリカバリキーを追加するよう説得し、ゼロから構成された新しいリカバリキーを追加するコマンドを実行させることで、復号化プロセスを簡素化できます。
