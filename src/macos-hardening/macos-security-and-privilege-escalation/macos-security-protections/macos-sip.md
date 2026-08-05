# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **基本情報**

macOSの**System Integrity Protection (SIP)**は、最も高い権限を持つユーザーであっても、主要なシステムフォルダに対して許可されていない変更を加えることを防ぐためのmechanismです。この機能は、保護された領域でのファイルの追加、変更、削除などの操作を制限することで、システムのintegrityを維持するうえで重要な役割を果たします。SIPによって保護される主なフォルダは次のとおりです。

- **/System**
- **/bin**
- **/sbin**
- **/usr**

SIPの動作を制御するルールは、**`/System/Library/Sandbox/rootless.conf`**にあるconfiguration fileで定義されています。このファイル内では、アスタリスク（\*）が先頭に付いているパスは、厳格なSIPの制限に対する例外として示されています。

以下の例を見てみましょう。
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
このスニペットは、SIP が通常 **`/usr`** ディレクトリを保護している一方で、パスの前に付いたアスタリスク（*）が示す特定のサブディレクトリ（`/usr/libexec/cups`、`/usr/local`、`/usr/share/man`）では変更が許可されていることを示しています。

ディレクトリまたはファイルが SIP によって保護されているか確認するには、**`ls -lOd`** コマンドを使用して、**`restricted`** または **`sunlnk`** フラグの有無を確認できます。例:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
この場合、**`sunlnk`**フラグは、`/usr/libexec/cups`ディレクトリ自体は**削除できない**ものの、その中のファイルは作成、変更、削除できることを示します。

一方で:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
ここで、**`restricted`** フラグは、`/usr/libexec` ディレクトリが SIP によって保護されていることを示します。SIP によって保護されたディレクトリでは、ファイルの作成、変更、削除はできません。

さらに、ファイルに **`com.apple.rootless`** 拡張 **属性** が含まれている場合、そのファイルも **SIP によって保護** されます。

> [!TIP]
> **Sandbox** の hook **`hook_vnode_check_setextattr`** は、拡張属性 **`com.apple.rootless`** を変更しようとするすべての試みを防止します。

**SIP は、その他の root 操作も制限します**。

- 信頼されていない kernel extensions のロード
- Apple が署名したプロセスの task-ports の取得
- NVRAM 変数の変更
- kernel debugging の許可

オプションは、bitflag として nvram 変数（Intel では `csr-active-config`、ARM では booted Device Tree から読み取られる `lp-sip0`）に保持されます。フラグは、XNU のソースコード内の `csr.sh` で確認できます。

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### SIP の状態

次のコマンドを使用して、システムで SIP が有効になっているか確認できます。
```bash
csrutil status
```
SIPを無効化する必要がある場合は、コンピュータをリカバリーモードで再起動し（起動中にCommand+Rを押します）、次のコマンドを実行します:
```bash
csrutil disable
```
SIPを有効にしたままデバッグ保護を解除したい場合は、次のようにします：
```bash
csrutil enable --without debug
```
### その他の制限

- **署名されていない kernel extensions**（kexts）のロードを禁止し、検証済みの extensions のみがシステム kernel とやり取りできるようにする。
- **macOS system processes の debugging**を防止し、core system components を不正なアクセスや変更から保護する。
- dtrace などの **tools** が system processes を検査することを阻止し、システムの動作の完全性をさらに保護する。

[**Learn more about SIP info in this talk**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**<sup>[1]</sup>

### **SIP related Entitlements**

- `com.apple.rootless.xpc.bootstrap`: launchd を制御
- `com.apple.rootless.install[.heritable]`: file system へのアクセス
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: UF_DATAVAULT を管理
- `com.apple.rootless.xpc.bootstrap`: XPC setup capabilities
- `com.apple.rootless.xpc.effective-root`: launchd XPC 経由で Root
- `com.apple.rootless.restricted-block-devices`: raw block devices へのアクセス
- `com.apple.rootless.internal.installer-equivalent`: 制限のない filesystem access
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: NVRAM への完全なアクセス
- `com.apple.rootless.storage.label`: 対応する label を持つ com.apple.rootless xattr によって制限された files を変更
- `com.apple.rootless.volume.VM.label`: volume 上の VM swap を維持

## SIP Bypasses

SIP を bypass すると、attacker は以下を実行できるようになる。

- **User Data へのアクセス**: すべての user accounts から、mail、messages、Safari history などの機密性の高い user data を読み取る。
- **TCC Bypass**: TCC（Transparency, Consent, and Control）database を直接操作し、webcam、microphone、その他の resources への不正なアクセスを許可する。
- **Persistence の確立**: malware を SIP-protected locations に配置し、root privileges であっても削除されにくくする。これには Malware Removal Tool（MRT）を tamper する可能性も含まれる。
- **Kernel Extensions のロード**: 追加の safeguards は存在するものの、SIP を bypass すると unsigned kernel extensions のロードが容易になる。

### Installer Packages

**Apple の certificate で署名された Installer packages** は、その protections を bypass できる。つまり、standard developers によって署名された packages であっても、SIP-protected directories を変更しようとすると block される。

### Inexistent SIP file

考えられる loophole の 1 つは、**`rootless.conf` に指定されている file が現在存在しない場合**、その file を作成できることである。malware はこれを悪用してシステム上に **persistence を確立**できる。例えば、malicious program は、`rootless.conf` に記載されているものの存在していない場合、`/System/Library/LaunchDaemons` に .plist file を作成できる。

### com.apple.rootless.install.heritable

> [!CAUTION]
> entitlement **`com.apple.rootless.install.heritable`** は SIP を bypass することを許可する

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

system が code **signature** を検証した後に Installer package を **swap** でき、その結果、system が original の代わりに malicious package を install できることが発見された。これらの actions は **`system_installd`** によって実行されるため、SIP を bypass できた。<sup>[2]</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

package が mounted image または external drive から install された場合、**installer** は binary を SIP protected location ではなく **その file system から execute** し、**`system_installd`** に arbitrary binary を execute させることができた。<sup>[3]</sup>

#### CVE-2021-30892 - Shrootless

[**Researchers from this blog post**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) は、macOS の System Integrity Protection（SIP）mechanism における vulnerability を発見し、これを「Shrootless」vulnerability と名付けた。この vulnerability は **`system_installd`** daemon を中心とするもので、この daemon には **`com.apple.rootless.install.heritable`** entitlement があり、そのすべての child processes が SIP の file system restrictions を bypass できる。<sup>[4]</sup>

**`system_installd`** daemon は、**Apple** によって署名された packages を install する。

Researchers は、Apple-signed package（.pkg file）の installation 中に、**`system_installd`** が package に含まれる任意の **post-install** scripts を **run** することを発見した。これらの scripts は default shell である **`zsh`** によって execute される。`zsh` は non-interactive mode であっても、`/etc/zshenv` file が存在する場合、その file の commands を自動的に **run** する。この behaviour は attackers によって exploit 可能であり、malicious な `/etc/zshenv` file を作成して **`system_installd` が `zsh` を invoke するのを待つ**ことで、device 上で arbitrary operations を実行できる。<sup>[4]</sup>

さらに、**`/etc/zshenv` は SIP bypass だけでなく、general attack technique としても利用できる**ことが発見された。各 user profile には `~/.zshenv` file があり、これは `/etc/zshenv` と同じように動作するが、root permissions を必要としない。この file は persistence mechanism として使用でき、`zsh` が start するたびに trigger される。または privilege elevation mechanism としても使用できる。admin user が `sudo -s` または `sudo <command>` を使用して root に elevate すると、`~/.zshenv` file が trigger され、結果として root に elevate される。<sup>[4]</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

[**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) では、同じ **`system_installd`** process が依然として abuse 可能であることが発見された。これは、**post-install script を `/tmp` 内の SIP によって保護された random named folder に配置していた**ためである。問題は、**`/tmp` 自体は SIP によって保護されていない**ことであり、そこに **virtual image を mount** できた。その後、**installer** はそこに **post-install script を配置**し、virtual image を **unmount** して、すべての **folders を recreate** し、execute する **payload** を含む **post-installation** script を **add** できた。<sup>[5]</sup>

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

`fsck_cs` が **symbolic links** を follow できることにより、重要な file を corrupt させるよう誘導される vulnerability が発見された。具体的には、attackers が _`/dev/diskX`_ から `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist` への link を作成した。_`/dev/diskX`_ 上で **`fsck_cs`** を実行すると、`Info.plist` が corrupt された。この file の integrity は、kernel extensions の loading を制御する operating system の SIP（System Integrity Protection）にとって重要である。corrupt されると、kernel exclusions を管理する SIP の ability が compromise される。<sup>[6]</sup>

この vulnerability を exploit する commands は次のとおりである。
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
この脆弱性の悪用は、深刻な影響を及ぼします。通常、kernel extensions の権限管理を担う `Info.plist` ファイルが機能しなくなります。これには、`AppleHWAccess.kext` など特定の extension を blacklist に登録できなくなることも含まれます。その結果、SIP の制御メカニズムが機能しなくなり、この extension をロードできるようになるため、システムの RAM への不正な読み取りおよび書き込みアクセスが許可されます。<sup>[6]</sup>

#### [SIP で保護されたフォルダーへの mount](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

**SIP で保護されたフォルダー上に新しい file system を mount して、保護を bypass することが可能でした**。<sup>[1]</sup>
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

システムは、`bless` utilityを利用してOSをアップグレードするため、`Install macOS Sierra.app`内に組み込まれたインストーラーディスクイメージから起動するよう設定されています。使用されるコマンドは以下のとおりです。<sup>[7]</sup>
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
このプロセスの security は、boot 前に attacker が upgrade image（`InstallESD.dmg`）を改変すると compromise される可能性があります。この strategy では、dynamic loader（dyld）を malicious version（`libBaseIA.dylib`）に置き換えます。この置き換えにより、installer の開始時に attacker の code が実行されます。<sup>[7]</sup>

attacker の code は、installer に対する system の trust を悪用し、upgrade process 中に control を取得します。この attack では、method swizzling によって `InstallESD.dmg` image を改変し、特に `extractBootBits` method を標的にします。これにより、disk image が使用される前に malicious code を injection できます。<sup>[7]</sup>

さらに、`InstallESD.dmg` 内には `BaseSystem.dmg` があり、upgrade code の root file system として機能します。ここに dynamic library を injection すると、OS-level files を改変できる process 内で malicious code を動作させることができ、system compromise の可能性が大幅に高まります。<sup>[7]</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

[**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) のこの talk では、**`systemmigrationd`**（SIP を bypass 可能）が **bash** および **perl** script を実行することが示されています。これらは、env variables **`BASH_ENV`** および **`PERL5OPT`** を介して abuse できます。<sup>[8]</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

[**この blog post で詳しく説明されているように**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)、`InstallAssistant.pkg` packages の `postinstall` script は、以下を実行できました。<sup>[9]</sup>
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
そして、`${SHARED_SUPPORT_PATH}/SharedSupport.dmg` に symlink を作成することで、ユーザーが **任意のファイルの制限を解除し、SIP protection を bypass できる** 可能性がありました。<sup>[9]</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> entitlement **`com.apple.rootless.install`** により SIP を bypass できます

entitlement `com.apple.rootless.install` は、macOS の System Integrity Protection (SIP) を bypass することが知られています。これは特に [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) との関連で言及されました。<sup>[10]</sup>

このケースでは、`/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` にある system XPC service がこの entitlement を保有しています。これにより、関連する process は SIP の制約を回避できます。さらに、この service には security measures を適用せずにファイルを移動できる method があります。<sup>[10]</sup>

## Sealed System Snapshots

Sealed System Snapshots は、追加の security と system stability を提供するため、**macOS Big Sur (macOS 11)** で Apple が **System Integrity Protection (SIP)** の一部として導入した feature です。これは基本的に system volume の read-only version です。

詳細は以下のとおりです。

1. **Immutable System**: Sealed System Snapshots により macOS system volume は「immutable」になります。つまり、変更できません。これにより、security や system stability を損なう可能性のある、意図しない system の変更や accidental changes を防止できます。
2. **System Software Updates**: macOS update または upgrade を install すると、macOS は新しい system snapshot を作成します。その後、macOS startup volume は **APFS (Apple File System)** を使用して、この新しい snapshot に切り替えます。update 中に問題が発生しても system は常に以前の snapshot に戻せるため、update を適用するプロセス全体がより安全で信頼性の高いものになります。
3. **Data Separation**: macOS Catalina で導入された Data と System volume の分離という概念と併せて、Sealed System Snapshot feature はすべての data と settings が別の "**Data**" volume に保存されることを保証します。この分離により、data が system から独立するため、system update のプロセスが簡素化され、system security が向上します。

これらの snapshot は macOS によって自動的に管理され、APFS の space sharing capabilities により disk 上の追加 space を消費しません。また、これらの snapshot は system 全体の user-accessible な backup である **Time Machine snapshots** とは異なる点にも注意してください。

### Check Snapshots

command **`diskutil apfs list`** は、**APFS volumes の詳細**とその layout を一覧表示します。

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-< Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
|   Encrypted:                 No
</code></pre>

前の output では、**user-accessible locations** が `/System/Volumes/Data` 配下に mount されていることを確認できます。

さらに、**macOS System volume snapshot** は `/` に mount されており、**sealed** されています（OS によって cryptographically signed されています）。したがって、SIP が bypass されてこれが変更されると、**OS は boot しなくなります**。

次の command を実行して、**seal が enabled であることを verify** することもできます。
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
さらに、snapshot diskも**読み取り専用**としてマウントされています:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
## 参考文献

- [1] [SyScan360 - Stefan Esser - OS X El Capitan が S\H/IP を沈める](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)
- [2] [CVE-2019-8561 - Objective-See ブログ](https://objective-see.org/blog/blog_0x42.html)
- [3] [CVE-2020–9854: 「Unauthd」（3つ）の logic bugs ftw! - Objective-See ブログ](https://objective-see.org/blog/blog_0x4D.html)
- [4] [Microsoft、System Integrity Protection を bypass できる新たな macOS vulnerability「Shrootless」を発見](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Technical Analysis: CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [ツイートに収まるコードによって Apple の fruitless rootless security が破られる - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] Apple の System Integrity Protection を bypass - Objective-See ブログ](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Getting a Migraine - MacOS の Unique SIP Bypass - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [Apple、Installer Scripts の vulnerabilities を mitigate - Kandji ブログ](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712: SIP-Bypass の POC はさらにツイート可能](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)

{{#include ../../../banners/hacktricks-training.md}}
