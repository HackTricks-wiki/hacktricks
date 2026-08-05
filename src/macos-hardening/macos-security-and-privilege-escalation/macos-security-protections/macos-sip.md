# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **基本情報**

macOS の **System Integrity Protection (SIP)** は、最も高い権限を持つユーザーであっても、重要なシステムフォルダーに対して未承認の変更を行えないようにするための mechanism です。この機能は、保護された領域内のファイルの追加、変更、削除などの操作を制限することで、システムの integrity を維持する上で重要な役割を果たします。SIP によって保護される主なフォルダーは次のとおりです。

- **/System**
- **/bin**
- **/sbin**
- **/usr**

SIP の動作を規定するルールは、**`/System/Library/Sandbox/rootless.conf`** にある設定ファイルで定義されています。このファイル内で、アスタリスク (\*) が前に付いているパスは、それ以外の厳格な SIP 制限に対する例外として示されています。

以下の例を見てください。
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
このスニペットは、SIP が通常 **`/usr`** ディレクトリを保護する一方で、パスの前にアスタリスク（\*）が付いている特定のサブディレクトリ（`/usr/libexec/cups`、`/usr/local`、`/usr/share/man`）では変更が許可されることを示しています。

ディレクトリまたはファイルが SIP によって保護されているか確認するには、**`ls -lOd`** コマンドを使用して、**`restricted`** または **`sunlnk`** フラグの有無を確認できます。例:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
この場合、**`sunlnk`** フラグは、`/usr/libexec/cups` ディレクトリ自体は**削除できない**ものの、その内部のファイルは作成、変更、削除できることを意味します。

一方で:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
ここで、**`restricted`** flag は、`/usr/libexec` directory が SIP によって保護されていることを示します。SIP で保護された directory では、files の作成、変更、削除はできません。

さらに、file に **`com.apple.rootless`** extended **attribute** が含まれている場合、その file も **SIP によって保護**されます。

> [!TIP]
> **Sandbox** hook **`hook_vnode_check_setextattr`** は、extended attribute **`com.apple.rootless`** を変更しようとするすべての試みを防止します。

**SIP は、その他の root actions も制限します**。例:

- 信頼されていない kernel extensions のロード
- Apple-signed processes の task-ports の取得
- NVRAM variables の変更
- kernel debugging の許可

Options は bitflag として nvram variable に保持されます（Intel では `csr-active-config`、ARM では booted Device Tree から `lp-sip0` が読み取られます）。flags は XNU source code の `csr.sh` で確認できます。

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### SIP Status

次の command を使用して、system で SIP が有効になっているか確認できます。
```bash
csrutil status
```
SIPを無効化する必要がある場合は、コンピュータの起動中にCommand+Rを押してリカバリモードで再起動し、次のコマンドを実行します。
```bash
csrutil disable
```
SIPを有効にしたままデバッグ保護を削除するには、次のコマンドを実行します。
```bash
csrutil enable --without debug
```
### その他の制限

- **署名されていない kernel extensions**（kexts）の読み込みを禁止し、検証済みの extensions のみがシステム kernel と相互作用できるようにします。
- **macOS system processes の debugging**を防止し、主要な system components への不正なアクセスや変更から保護します。
- **dtrace** などの tools による system processes の検査を阻止し、システム動作の完全性をさらに保護します。

[**この talk で SIP info の詳細を確認**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**。**<sup>[[1]](#references)</sup>

### **SIP 関連の Entitlements**

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

SIP を bypass すると、attacker は以下を実行できます。

- **User Data へのアクセス**: すべての user accounts から、mail、messages、Safari history などの機密性の高い user data を読み取る。
- **TCC Bypass**: TCC (Transparency, Consent, and Control) database を直接操作し、webcam、microphone、その他の resources への不正な access を許可する。
- **Persistence の確立**: SIP-protected locations に malware を配置し、root privileges を持つユーザーによる削除に対しても耐性を持たせる。これには Malware Removal Tool (MRT) を tamper する可能性も含まれる。
- **Kernel Extensions のロード**: 追加の safeguards は存在するものの、SIP を bypass することで、unsigned kernel extensions のロードが容易になる。

### Installer Packages

**Apple の certificate で signed された Installer packages** は、その protections を bypass できます。つまり、standard developers によって signed された packages であっても、SIP-protected directories を変更しようとすると blocked されます。

### 存在しない SIP file

潜在的な loophole の 1 つは、**`rootless.conf` で指定されているものの現在存在しない file** は作成できることです。Malware はこれを exploit して、システム上に **persistence を確立**できます。たとえば、malicious program は、`rootless.conf` に記載されているものの存在しない場合、`/System/Library/LaunchDaemons` に .plist file を作成できます。

### com.apple.rootless.install.heritable

> [!CAUTION]
> Entitlement **`com.apple.rootless.install.heritable`** により SIP を bypass できます

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

system が code **signature** を検証した後に installer package を **swap** でき、その結果、system は original ではなく malicious package を install する可能性があることが発見されました。これらの actions は **`system_installd`** によって実行されるため、SIP を bypass できました。<sup>[[2]](#references)</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Package が mounted image または external drive から install された場合、**installer** は **SIP protected location** ではなく **その file system** 上の binary を **execute**しました。そのため、**`system_installd`** に arbitrary binary を execute させることが可能でした。<sup>[[3]](#references)</sup>

#### CVE-2021-30892 - Shrootless

[**この blog post の Researchers**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) は、macOS の System Integrity Protection (SIP) mechanism にある vulnerability を発見し、これを「Shrootless」vulnerability と名付けました。この vulnerability は **`com.apple.rootless.install.heritable`** entitlement を持つ **`system_installd`** daemon を中心としたもので、この entitlement により、その child processes は SIP の file system restrictions を bypass できます。<sup>[[4]](#references)</sup>

**`system_installd`** daemon は、**Apple** によって signed された packages を install します。

Researchers は、Apple-signed package (.pkg file) の installation 中に、**`system_installd`** が package に含まれる **post-install** scripts をすべて **runs** することを発見しました。これらの scripts は default shell である **`zsh`** によって execute されます。`zsh` は non-interactive mode であっても、`/etc/zshenv` file が存在する場合、その file の commands を自動的に **runs** します。この behaviour は attackers によって exploit される可能性があります。malicious `/etc/zshenv` file を作成し、**`system_installd` が `zsh` を invoke するのを待つ**ことで、device 上で arbitrary operations を実行できます。<sup>[[4]](#references)</sup>

さらに、**`/etc/zshenv` は SIP bypass 以外の general attack technique としても使用できる**ことが発見されました。各 user profile には `~/.zshenv` file があり、これは `/etc/zshenv` と同じように動作しますが、root permissions を必要としません。この file は persistence mechanism として使用でき、`zsh` の起動時に毎回 trigger させたり、elevation of privilege mechanism として利用したりできます。admin user が `sudo -s` または `sudo <command>` を使用して root に elevate すると、`~/.zshenv` file が trigger され、実質的に root へ elevate されます。<sup>[[4]](#references)</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

[**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) では、同じ **`system_installd`** process が依然として abuse 可能であることが発見されました。これは、**post-install script を `/tmp` 内の SIP によって保護された random named folder に配置していた**ためです。問題は、**`/tmp` 自体は SIP によって保護されていない**ことです。そのため、そこに **virtual image を mount**し、installer に **post-install script** を配置させ、virtual image を **unmount**し、すべての **folders** を **recreate**した後、実行する **payload** を含む **post installation** script を **add**することが可能でした。<sup>[[5]](#references)</sup>

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

**symbolic links** を follow できるため、`fsck_cs` が重要な file を corrupt するように mislead される vulnerability が特定されました。具体的には、attackers は _`/dev/diskX`_ から `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist` への link を作成しました。_`/dev/diskX`_ 上で **`fsck_cs`** を execute すると、`Info.plist` が corrupt されました。この file の integrity は、kernel extensions の loading を制御する operating system の SIP (System Integrity Protection) にとって重要です。corrupt されると、kernel exclusions を manage する SIP の ability が compromised になります。<sup>[[6]](#references)</sup>

この vulnerability を exploit する commands は次のとおりです。
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
この脆弱性の悪用は、重大な影響を及ぼします。通常、kernel extensionsの権限を管理する`Info.plist`ファイルが機能しなくなります。これには、`AppleHWAccess.kext`など特定のextensionsをblacklistに登録できなくなることも含まれます。その結果、SIPのcontrol mechanismが機能しなくなり、このextensionをloadできるようになるため、システムのRAMへの不正なreadおよびwrite accessが許可されます。<sup>[[6]](#references)</sup>

#### [SIP protected foldersの上にmountする](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

**SIP protected folders上に新しいfile systemをmountしてprotectionをbypassする**ことが可能でした。<sup>[[1]](#references)</sup>
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

システムは、`bless` utilityを利用してOSをupgradeするため、`Install macOS Sierra.app`内の埋め込みinstaller disk imageからbootするように設定されます。使用されるcommandは次のとおりです。<sup>[[7]](#references)</sup>
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
このプロセスのセキュリティは、起動前に攻撃者がアップグレードイメージ（`InstallESD.dmg`）を改変すると侵害される可能性があります。この手法では、dynamic loader（dyld）を悪意のあるバージョン（`libBaseIA.dylib`）に置き換えます。この置き換えにより、インストーラーの起動時に攻撃者のコードが実行されます。<sup>[[7]](#references)</sup>

攻撃者のコードは、インストーラーに対するシステムの信頼を悪用し、アップグレードプロセス中に制御を取得します。攻撃では、method swizzling により `InstallESD.dmg` イメージを改変し、特に `extractBootBits` メソッドを標的にします。これにより、ディスクイメージが使用される前に悪意のあるコードを注入できます。<sup>[[7]](#references)</sup>

さらに、`InstallESD.dmg` 内には `BaseSystem.dmg` があり、これはアップグレードコードの root file system として機能します。ここに dynamic library を注入すると、OS レベルのファイルを改変できるプロセス内で悪意のあるコードを動作させることが可能になり、システム侵害の可能性が大幅に高まります。<sup>[[7]](#references)</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

この [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) の講演では、**`systemmigrationd`**（SIP を bypass 可能）が **bash** および **perl** script を実行し、env variables **`BASH_ENV`** と **`PERL5OPT`** を介して abuse できることが示されています。<sup>[[8]](#references)</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

[**この blog post で詳しく説明されているように**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)、`InstallAssistant.pkg` packages に含まれる `postinstall` script は、次の処理を実行できました。<sup>[[9]](#references)</sup>
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
そして、`${SHARED_SUPPORT_PATH}/SharedSupport.dmg` に symlink を作成することが可能であり、これによりユーザーは **任意のファイルの制限を解除し、SIP protection をバイパスできました**。<sup>[[9]](#references)</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> entitlement **`com.apple.rootless.install`** により SIP をバイパスできます

entitlement `com.apple.rootless.install` は、macOS の System Integrity Protection (SIP) をバイパスすることが知られています。これは特に [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/) との関連で言及されました。<sup>[[10]](#references)</sup>

この具体的なケースでは、`/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` に存在する system XPC service がこの entitlement を保有しています。これにより、関連する process は SIP の制約を回避できます。さらに、この service には、security measures を適用せずにファイルを移動できる method が存在します。<sup>[[10]](#references)</sup>

## Sealed System Snapshots

Sealed System Snapshots は、追加の security layer と system stability を提供するため、**macOS Big Sur (macOS 11)** で **System Integrity Protection (SIP)** の一部として Apple が導入した feature です。これは本質的に system volume の read-only version です。

詳しくは以下のとおりです。

1. **Immutable System**: Sealed System Snapshots により macOS の system volume は "immutable" になります。つまり、変更できません。これにより、security や system stability を損なう可能性のある、system への不正または偶発的な変更を防止します。
2. **System Software Updates**: macOS の update または upgrade をインストールすると、macOS は新しい system snapshot を作成します。その後、macOS startup volume は **APFS (Apple File System)** を使用して、この新しい snapshot に切り替えます。update 中に問題が発生しても、system は常に以前の snapshot に戻せるため、update の適用プロセス全体がより安全で信頼性の高いものになります。
3. **Data Separation**: macOS Catalina で導入された Data volume と System volume の分離という概念と組み合わせることで、Sealed System Snapshot feature は、すべての data と settings が独立した "**Data**" volume に保存されることを保証します。この分離により、data は system から独立するため、system update のプロセスが簡素化され、system security が強化されます。

これらの snapshot は macOS によって自動的に管理され、APFS の space sharing capabilities により、disk 上の追加の space を消費しないことに注意してください。また、これらの snapshot は、system 全体の user-accessible な backup である **Time Machine snapshots** とは異なることも重要です。

### Check Snapshots

command **`diskutil apfs list`** は、**APFS volumes の details** とその layout を一覧表示します。

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
|   |   Encrypted:                No
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

前の output から、**user-accessible locations** が `/System/Volumes/Data` の下に mount されていることがわかります。

さらに、**macOS System volume snapshot** は `/` に mount されており、**sealed** されています（OS によって cryptographically signed されています）。したがって、SIP がバイパスされて変更が加えられると、**OS は起動できなくなります**。

次の command を実行して、**seal が有効になっていることを verify** することもできます。
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
さらに、snapshot disk も **read-only** として mount されています：
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
## 参考文献

- [1] [SyScan360 - Stefan Esser - OS X El Capitan sinking the S\H/IP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)
- [2] [CVE-2019-8561 - Objective-See Blog](https://objective-see.org/blog/blog_0x42.html)
- [3] [CVE-2020–9854: 「Unauthd」（three）logic bugs ftw! - Objective-See Blog](https://objective-see.org/blog/blog_0x4D.html)
- [4] [Microsoft、System Integrity Protectionをbypass可能な新たなmacOS vulnerability「Shrootless」を発見](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Technical Analysis: CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [Appleのfruitless rootless securityが、tweetに収まるコードによって破られる - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] AppleのSystem Integrity Protectionをbypassする - Objective-See Blog](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Getting a Migraine - MacOSのUnique SIP Bypass - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [Apple、Installer Scriptsのvulnerabilityをmitigate - Kandji Blog](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712: SIP-BypassのPOCはtweetにも収まる](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)

{{#include ../../../banners/hacktricks-training.md}}
