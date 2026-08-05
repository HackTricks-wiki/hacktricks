# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** は Mac operating systems 向けに開発された security feature で、ユーザーがシステム上で **trusted software のみを実行する** ように設計されています。これは、ユーザーが **App Store 以外の sources** から download して開こうとする software（app、plug-in、installer package など）を **validating** することで機能します。

Gatekeeper の主要な mechanism は **verification** プロセスにあります。download された software が **recognized developer によって signed されているか** を確認し、その software の authenticity を検証します。さらに、software が **Apple によって notarised されているか** を確認し、既知の malicious content が含まれておらず、notarisation 後に tampered with されていないことを検証します。

また、Gatekeeper は download された software を初めて開く際に **ユーザーへ opening の approve を求める** ことで、ユーザーによる control と security を強化します。この safeguard は、無害な data file だと誤認した可能性のある、潜在的に有害な executable code をユーザーが誤って実行することを防ぎます。

### Application Signatures

Application signatures（code signatures とも呼ばれます）は、Apple の security infrastructure における重要な component です。これは **software author（developer）の identity を verify する** ため、および最後に signed されてから code が tampered with されていないことを確認するために使用されます。

仕組みは次のとおりです。

1. **Signing the Application:** developer が application を distribute する準備ができたら、**private key を使用して application に sign します**。この private key は、developer が Apple Developer Program に enrol した際に **Apple が developer に発行する certificate** と関連付けられています。signing process では、app のすべての部分から cryptographic hash を作成し、この hash を developer の private key で encrypt します。
2. **Distributing the Application:** signed application は、対応する public key を含む developer の certificate とともに users に distribute されます。
3. **Verifying the Application:** user が application を download して実行しようとすると、その Mac operating system は developer の certificate に含まれる public key を使用して hash を decrypt します。次に、application の現在の state に基づいて hash を再計算し、これを decrypted hash と比較します。一致した場合、**developer が sign してから application が modified されていない** ことを意味し、system は application の実行を許可します。

Application signatures は Apple の Gatekeeper technology における essential part です。user が **internet から download した application を open しようとすると**、Gatekeeper は application signature を verify します。Apple が known developer に発行した certificate で signed されており、code が tampered with されていなければ、Gatekeeper は application の実行を許可します。それ以外の場合、application を block して user に alert を表示します。

macOS Catalina 以降、**Gatekeeper は application が Apple によって notarized されているかも check します**。これにより、security の追加 layer が提供されます。notarization process では、application に既知の security issues や malicious code がないかを check し、これらの check に pass すると、Apple は Gatekeeper が verify できる ticket を application に追加します。

#### Check Signatures

**malware sample** を check する際は、binary の **signature を必ず check してください**。その binary を signed した **developer** が、すでに **malware と関連している** 可能性があるためです。
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```
### Notarization

Appleのnotarizationプロセスは、ユーザーを潜在的に有害なsoftwareから保護するための追加の安全対策です。これには、**developerが自身のapplicationを** **Apple's Notary Service** による検査のために提出することが含まれます。このサービスはApp Reviewと混同しないでください。これは、提出されたsoftwareに**malicious content**が含まれていないか、またcode-signingに潜在的な問題がないかを精査する**automated system**です。

softwareが問題を起こすことなくこの検査に**合格**すると、Notary Serviceはnotarization ticketを生成します。その後、developerはこのticketを**softwareに添付**する必要があります。このプロセスは「stapling」と呼ばれます。さらに、notarization ticketはオンラインにも公開され、Gatekeeper（Appleのsecurity technology）がアクセスできるようになります。

ユーザーがsoftwareを初めてインストールまたは実行すると、実行可能ファイルにstapleされているかオンラインで見つかったかにかかわらず、notarization ticketの存在によって、**softwareがAppleによってnotarizedされていることがGatekeeperに通知されます**。その結果、Gatekeeperは初回起動ダイアログに説明メッセージを表示し、そのsoftwareがAppleによってmalicious contentのチェックを受けたことを示します。これにより、ユーザーが自身のシステムにインストールまたは実行するsoftwareのsecurityに対する信頼が高まります。

### spctl & syspolicyd

> [!CAUTION]
> Sequoia version以降、**`spctl`**ではGatekeeper configurationを変更できなくなったことに注意してください。

**`spctl`**は、Gatekeeper（XPC messagesを介して`syspolicyd` daemonと通信）を列挙および操作するためのCLI toolです。例えば、以下のコマンドで**GateKeeper**の**status**を確認できます。
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> GateKeeper の signature checks は、すべての file ではなく、**Quarantine attribute を持つ files** に対してのみ実行されます。

GateKeeper は、**preferences と signature** に従って binary を実行できるかどうかを check します：

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** は Gatekeeper の enforcing を担当する主要な daemon です。`/var/db/SystemPolicy` にある database を管理しており、[database をサポートする code はここ](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp)、[SQL template はここ](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql) で確認できます。database は SIP によって制限されず、root が writable であることに注意してください。また、database `/var/db/.SystemPolicy-default` は、もう一方の database が corrupted した場合に original backup として使用されます。

さらに、bundles **`/var/db/gke.bundle`** と **`/var/db/gkopaque.bundle`** には、database に挿入される rules を含む files があります。root として次の command でこの database を check できます：
```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```
**`syspolicyd`** は、`assess`、`update`、`record`、`cancel` などのさまざまな操作を備えた XPC server も公開しており、これらには **`Security.framework` の `SecAssessment*`** APIs を使って到達できます。また、**`spctl`** は実際に XPC 経由で **`syspolicyd`** と通信します。

最初の rule が "**App Store**" で終わり、2 番目の rule が "**Developer ID**" で終わっていること、そして前の image では **App Store および identified developers の apps を実行できるようになっていた**ことに注目してください。\
その設定を App Store に**変更**すると、"**Notarized Developer ID" rules は消えます**。

**type GKE** の rules も数千存在します：
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
これらは以下から取得された hash です。

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

または、以下のコマンドで前述の情報を一覧表示できます。
```bash
sudo spctl --list
```
**`spctl`** の **`--master-disable`** および **`--global-disable`** オプションは、これらの署名チェックを完全に **無効化** します：
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
完全に有効化すると、新しいオプションが表示されます：

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

次のコマンドで、**App が GateKeeper によって許可されるかどうかを確認**できます：
```bash
spctl --assess -v /Applications/App.app
```
GateKeeperに新しいルールを追加して、特定のアプリの実行を許可できます：
```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```
**kernel extensions**に関しては、フォルダ `/var/db/SystemPolicyConfiguration` に、ロードが許可された kexts のリストを含むファイルがあります。さらに、`spctl` には `com.apple.private.iokit.nvram-csr` entitlement があります。これは、新たに事前承認された kernel extensions を追加でき、それらを NVRAM の `kext-allowed-teams` key にも保存する必要があるためです。

#### macOS 15 (Sequoia) 以降での Gatekeeper の管理

- 長年利用されてきた Finder の **Ctrl+Open / 右クリック → Open** による bypass は削除されました。ユーザーは、最初のブロックダイアログの後、**System Settings → Privacy & Security → Open Anyway** からブロックされた app を明示的に許可する必要があります。<sup>[4]</sup>
- `spctl --master-disable/--global-disable` は受け付けられなくなりました。`spctl` は assessment と label management に関して実質的に read-only となり、policy enforcement は UI または MDM を通じて設定されます。

macOS 15 Sequoia 以降、end users は `spctl` から Gatekeeper policy を切り替えられなくなりました。Management は System Settings を通じて行うか、`com.apple.systempolicy.control` payload を含む MDM configuration profile を deploy して行います。以下は、App Store と identified developers を許可する（ただし「Anywhere」は許可しない）profile の例です。

<details>
<summary>App Store と identified developers を許可する MDM profile</summary>
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>PayloadContent</key>
<array>
<dict>
<key>PayloadType</key>
<string>com.apple.systempolicy.control</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadIdentifier</key>
<string>com.example.gatekeeper</string>
<key>EnableAssessment</key>
<true/>
<key>AllowIdentifiedDevelopers</key>
<true/>
</dict>
</array>
<key>PayloadType</key>
<string>Configuration</string>
<key>PayloadIdentifier</key>
<string>com.example.profile.gatekeeper</string>
<key>PayloadUUID</key>
<string>00000000-0000-0000-0000-000000000000</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadDisplayName</key>
<string>Gatekeeper</string>
</dict>
</plist>
```
</details>

### Quarantine Files

アプリケーションまたはファイルを**ダウンロード**すると、Webブラウザやメールクライアントなどの特定のmacOS **applications**は、一般に「**quarantine flag**」と呼ばれる**extended file attribute**をダウンロードしたファイルに付加します。この属性は、**ファイルが信頼できないソース**（インターネット）から取得されたものであり、潜在的なリスクを持つ可能性があることを**マークする**セキュリティ対策として機能します。ただし、すべてのアプリケーションがこの属性を付加するわけではありません。例えば、一般的なBitTorrentクライアントソフトウェアは通常、この処理を回避します。

**quarantine flagの存在は、ユーザーがファイルを実行しようとした際に、macOSのGatekeeperセキュリティ機能を作動させます**。

**quarantine flagが存在しない場合**（一部のBitTorrentクライアント経由でダウンロードされたファイルなど）、Gatekeeperの**checksが実行されない可能性があります**。そのため、ユーザーは安全性の低い、または不明なソースからダウンロードしたファイルを開く際に注意する必要があります。

> [!NOTE] > **code signaturesの有効性の確認**は、コードとそのすべてのバンドルリソースの暗号学的な**hashes**の生成を含む、**resource-intensive**な処理です。さらに、certificateの有効性の確認には、発行後に失効していないかを確認するため、Appleのサーバーへの**online check**が必要です。これらの理由から、アプリが起動するたびに完全なcode signatureおよびnotarization checkを実行するのは**実用的ではありません**。
>
> したがって、これらのchecksは**quarantined attributeが付いたアプリを実行する場合にのみ実行されます**。

> [!WARNING]
> この属性は、ファイルを作成またはダウンロードする**applicationによって設定される必要があります**。
>
> ただし、sandbox化されたファイルは、作成するすべてのファイルにこの属性が設定されます。また、non sandboxed appsは自分で設定することも、[**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc)キーを**Info.plist**で指定することもできます。これにより、システムは作成されたファイルに`com.apple.quarantine` extended attributeを設定します。

さらに、**`qtn_proc_apply_to_self`**を呼び出すprocessによって作成されたすべてのファイルはquarantinedになります。また、API **`qtn_file_apply_to_path`**は、指定されたfile pathにquarantine attributeを追加します。

**statusの確認と有効化/無効化**（root required）は、次の方法で実行できます。
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
また、ファイルに quarantine 拡張属性があるかどうかも **確認できます**。
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
**extended** **attributes** の**value**を確認し、次の方法で quarantine attr を書き込んだアプリを特定します:
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
実際には、プロセスは「作成するファイルに quarantine flags を設定できる」可能性があります（作成したファイルに USER_APPROVED flag を適用しようとしましたが、適用できませんでした）。

<details>

<summary>Source Code apply quarantine flags</summary>
```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
QTN_FLAG_DOWNLOAD = 0x0001,
QTN_FLAG_SANDBOX = 0x0002,
QTN_FLAG_HARD = 0x0004,
QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

qtn_proc_t qp = qtn_proc_alloc();
qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
qtn_proc_apply_to_self(qp);
qtn_proc_free(qp);

FILE *fp;
fp = fopen("thisisquarantined.txt", "w+");
fprintf(fp, "Hello Quarantine\n");
fclose(fp);

return 0;

}
```
</details>

そして、次のコマンドでその属性を**削除**します。
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
そして、次のコマンドですべての隔離されたファイルを見つけます：
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine information は、LaunchServices が管理する中央データベース **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** にも保存されます。これにより、GUI はファイルの出所に関するデータを取得できます。さらに、出所を隠すことに関心のあるアプリケーションによって、この情報が上書きされる可能性もあります。また、これは LaunchServices API から実行できます。

#### **libquarantine.dylib**

この library は、extended attribute fields を操作できる複数の functions を export します。

`qtn_file_*` API は file quarantine policies を扱い、`qtn_proc_*` API は processes（process によって作成された files）に適用されます。export されていない `__qtn_syscall_quarantine*` functions は、policies を適用する functions であり、第一引数に "Quarantine" を指定して `mac_syscall` を呼び出し、requests を `Quarantine.kext` に送信します。

#### **Quarantine.kext**

この kernel extension は、システム上の **kernel cache** からのみ利用できます。ただし、[**https://developer.apple.com/**](https://developer.apple.com/) から **Kernel Debug Kit** をダウンロードできます。これには、この extension の symbolicated version が含まれています。

この Kext は MACF を介して複数の calls に hook し、すべての file lifecycle events（Creation、opening、renaming、hard-linkning...）を trap します。`setxattr` で `com.apple.quarantine` extended attribute が設定されることも防ぎます。

また、いくつかの MIBs も使用します。

- `security.mac.qtn.sandbox_enforce`: Sandbox と連携して quarantine を強制する
- `security.mac.qtn.user_approved_exec`: Querantined procs は approved files のみ実行できる

#### Provenance xattr (Ventura and later)

macOS 13 Ventura では、quarantined app の実行が初めて許可された際に設定される、別の provenance mechanism が導入されました。<sup>[2]</sup> 2 つの artefacts が作成されます。

- `.app` bundle directory 上の `com.apple.provenance` xattr（primary key と flags を含む固定サイズの binary value）。
- `/var/db/SystemPolicyConfiguration/ExecPolicy/` の ExecPolicy database 内にある `provenance_tracking` table の row。app の cdhash と metadata が保存されます。

Practical usage:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtectはmacOSに組み込まれた**anti-malware**機能です。XProtectは、**初回起動時または変更時に、すべてのアプリケーションを既知のmalwareおよび安全でないファイルタイプのデータベースと照合します**。Safari、Mail、Messagesなどの特定のアプリを通じてファイルをダウンロードすると、XProtectは自動的にファイルをスキャンします。データベース内の既知のmalwareと一致した場合、XProtectは**ファイルの実行を阻止し**、脅威を通知します。

XProtectのデータベースは、Appleによって**新しいmalware定義で定期的に更新**され、これらの更新はMacに自動的にダウンロードおよびインストールされます。これにより、XProtectは既知の最新の脅威に常に対応できます。

ただし、**XProtectは完全な機能を備えたantivirusソリューションではありません**。特定の既知の脅威リストのみをチェックし、ほとんどのantivirusソフトウェアのようなon-access scanningは実行しません。

次のコマンドを実行すると、最新のXProtectアップデートに関する情報を取得できます:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtectはSIPで保護された **/Library/Apple/System/Library/CoreServices/XProtect.bundle** にあります。bundleの内部には、XProtectが使用する以下の情報があります。

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: これらのcdhashを持つcodeがlegacy entitlementsを使用することを許可します。
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: BundleIDとTeamIDによってloadを拒否するpluginやextension、またはminimum versionを指定するpluginやextensionの一覧です。
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: malwareを検出するYara rulesです。
- **`XProtect.bundle/Contents/Resources/gk.db`**: blockされたapplicationのhashとTeamIDを含むSQLite3 databaseです。

**/Library/Apple/System/Library/CoreServices/XProtect.app** にもXProtectに関連する別のAppがありますが、Gatekeeper processには関与しません。

> XProtect Remediator: modern macOSでは、Appleはon-demand scanner（XProtect Remediator）を提供しており、launchd経由で定期的に実行され、malware familyを検出してremediateします。unified logsでこれらのscanを確認できます。
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Gatekeeperではない

> [!CAUTION]
> Gatekeeperはapplicationを実行するたびに実行されるわけではありません。_**AppleMobileFileIntegrity**_だけが、Gatekeeperによってすでに実行および検証されたappを実行するときに、**executable code signatures**をverifyします。

そのため、以前はGatekeeperでappをcacheするためにappを実行し、その後applicationの**実行ファイルではないファイル**（ElectronのasarやNIB filesなど）を**modify**できました。他のprotectionsが存在しなければ、applicationは**malicious**な追加要素とともに**実行**されました。

しかし現在は、macOSがapplication bundle内部の**filesのmodifyを防止する**ため、これは不可能です。そのため、[Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attackを試すと、Gatekeeperでcacheするためにappを実行した後はbundleをmodifyできないため、もはやabuseできないことがわかります。また、exploitで示されているように、たとえばContents directoryの名前をNotConに変更してから、appのmain binaryを実行してGatekeeperでcacheしようとしても、errorがtriggerされて実行されません。

## Gatekeeper Bypasses

Gatekeeperをbypassする方法（Gatekeeperが拒否すべきものをuserにdownloadさせて実行させること）は、macOSにおけるvulnerabilityとみなされます。過去にGatekeeperのbypassを可能にしたtechniqueには、以下のCVEが割り当てられています。

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

**Archive Utility**をextractionに使用した場合、**886 charactersを超えるpath**を持つfilesにはcom.apple.quarantine extended attributeが付与されないことが確認されました。この状況により、これらのfilesは意図せず**Gatekeeperの**security checksを**circumvent**できます。<sup>[5]</sup>

詳細については[**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)を確認してください。

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

このbypassでは、**Automator**でapplicationを作成すると、実行に必要な情報はexecutableではなく`application.app/Contents/document.wflow`内にあります。executableは、**Automator Application Stub**と呼ばれるgenericなAutomator binaryにすぎません。

したがって、`application.app/Contents/MacOS/Automator\ Application\ Stub`を、**system内にある別のAutomator Application Stubへのsymbolic link**にすることで、実際のexecutableにはquarantine xattrがないため、Gatekeeperをtriggerせずに`document.wflow`内の内容（your script）を実行できます。<sup>[6]</sup>

想定されるlocationの例: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

詳細については[**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper)を確認してください。

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

このbypassでは、`application.app`ではなく`application.app/Contents`から圧縮を開始してzip fileを作成しました。そのため、**quarantine attr**は**`application.app/Contents`内のすべてのfiles**には適用されましたが、Gatekeeperがcheckしていた**`application.app`**には適用されませんでした。したがって、`application.app`がtriggerされたときに**quarantine attributeがなかった**ため、Gatekeeperがbypassされました。<sup>[7]</sup>
```bash
zip -r test.app/Contents test.zip
```
詳細については、[**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)を確認してください。

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

コンポーネントは異なりますが、この脆弱性のexploitは前述のものと非常によく似ています。この場合、**`application.app/Contents`** からApple Archiveを生成するため、**`application.app`** は**Archive Utility**によって展開される際にquarantine attrを取得しません。<sup>[8]</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
詳細については、[**original report**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)を確認してください。

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`**を使用すると、ファイルへの属性の書き込みをすべてのユーザーに対して防止できます。
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
さらに、**AppleDouble** ファイル形式は、ACE を含めてファイルをコピーします。<sup>[9]</sup>

[**ソースコード**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) では、**`com.apple.acl.text`** という xattr 内に保存された ACL のテキスト表現が、展開されたファイルの ACL として設定されることを確認できます。したがって、他の xattr の書き込みを阻止する ACL を持つ **AppleDouble** ファイル形式でアプリケーションを zip ファイルに圧縮すると、quarantine xattr はアプリケーションに設定されません。
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
詳細については、[**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) を確認してください。

これは AppleArchives を使用しても exploit できることに注意してください：
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

**Google Chrome がダウンロードしたファイルに quarantine attribute を設定していなかった**ことが、macOS 内部の問題により判明しました。<sup>[10]</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble file formats は、ファイルの attributes を `._` で始まる別のファイルに保存します。これにより、**macOS マシン間でファイル attributes をコピー**できます。しかし、AppleDouble file を decompress した後、`._` で始まるファイルに **quarantine attribute が付与されていなかった**ことが判明しました。<sup>[11]</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
quarantine属性が設定されないファイルを作成できれば、**Gatekeeperをbypassすることが可能でした。** その手法は、AppleDoubleの命名規則（`._`で始める）を使用して**DMGファイルのアプリケーションを作成**し、この隠しファイルへの**quarantine属性がないvisible fileのsym link**を作成するというものでした。\
**dmg fileを実行すると**、quarantine属性がないため、**Gatekeeperをbypassします。**
```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```
### [CVE-2023-41067]

macOS Sonoma 14.0で修正されたGatekeeper bypassにより、細工されたアプリをプロンプトなしで実行できました。詳細はパッチ適用後に公開され、この問題は修正前に実際の攻撃で悪用されていました。Sonoma 14.0以降がインストールされていることを確認してください。

### [CVE-2024-27853]

macOS 14.4（2024年3月リリース）におけるGatekeeper bypassは、悪意のあるZIPの`libarchive`処理に起因し、アプリがassessmentを回避できました。この問題はAppleが対処した14.4以降にupdateしてください。<sup>[1]</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

ダウンロードしたアプリに埋め込まれた**Automator Quick Action workflow**は、Gatekeeper assessmentなしで実行される可能性がありました。これは、workflowがdataとして扱われ、通常のnotarization promptの経路外でAutomator helperによって実行されていたためです。そのため、shell scriptを実行するQuick Action（例：`Contents/PlugIns/*.workflow/Contents/document.wflow`内）をバンドルした細工済みの`.app`は、起動時に直ちに実行される可能性がありました。Appleは追加の同意ダイアログを導入し、Ventura **13.7**、Sonoma **14.7**、Sequoia **15**でassessmentの経路を修正しました。<sup>[3]</sup>

### Third‑party unarchivers mis‑propagating quarantine (2023–2024)

一般的な複数のextraction tool（例：The Unarchiver）の脆弱性により、archiveから展開されたファイルに`com.apple.quarantine` xattrが付与されず、Gatekeeper bypassの機会が生じました。テスト時は必ずmacOS Archive Utilityまたはpatched toolを使用し、展開後にxattrを検証してください。

### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- アプリを含むdirectoryを作成します。
- アプリにuchgを追加します。
- アプリをtar.gz fileにcompressします。
- tar.gz fileをvictimに送信します。
- victimがtar.gz fileを開き、アプリを実行します。
- Gatekeeperはアプリをcheckしません。<sup>[12]</sup>

### Prevent Quarantine xattr

".app" bundleにquarantine xattrが追加されていない場合、実行時に**Gatekeeperはtriggerされません**。


## References

- [1] [Apple Platform Security: About the security content of macOS Sonoma 14.4 (includes CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: How macOS now tracks the provenance of apps](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: About the security content of macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia removes the Control‑click “Open” Gatekeeper bypass](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)
- [5] [WithSecure Labs: The Discovery of CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, Bypassing The macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs identifies Safari vulnerability allowing for Gatekeeper bypass](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs identifies macOS Archive Utility vulnerability allowing for Gatekeeper bypass (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Gatekeeper's Achilles heel: Unearthing a macOS vulnerability](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Discovery of a Gatekeeper Bypass (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Finding and reporting a Gatekeeper bypass exploit with help from Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Bypassing macOS Security and Privacy Mechanisms — From Gatekeeper to System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)

{{#include ../../../banners/hacktricks-training.md}}
