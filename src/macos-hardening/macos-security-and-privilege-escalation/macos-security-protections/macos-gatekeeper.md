# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** は Mac オペレーティングシステム向けに開発されたセキュリティ機能で、ユーザーがシステム上で **信頼できるソフトウェアのみを実行する** ように設計されています。アプリ、プラグイン、インストーラパッケージなど、**App Store 以外のソースから** ユーザーがダウンロードして開こうとするソフトウェアを **検証する** ことで機能します。

Gatekeeper の主要な仕組みは **検証** プロセスです。ダウンロードしたソフトウェアが **認識された開発者によって署名されているか** を確認し、ソフトウェアの信頼性を検証します。さらに、そのソフトウェアが **Apple によって notarised されているか** を確認し、既知の悪意あるコンテンツが含まれておらず、notarisation 後に改ざんされていないことを確認します。

また、Gatekeeper は、ダウンロードしたソフトウェアを初めて開く際に **ユーザーに開くことの承認を求める** ことで、ユーザーによる制御とセキュリティを強化します。この保護機能により、無害なデータファイルだと思い込んだ、潜在的に有害な実行可能コードをユーザーが誤って実行することを防ぎます。

### Application Signatures

アプリケーション署名は code signatures とも呼ばれ、Apple のセキュリティ基盤における重要な要素です。これは **ソフトウェア作成者**（開発者）の身元を **検証** し、最後に署名されて以降、コードが改ざんされていないことを確認するために使用されます。

仕組みは次のとおりです。

1. **Signing the Application:** 開発者がアプリケーションを配布する準備ができると、**private key を使用してアプリケーションに署名します**。この private key は、Apple Developer Program に登録した際に **Apple が開発者へ発行する certificate** に関連付けられています。署名プロセスでは、アプリのすべての部分から cryptographic hash を作成し、この hash を開発者の private key で暗号化します。
2. **Distributing the Application:** 署名済みアプリケーションは、対応する public key を含む開発者の certificate とともにユーザーへ配布されます。
3. **Verifying the Application:** ユーザーがアプリケーションをダウンロードして実行しようとすると、Mac オペレーティングシステムは開発者の certificate に含まれる public key を使用して hash を復号します。次に、アプリケーションの現在の状態に基づいて hash を再計算し、復号した hash と比較します。一致した場合、**開発者が署名して以降、アプリケーションが変更されていない** ことを意味し、システムはアプリケーションの実行を許可します。

アプリケーション署名は、Apple の Gatekeeper technology における重要な要素です。ユーザーが **インターネットからダウンロードしたアプリケーションを開こうとすると**、Gatekeeper はアプリケーション署名を検証します。Apple が既知の開発者に発行した certificate で署名されており、コードが改ざんされていなければ、Gatekeeper はアプリケーションの実行を許可します。それ以外の場合、アプリケーションをブロックしてユーザーに警告します。

macOS Catalina 以降、**Gatekeeper はアプリケーションが Apple によって notarized されているかどうかも確認します**。これにより、セキュリティがさらに強化されます。notarization プロセスでは、既知のセキュリティ問題や悪意あるコードがないかアプリケーションを確認し、これらのチェックに合格すると、Apple は Gatekeeper が検証できる ticket をアプリケーションに追加します。

#### Check Signatures

**malware sample** を確認する際は、バイナリに署名した **developer** がすでに **malware** と **関連している** 可能性があるため、必ず **signature を確認してください**。
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

Appleのnotarization processは、潜在的に有害なsoftwareからユーザーを保護するための追加の安全対策です。これは、**developerが自身のapplicationを検査のために提出すること**で実施されます。検査を行うのは**Apple's Notary Service**であり、App Reviewと混同しないでください。このserviceは**automated system**で、提出されたsoftwareに**malicious content**が含まれていないか、またcode-signingに問題がないかを精査します。

softwareが問題なくこの検査に**passes**すると、Notary Serviceはnotarization ticketを生成します。その後、developerはこのticketをsoftwareに**attachすること**が必要です。この処理は「stapling」と呼ばれます。さらに、notarization ticketはonlineにも公開され、Appleのsecurity technologyであるGatekeeperがアクセスできるようになります。

ユーザーがsoftwareを初めてinstallまたはexecuteした際、notarization ticketが存在すること（executableにstapleされている場合でも、onlineで見つかった場合でも）により、**GatekeeperはsoftwareがAppleによってnotarizedされていることを認識します**。その結果、Gatekeeperはinitial launch dialogに説明メッセージを表示し、softwareがAppleによってmalicious contentの検査を受けたことを示します。これにより、ユーザーが自身のsystemにinstallまたはrunするsoftwareのsecurityに対する信頼が高まります。

### spctl & syspolicyd

> [!CAUTION]
> Sequoia version以降、**`spctl`**ではGatekeeper configurationを変更できなくなったことに注意してください。

**`spctl`**は、Gatekeeper（XPC messagesを介して`syspolicyd` daemonと通信）をenumerateおよび操作するためのCLI toolです。例えば、次のコマンドで**GateKeeper**の**status**を確認できます。
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> GateKeeper の signature check は、すべてのファイルではなく、**Quarantine attribute が付いたファイル**に対してのみ実行されることに注意してください。

GateKeeper は、**preferences と signature** に従って binary を実行できるかどうかを確認します。

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** は Gatekeeper の適用を担当する主要な daemon です。`/var/db/SystemPolicy` にある database を管理しており、[database をサポートする code](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) と [SQL template](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql) を確認できます。database は SIP による制限を受けず、root が書き込み可能であることに注意してください。また、database `/var/db/.SystemPolicy-default` は、もう一方の database が破損した場合に original backup として使用されます。

さらに、bundle **`/var/db/gke.bundle`** と **`/var/db/gkopaque.bundle`** には、database に挿入される rule を含むファイルがあります。root として次のコマンドでこの database を確認できます。
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
**`syspolicyd`** は、`assess`、`update`、`record`、`cancel` などのさまざまな操作を備えた XPC server も公開しており、これらは **`Security.framework` の `SecAssessment*`** APIs を使用して到達することもでき、**`spctl`** は実際に XPC 経由で **`syspolicyd`** と通信します。

最初のルールが "**App Store**" で終わり、2 番目のルールが "**Developer ID**" で終わっていること、そして前の画像では **App Store と識別済みの developers からの apps の実行が有効になっていた**ことに注目してください。\
その設定を App Store に**変更**すると、"**Notarized Developer ID" rules が消えます**。

**type GKE** のルールも数千件存在します：
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

または、以下を使用して前述の情報を一覧表示できます：
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
完全に有効にすると、新しいオプションが表示されます：

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

次のコマンドで、**App が GateKeeper によって許可されるかどうかを確認**できます：
```bash
spctl --assess -v /Applications/App.app
```
GateKeeper に新しいルールを追加して、特定のアプリの実行を許可できます：
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
**kernel extensions**に関しては、`/var/db/SystemPolicyConfiguration`フォルダに、読み込みを許可されたkextのリストを含むファイルがあります。さらに、`spctl`には`com.apple.private.iokit.nvram-csr` entitlementがあります。これは、事前に承認された新しいkernel extensionsを追加でき、それらをNVRAMの`kext-allowed-teams`キーにも保存する必要があるためです。

#### macOS 15（Sequoia）以降でのGatekeeperの管理

- 長年利用されてきたFinderの**Ctrl+Open / Right-click → Open** bypassは削除されました。ユーザーは、最初のブロックダイアログの後、**System Settings → Privacy & Security → Open Anyway**からブロックされたアプリを明示的に許可する必要があります。<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable`は受け付けられなくなりました。`spctl`は実質的にassessmentとlabel managementのread-only操作のみを行い、policy enforcementはUIまたはMDMを通じて設定されます。

macOS 15 Sequoia以降、end usersは`spctl`からGatekeeper policyを切り替えられなくなりました。管理はSystem Settingsから行うか、`com.apple.systempolicy.control` payloadを含むMDM configuration profileをdeployして行います。以下は、App Storeとidentified developersを許可する（ただし「Anywhere」は許可しない）profile snippetの例です。

<details>
<summary>App Storeとidentified developersを許可するMDM profile</summary>
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

アプリケーションまたはファイルを**ダウンロード**すると、Webブラウザやメールクライアントなど、特定のmacOS **applications**は、ダウンロードしたファイルに一般に「**quarantine flag**」として知られる**拡張ファイル属性**を付加します。この属性は、**ファイルに印を付ける**セキュリティ対策として機能し、そのファイルが信頼されていないソース（インターネット）から取得されたものであり、潜在的なリスクを含む可能性があることを示します。ただし、すべてのアプリケーションがこの属性を付加するわけではありません。例えば、一般的なBitTorrent client softwareは通常、この処理を回避します。

**ユーザーがファイルを実行しようとした際、quarantine flagの存在はmacOSのGatekeeper security featureに通知されます**。

**quarantine flagが存在しない場合**（一部のBitTorrent clientsを介してダウンロードされたファイルなど）、Gatekeeperの**checksが実行されない可能性があります**。そのため、ユーザーは安全性の低い、または未知のソースからダウンロードしたファイルを開く際に注意する必要があります。

> [!NOTE] > **code signaturesの** **validity**を**checking**する処理は、コードおよびバンドル内のすべてのリソースから暗号学的な**hashes**を生成する必要があるため、**resource-intensive**です。さらに、certificate validityのcheckingには、証明書の発行後に失効していないかを確認するため、Appleのサーバーへの**online check**が含まれます。これらの理由により、アプリの起動ごとに完全なcode signatureおよびnotarization checkを**実行するのは非現実的です**。
>
>したがって、これらのchecksは**quarantined attributeを持つアプリを実行するときにのみ実行されます**。

> [!WARNING]
>この属性は、ファイルを作成またはダウンロードするアプリケーションによって**設定される必要があります**。
>
>ただし、sandboxedなファイルは、作成するすべてのファイルにこの属性が設定されます。また、non sandboxed appsは自身で設定することも、[**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) keyを**Info.plist**で指定することもできます。これにより、システムは作成されたファイルに`com.apple.quarantine` extended attributeを設定します。

さらに、**`qtn_proc_apply_to_self`**を呼び出すprocessによって作成されたすべてのファイルはquarantinedになります。また、API **`qtn_file_apply_to_path`**は、指定されたファイルパスにquarantine attributeを追加します。

次の方法で**statusの確認およびenable/disable**（root required）が可能です。
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
次の方法で、ファイルに **quarantine 拡張属性** があるかどうかも確認できます：
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
**extended** **attributes** の **value** を確認し、次のコマンドで quarantine attr を書き込んだ app を特定します：
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

<summary>quarantine flags を適用する Source Code</summary>
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

そして、次のコマンドでその属性を**削除**します:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
以下のコマンドですべての隔離済みファイルを検索します:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine information は、**`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** にある LaunchServices が管理する中央データベースにも保存されており、GUI がファイルの origin に関するデータを取得できます。さらに、これは origin を隠すことに関心のあるアプリケーションによって上書きされる可能性があります。また、LaunchServices APIS から実行することもできます。

#### **libquarantine.dylib**

この library は、extended attribute fields を操作できる複数の functions を export します。

`qtn_file_*` APIs は file quarantine policies を扱い、`qtn_proc_*` APIs は processes（その process によって作成された files）に適用されます。export されていない `__qtn_syscall_quarantine*` functions は policies を適用するもので、最初の引数に "Quarantine" を指定して `mac_syscall` を呼び出し、requests を `Quarantine.kext` に送信します。

#### **Quarantine.kext**

この kernel extension は **system 上の kernel cache** からのみ利用できます。ただし、**Kernel Debug Kit は** [**https://developer.apple.com/**](https://developer.apple.com/) **から download** でき、symbolicated version の extension が含まれています。

この Kext は MACF 経由で複数の calls に hook し、file lifecycle events（Creation、opening、renaming、hard-linkning...）をすべて trap します。`setxattr` で `com.apple.quarantine` extended attribute が設定されることも防止します。

また、いくつかの MIBs も使用します。

- `security.mac.qtn.sandbox_enforce`: Sandbox とともに quarantine を Enforce
- `security.mac.qtn.user_approved_exec`: Querantined procs は approved files のみ execute 可能

#### Provenance xattr (Ventura and later)

macOS 13 Ventura では、quarantined app の実行が許可された最初の時点で populated される、独立した provenance mechanism が導入されました。<sup>[[2]](#references)</sup> 2 つの artefacts が作成されます。

- `.app` bundle directory 上の `com.apple.provenance` xattr（primary key と flags を含む fixed-size binary value）。
- `/var/db/SystemPolicyConfiguration/ExecPolicy/` の ExecPolicy database 内にある `provenance_tracking` table の row。ここには app の cdhash と metadata が保存されます。

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

XProtectはmacOSに組み込まれた**アンチマルウェア**機能です。XProtectは、**アプリケーションが初めて起動されたとき、または変更されたときに、既知のマルウェアや安全でないファイルタイプのデータベースと照合します**。Safari、Mail、Messagesなどの特定のアプリを通じてファイルをダウンロードすると、XProtectは自動的にファイルをスキャンします。データベース内の既知のマルウェアと一致した場合、XProtectは**ファイルの実行を防止**し、脅威を警告します。

XProtectのデータベースは、Appleによって新しいマルウェア定義で**定期的に更新**され、これらの更新はMacに自動的にダウンロードおよびインストールされます。これにより、XProtectは既知の最新の脅威に対して常に最新の状態に保たれます。

ただし、**XProtectはフル機能のアンチウイルスソリューションではありません**。既知の脅威の特定のリストのみをチェックし、ほとんどのアンチウイルスソフトウェアのようなオンアクセススキャンは実行しません。

以下を実行すると、最新のXProtectの更新に関する情報を取得できます。
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect は SIP protected location の **/Library/Apple/System/Library/CoreServices/XProtect.bundle** にあります。bundle 内には、XProtect が使用する情報があります。

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: これらの cdhash を持つコードが legacy entitlements を使用することを許可します。
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: BundleID と TeamID によってロードが禁止されている、または minimum version を示す plugins と extensions のリストです。
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: malware を検出する Yara rules です。
- **`XProtect.bundle/Contents/Resources/gk.db`**: block された applications と TeamIDs の hashes を含む SQLite3 database です。

**/Library/Apple/System/Library/CoreServices/XProtect.app** には、XProtect に関連する別の App もありますが、Gatekeeper process には関与しません。

> XProtect Remediator: modern macOS では、Apple は on-demand scanners（XProtect Remediator）を提供しており、launchd 経由で定期的に実行され、malware の families を検出して remediation します。unified logs でこれらの scans を確認できます。
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Gatekeeper ではない

> [!CAUTION]
> Gatekeeper は、application を実行するたびに**実行されるわけではない**ことに注意してください。_**AppleMobileFileIntegrity**_（AMFI）は、Gatekeeper によってすでに実行・検証された app を実行するときに、**executable code signatures のみを verify** します。

そのため以前は、Gatekeeper で app を cache するために app を実行し、その後 **application の executable ではない files**（Electron の asar や NIB files など）を**変更**できました。ほかの protections が存在しない場合、application はその**malicious**な追加要素とともに**実行**されました。

しかし現在は、macOS が application bundles 内の **files の変更を防止する**ため、これは不可能です。したがって、[Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attack を試みても、Gatekeeper で cache するために app を実行した後は bundle を変更できないため、もはや abuse できません。また、たとえば exploit で示されているように Contents directory の名前を NotCon に変更し、その後 app の main binary を実行して Gatekeeper で cache しようとすると、error が発生して実行されません。

## Gatekeeper Bypasses

Gatekeeper を bypass する方法（Gatekeeper が disallow すべきものを user に download させて実行させることに成功する方法）は、macOS における vulnerability とみなされます。過去に Gatekeeper を bypass できた techniques に割り当てられた CVEs の一部を以下に示します。

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

**Archive Utility** を extraction に使用した場合、**886 characters を超える paths** を持つ files に com.apple.quarantine extended attribute が付与されないことが確認されました。この状況により、これらの files は意図せず **Gatekeeper の** security checks を**回避**できました。<sup>[[5]](#references)</sup>

詳細については、[**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) を確認してください。<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

**Automator** で application を作成すると、実行に必要な情報は executable 内ではなく `application.app/Contents/document.wflow` 内にあります。executable は **Automator Application Stub** と呼ばれる generic な Automator binary にすぎません。

そのため、`application.app/Contents/MacOS/Automator\ Application\ Stub` を、**system 内にある別の Automator Application Stub への symbolic link に設定**できます。これにより、実際の executable には quarantine xattr がないため、**Gatekeeper を trigger せずに** `document.wflow` 内の内容（あなたの script）が実行されます。<sup>[[6]](#references)</sup>

想定される location の例: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

詳細については、[**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) を確認してください。<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

この bypass では、`application.app` ではなく `application.app/Contents` から compress を開始するように zip file が作成されました。そのため、**quarantine attr** は **application.app/Contents 内のすべての files** に適用されましたが、Gatekeeper が check していた **`application.app`** には適用されませんでした。したがって、`application.app` が trigger されたときに **quarantine attribute がなかった**ため、Gatekeeper は bypass されました。<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
詳細については、[**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) を確認してください。<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

コンポーネントが異なる場合でも、この vulnerability の exploit は前のものと非常によく似ています。この場合、**`application.app/Contents`** から Apple Archive を生成するため、**`application.app`** は **Archive Utility** によって解凍された際に quarantine attr を取得しません。<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
詳細については、[**original report**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)を確認してください。<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`**を使用すると、誰もファイルの属性を書き込めないようにできます：
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
さらに、**AppleDouble** file format は、ファイルをその ACEs とともにコピーします。<sup>[[9]](#references)</sup>

[**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) では、**`com.apple.acl.text`** という xattr 内に保存された ACL のテキスト表現が、展開されたファイルの ACL として設定されることを確認できます。したがって、他の xattr が書き込まれるのを防ぐ ACL を持つアプリケーションを **AppleDouble** file format の zip file に圧縮すると、quarantine xattr はアプリケーションに設定されません：
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
詳細については、[**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)を参照してください。<sup>[[9]](#references)</sup>

これは AppleArchives でも exploit 可能である点に注意してください：
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

macOS内部の問題により、**Google Chromeがダウンロードしたファイルにquarantine attributeを設定していなかった**ことが発見されました。<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDoubleファイル形式では、ファイルのattributesを`._`で始まる別のファイルに保存します。これにより、**macOSマシン間でファイルのattributesをコピー**できます。しかし、AppleDoubleファイルを解凍した後、`._`で始まるファイルに**quarantine attributeが付与されていなかった**ことが確認されました。<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
隔離属性が設定されないファイルを作成できるため、**Gatekeeper を bypass することが可能でした。** その手法は、AppleDouble の命名規則（`._` で始める）を使用して **DMG file application** を作成し、隔離属性のないこの hidden file への sym link として **visible file** を作成するというものでした。\
**dmg file が実行されると**、隔離属性を持たないため、**Gatekeeper を bypass します。**
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

macOS Sonoma 14.0で修正されたGatekeeper bypassにより、細工されたアプリがプロンプトなしで実行される可能性がありました。詳細はパッチ適用後に公開され、この問題は修正前に実際の攻撃で悪用されていました。Sonoma 14.0以降がインストールされていることを確認してください。<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

macOS 14.4（2024年3月リリース）におけるGatekeeper bypassは、悪意のあるZIPを`libarchive`が処理する方法に起因し、アプリがassessmentを回避できる可能性がありました。Appleがこの問題に対処した14.4以降にアップデートしてください。<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

ダウンロードしたアプリに埋め込まれた**Automator Quick Action workflow**は、Gatekeeper assessmentを受けずに実行される可能性がありました。これは、workflowがデータとして扱われ、通常のnotarization promptの経路外でAutomator helperによって実行されていたためです。そのため、shell scriptを実行するQuick Action（例：`Contents/PlugIns/*.workflow/Contents/document.wflow`内）をバンドルした細工済みの`.app`は、起動時に直ちに実行される可能性がありました。Appleは追加の同意ダイアログを導入し、Ventura **13.7**、Sonoma **14.7**、Sequoia **15**でassessmentの経路を修正しました。<sup>[[3]](#references)</sup>

### Third‑party unarchiversによるquarantineの誤った伝播（2023–2024）

一般的な複数のextraction tool（例：The Unarchiver）に存在する脆弱性により、アーカイブから展開されたファイルに`com.apple.quarantine` xattrが付与されず、Gatekeeper bypassの機会が生じていました。テスト時は常にmacOS Archive Utilityまたはパッチ適用済みのツールを使用し、展開後にxattrを検証してください。

### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- アプリを含むディレクトリを作成します。
- アプリにuchgを追加します。
- アプリをtar.gzファイルに圧縮します。
- tar.gzファイルを被害者に送信します。
- 被害者がtar.gzファイルを開き、アプリを実行します。
- Gatekeeperはアプリをチェックしません。<sup>[[12]](#references)</sup>

### Quarantine xattrの防止

".app" bundleにquarantine xattrが追加されていない場合、それを実行しても**Gatekeeperはトリガーされません**。

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
- [13] [Apple: About the security content of macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)

{{#include ../../../banners/hacktricks-training.md}}
