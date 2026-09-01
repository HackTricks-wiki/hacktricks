# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** は、Mac オペレーティングシステム向けに開発されたセキュリティ機能であり、ユーザーがシステム上で **信頼できるソフトウェアのみを実行する** ように設計されています。これは、ユーザーが **App Store 以外のソース** からダウンロードして開こうとするソフトウェア（アプリ、プラグイン、インストーラパッケージなど）を **検証** することで機能します。

Gatekeeper の主要な仕組みは **検証** プロセスです。ダウンロードしたソフトウェアが **認証された開発者によって署名されているか** を確認し、そのソフトウェアの真正性を保証します。さらに、そのソフトウェアが **Apple によって notarised されているか** を確認し、既知の悪意あるコンテンツが含まれておらず、notarisation 後に改ざんされていないことを確かめます。

また、Gatekeeper は、ダウンロードしたソフトウェアを初めて開く際に **ユーザーへ開くことの承認を求める** ことで、ユーザーによる制御とセキュリティを強化します。この保護機能により、無害なデータファイルだと誤認した可能性のある、潜在的に有害な実行可能コードをユーザーが誤って実行することを防止できます。

### Application Signatures

Application signatures（code signatures とも呼ばれます）は、Apple のセキュリティインフラストラクチャにおける重要な要素です。これらは **ソフトウェア作成者（開発者）の身元を検証** し、最後に署名されてからコードが改ざんされていないことを保証するために使用されます。

仕組みは次のとおりです。

1. **Signing the Application:** 開発者がアプリケーションを配布する準備が整うと、**private key を使用してアプリケーションに署名します**。この private key は、開発者が Apple Developer Program に登録した際に **Apple が開発者へ発行する certificate に関連付けられています**。署名プロセスでは、アプリのすべての部分から cryptographic hash を作成し、この hash を開発者の private key で暗号化します。
2. **Distributing the Application:** 署名されたアプリケーションは、対応する public key を含む開発者の certificate とともにユーザーへ配布されます。
3. **Verifying the Application:** ユーザーがアプリケーションをダウンロードして実行しようとすると、Mac オペレーティングシステムは開発者の certificate に含まれる public key を使用して hash を復号します。次に、アプリケーションの現在の状態に基づいて hash を再計算し、これを復号された hash と比較します。一致した場合、**開発者が署名してからアプリケーションが変更されていない** ことを意味し、システムはアプリケーションの実行を許可します。

Application signatures は、Apple の Gatekeeper technology に不可欠な要素です。ユーザーが **インターネットからダウンロードしたアプリケーションを開こうとすると**、Gatekeeper は application signature を検証します。Apple が既知の開発者に発行した certificate で署名されており、コードが改ざんされていなければ、Gatekeeper はアプリケーションの実行を許可します。それ以外の場合、アプリケーションをブロックしてユーザーに警告します。

macOS Catalina 以降、**Gatekeeper はアプリケーションが Apple によって notarized されているかどうかも確認します**。これにより、セキュリティがさらに強化されます。notarization プロセスでは、既知のセキュリティ問題や malicious code がないかアプリケーションを確認します。これらのチェックに合格すると、Apple はアプリケーションに ticket を追加し、Gatekeeper が検証できるようにします。

#### Check Signatures

**malware sample** を確認する際は、バイナリの **signature を必ず確認してください**。署名した **developer** がすでに **malware と関連している** 可能性があるためです。
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

Appleのnotarizationプロセスは、潜在的に有害なsoftwareからユーザーを保護するための追加の安全対策として機能します。これは、**developerが自身のapplicationを検査のために提出すること**を意味し、検査は**Apple's Notary Service**によって行われます。これはApp Reviewと混同しないでください。このserviceは**automated system**であり、提出されたsoftwareに**malicious content**が含まれていないか、またcode-signingに潜在的な問題がないかを精査します。

softwareがこの検査に**合格**し、問題が見つからなかった場合、Notary Serviceはnotarization ticketを生成します。その後、developerはこの**ticketをsoftwareに添付する**必要があります。このプロセスは「stapling」と呼ばれます。さらに、notarization ticketはonlineにも公開され、Gatekeeper（Appleのsecurity technology）がアクセスできるようになります。

ユーザーがsoftwareを初めてinstallまたは実行すると、notarization ticketが存在すること（executableにstapleされている場合でも、onlineで見つかった場合でも）により、**softwareがAppleによってnotarizedされていることをGatekeeperに通知します**。その結果、Gatekeeperは初回起動dialogに説明メッセージを表示し、そのsoftwareがAppleによってmalicious contentの検査を受けたことを示します。このプロセスにより、ユーザーがsystemにinstallまたは実行するsoftwareのsecurityに対する信頼性が高まります。

### spctl & syspolicyd

> [!CAUTION]
> Sequoia version以降、**`spctl`**ではGatekeeper configurationを変更できなくなったことに注意してください。

**`spctl`**は、Gatekeeper（XPC messagesを介して`syspolicyd` daemonと通信）を列挙および操作するためのCLI toolです。例えば、以下のコマンドで**GateKeeperのstatus**を確認できます。
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> GateKeeper の signature checks は、すべてのファイルではなく、**Quarantine attribute を持つファイル**に対してのみ実行されます。

GateKeeper は、**preferences と signature** に従って binary を実行できるかどうかを確認します。

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** は Gatekeeper の適用を担当する主要な daemon です。`/var/db/SystemPolicy` にある database を管理しており、[database をサポートするコードはこちら](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp)、[SQL template はこちら](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql)で確認できます。なお、この database は SIP による制限を受けず、root が書き込み可能です。また、他方の database が破損した場合に備え、`/var/db/.SystemPolicy-default` が元の backup として使用されます。

さらに、bundles **`/var/db/gke.bundle`** と **`/var/db/gkopaque.bundle`** には、database に挿入される rules を含むファイルがあります。root として次のコマンドを実行すると、この database を確認できます。
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
**`syspolicyd`** は、`assess`、`update`、`record`、`cancel` などの異なる操作を備えた XPC サーバーも公開しており、これらは **`Security.framework` の `SecAssessment*`** API を使用して到達することもでき、**`spctl`** は実際に XPC 経由で **`syspolicyd`** と通信します。

最初のルールが "**App Store**" で終わり、2 番目のルールが "**Developer ID**" で終わっていること、そして前のイメージでは **App Store と識別された開発元のアプリを実行できるようになっていた**ことに注目してください。\
その設定を App Store に**変更**すると、"**Notarized Developer ID" のルールは表示されなくなります**。

さらに、**タイプ GKE** のルールも何千件も存在します：
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
これらは次のファイルに含まれるハッシュです。

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

または、次のコマンドで以前の情報を一覧表示できます：
```bash
sudo spctl --list
```
**`spctl`** のオプション **`--master-disable`** と **`--global-disable`** は、これらの署名チェックを完全に **無効化** します。
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

**App が GateKeeper によって許可されるかを確認する**には、次を使用できます：
```bash
spctl --assess -v /Applications/App.app
```
macOS 14以降では、**`syspolicy_check`**はアプリケーションバンドルの配布前チェックに役立つ、より高レベルなツールです。単純な`spctl`の結果よりも、trusted executionに関する実用的な診断情報を提供しますが、Appleは実際のダウンロード、展開、初回起動の経路でテストすることも推奨しています。これはquarantineの伝播も検証するためです。<sup>[[14]](#references)</sup>
```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
```
GateKeeper に新しいルールを追加して、特定のアプリの実行を許可することが可能です:
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
**kernel extensions** に関しては、`/var/db/SystemPolicyConfiguration` フォルダに、ロードを許可された kext のリストを含むファイルがあります。さらに、`spctl` には `com.apple.private.iokit.nvram-csr` entitlement があります。これは、新たに事前承認された kernel extensions を追加でき、それらを `kext-allowed-teams` key の NVRAM にも保存する必要があるためです。

#### Managing Gatekeeper on macOS 15 (Sequoia) and later

- 長年利用されてきた Finder の **Ctrl+Open / 右クリック → Open** による bypass は削除されました。ユーザーは、最初の block dialog の後、**System Settings → Privacy & Security → Open Anyway** から block された app を明示的に許可する必要があります。<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` は、unattended policy changes として受け付けられなくなりました。rule database または global assessment state を変更する操作は deprecated となっているため、assessment には `spctl` を使用し、enforcement は UI または MDM で設定してください。

macOS 15 Sequoia 以降、end users は `spctl` から Gatekeeper policy を切り替えられなくなりました。Management は System Settings を使用するか、`com.apple.systempolicy.control` payload を含む MDM configuration profile を deploy して実行します。以下は、App Store と identified developers を許可する（ただし **"Anywhere"** は許可しない）profile snippet の例です。

<details>
<summary>MDM profile to allow App Store and identified developers</summary>
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

アプリケーションまたはファイルを**ダウンロード**すると、Webブラウザやメールクライアントなどの特定のmacOS **applications**は、一般に「**quarantine flag**」として知られる**拡張ファイル属性**をダウンロードしたファイルに付加します。この属性は、**ファイルに印を付ける**セキュリティ対策として機能し、そのファイルが信頼できないソース（インターネット）から取得されたものであり、潜在的なリスクを含む可能性があることを示します。ただし、すべてのアプリケーションがこの属性を付加するわけではありません。たとえば、一般的なBitTorrent client softwareは通常、この処理をバイパスします。

**quarantine flagの存在は、ユーザーがファイルを実行しようとした際にmacOSのGatekeeper security featureを作動させます**。

**quarantine flagが存在しない場合**（一部のBitTorrent clients経由でダウンロードされたファイルなど）、Gatekeeperの**checksが実行されない可能性があります**。したがって、ユーザーは安全性の低い、または未知のソースからダウンロードしたファイルを開く際に注意する必要があります。

> [!NOTE] > **code signaturesの** **validity**を**checking**する処理は、コードとそのすべてのbundled resourcesの暗号学的**hashes**を生成する処理を含む、**resource-intensive**なプロセスです。さらに、certificate validityのcheckingでは、発行後に失効していないかを確認するため、Appleのサーバーに対して**online check**を実行する必要があります。これらの理由から、完全なcode signatureおよびnotarization checkを**アプリの起動時に毎回実行するのは実用的ではありません**。
>
> そのため、これらのchecksは**quarantined attributeを持つアプリを実行するときにのみ実行されます**。

> [!WARNING]
> この属性は、ファイルを作成またはダウンロードする**applicationによって設定される必要があります**。
>
> ただし、sandboxedされたファイルは、作成するすべてのファイルにこの属性が設定されます。また、non sandboxed appsは自分で設定することも、[**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) keyを**Info.plist**で指定することもできます。これにより、システムは作成されたファイルに`com.apple.quarantine` extended attributeを設定します。

さらに、**`qtn_proc_apply_to_self`**を呼び出すprocessによって作成されたすべてのファイルはquarantinedになります。また、API **`qtn_file_apply_to_path`**は、指定されたfile pathにquarantine attributeを追加します。

**statusを確認し、enable/disableする**（root required）ことが可能です:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
また、ファイルに **quarantine extended attribute** があるか確認できます：
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
**extended** **attributes** の **value** を確認し、次のコマンドで quarantine attr を書き込んだ app を特定します。
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
# 00c1 -- The user has been allowed to execute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
実際、プロセスは「作成するファイルに quarantine フラグを設定できる」可能性があります（作成したファイルに USER_APPROVED フラグを適用しようとしましたが、適用できませんでした）。

<details>

<summary>quarantine フラグを適用するソースコード</summary>
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

そして、次のコマンドでその属性を**削除**します：
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
また、次の方法ですべての隔離されたファイルを見つけます：
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine情報は、LaunchServicesによって管理される中央データベース **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** にも保存されます。これにより、GUIはファイルの取得元に関するデータを取得できます。さらに、取得元を隠すことに関心のあるアプリケーションによって、この情報が上書きされる可能性があります。また、これはLaunchServices APIsから実行できます。

#### **libquarantine.dylib**

このlibraryは、extended attribute fieldsを操作できる複数のfunctionsをexportします。

`qtn_file_*` APIsはfile quarantine policiesを扱い、`qtn_proc_*` APIsはprocess（そのprocessによって作成されたfiles）に適用されます。unexportedな`__qtn_syscall_quarantine*` functionsは、`mac_syscall`のfirst argumentに"Quarantine"を指定してrequestsを`Quarantine.kext`へ送信し、policiesを適用します。

#### **Quarantine.kext**

このkernel extensionは、system上の**kernel cacheからのみ**利用できます。ただし、[**https://developer.apple.com/**](https://developer.apple.com/)から**Kernel Debug Kitをdownload**できます。これには、symbolicated versionのextensionが含まれています。

このKextはMACF経由で複数のcallsにhookし、file lifecycle events（Creation、opening、renaming、hard-linkingなど）をすべてtrapします。さらに、`com.apple.quarantine` extended attributeの設定を防ぐため、`setxattr`もtrapします。

また、いくつかのMIBsも使用します。

- `security.mac.qtn.sandbox_enforce`: Sandboxとともにquarantineをenforceする
- `security.mac.qtn.user_approved_exec`: Querantined procsはapproved filesのみexecuteできる

#### Provenance xattr（Ventura以降）

macOS 13 Venturaでは、quarantined appの実行が初めて許可されたときに設定される、独立したprovenance mechanismが導入されました。<sup>[[2]](#references)</sup> 2つのartefactsが作成されます。

- `.app` bundle directory上の`com.apple.provenance` xattr（primary keyとflagsを含む固定サイズのbinary value）。
- `/var/db/SystemPolicyConfiguration/ExecPolicy/`のExecPolicy database内の`provenance_tracking` tableに保存される、appのcdhashとmetadataを含むrow。

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

XProtectはmacOSに組み込まれた**anti-malware**機能です。XProtectは、**初めて起動または変更されたアプリケーションを、既知のmalwareおよび安全でないファイルタイプのデータベースと照合します**。Safari、Mail、Messagesなどの特定のアプリを通じてファイルをダウンロードすると、XProtectはそのファイルを自動的にスキャンします。データベース内の既知のmalwareと一致した場合、XProtectは**ファイルの実行を阻止し**、脅威を警告します。

XProtectのデータベースは、Appleによって新しいmalware定義で**定期的に更新**され、これらの更新はMacに自動的にダウンロードおよびインストールされます。これにより、XProtectは既知の最新の脅威に対して常に最新の状態に保たれます。

ただし、**XProtectはフル機能のantivirusソリューションではありません**。特定の既知の脅威リストのみをチェックし、ほとんどのantivirusソフトウェアのようなオンアクセススキャンは実行しません。

次を実行すると、最新のXProtect更新に関する情報を取得できます：
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtectはSIPで保護された場所 **/Library/Apple/System/Library/CoreServices/XProtect.bundle** にあります。バンドル内には、XProtectが使用する情報が含まれています。

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: これらのcdhashを持つコードによるlegacy entitlementsの使用を許可します。
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: BundleIDとTeamIDによってロードを禁止するプラグインおよび拡張機能、または必要な最小バージョンを示す一覧です。
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: malwareを検出するYara rulesです。
- **`XProtect.bundle/Contents/Resources/gk.db`**: ブロックされたアプリケーションとTeamIDのhashを含むSQLite3 databaseです。

**`/Library/Apple/System/Library/CoreServices/XProtect.app`** にもXProtect関連の別のAppがありますが、Gatekeeper processには関与していません。

> XProtect Remediator: modern macOSでは、Appleは定期的にlaunchd経由で実行され、malwareのfamilyを検出してremediateするon-demand scanner（XProtect Remediator）を提供しています。これらのscanはunified logsで確認できます。
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Gatekeeperではないもの

> [!CAUTION]
> Gatekeeperはアプリケーションを実行するたびに実行されるわけではありません。アプリがGatekeeperによってすでに実行および検証されている場合、_**AppleMobileFileIntegrity**_（AMFI）は実行時に**executable code signaturesのみを検証**します。

そのため、以前はアプリを実行してGatekeeperでcacheし、その後アプリケーション内の**executableではないファイル**（ElectronのasarやNIB filesなど）を**modify**することが可能でした。他のprotectionsが存在しなければ、アプリケーションは**malicious**な追加要素とともに**実行**されました。

しかし現在は、macOSがapplication bundles内のファイルの**modifyingを防止**するため、これは不可能です。したがって、[Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attackを試すと、Gatekeeperでcacheするためにアプリを実行した後はbundleをmodifyできないため、もはやabuseできないことが分かります。さらに、exploitで示されているように、たとえばContents directoryの名前をNotConに変更し、その後アプリのmain binaryを実行してGatekeeperでcacheしようとすると、errorがtriggerされ、実行されません。

## Gatekeeper Bypasses

Gatekeeperをbypassする方法（Gatekeeperがdisallowすべきものをuserにdownloadさせて実行させることに成功する方法）は、macOSのvulnerabilityと見なされます。過去にGatekeeperのbypassを可能にしたtechniqueには、次のCVEが割り当てられています。

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

**Archive Utility**をextractionに使用すると、**886 charactersを超えるpath**を持つfilesにはcom.apple.quarantine extended attributeが付与されないことが確認されました。この状況により、それらのfilesは意図せずGatekeeperのsecurity checksを**circumvent**できます。<sup>[[5]](#references)</sup>

詳細については[**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)を確認してください。<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

**Automator**でapplicationを作成すると、実行に必要な情報はexecutableではなく`application.app/Contents/document.wflow`内に保存されます。executableは、**Automator Application Stub**というgenericなAutomator binaryにすぎません。

そのため、`application.app/Contents/MacOS/Automator\ Application\ Stub`を、**system内にある別のAutomator Application Stubへのsymbolic link**にすることで、実際のexecutableにはquarantine xattrがないため、Gatekeeperをtriggerせずに`document.wflow`内の内容（your script）を実行できました。<sup>[[6]](#references)</sup>

想定されるlocationの例: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

詳細については[**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper)を確認してください。<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

このbypassでは、`application.app`ではなく`application.app/Contents`からcompressを開始する形でzip fileが作成されました。そのため、**quarantine attr**は**`application.app/Contents`内のすべてのfiles**に適用されましたが、Gatekeeperがcheckしていた**`application.app`**には適用されませんでした。つまり、`application.app`がtriggerされたときに**quarantine attributeを持っていなかった**ため、Gatekeeperがbypassされました。<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
詳細については、[**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) を確認してください。<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

コンポーネントは異なりますが、この脆弱性のexploitは前のものと非常によく似ています。この場合、**`application.app/Contents`** からApple Archiveを生成するため、**`application.app`** は **Archive Utility** によって展開された際にquarantine属性を取得しません。<sup>[[8]](#references)</sup>
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
さらに、**AppleDouble** ファイル形式は、ACEs を含めてファイルをコピーします。<sup>[[9]](#references)</sup>

[**ソースコード**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) では、**`com.apple.acl.text`** という xattr 内に保存された ACL のテキスト表現が、展開されたファイルの ACL として設定されることを確認できます。したがって、他の xattr が書き込まれるのを防ぐ ACL を設定した **AppleDouble** ファイル形式でアプリケーションを zip ファイルに圧縮すると、quarantine xattr はアプリケーションに設定されませんでした。
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
詳細については、[**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) を確認してください。<sup>[[9]](#references)</sup>

これは AppleArchives を使っても exploit できることに注意してください：
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

macOS内部の問題により、**Google Chromeがダウンロードしたファイルにquarantine attributeを設定していなかった**ことが発見されました。<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDoubleは、ファイル名が`._`で始まる別のファイルにファイルの属性を保存します。これは、ファイル属性を**macOSマシン間で**コピーするのに役立ちます。しかし、AppleDoubleファイルを解凍した後、`._`で始まるファイルに**quarantine attributeが付与されていませんでした**。<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```
隔離属性が設定されないファイルを作成できたため、**Gatekeeper をバイパスすることが可能でした。** その手法は、AppleDouble の命名規則（`._` で始める）を使用して **DMG ファイルのアプリケーション**を作成し、隔離属性のないこの隠しファイルへのシンボリックリンクとして **表示されるファイル**を作成するというものでした。\
**dmg ファイルが実行される**と、隔離属性が設定されていないため、**Gatekeeper をバイパスします。**
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

Apple は、チェックを改善することで macOS Sonoma 14.0 における LaunchServices のロジックエラーを修正しました。公開された advisory では、app が Gatekeeper を bypass できる可能性があるとだけ記載されているため、CVE エントリだけから特定の carrier format や exploitation chain を推測しないでください。<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

macOS 14.4（2024 年 3 月リリース）における Gatekeeper bypass は、悪意のある ZIP の `libarchive` による処理に起因し、app が assessment を回避できるものでした。この問題が修正されている 14.4 以降に update してください。<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

ダウンロードした app に埋め込まれた **Automator Quick Action workflow** は、Gatekeeper assessment を受けずに trigger できました。これは、workflow が data として扱われ、通常の notarization prompt path の外側で Automator helper によって実行されていたためです。そのため、shell script を実行する Quick Action（例: `Contents/PlugIns/*.workflow/Contents/document.wflow` 内）を bundling した crafted `.app` は、launch 時に直ちに実行される可能性がありました。Apple は追加の consent dialog を導入し、Ventura **13.7**、Sonoma **14.7**、および Sequoia **15** で assessment path を修正しました。<sup>[[3]](#references)</sup>

### Quarantine propagation failures at extraction and copy boundaries

2024 年の study では、テスト対象となった iZip（ZIP/TAR/7Z）、Archiver（ARCHIVER/ZIP/TAR/7Z）、BetterZip（ZIP/TAR/7Z）、WinRAR（ZIP/TAR/7Z）、および 7z Utility（DMG/ZIP/7Z）で propagation gap が確認されました。また、VMware Tools の host-to-guest copy 中に attribute が失われることも確認されています。その後、複数の vendor が fix を発表しているため、これらの名前は恒久的な vulnerable-software list ではなく、**version-specific retesting** の手がかりとして扱ってください。同じ trust-boundary problem は native Unix workflow にも当てはまります。`curl`/`scp` は quarantine を追加せず、command-line の `tar`/`unzip` は carrier archive から quarantine を自動的に inherit しません。<sup>[[15]](#references)</sup>

offensive testing では、browser、mail client、archive、disk-image、cloud-sync、shared-folder、および VM-copy の **すべての** transition 後に、carrier と最終的な app を比較してください。明示的な `spctl` rejection では、欠落した xattr は修復されません。quarantine がなければ、通常の first-open Gatekeeper path でその assessment が request されない可能性があります。<sup>[[15]](#references)</sup>
```bash
# 1. Confirm the browser-downloaded carrier is quarantined
xattr -p com.apple.quarantine ./payload.zip

# 2. Extract/copy it through the application under test, then inspect the result
xattr -p com.apple.quarantine ./out/Payload.app || echo "QUARANTINE LOST"
spctl --assess --type execute -vv ./out/Payload.app

# 3. Enumerate every app bundle whose top-level directory lost the marker
find ./out -type d -name '*.app' -prune -exec sh -c \
'for app do xattr -p com.apple.quarantine "$app" >/dev/null 2>&1 || echo "$app"; done' sh {} +
```
### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- appを含むディレクトリを作成する。
- appにuchgを追加する。
- appをtar.gzファイルに圧縮する。
- tar.gzファイルを被害者に送信する。
- 被害者がtar.gzファイルを開き、appを実行する。
- Gatekeeperはappをチェックしない。<sup>[[12]](#references)</sup>

### Quarantine xattrを防止する

".app" bundleにquarantine xattrが追加されていない場合、それを実行しても**Gatekeeperはtriggerされません**。

extended attributesを防止または破棄できるfilesystem、flag、ACL、AppleDoubleベースのprimitiveについては、[macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks)を参照してください。



## References

- [1] [Apple Platform Security: macOS Sonoma 14.4のsecurity contentについて（CVE-2024-27853を含む）](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: macOSがappのprovenanceを追跡するようになった方法](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: macOS Sonoma 14.7 / Ventura 13.7のsecurity contentについて（CVE-2024-44128）](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 SequoiaがControl‑clickによる「Open」のGatekeeper bypassを削除](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: CVE-2021-1810の発見](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990、macOS Gatekeeperのbypass](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat LabsがGatekeeper bypassを可能にするSafari vulnerabilityを特定](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat LabsがGatekeeper bypassを可能にするmacOS Archive Utility vulnerability（CVE-2022-32910）を特定](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [GatekeeperのAchilles heel：macOS vulnerabilityを発掘](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure：Gatekeeper Bypass（CVE-2023-27943）の発見](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Mac Monitorの支援によるGatekeeper bypass exploitの発見と報告](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023：macOS Security and Privacy Mechanismsのbypass — GatekeeperからSystem Integrity Protectionまで（Koh Nakagawa）](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: macOS Sonoma 14のsecurity contentについて（CVE-2023-41067）](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: notarised productのtesting](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Gatekeeper Bypass — macOS security mechanismのweaknessesを発見](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}
