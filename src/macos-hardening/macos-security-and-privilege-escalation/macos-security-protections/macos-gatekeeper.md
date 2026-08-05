# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** は Mac オペレーティングシステム向けに開発されたセキュリティ機能で、ユーザーがシステム上で **信頼されたソフトウェアのみを実行する** ように設計されています。アプリ、プラグイン、インストーラーパッケージなど、ユーザーが **App Store 以外のソースから** ダウンロードして開こうとするソフトウェアを **検証** します。

Gatekeeper の中核となる仕組みは **検証** プロセスです。ダウンロードされたソフトウェアが **認証された開発者によって署名されているか** を確認し、そのソフトウェアの真正性を保証します。さらに、ソフトウェアが **Apple によって notarised されているか** を確認し、既知の悪意あるコンテンツが含まれておらず、notarisation 後に改ざんされていないことを確かめます。

また、Gatekeeper は、ダウンロードしたソフトウェアを初めて開く際に **ユーザーへ開くことの承認を求める** ことで、ユーザーによる制御とセキュリティを強化します。この保護機能により、無害なデータファイルだと誤認した可能性のある、潜在的に有害な実行可能コードをユーザーが不注意に実行することを防ぎます。

### Application Signatures

Application signatures は code signatures とも呼ばれ、Apple のセキュリティ基盤における重要な要素です。これは **ソフトウェア作成者**（開発者）の身元を **検証** し、最後に署名されてからコードが改ざんされていないことを保証するために使用されます。

仕組みは次のとおりです。

1. **Signing the Application:** 開発者がアプリケーションを配布する準備が整うと、**秘密鍵を使用してアプリケーションに署名します**。この秘密鍵は、開発者が Apple Developer Program に登録した際に **Apple が開発者へ発行する証明書** に関連付けられています。署名プロセスでは、アプリのすべての部分から暗号学的ハッシュを作成し、このハッシュを開発者の秘密鍵で暗号化します。
2. **Distributing the Application:** 署名されたアプリケーションは、対応する公開鍵を含む開発者の証明書とともにユーザーへ配布されます。
3. **Verifying the Application:** ユーザーがアプリケーションをダウンロードして実行しようとすると、Mac オペレーティングシステムは開発者の証明書に含まれる公開鍵を使用してハッシュを復号します。次に、アプリケーションの現在の状態に基づいてハッシュを再計算し、これを復号されたハッシュと比較します。一致した場合、**開発者が署名してからアプリケーションが変更されていない** ことを意味し、システムはアプリケーションの実行を許可します。

Application signatures は Apple の Gatekeeper 技術に不可欠な要素です。ユーザーが **インターネットからダウンロードしたアプリケーションを開こうとすると**、Gatekeeper はアプリケーションの署名を検証します。Apple が既知の開発者へ発行した証明書で署名されており、コードが改ざんされていなければ、Gatekeeper はアプリケーションの実行を許可します。それ以外の場合、アプリケーションをブロックしてユーザーに警告します。

macOS Catalina 以降、**Gatekeeper はアプリケーションが Apple によって notarized されているかどうかも確認します**。これにより、セキュリティがさらに強化されます。notarization プロセスでは、既知のセキュリティ問題や悪意のあるコードがないかアプリケーションを確認し、これらのチェックに合格すると、Apple は Gatekeeper が検証できる ticket をアプリケーションに追加します。

#### Check Signatures

**malware sample** を確認する際は、バイナリの **signature を必ず確認してください**。署名した **developer** がすでに **malware** と **関連している** 可能性があるためです。
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

Appleのnotarizationプロセスは、潜在的に有害なsoftwareからユーザーを保護するための追加の安全対策として機能します。これには、**developerが自身のapplicationを、Apple's Notary Serviceによる検査のためにsubmitすること**が含まれます。これはApp Reviewと混同しないでください。このserviceは**automated system**であり、submitされたsoftwareに**malicious content**が含まれていないか、またcode-signingに関する潜在的な問題がないかを精査します。

softwareが問題を起こさずにこの検査に**pass**すると、Notary Serviceはnotarization ticketを生成します。その後、developerはこのticketを自身のsoftwareに**attachする必要があります**。このprocessは「stapling」と呼ばれます。さらに、notarization ticketはonlineにも公開され、Appleのsecurity technologyであるGatekeeperがaccessできるようになります。

ユーザーがsoftwareを初めてinstallまたはexecuteする際、notarization ticketがexecutableにstapleされているか、onlineで見つかるかにかかわらず、**softwareがAppleによってnotarizedされていることをGatekeeperに通知します**。その結果、Gatekeeperはinitial launch dialogに説明メッセージを表示し、そのsoftwareがAppleによってmalicious contentの検査を受けたことを示します。このprocessにより、ユーザーがsystemにinstallまたはrunするsoftwareのsecurityに対する信頼が高まります。

### spctl & syspolicyd

> [!CAUTION]
> Sequoia version以降、**`spctl`**ではGatekeeper configurationを変更できなくなったことに注意してください。

**`spctl`**は、Gatekeeper（XPC messagesを介して`syspolicyd` daemonと通信）をenumerateおよび操作するためのCLI toolです。例えば、以下のコマンドで**GateKeeperのstatus**を確認できます。
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> GateKeeper の署名チェックは、すべてのファイルではなく、**Quarantine 属性を持つファイルに対してのみ**実行されることに注意してください。

GateKeeper は、**preferences と署名**に基づいてバイナリを実行できるかどうかをチェックします:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** は Gatekeeper の強制を担当する主要な daemon です。この daemon は `/var/db/SystemPolicy` にあるデータベースを管理しており、[database here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) でそのデータベースをサポートするコード、[SQL template here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql) で SQL template を確認できます。なお、このデータベースは SIP による制限を受けず、root が書き込み可能です。また、データベース `/var/db/.SystemPolicy-default` は、もう一方のデータベースが破損した場合に備えたオリジナルのバックアップとして使用されます。

さらに、**`/var/db/gke.bundle`** と **`/var/db/gkopaque.bundle`** には、データベースに挿入されるルールを含むファイルがあります。root として次のコマンドでこのデータベースを確認できます:
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
**`syspolicyd`** は、`assess`、`update`、`record`、`cancel` などの異なる操作を持つ XPC server も公開しており、これらには **`Security.framework` の `SecAssessment*`** APIs を使用してアクセスできます。また、**`spctl`** は実際に XPC 経由で **`syspolicyd`** と通信します。

最初の rule が "**App Store**" で終わり、2 番目の rule が "**Developer ID**" で終わっていること、そして前の image では **App Store と識別済みの developers からの apps の実行が有効になっていた**ことに注目してください。\
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
これらは以下から取得されたハッシュです：

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

以下を使用して、**App が GateKeeper によって許可されるか確認**できます：
```bash
spctl --assess -v /Applications/App.app
```
GateKeeperに新しいルールを追加して、特定のアプリの実行を許可できます。方法は以下のとおりです：
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
**kernel extensions** については、`/var/db/SystemPolicyConfiguration` フォルダーに、読み込みが許可された kext のリストを含むファイルがあります。さらに、`spctl` には `com.apple.private.iokit.nvram-csr` entitlement があります。これは、事前承認済みの新しい kernel extensions を追加でき、それらを `kext-allowed-teams` キーとして NVRAM にも保存する必要があるためです。

#### macOS 15（Sequoia）以降での Gatekeeper の管理

- 長年利用されてきた Finder の **Ctrl+Open / Right-click → Open** bypass は削除されました。ユーザーは、最初のブロックダイアログの後に **System Settings → Privacy & Security → Open Anyway** から、ブロックされたアプリを明示的に許可する必要があります。<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` は受け付けられなくなりました。`spctl` は実質的に assessment と label management の read-only ツールとなり、policy enforcement は UI または MDM を通じて設定します。

macOS 15 Sequoia 以降、end users は `spctl` から Gatekeeper policy を切り替えられなくなりました。Management は System Settings を使用するか、`com.apple.systempolicy.control` payload を含む MDM configuration profile を deploy して行います。以下は、App Store と identified developers を許可する（ただし「Anywhere」は許可しない）profile の例です。

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

アプリケーションまたはファイルを**ダウンロード**すると、Webブラウザやメールクライアントなどの特定の macOS **applications**は、一般に "**quarantine flag**" と呼ばれる**拡張ファイル属性**をダウンロードしたファイルに付加します。この属性は、**ファイルが信頼できないソース（インターネット）から取得されたものであり**、潜在的なリスクを含む可能性があることを**示す**セキュリティ対策として機能します。ただし、すべてのアプリケーションがこの属性を付加するわけではありません。たとえば、一般的な BitTorrent client software は通常、この処理を回避します。

**quarantine flag の存在は、ユーザーがファイルを実行しようとした際に macOS の Gatekeeper security feature を起動します**。

**quarantine flag が存在しない場合**（一部の BitTorrent clients 経由でダウンロードされたファイルなど）、Gatekeeper の**checks が実行されない可能性があります**。そのため、ユーザーは安全性の低い、または未知のソースからダウンロードしたファイルを開く際に注意する必要があります。

> [!NOTE] > **コード署名の** **有効性**を**確認**する処理は、コードとそのすべての bundled resources の暗号学的な**hashes**を生成する必要があるため、**リソースを大量に消費します**。さらに、certificate の有効性を確認するには、発行後に失効していないかを確認するため、Apple のサーバーに対して**オンライン check**を実行する必要があります。これらの理由から、完全な code signature と notarization の check を**アプリの起動時に毎回実行するのは現実的ではありません**。
>
> したがって、これらの check は**quarantined attribute が付いた apps を実行するときにのみ実行されます**。

> [!WARNING]
> この属性は、**ファイルを作成またはダウンロードする application によって設定される必要があります**。
>
> ただし、sandboxed のファイルには、作成するすべてのファイルにこの属性が設定されます。また、non sandboxed apps は自分で設定することも、[**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) key を **Info.plist** に指定することもできます。これにより、システムは作成されたファイルに `com.apple.quarantine` extended attribute を設定します。

さらに、**`qtn_proc_apply_to_self`** を呼び出す process によって作成されたすべてのファイルは quarantined になります。また、API **`qtn_file_apply_to_path`** は、指定された file path に quarantine attribute を追加します。

次のコマンドで、**status の確認と enable/disable**（root required）が可能です。
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
次のコマンドで、ファイルに quarantine extended attribute があるかどうかも **確認できます**:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
次のコマンドで **extended** **attributes** の **value** を確認し、quarantine attr を書き込んだ app を特定します:
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
実際には、プロセスは「作成するファイルに quarantine flags を設定できる」（作成したファイルに USER_APPROVED flag を適用しようとしましたが、適用できませんでした）:

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

そして、次のコマンドでその属性を**削除**します。
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
また、次のコマンドですべての隔離されたファイルを検索します：
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine情報は、LaunchServicesが管理する中央データベース **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** にも保存されており、GUIはこれを使ってファイルの取得元に関するデータを取得できます。さらに、取得元を隠したいアプリケーションによって、この情報が上書きされる可能性があります。また、これはLaunchServices APIから実行できます。

#### **libquarantine.dylib**

このライブラリは、extended attributeフィールドを操作できる複数の関数をエクスポートします。

`qtn_file_*` APIはファイルのQuarantineポリシーを扱い、`qtn_proc_*` APIはプロセス（そのプロセスが作成したファイル）に適用されます。エクスポートされていない`__qtn_syscall_quarantine*`関数は、ポリシーを適用する関数であり、最初の引数に"Quarantine"を指定して`mac_syscall`を呼び出し、リクエストを`Quarantine.kext`に送信します。

#### **Quarantine.kext**

このkernel extensionはシステム上の**kernel cacheからのみ利用可能**です。ただし、[**https://developer.apple.com/**](https://developer.apple.com/)から**Kernel Debug Kitをダウンロード**できます。これには、extensionのsymbolicated versionが含まれています。

このKextはMACFを介して複数の呼び出しにhookし、ファイルのライフサイクルイベント（作成、オープン、名前変更、hard-linkningなど）をすべてtrapします。さらに、`setxattr`による`com.apple.quarantine` extended attributeの設定も防止します。

また、いくつかのMIBも使用します。

- `security.mac.qtn.sandbox_enforce`: SandboxとともにQuarantineを強制
- `security.mac.qtn.user_approved_exec`: Querantinedプロセスは承認済みファイルのみ実行可能

#### Provenance xattr (Ventura and later)

macOS 13 Venturaでは、Quarantineされたアプリの実行が初めて許可されたときに設定される、独立したprovenanceメカニズムが導入されました。<sup>[[2]](#references)</sup> 2つのartefactが作成されます。

- `.app` bundleディレクトリ上の`com.apple.provenance` xattr（primary keyとflagsを含む固定サイズのbinary value）。
- `/var/db/SystemPolicyConfiguration/ExecPolicy/`のExecPolicyデータベース内にある`provenance_tracking`テーブルの行。アプリのcdhashとmetadataが保存されます。

実用例:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtectは、macOSに組み込まれた**anti-malware**機能です。XProtectは、**アプリケーションが初めて起動されたとき、または変更されたときに、既知のmalwareおよび安全でないファイルタイプのデータベースと照合します**。Safari、Mail、Messagesなどの特定のアプリを通じてファイルをダウンロードすると、XProtectはそのファイルを自動的にスキャンします。データベース内の既知のmalwareと一致した場合、XProtectは**ファイルの実行を阻止し**、脅威を警告します。

XProtectのデータベースは、Appleによって新しいmalware定義で**定期的に更新**され、これらの更新はMacに自動的にダウンロードおよびインストールされます。これにより、XProtectは既知の最新の脅威に常に対応できます。

ただし、**XProtectは完全な機能を備えたantivirus solutionではありません**。特定の既知の脅威のリストのみをチェックし、ほとんどのantivirus softwareのようなon-access scanningは実行しません。

次のコマンドを実行すると、最新のXProtect updateに関する情報を取得できます。
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtectはSIPで保護された場所 **/Library/Apple/System/Library/CoreServices/XProtect.bundle** にあります。bundle内には、XProtectが使用する情報があります。

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: これらのcdhashを持つcodeにlegacy entitlementsの使用を許可します。
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: BundleIDとTeamIDによってloadを許可しないpluginsとextensions、またはminimum versionを示す一覧です。
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: malwareを検出するYara rulesです。
- **`XProtect.bundle/Contents/Resources/gk.db`**: blockされたapplicationsとTeamIDsのhashを含むSQLite3 databaseです。

**/Library/Apple/System/Library/CoreServices/XProtect.app** には、XProtectに関連する別のAppもありますが、Gatekeeper processには関係しません。

> XProtect Remediator: modern macOSでは、Appleはon-demand scanners（XProtect Remediator）を提供しており、launchd経由で定期的に実行され、malwareのfamilyをdetectしてremediateします。これらのscanはunified logsで確認できます。
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Gatekeeperではないもの

> [!CAUTION]
> Gatekeeperはapplicationをexecuteするたびに**実行されるわけではありません**。_**AppleMobileFileIntegrity**_だけが、Gatekeeperによってすでにexecuteおよびverifyされたappをexecuteするときに、**executable code signaturesをverify**します。

そのため以前は、まずGatekeeperでcacheされるようにappをexecuteし、その後applicationの**実行可能ではないfile**（ElectronのasarやNIB filesなど）を**modify**することが可能でした。他のprotectionが存在しなければ、applicationは**malicious**な追加要素を含んだ状態で**execute**されました。

しかし現在は、macOSがapplications bundles内の**filesのmodifyを防止する**ため、これは不可能です。したがって、[Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) attackを試すと、Gatekeeperでcacheするためにappをexecuteした後はbundleをmodifyできないため、もはやabuseできないことが分かります。また、exploitで示されているように、たとえばContents directoryの名前をNotConに変更してから、appのmain binaryをexecuteしてGatekeeperでcacheしようとすると、errorが発生してexecuteされません。

## Gatekeeper Bypasses

Gatekeeperをbypassする方法（Gatekeeperがdisallowすべきものをuserにdownloadさせてexecuteさせること）は、macOSのvulnerabilityとみなされます。過去にGatekeeperのbypassを可能にしたtechniqueには、次のCVEが割り当てられています。

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

**Archive Utility**をextractionに使用すると、**886文字を超えるpaths**を持つfilesにはcom.apple.quarantine extended attributeが付与されないことが確認されました。この状況により、これらのfilesは意図せずGatekeeperのsecurity checksを**circumvent**できます。<sup>[[5]](#references)</sup>

詳細については[**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)を確認してください。

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

**Automator**でapplicationを作成すると、executeに必要な情報はexecutable内ではなく、`application.app/Contents/document.wflow`内に格納されます。executableは、**Automator Application Stub**というgenericなAutomator binaryにすぎません。

そのため、`application.app/Contents/MacOS/Automator\ Application\ Stub`を、**system内にある別のAutomator Application Stubへのsymbolic link**にすることで、実際のexecutableにquarantine xattrがないため、Gatekeeperを**triggerせずに**`document.wflow`内の内容（your script）をexecuteできます。<sup>[[6]](#references)</sup>

Example os expected location: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

詳細については[**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper)を確認してください。

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

このbypassでは、`application.app`ではなく`application.app/Contents`からcompressを開始するようにzip fileが作成されました。そのため、**quarantine attr**は**`application.app/Contents`内のすべてのfiles**に適用されましたが、Gatekeeperがcheckしていた**`application.app`**には適用されませんでした。つまり、`application.app`がtriggerされたときに**quarantine attributeがなかった**ため、Gatekeeperがbypassされました。<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
詳細については、[**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) を確認してください。

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

コンポーネントは異なりますが、この脆弱性の exploitation は前のものと非常によく似ています。この場合、**`application.app/Contents`** から Apple Archive を生成するため、**`application.app`** は **Archive Utility** によって decompressed されたときに quarantine attr を取得しません。<sup>[[8]](#references)</sup>
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
さらに、**AppleDouble** ファイル形式では、ACEs を含むファイルがコピーされます。<sup>[[9]](#references)</sup>

[**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) では、**`com.apple.acl.text`** という xattr 内に保存された ACL のテキスト表現が、展開されたファイルの ACL として設定されることを確認できます。したがって、他の xattr の書き込みを防止する ACL を付与したアプリケーションを **AppleDouble** ファイル形式の zip ファイルに圧縮すると、quarantine xattr はアプリケーションに設定されません。
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

macOS内部の問題により、**Google Chromeがダウンロードしたファイルにquarantine attributeを設定していなかった**ことが発見されました。<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble file formatsは、ファイルのattributesを`._`で始まる別のファイルに保存します。これにより、**macOSマシン間でファイルのattributesをコピー**できます。しかし、AppleDouble fileをdecompressした後、`._`で始まるファイルに**quarantine attributeが付与されていなかった**ことが確認されました。<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
quarantine attribute が設定されないファイルを作成できたため、**Gatekeeper を bypass することが可能でした。** その手法は、AppleDouble の命名規則（`._` で始める）を使用して **DMG file application** を作成し、quarantine attribute のないこの hidden file への **sym link として visible file** を作成するというものでした。\
**dmg file を実行すると**、quarantine attribute がないため **Gatekeeper を bypass します。**
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

macOS Sonoma 14.0で修正されたGatekeeper bypassにより、細工されたappをプロンプトなしで実行できました。詳細はパッチ適用後に公開され、この問題は修正前に実際の攻撃で悪用されていました。Sonoma 14.0以降がインストールされていることを確認してください。

### [CVE-2024-27853]

macOS 14.4（2024年3月リリース）におけるGatekeeper bypassは、悪意のあるZIPの`libarchive`による処理に起因し、appがassessmentを回避できるものでした。この問題はAppleが対処した14.4以降に更新してください。<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

ダウンロードしたappに埋め込まれた**Automator Quick Action workflow**は、Gatekeeperのassessmentなしで実行される可能性がありました。これは、workflowがdataとして扱われ、通常のnotarization prompt経路の外部でAutomator helperによって実行されていたためです。そのため、shell scriptを実行するQuick Action（例：`Contents/PlugIns/*.workflow/Contents/document.wflow`内）をバンドルした細工済みの`.app`は、起動時に直ちに実行される可能性がありました。Appleは追加のconsent dialogを導入し、Ventura **13.7**、Sonoma **14.7**、Sequoia **15**でassessment経路を修正しました。<sup>[[3]](#references)</sup>

### Third‑party unarchiversによるquarantineの誤った伝播（2023–2024）

一般的な複数のextraction tool（例：The Unarchiver）の脆弱性により、archiveからextractionされたfileに`com.apple.quarantine` xattrが付与されず、Gatekeeper bypassの機会が生じました。testing時は必ずmacOS Archive Utilityまたはパッチ適用済みのtoolを使用し、extraction後にxattrを検証してください。

### uchg（この[talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)より）

- appを含むdirectoryを作成します。
- appにuchgを追加します。
- appをtar.gz fileにcompressします。
- tar.gz fileをvictimに送信します。
- victimがtar.gz fileを開き、appを実行します。
- Gatekeeperはappをcheckしません。<sup>[[12]](#references)</sup>

### Quarantine xattrを防止する

".app" bundleにquarantine xattrが追加されていない場合、それを実行しても**Gatekeeperはtriggerされません**。


## References

- [1] [Apple Platform Security：macOS Sonoma 14.4のsecurity content（CVE-2024-27853を含む）](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light：macOSがappのprovenanceを追跡する方法](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple：macOS Sonoma 14.7 / Ventura 13.7のsecurity content（CVE-2024-44128）](https://support.apple.com/en-us/121234)
- [4] [MacRumors：macOS 15 SequoiaがControl‑clickによる「Open」Gatekeeper bypassを削除](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)
- [5] [WithSecure Labs：CVE-2021-1810の発見](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990、macOS Gatekeeperのbypass](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat LabsがGatekeeper bypassを可能にするSafari vulnerabilityを特定](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat LabsがGatekeeper bypassを可能にするmacOS Archive Utility vulnerability（CVE-2022-32910）を特定](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [GatekeeperのAchilles heel：macOS vulnerabilityの発掘](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure：Gatekeeper Bypass（CVE-2023-27943）の発見](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Mac Monitorの支援によるGatekeeper bypass exploitの発見と報告](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023：macOS Security and Privacy Mechanismsのbypass — GatekeeperからSystem Integrity Protectionまで（Koh Nakagawa）](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)

{{#include ../../../banners/hacktricks-training.md}}
