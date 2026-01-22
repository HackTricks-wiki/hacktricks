# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** は macOS のセキュリティ機能で、ユーザーがシステムで **信頼されたソフトウェアのみを実行する** ことを目的としています。これは、ユーザーがダウンロードして開こうとする **App Store 以外のソース**（アプリ、プラグイン、インストーラパッケージなど）からのソフトウェアを **検証する** ことで機能します。

Gatekeeper の主要な仕組みはその **検証プロセス** にあります。ダウンロードしたソフトウェアが **認識された開発者によって署名されているか** を確認し、ソフトウェアの真正性を担保します。さらに、ソフトウェアが **Apple によって notarised（公証）されているか** を確認し、既知の悪意あるコンテンツが含まれていないこと、また公証後に改ざんされていないことを検証します。

加えて、Gatekeeper はダウンロードしたソフトウェアを初めて開く際に **ユーザーに許可を求める** ことで、ユーザーの操作性とセキュリティを強化します。これにより、ユーザーがデータファイルと誤認してしまった潜在的に有害な実行コードを誤って実行するのを防ぎます。

### アプリケーション署名

アプリケーション署名（code signatures とも呼ばれる）は、Apple のセキュリティインフラストラクチャの重要な要素です。これらは **ソフトウェア作者の身元を検証する**（開発者）ため、また署名後にコードが改ざんされていないことを保証するために使用されます。

仕組みは次のとおりです:

1. **アプリケーションの署名:** 開発者がアプリケーションを配布する準備ができたら、**秘密鍵を使ってアプリに署名します**。この秘密鍵は、Apple Developer Program に登録した開発者に Apple が発行する **証明書** に紐付いています。署名プロセスでは、アプリの全部分の暗号学的ハッシュを作成し、そのハッシュを開発者の秘密鍵で暗号化します。
2. **アプリケーションの配布:** 署名されたアプリは、対応する公開鍵を含む開発者の証明書とともにユーザーに配布されます。
3. **アプリケーションの検証:** ユーザーがアプリをダウンロードして実行しようとすると、macOS は開発者の証明書から公開鍵を使って暗号化されたハッシュを復号します。次に、現在のアプリの状態に基づいてハッシュを再計算し、復号されたハッシュと比較します。一致すれば、**アプリが署名以降に改ざんされていない** ことを意味し、システムはアプリの実行を許可します。

アプリケーション署名は Gatekeeper 技術の不可欠な部分です。ユーザーが **インターネットからダウンロードしたアプリケーションを開こうとする際**、Gatekeeper はアプリの署名を検証します。Apple が既知の開発者に発行した証明書で署名され、かつコードが改ざんされていなければ、Gatekeeper はアプリの実行を許可します。そうでない場合は、アプリをブロックしユーザーに警告します。

macOS Catalina 以降、**Gatekeeper はアプリケーションが Apple によって notarized されているかどうかも確認します**。notarization プロセスはアプリを既知のセキュリティ問題や悪意あるコードについてチェックし、これらのチェックを通過すると Apple はアプリに対してチケットを付与し、Gatekeeper がそれを検証できるようにします。

#### 署名の確認

いくつかの **malware sample** を調査する際は、バイナリの **署名を必ず確認する** べきです。署名した **開発者** が既に **malware** と関連している可能性があるためです。
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
### ノータリゼーション

Apple のノータリゼーションプロセスは、潜在的に有害なソフトウェアからユーザーを保護するための追加的な安全策です。これは、**開発者が自分のアプリケーションを検査のために提出する**ことを含み、**Apple's Notary Service**（App Review と混同しないでください）によって行われます。このサービスは**自動化されたシステム**であり、提出されたソフトウェアに**悪意のあるコンテンツ**が含まれていないか、コード署名に関する潜在的な問題がないかを精査します。

ソフトウェアがこの検査を問題なく**通過**した場合、Notary Service はノータリゼーションチケットを発行します。開発者はこのチケットをソフトウェアに**添付する**必要があり、これを一般に 'stapling' と呼びます。さらに、そのノータリゼーションチケットは Gatekeeper（Apple のセキュリティ技術）がアクセスできるようにオンラインにも公開されます。

ユーザーがソフトウェアを初めてインストールまたは実行するとき、ノータリゼーションチケットが実行ファイルにステープルされているかオンラインで見つかるかを問わず、その存在は **Gatekeeper に対して当該ソフトウェアが Apple によってノータリゼーションされたことを知らせます**。その結果、Gatekeeper は初回起動時のダイアログに説明文を表示し、ソフトウェアが Apple による悪意あるコンテンツのチェックを受けたことを示します。このプロセスは、ユーザーがシステムにインストールまたは実行するソフトウェアの安全性に対する信頼を高めます。

### spctl & syspolicyd

> [!CAUTION]
> Sequoia バージョン以降、**`spctl`** はもはや Gatekeeper の設定を変更できない点に注意してください。

**`spctl`** は Gatekeeper を列挙・操作するための CLI ツールです（`syspolicyd` デーモンと XPC メッセージ経由で連携します）。例えば、GateKeeper の **状態** を次のように確認できます:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> GateKeeper の署名チェックは、すべてのファイルではなく **Quarantine attribute** が付与されたファイルのみに対して行われることに注意してください。

GateKeeper は、**preferences & the signature** に従ってバイナリが実行可能かどうかをチェックします:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** は Gatekeeper を強制する主要なデーモンです。`/var/db/SystemPolicy` に配置されたデータベースを維持しており、データベースをサポートするコードは [database here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) と、SQL テンプレートは [SQL template here](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql) で確認できます。データベースは SIP による制限を受けず root によって書き込み可能で、他方が破損した場合のオリジナルバックアップとして `/var/db/.SystemPolicy-default` が使用されます。

さらに、バンドル **`/var/db/gke.bundle`** と **`/var/db/gkopaque.bundle`** にはデータベースに挿入されるルールを含むファイルが含まれています。root でこのデータベースを確認するには:
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
**`syspolicyd`** は、`assess`、`update`、`record`、`cancel` のような複数の操作を持つ XPC サーバーも公開しており、これらは **`Security.framework`'s `SecAssessment*`** APIs を使って到達可能で、**`spctl`** は実際に XPC 経由で **`syspolicyd`** と通信します。

最初のルールが "**App Store**" で終わり、2つ目が "**Developer ID**" で終わっている点に注意してください。また、前の画像では **App Store と identified developers からのアプリ実行が有効になっていました**。\\

その設定を App Store に**変更**すると、"**Notarized Developer ID のルールは消えます**。

また、**type GKE** のルールが何千もあります :
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
これらは次のファイルからのハッシュです:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

または、前述の情報を次のコマンドで一覧表示できます:
```bash
sudo spctl --list
```
**`spctl`** のオプション **`--master-disable`** と **`--global-disable`** は、これらの署名チェックを完全に **無効化** します：
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
完全に有効化されると、新しいオプションが表示されます:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

以下のコマンドで、**アプリが GateKeeper によって許可されるかを確認できます**:
```bash
spctl --assess -v /Applications/App.app
```
GateKeeper に新しいルールを追加して、特定のアプリの実行を許可することができます:
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
**カーネル拡張** に関して、フォルダ `/var/db/SystemPolicyConfiguration` はロードを許可された kext のリストを含むファイルを保持しています。さらに、`spctl` はエンタイトルメント `com.apple.private.iokit.nvram-csr` を持っており、新たに事前承認されたカーネル拡張を追加できるため、それらは NVRAM の `kext-allowed-teams` キーにも保存する必要があります。

#### macOS 15 (Sequoia) 以降の Gatekeeper の管理

- 長年の Finder **Ctrl+Open / Right‑click → Open** バイパスは削除されました。ユーザーは最初のブロックダイアログの後、**System Settings → Privacy & Security → Open Anyway** からブロックされたアプリを明示的に許可する必要があります。
- `spctl --master-disable/--global-disable` はもはや受け付けられません。`spctl` は評価とラベル管理に関して実質的に読み取り専用となり、ポリシーの強制は UI または MDM を通じて構成されます。

macOS 15 Sequoia 以降、エンドユーザーは `spctl` から Gatekeeper ポリシーを切り替えることができなくなりました。管理は System Settings で行うか、`com.apple.systempolicy.control` ペイロードを含む MDM 構成プロファイルを展開して行います。App Store と identified developers を許可する（ただし "Anywhere" は許可しない）ためのプロファイルの例スニペット：

<details>
<summary>App Store と identified developers を許可する MDM プロファイル</summary>
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

### 隔離ファイル

アプリやファイルを**ダウンロード**すると、webブラウザやメールクライアントなどの特定の macOS **アプリケーション**は、ダウンロードされたファイルに一般に「**隔離フラグ**」として知られる**拡張ファイル属性を付加します**。この属性は、ファイルが信頼できないソース（インターネット）から来たことを**示す**セキュリティ対策であり、潜在的なリスクを含んでいる可能性があります。ただし、すべてのアプリがこの属性を付与するわけではなく、例えば一般的な BitTorrent クライアントソフトは通常この処理をバイパスします。

**隔離フラグの存在は、ユーザーがファイルを実行しようとした際に macOS の Gatekeeper セキュリティ機能に通知します。**

もし**隔離フラグが存在しない**場合（いくつかの BitTorrent クライアントでダウンロードされたファイルのように）、Gatekeeper の**チェックが行われない場合があります**。したがって、安全性の低い、または不明なソースからダウンロードしたファイルを開く際には注意が必要です。

> [!NOTE] > **コード署名の有効性を確認することは**、コードとそのバンドルされたリソース全体の暗号学的**ハッシュを生成する**などの**リソース集約型**の処理です。さらに、証明書の有効性を確認するには、発行後に取り消されていないかを確かめるために Apple のサーバーへの**オンラインチェック**が必要です。これらの理由から、完全なコード署名および公証のチェックを**アプリ起動時に毎回実行するのは現実的ではありません**。
>
> したがって、これらのチェックは**隔離属性が付与されたアプリを実行する場合にのみ行われます**。

> [!WARNING]
> この属性はファイルを作成/ダウンロードする**アプリケーションによって設定される必要があります**。
>
> ただし、サンドボックス化されたアプリが作成するファイルには常にこの属性が設定されます。サンドボックス化されていないアプリは自分で設定することもでき、または **Info.plist** の [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) キーを指定すると、システムが作成されたファイルに `com.apple.quarantine` 拡張属性を設定します、

さらに、**`qtn_proc_apply_to_self`** を呼び出すプロセスによって作成されたすべてのファイルは隔離されます。あるいは、API **`qtn_file_apply_to_path`** が指定したファイルパスに隔離属性を追加します。

次の方法で（root 権限が必要）その**ステータスを確認し、有効/無効を切り替える**ことができます:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
次のコマンドでファイルに **quarantine 拡張属性があるかどうか** を確認できます:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
**extended** **attributes** の **value** を確認し、どのアプリが quarantine attr を書き込んだかを次のコマンドで調べる:
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
実際、プロセスは作成したファイルに quarantine フラグを設定できます（作成したファイルに USER_APPROVED フラグを適用しようとしましたが、適用されませんでした）:

<details>

<summary>ソースコード: quarantine フラグの適用</summary>
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

そしてその属性を**削除**してください:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
そして、次のコマンドで隔離されたファイルをすべて見つけます:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Quarantine information is also stored in a central database managed by LaunchServices in **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`** which allows the GUI to obtain data about the file origins. Moreover this can be overwritten by applications which might be interested in hiding its origins. Moreover, this can be done from LaunchServices APIS.

#### **libquarantine.dylib**

このライブラリは、拡張属性フィールドを操作するためのいくつかの関数をエクスポートしています。

`qtn_file_*` APIs はファイルの検疫ポリシーを扱い、`qtn_proc_*` APIs はプロセス（そのプロセスが作成したファイル）に適用されます。エクスポートされていない `__qtn_syscall_quarantine*` 関数群はポリシーを適用するもので、最初の引数に "Quarantine" を指定して `mac_syscall` を呼び出し、`Quarantine.kext` にリクエストを送ります。

#### **Quarantine.kext**

このカーネル拡張は **システム上のカーネルキャッシュを介してのみ利用可能** ですが、[**https://developer.apple.com/**](https://developer.apple.com/) から **Kernel Debug Kit** をダウンロードすれば、シンボル化されたバージョンの拡張が含まれています。

この Kext は MACF を介していくつかの呼び出しをフックし、ファイルのライフサイクルイベント（作成、オープン、リネーム、ハードリンク化...）をすべて捕捉します。`setxattr` による `com.apple.quarantine` 拡張属性の設定を防ぐことさえします。

It also uses a couple of MIBs:

- `security.mac.qtn.sandbox_enforce`: Sandbox と連携して検疫を強制する
- `security.mac.qtn.user_approved_exec`: 検疫されたプロセスは承認されたファイルのみ実行できる

#### Provenance xattr (Ventura and later)

macOS 13 Ventura では、検疫されたアプリが初めて実行を許可されたときに設定される別の provenance メカニズムが導入されました。2つのアーティファクトが作成されます：

- The `com.apple.provenance` xattr on the `.app` bundle directory (fixed-size binary value containing a primary key and flags).
- A row in the `provenance_tracking` table inside the ExecPolicy database at `/var/db/SystemPolicyConfiguration/ExecPolicy/` storing the app’s cdhash and metadata.

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

XProtectはmacOSに組み込まれた**anti-malware**機能です。XProtectは、アプリケーションが最初に起動されたときや変更されたときに、既知のマルウェアや危険なファイルタイプのデータベースと**照合します**。Safari、Mail、または Messages のような特定のアプリを通じてファイルをダウンロードすると、XProtectはそのファイルを自動的にスキャンします。データベースの既知のマルウェアと一致した場合、XProtectは**ファイルの実行を防止**し、脅威を通知します。

XProtectのデータベースは、Appleによって新しいマルウェア定義で**定期的に更新**され、これらの更新はMacに自動的にダウンロードおよびインストールされます。これにより、XProtectは常に最新の既知の脅威に対応できます。

ただし、**XProtectはフル機能のantivirusソリューションではない**点に注意してください。既知の脅威の特定のリストのみをチェックし、ほとんどのantivirusソフトウェアのようなon-access scanningは実行しません。

最新のXProtectアップデートに関する情報は、次のコマンドを実行して取得できます:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtectはSIPで保護された場所、**/Library/Apple/System/Library/CoreServices/XProtect.bundle** にあり、バンドル内にはXProtectが使用する情報が含まれています:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: これらのcdhashを持つコードがレガシーエンタイトルメントを使用することを許可します。
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: BundleIDやTeamIDでロードが禁止されているプラグインや拡張機能の一覧、または最小バージョンを示します。
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: マルウェア検出用のYaraルール。
- **`XProtect.bundle/Contents/Resources/gk.db`**: ブロックされたアプリケーションのハッシュとTeamIDを格納したSQLite3データベース。

`/Library/Apple/System/Library/CoreServices/XProtect.app` に関連する別のAppが存在しますが、これはGatekeeperのプロセスには関与していません。

> XProtect Remediator: 現代のmacOSでは、Appleはlaunchd経由で定期的に実行されるオンデマンドスキャナ（XProtect Remediator）を提供しており、マルウェアファミリの検出と修復を行います。これらのスキャンはユニファイドログで確認できます:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Gatekeeperではない

> [!CAUTION]
> Gatekeeperがアプリを実行するたびに**毎回実行されるわけではない**ことに注意してください。実行済みかつGatekeeperで検証済みのアプリを実行する場合、_**AppleMobileFileIntegrity**_（AMFI）は実行可能コードの署名のみを**検証します**。

そのため、以前はアプリをGatekeeperでキャッシュするために一度実行し、その後アプリの実行ファイルでないファイル（ElectronのasarやNIBファイルなど）を変更し、他に保護がなければ、アプリは悪意ある追加を含んだ状態で**実行されてしまう**可能性がありました。

しかし現在は、macOSがアプリケーションバンドル内のファイルの**変更を防止する**ため、これは不可能です。したがって、[Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md) 攻撃を試みても、Gatekeeperでキャッシュするために一度アプリを実行した後はバンドルを変更できないため、もはや悪用できません。例えばexploitで示されているようにContentsディレクトリの名前をNotConに変更し、アプリのメインバイナリをGatekeeperでキャッシュするために実行すると、エラーが発生して実行されなくなります。

## Gatekeeperのバイパス

Gatekeeperをバイパスする（Gatekeeperが許可しないはずのものをユーザにダウンロードさせ実行させる）方法は、macOSの脆弱性と見なされます。過去にGatekeeperをバイパスする手法に割り当てられたCVEの例は次のとおりです:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Archive Utilityを使用して解凍した場合、**パスが886文字を超えるファイル**に対してはcom.apple.quarantine拡張属性が付与されないことが観測されました。この状況により、これらのファイルが意図せずGatekeeperのセキュリティチェックを**回避してしまう**可能性がありました。

詳細は[**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)を参照してください。

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Automatorで作成されたアプリケーションでは、実行に必要な情報が実行ファイルではなく `application.app/Contents/document.wflow` の中にあり、実行ファイル自体は**Automator Application Stub**と呼ばれる汎用のAutomatorバイナリです。

したがって、`application.app/Contents/MacOS/Automator\ Application\ Stub` をシステム内の別のAutomator Application Stubへのシンボリックリンクに**向ける（point with a symbolic link）**ことができれば、`document.wflow` の中身（あなたのスクリプト）を**Gatekeeperをトリガーせずに**実行できます。これは実際の実行ファイルがquarantineのxattrを持っていないためです。

例: 期待される場所は `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub` です。

詳細は[**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper)を参照してください。

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

このバイパスでは、アプリケーションを `application.app` ではなく `application.app/Contents` から圧縮し始めるようにzipファイルが作成されました。そのため、**quarantine属性**は `application.app/Contents` 内の**すべてのファイル**には適用されましたが、Gatekeeperがチェックしている `application.app` には**適用されませんでした**。結果として、`application.app` がトリガーされたときに**quarantine属性が付いていない**ため、Gatekeeperがバイパスされてしまいました。
```bash
zip -r test.app/Contents test.zip
```
詳細は[**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)を確認してください。

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

構成要素は異なっていても、この脆弱性の悪用方法は前のものと非常に似ています。  
このケースでは、**`application.app/Contents`** から Apple Archive を生成するため、**`application.app` は quarantine attr を受け取りません**（**Archive Utility** によって解凍されたとき）。
```bash
aa archive -d test.app/Contents -o test.app.aar
```
詳細については、[**original report**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) をご確認ください。

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** は、ファイルに属性を書き込むことを誰にも許可しないようにするために使用できます:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
さらに、**AppleDouble** file format は ACEs を含むファイルをコピーします。

In the [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) it's possible to see that the ACL text representation stored inside the xattr called **`com.apple.acl.text`** is going to be set as ACL in the decompressed file. So, if you compressed an application into a zip file with **AppleDouble** file format with an ACL that prevents other xattrs to be written to it... the quarantine xattr wasn't set into de application:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
詳細については[**original report**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)を確認してください。

なお、これは AppleArchives を使用しても悪用可能です:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

macOS の内部的な問題により、ダウンロードしたファイルに対して **Google Chrome wasn't setting the quarantine attribute** ことが判明しました。

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble ファイル形式は、ファイルの属性を `._` で始まる別ファイルに保存します。これにより、ファイル属性を **across macOS machines** にコピーするのに役立ちます。しかし、AppleDouble ファイルを展開した後、`._` で始まるファイルに **wasn't given the quarantine attribute** ことが確認されました。
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
quarantine属性が設定されないファイルを作成できれば、**Gatekeeperをバイパスすることが可能だった。** トリックは、AppleDouble命名規則（`._`で始める）を使って**DMG file applicationを作成**し、quarantine属性のないこの隠しファイルに対して可視のファイルを**sym linkとして作成**することだった。\
この**dmg fileが実行されると**、quarantine属性がないため**Gatekeeperをバイパスする**。
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

macOS Sonoma 14.0で修正されたGatekeeperのバイパスにより、細工されたアプリがプロンプトなしで実行される可能性がありました。パッチ適用後に詳細が公開され、修正前に実際に悪用されていました。Sonoma 14.0以降がインストールされていることを確認してください。

### [CVE-2024-27853]

macOS 14.4（2024年3月リリース）での、悪意あるZIPを`libarchive`が処理することに起因するGatekeeperのバイパスにより、アプリが評価を回避できました。Appleがこの問題に対処した14.4以降にアップデートしてください。

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

ダウンロードされたアプリに埋め込まれた**Automator Quick Action workflow**が、ワークフローがデータとして扱われ、Automatorヘルパーによって通常のnotarizationプロンプト経路の外で実行されるため、Gatekeeperの評価なしにトリガーされる可能性がありました。シェルスクリプトを実行するQuick Actionをバンドルした細工された`.app`（例: `Contents/PlugIns/*.workflow/Contents/document.wflow`内）が起動時に即座に実行される可能性がありました。Appleは追加の同意ダイアログを導入し、Ventura **13.7**、Sonoma **14.7**、Sequoia **15**で評価経路を修正しました。

### Third‑party unarchivers mis‑propagating quarantine (2023–2024)

人気の解凍ツール（例: The Unarchiver）における複数の脆弱性により、アーカイブから抽出されたファイルに`com.apple.quarantine` xattrが付与されず、Gatekeeperのバイパスにつながる可能性がありました。テストする際は常にmacOSのArchive Utilityまたは修正済みのツールを使用し、抽出後にxattrを検証してください。

### uchg (この [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf) より)

- アプリを含むディレクトリを作成する。
- アプリに uchg を追加する。
- アプリを tar.gz ファイルに圧縮する。
- tar.gz ファイルを被害者に送る。
- 被害者が tar.gz を開きアプリを実行する。
- Gatekeeper はアプリをチェックしない。

### Prevent Quarantine xattr

".app" バンドルに quarantine xattr が追加されていない場合、実行時に **Gatekeeper はトリガーされません**。

## References

- Apple Platform Security: macOS Sonoma 14.4 のセキュリティに関する情報（CVE-2024-27853を含む） – [https://support.apple.com/en-us/HT214084](https://support.apple.com/en-us/HT214084)
- Eclectic Light: macOSが現在アプリの由来を追跡する方法 – [https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- Apple: macOS Sonoma 14.7 / Ventura 13.7 のセキュリティに関する情報（CVE-2024-44128） – [https://support.apple.com/en-us/121234](https://support.apple.com/en-us/121234)
- MacRumors: macOS 15 Sequoia は Control‑click の “Open” Gatekeeper バイパスを削除 – [https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)

{{#include ../../../banners/hacktricks-training.md}}
