# macOS Kernel Extensions & Debugging

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

Kernel extensions (Kexts) は **パッケージ** で、**`.kext`** 拡張子を持ち、**macOS カーネル空間に直接ロードされる**ことで、主要なオペレーティングシステムに追加機能を提供します。

### 非推奨ステータス & DriverKit / システム拡張
**macOS Catalina (10.15)** から、Apple はほとんどのレガシー KPI を *非推奨* とし、**システム拡張 & DriverKit** フレームワークを導入しました。これらは **ユーザースペース** で実行されます。**macOS Big Sur (11)** 以降、オペレーティングシステムは、非推奨の KPI に依存するサードパーティの kext を *ロードすることを拒否します*。Apple Silicon では、kext を有効にするには、ユーザーが以下を行う必要があります：

1. **リカバリ** に再起動 → *スタートアップセキュリティユーティリティ*。
2. **Reduced Security** を選択し、**「特定の開発者からのカーネル拡張のユーザー管理を許可」** にチェックを入れます。
3. 再起動し、**システム設定 → プライバシーとセキュリティ** から kext を承認します。

DriverKit/システム拡張で書かれたユーザランドドライバは、クラッシュやメモリ破損がカーネル空間ではなくサンドボックス化されたプロセスに制限されるため、**攻撃面を大幅に削減**します。

> 📝 macOS Sequoia (15) から、Apple はいくつかのレガシーなネットワーキングおよび USB KPI を完全に削除しました。ベンダーにとって唯一の前方互換性のある解決策は、システム拡張に移行することです。

### 要件

明らかに、これは非常に強力であるため、**カーネル拡張をロードするのは複雑です**。カーネル拡張がロードされるために満たすべき **要件** は以下の通りです：

- **リカバリモードに入るとき**、カーネル **拡張がロードされることを許可する必要があります**：

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- カーネル拡張は **カーネルコード署名証明書で署名されている必要があり**、これは **Apple によってのみ付与されます**。誰が会社とその必要性を詳細にレビューします。
- カーネル拡張は **ノータライズされている必要があり**、Apple はそれをマルウェアのチェックができます。
- その後、**root** ユーザーが **カーネル拡張をロードできる**のは、パッケージ内のファイルが **root に属している必要があります**。
- アップロードプロセス中、パッケージは **保護された非ルートの場所** に準備される必要があります：`/Library/StagedExtensions`（`com.apple.rootless.storage.KernelExtensionManagement` の付与が必要です）。
- 最後に、ロードを試みると、ユーザーは [**確認リクエストを受け取ります**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) 。受け入れられた場合、コンピュータは **再起動** してロードする必要があります。

### ロードプロセス

Catalina では次のようになっていました：**検証** プロセスは **ユーザランド** で行われることに注目するのは興味深いです。しかし、**`com.apple.private.security.kext-management`** の付与を持つアプリケーションのみが **カーネルに拡張をロードするよう要求できます**：`kextcache`、`kextload`、`kextutil`、`kextd`、`syspolicyd`

1. **`kextutil`** CLI **が** 拡張のロードのための **検証** プロセスを **開始します**
- **`kextd`** に **Mach サービス** を使用して送信します。
2. **`kextd`** は、**署名** などのいくつかのことをチェックします
- **`syspolicyd`** に話しかけて、拡張が **ロードできるかどうかを確認します**。
3. **`syspolicyd`** は、拡張が以前にロードされていない場合、**ユーザーにプロンプトを表示します**。
- **`syspolicyd`** は結果を **`kextd`** に報告します。
4. **`kextd`** は最終的に **カーネルに拡張をロードするよう指示できます**。

もし **`kextd`** が利用できない場合、**`kextutil`** は同じチェックを実行できます。

### 列挙と管理（ロードされた kexts）

`kextstat` は歴史的なツールでしたが、最近の macOS リリースでは **非推奨** となっています。現代のインターフェースは **`kmutil`** です：
```bash
# List every extension currently linked in the kernel, sorted by load address
sudo kmutil showloaded --sort

# Show only third-party / auxiliary collections
sudo kmutil showloaded --collection aux

# Unload a specific bundle
sudo kmutil unload -b com.example.mykext
```
古い構文は参照用にまだ利用可能です：
```bash
# (Deprecated) Get loaded kernel extensions
kextstat

# (Deprecated) Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
`kmutil inspect` は、**カーネルコレクション (KC) の内容をダンプする** または kext がすべてのシンボル依存関係を解決していることを確認するためにも利用できます:
```bash
# List fileset entries contained in the boot KC
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Check undefined symbols of a 3rd party kext before loading
kmutil libraries -p /Library/Extensions/FancyUSB.kext --undef-symbols
```
## Kernelcache

> [!CAUTION]
> たとえカーネル拡張が `/System/Library/Extensions/` にあることが期待されていても、このフォルダーに行っても **バイナリは見つかりません**。これは **kernelcache** のためであり、`.kext` を逆コンパイルするには、それを取得する方法を見つける必要があります。

**kernelcache** は **XNUカーネルの事前コンパイルおよび事前リンクされたバージョン** であり、重要なデバイス **ドライバー** と **カーネル拡張** が含まれています。これは **圧縮** 形式で保存され、起動プロセス中にメモリに展開されます。kernelcache は、カーネルと重要なドライバーの実行準備が整ったバージョンを利用することで **起動時間を短縮** し、起動時にこれらのコンポーネントを動的に読み込みおよびリンクするのにかかる時間とリソースを削減します。

### Local Kernelcache

iOS では **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** にあり、macOS では次のコマンドで見つけることができます: **`find / -name "kernelcache" 2>/dev/null`** \
私の場合、macOS では次の場所に見つけました:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

IMG4 ファイル形式は、Apple が iOS および macOS デバイスで **ファームウェア** コンポーネント（**kernelcache** など）を安全に **保存および検証** するために使用するコンテナ形式です。IMG4 形式にはヘッダーと、実際のペイロード（カーネルやブートローダーなど）、署名、および一連のマニフェストプロパティをカプセル化するいくつかのタグが含まれています。この形式は暗号的検証をサポートしており、デバイスがファームウェアコンポーネントを実行する前に、その真正性と完全性を確認できるようにします。

通常、次のコンポーネントで構成されています:

- **ペイロード (IM4P)**:
- よく圧縮されている (LZFSE4, LZSS, …)
- オプションで暗号化されている
- **マニフェスト (IM4M)**:
- 署名を含む
- 追加のキー/値辞書
- **復元情報 (IM4R)**:
- APNonce とも呼ばれる
- 一部のアップデートの再生を防ぐ
- OPTIONAL: 通常は見つからない

Kernelcache を解凍する:
```bash
# img4tool (https://github.com/tihmstar/img4tool)
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e

# pyimg4 (https://github.com/m1stadev/PyIMG4)
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### ダウンロード

- [**KernelDebugKit Github**](https://github.com/dortania/KdkSupportPkg/releases)

[https://github.com/dortania/KdkSupportPkg/releases](https://github.com/dortania/KdkSupportPkg/releases) では、すべてのカーネルデバッグキットを見つけることができます。ダウンロードして、マウントし、[Suspicious Package](https://www.mothersruin.com/software/SuspiciousPackage/get.html) ツールで開き、**`.kext`** フォルダーにアクセスして**抽出**します。

シンボルを確認するには:
```bash
nm -a ~/Downloads/Sandbox.kext/Contents/MacOS/Sandbox | wc -l
```
- [**theapplewiki.com**](https://theapplewiki.com/wiki/Firmware/Mac/14.x)**,** [**ipsw.me**](https://ipsw.me/)**,** [**theiphonewiki.com**](https://www.theiphonewiki.com/)

時々、Appleは**kernelcache**を**symbols**付きでリリースします。これらのページのリンクをたどることで、symbols付きのファームウェアをダウンロードできます。ファームウェアには他のファイルとともに**kernelcache**が含まれています。

ファイルを**extract**するには、まず拡張子を`.ipsw`から`.zip`に変更し、**unzip**します。

ファームウェアを抽出すると、**`kernelcache.release.iphone14`**のようなファイルが得られます。これは**IMG4**形式で、興味深い情報を以下のコマンドで抽出できます：

[**pyimg4**](https://github.com/m1stadev/PyIMG4)**:**
```bash
pyimg4 im4p extract -i kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
[**img4tool**](https://github.com/tihmstar/img4tool)**:**
```bash
img4tool -e kernelcache.release.iphone14 -o kernelcache.release.iphone14.e
```
### Inspecting kernelcache

カーネルキャッシュにシンボルがあるか確認します。
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
これで、**すべての拡張機能**または**興味のある拡張機能**を**抽出**できます。
```bash
# List all extensions
kextex -l kernelcache.release.iphone14.e
## Extract com.apple.security.sandbox
kextex -e com.apple.security.sandbox kernelcache.release.iphone14.e

# Extract all
kextex_all kernelcache.release.iphone14.e

# Check the extension for symbols
nm -a binaries/com.apple.security.sandbox | wc -l
```
## 最近の脆弱性とエクスプロイト技術

| 年 | CVE | 概要 |
|------|-----|---------|
| 2024 | **CVE-2024-44243** | **`storagekitd`** の論理的欠陥により、*root* 攻撃者が悪意のあるファイルシステムバンドルを登録でき、最終的に **署名されていない kext** を読み込むことができ、**システム整合性保護 (SIP) を回避** し、永続的なルートキットを有効にしました。macOS 14.2 / 15.2 で修正されました。 |
| 2021 | **CVE-2021-30892** (*Shrootless*) | `com.apple.rootless.install` の権限を持つインストールデーモンが悪用され、任意のポストインストールスクリプトを実行し、SIPを無効にし、任意のkextを読み込むことができました。 |

**レッドチーム向けのポイント**

1. **Disk Arbitration、Installer、またはKext Managementと相互作用する権限のあるデーモンを探してください (`codesign -dvv /path/bin | grep entitlements`)。**
2. **SIPのバイパスを悪用することは、ほぼ常にkextを読み込む能力を与えます → カーネルコードの実行**。

**防御のヒント**

*SIPを有効に保ち*、Apple以外のバイナリからの `kmutil load` / `kmutil create -n aux` の呼び出しを監視し、`/Library/Extensions` への書き込みに警告を出します。エンドポイントセキュリティイベント `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` は、ほぼリアルタイムの可視性を提供します。

## macOSカーネルとkextのデバッグ

Appleの推奨ワークフローは、実行中のビルドに一致する **Kernel Debug Kit (KDK)** を構築し、その後 **KDP (Kernel Debugging Protocol)** ネットワークセッションを介して **LLDB** を接続することです。

### パニックのワンショットローカルデバッグ
```bash
# Create a symbolication bundle for the latest panic
sudo kdpwrit dump latest.kcdata
kmutil analyze-panic latest.kcdata -o ~/panic_report.txt
```
### 別のMacからのライブリモートデバッグ

1. ターゲットマシンに対して正確な**KDK**バージョンをダウンロードしてインストールします。
2. ターゲットMacとホストMacを**USB-CまたはThunderboltケーブル**で接続します。
3. **ターゲット**で:
```bash
sudo nvram boot-args="debug=0x100 kdp_match_name=macbook-target"
reboot
```
4. **ホスト**上で:
```bash
lldb
(lldb) kdp-remote "udp://macbook-target"
(lldb) bt  # get backtrace in kernel context
```
### 特定のロードされたkextにLLDBをアタッチする
```bash
# Identify load address of the kext
ADDR=$(kmutil showloaded --bundle-identifier com.example.driver | awk '{print $4}')

# Attach
sudo lldb -n kernel_task -o "target modules load --file /Library/Extensions/Example.kext/Contents/MacOS/Example --slide $ADDR"
```
> ℹ️  KDPは**読み取り専用**インターフェースのみを公開します。動的インストゥルメンテーションには、ディスク上のバイナリをパッチするか、**カーネル関数フック**（例：`mach_override`）を利用するか、完全な読み書きのためにドライバを**ハイパーバイザ**に移行する必要があります。

## 参考文献

- DriverKit Security – Apple Platform Security Guide
- Microsoft Security Blog – *Analyzing CVE-2024-44243 SIP bypass*

{{#include ../../../banners/hacktricks-training.md}}
