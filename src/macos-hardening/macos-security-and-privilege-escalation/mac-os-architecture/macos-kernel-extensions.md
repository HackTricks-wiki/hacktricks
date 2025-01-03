# macOS Kernel Extensions & Debugging

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

カーネル拡張（Kexts）は、**`.kext`** 拡張子を持つ **パッケージ** であり、**macOS カーネル空間に直接ロードされる**ことで、主要なオペレーティングシステムに追加機能を提供します。

### 要件

明らかに、これは非常に強力であるため、**カーネル拡張をロードするのは複雑です**。カーネル拡張がロードされるために満たすべき **要件** は次のとおりです：

- **リカバリモードに入るとき**、カーネル **拡張がロードされることを許可する必要があります**：

<figure><img src="../../../images/image (327).png" alt=""><figcaption></figcaption></figure>

- カーネル拡張は **カーネルコード署名証明書で署名されている必要があり**、これは **Appleによってのみ付与されます**。誰が会社とその必要性を詳細にレビューします。
- カーネル拡張は **ノータライズされている必要があり**、Appleはそれをマルウェアのチェックができます。
- 次に、**root** ユーザーが **カーネル拡張をロードできる**のは、パッケージ内のファイルが **rootに属している必要があります**。
- アップロードプロセス中、パッケージは **保護された非rootの場所** に準備される必要があります：`/Library/StagedExtensions`（`com.apple.rootless.storage.KernelExtensionManagement` の付与が必要です）。
- 最後に、ロードを試みると、ユーザーは [**確認リクエストを受け取ります**](https://developer.apple.com/library/archive/technotes/tn2459/_index.html) 。受け入れられた場合、コンピュータは **再起動** されてロードされる必要があります。

### ロードプロセス

カタリナでは次のようでした：**検証** プロセスは **ユーザーランド** で行われることに注目することが興味深いです。しかし、**`com.apple.private.security.kext-management`** の付与を持つアプリケーションのみが **カーネルに拡張をロードするよう要求できます**：`kextcache`、`kextload`、`kextutil`、`kextd`、`syspolicyd`

1. **`kextutil`** cli **が** 拡張のロードのための **検証** プロセスを **開始します**
- **Machサービス** を使用して **`kextd`** に話しかけます。
2. **`kextd`** は、**署名** などのいくつかのことをチェックします
- 拡張が **ロードできるかどうかを確認するために** **`syspolicyd`** に話しかけます。
3. **`syspolicyd`** は、拡張が以前にロードされていない場合、**ユーザーにプロンプトを表示します**。
- **`syspolicyd`** は結果を **`kextd`** に報告します。
4. **`kextd`** は最終的に **カーネルに拡張をロードするよう指示できる**ようになります。

もし **`kextd`** が利用できない場合、**`kextutil`** は同じチェックを実行できます。

### 列挙（ロードされたkexts）
```bash
# Get loaded kernel extensions
kextstat

# Get dependencies of the kext number 22
kextstat | grep " 22 " | cut -c2-5,50- | cut -d '(' -f1
```
## Kernelcache

> [!CAUTION]
> カーネル拡張は `/System/Library/Extensions/` にあると予想されていますが、このフォルダーに行っても **バイナリは見つかりません**。これは **kernelcache** のためであり、`.kext` を逆コンパイルするには、それを取得する方法を見つける必要があります。

**kernelcache** は **XNUカーネルの事前コンパイルおよび事前リンクされたバージョン**であり、重要なデバイス **ドライバー** と **カーネル拡張** が含まれています。これは **圧縮** 形式で保存され、起動プロセス中にメモリに展開されます。kernelcache は、カーネルと重要なドライバーの実行準備が整ったバージョンを利用することで **起動時間を短縮** し、起動時にこれらのコンポーネントを動的に読み込んでリンクするのにかかる時間とリソースを削減します。

### Local Kerlnelcache

iOS では **`/System/Library/Caches/com.apple.kernelcaches/kernelcache`** にあり、macOS では次のコマンドで見つけることができます: **`find / -name "kernelcache" 2>/dev/null`** \
私の場合、macOS では次の場所で見つけました:

- `/System/Volumes/Preboot/1BAEB4B5-180B-4C46-BD53-51152B7D92DA/boot/DAD35E7BC0CDA79634C20BD1BD80678DFB510B2AAD3D25C1228BB34BCD0A711529D3D571C93E29E1D0C1264750FA043F/System/Library/Caches/com.apple.kernelcaches/kernelcache`

#### IMG4

IMG4 ファイル形式は、Apple が iOS および macOS デバイスで **ファームウェア** コンポーネント（**kernelcache** など）を安全に **保存および検証** するために使用するコンテナ形式です。IMG4 形式にはヘッダーと、実際のペイロード（カーネルやブートローダーなど）、署名、および一連のマニフェストプロパティをカプセル化するいくつかのタグが含まれています。この形式は暗号的検証をサポートしており、デバイスがファームウェアコンポーネントを実行する前にその真正性と整合性を確認できるようにします。

通常、以下のコンポーネントで構成されています:

- **Payload (IM4P)**:
- よく圧縮されている (LZFSE4, LZSS, …)
- オプションで暗号化されている
- **Manifest (IM4M)**:
- 署名を含む
- 追加のキー/値辞書
- **Restore Info (IM4R)**:
- APNonce としても知られる
- 一部の更新の再生を防ぐ
- OPTIONAL: 通常は見つからない

Kernelcache を解凍する:
```bash
# img4tool (https://github.com/tihmstar/img4tool
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
### カーネルキャッシュの検査

カーネルキャッシュにシンボルがあるか確認します。
```bash
nm -a kernelcache.release.iphone14.e | wc -l
```
これで、**すべての拡張機能**または**あなたが興味のあるもの**を**抽出**できます：
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
## デバッグ

## 参考文献

- [https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/](https://www.makeuseof.com/how-to-enable-third-party-kernel-extensions-apple-silicon-mac/)
- [https://www.youtube.com/watch?v=hGKOskSiaQo](https://www.youtube.com/watch?v=hGKOskSiaQo)

{{#include ../../../banners/hacktricks-training.md}}
