# Windows MDL-Mapped User Buffer Double-Fetch

{{#include ../../banners/hacktricks-training.md}}

Windows kernel driverが呼び出し元のページにあるデータを検証した後、同じページへのポインターをセキュリティ上重要なAPIに渡すと、double-fetchが発生します。ページをロックしてマッピングしても、その内容は不変になりません。`cldflt.sys`のCVE-2025-55680はこのパターンを示しています。ドライバーはCloud Files placeholderの相対名を検証した後も、呼び出し元が変更可能なバッファーを参照したままオブジェクトを作成していました。<sup>[[1]](#references)[[3]](#references)</sup>

`CfCreatePlaceholders()`は、登録済みのCloud Files sync rootの下にファイルまたはディレクトリを作成します。脆弱な処理経路では、検証後に名前を変更すると、特権を使った作成先をそのrootの外へ誘導できました。<sup>[[1]](#references)[[2]](#references)</sup>

## ページをロックしてもデータがロックされなかった理由

脆弱な`HsmpOpCreatePlaceholders()`の処理経路では、呼び出し元のpayloadに対してMDLを割り当て、`ProbeForRead()`と`MmProbeAndLockPages()`を呼び出し、ページをカーネル仮想アドレス空間にマッピングしていました。MDLは物理ページを記述してロックし、ページが常駐し続けるようにします。しかし、バイト列のスナップショットは作成しません。そのため、ドライバーがシステムマッピングを介して読み取っている間も、ユーザーモードから同じ物理メモリーを変更できます。<sup>[[1]](#references)[[3]](#references)</sup>

関連するリクエストと使用の処理経路は次のとおりです。<sup>[[1]](#references)</sup>

1. `cldapi.dll`は、タグ`IO_REPARSE_TAG_CLOUD`（`0x9000001A`）とcreate-placeholder操作`0xC0000001`を指定して、Cloud Files制御コード`0x903BC`を送信しました。
2. 各payloadレコードには、相対名とファイルIDの16ビットオフセット/長さペアが含まれていました。固定フィールドの大部分はスタック上のレコードにコピーされましたが、可変長の名前はマッピングされたユーザーページに残っていました。
3. ドライバーはUTF-16名を走査し、バックスラッシュまたはコロンが含まれていれば拒否しました。
4. 続いて、`Buffer`がマッピングされたpayload内を指したままの`UNICODE_STRING`を構築し、それを`OBJECT_ATTRIBUTES.ObjectName`に割り当てました。
5. `FltCreateFileEx2()`はそのポインターを再度読み取りました。そのため、同時実行中のwriterによって、検証時に読み取られる文字列とファイル作成時に読み取られる文字列が異なる可能性がありました。

両方の読み取りがカーネル仮想アドレスを使用していても、これは**double-fetch**です。セキュリティ境界を決めるのは、ドライバーがどの仮想マッピングを参照するかではなく、バックストレージです。<sup>[[1]](#references)</sup>

## Cloud Filesのrace構成

公開されたexploit戦略では、繰り返しリクエスト、mutatorスレッド、junctionを利用して、double-fetchをパスリダイレクトにつなげていました。<sup>[[1]](#references)</sup>

1. `CfRegisterSyncRoot()`で攻撃者が制御するディレクトリを登録し、その下に保護対象の保存先を指すjunctionとして`JUSTASTRING`を作成します。
2. 有効な単一コンポーネント名`JUSTASTRINGDnewfile.dll`を含む、共有のplaceholderレコードを準備します。
3. mutatorスレッドに、UTF-16の`D`コードユニットを`D`と`\`の間で切り替えさせます。後者の表現は`JUSTASTRING\newfile.dll`です。
4. workerスレッドから同じpayloadを参照するcreate-placeholderリクエストを繰り返し送信させる一方、monitorで保護対象の保存先を確認します。
5. 成功した場合、区切り文字のない表現で検証された後、後続のcreate処理が`\`を含む表現を読み取るとjunctionをたどります。

このprimitiveで実現できるのは、保護対象のファイルまたはディレクトリの作成までです。これをcode executionにつなげるには、作成されるファイルの内容を制御し、適切なDLL side-loading対象のような特権プロセスに利用させる必要があります。元の分析では、この種の最終段階を含む攻撃チェーンが使われましたが、loader、payload、単独で動作する完全なexploitは公開されていません。<sup>[[1]](#references)</sup>

Windowsのパス検索におけるraceを意図的に拡大する補完的な手法については、[Object Managerの低速パスを介したKernel Race Condition Exploitation](kernel-race-condition-object-manager-slowdown.md)を参照してください。

## References

- [1] [Exodus Intelligence - Microsoft Windows Cloud Files MinifilterのTOCTOUによる特権昇格](https://blog.exodusintel.com/2025/10/20/microsoft-windows-cloud-files-minifilter-toctou-privilege-escalation/)
- [2] [Microsoft Learn - CfCreatePlaceholders関数](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfcreateplaceholders)
- [3] [Microsoft Learn - MmProbeAndLockPages関数](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmprobeandlockpages)
{{#include ../../banners/hacktricks-training.md}}
