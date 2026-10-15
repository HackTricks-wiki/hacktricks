# Windows Kernel Rootkits and DKOM

{{#include ../../banners/hacktricks-training.md}}

## 範囲

侵害後のimplantは、署名済みkernel driverをserviceとしてロードし、`IRP_MJ_DEVICE_CONTROL`を通じてuser-modeの制御プレーンを公開することがあります。Driver signingによって保証されるのは、Windowsがイメージを受け入れることだけです。IOCTLの認可、メモリ操作、callback、hookが安全になるわけではありません。解析したあるrootkitは通常動作中に3つのhandlerを使用していましたが、post-exploitation用の追加プリミティブを数十個公開していました。そのため、reverse engineeringではmalware traceで確認されたrequestだけでなく、dispatcher全体を調べる必要があります。<sup>[[1]](#references)</sup>

## 署名済みdriverとIOCTLのトリアージ

`DriverEntry`から調査を始め、device objectとDOS symbolic linkを記録し、`MajorFunction[IRP_MJ_DEVICE_CONTROL]`のroutineを特定して、handlerにつながる比較処理やtable entryをすべてマッピングします。user modeが開く名前と、driverが実際に作成する名前を照合してください。ある事例では、開かれたのは`\\.\msagent`でしたが、driverが作成したのは`\Device\ToolTool`と`\DosDevices\ToolTool`でした。この不一致は、別のsample/configuration、setup logicの欠落、または解析の不整合を示している可能性があります。<sup>[[1]](#references)</sup>

input structureを再構築する前に、各control codeをデコードしてください。<sup>[[1]](#references)</sup>

```python
def decode_ioctl(code):
    return {
        "device_type": code >> 16,
        "access": (code >> 14) & 3,
        "function": (code >> 2) & 0xfff,
        "method": code & 3,
    }

for code in (0x2220F0, 0x222120, 0x2221E0):
    print(hex(code), decode_ioctl(code))
```

これら3つのコードは、それぞれ `FILE_DEVICE_UNKNOWN`、`FILE_ANY_ACCESS`、`METHOD_BUFFERED` としてデコードされます。ただし、これだけでは権限のない呼び出し元がアクセスできる証拠にはなりません。デバイスの DACL、create/open のディスパッチ、リクエストごとの呼び出し元チェック、想定されるバッファ長、埋め込みポインター、PID のライフタイム処理、ハンドラーが呼び出し元の指定した PID やフラグを信頼するかどうかも確認してください。<sup>[[1]](#references)</sup>

implant が一部のコマンドしか使用しない場合でも、残りのハンドラーを死んだコードとして片付けず、プリミティブごとに分類してください。単一の多機能ドライバーが、以下のすべてのクラスを公開した事例があります。<sup>[[1]](#references)</sup>

- **制御/設定:** rootkit の状態を切り替える。保護対象のパス、プロセス、C2 アドレスを追加、削除、照会、またはクリアする。
- **プロセス操作:** PID を終了する、イメージをアンマップする、`NtCreateThreadEx` でインジェクトする、プロセスまたはユーザーモジュールを隠す/復元する、PPL 保護を解除する。
- **カーネル操作:** ロード済みドライバーのリンクを解除する、通知コールバックを列挙/無効化/復元する、別のドライバーを手動マップする、任意のカーネルアドレスに書き込む。
- **オブジェクト操作:** ファイルを削除/復号する、レジストリ値を作成または変更する。

## 脆弱な署名済みドライバーを介した手動カーネルマッピング

カーネルメモリの読み書き機能を備えた署名済みドライバーは、Windows に通常のドライバーとしてロードさせずに、未署名のドライバーイメージをロードするローダーとして利用できます。<sup>[[2]](#references)[[7]](#references)</sup> LocalStranger の例は既存の `\\.\WinNotify` デバイスを開きますが、そのソースからは、任意のホストで権限のないユーザーがドライバーをインストール、起動、またはオープンできるとは確認できません。<sup>[[2]](#references)[[3]](#references)</sup> mapper はイメージのパスを受け取り、ロード済みカーネルのベースアドレスを照会し、デバイスの仮想メモリ読み書き用 IOCTL を使用します。<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup>

この読み書きアクセスをカーネル呼び出しに利用するため、mapper は `MmGetVirtualForPhysical` 内の PTE ベース即値を読み取り、`NtAddAtom` を含むページングエントリーをたどります。<sup>[[5]](#references)[[7]](#references)</sup> PTE の計算式は `PteBase + ((VA >> 9) & 0x7FFFFFFFF8)` です。コードは large-page PDE も確認します。<sup>[[5]](#references)[[7]](#references)</sup> 対象エントリーを一時的に書き込み可能にし、syscall エントリーを目的のカーネル関数へのジャンプに置き換えてから、ユーザーモードの `NtAddAtom` stub を呼び出し、最後に元のバイト列とページエントリーを復元します。<sup>[[6]](#references)</sup>

mapper はこの呼び出し経路を使って `ExAllocatePool` を呼び出し、PE セクション、インポート、再配置情報をイメージにマップして、割り当て領域に書き込み、エントリポイントを呼び出します。<sup>[[7]](#references)[[8]](#references)</sup> この実装が受け付けるのは x64 の再配置可能な PE イメージのみです。また、PTE ベースの読み取りは固定された `MmGetVirtualForPhysical + 34` のレイアウトを前提としています。<sup>[[5]](#references)[[8]](#references)</sup> これはビルドに依存する手法として扱い、独立した KASLR バイパスや、HVCI または PatchGuard がこのマッピングを許可する証拠とは見なさないでください。<sup>[[5]](#references)[[8]](#references)</sup> カーネル R/W をデータのみの用途に使う方法については、[SYSTEM token theft](arbitrary-kernel-rw-token-theft.md) を参照してください。

## 信頼済みプロセスの例外

有用な設計パターンは、PID と **trusted** フラグを登録する IOCTL です。同じ信頼性の照会が、ファイル、レジストリ、プロセス、スレッドの各フィルターで使われます。信頼されていないツールには、フィルター済みの列挙結果、制限されたハンドル権限、または `STATUS_ACCESS_DENIED` を返す一方で、implant は自身の隠しオブジェクトを更新できます。これを認可境界として扱い、エントリーの認証、同期、およびプロセス終了後や PID 再利用時の削除方法を確認してください。<sup>[[1]](#references)</sup>

rootkit はポリシーを `REG_MULTI_SZ` 値に保存し、ファイル、ディレクトリ、レジストリキー、レジストリ値、無視対象イメージ、保護対象イメージ、隠しイメージのリストを AVL tree にコンパイルできます。分析時は、これらの共有ツリーを読み書きするすべての箇所を追跡してください。関数名が削除されていても、レジストリ設定、IOCTL、コールバック、フィルタリングロジックのつながりを特定できます。<sup>[[1]](#references)</sup>

## DKOM によるプロセスとモジュールの隠蔽

### `EPROCESS.ActiveProcessLinks`

`ActiveProcessLinks` のオフセットは Windows のビルドによって異なります。バージョンに依存しない rootkit は、既知の候補をテストし、隣接エントリーが候補自身を指し返す、一貫性のある `LIST_ENTRY` を `EPROCESS` 内でスキャンできます。検出したオフセットを保持し、隣接エントリーの `Flink`/`Blink` をつなぎ直してプロセスを隠し、後でエントリーを再リンクできるよう状態を保存します。プロセスは実行を続けますが、アクティブプロセスリストをたどる列挙ツールからは見えなくなります。<sup>[[1]](#references)</sup>

これは **DKOM** であり、プロセスの終了ではありません。検出では、リストベースの結果を、pool/object スキャン、スレッドの所有関係、ハンドルテーブル、スケジューラーの痕跡、カーネルメモリの調査など、独立した証拠と比較してください。スキャンでは見つかる一方で正規リストには存在しないプロセスは、どちらか一方の結果だけを見るよりも重要な兆候です。<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

同様のモジュール隠蔽プリミティブは、`PsLoadedModuleList` 内で対象エントリーを見つけ、隣接する `Flink`/`Blink` ポインターを書き換えます。ドライバーはマップされたまま実行可能ですが、リストに基づくモジュール照会では表示されません。ローダーリストを、実行可能なカーネルマッピング、pool tag、デバイス/ドライバーオブジェクト、サービスキー、コールバックアドレス、リストに含まれないイメージを指すディスパッチポインターと比較してください。<sup>[[1]](#references)</sup>

## コールバックベースの保護と隠蔽

rootkit は、文書化されたコールバックフレームワークを DKOM やフックと組み合わせることができます。<sup>[[1]](#references)</sup>

- `ObRegisterCallbacks` の pre-operation ハンドラーは、`PsProcessType` と `PsThreadType` に対して、信頼されていない呼び出し元が保護対象を開く際に、終了、VM アクセス、複製、スレッド操作に使われる権限を取り除きます。コールバックの altitude を記録し、各コールバックアドレスの所有モジュールを特定してください。
- `PsSetCreateProcessNotifyRoutineEx` と `PsSetLoadImageNotifyRoutine` は、プロセスやイメージの出現に応じて、保護/無視/隠蔽の状態を管理します。登録前から存在していたオブジェクトは、一度だけのプロセス走査で補完できます。
- ファイルシステムの minifilter は、設定されたパスへのアクセスを拒否します。通常と異なる実装では `Instances` キーを作成し、altitude を動的に選んで、`FltRegisterFilter` が競合を報告した場合に値を増やして再試行することがあります。
- `CmRegisterCallbackEx` ルーチンは、保護対象の名前を列挙結果から隠し、直接のオープン、名前変更、設定、削除操作を拒否しながら、登録済みの信頼済みプロセスを例外扱いできます。

`ObRegisterCallbacks` の登録、レジストリコールバックの altitude、`fltmc filters` の出力、サービスの `Instances` キー、コールバックアドレスを相関させてください。通常のツールがフィルターされている場合は、オフラインのメモリイメージ、または別の信頼できる取得レイヤーからこれらの構造体を調査してください。<sup>[[1]](#references)</sup>

## Nsiproxy の結果フィルタリング

ネットワークの隠蔽では、`\Driver\Nsiproxy` を対象にできます。`ObReferenceObjectByName` でドライバーオブジェクトを取得し、ハンドラーポインターを保存して、ラッパーに置き換えます。ユーザーモードに返す前に、IOCTL で管理される C2 リストに一致する IPv4 レコードを取り除きます。フィルターされた NSI データを使用するアプリケーションでは、通信が継続しているにもかかわらず、接続が表示されなくなることがあります。<sup>[[1]](#references)</sup>

ホスト上の接続表示を、パケットキャプチャ、WFP/ETW テレメトリー、カーネルメモリ内のネットワークオブジェクトと比較してください。また、`Nsiproxy` のディスパッチ/ハンドラーポインターを調査し、それぞれが想定された署名済みモジュール内を指していることを確認してください。リストにないマッピングを指すポインターがあれば、ネットワークフィルタリングと `PsLoadedModuleList` の DKOM を結び付けられる可能性があります。<sup>[[1]](#references)</sup>

## 調査チェックリスト

最も強い兆候は、単一のファイル名やハッシュではなく、レイヤー間の不一致です。以下を相関させてください。<sup>[[1]](#references)</sup>

1. カーネルサービスの作成と、証明書の経過年数、発行元、またはパスがインストール済み製品と一致しない署名済みドライバー。
2. デバイスの作成、DOS リンク、IOCTL トラフィック。ユーザーモードとカーネルのデバイス名の不一致も含みます。
3. PID 登録リクエストの後、他のプロセスが同じオブジェクトを開く、列挙する、変更する、または削除しようとして失敗すること。
4. オブジェクト/レジストリ/プロセス/イメージのコールバック、minifilter インスタンス、および通常の列挙で見つかるドライバーに属さないアドレスを持つフック。
5. リストベースとスキャンベースによる、プロセス、モジュール、コールバック、ネットワークの各インベントリの差異。

## References

- [1] [Kaspersky Securelist - HoneyMyte、署名済み Windows カーネル rootkit で CoolClient を強化](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [2] [LocalStranger README](https://github.com/nbs32k/LocalStranger/blob/master/README.md)
- [3] [LocalStranger ドライバーの初期化](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/init.c)
- [4] [LocalStranger mapper のコマンドライン](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/main.cpp)
- [5] [LocalStranger のカーネルエクスポートと PTE ベースの解決](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/utils.cpp)
- [6] [LocalStranger のカーネル呼び出しトランポリン](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.h)
- [7] [LocalStranger mapper の割り当てとエントリ呼び出し](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.cpp)
- [8] [LocalStranger の PE マッピング](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/pe.cpp)
- [9] [LocalStranger のカーネルと syscall コンテキスト](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/context.cpp)
- [10] [LocalStranger の仮想メモリ IOCTL ラッパー](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/virtual.c)
{{#include ../../banners/hacktricks-training.md}}
