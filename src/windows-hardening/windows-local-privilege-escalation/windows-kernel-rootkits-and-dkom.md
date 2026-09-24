# Windows Kernel Rootkits and DKOM

{{#include ../../banners/hacktricks-training.md}}

## スコープ

侵害後の implant は、署名済み kernel driver を service としてロードし、`IRP_MJ_DEVICE_CONTROL` を介して user-mode の control plane を公開できます。Driver signing は Windows がイメージを受け入れることを示すだけであり、IOCTL の認可、メモリ操作、callbacks、hooks が安全であることを保証するものではありません。ある rootkit の解析では、通常動作中に3つの handlers を使用していましたが、追加の post-exploitation primitives を数十個公開していました。そのため、reverse engineering では malware trace で観測された requests だけでなく、dispatcher 全体を対象にする必要があります。<sup>[[1]](#references)</sup>

## Signed-driver と IOCTL のトリアージ

`DriverEntry` から開始し、device objects と DOS symbolic links を記録し、`MajorFunction[IRP_MJ_DEVICE_CONTROL]` routine を特定して、handler に到達するすべての比較処理と table エントリをマッピングします。user mode が開く names と、driver が実際に作成する names を照合します。ある観測された chain では `\\.\msagent` を開いていましたが、その driver は `\Device\ToolTool` と `\DosDevices\ToolTool` を作成していました。この不一致から、別の sample/configuration、欠落した setup logic、または解析上の不整合を特定できる場合があります。<sup>[[1]](#references)</sup>

各 control code の input structure を再構築する前に、その control code を decode します。<sup>[[1]](#references)</sup>
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
これら3つのコードは、それぞれ `FILE_DEVICE_UNKNOWN`、`FILE_ANY_ACCESS`、`METHOD_BUFFERED` としてデコードされます。これは、権限のない caller がそれらに到達できることを**証明するものではありません**。デバイス DACL、create/open dispatch、リクエストごとの caller チェック、想定されるバッファ長、埋め込みポインタ、PID のライフタイム処理、さらに handler が caller から提供された PID や flag を信頼しているかどうかも確認してください。<sup>[[1]](#references)</sup>

implant が一部のコマンドだけを使用する場合、残りの handler を dead code として片付けるのではなく、primitive ごとに分類してください。ある単一の multifunction driver では、次のすべてのクラスが公開されていました。<sup>[[1]](#references)</sup>

- **Control/configuration:** rootkit の状態を切り替える、保護対象の path、process、C2 address を追加、削除、照会、またはクリアする。
- **Process manipulation:** PID を終了する、image を unmap する、`NtCreateThreadEx` で inject する、process または user module を hide/restore する、PPL protection を削除する。
- **Kernel manipulation:** loaded driver の link を解除する、notification callback を列挙、無効化、復元する、別の driver を手動で map する、任意の kernel address に write する。
- **Object manipulation:** file を削除または decrypt し、registry value を作成または変更する。

## Trusted-process exemptions

有用な設計パターンとして、PID と **trusted** flag を登録する IOCTL があります。同じ trust lookup が file、registry、process、thread filter から参照されます。untrusted tool には filter 済みの列挙結果、縮小された handle 権限、または `STATUS_ACCESS_DENIED` が返される一方、implant は自身の hidden object を更新できます。これを authorization boundary として扱い、entry がどのように認証、同期され、process の終了または PID の再利用後に削除されるかを確認してください。<sup>[[1]](#references)</sup>

rootkit は `REG_MULTI_SZ` value に policy を永続化し、file、directory、registry-key、registry-value、ignored-image、protected-image、hidden-image の list を AVL tree にコンパイルできます。分析時には、これらの共有 tree のすべての reader と writer を追跡してください。これにより、function name が削除されていても、registry configuration、IOCTL、callback、filtering logic の関連性を把握できます。<sup>[[1]](#references)</sup>

## DKOM process and module hiding

### `EPROCESS.ActiveProcessLinks`

`ActiveProcessLinks` の offset は Windows build ごとに異なります。version-tolerant な rootkit は既知の候補をテストし、その後 `EPROCESS` を scan して、neighbor が候補を指し返す自己整合的な `LIST_ENTRY` を探します。検出した offset を保持し、process を hide する際には neighbor の `Flink`/`Blink` を再接続し、後で entry を relink できるよう状態を保存します。process は実行を継続しますが、active-process list を走査する enumerator からは消えます。<sup>[[1]](#references)</sup>

これは終了処理ではなく **DKOM** です。検出では、list ベースの結果を、pool/object scan、thread ownership、handle table、scheduler artifact、kernel memory inspection などの独立した証拠と比較してください。scan では表示される一方で canonical list には存在しない process は、どちらか一方の view だけよりも有意な結果です。<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

同等の module-hiding primitive は、`PsLoadedModuleList` 内で対象 entry を探し、隣接する `Flink`/`Blink` pointer を patch します。driver は map されたまま実行可能ですが、list ベースの module query からは除外されます。loader list を、実行可能な kernel mapping、pool tag、device/driver object、service key、callback address、一覧に存在しない image 内を指す dispatch pointer と比較してください。<sup>[[1]](#references)</sup>

## Callback-based protection and cloaking

rootkit は、documented callback framework を DKOM や hook と組み合わせることができます。<sup>[[1]](#references)</sup>

- `ObRegisterCallbacks` の pre-operation handler は、`PsProcessType` と `PsThreadType` に対して、untrusted caller が保護対象を open した際に、termination、VM access、duplication、thread manipulation に使用される権限を削除します。callback の altitude を記録し、各 callback address を所有 module に解決してください。
- `PsSetCreateProcessNotifyRoutineEx` と `PsSetLoadImageNotifyRoutine` は、process と image の出現に応じて protected/ignored/hidden process state を維持します。registration 前から存在していた object については、1回限りの process walk で backfill できます。
- filesystem minifilter は、設定された path への access を拒否します。通常とは異なる実装では、`Instances` key を作成し、動的に altitude を選択し、`FltRegisterFilter` が collision を報告した場合に increment/retry することがあります。
- `CmRegisterCallbackEx` routine は、保護された name を enumeration から隠し、direct open、rename、set、delete operation を拒否できます。ただし、登録済みの trusted process は除外します。

`ObRegisterCallbacks` registration、registry-callback altitude、`fltmc filters` output、service `Instances` key、callback address を相関分析してください。通常の tool が filter されている場合は、offline memory image または別の trusted acquisition layer からこれらの構造体を調査してください。<sup>[[1]](#references)</sup>

## Nsiproxy result filtering

Network concealment は `\Driver\Nsiproxy` を対象にできます。`ObReferenceObjectByName` で driver object を取得し、handler pointer を保存して wrapper に置き換え、user mode に届く前に IOCTL で管理された C2 list と一致する返却済み IPv4 record を削除します。filter された NSI data を使用する application では、traffic が実際には存在していても connection が表示されなくなることがあります。<sup>[[1]](#references)</sup>

host の connection view を packet capture、WFP/ETW telemetry、kernel-memory network object と比較してください。また、`Nsiproxy` の dispatch/handler pointer を調査し、それぞれが想定される signed module 内に解決されることを確認してください。一覧に存在しない mapping 内を指す pointer は、network filtering と `PsLoadedModuleList` DKOM を関連付ける手掛かりになります。<sup>[[1]](#references)</sup>

## Investigation checklist

最も強い signal は、1つの filename や hash ではなく、layer 間の不一致です。次の情報を相関させてください。<sup>[[1]](#references)</sup>

1. Kernel-service creation と、certificate の年代、publisher、または path がインストール済み product と一致しない signed driver。
2. Device creation、DOS link、IOCTL traffic。user-mode と kernel の device name が一致しないケースも含みます。
3. PID registration request の後に、他の process から同じ object を open、enumerate、modify、または delete できないこと。
4. Object/registry/process/image callback、minifilter instance、hook の address が、通常の enumeration で確認できる driver に属していないこと。
5. list ベースと scan ベースによる process、module、callback、network inventory の差異。

## References

- [1] [Kaspersky Securelist - 署名付き Windows Kernel Rootkit により CoolClient を強化する HoneyMyte](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
