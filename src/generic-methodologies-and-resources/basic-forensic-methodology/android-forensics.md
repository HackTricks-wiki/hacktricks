# Android Forensics

{{#include ../../banners/hacktricks-training.md}}

## ロックされたデバイス

デバイスの状態を保持できる取得方法を優先し、実施したすべての操作を記録してください。デバイスがロックされている場合、利用できる選択肢はモデル、Androidのバージョン、パッチレベル、押収前にアクセスが設定されていたかどうかによって異なります。NISTは、デバイスと調査権限に応じた方法を選択することを推奨しています。<sup>[[1]](#references)</sup>

- USBデバッグが有効になっていたか、また取得用ワークステーションがすでに承認済みかを確認してください。通常、ADBへのアクセスには、ユーザーによるデバイスのロック解除と、ワークステーションのRSAキーの承認が必要です。<sup>[[3]](#references)</sup>
- 適用される法的・手続き上の規則の下で、生体認証によるアクセスが引き続き可能かどうかを検討してください。
- **smudge attack**では、画面に残った跡からグラフィカルなロック解除パターンを特定できる場合があります。ただし、その後のタッチや画面の清掃によって信頼性は低下します。<sup>[[2]](#references)</sup>
- 承認済みツールが対象のデバイスとソフトウェアビルドに対応している場合、PIN、パスワード、またはパターンの回復やbrute forceを試みることがあります。ハードウェアベースの認証情報検証、再試行の遅延、ワイプポリシーの影響はデバイスごとに異なるため、Androidデバイスが対応している証拠として、iPhone向けの手法や結果を代用しないでください。<sup>[[1]](#references)</sup>

## データ取得

古いデバイスでは、レガシーの[ADBバックアップ](../../mobile-pentesting/android-app-pentesting/adb-commands.md#legacy-adb-backup)によって`.backup`ファイルが生成される場合があります。このファイルはAndroid Backup Extractorで展開できます。<sup>[[6]](#references)</sup>

```bash
java -jar abe.jar unpack file.backup file.tar
```

すべてのアプリが取得できるとは限りません。ADBではこのコマンドは非推奨とされており、Android 12では、API level 31以降を対象とするアプリのデータは、そのアプリがdebuggableでない限り除外されます。<sup>[[4]](#references)</sup>

### Rootまたは物理的なdebugアクセス

稼働中のデバイスにrootアクセスできる場合、まずパーティションとマウントを一覧表示してください。以下のコマンドは、物理的なJTAG取得に直接適用できません。正しいブロックデバイスはハードウェアに依存するため、常に`mmcblk0`だと決めつけないでください。検証済みのソースのみを別のストレージにイメージ化してください。<sup>[[1]](#references)</sup>

JTAG取得では、デバイスのハードウェアテストアクセスインターフェースと互換性のある取得機器を使って、アクセス可能なメモリを読み取ります。ピン配置、チップセットのサポート、デバイスの状態、揮発性と不揮発性の対象の区別はデバイスごとに異なります。ハードウェアへのアクセス経路を記録し、そのモデルで検証済みの手順を使用してください。<sup>[[1]](#references)</sup>

```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```

たとえば、パーティション一覧から `/dev/block/mmcblk0` がフラッシュデバイス全体であり、保存先に十分な空き容量があることが確認できた場合、元の取得コマンドは次のようになります:<sup>[[1]](#references)</sup>

```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```

ここで、`df /data` は `/data` とマウントされているファイルシステムとの対応付けに役立ちますが、`mmcblk0` が正しいデバイス全体の取得元であることや、`4096` だけが有効な `dd` のブロックサイズであることの証明として扱うべきではありません。

取得結果をハッシュ化し、正確なコマンド、デバイス識別子、時刻、および取得中に行った変更を記録します。<sup>[[1]](#references)</sup>

### メモリ

LiME は Linux および一部の Android デバイスから物理メモリを取得できますが、対象のカーネル向けにビルドし、十分な権限でロードする必要があります。モジュール署名、カーネルロックダウン、最新の Android の強化機能によって、ロードできない場合があります。<sup>[[5]](#references)</sup>

このプロジェクトの Android ワークフローでは、ADB を使って対応するモジュールを転送し、TCP ポートを転送設定し、root シェルからモジュールをロードして、検査ホスト上でストリームを取得します。<sup>[[5]](#references)</sup>

```bash
adb push lime.ko /sdcard/lime.ko
adb forward tcp:4444 tcp:4444
adb shell
su
insmod /sdcard/lime.ko "path=tcp:4444 format=lime"
```

```bash
nc localhost 4444 > ram.lime
```

LiMEは代わりに`path=/sdcard/ram.lime`を指定してデバイスのストレージに書き込むこともできますが、これによりデバイスのストレージが変更され、十分な空き容量が必要になります。この副作用を記録し、取得したイメージのハッシュを計算してください。<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - モバイルデバイスフォレンジックのガイドライン](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - スマートフォンのタッチスクリーンに対するSmudge攻撃](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Android 12のADBバックアップ制限](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../../banners/hacktricks-training.md}}
