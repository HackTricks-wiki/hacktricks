# Android Forensics

{{#include ../banners/hacktricks-training.md}}

## ロックされたデバイス

デバイスの状態を保持し、すべての操作を記録できる取得方法を優先します。デバイスがロックされている場合、利用可能な選択肢はモデル、Androidのバージョン、パッチレベル、押収前にアクセス設定が行われていたかどうかによって異なります。NISTは、デバイスと検査権限に応じて方法を選択することを推奨しています。<sup>[[1]](#references)</sup>

- USB debuggingが有効になっているか、また取得用ワークステーションがすでに承認されているかを確認します。ADB accessでは通常、ユーザーによるデバイスのロック解除と、ワークステーションのRSA keyの確認が必要です。<sup>[[3]](#references)</sup>
- 適用される法的および手続き上の規則に基づき、生体認証によるアクセスが引き続き利用可能かどうかを検討します。
- **smudge attack** により、画面に残った痕跡から graphical unlock pattern が明らかになる可能性がありますが、その後のタッチや清掃によって信頼性は低下します。<sup>[[2]](#references)</sup>
- 認可されたtoolingが対象のデバイスとソフトウェアビルドを正確にサポートしている場合、PIN、password、またはpatternの recovery や brute force を試行できることがあります。Hardware-backed credential verification、retry delay、wipe policyにより、この方法はデバイスに大きく依存します。そのため、Androidデバイスがサポートされていることを示す証拠として、iPhoneの technique や結果を代用しないでください。<sup>[[1]](#references)</sup>

## データ取得

古いデバイスでは、従来の [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) によって `.backup` file が生成され、Android Backup Extractorで展開できます。<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
すべてのアプリケーションを網羅しているとは限りません。ADB はこの command に deprecated のラベルを付けており、Android 12 では、app が debuggable でない限り、API level 31 以降を対象とする app の data は除外されます。<sup>[[4]](#references)</sup>

### Root または物理的な debug access

稼働中の device で root access を取得している場合は、まず partitions と mounts の inventory を作成します。以下の commands は、物理的な JTAG acquisition には直接適用できません。正しい block device は hardware に依存するため、常に `mmcblk0` であると想定しないでください。検証済みの source のみを別の storage に image 化します。<sup>[[1]](#references)</sup>

JTAG acquisition では、device の hardware test-access interface と互換性のある acquisition equipment を使用して、access 可能な memory を読み取ります。pinout、chipset の support、device の state、volatile target と non-volatile target の区別は device 固有です。その model の hardware path を document 化し、validated procedure を使用してください。<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
たとえば、partition inventory により `/dev/block/mmcblk0` が flash device 全体であり、保存先に十分な空き容量があることが確認された場合、元の acquisition command は次のようになります。<sup>[[1]](#references)</sup>
```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```
ここで、`df /data` は `/data` をマウントされたファイルシステムに関連付けるのに役立ちますが、`mmcblk0` が正しいデバイス全体のソースであることや、`4096` が有効な `dd` ブロックサイズとして唯一のものであることの証拠として扱ってはいけません。

結果を Hash 化し、正確なコマンド、デバイス識別子、時刻、および取得中に行った変更を記録します。<sup>[[1]](#references)</sup>

### Memory

LiME は Linux および一部の Android デバイスから物理メモリを取得できますが、その kernel module は対象 kernel 用に build し、十分な privileges で load する必要があります。Module signing、kernel lockdown、および modern Android hardening によって、load が阻止される場合があります。<sup>[[5]](#references)</sup>

この project's Android workflow では、ADB を使用して一致する module を push し、TCP port を forward し、root shell から module を load して、examination host 上で stream を capture します。<sup>[[5]](#references)</sup>
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
LiME は、`path=/sdcard/ram.lime` を指定してデバイスストレージに書き込むこともできますが、その場合はデバイスのストレージが変更され、十分な空き容量が必要になります。この副作用を記録し、取得したイメージをハッシュ化してください。<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - モバイルデバイスフォレンジックに関するガイドライン](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - スマートフォンのタッチスクリーンに対する Smudge Attacks](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Android 12 ADB backup restriction](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}
