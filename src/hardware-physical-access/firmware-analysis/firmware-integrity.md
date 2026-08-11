# Firmwareの完全性

{{#include ../../banners/hacktricks-training.md}}

認証済みの評価で、firmware署名の検証が弱い、または存在しないことが判明した場合、modified firmware imageによって完全性への影響を実証できます。以下のlab workflowでは、元の抽出、emulation、repacking手順を維持しながらbind shellを追加します。<sup>[[2]](#references)[[3]](#references)</sup>

1. firmwareはfirmware-mod-kit (FMK)を使用して抽出できます。
2. 対象firmwareのarchitectureとendiannessを特定します。
3. 環境に適した方法として、Buildrootなどを使用してcross compilerを構築します。
4. cross compilerを使用してbackdoorをbuildします。
5. backdoorを抽出したfirmwareの`/usr/bin` directoryにコピーします。
6. 適切なQEMU binaryを抽出したfirmwareのrootfsにコピーします。
7. chrootとQEMUを使用してbackdoorをemulateします。
8. netcat経由でbackdoorにアクセスします。
9. 抽出したfirmwareのrootfsからQEMU binaryを削除します。
10. FMKを使用してmodified firmwareをrepackageします。
11. firmware analysis toolkit (FAT)でemulateし、netcatを使用して対象backdoorのIPとportに接続することで、backdoored firmwareをtestします。

dynamic analysis、bootloader manipulation、またはhardware security testingによってすでにroot shellを取得している場合、implantsやreverse shellsなどのprecompiled test binariesを実行できます。Metasploitの`msfvenom`は、このvalidation workflow用にarchitecture-specific payloadを生成できます。<sup>[[4]](#references)</sup>

1. 対象firmwareのarchitectureとendiannessを特定します。
2. Msfvenomを使用して、target payload、attacker hostのIP、listening port number、filetype、architecture、platform、およびoutput fileを指定できます。
3. payloadをcompromised deviceに転送し、execution permissionsが付与されていることを確認します。
4. msfconsoleを起動し、payloadに従ってsettingsを設定することで、Metasploitがincoming requestsを処理できるよう準備します。
5. meterpreter reverse shellをcompromised device上で実行します。

## 認証なしでprivileged update protocolsに接続できるtransport bridges

embedded designでよくある誤りは、**同じinternal command protocolを複数のtransportで公開しながら、認証をそのうち1つでしか適用しないこと**です。たとえば、USBではchallenge-responseが必要でも、BLEでは認証なしの**GATT writes**を同じprivileged firmware-update handlerにそのまま転送している場合があります。<sup>[[1]](#references)</sup>

Typical offensive workflow:

1. BLE GATT databaseをenumerateし、公式mobile appが使用するwritable characteristicsを特定します。
2. app trafficをsniffし、有線protocolと一致する**magic bytes / opcodes**を探します。
3. **pairingなし**でBLE経由でprivileged commandsをreplayし、sensitive operationsが引き続き機能するか確認します。
4. firmware upgrade、config write、debug、またはfactory-test opcodesに到達できる場合、BLEを**radio-reachable admin port**として扱います。

Quick checks:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
逆アセンブル時に確認する事項:

- BLE には **pairing/bonding** が必要か、それとも単純な接続だけでよいか?
- すべての transport が同じ内部 dispatcher table にルーティングされているか?
- privileged opcode は USB / BLE / UART / Wi-Fi で異なる方法によりフィルタリングされているか?
- mobile app から firmware update、recovery、または diagnostic handler をリモートでトリガーできるか?

## Checksum-only firmware containers are still attacker-controlled firmware

**unkeyed checksum** (CRC32、SHA-256、MD5 など) のみによって保護された firmware container は、改ざん検出は提供しますが、**authenticity** は提供しません。attacker が update routine に到達できる場合、image にパッチを適用し、checksum を再計算して、任意の code を flash できます。<sup>[[1]](#references)</sup>

RE 中の red flags:

- Update code が `CHK2`、`CRC`、`SHA256` などの末尾の checksum blob だけを検証している。
- signature verification または secure-boot root of trust が存在しない。
- device-bound MAC / HMAC / authenticated encryption が使用されていない。
- Recovery mode が同じ unauthenticated image format を受け入れる。

実践的な検証フロー:

1. Firmware container を抽出し、bootloader、main firmware、integrity metadata を特定する。
2. Image 内の無害な string または banner を変更する。
3. Updater が期待する形式で checksum を正確に再計算する。
4. 通常の update path を通じて image を reflash する。
5. Boot 時に変更を確認し、任意の firmware replacement が可能であることを証明する。

これが BLE/Wi-Fi などのリモート到達可能な transport 経由で機能する場合、この bug は実質的に **unauthenticated OTA firmware replacement** となります。

## Turning a trusted USB peripheral into BadUSB via firmware reflashing

対象 device が USB 経由で host からすでに信頼されている場合、malicious firmware は新しい USB stack 全体を実装する必要がないことがあります。多くの場合、より簡単な pivot は **existing HID support** の **reuse** です。<sup>[[1]](#references)</sup>

有用な pattern:

1. Device がすでに **HID Consumer Control** / media / vendor HID interface として enumerate されているか確認する。
2. Firmware 内の既存の **HID report descriptor** を特定する。
3. Descriptor entry を追加または置換し、device が **keyboard** capability も advertise するようにする。
4. 新しい transport implementation を記述する代わりに、HID report をすでに送信している既存の firmware routine を reuse する。
5. Key press + key release report を inject して host 上で command を入力する。

これにより、PC は reflash された peripheral を正規の keyboard として信頼するため、firmware compromise が **host compromise** に変わります。

### Minimal assessment checklist

- `dmesg`、Device Manager、または USB descriptor に既存の HID interface が表示されるか?
- Report descriptor の近く、または relocatable descriptor table に空き領域があるか?
- 既存の media-control send routine を keyboard report に reuse できるか?
- Reflash 後、host が新しい keyboard interface を自動的に受け入れるか?

## Reliable payload execution inside RTOS firmware

ランダムな code path に fragile な trampoline を挿入する代わりに、通常の operation では未使用または影響の小さい **existing RTOS task** を探します。<sup>[[1]](#references)</sup>

これが有用な理由:

- Scheduler が boot 中に payload を自然に開始する。
- Critical control flow の破損を回避できる。
- Latency-sensitive な USB/network handler 内で実行する場合と比べ、delayed payload は watchdog reset を引き起こしにくい。

適した target は、通常の usage では dormant に見える diagnostic、factory-test、telemetry、または coprocessor service task です。

## Fast exploit iteration: repurpose benign protocol handlers

Firmware patching が可能になったら、RE を高速化する簡潔な方法は、無害な command handler (たとえば **echo/debug opcode**) を custom **memory read / write / execute** primitive で overwrite することです。これにより、実験ごとに full reflashing を行う必要がなくなり、modified handler を高速な wired transport 経由で device がサポートしている場合に特に有用です。<sup>[[1]](#references)</sup>

これを使用して:

- Scatter-loaded memory map を検証する
- Heap/task state を live で調査する
- Flash に書き込む前に小さな payload をテストする
- Function pointer、string、descriptor table を安全に復元する

## References

- [1] [Pwnd Blaster: スピーカーに一切触れずにスピーカーを使って PC を hack する方法](https://blog.nns.ee/2026/06/03/katana-badusb/)
- [2] [firmware-mod-kit](https://github.com/rampageX/firmware-mod-kit)
- [3] [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit)
- [4] [Metasploit - `msfvenom` の使用方法](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html)
{{#include ../../banners/hacktricks-training.md}}
