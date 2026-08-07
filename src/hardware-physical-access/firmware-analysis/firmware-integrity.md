# Firmware Integrity

{{#include ../../banners/hacktricks-training.md}}

**custom firmware やコンパイル済みバイナリをアップロードして、integrity または signature verification の脆弱性を悪用できる**。以下の手順で backdoor bind shell をコンパイルできる。

1. firmware は firmware-mod-kit（FMK）を使用して抽出できる。
2. 対象 firmware のアーキテクチャとエンディアンを特定する。
3. Buildroot または環境に適した他の方法を使用して cross compiler を構築する。
4. cross compiler を使用して backdoor をビルドする。
5. backdoor を抽出した firmware の /usr/bin ディレクトリにコピーする。
6. 適切な QEMU バイナリを、抽出した firmware の rootfs にコピーする。
7. chroot と QEMU を使用して backdoor をエミュレートする。
8. netcat 経由で backdoor にアクセスする。
9. 抽出した firmware の rootfs から QEMU バイナリを削除する。
10. FMK を使用して変更した firmware を再パッケージ化する。
11. firmware analysis toolkit（FAT）でエミュレートし、netcat を使用して対象 backdoor の IP とポートに接続することで、backdoor 化した firmware をテストできる。

dynamic analysis、bootloader manipulation、または hardware security testing によってすでに root shell を取得している場合は、implants や reverse shells などの事前コンパイル済みの悪意あるバイナリを実行できる。Metasploit framework や 'msfvenom' などの自動化された payload/implant ツールは、以下の手順で利用できる。

1. 対象 firmware のアーキテクチャとエンディアンを特定する。
2. Msfvenom を使用して、対象 payload、attacker host の IP、listening port 番号、filetype、アーキテクチャ、platform、および出力ファイルを指定できる。
3. payload を侵害したデバイスに転送し、実行権限が付与されていることを確認する。
4. msfconsole を起動し、payload に応じて設定を構成することで、Metasploit が incoming requests を処理できるよう準備する。
5. 侵害したデバイス上で meterpreter reverse shell を実行する。

## 認証なしで特権 update protocol に接続できる transport bridge

組み込みシステムでよくある設計上の誤りは、**同じ内部 command protocol を複数の transport 上で公開し、そのうち1つでしか認証を強制しないこと**である。たとえば、USB では challenge-response が必要なのに、BLE では認証なしの **GATT writes** が同じ特権 firmware-update handler に単純に転送される場合がある。<sup>[[1]](#references)</sup>

典型的な offensive workflow：

1. BLE GATT database を列挙し、公式 mobile app が使用する writable characteristics を特定する。
2. app の通信を sniff し、有線 protocol と一致する **magic bytes / opcodes** を探す。
3. **pairing なしで** BLE 経由で特権 command を replay し、sensitive operations が引き続き動作するか確認する。
4. firmware upgrade、config write、debug、または factory-test opcode に到達できる場合、BLE を **radio-reachable admin port** として扱う。

簡易チェック：
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
Things to verify while reversing:

- BLE では **pairing/bonding** が必要か、それとも単純な接続だけでよいか。
- すべての transport が同じ内部 dispatcher table にルーティングされているか。
- privileged opcode は USB / BLE / UART / Wi-Fi で異なる方法でフィルタリングされているか。
- mobile app から firmware update、recovery、または diagnostic handler をリモートでトリガーできるか。

## Checksum-only firmware containers are still attacker-controlled firmware

**unkeyed checksum**（CRC32、SHA-256、MD5 など）だけで保護された firmware container は、改ざんの検出はできますが、**authenticity** は保証しません。攻撃者が update routine に到達できる場合、image を patch し、checksum を再計算して、任意の code を flash できます。<sup>[[1]](#references)</sup>

RE 中の red flags:

- Update code が `CHK2`、`CRC`、`SHA256` などの末尾の checksum blob だけを検証している。
- signature verification または secure-boot root of trust が存在しない。
- device-bound MAC / HMAC / authenticated encryption が使用されていない。
- Recovery mode が同じ unauthenticated image format を受け入れる。

実践的な validation flow:

1. firmware container を抽出し、bootloader、main firmware、integrity metadata を特定する。
2. image 内の無害な string または banner を変更する。
3. updater が期待する形式で checksum を再計算する。
4. 通常の update path を通じて image を reflash する。
5. boot 時に変更を確認し、任意の firmware replacement が可能であることを証明する。

これが BLE/Wi-Fi などのリモート到達可能な transport 経由で機能する場合、この bug は実質的に **unauthenticated OTA firmware replacement** である。

## Turning a trusted USB peripheral into BadUSB via firmware reflashing

対象 device が USB 経由で host からすでに trusted されている場合、malicious firmware は新しい USB stack 全体を実装する必要がない可能性があります。多くの場合、より簡単な pivot は **existing HID support** の **reuse** です。<sup>[[1]](#references)</sup>

有用な pattern:

1. device がすでに **HID Consumer Control** / media / vendor HID interface として enumerate されているか確認する。
2. firmware 内の既存の **HID report descriptor** を特定する。
3. descriptor entry を追加または置換し、device が **keyboard** capability も advertise するようにする。
4. 新しい transport implementation を記述する代わりに、すでに HID report を送信している既存の firmware routine を reuse する。
5. key press + key release report を inject して、host 上で command を入力する。

これにより、firmware compromise が **host compromise** に変わります。PC は reflash された peripheral を legitimate keyboard として trust するためです。

### Minimal assessment checklist

- `dmesg`、Device Manager、または USB descriptor に既存の HID interface が表示されるか。
- report descriptor の近く、または relocatable descriptor table に spare room があるか。
- 既存の media-control send routine を keyboard report に reuse できるか。
- reflash 後、host が新しい keyboard interface を自動的に accept するか。

## Reliable payload execution inside RTOS firmware

random な code path に fragile な trampoline を挿入する代わりに、通常の operation で unused または low-impact な **existing RTOS task** を探します。<sup>[[1]](#references)</sup>

これが有用な理由:

- scheduler が boot 中に payload を自然に start する。
- critical control flow の破壊を避けられる。
- latency-sensitive な USB/network handler 内で実行する場合と比べ、delayed payload は watchdog reset を trigger する可能性が低い。

適切な target は、通常の usage では dormant に見える diagnostic、factory-test、telemetry、または coprocessor service task です。

## Fast exploit iteration: repurpose benign protocol handlers

firmware patching が可能になったら、RE を高速化する簡潔な方法として、harmless な command handler（例えば **echo/debug opcode**）を custom な **memory read / write / execute** primitive で overwrite します。これにより、すべての experiment のたびに full reflashing を行う必要がなくなり、modified handler を fast wired transport 経由で利用できる device では特に有用です。<sup>[[1]](#references)</sup>

次の用途に使用できます:

- scatter-loaded memory map の検証
- heap/task state の live inspection
- flash に burn する前の小さな payload の test
- function pointer、string、descriptor table の安全な recovery

## References

- [1] [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
