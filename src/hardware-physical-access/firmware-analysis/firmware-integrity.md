# Firmware Integrity

{{#include ../../banners/hacktricks-training.md}}

**custom firmware や/または compiled binaries は、integrity や signature verification の欠陥を悪用するためにアップロードできます**。backdoor bind shell の compilation には、以下の手順を踏めます:

1. firmware は firmware-mod-kit (FMK) を使用して抽出できます。
2. target firmware の architecture と endianness を特定する必要があります。
3. Cross compiler は Buildroot など、環境に適した方法でビルドできます。
4. backdoor は cross compiler を使ってビルドできます。
5. backdoor を抽出した firmware の /usr/bin ディレクトリにコピーできます。
6. 適切な QEMU binary を抽出した firmware の rootfs にコピーできます。
7. backdoor は chroot と QEMU を使って emulation できます。
8. backdoor には netcat 経由でアクセスできます。
9. QEMU binary は抽出した firmware の rootfs から削除する必要があります。
10. 変更した firmware は FMK を使って repackaging できます。
11. backdoored firmware は firmware analysis toolkit (FAT) で emulating し、netcat を使って target backdoor IP と port に接続することでテストできます。

dynamic analysis、bootloader manipulation、または hardware security testing を通じてすでに root shell を取得している場合、implants や reverse shells のような precompiled malicious binaries を実行できます。Metasploit framework や 'msfvenom' のような automated payload/implant tools は、以下の手順で活用できます:

1. target firmware の architecture と endianness を特定する必要があります。
2. Msfvenom を使って、target payload、attacker host の IP、listening port number、filetype、architecture、platform、および output file を指定できます。
3. payload を compromised device に転送し、実行権限があることを確認します。
4. Metasploit は msfconsole を起動し、payload に応じて設定を行うことで、受信リクエストを処理できるように準備できます。
5. meterpreter reverse shell を compromised device 上で実行できます。

## Unauthenticated transport bridges to privileged update protocols

よくある embedded design のミスは、**同じ internal command protocol を複数の transports で公開しているのに、authentication をそのうち 1 つにしか強制していない**ことです。たとえば、USB は challenge-response を要求する一方で、BLE は unauthenticated **GATT writes** をそのまま同じ privileged firmware-update handler に流してしまうことがあります。

典型的な offensive workflow:

1. BLE GATT database を列挙し、公式 mobile app が使用する writable characteristics を特定します。
2. app traffic を sniff して、wired protocol と一致する **magic bytes / opcodes** を探します。
3. pairing なしで BLE 経由で privileged commands を replay し、sensitive operations がまだ動作するか確認します。
4. firmware upgrade、config write、debug、factory-test の opcodes に到達できる場合、BLE を **radio-reachable admin port** として扱います。

Quick checks:
```bash
# Enumerate services/characteristics
ble.enum <MAC>

# Replay a sniffed command
ble.write <MAC> <UUID> <HEX_DATA>

# gatttool equivalent
# gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_DATA>
```
逆アセンブル中に確認すべきこと:

- BLE は **pairing/bonding** を必要とするか、それとも単純な接続だけでよいか?
- すべての transport は同じ内部 dispatcher table にルーティングされるか?
- privileged opcodes は USB / BLE / UART / Wi-Fi で異なるフィルタリングを受けるか?
- mobile app は firmware update, recovery, または diagnostic handlers をリモートで起動できるか?

## Checksum のみの firmware container も、依然として attacker-controlled firmware である

**unkeyed checksum**（CRC32, SHA-256, MD5 など）だけで保護された firmware container は、破損検出は提供するが、**真正性**は提供しない。攻撃者が update routine に到達できるなら、image を patch し、checksum を再計算して、任意の code を flash できる。

RE 中の red flags:

- Update code が `CHK2`, `CRC`, `SHA256` などの末尾の checksum blob のみを検証している。
- signature verification や secure-boot の root of trust が存在しない。
- device-bound MAC / HMAC / authenticated encryption が使われていない。
- recovery mode が同じ unauthenticated な image format を受け入れる。

実用的な validation flow:

1. firmware container を抽出し、bootloader、main firmware、integrity metadata を特定する。
2. image 内の無害な文字列や banner を変更する。
3. updater が期待する形式で checksum を正確に再計算する。
4. 通常の update path から image を reflash する。
5. boot 時に変更を確認し、任意の firmware replacement が可能であることを証明する。

これが BLE/Wi-Fi のような remote から到達可能な transport 経由で動作するなら、バグは実質的に **unauthenticated OTA firmware replacement** である。

## 信頼された USB peripheral を firmware reflashing で BadUSB に変える

対象 device がすでに USB 経由で host から信頼されている場合、malicious firmware は完全な新しい USB stack を実装する必要がないことがある。より簡単な pivot は、しばしば既存の HID support を **reuse** することだ。

有用な pattern:

1. device がすでに **HID Consumer Control** / media / vendor HID interface として enumerate されるか確認する。
2. firmware 内の既存の **HID report descriptor** を特定する。
3. descriptor entry を追加または置換し、device が **keyboard** capability も宣言するようにする。
4. 新しい transport implementation を書く代わりに、すでに HID report を送信している既存の firmware routine を再利用する。
5. key press + key release report を注入して、host 上で command を入力させる。

これにより firmware compromise は **host compromise** になる。PC は reflashing 済み peripheral を正規の keyboard として信頼するからだ。

### 最小限の確認 checklist

- `dmesg`、Device Manager、または USB descriptors に既存の HID interface が表示されているか?
- report descriptor の近くに余裕領域、または relocatable な descriptor table があるか?
- 既存の media-control 送信 routine を keyboard report に再利用できるか?
- host は reflashing 後に新しい keyboard interface を自動的に受け入れるか?

## RTOS firmware 内で信頼性の高い payload 実行を行う

ランダムな code path に不安定な trampoline を挿入する代わりに、通常動作で未使用または影響の小さい **既存の RTOS task** を探すとよい。

これが有用な理由:

- scheduler が boot 中に自然に payload を開始してくれる。
- 重要な control flow を壊さずに済む。
- 遅延 payload は、latency に敏感な USB/network handler の内部で実行する場合より watchdog reset を引き起こしにくい。

良い target は、通常使用では休止しているように見える diagnostic、factory-test、telemetry、または coprocessor service task である。

## Fast exploit iteration: benign な protocol handler を repurpose する

firmware patching が可能になったら、RE を高速化する compact な方法として、無害な command handler（たとえば **echo/debug opcode**）をカスタムの **memory read / write / execute** primitive に置き換えるとよい。これにより、実験のたびに完全な reflashing を行う必要がなくなり、特に device が高速な wired transport 経由で modified handler をサポートする場合に有効だ。

これを使って:

- scatter-loaded memory map を検証する
- heap/task state を live で調べる
- 小さな payload を flash に書き込む前にテストする
- function pointer、string、descriptor table を安全に復元する

## References

- [Pwnd Blaster: Hacking your PC using your speaker without ever touching it](https://blog.nns.ee/2026/06/03/katana-badusb/)

{{#include ../../banners/hacktricks-training.md}}
