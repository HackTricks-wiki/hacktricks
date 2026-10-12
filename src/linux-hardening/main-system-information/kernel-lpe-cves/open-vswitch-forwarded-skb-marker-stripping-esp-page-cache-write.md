# Open vSwitch forwarded-skb marker strippingによるESP page-cache writes

{{#include ../../../banners/hacktricks-training.md}}

Linux kernel exploitationで有効なパターンの1つは、**外部フラグメントを取り除かずにskbの所有権メタデータをロンダリングし、そのskbをインプレースで書き込むconsumerへ渡す**ことです。Open vSwitch (OVS)の場合、userspace upcallの失敗によって、まだ有効な`MSG_ZEROCOPY` skbから`SKBFL_SHARED_FRAG`がクリアされます。その後、ESPがread-only fileのpage-cache folioを直接上書きする形で復号します。これにより、決定論的なローカルpage-cache writeが可能になります。この問題はCVE-2026-90049、CVE-2026-89487、CVE-2026-80977として追跡されています。<sup>[[1]](#references)[[2]](#references)</sup>

これは従来のmemory corruptionではなく、Copy Fail/Dirty Frag系の問題です。raceやアドレス開示は不要で、対象fileは読み取り可能であればよく、変更されたbytesはdisk上ではなくpage cacheに存在します。<sup>[[2]](#references)[[3]](#references)</sup>

## セキュリティ不変条件: 外部フラグメントのmarkerを保持する

`SKBFL_SHARED_FRAG`は、skb fragmentが自分たちで所有していないstorageを参照する可能性があることを、インプレースconsumerに伝えます。ESP fast pathの`esp_input()`は、`skb_has_shared_frag()`がfalseの場合に限り、nonlinearかつunclonedなskbをインプレースで復号できます。それ以外の場合、`skb_cow_data()`がまずprivate storageを作成します。このconsumer側のチェックはDirty Fragの後に追加されました。<sup>[[5]](#references)</sup>

したがって、不変条件には独立した2つの要件があります。<sup>[[2]](#references)[[4]](#references)[[5]](#references)</sup>

1. インプレースwriterは`SKBFL_SHARED_FRAG`を確認し、変更前にshared dataをコピーしなければならない。
2. clone、coalesce、transfer、forwardingの各pathは、外部ページが引き続き紐付いている間、markerを保持しなければならない。

Fragnesiaは、`skb_try_coalesce()`でfragment descriptorを移動する際に2つ目のルールに違反しました。OVS pathは微妙に異なります。fragment自体はtransferせず、**元のskb上でmarkerをインプレースにクリアしてから、そのskbのforwardingを続けます**。<sup>[[2]](#references)[[4]](#references)</sup>

## 権限のないユーザーからのOVS到達性

OVSのkernel datapathは、`ovs_datapath`、`ovs_vport`、`ovs_flow`、`ovs_packet`などのgeneric-netlink familyを通じて制御されます。変更操作ではnamespace-awareな`GENL_UNS_ADMIN_PERM`が使われるため、`unshare -Urn`で実行するプロセスは、自身のnetwork namespace内でdatapathを作成し、vethを接続し、flow actionをインストールするために必要な`CAP_NET_ADMIN`を取得できます。OVS familyの解決によって`openvswitch.ko`がautoloadされる場合もあります。この攻撃面にhostの`CAP_SYS_MODULE`、`ovs-vsctl`、`ovs-vswitchd`は必要ありません。<sup>[[2]](#references)[[7]](#references)</sup>

重要なのは、次の2種類のupcallの違いです。<sup>[[2]](#references)[[7]](#references)</sup>

- **flow miss**はpacketを`ovs-vswitchd`に送信します。upcallが失敗すると、通常packetはdropされます。
- 明示的な`OVS_ACTION_ATTR_USERSPACE` actionは、選択したport IDに借用したcopyを送信した後、元のskbに対して後続のactionを実行します。

したがって、攻撃者は次のようなflowをインストールできます。<sup>[[1]](#references)[[2]](#references)</sup>

```text
in_port(1),ipv4 -> USERSPACE(pid=<unbound-portid>), OUTPUT(0)
```

選択された port ID を所有する listener は存在しないため、userspace action は予測どおり失敗する一方、後続の `OUTPUT` action により元のパケットは存続する。<sup>[[1]](#references)[[2]](#references)</sup>

## 根本原因: 生存するパケットに対する `skb_tx_error()`

脆弱な OVS upcall のエラーパスは `skb_tx_error(skb)` を呼び出す。この helper は、送信に失敗した後に skb が解放されるケースを想定して設計されていた。`skb_zcopy_clear()` を通じて zerocopy の bookkeeping を完了するが、その flag mask は従来 `SKBFL_SHARED_FRAG` も削除していた。OVS は userspace action のエラーを無視して action list の処理を続けたため、この helper の lifetime contract に違反した。<sup>[[1]](#references)[[2]](#references)</sup>

悪用可能な状態遷移は次のとおり。<sup>[[2]](#references)</sup>

```text
before failed upcall: flags=0xb, nr_frags=1, page-cache folio attached
skb_tx_error():       zerocopy flags, including SHARED_FRAG, are cleared
after failed upcall:  flags=0x0, nr_frags=1, same folio still attached
OUTPUT:               unmarked skb continues to local ESP input
```

これは `skb_zcopy()` が zerocopy state を見つけた場合にのみ機能します。`SKBFL_SHARED_FRAG` だけを持つ fragment では不十分です。`MSG_ZEROCOPY` を使うと `SKBFL_ZEROCOPY_ENABLE | SKBFL_SHARED_FRAG` が設定され、さらに `SKBFL_DONT_ORPHAN` も設定されます。後者により、OVS userspace copy 中に `skb_orphan_frags()` が foreign pages を置き換えずに済みます。<sup>[[2]](#references)[[3]](#references)</sup>

## write primitive の構築

エンドツーエンドのトリガーは、次の要素で構成されます。<sup>[[2]](#references)[[3]](#references)</sup>

1. `unshare -Urn` で private user namespace と network namespace に入ります。
2. `PROT_READ | MAP_SHARED` を指定して、読み取り可能な target file を map します。
3. 個別の sender netns と veth pair を使います。local loopback では借用した pages がコピーされ、primitive が無効になります。
4. OVS datapath と、失敗する `USERSPACE`-then-`OUTPUT` flow を構築します。
5. `rfc4106(gcm(aes))` と UDP port 4500 を使い、transport-mode ESP-in-UDP XFRM state をインストールします。
6. `[ESP header | mapped file bytes | invalid ICV]` の構成の iovec を使って、`MSG_ZEROCOPY` datagram を1つ送信します。

XFRM state は、AES-128-GCM の keying material として20 bytes を使います。内訳は、16 bytes の AES key と、それに続く4-byte の RFC 4106 salt です。選択した8-byte の explicit IV に対し、payload confidentiality は counter block `salt || IV || be32(2)` から始まります。counter value 1 は、代わりに authentication result をマスクします。<sup>[[2]](#references)[[6]](#references)</sup>

```bash
ip xfrm state add src 10.99.99.1 dst 10.99.99.2 proto esp \
  spi 0x42434445 mode transport \
  aead 'rfc4106(gcm(aes))' \
  0x000102030405060708090a0b0c0d0e0f11223344 128 \
  encap espinudp 4500 4500 0.0.0.0
```

OVSがmarkerを取り除くと、ESPはコピーなしのパスを取り、file-backed fragmentに対して `plaintext = ciphertext XOR keystream` を実行します。認証チェックはこの変換**後**に行われるため、すべてゼロの無効なICVでは、page-cacheのバイト列がすでに変更された後にのみ、パケットが `-EBADMSG` で失敗します。<sup>[[2]](#references)</sup>

### GCMを任意のバイト列に変換する

現在のバイトが `C` で、目的のバイトが `P` の場合、payloadの最初のkeystream byteは `C XOR P` でなければなりません。AES keyとsaltを固定した状態で、explicit IVの16-bit suffixを総当たりし、最初のkeystream byteの候補ごとに1つずつsuffixを事前計算します。<sup>[[2]](#references)[[3]](#references)[[6]](#references)</sup>

```text
for n in 0..0xffff:
    iv = 0xcccccccc || 0x0000 || be16(n)
    k0 = AES_K(salt || iv || be32(2))[0]
    first_suffix_for[k0] ??= n
```

公開されている実装では、ciphertext は32バイトに制限され、各パケットごとにファイルフラグメントが1バイト進みます。選択した先頭バイトは、前のパケットの最初の collateral byte を上書きします。`pread()` は各パケットの前に `C` を更新し、同じバイトはスキップされ、最後のパケットは要求範囲を超えて書き込まないよう短縮されます。そのため、256エントリのルックアップテーブルを使うと、このプリミティブは、異なるバイトごとにおよそ1パケットで実行できる、バイト単位の chosen-content page-cache write になります。<sup>[[2]](#references)[[3]](#references)</sup>

## Page-cache write to root

実用的なターゲットは、既存の setuid-root 実行ファイルです。PoC は最初の160バイトを、固定アドレスの読み取り/実行可能な `PT_LOAD` を1つ持ち、`PT_INTERP` がなく、`setuid(0)` を呼び出してから `execve("/bin/sh", ...)` を実行するコードを含む、完全な static ELF で置き換えます。これにより、元のバイナリのエントリポイント、PIE の配置、dynamic loader、relocation に関する前提を避けられます。<sup>[[2]](#references)[[3]](#references)</sup>

page cache は namespace 化されていないため、この変更は user namespace をまたいで可視です。変更された folio は dirty としてマークされないため、ディスクに書き戻されません。ターゲットがページキャッシュ上にある間に実行し、その後 `posix_fadvise(..., POSIX_FADV_DONTNEED)` で一時的な破損を破棄すると、以降の読み取りではディスク上の元の内容が再読み込みされます。<sup>[[2]](#references)[[3]](#references)</sup>

## Exposure checks and mitigation

まず、実際に使用しているベンダー kernel を確認してください。関連する exposure の条件は、unprivileged user namespace、OVS が利用可能または常駐していること、および ESP の実装が利用可能であることです。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
unshare -Urn true 2>/dev/null && echo 'user+net namespaces available'
sysctl user.max_user_namespaces kernel.unprivileged_userns_clone \
  kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
lsmod | grep openvswitch
modprobe -n -v openvswitch esp4 esp6 2>/dev/null
modinfo esp4 esp6 2>/dev/null | grep -E '^(name|alias):'
```

完全な修正シリーズを含む kernel にアップグレードしてください。最終修正では recirculation path にも対処し、共有される `skb_shinfo()` の状態を変更しないようにするとともに、`skb_zerocopy()` における関連する strip も修正します。<sup>[[1]](#references)[[2]](#references)</sup>

OVS を使用していない場合は、`blacklist` だけに頼らず、modprobe の `install` ルールを使って alias と by-name の両方によるロードを防いでください。ホストで IPsec を終端せず、ESP がモジュールとして組み込まれている場合、同じ制御で decrypt sink も取り除けます。<sup>[[2]](#references)</sup>

```conf
# /etc/modprobe.d/disable-unused-network-surfaces.conf
install openvswitch /bin/false
install esp4 /bin/false
install esp6 /bin/false
```

これらのルールは、モジュールがすでにロードされている場合や、その機能がカーネルに組み込まれている場合には役立ちません。非特権ユーザー namespace を無効にすると、namespace による機能の提供元もなくなりますが、ブラウザー、Flatpak、Podman、その他のサンドボックス／コンテナワークロードに支障をきたす可能性があります。<sup>[[2]](#references)</sup>

## レビューでの教訓

zero-copy networking を監査する際は、フラグメントをコピーまたは移動するヘルパーだけに調査対象を限定しないでください。グループ化されたフラグをクリアするエラー／完了処理用ヘルパーも特定し、すべての呼び出し元が文書化された skb のライフタイム契約に従っていることを確認してください。zerocopy のライフサイクルビットと一緒にグループ化されたページ所有権ビットは、クリア処理がフラグメントに直接アクセスしない場合でも、セキュリティ上重要です。<sup>[[1]](#references)[[2]](#references)</sup>

堅牢な修正では、action continuation や recirculation を含め、skb が存続しうるすべての経路をカバーし、クローン間で `skb_shinfo()` が共有されることも考慮する必要があります。コンシューマー側では、認証に失敗しても、in-place AEAD transform によってすでに行われた平文の書き込みは取り消されません。そのため、復号を開始する前に、ストレージが外部所有のものかどうかを確認する必要があります。<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Doyensec netdev 修正シリーズ: net: 転送された skb から zerocopy frag マーカーを削除しない](https://lore.kernel.org/netdev/4B5CCA6E-2C49-4F86-8C4E-E1BE15C16C0A@doyensec.com/T/#t)
- [2] [Doyensec: Open vSwitch の Forwarded-SKB マーカー削除により、決定論的な ESP page-cache LPE が可能になる](https://blog.doyensec.com/2026/09/17/ovs.html)
- [3] [Doyensec `ovs-pagecache-write` proof of concept](https://github.com/doyensec/ovs-pagecache-write)
- [4] [元の Fragnesia coalescing 経路に対する Linux の修正 (`f84eca581739`)](https://github.com/torvalds/linux/commit/f84eca5817390257cef78013d0112481c503b4a3)
- [5] [Linux ESP コンシューマー側の共有フラグメントチェック (`f4c50a4034e6`)](https://github.com/torvalds/linux/commit/f4c50a4034e6)
- [6] [RFC 4106: IPsec ESP における Galois/Counter Mode (GCM) の使用](https://datatracker.ietf.org/doc/html/rfc4106)
- [7] [Open vSwitch カーネル datapath のドキュメント](https://docs.openvswitch.org/en/latest/topics/datapath/)
{{#include ../../../banners/hacktricks-training.md}}
