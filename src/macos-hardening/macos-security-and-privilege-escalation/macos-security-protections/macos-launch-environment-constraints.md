# macOS Launch/Environment Constraints & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

macOS の Launch constraints は、**プロセスをどのように、誰が、どこから開始できるかを制御する**ことでセキュリティを強化するために導入されました。macOS Ventura で導入され、**各システムバイナリを個別の constraint category に分類する framework**を提供します。これらは、システムバイナリとそれぞれの hash を含むリストである **trust cache** 内に定義されています。これらの constraints はシステム内のすべての executable binary に適用され、**特定の binary を起動する**ための要件を定める一連の **rules** を構成します。rules には、binary 自身が満たす必要のある self constraints、親プロセスが満たす必要のある parent constraints、その他の関連する entity が従う必要のある responsible constraints が含まれます。

この仕組みは macOS Sonoma から **Environment Constraints** によって third-party app にも拡張され、developer は **environment constraints 用の key と value の set**を指定して app を保護できるようになりました。

**launch environment と library constraints** は constraint dictionary で定義します。これは **`launchd` property list file** に保存するか、code signing で使用する **separate property list** file に保存します。

constraints には 4 つの type があります。

- **Self Constraints**: **実行中の** binary に適用される constraints。
- **Parent Process**: **プロセスの parent** に適用される constraints（例: **`launchd`** が XP service を実行する場合）
- **Responsible Constraints**: XPC communication において **service を呼び出している process** に適用される constraints
- **Library load constraints**: library load constraints を使用して、load 可能な code を選択的に記述します

したがって、ある process が `execve(_:_:_:)` または `posix_spawn(_:_:_:_:_:_:)` を呼び出して別の process を起動しようとすると、operating system は **executable** file がその **own self constraint** を満たしていることを確認します。また、**parent** **process** の executable が、その executable の **parent constraint** を満たしていること、および **responsible** **process** の executable が、その executable の responsible process **constraint** を満たしていることも確認します。これらの launch constraints のいずれかが満たされない場合、operating system は program を実行しません。

library を load する際に **library constraint の一部でも満たされない**場合、process は library を **load しません**。

## LC Categories

LC は **facts** と、それらの facts を組み合わせる **logical operations**（and、or など）で構成されます。

LC が使用できる [**facts は documented です**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints)。例:

- is-init-proc: executable が operating system の initialization process（`launchd`）でなければならないかどうかを示す Boolean value。
- is-sip-protected: executable が System Integrity Protection（SIP）によって保護された file でなければならないかどうかを示す Boolean value。
- `on-authorized-authapfs-volume:` operating system が executable を authorized かつ authenticated な APFS volume から load したかどうかを示す Boolean value。
- `on-authorized-authapfs-volume`: operating system が executable を authorized かつ authenticated な APFS volume から load したかどうかを示す Boolean value。
- Cryptexes volume
- `on-system-volume:` operating system が executable を現在 boot されている system volume から load したかどうかを示す Boolean value。
- Inside /System...
- ...

Apple binary は signed される際に、**trust cache** 内の LC category に **割り当てられます**。

- **iOS 16 LC categories** は[**こちらで reverse され、documented されています**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)。<sup>[[6]](#references)</sup>
- 現在の **LC categories（macOS 14** - Somona）は reverse され、[**その descriptions はこちらで確認できます**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)。<sup>[[7]](#references)</sup>

例えば Category 1 は次のとおりです。<sup>[[7]](#references)</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: System または Cryptexes volume 内に存在している必要があります。
- `launch-type == 1`: system service である必要があります（LaunchDaemons 内の plist）。
- `validation-category == 1`: operating system executable である必要があります。
- `is-init-proc`: Launchd

### LC Categories の Reversing

[**こちらで詳細を確認できます**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)が、基本的には **AMFI (AppleMobileFileIntegrity)** で定義されています。そのため、Kernel Development Kit をダウンロードして **KEXT** を取得する必要があります。**`kConstraintCategory`** で始まるシンボルが**重要なもの**です。これらを抽出すると DER (ASN.1) encoded stream が得られるため、[ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) または python-asn1 library とその `dump.py` script、[andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) を使用して decode する必要があります。これにより、より理解しやすい string が得られます。<sup>[[3]](#references)</sup>

## Environment Constraints

これらは **third party applications** に設定された Launch Constraints です。developer は、application 自体への access を制限するために、application 内で使用する **facts** と **logical operands** を選択できます。

次のコマンドで application の Environment Constraints を enumerate できます：
```bash
codesign -d -vvvv app.app
```
## トラストキャッシュ

**macOS** には、いくつかのトラストキャッシュがあります。

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

また、iOS では **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`** にあるようです。

> [!WARNING]
> Apple Silicon デバイス上で動作する macOS では、Apple によって署名された binary がトラストキャッシュに存在しない場合、AMFI はそのロードを拒否します。

### トラストキャッシュの列挙

前述のトラストキャッシュファイルは **IMG4** 形式であり、**IM4P** は IMG4 形式の payload セクションです。

[**pyimg4**](https://github.com/m1stadev/PyIMG4) を使用して、データベースの payload を抽出できます。
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
（別の方法として、[**img4tool**](https://github.com/tihmstar/img4tool) を使用することもできます。このツールは、リリースが古くても M1 で実行でき、x86_64 の場合も適切な場所にインストールすれば実行できます）。

これで、[**trustcache**](https://github.com/CRKatri/trustcache) を使用して、情報を読みやすい形式で取得できます：
```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```
Trust cache は以下の構造に従うため、**LC category は4列目**です。
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
その後、データを抽出するために、[**このスクリプト**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) のようなものを使用できます。

そのデータから、**launch constraints の値が `0` の Apps** を確認できます。これらは制約されていないものです（各値の意味については[**こちらを確認**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)してください）。<sup>[[6]](#references)</sup>

## 攻撃の緩和

Launch Constraints は、**プロセスが予期しない条件で実行されないようにする**ことで、過去の複数の攻撃を緩和できました。たとえば、予期しない場所から実行されたり、予期しない親プロセスによって呼び出されたりする場合です（launchd のみが起動すべき場合）。

さらに、Launch Constraints は**downgrade attacks**も緩和します。

ただし、一般的な **XPC** abuse、**Electron** code injection、または library validation のない **dylib injection** は緩和しません（ライブラリをロードできる team ID が既知の場合を除きます）。<sup>[[3]](#references)</sup>

### XPC Daemon Protection

Sonoma release では、daemon XPC service の**責任設定**が注目すべき点です。XPC service の責任は接続する client ではなく、XPC service 自身にあります。これは feedback report FB13206884 に記載されています。この構成には欠陥があるように見えるかもしれません。これは、XPC service に対する特定の操作を可能にするためです。

- **XPC Service の起動**: これが bug だと仮定した場合、この構成では attacker code を介して XPC service を起動することはできません。
- **稼働中の Service への接続**: XPC service がすでに実行中である場合（元の application によって起動された可能性があります）、接続を妨げる障壁はありません。

XPC service に constraints を実装することで、**攻撃の可能性がある期間を狭める**ことは有益かもしれませんが、主要な問題には対処できません。XPC service の security を根本的に確保するには、**接続する client を効果的に検証する**必要があります。service の security を強化する方法は、これだけです。また、前述の責任設定は現在 operational であり、意図された design と一致していない可能性がある点にも注意が必要です。<sup>[[3]](#references)</sup>

### Electron Protection

application が**LaunchService によって開かれている**必要がある場合でも（parents constraints 内で）、これは **`open`**（env variables を設定可能）を使用するか、**Launch Services API**（env variables を指定可能）を使用することで実現できます。<sup>[[3]](#references)</sup>

### CVE-2025-43253 - spawn 時に組み込み constraints を上書きする

Launch constraints（正式には **lightweight code requirements**、*LWCR*）は、**AMFI MAC policy** によって適用されます。`posix_spawn` では、caller が **`posix_spawnattr_setmacpolicyinfo_np()`** を通じて任意の blob を MAC policy に渡すことができます。AMFI はこの経路を通じて、caller が指定した LWCR dictionary を受け入れていました。この bug の問題は、**attacker が指定した constraints が、追加で検証されるのではなく binary の組み込み constraints を置き換えていた**ことです。

- 最小の（空でもよい）launch-constraints dictionary を構築する。
- **constraint category を `127` に設定する**。これは AMFI が spawn attributes では許可するものの、**enforce しない**値です。実行をブロックする代わりに、`Launch Constraint Violation (not enforcing)` とだけログに記録します。
- spawn attributes を介して渡すと、実際の self/parent constraints なら禁止していた context で process が起動します。

修正後は、**組み込み constraints と指定された constraints の両方**が検証されるため、指定された dictionary によって組み込み constraints を弱めることはできなくなりました。<sup>[[2]](#references)</sup>

> [!TIP]
> constraint enforcement を audit する際に探すべき一般的な形は次のとおりです。untrusted input が policy を *supply* できる API は、policy engine が指定された値を追加要件ではなく置換値として扱う場合、興味深い対象になります。

## References

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Live-Stream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: macOS の Launch Constraints を bypass する (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch and Environment Constraints Deep Dive - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [なぜ system app や command tool は実行されないのか？Launch constraints と trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [environment constraints で Mac app を保護する - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [iOS 16 で導入された Launch Constraints の説明 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)

{{#include ../../../banners/hacktricks-training.md}}
