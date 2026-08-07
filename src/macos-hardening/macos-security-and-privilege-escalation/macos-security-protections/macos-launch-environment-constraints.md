# macOS Launch/Environment Constraints & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

macOSのLaunch constraintsは、**プロセスをどのように、誰が、どこから開始できるかを規制する**ことでセキュリティを強化するために導入されました。macOS Venturaで導入されたこの仕組みは、**各システムバイナリを個別のconstraintカテゴリに分類する**フレームワークを提供します。これらのカテゴリは、システムバイナリとそれぞれのハッシュを含むリストである**trust cache**内に定義されています。これらのconstraintsはシステム内のすべての実行可能バイナリに適用され、**特定のバイナリを起動する**ための要件を定める**ルール**を構成します。このルールには、バイナリ自身が満たす必要のあるself constraints、親プロセスが満たす必要のあるparent constraints、その他の関連エンティティが従う必要のあるresponsible constraintsが含まれます。<sup>[[1]](#references)[[4]](#references)</sup>

この仕組みは、macOS Sonoma以降、**Environment Constraints**によってthird-party appにも拡張されています。これにより開発者は、**Environment constraints用のキーと値のセット**を指定してアプリを保護できます。<sup>[[5]](#references)</sup>

**launch environmentとlibrary constraints**は、**`launchd`のproperty listファイル**、またはcode signingで使用する**個別のproperty list**ファイルに保存するconstraint dictionary内で定義します。<sup>[[5]](#references)</sup>

constraintsには4つの種類があります。

- **Self Constraints**: **実行中の**バイナリに適用されるconstraints。
- **Parent Process**: **プロセスの親**に適用されるconstraints（例: XP serviceを実行する**`launchd`**）
- **Responsible Constraints**: XPC通信で**serviceを呼び出すプロセス**に適用されるconstraints
- **Library load constraints**: library load constraintsを使用して、ロード可能なcodeを選択的に記述します

したがって、あるプロセスが`execve(_:_:_:)`または`posix_spawn(_:_:_:_:_:_:)`を呼び出して別のプロセスを起動しようとすると、オペレーティングシステムは**executable**ファイルがその**self constraint**を満たしていることを確認します。また、**parent** **process**のexecutableが、そのexecutableの**parent constraint**を満たしていること、および**responsible** **process**のexecutableが、そのexecutableのresponsible process constraintを満たしていることも確認します。これらのlaunch constraintsのいずれかが満たされない場合、オペレーティングシステムはプログラムを実行しません。

libraryのロード時に**library constraint**の一部でも満たされない場合、プロセスはそのlibraryを**ロードしません**。

## LC Categories

LCは、factsと、factsを組み合わせる**論理演算**（and、orなど）で構成されます。

LCが使用できる[**factsは文書化されています**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints)。例:

- is-init-proc: executableがオペレーティングシステムの初期化プロセス（`launchd`）でなければならないかを示すBoolean値。
- is-sip-protected: executableがSystem Integrity Protection（SIP）によって保護されたファイルでなければならないかを示すBoolean値。
- `on-authorized-authapfs-volume:` オペレーティングシステムが、認証済みで認可されたAPFS volumeからexecutableをロードしたかを示すBoolean値。
- `on-authorized-authapfs-volume`: オペレーティングシステムが、認証済みで認可されたAPFS volumeからexecutableをロードしたかを示すBoolean値。
- Cryptexes volume
- `on-system-volume:` オペレーティングシステムが、現在bootされているsystem volumeからexecutableをロードしたかを示すBoolean値。
- /System内...
- ...

Apple binaryに署名すると、**trust cache**内のLC categoryに割り当てられます。

- **iOS 16 LC categories**は[**こちらでreversedされ、文書化されています**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)。<sup>[[6]](#references)</sup>
- 現在の**LC categories（macOS 14** - Somona）はreversedされており、[**説明はこちらにあります**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)。<sup>[[7]](#references)</sup>

たとえば、Category 1は次のとおりです。<sup>[[7]](#references)</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: SystemまたはCryptexes volume上に存在している必要があります。
- `launch-type == 1`: system serviceである必要があります（LaunchDaemons内のplist）。
- `validation-category == 1`: operating system executableです。
- `is-init-proc`: Launchd

### LC Categoriesのリバース

[**こちらで詳しく説明しています**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)が、基本的には、これらは**AMFI (AppleMobileFileIntegrity)**で定義されています。そのため、Kernel Development Kitをダウンロードして**KEXT**を取得する必要があります。**`kConstraintCategory`**で始まるシンボルが**重要なもの**です。これらを抽出すると、DER（ASN.1）でエンコードされたストリームが得られます。これを[ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php)またはpython-asn1ライブラリとその`dump.py`スクリプト、[andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master)でデコードすると、より理解しやすい文字列が得られます。<sup>[[3]](#references)[[8]](#references)</sup>

## Environment Constraints

これらは、**third party applications**に設定されたLaunch Constraintsです。developerは、applicationへのアクセスを制限するために、自身のapplicationで使用する**facts**と**logical operands**を選択できます。

次の方法で、applicationのEnvironment Constraintsを列挙できます。
```bash
codesign -d -vvvv app.app
```
## Trust Caches

**macOS** には、いくつかの trust cache があります。

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

また、iOS では **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`** にあるようです。

> [!WARNING]
> Apple Silicon デバイス上で動作する macOS では、Apple によって署名された binary が trust cache に存在しない場合、AMFI はそのロードを拒否します。

### Trust Caches の列挙

前述の trust cache ファイルは **IMG4** 形式であり、**IM4P** は IMG4 形式の payload セクションです。

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
（別の方法として、[**img4tool**](https://github.com/tihmstar/img4tool)というツールを使用することもできます。このツールは、リリースが古くてもM1上で実行でき、適切な場所にインストールすればx86_64でも実行できます）。

これで、[**trustcache**](https://github.com/CRKatri/trustcache)ツールを使用して、情報を読みやすい形式で取得できます：
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
trust cacheは以下の構造に従うため、**LC categoryは4列目**です。
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
その後、データを抽出するために [**this one**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) のような script を使用できます。

そのデータから、**launch constraints value が `0`** の Apps を確認できます。これらは制約を受けていない Apps です（各値の意味については [**check here**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) を参照してください）。<sup>[[6]](#references)</sup>

## Attack Mitigations

Launch Constraints は、**process が予期しない条件で実行されないようにすることで、** いくつかの古い攻撃を軽減できました。たとえば、予期しない場所から実行されたり、予期しない parent process によって呼び出されたりする場合です（その process を起動できるのが launchd だけである場合）。

さらに、Launch Constraints は **downgrade attacks** も軽減します。

ただし、**一般的な XPC** abuse、**Electron** code injection、または library validation がない状態での **dylib injection** は軽減しません（library を load できる team ID が既知の場合を除きます）。<sup>[[3]](#references)</sup>

### XPC Daemon Protection

Sonoma release では、daemon XPC service の **responsibility configuration** が注目すべき点です。XPC service への接続 client が責任を負うのではなく、XPC service 自体が責任を負います。これは feedback report FB13206884 に記載されています。この構成には問題があるように見えるかもしれません。なぜなら、XPC service に対して一定の interaction が可能になるためです。

- **XPC Service の起動**: bug だと仮定した場合でも、この構成では attacker code を介して XPC service を開始することはできません。
- **Active Service への接続**: XPC service がすでに実行中の場合（元の application によって activate された可能性があります）、接続を妨げる barrier はありません。

XPC service に constraints を実装することで、**潜在的な攻撃の window を狭める** ことは有益かもしれませんが、primary concern には対処できません。XPC service の security を確保するには、基本的に **connecting client を効果的に validate する** 必要があります。service の security を強化する方法は、これしかありません。また、前述の responsibility configuration は現在 operational であり、intended design と一致していない可能性がある点にも注意してください。<sup>[[3]](#references)</sup>

### Electron Protection

application が **LaunchService によって opened される** 必要がある場合でも（parents constraints 内で）、これは **`open`**（env variables を設定可能）または **Launch Services API**（env variables を指定可能）を使用して実現できます。<sup>[[3]](#references)</sup>

### CVE-2025-43253 - Overriding the built-in constraints at spawn time

Launch constraints（正式には **lightweight code requirements**、*LWCR*）は **AMFI MAC policy** によって enforce されます。`posix_spawn` では、caller が **`posix_spawnattr_setmacpolicyinfo_np()`** を通じて任意の blob を MAC policy に渡すことができ、AMFI はその経路から caller-supplied LWCR dictionary を受け入れていました。この bug では、**attacker-supplied constraints が binary の built-in constraints に追加で検証されるのではなく、それらを置き換えていました**。

- 最小限の（空でもよい）launch-constraints dictionary を作成する。
- **constraint category を `127` に設定する**。これは AMFI が spawn attributes では許可するものの、**enforce しない** 値です。execution を block する代わりに、`Launch Constraint Violation (not enforcing)` と log するだけです。
- これを spawn attributes 経由で渡すと、実際の self/parent constraints なら禁止していた context で process が launch されます。

修正後は、built-in constraints と supplied constraints の **両方** が validate されるため、supplied dictionary によって built-in constraint を弱めることはできなくなりました。<sup>[[2]](#references)</sup>

> [!TIP]
> constraint enforcement を audit する際に探すべき一般的な形は次のとおりです。untrusted input が policy を *supply* できる API は、policy engine が supplied value を追加要件ではなく置き換えとして扱う場合に、興味深い対象となります。

## References

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Live-Stream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Bypassing Launch Constraints on macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch and Environment Constraints Deep Dive - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Why won't a system app or command tool run? Launch constraints and trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Protect your Mac app with environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Description of the Launch Constraints introduced in iOS 16 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)
- [8] [Beyond the good ol` LaunchAgents - about it in here](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)

{{#include ../../../banners/hacktricks-training.md}}
