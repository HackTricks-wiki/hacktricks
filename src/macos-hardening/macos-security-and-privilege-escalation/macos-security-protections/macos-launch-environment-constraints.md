# macOS Launch/Environment Constraints & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

macOSのLaunch constraintsは、**プロセスをどのように、誰が、どこから開始できるかを制御する**ことでセキュリティを強化するために導入されました。macOS Venturaで導入されたこの仕組みは、**各システムバイナリを個別のconstraint categoryに分類する**フレームワークを提供します。これらは、システムバイナリとそれぞれのhashを含むリストである**trust cache**内で定義されています。これらのconstraintsはシステム内のすべての実行可能バイナリに適用され、**特定のバイナリをlaunchする**ための要件を定める**ルール**の集合を構成します。ルールには、バイナリ自体が満たす必要のあるself constraints、親プロセスが満たす必要のあるparent constraints、その他の関連エンティティが従う必要のあるresponsible constraintsが含まれます。

この仕組みは、macOS Sonoma以降、third-party appにも**Environment Constraints**として拡張されました。これにより、developersはenvironment constraints用の**keyとvalueの集合**を指定して、自身のappを保護できます。

**launch environmentとlibrary constraints**はconstraint dictionaryで定義します。このdictionaryは、**`launchd` property list file**に保存するか、code signingで使用する**separate property list** fileに保存します。

constraintsには4つのタイプがあります。

- **Self Constraints**: **実行中の**バイナリに適用されるconstraints。
- **Parent Process**: **プロセスのparent**に適用されるconstraints（例: **`launchd`**がXP serviceを実行する場合）
- **Responsible Constraints**: XPC communicationで**serviceを呼び出すprocess**に適用されるconstraints。
- **Library load constraints**: library load constraintsを使用して、load可能なcodeを選択的に記述します。

そのため、あるprocessが`execve(_:_:_:)`または`posix_spawn(_:_:_:_:_:_:)`を呼び出して別のprocessをlaunchしようとすると、operating systemは**executable** fileがその**自身のself constraint**を**満たしている**ことを確認します。また、**parent** **process**のexecutableが、そのexecutableの**parent constraint**を**満たしている**こと、さらに**responsible** **process**のexecutableが、そのexecutableの**responsible process constraint**を**満たしている**ことも確認します。これらのlaunch constraintsのいずれかが満たされない場合、operating systemはprogramを実行しません。

libraryをloadする際に**library constraintの一部でも満たされない**場合、processはそのlibraryを**loadしません**。

## LC Categories

LCは、**facts**と、それらのfactsを組み合わせる**logical operations**（and、orなど）で構成されます。

[ **LCが使用できるfactsはdocumentedされています**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints)。例えば、次のようなものがあります。

- is-init-proc: executableがoperating systemのinitialization process（`launchd`）でなければならないかを示すBoolean value。
- is-sip-protected: executableがSystem Integrity Protection（SIP）によって保護されたfileでなければならないかを示すBoolean value。
- `on-authorized-authapfs-volume:` operating systemがauthorizedかつauthenticatedなAPFS volumeからexecutableをloadしたかを示すBoolean value。
- `on-authorized-authapfs-volume`: operating systemがauthorizedかつauthenticatedなAPFS volumeからexecutableをloadしたかを示すBoolean value。
- Cryptexes volume
- `on-system-volume:`operating systemが現在bootされているsystem volumeからexecutableをloadしたかを示すBoolean value。
- Inside /System...
- ...

Apple binaryにsignすると、**trust cache**内のLC categoryに**割り当てられます**。

- **iOS 16 LC categories**は[**こちらでreverseされ、documentedされています**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)。<sup>[6]</sup>
- 現在の**LC categories（macOS 14** - Somona）はreverseされており、その[**descriptionはこちらで確認できます**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)。<sup>[7]</sup>

例えば、Category 1は次のとおりです。<sup>[7]</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: System または Cryptexes volume 内に存在している必要があります。
- `launch-type == 1`: system service（LaunchDaemons 内の plist）である必要があります。
- `validation-category == 1`: operating system executable です。
- `is-init-proc`: Launchd

### LC Categories の Reversing

[**こちらで詳細を確認できます**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)が、基本的にこれらは**AMFI (AppleMobileFileIntegrity)**で定義されているため、Kernel Development Kitをダウンロードして**KEXT**を取得する必要があります。**`kConstraintCategory`**で始まるシンボルが**興味深い**ものです。これらを抽出するとDER (ASN.1) encoded streamが得られます。これを[ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php)またはpython-asn1 libraryとその`dump.py` script、[andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master)でdecodeすると、より理解しやすいstringが得られます。<sup>[3]</sup>

## Environment Constraints

これらは**third party applications**に設定されたLaunch Constraintsです。developerは、アプリケーションへのアクセスを制限するために、自身のアプリケーションで使用する**facts**と**logical operands**を選択できます。

以下を使用して、アプリケーションのEnvironment Constraintsをenumerateできます：
```bash
codesign -d -vvvv app.app
```
## Trust Caches

**macOS** には、いくつかの Trust Cache があります。

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

iOS では、**`/usr/standalone/firmware/FUD/StaticTrustCache.img4`** にあるようです。

> [!WARNING]
> Apple Silicon デバイス上で動作する macOS では、Apple 署名済みバイナリが Trust Cache に含まれていない場合、AMFI はそのロードを拒否します。

### Trust Caches の列挙

前述の Trust Cache ファイルは **IMG4** および **IM4P** 形式で、IM4P は IMG4 形式における payload セクションです。

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
（別の方法として、[**img4tool**](https://github.com/tihmstar/img4tool) を使用することもできます。このツールは、リリースが古くても M1 上で実行でき、x86_64 では適切な場所にインストールすれば実行できます）。

これで、[**trustcache**](https://github.com/CRKatri/trustcache) を使用して、情報を読みやすい形式で取得できます。
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
trust cache は次の構造に従うため、**LC category は4列目**です。
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
その後、[**このスクリプト**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) などを使用してデータを抽出できます。

そのデータから、**launch constraints の値が `0`** のアプリを確認できます。これらは制約されていないアプリです（各値の意味については[**こちらを確認**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)してください）。<sup>[6]</sup>

## 攻撃の緩和策

Launch Constraints は、**プロセスが予期しない条件で実行されないようにすることで**、いくつかの古い攻撃を緩和していました。例えば、予期しない場所から実行されたり、予期しない親プロセスによって起動されたりする場合です（起動できるのが launchd のみである場合）。

さらに、Launch Constraints は**downgrade attacks**も緩和します。

ただし、一般的な **XPC** abuse、**Electron** code injection、library validation を使用しない **dylib injection** は緩和しません（ライブラリをロードできる team ID が既知である場合を除きます）。<sup>[3]</sup>

### XPC Daemon Protection

Sonoma release では、daemon XPC service の**責任設定**が注目すべき点です。XPC service は接続する client が責任を負うのではなく、自身に対して責任を負います。これは feedback report FB13206884 に記載されています。この設定には欠陥があるように見えるかもしれません。これは、XPC service に対する特定の操作を可能にするためです。

- **XPC Service の起動**: bug だと仮定した場合でも、この設定では attacker code を通じて XPC service を開始することはできません。
- **Active Service への接続**: XPC service がすでに実行中の場合（元のアプリケーションによって起動された可能性があります）、接続を妨げる障壁はありません。

XPC service に constraints を実装することで、**潜在的な攻撃の window を狭める**ことは有益かもしれませんが、主要な懸念には対処できません。XPC service の security を確保するには、基本的に**接続する client を効果的に validation する**必要があります。これが service の security を強化する唯一の方法です。また、前述の責任設定は現在 operational であり、意図された design と一致していない可能性がある点にも注意してください。<sup>[3]</sup>

### Electron Protection

アプリケーションが **LaunchService によって opened される**必要がある場合でも（parents constraints 内で）、これは **`open`**（env variables を設定可能）を使用するか、**Launch Services API**（env variables を指定可能）を使用することで実現できます。<sup>[3]</sup>

### CVE-2025-43253 - spawn time に組み込み constraints を override する

Launch constraints（正式には **lightweight code requirements**、*LWCR*）は **AMFI MAC policy** によって強制されます。`posix_spawn` では、caller が **`posix_spawnattr_setmacpolicyinfo_np()`** を通じて任意の blob を MAC policy に渡せます。また、AMFI はこの経路を通じて caller が提供した LWCR dictionary を受け入れていました。この bug では、**attacker が提供した constraints が binary の組み込み constraints に追加して検証されるのではなく、それらを置き換えていました**。

- 最小限の（空でもよい）launch-constraints dictionary を構築する。
- **constraint category を `127` に設定する**。これは AMFI が spawn attributes では許可するものの、**enforce しない**値です。実行を block する代わりに、`Launch Constraint Violation (not enforcing)` とログに記録するだけです。
- それを spawn attributes 経由で渡すと、実際の self/parent constraints で禁止されるはずの context で process が launch されます。

修正後は、**組み込み constraints と提供された constraints の両方が validation される**ため、提供された dictionary によって組み込み constraints を弱めることはできなくなりました。<sup>[2]</sup>

> [!TIP]
> constraints enforcement を audit する際に探すべき一般的な形は次のとおりです。untrusted input に policy を *supply* させる API は、policy engine が supplied value を追加の requirement ではなく replacement として扱う場合に興味深い対象になります。

## References

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Live-Stream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: macOS の Launch Constraints を bypass する方法 (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch and Environment Constraints Deep Dive - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [system app または command tool が実行されない理由: Launch constraints と trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [environment constraints で Mac app を保護する - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [iOS 16 で導入された Launch Constraints の説明 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)

{{#include ../../../banners/hacktricks-training.md}}
