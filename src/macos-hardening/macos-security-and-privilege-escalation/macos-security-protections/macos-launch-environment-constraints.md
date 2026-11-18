# macOS Launch/Environment Constraints & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

macOSのLaunch Constraintsは、**プロセスをどのように、誰が、どこから起動できるかを制御する**ことでセキュリティを強化するために導入されました。macOS Venturaで導入されたこの仕組みは、**各システムバイナリを個別のconstraint categoryに分類する**フレームワークを提供します。これらのcategoryは、システムバイナリとそれぞれのハッシュを含むリストである**trust cache**内に定義されています。これらのconstraintsはシステム内のすべての実行可能バイナリに適用され、**特定のバイナリを起動するための要件**を定めた一連の**ルール**を含みます。このルールには、バイナリが満たす必要のあるself constraints、親プロセスが満たす必要のあるparent constraints、その他の関係するエンティティが遵守すべきresponsible constraintsが含まれます。<sup>[[1]](#references)[[4]](#references)</sup>

この仕組みはmacOS SonomaからEnvironment Constraintsを通じてサードパーティ製アプリにも拡張され、開発者は**環境constraints用のキーと値のセット**を指定してアプリを保護できます。<sup>[[5]](#references)</sup>

**launch environmentとlibrary constraints**はconstraint dictionaryで定義します。このdictionaryは、**`launchd`のproperty listファイル**に保存するか、コード署名で使用する**個別のproperty list**ファイルに保存します。<sup>[[5]](#references)</sup>

constraintsには4つの種類があります。

- **Self Constraints**: **実行中の**バイナリに適用されるconstraints。
- **Parent Process**: **プロセスの親**に適用されるconstraints（たとえば、`launchd`がXPサービスを実行する場合）。
- **Responsible Constraints**: XPC通信で**サービスを呼び出すプロセス**に適用されるconstraints。
- **Library load constraints**: 読み込み可能なコードを選択的に記述するために使用します。

プロセスが`execve(_:_:_:)`または`posix_spawn(_:_:_:_:_:_:)`を呼び出して別のプロセスを起動しようとすると、オペレーティングシステムは**実行可能ファイル**が自身の**self constraint**を**満たしている**ことを確認します。また、**親**プロセスの実行可能ファイルがその実行可能ファイルの**parent constraint**を**満たしている**こと、そして**responsible**プロセスの実行可能ファイルがその実行可能ファイルの**responsible process constraint**を**満たしている**ことも確認します。これらのlaunch constraintsのいずれかが満たされない場合、オペレーティングシステムはプログラムを実行しません。

ライブラリの読み込み時に**library constraint**の一部でも満たされない場合、プロセスはそのライブラリを**読み込みません**。

## LC Categories

LCは、複数のfactを組み合わせる**fact**と**論理演算**（and、orなど）で構成されます。

LCで使用できる[**factはドキュメントで説明されています**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints)。たとえば、次のものがあります。

- is-init-proc: 実行可能ファイルがオペレーティングシステムの初期化プロセス（`launchd`）でなければならないかを示すBoolean値。
- is-sip-protected: 実行可能ファイルがSystem Integrity Protection（SIP）によって保護されたファイルでなければならないかを示すBoolean値。
- `on-authorized-authapfs-volume:` オペレーティングシステムが、認証済みのAPFS volumeから実行可能ファイルを読み込んだかを示すBoolean値。
- `on-authorized-authapfs-volume`: オペレーティングシステムが、認証済みのAPFS volumeから実行可能ファイルを読み込んだかを示すBoolean値。
  - Cryptexes volume
- `on-system-volume:`オペレーティングシステムが、現在起動中のsystem volumeから実行可能ファイルを読み込んだかを示すBoolean値。
  - /System内など...
- ...

Appleのバイナリに署名すると、**trust cache**内のLC categoryに**割り当てられます**。

- **iOS 16のLC categories**は[**リバースエンジニアリングされ、こちらでドキュメント化されています**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)。<sup>[[6]](#references)</sup>
- 現行の**LC categories（macOS 14 - Somona）**はリバースエンジニアリングされており、[**説明はこちらで確認できます**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)。<sup>[[7]](#references)</sup>

たとえば、Category 1は次のとおりです。<sup>[[7]](#references)</sup>

```
Category 1:
        Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
        Parent Constraint: is-init-proc
```

- `(on-authorized-authapfs-volume || on-system-volume)`: System または Cryptexes volume 内にある必要があります。
- `launch-type == 1`: system service（LaunchDaemons 内の plist）である必要があります。
- `validation-category == 1`: operating system executable です。
- `is-init-proc`: Launchd

### LC Categories のリバース

[**こちらで詳細を確認できます**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)が、基本的にこれらは**AMFI (AppleMobileFileIntegrity)**で定義されています。そのため、Kernel Development Kit をダウンロードして**KEXT**を入手する必要があります。**`kConstraintCategory`**で始まるシンボルが**重要**です。これらを抽出すると DER (ASN.1) エンコードされたストリームが得られるので、[ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) または python-asn1 ライブラリとその `dump.py` スクリプト [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) でデコードすると、より理解しやすい文字列になります。<sup>[[3]](#references)[[8]](#references)</sup>

## Environment Constraints

これらは**サードパーティアプリケーション**に設定される Launch Constraints です。開発者は、アプリケーションへのアクセスを制限するために使用する**facts**と**論理演算子**を選択できます。

次の方法で、アプリケーションの Environment Constraints を列挙できます。

```bash
codesign -d -vvvv app.app
```

## トラストキャッシュ

**macOS** には、いくつかのトラストキャッシュがあります。

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

iOS では、**`/usr/standalone/firmware/FUD/StaticTrustCache.img4`** にあるようです。

> [!WARNING]
> Apple Silicon デバイスで動作する macOS では、Apple による署名済みのバイナリがトラストキャッシュに含まれていない場合、AMFI はその読み込みを拒否します。

### トラストキャッシュの列挙

前述のトラストキャッシュファイルは **IMG4** 形式です。**IM4P** は IMG4 形式のペイロードセクションです。

[**pyimg4**](https://github.com/m1stadev/PyIMG4) を使って、データベースのペイロードを抽出できます。

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

（別の方法として、[**img4tool**](https://github.com/tihmstar/img4tool) を使うこともできます。リリースが古くても、適切な場所にインストールすれば、M1上でもx86_64向けのものが実行できます。）

これで、[**trustcache**](https://github.com/CRKatri/trustcache) を使って情報を読みやすい形式で取得できます。

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

その後、[**こちら**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30)のようなスクリプトを使ってデータを抽出できます。

そのデータから、**launch constraints の値が `0` の**アプリを確認できます。これらは制約されていないアプリです（各値の意味については[**こちら**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)を確認してください）。<sup>[[6]](#references)</sup>

## 攻撃の緩和

Launch Constraints は、**プロセスが想定外の条件で実行されないようにする**ことで、いくつかの過去の攻撃を緩和できたはずです。たとえば、想定外の場所から実行される場合や、想定外の親プロセスによって起動される場合です（起動するのが launchd のみであるべき場合）。

さらに、Launch Constraints は**ダウングレード攻撃も緩和**します。

ただし、一般的な XPC の悪用、**Electron** のコードインジェクション、library validation がない状態での **dylib インジェクション**は緩和しません（ライブラリをロードできる team ID が判明している場合を除く）。<sup>[[3]](#references)</sup>

### XPC Daemon の保護

Sonoma リリースで注目すべき点は、daemon XPC service の**責任設定**です。接続するクライアントではなく、XPC service 自体が責任を負います。これはフィードバックレポート FB13206884 に記載されています。この設定には問題があるように思えるかもしれません。XPC service との次のようなやり取りが可能になるためです。

- **XPC Service の起動**: これがバグだと仮定した場合でも、この設定では攻撃者のコードを使って XPC service を起動できません。
- **起動中の Service への接続**: XPC service がすでに実行中であれば（元のアプリケーションによって起動された可能性があります）、接続を妨げるものはありません。

XPC service に制約を実装すれば、潜在的な攻撃の機会を**減らす**うえで役立つかもしれませんが、根本的な懸念には対処できません。XPC service のセキュリティを確保するには、接続するクライアントを**適切に検証すること**が不可欠です。これが service のセキュリティを強化する唯一の方法です。また、前述の責任設定は現在も動作しており、意図された設計と一致していない可能性がある点にも注意してください。<sup>[[3]](#references)</sup>

### Electron の保護

アプリケーションが **LaunchService によって開かれること**が必須であっても（親プロセスの制約で指定）、**`open`**（環境変数を設定可能）や **Launch Services API**（環境変数を指定可能）を使えば、この条件を満たせます。<sup>[[3]](#references)</sup>

ポリシー固有の spawn 属性を支える一般的な MACF の仕組みについては、[MACF policy-specific spawn attributes](macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input)を参照してください。

### CVE-2025-43253 - spawn 時に組み込み制約を上書きする

Launch constraints（正式名称は**軽量コード要件**、*LWCR*）は **AMFI MAC policy** によって強制されます。`posix_spawn` では、呼び出し元が **`posix_spawnattr_setmacpolicyinfo_np()`** を通じて任意の blob を MAC policy に渡せます。AMFI はこの経路で、呼び出し元が指定した LWCR 辞書を受け入れていました。このバグでは、**攻撃者が指定した制約が、バイナリに組み込まれた制約に追加で検証されるのではなく、それを置き換えていました**。

- 最小限の（空でもよい）launch-constraints 辞書を作成します。
- **制約カテゴリを `127` に設定**します。この値は AMFI が spawn 属性で許可しますが、**強制しません**。実行をブロックする代わりに、`Launch Constraint Violation (not enforcing)` をログに記録するだけです。
- spawn 属性を介して渡すと、実際の self/parent 制約であれば実行が禁止されるコンテキストでも、プロセスが起動します。

修正後は、組み込み制約と指定された制約の**両方**が検証されるため、指定された辞書によって組み込み制約が弱められることはなくなりました。<sup>[[2]](#references)</sup>

> [!TIP]
> 制約の強制を監査する際は、次のようなパターンを探してください。信頼できない入力からポリシーを*指定*できる API は、ポリシーエンジンがその値を追加要件ではなく置き換えとして扱う場合、特に注目すべきです。



## References

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (ライブ配信)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: macOS の Launch Constraints をバイパスする (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch and Environment Constraints Deep Dive - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [システムアプリやコマンドツールが実行されないのはなぜか？Launch constraints と trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [環境制約で Mac アプリを保護する - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [iOS 16 で導入された Launch Constraints の説明 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)
- [8] [従来の LaunchAgents を超えて - 詳細はこちら](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)
{{#include ../../../banners/hacktricks-training.md}}
