# macOS XPC 接続プロセスチェック

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

## XPC 接続プロセスチェック

XPCサービスへの接続が確立されると、サーバーは接続が許可されているかどうかをチェックします。通常、以下のチェックを行います：

1. 接続している**プロセスがAppleによって署名された証明書で署名されているか**をチェックします（Appleからのみ発行されます）。
   * これが**検証されない場合**、攻撃者は他のチェックに合わせて**偽の証明書**を作成する可能性があります。
2. 接続しているプロセスが**組織の証明書で署名されているか**をチェックします（チームIDの検証）。
   * これが**検証されない場合**、Appleの**任意の開発者証明書**を使用して署名し、サービスに接続することができます。
3. 接続しているプロセスに**適切なバンドルIDが含まれているか**をチェックします。
   * これが**検証されない場合**、同じ組織によって署名された任意のツールを使用してXPCサービスと対話することができます。
4. (4または5) 接続しているプロセスに**適切なソフトウェアバージョン番号があるか**をチェックします。
   * これが**検証されない場合**、古い、安全でないクライアントがプロセスインジェクションに対して脆弱であり、他のチェックがあってもXPCサービスに接続するために使用される可能性があります。
5. (4または5) 接続しているプロセスが危険な権限（任意のライブラリをロードしたりDYLD環境変数を使用するなど）なしにハード化されたランタイムを持っているかをチェックします。
   * これが**検証されない場合**、クライアントは**コードインジェクションに対して脆弱**である可能性があります。
6. 接続しているプロセスにサービスに接続することを許可する**権限**があるかをチェックします。これはAppleのバイナリに適用されます。
7. **検証**は接続している**クライアントの監査トークン**に**基づいて**行われるべきであり、プロセスID（**PID**）ではないため、前者は**PID再利用攻撃**を防ぐことができます。
   * 開発者は**監査トークン**のAPIコールを**ほとんど使用しません**。なぜならそれは**プライベート**であり、Appleはいつでも**変更**する可能性があるからです。さらに、プライベートAPIの使用はMac App Storeのアプリでは許可されていません。
   * **`processIdentifier`**メソッドが使用されている場合、それは脆弱である可能性があります
   * **`xpc_dictionary_get_audit_token`**は**`xpc_connection_get_audit_token`**の代わりに使用されるべきです。後者は[特定の状況で脆弱](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)である可能性があります。

### 通信攻撃

PID再利用攻撃についての詳細は以下をチェックしてください：

{% content-ref url="macos-pid-reuse.md" %}
[macos-pid-reuse.md](macos-pid-reuse.md)
{% endcontent-ref %}

**`xpc_connection_get_audit_token`**攻撃についての詳細は以下をチェックしてください：

{% content-ref url="macos-xpc_connection_get_audit_token-attack.md" %}
[macos-xpc\_connection\_get\_audit\_token-attack.md](macos-xpc\_connection\_get\_audit\_token-attack.md)
{% endcontent-ref %}

### Trustcache - ダウングレード攻撃防止

TrustcacheはApple Siliconマシンで導入された防御方法で、AppleのバイナリのCDHSAHのデータベースを保存し、許可された変更されていないバイナリのみが実行されるようにします。これにより、ダウングレードバージョンの実行が防止されます。

### コード例

サーバーは**`shouldAcceptNewConnection`**と呼ばれる関数でこの**検証**を実装します。

{% code overflow="wrap" %}
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
{% endcode %}

オブジェクト NSXPCConnection には、**プライベート**プロパティ **`auditToken`**（使用されるべきだが変更される可能性がある）と、**パブリック**プロパティ **`processIdentifier`**（使用されるべきではない）があります。

接続プロセスは以下のように検証できます：

{% code overflow="wrap" %}
```objectivec
[...]
SecRequirementRef requirementRef = NULL;
NSString requirementString = @"anchor apple generic and identifier \"xyz.hacktricks.service\" and certificate leaf [subject.CN] = \"TEAMID\" and info [CFBundleShortVersionString] >= \"1.0\"";
/* Check:
- Signed by a cert signed by Apple
- Check the bundle ID
- Check the TEAMID of the signing cert
- Check the version used
*/

// Check the requirements with the PID (vulnerable)
SecRequirementCreateWithString(requirementString, kSecCSDefaultFlags, &requirementRef);
SecCodeCheckValidity(code, kSecCSDefaultFlags, requirementRef);

// Check the requirements wuing the auditToken (secure)
SecTaskRef taskRef = SecTaskCreateWithAuditToken(NULL, ((ExtendedNSXPCConnection*)newConnection).auditToken);
SecTaskValidateForRequirement(taskRef, (__bridge CFStringRef)(requirementString))
```
{% endcode %}

開発者がクライアントのバージョンをチェックしたくない場合、少なくともクライアントがプロセスインジェクションに対して脆弱でないことを確認することができます：

{% code overflow="wrap" %}
```objectivec
[...]
CFDictionaryRef csInfo = NULL;
SecCodeCopySigningInformation(code, kSecCSDynamicInformation, &csInfo);
uint32_t csFlags = [((__bridge NSDictionary *)csInfo)[(__bridge NSString *)kSecCodeInfoStatus] intValue];
const uint32_t cs_hard = 0x100;        // don't load invalid page.
const uint32_t cs_kill = 0x200;        // Kill process if page is invalid
const uint32_t cs_restrict = 0x800;    // Prevent debugging
const uint32_t cs_require_lv = 0x2000; // Library Validation
const uint32_t cs_runtime = 0x10000;   // hardened runtime
if ((csFlags & (cs_hard | cs_require_lv)) {
return Yes; // Accept connection
}
```
<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
