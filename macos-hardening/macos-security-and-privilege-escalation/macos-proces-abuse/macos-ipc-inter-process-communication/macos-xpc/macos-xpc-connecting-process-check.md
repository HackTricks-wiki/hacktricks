# macOS XPC 接続プロセスのチェック

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricks で企業を宣伝**したいですか？または、**PEASS の最新バージョンにアクセスしたり、HackTricks を PDF でダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な [**NFT**](https://opensea.io/collection/the-peass-family) のコレクションです。
* [**公式の PEASS & HackTricks スワッグ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord グループ**](https://discord.gg/hRep4RUj7f) または [**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)** をフォローしてください。**
* **ハッキングのトリックを共有するには、** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に PR を提出してください。**

</details>

## XPC 接続プロセスのチェック

XPC サービスへの接続が確立されると、サーバーは接続が許可されているかどうかをチェックします。通常、以下のチェックが行われます。

1. 接続する**プロセスが Apple によって署名された**証明書を持っているかどうかをチェックします（Apple によってのみ提供されます）。
* これが**検証されていない**場合、攻撃者は他のチェックに合わせるために**偽の証明書**を作成することができます。
2. 接続するプロセスが**組織の証明書**（チーム ID の検証）で署名されているかどうかをチェックします。
* これが**検証されていない**場合、Apple の**任意の開発者証明書**を使用して署名し、サービスに接続することができます。
3. 接続するプロセスが**適切なバンドル ID**を持っているかどうかをチェックします。
* これが**検証されていない**場合、同じ組織によって署名された**任意のツール**を使用して XPC サービスとやり取りすることができます。
4. (4 または 5) 接続するプロセスが**適切なソフトウェアバージョン番号**を持っているかどうかをチェックします。
* これが**検証されていない**場合、他のチェックが行われていても、古いセキュリティの脆弱性を持つクライアントがプロセスインジェクションに対して脆弱であるため、XPC サービスに接続することができます。
5. (4 または 5) 接続するプロセスが危険な権限（任意のライブラリを読み込むことや DYLD 環境変数を使用することを許可する権限など）を持たない、ハード化されたランタイムを持っているかどうかをチェックします。
* これが**検証されていない**場合、クライアントは**コードインジェクションの脆弱性**に対して脆弱になる可能性があります。
6. 接続するプロセスがサービスに接続するための**エンタイトルメント**を持っているかどうかをチェックします。これは Apple のバイナリに適用されます。
7. **検証**は、接続する**クライアントの監査トークン**に基づいて行われる必要があります。プロセス ID（PID）ではなく、監査トークンを使用することで、PID の再利用攻撃を防ぐことができます。
* 開発者は監査トークン API 呼び出しをほとんど使用しないため、Apple はいつでも変更できます。また、Mac App Store アプリではプライベート API の使用は許可されていません。

PID の再利用攻撃の詳細については、次を参照してください：

{% content-ref url="../../../mac-os-architecture/macos-ipc-inter-process-communication/macos-pid-reuse.md" %}
[macos-pid-reuse.md](../../../mac-os-architecture/macos-ipc-inter-process-communication/macos-pid-reuse.md)
{% endcontent-ref %}

### Trustcache - ダウングレード攻撃の防止

Trustcache は、Apple Silicon マシンに導入された防御手法であり、Apple のバイナリの CDHSAH のデータベースを格納し、変更されていない許可されたバイナリのみが実行されるようにします。これにより、ダウングレードバージョンの実行を防止します。

### コード例

サーバーは、**`shouldAcceptNewConnection`** という関数でこの**検証**を実装します。

{% code overflow="wrap" %}
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
{% endcode %}

オブジェクトNSXPCConnectionには、**`auditToken`**（使用すべきですが変更される可能性があるもの）と**`processIdentifier`**（使用すべきではないもの）という**非公開**プロパティがあります。

接続プロセスは、次のような方法で確認できます：

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

クライアントのバージョンをチェックしたくない場合、少なくともクライアントがプロセスインジェクションの脆弱性を持っていないことを確認することができます。

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
{% endcode %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
