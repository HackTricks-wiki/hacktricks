# macOS XPC 接続プロセスチェック

{{#include ../../../../../../banners/hacktricks-training.md}}

## XPC 接続プロセスチェック

XPCサービスへの接続が確立されると、サーバーは接続が許可されているかどうかを確認します。通常、以下のチェックが行われます：

1. 接続している**プロセスがApple署名の**証明書で署名されているか確認します（Appleからのみ発行されます）。
- これが**確認されない場合**、攻撃者は**偽の証明書**を作成して他のチェックに合致させることができます。
2. 接続しているプロセスが**組織の証明書**で署名されているか確認します（チームIDの確認）。
- これが**確認されない場合**、Appleの**任意の開発者証明書**が署名に使用され、サービスに接続できます。
3. 接続しているプロセスが**適切なバンドルID**を含んでいるか確認します。
- これが**確認されない場合**、同じ組織によって**署名された任意のツール**がXPCサービスと対話するために使用される可能性があります。
4. (4または5) 接続しているプロセスが**適切なソフトウェアバージョン番号**を持っているか確認します。
- これが**確認されない場合**、古い、脆弱なクライアントがプロセスインジェクションに対して脆弱であり、他のチェックが行われていてもXPCサービスに接続される可能性があります。
5. (4または5) 接続しているプロセスが危険な権限のない**ハードンされたランタイム**を持っているか確認します（任意のライブラリを読み込むことを許可するものやDYLD環境変数を使用するものなど）。
1. これが**確認されない場合**、クライアントは**コードインジェクションに対して脆弱**かもしれません。
6. 接続しているプロセスがサービスに接続することを許可する**権限**を持っているか確認します。これはAppleのバイナリに適用されます。
7. **検証**は接続している**クライアントの監査トークン**に**基づく**べきであり、そのプロセスID（**PID**）ではなく、前者は**PID再利用攻撃**を防ぎます。
- 開発者は**監査トークン**API呼び出しを**ほとんど使用しない**ため、これは**プライベート**であり、Appleはいつでも**変更**できる可能性があります。さらに、プライベートAPIの使用はMac App Storeアプリでは許可されていません。
- メソッド**`processIdentifier`**が使用される場合、脆弱である可能性があります。
- **`xpc_dictionary_get_audit_token`**は**`xpc_connection_get_audit_token`**の代わりに使用されるべきであり、後者は特定の状況で[脆弱である可能性があります](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)。

### コミュニケーション攻撃

PID再利用攻撃に関する詳細は以下を確認してください：

{{#ref}}
macos-pid-reuse.md
{{#endref}}

**`xpc_connection_get_audit_token`**攻撃に関する詳細は以下を確認してください：

{{#ref}}
macos-xpc_connection_get_audit_token-attack.md
{{#endref}}

### Trustcache - ダウングレード攻撃防止

TrustcacheはApple Siliconマシンで導入された防御方法で、AppleのバイナリのCDHSAHのデータベースを保存し、許可された非修正バイナリのみが実行されるようにします。これにより、ダウングレードバージョンの実行が防止されます。

### コード例

サーバーはこの**検証**を**`shouldAcceptNewConnection`**という関数で実装します。
```objectivec
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
//Check connection
return YES;
}
```
オブジェクト NSXPCConnection には **private** プロパティ **`auditToken`** （使用すべきだが変更される可能性があるもの）と **public** プロパティ **`processIdentifier`** （使用すべきでないもの）があります。

接続プロセスは次のようなもので確認できます:
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
もし開発者がクライアントのバージョンを確認したくない場合、少なくともクライアントがプロセスインジェクションに対して脆弱でないことを確認することができます:
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
{{#include ../../../../../../banners/hacktricks-training.md}}
