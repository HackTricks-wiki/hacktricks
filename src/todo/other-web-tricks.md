# Other Web Tricks

{{#include ../banners/hacktricks-training.md}}

### Host header

バックエンドが何らかの処理を実行する際に、**Host header**を信頼していることがあります。例えば、その値を**パスワードリセットメールの送信先ドメイン**として使用する場合があります。そのため、パスワードをリセットするリンクが記載されたメールを受け取ったとき、使用されているドメインは、Host headerに指定したものになります。そこで、他のユーザーのパスワードリセットを要求し、ドメインを自分が管理するものに変更することで、パスワードリセットコードを盗むことができます。[WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).<sup>[[1]](#references)</sup>

> [!WARNING]
> パスワードリセットリンクをユーザーがクリックするのを待つ必要すらなく、トークンを取得できる可能性がある点に注意してください。**spam filtersやその他の中間デバイス/botsが、リンクを分析するためにクリックすることもあるためです**。

### Session booleans

検証を正しく完了した際に、バックエンドが**単にセッションのsecurity attributeに値「True」のbooleanを追加するだけ**の場合があります。その後、別のendpointが、そのチェックに正常に合格したかどうかを確認します。\
しかし、**チェックに合格**し、セッションのsecurity attributeに「True」が付与された場合、**同じattributeに依存している**ものの、**本来はアクセス権限を持っていない**他のリソースへの**アクセスを試みる**ことができます。[WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).<sup>[[2]](#references)</sup>

### Register functionality

すでに存在するユーザーとして登録を試みてください。同等の文字（ドット、多数のスペース、Unicode）を使う方法も試してください。

### Takeover emails

メールアドレスを登録し、確認前にメールアドレスを変更します。その後、新しい確認メールが最初に登録したメールアドレスへ送信される場合、任意のメールアドレスをtakeoverできます。また、最初のメールアドレスを確認することで2つ目のメールアドレスを有効化できる場合も、任意のアカウントをtakeoverできます。

### atlassianを使用する企業のInternal servicedeskにアクセス


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE method

開発者が本番環境でさまざまなdebuggingオプションを無効化し忘れることがあります。例えば、HTTPの`TRACE` methodは診断目的で設計されています。有効になっている場合、Webサーバーは`TRACE` methodを使用したリクエストに対し、受信したリクエストをそのままレスポンス内に反映して応答します。この動作は通常は無害ですが、reverse proxiesによってリクエストに追加された可能性がある内部認証ヘッダーの名前など、情報漏えいにつながることがあります。![記事の画像](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![記事の画像](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [How I was able to take over any user's account with Host Header injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
