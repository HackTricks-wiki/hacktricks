# Other Web Tricks

{{#include ./banners/hacktricks-training.md}}


### Host header

バックエンドは、いくつかのアクションを実行するために**Host header**を信頼することがあります。たとえば、その値を**パスワードリセットを送信するドメイン**として使用することがあります。したがって、パスワードをリセットするためのリンクが含まれたメールを受け取ると、使用されるドメインはHost headerに入力したものになります。その後、他のユーザーのパスワードリセットを要求し、ドメインを自分が制御するものに変更して、彼らのパスワードリセットコードを盗むことができます。[WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2).

> [!WARNING]
> ユーザーがリセットパスワードリンクをクリックするのを待つ必要がない可能性があることに注意してください。おそらく、**スパムフィルターや他の中間デバイス/ボットがそれをクリックして分析することもあります**。


### Session booleans

時々、いくつかの検証を正しく完了すると、バックエンドは**セキュリティ属性に「True」という値のブール値を追加するだけです**。その後、別のエンドポイントは、そのチェックに成功したかどうかを知ることができます。\
ただし、**チェックに合格**し、セキュリティ属性に「True」値が付与された場合、**同じ属性に依存する他のリソースにアクセスしようとすることができますが、アクセス権がないはずです**。[WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a).

### Register functionality

既存のユーザーとして登録を試みてください。また、同等の文字（ドット、たくさんのスペース、Unicode）を使用してみてください。

### Takeover emails

メールを登録し、確認する前にメールを変更します。次に、新しい確認メールが最初に登録されたメールに送信される場合、任意のメールを乗っ取ることができます。また、最初のメールを確認するために2番目のメールを有効にできる場合も、任意のアカウントを乗っ取ることができます。

### Access Internal servicedesk of companies using atlassian

{% embed url="https://yourcompanyname.atlassian.net/servicedesk/customer/user/login" %}

### TRACE method

開発者は、プロダクション環境でさまざまなデバッグオプションを無効にするのを忘れることがあります。たとえば、HTTP `TRACE`メソッドは診断目的で設計されています。これが有効になっている場合、Webサーバーは`TRACE`メソッドを使用するリクエストに対して、受信した正確なリクエストを応答にエコーします。この動作は通常無害ですが、時折、リバースプロキシによってリクエストに追加される内部認証ヘッダーの名前など、情報漏洩につながることがあります。![Image for post](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![Image for post](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)


{{#include ./banners/hacktricks-training.md}}
