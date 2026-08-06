# Other Web Tricks

{{#include ../banners/hacktricks-training.md}}

### Host header

バックエンドが、いくつかの処理を実行するために **Host header** を信頼していることがあります。たとえば、その値を **password reset を送信するドメイン** として使用する場合があります。パスワードをリセットするリンクが記載されたメールを受け取ったとき、使用されるドメインは、Host header に指定したものになります。そこで、他のユーザーの password reset をリクエストし、ドメインを自分が管理するものに変更して、相手の password reset codes を盗むことができます。[WriteUp](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)。<sup>[[1]](#references)</sup>

> [!WARNING]
> password reset link をユーザーがクリックするのを待つ必要すらない可能性がある点に注意してください。**spam filters やその他の中間デバイス/bots が、リンクを分析するためにクリックすることもある**ためです。

### Session booleans

検証を正しく完了すると、バックエンドが **セッションの security attribute に、値が "True" の boolean を追加するだけ** の場合があります。その後、別の endpoint が、そのチェックに正常に合格したかどうかを確認します。\
ただし、**チェックに合格**し、セッションの security attribute に "True" の値が付与された場合、同じ attribute **に依存する他の resources** で、**本来はアクセス権限を持っていないもの**への **access を試みる**ことができます。[WriteUp](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)。<sup>[[2]](#references)</sup>

### Register functionality

すでに存在するユーザーとして登録を試みてください。同値の文字（ドット、多数のスペース、Unicode）も使用してみてください。

### Takeover emails

メールアドレスを登録し、確認前にメールアドレスを変更します。その後、新しい確認メールが最初に登録したメールアドレスに送信される場合、任意のメールアドレスを takeover できます。また、最初のメールアドレスを確認することで2つ目のメールアドレスを有効化できる場合も、任意のアカウントを takeover できます。

### Access Internal servicedesk of companies using atlassian


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

### TRACE method

開発者は、本番環境でさまざまな debugging options を無効化し忘れることがあります。たとえば、HTTP `TRACE` method は診断目的で設計されています。有効になっている場合、web server は `TRACE` method を使用したリクエストに対し、受信したリクエストを正確にレスポンスへ反映して応答します。この動作は多くの場合無害ですが、reverse proxies がリクエストに付加する可能性のある内部 authentication headers の名前など、情報漏えいにつながることがあります。![投稿の画像](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![投稿の画像](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [How I was able to take over any user's account with Host Header Injection](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [A less known attack vector: Second Order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)

{{#include ../banners/hacktricks-training.md}}
