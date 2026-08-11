# その他の Web Tricks

{{#include ../banners/hacktricks-training.md}}

## Host header

バックエンドは、絶対リンクを構築する際に HTTP `Host` フィールドを信頼することがあります。パスワードリセットメールで攻撃者が指定した host が使用される場合、被害者に対してリセットを要求すると、token を含むリンクが攻撃者の管理するドメイン経由で送信される可能性があります。各 proxy hop で、forwarded-host フィールド、重複する Host の処理、absolute-form のリクエストターゲットもテストしてください。<sup>[[1]](#references)</sup>

> [!WARNING]
> ユーザーのクリックは必要ない場合があります。**メールセキュリティスキャナー、プレビューサービス、その他の中間サービスが攻撃者の管理するリンクへ自動的にリクエストを送信し、リセット token が漏えいする可能性があります。**

## Session booleans

一部のアプリケーションは、検証の完了を session 内の boolean として記録し、その後、別の endpoint がその flag に依存するようにします。ある resource に対するチェックに正当に合格した後、同じ flag が別の user、object、workflow を誤って認可しないかテストしてください。これは単なる IDOR ではなく、二次的な authorization/state-reuse の欠陥です。<sup>[[2]](#references)</sup>

## Registration functionality

すでに存在する user として登録してみてください。同値の文字（ドット、多数のスペース、Unicode）を使う方法も試してください。

## Email-change state confusion

メールアドレスを登録し、確認前に変更してください。新しいアドレスの確認が古いアドレスに送信されるか、または古い token を確認すると新しいアドレスが有効になるかを確認します。確認 token は、正確な account、保留中のアドレス、目的、現在の state に紐付けられている必要があります。

## Exposed Atlassian service desks


{{#ref}}
https://yourcompanyname.atlassian.net/servicedesk/customer/user/login
{{#endref}}

## TRACE method

HTTP `TRACE` method は、診断のために受信したリクエストの loop-back を要求します。RFC 9110 は、受信側が反映された内容から credentials や cookies などの機密フィールドを除外することを要求していますが、安全でない実装や中間サービスによって追加された headers により、内部のリクエスト変換が漏えいする可能性があります。ブラウザは script から生成された TRACE requests を防止するため、過去の cross-site tracing attack も、保護されたフィールドを注入する別の方法に依存します。<sup>[[3]](#references)</sup>![TRACE response を示す画像](https://miro.medium.com/max/60/1*wDFRADTOd9Tj63xucenvAA.png?q=20)

![post 用の画像](https://miro.medium.com/max/1330/1*wDFRADTOd9Tj63xucenvAA.png)

## References

- [1] [Host Header Injection により、あらゆる user の account を takeover できた方法](https://medium.com/nassec-cybersecurity-writeups/how-i-was-able-to-take-over-any-users-account-with-host-header-injection-546fff6d0f2)
- [2] [あまり知られていない attack vector: Second Order IDOR attacks](https://medium.com/@ozguralp/a-less-known-attack-vector-second-order-idor-attacks-14468009781a)
- [3] [RFC 9110, section 9.3.8 — TRACE](https://www.rfc-editor.org/rfc/rfc9110.html#name-trace)
{{#include ../banners/hacktricks-training.md}}
