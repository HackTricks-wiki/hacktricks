# WhatsApp Prekey Bundleの枯渇と補充のサイドチャネル

{{#include ../banners/hacktricks-training.md}}

WhatsAppは各デバイスについて、identity key、signed prekey、およびone-time prekeyの予備を保存します。デバイスのbundleを取得すると、リクエスト側がメッセージを送信しなくても、サーバーが保持するone-time prekeyが1つ消費されます。これにより、WhatsAppアカウントと対象の電話番号を持つ攻撃者は、[クライアントの配信確認タイミング](side-channel-attacks-on-messaging-protocols.md)とは異なる、**サーバー側**のプローブを実行できます。one-time prekeyがなくなると、新たに確立されたセッションの*初期*メッセージのforward secrecyは弱まりますが、それだけで平文が漏れるわけではありません。<sup>[[1]](#references)[[2]](#references)</sup>

## 対象のデバイスbundleを調べる

[Prekey Pogo artifact](https://github.com/sbaresearch/prekey-pogo)はWhatsAppのコンパニオンセッションとしてペアリングし、デバイスとprekeyを**手動で**照会できます。テストアカウントとペアリングし、対話型の`target`、`devices`（プライマリデバイスの`prekey`）、`combine`（全デバイス）コマンドを使用します。公開されたartifactには、自動的な枯渇機能とサーバーを過負荷にする機能は意図的に含まれていません。<sup>[[1]](#references)[[3]](#references)</sup>

```bash
git clone https://github.com/sbaresearch/prekey-pogo
cd prekey-pogo
./setup.sh
go run .
```

各応答について、デバイス JID、バンドルのタイムスタンプ `t`、signed-prekey ID `skey.id`、および one-time `key.id` が存在するかどうかを記録します。デバイス ID `0` は phone、0 以外の ID は companion です。この論文でテストされた実装では、初期の signed-prekey ID によって一部のクライアントも識別できます。Android は `0` から始まり、iOS と macOS はランダム値を使用し、WhatsApp Web と Windows Desktop は `1` から始まります。これは実装のフィンガープリントとして扱い、変更されないプロトコル規則とは見なさないでください。<sup>[[1]](#references)</sup>

## 補充をオンライン状態 oracle に変える

まず、自分が管理するデバイスで調整します。サーバーが one-time `key` を返さなくなるまで、そのデバイスのバンドルを繰り返しリクエストし、最後のタイムスタンプと key ID を記録します。対象デバイスについては、同様にキーを枯渇させ、一定の間隔を置いて再度クエリします。新しい one-time key と進んだバンドルのタイムスタンプが確認できれば、そのデバイスが新しいバッチをアップロードしたことを示します。報告された WhatsApp のテストでは、残り 11 個未満になるとサーバーが補充を促し、クライアントは 812 個の新しいキーをアップロードしました。phone と companion を区別するには、デバイス JID ごとにこの手順を実施します。補充の遅れはデバイスがオフラインであることを**示唆するにとどまります**。バックグラウンドでのスケジューリング、ネットワーク障害、クライアント固有の補充遅延でも同じ結果が生じる可能性があります。receipt RTT と異なり、このプローブでは配信済み ciphertext も被害者側の acknowledgment も必要ありません。<sup>[[1]](#references)[[2]](#references)</sup>

クエリごとに one-time key が 1 つ消費されるため、oracle を継続的に使うには、prekey retrieval を繰り返せるカスタムクライアントが必要です。公開されている artifact で実証されているのは手動クエリのみです。予備キーを空の状態に保つと、他のユーザーが one-time prekey なしで新しいセッションを確立する可能性があります。これにより、新しい ratchet step が行われるまで初期メッセージの forward secrecy が低下します。ただし、記録された ciphertext を悪用するには、E2EE ciphertext へのアクセスに加え、後に該当する長期および中期の秘密鍵が侵害される必要があります。すでに確立されたセッションが自動的にダウングレードされることはありません。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Prekey Pogo: WhatsAppのHandshake Mechanismにおけるセキュリティとプライバシーの問題を調査する](https://www.usenix.org/system/files/woot25-gegenhuber.pdf)
- [2] [X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
- [3] [Prekey Pogo artifacts](https://github.com/sbaresearch/prekey-pogo)
{{#include ../banners/hacktricks-training.md}}
