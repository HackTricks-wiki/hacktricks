# LLM Gateway の信頼境界

{{#include ../banners/hacktricks-training.md}}

LLM gateway はモデルのルーティングを処理し、多くの場合プロバイダーの認証情報を保持するため、通常の API caller に設定やプロバイダーレベルの権限を継承させてはなりません。LiteLLM バージョン 1.77.7 の gateway 評価では、管理設定に対する UI セッションの認可と、推論に対する caller 提供のルーティング設定という、2つの異なる境界が確認されました。報告された問題はバージョン 1.83.9 で修正されました。<sup>[[1]](#references)</sup>

## UI route の分類は認可ではない

評価対象の LiteLLM バージョンでは、UI ログインキーは `litellm-dashboard` チームに属していました。認可処理は、ユーザーの role に関係なく、そのチーム識別子に基づいてキーを UI token として分類していました。UI route のチェックでは、allowlist に登録された prefix で始まるすべての route が許可されていました。その結果、`/config` のエントリーは管理用の `/config/update` handler にも一致しました。この handler は一般的な認証を要求しましたが、`PROXY_ADMIN` を個別に要求していなかったため、低権限の UI セッションが設定の書き込み権限を得てしまいました。<sup>[[1]](#references)</sup>

これは、proxy/backend 間の path 正規化の不一致とは異なります。認可コードと handler が、*同じ* route の権限を異なるものとして扱っています。<sup>[[1]](#references)</sup> gateway をレビューする際は、token の分類、route と method の厳密な照合、handler 自体の role チェックを比較してください。<sup>[[1]](#references)</sup> 関連するものの異なる境界については、[web API authorization](../pentesting-web/web-api-pentesting.md)、[401/403 bypasses](../pentesting-web/403-and-401-bypasses.md)、[proxy prefix exemptions](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys) を参照してください。

## 設定の書き込みは設定ストア以外にも影響する

同じ LiteLLM の設定更新処理は、環境変数の値を受け入れ、実行中のプロセスに適用していました。ある処理では `UI_LOGO_PATH` を `FileResponse` 用のローカルパスとして扱い、それがロゴを指しているか検証していませんでした。別の処理では、SSO 以外のログイン時に `UI_USERNAME` と `UI_PASSWORD` を読み取り、一致した場合に `PROXY_ADMIN` を割り当てていました。そのため、設定の書き込み権限は、後続処理によってローカルファイルの開示にも管理者 ID の変更にもつながる可能性がありました。レスポンスの media type は、配信されるファイルが画像であることを保証しません。<sup>[[1]](#references)</sup>

pass-through endpoint の設定も、後続処理に影響する別の sink でした。初期化処理はリモートの S3/GCS adapter を受け入れ、Python module をダウンロードし、`importlib` の `exec_module` を使って import していました。import は adapter instance が使われる前にトップレベルのコードを実行します。adapter の呼び出しだけを制限しても、この実行境界はなくなりません。これは設定で制御されるコード読み込みとして扱い、model file のデシリアライズとは区別してください。<sup>[[1]](#references)</sup> 別の file-read primitive については、[file inclusion and path traversal](../pentesting-web/file-inclusion/) を参照してください。

## リクエスト単位のモデルルーティングで gateway の認証情報が leak する可能性

LiteLLM の client-side credential 機能は、LLM リクエスト内の `user_config` object を受け入れていました。評価対象の route は、その object をもとに、model list とプロバイダーの `api_base` を含む一時的な `litellm.Router` を作成していました。caller が制御するプロバイダーの送信先には、gateway の outbound completion request と設定済みのプロバイダー認証ヘッダーが送られる可能性がありました。トップレベルの `api_base` や `api_key` field に対する制限は、この別個のネストされた設定経路をカバーしていませんでした。これは prompt injection の問題ではなく、認証情報を伴う SSRF 境界です。<sup>[[1]](#references)</sup>

認可された gateway 評価では、リクエスト単位の設定を含め、router や provider client を構築できるすべての経路を、通常の設定済み route で使われる送信先と認証情報のポリシーに照らして確認してください。<sup>[[1]](#references)</sup> [SSRF guide](../pentesting-web/ssrf-server-side-request-forgery/) では、一般的なサーバー側の送信先制御を解説しています。gateway 固有の問題は、信頼度の低いリクエスト object に送信先を選択させながら、特権を持つ outbound 認証情報を再利用することです。<sup>[[1]](#references)</sup>

## References

- [1] [Check Point Research — LLM Gateway の問題：LiteLLM の調査で判明した問題](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
{{#include ../banners/hacktricks-training.md}}
