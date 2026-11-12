# GitHub Issues と Repository Files を C2 Channel として利用する

{{#include ../banners/hacktricks-training.md}}

private repositoryを使うと、**session state** と **payload transfer** を分離できます。issuesには各ホストとそのhandshake stateを記録し、repository filesは暗号化データの双方向転送に使います。これは、issue bodyを単にpollingしてコマンドを取得する方法にとどまりません。確認された実装では、両方のAPIへのアクセスにGitHub personal access token (PAT) を使用しています。<sup>[[1]](#references)</sup> Fine-grained PATの場合、issueの作成や更新にはIssues write permission、ファイルのアップロードにはContents write permissionが必要です。一方、classic PATには`repo` scopeが必要です。十分な権限を持つtokenを入手した者は、同じchannelにアクセスできます。<sup>[[2]](#references)[[3]](#references)</sup>

## Issue と file のhandshake

確認されたworkflowでは、短い16進数のhost IDと以下のstate machineを使用します。IDの正確な範囲、文字列、prefixはprotocol markerであり、GitHub APIの要件ではありません。<sup>[[1]](#references)</sup>

1. 起動時に`GET /repos/{owner}/{repo}/issues?state=open`（および`state=closed`）でopenおよびclosedのissuesを照会し、過去のsession stateを探します。`POST /repos/{owner}/{repo}/issues`で、`1[ID]`というtitleと`hel`というbodyを持つopen issueを作成します。
2. 名前が`2[ID]`で始まるrepository fileを読み込みます。このfileにはserverのRSA public keyが含まれています。新しい16-byte session keyを生成してRSAで暗号化し、`1[ID]`をprefixとするfileにその結果をアップロードします。
3. 埋め込みのIVとsession keyをXORして、以降のIVを導出します。やり取りする各fileについて、filenameのランダムな16-byte keyを使い、内容をAESで暗号化または復号します。prefix `2`はserverからhostへのデータ、prefix `1`はhostからserverへのデータを示します。つまり、filenameはroutingとfileごとのkey materialを担い、issueはstateを担います。
4. 次の`2`をprefixとするfileを読み込み、復号した内容が`hel`と一致することを確認します。暗号化したhost情報をアップロードし、`PATCH /repos/{owner}/{repo}/issues/{issue_number}`でissue bodyを`hey`に変更します。その後に限り、コマンドのpollingを開始します。

GitHubのContents APIでは、`GET /repos/{owner}/{repo}/contents/{path}`でfileを読み込み、そのpathへの`PUT`でfileを作成または置換します。1 MB以下のfileでは、デフォルトのJSON responseにBase64でエンコードされた内容が含まれます。1 MBを超え100 MB以下のfileの内容を取得するには、raw media typeが必要です。アップロードbodyにはcommit messageとBase64でエンコードされたfileの内容が必要です。既存のfileを置換する場合は、現在のblob SHAも必要です。これらのAPIの詳細は、上述の暗号化protocolとは別のものです。<sup>[[2]](#references)[[3]](#references)</sup>

許可されたtest repositoryでは、REST APIを使ってissue-control部分をテストできます（test repositoryとtest PATに置き換えてください）。有効なtokenをURL、issue body、またはcommitするfileに含めないでください。<sup>[[2]](#references)</sup>

```bash
base="https://api.github.com/repos/$OWNER/$REPO"
curl -fsS -H "Authorization: Bearer $GH_TOKEN" "$base/issues?state=open"
issue_number=$(curl -fsS -X POST -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues" -d '{"title":"11000","body":"hel"}' | jq -r .number)
curl -fsS -X PATCH -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
  "$base/issues/$issue_number" -d '{"body":"hey"}'
```

この仕組みでは、issue のタイトル、`hel`/`hey` マーカー、ここに示す特定の暗号方式は必須ではありません。これらは一つの実装を示すものです。再利用可能な考え方は、変更可能なホスト状態と双方向の暗号化オブジェクトを分離し、両方をホスト ID に紐付けることです。<sup>[[1]](#references)</sup> 別の GitHub issue を使った通信方式については、[AdaptixC2 カスタム listener のメモ](basic-forensic-methodology/adaptixc2-config-extraction-and-ttps.md#custom-listener-profiles-dont-hard-code-only-the-classic-http-schema)を参照してください。セッション状態を保持する代わりにリポジトリの認証情報をローテーションする、issue コメントを使ったフォールバックについては、[Web サービスと dead-drop resolver](../privacy/offensive-infrastructure-and-attribution-evasion.md#web-services-and-dead-drop-resolvers)を参照してください。

## References

- [1] [Kaspersky Securelist – Operation FlashHole](https://securelist.com/lazarus-operation-flashhole/121541/)
- [2] [GitHub Docs – issue 向け REST API エンドポイント](https://docs.github.com/en/rest/issues/issues)
- [3] [GitHub Docs – リポジトリコンテンツ向け REST API エンドポイント](https://docs.github.com/en/rest/repos/contents)
