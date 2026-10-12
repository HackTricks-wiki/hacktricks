# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Intruder のペイロードタイプ

Burp Intruder には、次の組み込みペイロードジェネレーターと変換機能があります:<sup>[[1]](#references)</sup>

- **Simple list:** 設定した文字列リストをペイロードとして使用します。
- **Runtime file:** 実行時に1行につき1つのペイロードを読み込みます。ファイル全体をメモリに読み込まないため、大きなリストに便利です。
- **Case modification:** 変更前の値、小文字、大文字、`Propername`（先頭を大文字、残りを小文字）、または `ProperName`（先頭を大文字、残りは変更しない）を生成します。Burp は重複した結果を破棄します。
- **Numbers:** 設定した範囲内で、連続する数値またはランダムな数値を生成します。
- **Brute forcer:** 選択した文字セットと最小・最大の長さに基づき、すべての順列を生成します。

## 拡張機能と関連ツール

- **Collabfiltrator** は、コマンドを実行し、その出力を DNS クエリ経由で Burp Collaborator に外部送信するペイロードを生成します。<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** は、他のレポート作成ワークフローで使用するために Burp の検出結果をエクスポートします。<sup>[[3]](#references)</sup>
- **HTTP Script Generator** は、HTTP リクエストを複数の言語のスクリプトに変換します。<sup>[[4]](#references)</sup>

## Session Switcher による複数セッションの認可テスト

[Session Switcher](https://github.com/doyensec/burp-session-switcher) は、Cookie と一般的でないヘッダーを名前付きの認証情報プロファイルとして保存する、Burp Suite `2025.5+` 向けの Java 拡張機能です。Repeater やインターセプトした Proxy リクエストなど、編集可能なリクエストエディターでプロファイルを選択すると、リクエストの認証情報が置き換わります。これはリプレイを補助する機能であり、**認可バイパスではありません**。[web testing methodology](../pentesting-web/web-vulnerabilities-methodology.md) の一環として、水平アクセス、垂直方向のロール境界、テナント分離、[IDOR/BOLA](../pentesting-web/idor.md) を確認する際に、同じリクエストを異なるアカウントとして送信するために使用します。<sup>[[5]](#references)[[8]](#references)</sup>

### 再現可能な ID 差分テストの手順

次の手順では、リソース/アクションと実行するユーザーを別々のテスト変数として扱い、古いトークンや誤ったブラウザーセッションによる誤判定を減らします。<sup>[[5]](#references)[[8]](#references)</sup>

1. 別々のブラウザープロファイルまたはコンテナーで、関連する各ユーザー、ロール、テナントを表すテストアカウントに認証します。
2. いずれかのユーザーの Cookie とヘッダーを含むリクエストを開き、**Sessions > New** を選択して、`tenant-a-user` や `tenant-b-admin` のような明確な名前をプロファイルに付けます。すべてのテスト対象ユーザーについて繰り返します。
3. 候補となるリクエストを Repeater に送信し、メソッド、エンドポイント、パラメーター、オブジェクト識別子を変更せず、選択するセッションだけを切り替えて再送信します。ステータスコードだけでなく、レスポンスデータと観測可能な状態変化を比較します。
4. オブジェクトレベルの確認では、アカウント A に属することが分かっているオブジェクトへのリクエストを、アカウント B のプロファイルを選択して再送信します。機能レベルの確認では、同じ特権操作を、より権限の低いプロファイルで再送信します。
5. 再認証またはトークンローテーションの後は、比較を繰り返す前に、最新のブラウザーリクエストで **Update** を使用するか、Auto Update ルールを設定します。

### 取得と注入の動作

認証情報が2つのユーザーにまたがるハイブリッドリクエストでは比較が無効になる可能性があるため、テスト前に更新/注入モードを確認してください。現在のデフォルトでは、リクエストのすべての Cookie をプロファイルに反映し、すでに保存されている一般的でないヘッダーのみを更新し、選択したプロファイルの Cookie を宛先リクエストに反映（既存の Cookie は削除）して、プロファイルのヘッダーを追加します。セレクターの対象は、完全一致するサブドメイン、最上位のアプリケーションドメイン（デフォルト）、または保存済みのすべてのプロファイルに限定できます。<sup>[[7]](#references)</sup>

- **Mirror** は、Cookie 一式がユーザーの識別情報を定義し、古い宛先 Cookie を削除する必要がある場合に便利です。
- **Update existing** は、ブラウザートラフィックから無関係な Cookie やヘッダーを取り込まずに、ローテーションする値を追跡します。
- **Add all** は、プロファイルまたはリクエストにすでに保存されている追加の値を保持します。以前のセッションの識別情報を含むデータが残らないことを確認してください。
- **Do nothing** は、その認証情報クラスが無関係な場合に、Cookie またはヘッダーをプロファイルの更新対象から除外します。

### Proxy を使ったセッション同期

Auto Update ルールは、Proxy トラフィックを保存済みプロファイルに関連付け、その Cookie/ヘッダーを更新します。専用のリクエストヘッダー、プロファイル固有の `User-Agent` マーカー、識別用 Cookie、`X-PwnFox-Color`、JWT クレームなど、安定した識別子を使うことを推奨します。無関係なアプリケーションがプロファイルを更新できないよう、スコープ/ドメイン/パスの条件と組み合わせてください。1つのルール内のすべての条件は、記載順に論理 `AND` として評価されるため、制限の厳しいチェックを先に配置します。同じプロファイルを対象とする複数のルールを作成すれば、`OR` を実装できます。否定条件によるマッチングにも対応しています。<sup>[[6]](#references)</sup>

マッチした各ルールでは、Cookie とヘッダーそれぞれに **Mirror request**、**Add all**、**Update existing**、**Do nothing** のいずれかを選択します。リクエストのみを対象とするルールは、Proxy がリクエストを受信したときに実行されます。レスポンスステータス、レスポンスヘッダー、またはレスポンス本文の条件を追加すると、レスポンスの到着後に評価されます。ハイライト色を設定するとマッチしたトラフィックを識別でき、各ブラウザーのユーザー情報が意図したプロファイルだけを更新しているか確認するのに役立ちます。<sup>[[6]](#references)</sup>

保存済みプロファイルは Burp プロジェクト内にあり、JSON のプロジェクトデータエクスポートにはセッションとその Cookie/ヘッダーも含まれます。どちらのファイルも有効な認証情報として扱い、アクセスを制限し、作業終了後に保存された拡張機能データを削除してください。<sup>[[7]](#references)[[8]](#references)</sup>

## References

- [1] [PortSwigger ドキュメント - Burp Intruder のペイロードタイプ](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
- [5] [Doyensec - Session Switcher のソースと使用方法に関するドキュメント](https://github.com/doyensec/burp-session-switcher)
- [6] [Doyensec - Session Switcher の Auto Update ルール](https://github.com/doyensec/burp-session-switcher/blob/main/docs/auto_update_rules.md)
- [7] [Doyensec - Session Switcher の設定](https://github.com/doyensec/burp-session-switcher/blob/main/docs/settings.md)
- [8] [Doyensec - Session Switcher: Burp Suite での複数セッション認可テストを簡素化](https://blog.doyensec.com/2026/06/17/session-switcher.html)
{{#include ../banners/hacktricks-training.md}}
