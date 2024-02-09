<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)を**フォロー**してください。
* **HackTricks**（https://github.com/carlospolop/hacktricks）と**HackTricks Cloud**（https://github.com/carlospolop/hacktricks-cloud）のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>


**元の投稿は** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## 要約

現在のユーザーによって書き込み可能な2つのレジストリキーが見つかりました：

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

**RpcEptMapper**サービスのアクセス許可を**regedit GUI**を使用して確認することが提案されました。具体的には、**Advanced Security Settings**ウィンドウの**Effective Permissions**タブを使用します。このアプローチにより、各アクセス制御エントリ（ACE）を個別に調査する必要なく、特定のユーザーまたはグループに付与されたアクセス許可を評価できます。

スクリプトの調査結果によると、低特権ユーザーに割り当てられたアクセス許可が示されました。その中で、**Create Subkey**権限が注目されました。この権限は**AppendData/AddSubdirectory**とも呼ばれ、スクリプトの調査結果と一致します。

特定の値を直接変更できないが、新しいサブキーを作成できる能力があることが指摘されました。例として、**ImagePath**値を変更しようとした際にアクセスが拒否されたメッセージが表示されました。

これらの制限にもかかわらず、**RpcEptMapper**サービスのレジストリ構造内の**Performance**サブキーを活用することで特権昇格の可能性が特定されました。これはデフォルトでは存在しないサブキーで、DLLの登録とパフォーマンスモニタリングを可能にすることができます。

**Performance**サブキーに関するドキュメントとそのパフォーマンスモニタリングへの利用方法が参照され、**OpenPerfData**、**CollectPerfData**、および**ClosePerfData**関数の実装を示すPOC DLLが開発されました。このDLLは**rundll32**を介してテストされ、その操作的な成功が確認されました。

**RPCエンドポイントマッパーサービス**に作成されたパフォーマンスDLLをロードさせることが目標でした。PowerShellを介してパフォーマンスデータに関連するWMIクラスクエリを実行すると、ログファイルが作成され、**LOCAL SYSTEM**コンテキストで任意のコードを実行できるようになり、特権が昇格されます。

この脆弱性の持続性と潜在的な影響が強調され、そのポストエクスプロイテーション戦略、横断移動、およびアンチウイルス/EDRシステムの回避に対する重要性が示されました。

この脆弱性は元々スクリプトを通じて意図せず開示されましたが、その悪用は古いWindowsバージョン（例：**Windows 7 / Server 2008 R2**）に制限され、ローカルアクセスが必要です。

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)を**フォロー**してください。
* **HackTricks**（https://github.com/carlospolop/hacktricks）と**HackTricks Cloud**（https://github.com/carlospolop/hacktricks-cloud）のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>
