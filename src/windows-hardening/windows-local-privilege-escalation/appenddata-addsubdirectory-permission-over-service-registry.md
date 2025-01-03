{{#include ../../banners/hacktricks-training.md}}

**元の投稿は** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## 概要

現在のユーザーによって書き込み可能な2つのレジストリキーが見つかりました：

- **`HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`**
- **`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`**

**RpcEptMapper**サービスの権限を**regedit GUI**を使用して確認することが推奨されました。特に、**Advanced Security Settings**ウィンドウの**Effective Permissions**タブを使用します。このアプローチにより、各アクセス制御エントリ（ACE）を個別に調べることなく、特定のユーザーまたはグループに付与された権限を評価できます。

スクリーンショットには、低特権ユーザーに割り当てられた権限が示されており、その中で**Create Subkey**権限が注目されました。この権限は、**AppendData/AddSubdirectory**とも呼ばれ、スクリプトの結果と一致します。

特定の値を直接変更できない一方で、新しいサブキーを作成する能力があることが指摘されました。例として、**ImagePath**値を変更しようとした際にアクセス拒否メッセージが表示されたことが挙げられます。

これらの制限にもかかわらず、**RpcEptMapper**サービスのレジストリ構造内の**Performance**サブキーを利用することで特権昇格の可能性が特定されました。このサブキーはデフォルトでは存在しません。これにより、DLLの登録とパフォーマンス監視が可能になります。

**Performance**サブキーとそのパフォーマンス監視への利用に関する文書が参照され、概念実証DLLの開発が進められました。このDLLは、**OpenPerfData**、**CollectPerfData**、および**ClosePerfData**関数の実装を示し、**rundll32**を介してテストされ、その動作成功が確認されました。

目標は、作成したPerformance DLLを**RPC Endpoint Mapper service**に読み込ませることでした。観察結果によると、PowerShellを介してパフォーマンスデータに関連するWMIクラスクエリを実行すると、ログファイルが作成され、**LOCAL SYSTEM**コンテキストで任意のコードを実行できるようになり、特権が昇格されました。

この脆弱性の持続性と潜在的な影響が強調され、ポストエクスプロイト戦略、横移動、およびウイルス対策/EDRシステムの回避における関連性が示されました。

この脆弱性は、スクリプトを通じて意図せずに最初に開示されましたが、その悪用は古いWindowsバージョン（例：**Windows 7 / Server 2008 R2**）に制限され、ローカルアクセスが必要であることが強調されました。

{{#include ../../banners/hacktricks-training.md}}
