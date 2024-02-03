<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでのAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有してください。

</details>


**元の投稿は** [**https://itm4n.github.io/windows-registry-rpceptmapper-eop/**](https://itm4n.github.io/windows-registry-rpceptmapper-eop/)

## 概要
スクリプトの出力によると、現在のユーザーは以下の二つのレジストリキーに対する書き込み権限を持っています:

- `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache`
- `HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper`

RpcEptMapperサービスの権限をさらに調査するために、ユーザーはregedit GUIの使用を述べ、Advanced Security SettingsウィンドウのEffective Permissionsタブの有用性を強調しています。このタブを使用すると、個々のACEを検査することなく、特定のユーザーやグループに付与された実際の権限を確認できます。

提供されたスクリーンショットは、権限の低いlab-userアカウントの権限を表示しています。Query Valueなどの標準的な権限がほとんどですが、Create Subkeyという権限が目立ちます。この権限の一般的な名前はAppendData/AddSubdirectoryであり、スクリプトによって報告された内容と一致しています。

ユーザーは、これは特定の値を直接変更することはできず、新しいサブキーを作成することしかできないことを意味すると説明しています。ImagePathの値を変更しようとするとアクセス拒否エラーが発生する例を示しています。

しかし、これが偽陽性ではなく、ここに興味深い機会があることを明確にしています。彼らはWindowsレジストリの構造を調査し、RpcEptMapperサービスにはデフォルトで存在しないPerformanceサブキーを利用する潜在的な方法を発見します。このサブキーは、DLLの登録とパフォーマンスモニタリングを可能にし、権限昇格の機会を提供する可能性があります。

彼らは、Performanceサブキーに関連するドキュメントを見つけ、パフォーマンスモニタリングに使用する方法を発見したと述べています。これにより、彼らはプルーフ・オブ・コンセプトのDLLを作成し、必要な関数であるOpenPerfData、CollectPerfData、ClosePerfDataを実装するコードを示しています。また、これらの関数を外部使用のためにエクスポートしています。

ユーザーは、rundll32を使用してDLLをテストし、期待通りに機能し、情報を正常にログに記録することを示しています。

次に、RPC Endpoint Mapperサービスに自分のPerformance DLLを読み込ませるという課題について説明しています。PowerShellでパフォーマンスデータに関連するWMIクラスを照会したときに、ログファイルが作成されるのを観察したと述べています。これにより、LOCAL SYSTEMとして実行されるWMIサービスのコンテキストで任意のコードを実行することができ、予期せぬ昇格されたアクセスを提供します。

最後に、この脆弱性の説明されていない持続性とその潜在的な影響を強調しています。これには、横断的な移動やアンチウイルス/EDR回避など、悪用後の影響が含まれる可能性があります。

また、当初はスクリプトを通じて偶然にも脆弱性を公開したものの、その影響はローカルアクセスがあるサポートされていないWindowsバージョン（例：Windows 7 / Server 2008 R2）に限定されていると述べています。


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでのAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有してください。

</details>
