# 脅威モデリング

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を活用した検索エンジンで、企業やその顧客が**盗難型マルウェア**によって**侵害**されていないかをチェックする**無料**機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃と戦うことです。

彼らのウェブサイトをチェックし、エンジンを**無料**で試すことができます：

{% embed url="https://whiteintel.io" %}

---

## 脅威モデリング

脅威モデリングに関するHackTricksの包括的なガイドへようこそ！ここでは、システム内の潜在的な脆弱性を特定し、理解し、対策を立てるサイバーセキュリティの重要な側面を探求します。このスレッドは、実践的な例、役立つソフトウェア、わかりやすい説明が詰まったステップバイステップのガイドとして機能します。初心者から経験豊富な実務家まで、サイバーセキュリティの防御を強化したい人に最適です。

### よく使用されるシナリオ

1. **ソフトウェア開発**：セキュアソフトウェア開発ライフサイクル（SSDLC）の一環として、脅威モデリングは開発初期段階での**潜在的な脆弱性の特定**に役立ちます。
2. **ペネトレーションテスト**：ペネトレーションテスト実行標準（PTES）フレームワークでは、**システムの脆弱性を理解するための脅威モデリング**がテストの実施前に必要です。

### 脅威モデルの要点

脅威モデルは、通常、アプリケーションの計画されたアーキテクチャや既存の構築を示す図、画像、または他の視覚的な表現として表されます。これは**データフローダイアグラム**に似ていますが、そのセキュリティ指向の設計において異なる点があります。

脅威モデルには、潜在的な脆弱性、リスク、または障壁を示す赤でマークされた要素がよく含まれます。リスクの特定プロセスを効率化するために、CIA（機密性、整合性、可用性）トライアドが使用され、多くの脅威モデリング手法の基礎となっています。STRIDEが最も一般的な手法の1つですが、選択される手法は特定の文脈や要件に応じて異なる場合があります。

### CIAトライアド

CIAトライアドは、情報セキュリティ分野で広く認識されているモデルで、機密性、整合性、可用性を表しています。これらの3つの柱は、脅威モデリング手法を含む多くのセキュリティ対策やポリシーの基盤を形成しており、それぞれの柱は以下のような意味を持ちます。

1. **機密性**：データやシステムが不正な個人によってアクセスされないようにすること。これはセキュリティの中心的な側面であり、データ漏洩を防ぐために適切なアクセス制御、暗号化、およびその他の対策が必要です。
2. **整合性**：データの正確性、一貫性、および信頼性をデータのライフサイクル全体で確保すること。この原則は、データが不正な者によって変更されたり改ざんされたりしないようにすることを保証します。これにはチェックサム、ハッシュ、および他のデータ検証手法がしばしば含まれます。
3. **可用性**：データやサービスが必要な時に認可されたユーザーに利用可能であることを保証すること。これには冗長性、障害耐性、および高可用性構成が含まれ、システムが障害に直面しても稼働し続けるようにします。

### 脅威モデリング手法

1. **STRIDE**：Microsoftによって開発されたSTRIDEは、**スプーフィング、改ざん、否認、情報開示、サービス拒否、特権昇格**を表す頭字語です。各カテゴリは脅威のタイプを表し、この手法は潜在的な脅威を特定するためにプログラムやシステムの設計段階で一般的に使用されます。
2. **DREAD**：Microsoftの別の手法で、特定された脅威のリスク評価に使用されます。DREADは**損害の可能性、再現性、悪用可能性、影響を受けるユーザー、発見可能性**を表しています。これらの要素はスコア付けされ、その結果は特定された脅威の優先順位付けに使用されます。
3. **PASTA**（攻撃シミュレーションと脅威分析のプロセス）：これは7つのステップからなる**リスク中心**の手法です。セキュリティ目標の定義と特定、技術的範囲の作成、アプリケーション分解、脅威分析、脆弱性分析、リスク/トリアージ評価が含まれます。
4. **Trike**：資産の防御に焦点を当てたリスクベースの手法です。リスク管理の観点から始まり、その文脈で脅威や脆弱性を考察します。
5. **VAST**（ビジュアル、アジャイル、シンプル脅威モデリング）：このアプローチは、アジャイル開発環境に統合されやすく、**脅威の視覚的表現**に焦点を当てています。他の手法から要素を組み合わせ、脅威の視覚的表現に重点を置いています。
6. **OCTAVE**（運用上重要な脅威、資産、脆弱性評価）：CERT Coordination Centerによって開発されたこのフレームワークは、**特定のシステムやソフトウェアではなく組織のリスク評価**に焦点を当てています。

## ツール

脅威モデルの作成と管理を**支援**するために利用可能ないくつかのツールやソフトウェアソリューションがあります。以下は検討する価値のあるいくつかのツールです。

### [SpiderSuite](https://github.com/3nock/SpiderSuite)

サイバーセキュリティ専門家向けの高度なクロスプラットフォームおよびマルチ機能GUIウェブスパイダー/クローラーです。Spider Suiteは攻撃面のマッピングと分析に使用できます。

**使用方法**

1. URLを選択してクロール

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_1.png" alt=""><figcaption></figcaption></figure>

2. グラフを表示

<figure><img src="../.gitbook/assets/threatmodel_spidersuite_2.png" alt=""><figcaption></figcaption></figure>

### [OWASP Threat Dragon](https://github.com/OWASP/threat-dragon/releases)

OWASPのオープンソースプロジェクトであるThreat Dragonは、システム図作成と脅威/緩和策の自動生成を行うルールエンジンを備えたWebおよびデスクトップアプリケーションです。

**使用方法**

1. 新しいプロジェクトを作成

<figure><img src="../.gitbook/assets/create_new_project_1.jpg" alt=""><figcaption></figcaption></figure>

場合によっては、次のように見えるかもしれません：

<figure><img src="../.gitbook/assets/1_threatmodel_create_project.jpg" alt=""><figcaption></figcaption></figure>

2. 新しいプロジェクトを起動

<figure><img src="../.gitbook/assets/launch_new_project_2.jpg" alt=""><figcaption></figcaption></figure>

3. 新しいプロジェクトを保存

<figure><img src="../.gitbook/assets/save_new_project.jpg" alt=""><figcaption></figcaption></figure>

4. モデルを作成

SpiderSuite Crawlerなどのツールを使用して、基本的なモデルは次のようになります

<figure><img src="../.gitbook/assets/0_basic_threat_model.jpg" alt=""><figcaption></figcaption></figure>

エンティティについて少し説明します：

* プロセス（WebサーバーやWeb機能などのエンティティ自体）
* アクター（Webサイトの訪問者、ユーザー、管理者などの人物）
* データフローライン（相互作用の指標）
* 信頼境界（異なるネットワークセグメントやスコープ）
* ストア（データが保存される場所、例：データベース）

5. 脅威を作成（ステップ1）

最初に脅威を追加したいレイヤーを選択する必要があります

<figure><img src="../.gitbook/assets/3_threatmodel_chose-threat-layer.jpg" alt=""><figcaption></figcaption></figure>

今、脅威を作成できます

<figure><img src="../.gitbook/assets/4_threatmodel_create-threat.jpg" alt=""><figcaption></figcaption></figure>

アクター脅威とプロセス脅威の違いに注意してください。アクターに脅威を追加する場合は、「スプーフィング」と「否認」のみを選択できます。ただし、この例ではプロセスエンティティに脅威を追加するため、脅威作成ボックスには次のように表示されます：

<figure><img src="../.gitbook/assets/2_threatmodel_type-option.jpg" alt=""><figcaption></figcaption></figure>

6. 完了

これで、完成したモデルは次のようになります。これがOWASP Threat Dragonを使用してシンプルな脅威モデルを作成する方法です。

<figure><img src="../.gitbook/assets/threat_model_finished.jpg" alt=""><figcaption></figcaption></figure>
### [Microsoft Threat Modeling Tool](https://aka.ms/threatmodelingtool)

これはMicrosoftからの無料ツールで、ソフトウェアプロジェクトの設計フェーズで脅威を見つけるのに役立ちます。STRIDE方法論を使用し、特にMicrosoftのスタックで開発している人に適しています。


## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は**ダークウェブ**を活用した検索エンジンで、企業やその顧客が**スティーラーマルウェア**によって**侵害**されていないかをチェックする**無料**の機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃と戦うことです。

彼らのウェブサイトをチェックして、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}
