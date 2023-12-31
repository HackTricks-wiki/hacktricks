# macOS MDM

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) で AWS ハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks にあなたの会社を広告したい**、または **HackTricks を PDF でダウンロードしたい** 場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com) を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見する、私たちの独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクション
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に **参加する** か、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を **フォローする**。
* **HackTricks** の PR を提出して、あなたのハッキングのコツを共有する [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github リポジトリ。

</details>

## 基本

### MDM (モバイルデバイス管理) とは何か？

[モバイルデバイス管理](https://en.wikipedia.org/wiki/Mobile\_device\_management) (MDM) は、携帯電話、ラップトップ、デスクトップ、タブレットなどのエンドユーザーのコンピューティングデバイスを **管理するために一般的に使用される技術** です。iOS、macOS、tvOS などの Apple プラットフォームの場合、デバイスを管理するために管理者が使用する特定の機能、API、および技術を指します。デバイスを MDM 経由で管理するには、[MDM プロトコル](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf) のサポートを実装する互換性のある商用またはオープンソースの MDM サーバーが必要です。

* **集中デバイス管理** を実現する方法
* MDM プロトコルのサポートを実装する **MDM サーバー** が必要
* MDM サーバーは、リモートワイプや「この設定をインストールする」などの **MDM コマンドを送信** できます

### 基本 DEP (デバイス登録プログラム) とは何か？

[デバイス登録プログラム](https://www.apple.com/business/site/docs/DEP\_Guide.pdf) (DEP) は、iOS、macOS、tvOS デバイスの **ゼロタッチ構成** を提供することで、モバイルデバイス管理 (MDM) **登録を簡素化する** Apple が提供するサービスです。従来の展開方法とは異なり、エンドユーザーや管理者がデバイスを設定するためのアクションを取るか、手動で MDM サーバーに登録する必要があるのに対し、DEP はこのプロセスをブートストラップし、**ユーザーが新しい Apple デバイスを開封してすぐに組織で使用するために設定されるようにすることを目指しています**。

管理者は DEP を利用して、デバイスを自組織の MDM サーバーに自動的に登録することができます。デバイスが登録されると、**多くの場合、組織が所有する「信頼された」** デバイスとして扱われ、任意の数の証明書、アプリケーション、WiFi パスワード、VPN 設定 [など](https://developer.apple.com/enterprise/documentation/Configuration-Profile-Reference.pdf) を受け取ることができます。

* デバイスが **初めて電源を入れたときに**、事前に設定された MDM サーバーに自動的に登録することを可能にする
* **デバイス** が **真新しいとき** に最も役立つ
* OS の新規インストールで **ワイプされた** ワークフローの **再プロビジョニング** にも役立つ

{% hint style="danger" %}
残念ながら、組織が MDM 登録を保護するための追加の手順を講じていない場合、DEP を通じた簡素化されたエンドユーザー登録プロセスは、攻撃者が組織の MDM サーバーに自分の選択したデバイスを登録するための簡素化されたプロセスを意味することもあります。これは、企業デバイスの「アイデンティティ」を想定しています。
{% endhint %}

### 基本 SCEP (シンプル証明書登録プロトコル) とは何か？

* TLS と HTTPS が広く普及する前に作成された比較的古いプロトコルです。
* クライアントが証明書を付与する目的で **証明書署名要求** (CSR) を送信する標準化された方法を提供します。クライアントはサーバーに署名された証明書を要求します。

### 設定プロファイル (別名 mobileconfigs) とは何か？

* Apple の公式な **システム設定の設定/強制の方法**。
* 複数のペイロードを含むことができるファイル形式。
* プロパティリスト (XML タイプ) に基づいています。
* 「署名および暗号化されて、その起源を検証し、完全性を保証し、内容を保護することができます。」基本 — ページ 70、iOS セキュリティガイド、2018年1月。

## プロトコル

### MDM

* APNs (**Apple サーバー**) + RESTful API (**MDM ベンダー** サーバー) の組み合わせ
* **デバイス** と **デバイス管理製品** に関連するサーバー間で **通信** が発生します
* **コマンド** は、plist エンコードされた辞書で MDM からデバイスに配信されます
* すべて **HTTPS** 経由。MDM サーバーは通常ピン留めされています。
* Apple は認証のために MDM ベンダーに **APNs 証明書** を付与します

### DEP

* **3つの API**: 1つはリセラー用、1つは MDM ベンダー用、1つはデバイスアイデンティティ用 (未文書化):
* いわゆる [DEP "クラウドサービス" API](https://developer.apple.com/enterprise/documentation/MDM-Protocol-Reference.pdf)。これは、MDM サーバーが特定のデバイスに DEP プロファイルを関連付けるために使用されます。
* デバイスを登録し、登録状況を確認し、トランザクション状況を確認するために [Apple 認定リセラーが使用する DEP API](https://applecareconnect.apple.com/api-docs/depuat/html/WSImpManual.html)。
* 未文書化のプライベート DEP API。これは、Apple デバイスが DEP プロファイルを要求するために使用されます。macOS では、`cloudconfigurationd` バイナリがこの API で通信するために使用されます。
* より現代的で **JSON** ベース (plist と比較して)
* Apple は MDM ベンダーに **OAuth トークン** を付与します

**DEP "クラウドサービス" API**

* RESTful
* Apple から MDM サーバーへのデバイスレコードの同期
* MDM サーバーから Apple への「DEP プロファイル」の同期 (後で Apple からデバイスに配信される)
* DEP 「プロファイル」には以下が含まれます:
* MDM ベンダーサーバーの URL
* サーバー URL の追加信頼証明書 (オプションのピン留め)
* 追加設定 (例: セットアップアシスタントでスキップする画面)

## シリアル番号

2010年以降に製造された Apple デバイスは一般に **12文字の英数字** のシリアル番号を持っており、**最初の3桁は製造場所**、次の **2桁** は製造 **年** と **週**、次の **3桁** は **ユニークな識別子** を提供し、**最後の4桁** は **モデル番号** を表しています。

{% content-ref url="macos-serial-number.md" %}
[macos-serial-number.md](macos-serial-number.md)
{% endcontent-ref %}

## 登録と管理の手順

1. デバイスレコードの作成 (リセラー、Apple): 新しいデバイスのレコードが作成されます
2. デバイスレコードの割り当て (顧客): デバイスが MDM サーバーに割り当てられます
3. デバイスレコードの同期 (MDM ベンダー): MDM はデバイスレコードを同期し、DEP プロファイルを Apple にプッシュします
4. DEP チェックイン (デバイス): デバイスが DEP プロファイルを取得します
5. プロファイルの取得 (デバイス)
6. プロファイルのインストール (デバイス) a. MDM、SCEP、ルート CA ペイロードを含む
7. MDM コマンドの発行 (デバイス)

![](<../../../.gitbook/assets/image (564).png>)

ファイル `/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/System/Library/PrivateFrameworks/ConfigurationProfiles.framework/ConfigurationProfiles.tbd` は、登録プロセスの **高レベルの「手順」** と考えられる関数をエクスポートします。

### ステップ 4: DEP チェックイン - アクティベーションレコードの取得

このプロセスの部分は、**ユーザーが Mac を初めて起動するとき** (または完全にワイプした後)

![](<../../../.gitbook/assets/image (568).png>)

または `sudo profiles show -type enrollment` を実行するときに発生します

* **デバイスが DEP 有効かどうかを判断する**
* アクティベーションレコードは **DEP 「プロファイル」** の内部名です
* デバイスがインターネットに接続されるとすぐに開始されます
* **`CPFetchActivationRecord`** によって駆動されます
* **`cloudconfigurationd`** 経由で XPC によって実装されます。デバイスが最初に起動されたときの **「セットアップアシスタント」** または **`profiles`** コマンドは、アクティベーションレコードを取得するためにこのデーモンに **連絡します**。
* LaunchDaemon (常に root として実行)

アクティベーションレコードを取得するために **`MCTeslaConfigurationFetcher`** によって実行されるいくつかのステップに従います。このプロセスでは **Absinthe** と呼ばれる暗号化が使用されます

1. **証明書の取得**
1. GET [https://iprofiles.apple.com/resource/certificate.cer](https://iprofiles.apple.com/resource/certificate.cer)
2. 証明書から状態を **初期化する** (**`NACInit`**)
1. 様々なデバイス固有のデータを使用します (例: **`IOKit` 経由のシリアル番号**)
3. **セッションキーの取得**
1. POST [https://iprofiles.apple.com/session](https://iprofiles.apple.com/session)
4. セッションの確立 (**`NACKeyEstablishment`**)
5. リクエストの作成
1. POST [https://iprofiles.apple.com/macProfile](https://iprofiles.apple.com/macProfile) に `{ "action": "RequestProfileConfiguration", "sn": "" }` のデータを送信
2. JSON ペイロードは Absinthe を使用して暗号化されます (**`NACSign`**)
3. すべてのリクエストは HTTPs 経由で、組み込みのルート証明書が使用されます

![](<../../../.gitbook/assets/image (566).png>)

応答は、以下のような重要なデータを含む JSON 辞書です:

* **url**: アクティベーションプロファイルの MDM ベンダーホストの URL
* **anchor-certs**: 信頼されたアンカーとして使用される DER 証明書の配列

### **ステップ 5: プロファイルの取得**

![](<../../../.gitbook/assets/image (567).png>)

* DEP プロファイルで提供された **url** にリクエストを送信します。
* 提供された場合、**アンカー証明書** を使用して **信頼を評価します**。
* リマインダー: DEP プロファイルの **anchor\_certs** プロパティ
* **リクエストは単純な .plist** で、デバイス識別情報を
