# フィッシングの検出

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

## 導入

フィッシング試行を検出するためには、**現在使用されているフィッシング技術を理解することが重要**です。この投稿の親ページには、この情報が記載されていますので、現在使用されている技術について知らない場合は、親ページに移動して少なくともそのセクションを読むことをお勧めします。

この投稿は、**攻撃者がいかにして被害者のドメイン名を模倣または使用するか**という考えに基づいています。例えば、あなたのドメインが`example.com`と呼ばれ、`youwonthelottery.com`のような完全に異なるドメイン名を使用してフィッシングされた場合、これらの技術はそれを発見することはできません。

## ドメイン名の変種

メール内で使用される**類似したドメイン**名を使用する**フィッシング**試行を**発見**するのは**比較的簡単**です。\
攻撃者が使用する可能性のある**最もありそうなフィッシング名のリスト**を生成し、それが**登録されているかどうかを確認**するか、単にそれを使用している**IP**があるかどうかを**チェック**すれば十分です。

### 不審なドメインの検出

この目的のために、次のツールのいずれかを使用できます。これらのツールは、ドメインに割り当てられたIPがあるかどうかを自動的にDNSリクエストして確認することも注意してください。

* [**dnstwist**](https://github.com/elceef/dnstwist)
* [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### ビットフリップ

コンピューティングの世界では、メモリの裏側でビット（0と1）ですべてがビットで（ゼロと1）で格納されています。\
ドメインにもこれが適用されます。例えば、_windows.com_は、コンピューティングデバイスの揮発性メモリ内では_01110111..._となります。\
しかし、もし1つのビットが太陽フレア、宇宙線、またはハードウェアエラーによって自動的に反転した場合はどうでしょうか？つまり、0の1が1の0になるか、その逆です。\
DNSリクエストにこのコンセプトを適用すると、DNSサーバーに到着する**要求されたドメインが最初に要求されたドメインとは異なる可能性がある**ことがあります。

例えば、ドメインmicrosoft.comの1ビットの変更により、_windnws.com_に変換される可能性があります。\
**攻撃者は、被害者に関連するビットフリップドメインをできるだけ多く登録し、正規のユーザーを自分たちのインフラストラクチャにリダイレクトする**ことができます。

詳細については、[https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)を読んでください。

**すべての可能なビットフリップドメイン名も監視する必要があります。**

### 基本的なチェック

潜在的な不審なドメイン名のリストがある場合、それらを（主にHTTPおよびHTTPSのポート）**チェック**して、被害者のドメインと似たようなログインフォームを使用しているかどうかを**確認**する必要があります。\
ポート3333もチェックして、`gophish`のインスタンスが実行されているかどうかを確認することもできます。\
また、発見された不審なドメインの**年齢**を知ることも興味深いです。若いほどリスクが高くなります。\
HTTPおよび/またはHTTPSの不審なWebページの**スクリーンショット**を取得して、それが不審であるかどうかを確認し、その場合は**詳細を調査するためにアクセス**することもできます。

### 高度なチェック

さらに進む場合は、定期的に（毎日？数秒/数分しかかかりません）**これらの不審なドメインを監視し、さらに検索**することをお勧めします。関連するIPの**オープンポート**をチェックし、`gophish`や類似のツールのインスタンスを検索することも必要です（はい、攻撃者も間違えることがあります）。また、不審なドメインとサブドメインのHTTPおよびHTTPSのWebページを**監視**し、それらが被害者のWebページからログインフォームをコピーしているかどうかを確認することも重要です。\
これを**自動化**するためには、被害者のドメインのログインフォームのリストを持っておき、不審なWebページをスパイダリングし、不審なドメイン内で見つかった各ログインフォームを被害者のドメインの各ログインフォームと比較するために、`ssdeep`のようなものを使用することをお勧めします。\
不審なドメインのログインフォームを特定した場合、**ダミーの資格情報を送信**して、それが被害者のドメインにリダイレクトされるかどうかを**確認**することができます。
## キーワードを使用したドメイン名

親ページでは、**被害者のドメイン名を大きなドメインの中に配置する**ドメイン名の変化技術についても言及しています（例：paypal.comの場合、paypal-financial.com）。

### 証明書の透明性

以前の「ブルートフォース」アプローチはできませんが、証明書の透明性によってこのようなフィッシング試みを**発見することができます**。CAによって証明書が発行されるたびに、詳細が公開されます。つまり、証明書の透明性を読んだり、監視したりすることで、**名前にキーワードを使用しているドメインを見つけることができます**。たとえば、攻撃者が[https://paypal-financial.com](https://paypal-financial.com)の証明書を生成した場合、証明書を見ることでキーワード「paypal」を見つけ、不審なメールが使用されていることがわかります。

[https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)の投稿では、特定のキーワードに影響を与える証明書を検索し、日付（「新しい」証明書のみ）とCA発行者「Let's Encrypt」でフィルタリングするためにCensysを使用できると提案されています。

![](<../../.gitbook/assets/image (390).png>)

ただし、無料のウェブ[**crt.sh**](https://crt.sh)を使用して「同じこと」を行うこともできます。キーワードを**検索**し、必要に応じて結果を**日付とCAでフィルタリング**できます。

![](<../../.gitbook/assets/image (391).png>)

この最後のオプションでは、Matching Identitiesフィールドを使用して、実際のドメインのいずれかの識別子が不審なドメインと一致するかどうかを確認することもできます（不審なドメインは誤検知の可能性があることに注意してください）。

**別の代替案**は、[**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)という素晴らしいプロジェクトです。CertStreamは、新しく生成された証明書のリアルタイムストリームを提供し、指定されたキーワードを（ほぼ）リアルタイムで検出するために使用できます。実際、[**phishing\_catcher**](https://github.com/x0rz/phishing\_catcher)というプロジェクトがそれを行っています。

### **新しいドメイン**

**最後の代替案**は、一部のTLD（Top Level Domain）の**新しく登録されたドメインのリスト**を収集し、これらのドメインのキーワードを**チェックする**ことです（Whoxyがそのようなサービスを提供しています）。ただし、長いドメインは通常、1つ以上のサブドメインを使用するため、キーワードはFLD（First Level Domain）内に表示されず、フィッシングのサブドメインを見つけることはできません。
