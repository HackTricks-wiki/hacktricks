# データベース leak

{{#include ../../banners/hacktricks-training.md}}

## データ侵害検索エンジン

侵害データやレピュテーションデータを検索する際のAPIアクセスやサービス固有の注意事項については、[Reconnaissance and Threat-Intelligence APIs catalog](reconnaissance-and-threat-intelligence-apis.md)を参照してください。

- [GreyNoise Visualizer](https://viz.greynoise.io/) - IPやCIDRを調べ、タグ、CVE、メタデータでスキャナーのアクティビティを検索できます。<sup>[[1]](#references)</sup>
- [DeHashed](https://www.dehashed.com/) - ユーザー名、メールアドレス、IPアドレスなどの検索条件で公開データを検索できます。モニタリングとAPIも利用できます。<sup>[[2]](#references)</sup>
- [Have I Been Pwned?](https://haveibeenpwned.com/) - メールアドレスが既知のデータ侵害やpasteの記録に含まれているか確認できます。通知とAPIも利用できます。<sup>[[3]](#references)</sup>
- [ScamSearch](https://scamsearch.io/) - プロフィール画像、メールアドレス、ユーザー名、電話番号、暗号資産アドレス、ウェブサイトから、報告された詐欺師の記録を検索できます。<sup>[[4]](#references)</sup>
- [Intelligence X](https://intelx.io/) - メールアドレス、ドメイン、URL、IP、CIDRなどの検索条件で、インデックス化された情報源を検索できます。<sup>[[5]](#references)</sup>
- [SpyCloud](https://spycloud.com/check-your-exposure/) - 会社のメールアドレスまたはドメインを使って、公開された認証情報、infostealerに感染したID、盗まれたセッションCookieを確認できます。<sup>[[6]](#references)</sup>
- [WeLeakInfo](https://weleakinfo.io/) - ドメイン、氏名、メールアドレス、ID、電話番号、IP、URL、ハッシュを使って、leakされたデータベースを検索できます。<sup>[[7]](#references)</sup>
- [BreachDirectory](https://breachdirectory.org/) - メールアドレスまたはユーザー名が侵害されたか確認できます。
- [LeakCheck](https://leakcheck.io/) - 公開されたメールアドレス、ユーザー名、電話番号、ハッシュ、ドメインのデータを検索し、新しい情報をモニタリングできます。<sup>[[8]](#references)</sup>
- [Findemail.io](https://findemail.io/) - 指定した企業のメールアドレスを検索できます。
- [Library of Leaks](https://search.libraryofleaks.org/) - leakデータセットを含む公開文書、企業、人物を検索できます。<sup>[[9]](#references)</sup>
- [LeakRadar](https://leakradar.io/) - メールアドレス、ドメイン、または生の文字列からleakされた認証情報を検索し、新たな流出をモニタリングできます。<sup>[[10]](#references)</sup>
- [InfoStealers](https://infostealers.info/en/info) - 感染デバイスから収集されたinfostealerログを検索し、新しいデータをモニタリングできます。<sup>[[11]](#references)</sup>
- [Leak-Lookup](https://leak-lookup.com/) - データ侵害を横断検索し、認証情報の露出をモニタリングできます。<sup>[[12]](#references)</sup>
- [Scylla.so](https://scylla.so/) - コミュニティ主導のデータベース侵害検索エンジンです。
- [Leaked.domains](https://leaked.domains/) - ドメイン、メールアドレス、ユーザー名、パスワード、IPなどの検索条件から、leakされた認証情報や関連記録を検索できます。<sup>[[13]](#references)</sup>
- [WhiteIntel](https://whiteintel.io/) - ダークウェブ上のアクティビティ、認証情報のleak、infostealerデータ、ブランドへの言及をモニタリングできます。<sup>[[14]](#references)</sup>
- [PSBDMP](https://psbdmp.ws/) - Pastebinのダンプを検索・モニタリングするプラットフォームです。

## data leakを列挙するツール

- [Leaker](https://github.com/vflame6/leaker) - メールアドレス、ユーザー名、ドメイン、キーワード、電話番号を使って複数のオンライン情報源を検索する、パッシブなleak発見用CLIです。<sup>[[15]](#references)</sup>

## References

- [1] [GreyNoise Visualizerの使用方法](https://docs.greynoise.io/docs/using-the-greynoise-visualizer)
- [2] [DeHashed](https://www.dehashed.com/)
- [3] [Have I Been Pwned](https://haveibeenpwned.com/)
- [4] [世界の詐欺師データベース - ScamSearch](https://scamsearch.io/)
- [5] [Intelligence X](https://intelx.io/)
- [6] [露出状況の確認 - SpyCloud](https://spycloud.com/check-your-exposure/)
- [7] [WeLeakInfo](https://weleakinfo.io/)
- [8] [データ侵害検索エンジン - LeakCheck](https://leakcheck.io/)
- [9] [Library of Leaks](https://search.libraryofleaks.org/)
- [10] [LeakRadar](https://leakradar.io/)
- [11] [OSINT InfoStealers.Info](https://infostealers.info/en/info)
- [12] [Leak-Lookup - データ侵害検索エンジン](https://leak-lookup.com/)
- [13] [Leaked.Domains - ユニバーサル検索](https://leaked.domains/)
- [14] [WhiteIntel - ダークウェブインテリジェンスおよびモニタリングプラットフォーム](https://whiteintel.io/)
- [15] [vflame6/leaker](https://github.com/vflame6/leaker)
{{#include ../../banners/hacktricks-training.md}}
