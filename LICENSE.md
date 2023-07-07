<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出**してください。

</details>


<a rel="license" href="https://creativecommons.org/licenses/by-nc/4.0/"><img alt="Creative Commons License" style="border-width:0" src="https://licensebuttons.net/l/by-nc/4.0/88x31.png" /></a><br>著作権 © Carlos Polop 2021.  ただし、他の場所で特に指定されていない限り（書籍にコピーされた外部情報は元の著者の所有物です）、Carlos Polopの<a href="https://github.com/carlospolop/hacktricks">HACK TRICKS</a>のテキストは<a href="https://creativecommons.org/licenses/by-nc/4.0/">クリエイティブ・コモンズ・ライセンス表示 - 非営利 4.0 国際 (CC BY-NC 4.0)</a>の下でライセンスされています。

ライセンス: クリエイティブ・コモンズ・ライセンス表示 - 非営利 4.0 国際 (CC BY-NC 4.0)<br>
人間に読みやすいライセンス: https://creativecommons.org/licenses/by-nc/4.0/<br>
完全な法的条項: https://creativecommons.org/licenses/by-nc/4.0/legalcode<br>
フォーマット: https://github.com/jmatsushita/Creative-Commons-4.0-Markdown/blob/master/licenses/by-nc.markdown<br>

# クリエイティブ・コモンズ

# クリエイティブ・コモンズ表示 - 非営利 4.0 国際

クリエイティブ・コモンズ法人（以下「クリエイティブ・コモンズ」）は法律事務所ではなく、法的サービスや法的助言を提供していません。クリエイティブ・コモンズの公開ライセンスの配布は、弁護士とクライアントとの関係やその他の関係を作成するものではありません。クリエイティブ・コモンズは、ライセンス、その条件に従ってライセンスされた資料、および関連情報に関して、いかなる保証も提供しません。クリエイティブ・コモンズは、その使用によって生じる損害について、可能な限り免責します。

## クリエイティブ・コモンズ公開ライセンスの使用

クリエイティブ・コモンズの公開ライセンスは、著作権および一部の他の権利によって制約されるオリジナルの著作物や他の資料を共有するために、作成者や他の権利者が使用できる標準的な条件を提供します。以下の考慮事項は情報提供の目的であり、限定的ではなく、ライセンスの一部ではありません。

* __ライセンサーの考慮事項:__ クリエイティブ・コモンズの公開ライセンスは、著作権や一部の他の権利によって制約される資料を一般に使用許可する権限を持つ者が使用することを意図しています。ライセンスは取り消すことができません。ライセンサーは、適用するライセンスの条項と条件をよく読み理解する必要があります。ライセンサーは、ライセンスを適用する前に必要なすべての権利を確保する必要があります。これには、ライセンスの対象外の資料を明確に表示することも含まれます。これには、他のCCライセンスの資料や、著作権の例外や制限の下で使用される資料が含まれます。[ライセンサーの詳細な考慮事項](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensors)を参照してください。

* __一般の考慮事項:__ クリエイティブ・コモンズの公開ライセンスを使用することにより、ライセンサーは特定の条件の下でライセンスされた資料を一般に使用する許可を一般に与えます。ライセンサーの許可が必要ない場合（たとえば、著作権の例外や制限の適用により）、その使用はライセンスによって規制されません。クリエイティブ・コモンズのライセンスは、ライセンサーが許可する権限に基づく著作権および一部の他の権利のみを付与します。ライセンスされた資料の使用は、他の理由により制限される場合があります。これには、他の人が資料に著作権や他の権利を持っている場合も含まれます。ライセンサーは、すべての変更がマークされるか説明されるように特別な要求をする場合があります。クリエイティブ・コモンズのライセンスでは必要ではありませんが、合理的な範囲でこれらの要求を尊重することが推奨されます。[一般の考慮事項](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensees)を参照してください。

# クリエイティブ・コモンズ表示 - 非営利 4.0 国際 公開ライセンス

ライセンスされた権利（以下「ライセンスされた権利」という）を行使することにより、これらの利用規約に拘束されることを受け入れ、同意します。このクリエイティブ・コモンズ表示 - 非営利 4.0 国際公開ライセンス（以下「パブリック・ライセンス」という）の条項と条件によって、契約として解釈される場合、これらの利用規約を受け入れることにより、ライセンスされた権利が付与され、ライセンサーはこれらの条項と条件の下でライセンスされた資料を提供することによって受け取る利益に対する対価として、これらの権利をあなたに付与します。
## セクション1 - 定義

a. __適応された資料__ は、著作権および類似の権利の対象であり、ライセンサーが保持する著作権および類似の権利に基づいて翻訳、変更、編曲、変形、またはその他の方法でライセンス資料が許可を必要とするように変更されたものを指します。このパブリックライセンスの目的において、ライセンス資料が音楽作品、パフォーマンス、または音声録音である場合、適応された資料は常にライセンス資料が動画とタイミングを合わせて使用される場合に作成されます。

b. __アダプターのライセンス__ は、このパブリックライセンスの条件に従って、適応された資料への貢献における著作権および類似の権利に適用するライセンスを指します。

c. __著作権および類似の権利__ は、著作権に密接に関連する著作権、パフォーマンス、放送、音声録音、および独自のデータベース権利を指します。このパブリックライセンスの目的において、セクション2(b)(1)-(2)で指定された権利は著作権および類似の権利ではありません。

d. __効果的な技術的手段__ は、適切な権限のない場合に回避できない措置を指します。これは、1996年12月20日に採択されたWIPO著作権条約の第11条に基づく義務を果たす法律によって禁止されるものです。

e. __例外および制限__ は、著作権および類似の権利に適用される公正な使用、公正な処理、および/またはその他の例外または制限を指します。

f. __ライセンス資料__ は、ライセンサーがこのパブリックライセンスを適用した芸術作品、文学作品、データベース、またはその他の資料を指します。

g. __ライセンスされた権利__ は、ライセンサーがライセンスを付与する権利であり、ライセンサーがライセンスを付与する権限を持つライセンス資料の使用に適用されるすべての著作権および類似の権利に制限されます。

h. __ライセンサー__ は、このパブリックライセンスの下で権利を付与する個人または団体を指します。

i. __非営利__ は、主に商業的な利益または金銭的な報酬を目的としていないことを意味します。このパブリックライセンスの目的において、デジタルファイル共有または類似の手段による著作権および類似の権利の対象となる資料との交換において、金銭的な報酬の支払いがない場合、非営利であるとみなされます。

j. __共有__ は、ライセンスされた権利による許可が必要な方法またはプロセスによって、一般の人々に資料を提供し、複製、公開表示、公開演奏、配布、普及、通信、または輸入などの方法で資料を一般の人々が個別に選択した場所と時間でアクセスできるようにすることを指します。

k. __独自のデータベース権利__ は、1996年3月11日の欧州議会および理事会の指令96/9/ECに基づく著作権以外の権利を指します。これは、世界中の他の本質的に同等の権利を含みます。

l. __あなた__ は、このパブリックライセンスの下でライセンスされた権利を行使する個人または団体を指します。"Your" はそれに対応する意味を持ちます。

## セクション2 - 範囲

a. ___ライセンスの付与___

1. このパブリックライセンスの条件に従って、ライセンサーは、以下のライセンスをあなたに対して無償で、サブライセンス不可、非独占的、取り消し不能な世界的なライセンスとして、ライセンス資料に対するライセンス権を付与します。

A. 非営利目的のために、ライセンス資料を全部または一部複製し、共有すること。

B. 非営利目的のために、適応された資料を製作、複製、共有すること。

2. __例外および制限__ 確認のために、例外および制限があなたの使用に適用される場合、このパブリックライセンスは適用されず、その条件に従う必要はありません。

3. __期間__ このパブリックライセンスの期間は、セクション6(a)で指定されています。

4. __メディアおよびフォーマット；技術的な変更の許可__ ライセンサーは、既知または今後作成されるすべてのメディアおよびフォーマットでライセンス権を行使し、それを行うために必要な技術的な変更を許可します。ライセンサーは、このセクション2(a)(4)によって許可された修正を行うことを妨げる権利または権限を主張しないことに同意します。このパブリックライセンスの目的において、このセクション2(a)(4)によって許可された修正は、適応された資料を作成することはありません。

5. __下流の受取人__

A. __ライセンサーからの提供 - ライセンス資料__ ライセンス資料の受取人は、自動的にライセンサーからこのパブリックライセンスの条件に従ってライセンス権を行使するための提供を受けます。

B. __下流への制限なし__ ライセンス資料の受取人のライセンス権の行使を制限するために、追加または異なる条件を課したり、効果的な技術的手段を適用したりすることはできません。

6. __承認なし__ このパブリックライセンスによって、ライセンサーや他の属性の表示を受けることが許可されていると主張または暗示する許可を与えるものではありません。

b. ___その他の権利___

1. このパブリックライセンスでは、道徳的権利（完全性の権利など）や公表権、プライバシーなどの類似のパーソナリティ権利はライセンスされません。ただし、可能な限り、ライセンサーは、ライセンス権を行使するために必要な範囲で、これらの権
## セクション4 - Sui Generisデータベース権利。

ライセンスされた権利にSui Generisデータベース権利が含まれている場合：

a. 疑義を回避するために、セクション2(a)(1)は、非営利目的のためにデータベースの内容の全部または実質的な部分を抽出、再利用、複製、共有する権利を付与します。

b. Sui Generisデータベース権利を持つデータベースにデータベースの内容の全部または実質的な部分を含める場合、Sui Generisデータベース権利を持つデータベース（ただし、その個々の内容ではない）は適応された素材です。

c. データベースの内容の全部または実質的な部分を共有する場合、セクション3(a)の条件に従う必要があります。

疑義を回避するために、このセクション4は、ライセンスされた権利に他の著作権および類似の権利が含まれている場合でも、このパブリックライセンスの義務を補完し、置き換えるものではありません。

## セクション5 - 免責事項と責任制限。

a. __ライセンサーが別途引き受けていない限り、ライセンサーは可能な限りライセンスされた素材を現状有姿および利用可能な状態で提供し、明示的、黙示的、法定、その他のいかなる種類の表明や保証も行いません。これには、所有権、商品性、特定の目的への適合性、非侵害、潜在的な欠陥の有無、正確性、エラーの有無（既知または発見可能であるか否か）などの保証が含まれます。保証の免責が全面または一部で許可されていない場合、この免責事項は適用されない場合があります。__

b. __可能な限り、法的理論（過失を含む）またはその他の理由に基づき、ライセンサーはこのパブリックライセンスまたはライセンスされた素材の使用に起因する直接、特別、間接、付随的、結果的、懲罰的、模範的な損失、費用、経費、または損害について、ライセンシーに対して一切の責任を負いません。ライアビリティの制限が全面または一部で許可されていない場合、この制限は適用されない場合があります。__

c. 上記の保証の免責事項と責任制限は、可能な限り絶対的な免責事項および免責事項の放棄に最も近い方法で解釈されます。

## セクション6 - 期間と終了。

a. このパブリックライセンスは、ここでライセンスされた著作権および類似の権利の期間に適用されます。ただし、このパブリックライセンスに違反した場合、このパブリックライセンスの権利は自動的に終了します。

b. セクション6(a)に基づき、ライセンスされた素材の使用権が終了した場合、次のように再開されます：

1. 違反が修正された日付から30日以内に修正された場合、自動的に再開されます。

2. ライセンサーによる明示的な再開の場合。

疑義を回避するために、このセクション6(b)は、ライセンサーがこのパブリックライセンスの違反に対する救済措置を求める権利に影響を与えません。

c. 疑義を回避するために、ライセンサーはライセンスされた素材を別の条件または条件で提供することもあり、またいつでもライセンスされた素材の配布を停止することもあります。ただし、これによってこのパブリックライセンスは終了しません。

d. セクション1、5、6、7、および8は、このパブリックライセンスの終了後も存続します。

## セクション7 - その他の条件。

a. ライセンサーは、明示的に同意しない限り、ユーザーから伝えられた追加または異なる条件に拘束されません。

b. ここに記載されていないライセンスされた素材に関する取り決め、理解、または合意は、このパブリックライセンスの条件とは別に独立しています。

## セクション8 - 解釈。

a. 疑義を回避するために、このパブリックライセンスは、このパブリックライセンスの許可なしに合法的に行われる可能性のあるライセンスされた素材の使用に対して、減少、制限、制約、または条件を設けるものではありません。

b. 可能な限り、このパブリックライセンスのいかなる条項も強制されない場合、それを強制可能な最小限の範囲に自動的に改正します。規定が改正できない場合、それはこのパブリックライセンスから切り離され、残りの条項と条件の強制可能性に影響を与えません。

c. ライセンサーの明示的な同意がない限り、このパブリックライセンスのいかなる条項または条件も放棄されず、遵守の失敗も同意されません。

d. このパブリックライセンスには、ライセンサーまたはユーザーに適用される特権や免除に制限または放棄を意味するものではありません。これには、任意の管轄権または権限の法的手続きからの特権や免除が含まれます。
```
Creative Commons is not a party to its public licenses. Notwithstanding, Creative Commons may elect to apply one of its public licenses to material it publishes and in those instances will be considered the “Licensor.” Except for the limited purpose of indicating that material is shared under a Creative Commons public license or as otherwise permitted by the Creative Commons policies published at [creativecommons.org/policies](http://creativecommons.org/policies), Creative Commons does not authorize the use of the trademark “Creative Commons” or any other trademark or logo of Creative Commons without its prior written consent including, without limitation, in connection with any unauthorized modifications to any of its public licenses or any other arrangements, understandings, or agreements concerning use of licensed material. For the avoidance of doubt, this paragraph does not form part of the public licenses.

Creative Commons may be contacted at [creativecommons.org](http://creativecommons.org/).
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
