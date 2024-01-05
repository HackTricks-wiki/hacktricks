<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* 独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションである[**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>


<a rel="license" href="https://creativecommons.org/licenses/by-nc/4.0/"><img alt="クリエイティブ・コモンズ・ライセンス" style="border-width:0" src="https://licensebuttons.net/l/by-nc/4.0/88x31.png" /></a><br>Copyright © Carlos Polop 2021.  本書に記載されているテキストは、特に指定されている場合（本書にコピーされた外部情報は元の著者に属する）を除き、Carlos Polopによる<a href="https://github.com/carlospolop/hacktricks">HACK TRICKS</a>は、<a href="https://creativecommons.org/licenses/by-nc/4.0/">クリエイティブ・コモンズ 表示-非営利 4.0 国際 (CC BY-NC 4.0)</a>の下でライセンスされています。

ライセンス: 表示-非営利 4.0 国際 (CC BY-NC 4.0)<br>
人が読めるライセンス: https://creativecommons.org/licenses/by-nc/4.0/<br>
完全な法的条項: https://creativecommons.org/licenses/by-nc/4.0/legalcode<br>
フォーマット: https://github.com/jmatsushita/Creative-Commons-4.0-Markdown/blob/master/licenses/by-nc.markdown<br>

# クリエイティブ・コモンズ

# 表示-非営利 4.0 国際

クリエイティブ・コモンズ法人（「クリエイティブ・コモンズ」）は法律事務所ではなく、法的サービスや法的アドバイスを提供しません。クリエイティブ・コモンズの公共ライセンスの配布は、弁護士-クライアントまたはその他の関係を作成しません。クリエイティブ・コモンズは、「現状のまま」でライセンスと関連情報を提供します。クリエイティブ・コモンズは、そのライセンス、ライセンスの下で提供される任意の材料、または関連情報に関して、いかなる保証も行いません。クリエイティブ・コモンズは、それらの使用から生じる可能性のあるすべての損害について、可能な限り全責任を免責します。

## クリエイティブ・コモンズ公共ライセンスの使用

クリエイティブ・コモンズの公共ライセンスは、著作権および特定の他の権利が指定された公共ライセンスの下で、著作権および特定の他の権利が指定された材料を共有するために、創作者および他の権利保持者が使用することができる一連の権利と条件を提供します。以下の考慮事項は情報提供のみを目的としており、網羅的ではなく、私たちのライセンスの一部ではありません。

* __ライセンサーに対する考慮事項:__ 私たちの公共ライセンスは、著作権および特定の他の権利によって制限される方法で材料を使用するための公共の許可を与えることが許可されている人々によって使用されることを意図しています。私たちのライセンスは取り消し不可能です。ライセンサーは、それを適用する前にライセンスの条件を読み、理解するべきです。ライセンサーはまた、公共が期待するように材料を再利用できるように、私たちのライセンスを適用する前に必要なすべての権利を確保するべきです。ライセンサーは、ライセンスの対象でない任意の材料を明確にマークするべきです。これには他のCCライセンス材料、または著作権の例外または制限の下で使用される材料が含まれます。[ライセンサーに対するより多くの考慮事項](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensors).

* __公共に対する考慮事項:__ 私たちの公共ライセンスのいずれかを使用することによって、ライセンサーは指定された条件の下でライセンスされた材料を使用するための公共の許可を付与します。ライセンサーの許可が何らかの理由で必要ない場合–例えば、著作権の適用可能な例外または制限のために–その使用はライセンスによって規制されません。私たちのライセンスは、ライセンサーが許可を与える権限を持っている著作権および特定の他の権利の下でのみ許可を付与します。ライセンスされた材料の使用は、他の理由で制限される可能性があります。これには、他の人が材料に著作権または他の権利を持っている場合が含まれます。ライセンサーは特別な要求をすることができます。例えば、すべての変更をマークまたは説明するように依頼することです。私たちのライセンスによって要求されていないにもかかわらず、合理的な場合にはそれらの要求を尊重することをお勧めします。[公共に対するより多くの考慮事項](http://wiki.creativecommons.org/Considerations_for_licensors_and_licensees#Considerations_for_licensees).

# クリエイティブ・コモンズ 表示-非営利 4.0 国際 パブリックライセンス

以下で定義されたライセンスされた権利（以下「ライセンスされた権利」という）を行使することにより、あなたはこのクリエイティブ・コモンズ 表示-非営利 4.0 国際 パブリックライセンス（以下「公共ライセンス」という）の条件に拘束されることに同意し、同意します。この公共ライセンスが契約として解釈される場合、あなたはこれらの条件に同意することを考慮してライセンスされた権利を付与され、ライセンサーはライセンスされた材料をこれらの条件の下で利用可能にすることから得られる利益を考慮してあなたにそのような権利を付与します。

## 第1条 – 定義.

a. __改変された材料__ は、ライセンスされた材料から派生したり、ライセンスされた材料に基づいており、ライセンサーが保持する著作権および類似の権利の下で許可が必要な方法で、ライセンスされた材料が翻訳されたり、変更されたり、配置されたり、変換されたり、またはその他の方法で変更された著作権および類似の権利が適用される材料を意味します。この公共ライセンスの目的のために、ライセンスされた材料が音楽作品、演奏、または音声記録である場合、改変された材料は常にライセンスされた材料が動く画像と同期して時間的に関連付けられた場合に生産されます。

b. __アダプターのライセンス__ は、この公共ライセンスの条件に従って、あなたが改変された材料へのあなたの貢献に適用するあなたの著作権および類似の権利のライセンスを意味します。

c. __著作権および類似の権利__ は、著作権に密接に関連する権利を含むがこれに限定されない、パフォーマンス、放送、音声記録、およびSui Generisデータベース権利を意味します。この公共ライセンスの目的のために、第2条(b)(1)-(2)で指定された権利は著作権および類似の権利ではありません。

d. __有効な技術的措置__ は、適切な権限がない場合に、1996年12月20日に採択されたWIPO著作権条約の第11条の下での義務を履行する法律の下で回避されない措置を意味します、および/または類似の国際協定。

e. __例外および制限__ は、あなたがライセンスされた材料を使用する際に適用される著作権および類似の権利への公正な使用、公正な取引、および/またはその他の例外または制限を意味します。

f. __ライセンスされた材料__ は、ライセンサーがこの公共ライセンスを適用した芸術的または文学的作品、データベース、またはその他の材料を意味します。

g. __ライセンスされた権利__ は、この公共ライセンスの条件に従ってあなたに付与された権利を意味し、ライセンサーがライセンスを付与する権限を持っているライセンスされた材料の使用に適用されるすべての著作権および類似の権利に限定されます。

h. __ライセンサー__ は、この公共ライセンスの下で権利を付与する個人または実体を意味します。

i. __非営利__ は、主に商業的利益または金銭的報酬を目的としていないことを意味します。この公共ライセンスの目的のために、ライセンスされた材料と著作権および類似の権利が適用される他の材料との交換がデジタルファイル共有または類似の手段によって行われる場合、その交換に金銭的報酬の支払いが伴わない限り、その交換は非営利です。

j. __共有__ は、ライセンスされた権利の下で許可が必要な手段またはプロセスによって公共に材料を提供することを意味し、例えば、複製、公開表示、公開実行、配布、普及、通信、または輸入を含み、公共が場所と時間を個別に選択して材料にアクセスできる方法で公共に材料を利用可能にすることを含みます。

k. __Sui Generisデータベース権利__ は、1996年3月11日の欧州議会および理事会の指令96/9/ECによるデータベースの法的保護に関するもの、および/または修正されたものおよび/または後継のもの、および世界中の他の本質的に同等の権利から生じる著作権以外の権利を意味します。

l. __あなた__ は、この公共ライセンスの下でライセンスされた権利を行使する個人または実体を意味します。あなたには対応する意味があります。

## 第2条 – 範囲.

a. ___ライセンスの付与.___

1. この公共ライセンスの条件に従って、ライセンサーは以下のライセンスされた権利を行使するために、あなたに対して世界的に、無償、非独占的、不可撤回のライセンスを付与します:

A.
```
Creative Commons is not a party to its public licenses. Notwithstanding, Creative Commons may elect to apply one of its public licenses to material it publishes and in those instances will be considered the “Licensor.” Except for the limited purpose of indicating that material is shared under a Creative Commons public license or as otherwise permitted by the Creative Commons policies published at [creativecommons.org/policies](http://creativecommons.org/policies), Creative Commons does not authorize the use of the trademark “Creative Commons” or any other trademark or logo of Creative Commons without its prior written consent including, without limitation, in connection with any unauthorized modifications to any of its public licenses or any other arrangements, understandings, or agreements concerning use of licensed material. For the avoidance of doubt, this paragraph does not form part of the public licenses.

Creative Commons may be contacted at [creativecommons.org](http://creativecommons.org/).
```
<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* **ハッキングのコツを共有するために、** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のgithubリポジトリにPRを提出する。

</details>
