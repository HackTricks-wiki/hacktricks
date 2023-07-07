<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。

- **ハッキングのトリックを共有するには、[hacktricks repo](https://github.com/carlospolop/hacktricks)と[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>


From: [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

画像ファイル形式と同様に、オーディオおよびビデオファイルのトリックは、CTFフォレンジックの課題で一般的です。これは、現実世界ではハッキングやデータの隠蔽がこの方法で行われるわけではなく、単にオーディオとビデオが楽しいからです。画像ファイル形式と同様に、ステガノグラフィーを使用してコンテンツデータに秘密のメッセージを埋め込むことがあり、再びファイルのメタデータ領域をチェックする必要があります。最初のステップは、[mediainfo](https://mediaarea.net/en/MediaInfo)ツール（または`exiftool`）で内容のタイプを確認し、メタデータを確認することです。

[Audacity](http://www.audacityteam.org/)は、最も優れたオープンソースのオーディオファイルおよび波形表示ツールです。CTFの課題作成者は、テキストをオーディオ波形にエンコードすることが好きで、これはスペクトログラムビューを使用して確認できます（ただし、この特定のタスクには[Sonic Visualiser](http://www.sonicvisualiser.org/)という専門ツールの方が優れています）。 Audacityは、ガーブル音、干渉、または静的がある場合に隠されたメッセージを明らかにする可能性がある、スローダウン、逆再生などの操作も可能です。 [Sox](http://sox.sourceforge.net/)は、オーディオファイルの変換と操作に役立つ別の便利なコマンドラインツールです。

また、秘密のメッセージをLSB（Least Significant Bits）にエンコードすることも一般的です。ほとんどのオーディオおよびビデオメディア形式は、ストリーミングできるように個別の（固定サイズの）「チャンク」を使用するため、これらのチャンクのLSBは、ファイルに目に見える影響を与えずにデータを密輸するための一般的な場所です。

他の場合では、メッセージはオーディオに[DTMFトーン](http://dialabc.com/sound/detect/index.html)やモールス符号としてエンコードされている場合があります。これらの場合は、[multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)を使用してデコードを試みてください。

ビデオファイル形式は、再生のためにオーディオとビデオの別々のストリームを含むコンテナ形式です。ビデオファイル形式の分析と操作には、[FFmpeg](http://ffmpeg.org/)が推奨されています。 `ffmpeg -i`は、ファイルの内容の初期分析を提供します。また、コンテンツストリームをデマルチプレクスまたは再生することもできます。FFmpegのパワーは、[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)を使用してPythonに公開されています。



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。

- **ハッキングのトリックを共有するには、[hacktricks repo](https://github.com/carlospolop/hacktricks)と[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
