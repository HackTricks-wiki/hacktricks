<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見る
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦で**フォロー**する：[**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **ハッキングトリックを共有するには、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>


From: [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

画像ファイル形式と同様に、オーディオおよびビデオファイルのトリックは、現実世界でハッキングやデータの隠蔽がこの方法で行われるわけではないためではなく、単にオーディオとビデオが楽しいからです。画像ファイル形式と同様に、ステガノグラフィを使用してコンテンツデータに秘密のメッセージを埋め込むことがあり、再び、手がかりを見つけるためにファイルのメタデータ領域をチェックする必要があります。最初のステップは、[mediainfo](https://mediaarea.net/en/MediaInfo)ツール（または`exiftool`）を使用してコンテンツタイプを識別し、そのメタデータを確認することです。

[Audacity](http://www.audacityteam.org/)は、主要なオープンソースのオーディオファイルおよび波形表示ツールです。CTFのチャレンジ作成者は、テキストをオーディオ波形にエンコードすることが好きで、これはスペクトログラムビューを使用して見ることができます（専用のツールである[Sonic Visualiser](http://www.sonicvisualiser.org/)が特にこのタスクには向いています）。 Audacityを使用すると、隠されたメッセージがあると疑う場合に、スローダウン、逆再生、および他の操作を行うことができ、隠されたメッセージが明らかになるかもしれません（ガーブル音、干渉、または静的ノイズが聞こえる場合）。 [Sox](http://sox.sourceforge.net/)は、オーディオファイルの変換や操作に役立つ別の便利なコマンドラインツールです。

また、秘密のメッセージをチェックするために最も下位ビット（LSB）をチェックすることも一般的です。ほとんどのオーディオおよびビデオメディア形式は、ストリーミングできるように固定サイズの「チャンク」を使用しているため、これらのチャンクのLSBは、ファイルに目に見える影響を与えずにデータを隠す一般的な場所です。

他の場合、メッセージはオーディオに[DTMFトーン](http://dialabc.com/sound/detect/index.html)やモールス信号としてエンコードされている場合があります。これらの場合は、[multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)を使用してデコードしてみてください。

ビデオファイル形式はコンテナ形式であり、再生のためにオーディオとビデオの別々のストリームが多重化されて含まれています。ビデオファイル形式を分析および操作するには、[FFmpeg](http://ffmpeg.org/)が推奨されています。 `ffmpeg -i`はファイルコンテンツの初期分析を提供します。また、コンテンツストリームをデマルチプレックス化したり再生したりすることもできます。 FFmpegの機能は、[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)を使用してPythonに公開されています。

</details>
