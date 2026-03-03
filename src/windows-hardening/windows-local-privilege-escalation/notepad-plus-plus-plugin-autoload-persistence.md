# Notepad++ Plugin Autoload Persistence & Execution

{{#include ../../banners/hacktricks-training.md}}

Notepad++ irá **autoload every plugin DLL found under its `plugins` subfolders** ao iniciar. Dropar um plugin malicioso em qualquer **writable Notepad++ installation** fornece code execution dentro de `notepad++.exe` toda vez que o editor é iniciado, o que pode ser abusado para **persistence**, inicialização stealthy (**initial execution**), ou como um **in-process loader** se o editor for iniciado com privilégios elevados.

## Writable plugin locations
- Standard install: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (geralmente requer admin para escrever).
- Writable options for low-privileged operators:
- Use the **portable Notepad++ build** in a user-writable folder.
- Copy `C:\Program Files\Notepad++` to a user-controlled path (e.g., `%LOCALAPPDATA%\npp\`) and run `notepad++.exe` from there.
- Cada plugin recebe sua própria subpasta dentro de `plugins` e é carregado automaticamente na inicialização; entradas de menu aparecem em **Plugins**.

## Plugin load points (execution primitives)
Notepad++ espera funções **exported** específicas. Todas são chamadas durante a inicialização, oferecendo múltiplas superfícies de execução:
- **`DllMain`** — executa imediatamente ao carregar a DLL (primeiro ponto de execução).
- **`setInfo(NppData)`** — chamada uma vez no load para fornecer handles do Notepad++; lugar típico para registrar itens de menu.
- **`getName()`** — retorna o nome do plugin mostrado no menu.
- **`getFuncsArray(int *nbF)`** — retorna comandos de menu; mesmo que vazio, é chamado durante o startup.
- **`beNotified(SCNotification*)`** — recebe eventos do editor (abertura/alteração de arquivo, eventos de UI) para triggers contínuos.
- **`messageProc(UINT, WPARAM, LPARAM)`** — handler de mensagens, útil para trocas maiores de dados.
- **`isUnicode()`** — flag de compatibilidade verificada no load.

A maioria das exports pode ser implementada como **stubs**; execução pode ocorrer a partir de `DllMain` ou qualquer callback acima durante o autoload.

## Minimal malicious plugin skeleton
Compile uma DLL com as exports esperadas e coloque-a em `plugins\\MyNewPlugin\\MyNewPlugin.dll` dentro de uma pasta do Notepad++ onde seja gravável:
```c
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID) { if (r == DLL_PROCESS_ATTACH) MessageBox(NULL, TEXT("Hello from Notepad++"), TEXT("MyNewPlugin"), MB_OK); return TRUE; }
extern "C" __declspec(dllexport) void setInfo(NppData) {}
extern "C" __declspec(dllexport) const TCHAR *getName() { return TEXT("MyNewPlugin"); }
extern "C" __declspec(dllexport) FuncItem *getFuncsArray(int *nbF) { *nbF = 0; return NULL; }
extern "C" __declspec(dllexport) void beNotified(SCNotification *) {}
extern "C" __declspec(dllexport) LRESULT messageProc(UINT, WPARAM, LPARAM) { return TRUE; }
extern "C" __declspec(dllexport) BOOL isUnicode() { return TRUE; }
```
1. Construa a DLL (Visual Studio/MinGW).
2. Crie a subpasta do plugin em `plugins` e coloque a DLL dentro.
3. Reinicie o Notepad++; a DLL é carregada automaticamente, executando `DllMain` e callbacks subsequentes.

## Reflective loader plugin pattern
Um plugin weaponizado pode transformar o Notepad++ em um **reflective DLL loader**:
- Apresente uma UI/menu mínima (por exemplo, "LoadDLL").
- Aceitar um **caminho de arquivo** ou **URL** para buscar uma DLL payload.
- Mapear a DLL de forma refletiva no processo atual e invocar um ponto de entrada exportado (por exemplo, uma função loader dentro da DLL obtida).
- Vantagem: reutilizar um processo GUI com aparência inofensiva em vez de criar um novo loader; o payload herda a integridade de `notepad++.exe` (incluindo contextos elevados).
- Compromissos: deixar uma **DLL de plugin não assinada** no disco chama atenção; considere aproveitar plugins confiáveis já presentes, se houver.

## Notas de detecção e hardening
- Bloquear ou monitorar gravações nos diretórios de plugins do Notepad++ (incluindo cópias portáteis em perfis de usuário); ative Controlled Folder Access ou application allowlisting.
- Gerar alerta sobre **novas DLLs não assinadas** em `plugins` e atividade incomum de **processos filhos/rede** vindos de `notepad++.exe`.
- Imponha a instalação de plugins apenas via **Plugins Admin**, e restrinja a execução de cópias portáteis provenientes de caminhos não confiáveis.

## Referências
- [Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [MyNewPlugin PoC snippet](https://gitlab.com/-/snippets/4930986)
- [LoadDLL reflective loader plugin](https://gitlab.com/KevinJClark/ops-scripts/-/tree/main/notepad_plus_plus_plugin_LoadDLL)

{{#include ../../banners/hacktricks-training.md}}
