# Persistência e Execução por Autoload de Plugin do Notepad++

{{#include ../../banners/hacktricks-training.md}}

Notepad++ irá **carregar automaticamente toda DLL de plugin encontrada nas suas subpastas `plugins`** ao iniciar. Colocar um plugin malicioso em qualquer instalação do Notepad++ que seja **gravável** fornece execução de código dentro de `notepad++.exe` toda vez que o editor for iniciado, o que pode ser abusado para **persistência**, **execução inicial** discreta, ou como um **in-process loader** se o editor for iniciado com privilégios elevados.

## Locais de plugin graváveis
- Instalação padrão: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (geralmente requer admin para gravar).
- Opções graváveis para operadores com poucos privilégios:
- Use a **portable Notepad++ build** em uma pasta gravável pelo usuário.
- Copie `C:\Program Files\Notepad++` para um caminho controlado pelo usuário (por exemplo, `%LOCALAPPDATA%\npp\`) e execute `notepad++.exe` a partir daí.
- Cada plugin recebe sua própria subpasta dentro de `plugins` e é carregado automaticamente na inicialização; entradas de menu aparecem em **Plugins**.

## Pontos de carregamento do plugin (primitivas de execução)
Notepad++ espera funções **exportadas** específicas. Estas são todas chamadas durante a inicialização, fornecendo múltiplas superfícies de execução:
- **`DllMain`** — executa imediatamente quando a DLL é carregada (primeiro ponto de execução).
- **`setInfo(NppData)`** — chamada uma vez no carregamento para fornecer handles do Notepad++; local típico para registrar itens de menu.
- **`getName()`** — retorna o nome do plugin mostrado no menu.
- **`getFuncsArray(int *nbF)`** — retorna comandos do menu; mesmo se vazio, é chamado durante a inicialização.
- **`beNotified(SCNotification*)`** — recebe eventos do editor (abrir/alterar arquivo, eventos de UI) para gatilhos contínuos.
- **`messageProc(UINT, WPARAM, LPARAM)`** — manipulador de mensagens, útil para trocas de dados maiores.
- **`isUnicode()`** — flag de compatibilidade verificada no carregamento.

A maioria das exportações pode ser implementada como **stubs**; a execução pode ocorrer a partir de `DllMain` ou qualquer callback acima durante o autoload.

## Esqueleto mínimo de plugin malicioso
Compile uma DLL com as exportações esperadas e coloque-a em `plugins\\MyNewPlugin\\MyNewPlugin.dll` sob uma pasta do Notepad++ gravável:
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
2. Crie a subpasta do plugin dentro de `plugins` e coloque a DLL lá dentro.
3. Reinicie o Notepad++; a DLL é carregada automaticamente, executando `DllMain` e callbacks subsequentes.

## Padrão de plugin Reflective loader
A weaponized plugin pode transformar o Notepad++ em um **reflective DLL loader**:
- Apresente uma UI/menu mínima (por exemplo, "LoadDLL").
- Aceitar um **caminho de arquivo** ou **URL** para buscar um payload DLL.
- Mapear o DLL no processo atual usando reflective mapping e invocar um ponto de entrada exportado (por exemplo, uma função loader dentro do DLL buscado).
- Benefício: reutilizar um processo GUI com aparência benigno em vez de iniciar um novo loader; o payload herda a integridade de `notepad++.exe` (incluindo contextos elevados).
- Compromissos: colocar uma **DLL de plugin não assinada** no disco é ruidoso; considere piggybacking em plugins confiáveis existentes, se houver.

## Notas de detecção e hardening
- Bloquear ou monitorar **gravações nos diretórios de plugins do Notepad++** (incluindo cópias portáteis em perfis de usuário); habilitar controlled folder access ou application allowlisting.
- Alertar sobre **novas DLLs não assinadas** sob `plugins` e atividade incomum de **processos filho/atividade de rede** originada de `notepad++.exe`.
- Exigir instalação de plugins apenas via **Plugins Admin**, e restringir a execução de cópias portáteis de caminhos não confiáveis.

## Referências
- [Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [MyNewPlugin PoC snippet](https://gitlab.com/-/snippets/4930986)
- [LoadDLL reflective loader plugin](https://gitlab.com/KevinJClark/ops-scripts/-/tree/main/notepad_plus_plus_plugin_LoadDLL)

{{#include ../../banners/hacktricks-training.md}}
