# Escapando de KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Verificar o dispositivo físico

| Component    | Action                                                             |
| ------------ | ------------------------------------------------------------------ |
| Power button | Desligar e ligar o dispositivo pode expor a tela inicial           |
| Power cable  | Verifique se o dispositivo reinicia quando a alimentação é cortada brevemente |
| USB ports    | Conecte um teclado físico para mais atalhos                        |
| Ethernet     | Uma varredura de rede ou sniffing pode possibilitar exploração adicional |

## Verificar ações possíveis dentro da GUI application

**Common Dialogs** são aquelas opções de **saving a file**, **opening a file**, selecionar uma fonte, uma cor... A maioria delas **oferece funcionalidade completa do Explorer**. Isso significa que você poderá acessar funcionalidades do Explorer se conseguir acessar essas opções:

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

Você deve verificar se é possível:

- Modificar ou criar novos arquivos
- Criar links simbólicos
- Acessar áreas restritas
- Executar outros apps

### Execução de comandos

Talvez **using a `Open with`** option\*\* você consiga abrir/executar algum tipo de shell.

#### Windows

Por exemplo _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ encontre mais binários que podem ser usados para executar comandos (e realizar ações inesperadas) aqui: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Mais em: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Contornando restrições de caminho

- **Variáveis de ambiente**: Existem muitas variáveis de ambiente que apontam para algum caminho
- **Outros protocolos**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Links simbólicos**
- **Atalhos**: CTRL+N (abrir nova sessão), CTRL+R (Executar comandos), CTRL+SHIFT+ESC (Gerenciador de Tarefas), Windows+E (abrir o Explorer), CTRL-B, CTRL-I (Favoritos), CTRL-H (Histórico), CTRL-L, CTRL-O (Diálogo Arquivo/Abrir), CTRL-P (Diálogo de Impressão), CTRL-S (Salvar como)
- Menu Administrativo oculto: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: Caminhos para conectar a pastas compartilhadas. Você deve tentar conectar ao C$ da máquina local ("\\\127.0.0.1\c$\Windows\System32")
- **Mais UNC paths:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%               | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

### Restricted Desktop Breakouts (Citrix/RDS/VDI)

- **Dialog-box pivoting**: Use *Open/Save/Print-to-file* dialogs como um Explorer-lite. Tente `*.*` / `*.exe` no campo de nome de arquivo, clique com o botão direito em pastas para **Open in new window**, e use **Properties → Open file location** para expandir a navegação.
- **Create execution paths from dialogs**: Crie um novo arquivo e renomeie para `.CMD` ou `.BAT`, ou crie um atalho apontando para `%WINDIR%\System32` (ou um binário específico como `%WINDIR%\System32\cmd.exe`).
- **Shell launch pivots**: Se você puder navegar até `cmd.exe`, tente fazer **drag-and-drop** de qualquer arquivo sobre ele para abrir um prompt. Se o Task Manager estiver acessível (`CTRL+SHIFT+ESC`), use **Run new task**.
- **Task Scheduler bypass**: Se shells interativos estiverem bloqueados mas o agendamento permitido, crie uma tarefa para executar `cmd.exe` (GUI `taskschd.msc` ou `schtasks.exe`).
- **Weak allowlists**: Se a execução for permitida por **filename/extension**, renomeie seu payload para um nome permitido. Se for permitida por **directory**, copie o payload para uma pasta de programa permitida e execute-o lá.
- **Find writable staging paths**: Comece por `%TEMP%` e enumere pastas graváveis com o Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Próximo passo**: Se você obtiver um shell, pivoteie para o checklist de Windows LPE:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Baixe seus binários

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Acessando o sistema de arquivos pelo navegador

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### Atalhos

- Sticky Keys – Pressione SHIFT 5 vezes
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – Segure NUMLOCK por 5 segundos
- Filter Keys – Segure o SHIFT direito por 12 segundos
- WINDOWS+F1 – Pesquisa do Windows
- WINDOWS+D – Mostrar Área de Trabalho
- WINDOWS+E – Abrir Windows Explorer
- WINDOWS+R – Executar
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Pesquisar
- SHIFT+F10 – Menu de contexto
- CTRL+SHIFT+ESC – Gerenciador de Tarefas
- CTRL+ALT+DEL – Tela de opções nas versões mais recentes do Windows
- F1 – Ajuda F3 – Buscar
- F6 – Barra de Endereço
- F11 – Alternar tela cheia dentro do Internet Explorer
- CTRL+H – Histórico do Internet Explorer
- CTRL+T – Internet Explorer – Nova Aba
- CTRL+N – Internet Explorer – Nova Página
- CTRL+O – Abrir Arquivo
- CTRL+S – Salvar CTRL+N – Novo RDP / Citrix

### Gestos

- Deslize da borda esquerda para a direita para ver todas as janelas abertas, minimizando o aplicativo KIOSK e acessando o sistema operacional diretamente;
- Deslize da borda direita para a esquerda para abrir o Action Center, minimizando o aplicativo KIOSK e acessando o sistema operacional diretamente;
- Deslize a partir da borda superior para tornar a barra de título visível para um aplicativo em modo de tela cheia;
- Deslize de baixo para cima para mostrar a barra de tarefas em um aplicativo em tela cheia.

### Truques do Internet Explorer

#### 'Image Toolbar'

É uma toolbar que aparece no canto superior esquerdo de uma imagem quando ela é clicada. Você poderá Salvar, Imprimir, Mailto, Abrir "My Pictures" no Explorer. O Kiosk precisa estar usando o Internet Explorer.

#### Protocolo Shell

Digite estas URLs para obter uma visualização do Explorer:

- `shell:Administrative Tools`
- `shell:DocumentsLibrary`
- `shell:Libraries`
- `shell:UserProfiles`
- `shell:Personal`
- `shell:SearchHomeFolder`
- `shell:NetworkPlacesFolder`
- `shell:SendTo`
- `shell:UserProfiles`
- `shell:Common Administrative Tools`
- `shell:MyComputerFolder`
- `shell:InternetFolder`
- `Shell:Profile`
- `Shell:ProgramFiles`
- `Shell:System`
- `Shell:ControlPanelFolder`
- `Shell:Windows`
- `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Control Panel
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> My Computer
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> My Network Places
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### Mostrar extensões de arquivo

Consulte esta página para mais informações: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## Truques de navegadores

Versões de backup iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Crie um diálogo comum usando JavaScript e acesse o Explorer: `document.write('<input/type=file>')`\
Fonte: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gestos e botões

- Deslize para cima com quatro (ou cinco) dedos / Toque duplo no botão Home: Para ver a visualização multitarefa e trocar de App
- Deslize para um lado ou outro com quatro ou cinco dedos: Para mudar para o próximo/anterior App
- Feche a tela com cinco dedos / Toque no botão Home / Deslize para cima com 1 dedo a partir da parte inferior da tela rapidamente para cima: Para acessar a Home
- Deslize um dedo a partir da parte inferior da tela cerca de 1-2 polegadas (devagar): O dock aparecerá
- Deslize para baixo a partir do topo da tela com 1 dedo: Para ver suas notificações
- Deslize para baixo com 1 dedo no canto superior direito da tela: Para ver o control centre do iPad Pro
- Deslize 1 dedo a partir da esquerda da tela 1-2 polegadas: Para ver a visualização Today
- Deslize rápido 1 dedo a partir do centro da tela para a direita ou esquerda: Para mudar para o próximo/anterior App
- Pressione e segure o botão On/**Off**/Sleep no canto superior direito do **iPad +** Mova o slider Slide to **power off** totalmente para a direita: Para desligar
- Pressione o botão On/**Off**/Sleep no canto superior direito do **iPad e o botão Home por alguns segundos**: Para forçar um desligamento completo
- Pressione o botão On/**Off**/Sleep no canto superior direito do **iPad e o botão Home rapidamente**: Para tirar um screenshot que aparecerá no canto inferior esquerdo da tela. Pressionar ambos os botões ao mesmo tempo por um breve instante; se segurados por alguns segundos, um desligamento forçado será realizado.

### Atalhos

Você deve ter um teclado para iPad ou um adaptador de teclado USB. Apenas os atalhos que podem ajudar a escapar do aplicativo serão mostrados aqui.

| Key | Nome         |
| --- | ------------ |
| ⌘   | Command      |
| ⌥   | Option (Alt) |
| ⇧   | Shift        |
| ↩   | Return       |
| ⇥   | Tab          |
| ^   | Control      |
| ←   | Left Arrow   |
| →   | Right Arrow  |
| ↑   | Up Arrow     |
| ↓   | Down Arrow   |

#### Atalhos do sistema

Estes atalhos são para as configurações visuais e de som, dependendo do uso do iPad.

| Atalho | Ação                                                                            |
| ------ | ------------------------------------------------------------------------------- |
| F1     | Dim da tela                                                                     |
| F2     | Aumentar brilho                                                                  |
| F7     | Voltar uma música                                                                |
| F8     | Play/pause                                                                       |
| F9     | Avançar música                                                                   |
| F10    | Mudo                                                                             |
| F11    | Diminuir volume                                                                  |
| F12    | Aumentar volume                                                                  |
| ⌘ Space| Exibe uma lista de idiomas disponíveis; para escolher um, pressione a barra de espaço novamente. |

#### Navegação no iPad

| Atalho                                           | Ação                                                  |
| ------------------------------------------------ | ----------------------------------------------------- |
| ⌘H                                              | Ir para a Home                                        |
| ⌘⇧H (Command-Shift-H)                           | Ir para a Home                                        |
| ⌘ (Space)                                       | Abrir Spotlight                                       |
| ⌘⇥ (Command-Tab)                                | Listar os últimos dez apps usados                     |
| ⌘\~                                             | Ir para o último App                                  |
| ⌘⇧3 (Command-Shift-3)                           | Screenshot (aparece no canto inferior esquerdo para salvar ou agir sobre ele) |
| ⌘⇧4                                            | Screenshot e abrir no editor                          |
| Pressione e segure ⌘                             | Lista de atalhos disponíveis para o App               |
| ⌘⌥D (Command-Option/Alt-D)                      | Exibe o dock                                          |
| ^⌥H (Control-Option-H)                          | Botão Home                                            |
| ^⌥H H (Control-Option-H-H)                      | Mostrar barra multitarefa                             |
| ^⌥I (Control-Option-i)                          | Seletor de itens                                      |
| Escape                                          | Botão Voltar                                          |
| → (seta direita)                                | Próximo item                                          |
| ← (seta esquerda)                               | Item anterior                                         |
| ↑↓ (seta para cima, seta para baixo)            | Toque simultâneo no item selecionado                  |
| ⌥ ↓ (Option-Down arrow)                         | Rolar para baixo                                      |
| ⌥↑ (Option-Up arrow)                            | Rolar para cima                                       |
| ⌥← ou ⌥→ (Option-Left arrow ou Option-Right arrow) | Rolar para a esquerda ou direita                      |
| ^⌥S (Control-Option-S)                          | Ativa/desativa a fala do VoiceOver                    |
| ⌘⇧⇥ (Command-Shift-Tab)                         | Alternar para o app anterior                          |
| ⌘⇥ (Command-Tab)                                | Voltar ao app original                                |
| ←+→, então Option + ← ou Option+→               | Navegar pelo Dock                                     |

#### Atalhos do Safari

| Atalho                | Ação                                           |
| --------------------- | ---------------------------------------------- |
| ⌘L (Command-L)        | Abrir Localização                              |
| ⌘T                    | Abrir uma nova aba                             |
| ⌘W                    | Fechar a aba atual                              |
| ⌘R                    | Recarregar a aba atual                          |
| ⌘.                    | Parar de carregar a aba atual                   |
| ^⇥                    | Ir para a próxima aba                           |
| ^⇧⇥ (Control-Shift-Tab)| Ir para a aba anterior                         |
| ⌘L                    | Selecionar o campo de texto/URL para editar     |
| ⌘⇧T (Command-Shift-T) | Abrir a última aba fechada (pode ser usado várias vezes) |
| ⌘\[                   | Voltar uma página no histórico de navegação     |
| ⌘]                    | Avançar uma página no histórico de navegação    |
| ⌘⇧R                  | Ativar o Reader Mode                            |

#### Atalhos do Mail

| Atalho                   | Ação                       |
| ------------------------ | -------------------------- |
| ⌘L                       | Abrir Localização          |
| ⌘T                       | Abrir uma nova aba         |
| ⌘W                       | Fechar a aba atual         |
| ⌘R                       | Recarregar a aba atual     |
| ⌘.                       | Parar de carregar a aba    |
| ⌘⌥F (Command-Option/Alt-F)| Buscar na sua caixa postal |

## Referências

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
