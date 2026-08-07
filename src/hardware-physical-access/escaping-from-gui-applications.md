# Escapando de KIOSKs

{{#include ../banners/hacktricks-training.md}}

---

## Verificar o dispositivo físico

| Componente   | Ação                                                              |
| ------------ | ----------------------------------------------------------------- |
| Botão liga/desliga | Desligar e ligar o dispositivo novamente pode expor a tela inicial |
| Cabo de energia | Verifique se o dispositivo reinicia quando a energia é interrompida brevemente |
| Portas USB    | Conecte um teclado físico com mais atalhos                      |
| Ethernet     | A varredura ou o sniffing da rede podem permitir uma exploração adicional |

## Verificar possíveis ações dentro do aplicativo GUI

**Diálogos comuns** são aquelas opções de **salvar um arquivo**, **abrir um arquivo**, selecionar uma fonte, uma cor... A maioria deles **oferecerá todas as funcionalidades do Explorer**. Isso significa que você poderá acessar as funcionalidades do Explorer se conseguir acessar estas opções:

- Fechar/Fechar como
- Abrir/Abrir com
- Imprimir
- Exportar/Importar
- Pesquisar
- Digitalizar

Você deve verificar se é possível:

- Modificar ou criar novos arquivos
- Criar symbolic links
- Obter acesso a áreas restritas
- Executar outros aplicativos

### Execução de comandos

Talvez **usando uma opção `Open with`**\*\* você possa abrir/executar algum tipo de shell.

#### Windows

Por exemplo, _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ encontre mais binários que podem ser usados para executar comandos (e realizar ações inesperadas) aqui: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ Mais informações aqui: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### Contornando restrições de caminho

- **Variáveis de ambiente**: Existem muitas variáveis de ambiente que apontam para algum caminho
- **Outros protocolos**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Atalhos**: CTRL+N (abrir uma nova sessão), CTRL+R (Executar comandos), CTRL+SHIFT+ESC (Task Manager), Windows+E (abrir o explorer), CTRL-B, CTRL-I (Favoritos), CTRL-H (Histórico), CTRL-L, CTRL-O (diálogo Arquivo/Abrir), CTRL-P (diálogo Imprimir), CTRL-S (Salvar como)
- Menu administrativo oculto: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **Caminhos UNC**: Caminhos para se conectar a pastas compartilhadas. Você deve tentar se conectar ao C$ da máquina local ("\\\127.0.0.1\c$\Windows\System32")
- **Mais caminhos UNC:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%              | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

### Saídas de Restricted Desktop (Citrix/RDS/VDI)

- **Pivotamento por caixas de diálogo**: Use os diálogos *Open/Save/Print-to-file* como uma versão simplificada do Explorer. Tente `*.*` / `*.exe` no campo de nome do arquivo, clique com o botão direito nas pastas para selecionar **Open in new window** e use **Properties → Open file location** para expandir a navegação.<sup>[[1]](#references)</sup>
- **Criar caminhos de execução a partir dos diálogos**: Crie um novo arquivo e renomeie-o para `.CMD` ou `.BAT`, ou crie um atalho apontando para `%WINDIR%\System32` (ou para um binário específico, como `%WINDIR%\System32\cmd.exe`).
- **Pivôs para iniciar um shell**: Se você puder navegar até `cmd.exe`, tente usar **arrastar e soltar** qualquer arquivo sobre ele para iniciar um prompt. Se o Task Manager estiver acessível (`CTRL+SHIFT+ESC`), use **Run new task**.
- **Bypass do Task Scheduler**: Se os shells interativos estiverem bloqueados, mas o agendamento for permitido, crie uma tarefa para executar `cmd.exe` (GUI `taskschd.msc` ou `schtasks.exe`).
- **Allowlists fracas**: Se a execução for permitida por **nome/extensão**, renomeie seu payload para um nome permitido. Se for permitida por **diretório**, copie o payload para uma pasta de programas permitida e execute-o nela.
- **Encontrar caminhos de staging com permissão de escrita**: Comece com `%TEMP%` e enumere pastas com permissão de escrita usando o Sysinternals AccessChk.
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **Próximo passo**: Se você obtiver um shell, consulte o checklist de Windows LPE:
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### Baixe Seus Binaries

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Editor de registro: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### Acessando o filesystem pelo browser

| PATH                | PATH              | PATH               | PATH               |
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
- Toggle Keys – Mantenha NUMLOCK pressionado por 5 segundos
- Filter Keys – Mantenha SHIFT direito pressionado por 12 segundos
- WINDOWS+F1 – Windows Search
- WINDOWS+D – Mostrar a Área de Trabalho
- WINDOWS+E – Iniciar o Windows Explorer
- WINDOWS+R – Executar
- WINDOWS+U – Central de Facilidade de Acesso
- WINDOWS+F – Pesquisar
- SHIFT+F10 – Menu de contexto
- CTRL+SHIFT+ESC – Gerenciador de Tarefas
- CTRL+ALT+DEL – Tela inicial nas versões mais recentes do Windows
- F1 – Ajuda F3 – Pesquisar
- F6 – Barra de endereço
- F11 – Alternar tela cheia no Internet Explorer
- CTRL+H – Histórico do Internet Explorer
- CTRL+T – Internet Explorer – Nova aba
- CTRL+N – Internet Explorer – Nova página
- CTRL+O – Abrir arquivo
- CTRL+S – Salvar CTRL+N – Novo RDP / Citrix

### Gestos

- Deslize do lado esquerdo para o direito para ver todas as janelas abertas, minimizando o app KIOSK e acessando diretamente todo o sistema operacional;
- Deslize do lado direito para o esquerdo para abrir a Central de Ações, minimizando o app KIOSK e acessando diretamente todo o sistema operacional;
- Deslize a partir da borda superior para tornar visível a barra de título de um app aberto no modo de tela cheia;
- Deslize para cima a partir da parte inferior para exibir a barra de tarefas em um app de tela cheia.

### Truques do Internet Explorer

#### 'Image Toolbar'

É uma barra de ferramentas que aparece no canto superior esquerdo da imagem quando ela é clicada. Você poderá salvar, imprimir, usar Mailto e abrir "My Pictures" no Explorer. O Kiosk precisa estar usando o Internet Explorer.

#### Shell Protocol

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

Consulte esta página para obter mais informações: [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)<sup>[[7]](#references)</sup>

## Truques de browsers

Versões de backup do iKat:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

Crie uma caixa de diálogo comum usando JavaScript e acesse o file explorer: `document.write('<input/type=file>')`<sup>[[2]](#references)</sup>\
Fonte: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### Gestos e botões

- Deslize para cima com quatro (ou cinco) dedos / Toque duas vezes no botão Home: Para visualizar a multitarefa e trocar de App
- Deslize para um lado ou para o outro com quatro ou cinco dedos: Para mudar para o próximo/último App
- Junte cinco dedos na tela / Toque no botão Home / Deslize rapidamente para cima com 1 dedo a partir da parte inferior da tela: Para acessar o Home
- Deslize 1 dedo a partir da parte inferior da tela por apenas 1–2 polegadas (lentamente): O dock aparecerá
- Deslize para baixo a partir da parte superior da tela com 1 dedo: Para visualizar suas notificações
- Deslize para baixo com 1 dedo a partir do canto superior direito da tela: Para ver a central de controle do iPad Pro
- Deslize 1 dedo a partir do lado esquerdo da tela por 1–2 polegadas: Para ver a visualização Today
- Deslize rapidamente 1 dedo do centro da tela para a direita ou esquerda: Para mudar para o próximo/último App
- Pressione e mantenha pressionado o botão On/**Off**/Sleep no canto superior direito do **iPad +** Mova o controle deslizante **power off** totalmente para a direita: Para desligar
- Pressione e mantenha pressionados o botão On/**Off**/Sleep no canto superior direito do **iPad e o botão Home por alguns segundos**: Para forçar um desligamento completo
- Pressione rapidamente o botão On/**Off**/Sleep no canto superior direito do **iPad e o botão Home**: Para fazer uma captura de tela, que aparecerá no canto inferior esquerdo da tela. Pressione ambos os botões ao mesmo tempo por um período muito curto; se você os mantiver pressionados por alguns segundos, será realizado um desligamento completo.<sup>[[3]](#references)</sup>

### Atalhos

Você deve ter um teclado de iPad ou um adaptador de teclado USB. Apenas os atalhos que podem ajudar a escapar do app serão mostrados aqui.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

| Key | Name         |
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

Estes atalhos servem para as configurações visuais e de som, dependendo do uso do iPad.

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | Diminuir o brilho da tela                                                     |
| F2       | Aumentar o brilho da tela                                                     |
| F7       | Voltar uma música                                                               |
| F8       | Reproduzir/pausar                                                               |
| F9       | Pular música                                                                    |
| F10      | Silenciar                                                                      |
| F11      | Diminuir o volume                                                              |
| F12      | Aumentar o volume                                                              |
| ⌘ Space  | Exibir uma lista de idiomas disponíveis; para escolher um, toque novamente na barra de espaço. |

#### Navegação no iPad

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | Ir para Home                                            |
| ⌘⇧H (Command-Shift-H)                              | Ir para Home                                            |
| ⌘ (Space)                                          | Abrir o Spotlight                                       |
| ⌘⇥ (Command-Tab)                                   | Listar os dez últimos apps usados                       |
| ⌘\~                                                | Ir para o último App                                    |
| ⌘⇧3 (Command-Shift-3)                              | Captura de tela (fica no canto inferior esquerdo para salvá-la ou executar uma ação) |
| ⌘⇧4                                                | Fazer uma captura de tela e abri-la no editor           |
| Pressione e mantenha ⌘                              | Listar os atalhos disponíveis para o App                |
| ⌘⌥D (Command-Option/Alt-D)                         | Exibir o dock                                           |
| ^⌥H (Control-Option-H)                             | Botão Home                                              |
| ^⌥H H (Control-Option-H-H)                         | Mostrar a barra de multitarefa                          |
| ^⌥I (Control-Option-i)                             | Seletor de itens                                        |
| Escape                                             | Botão Voltar                                            |
| → (Right arrow)                                    | Próximo item                                            |
| ← (Left arrow)                                     | Item anterior                                           |
| ↑↓ (Up arrow, Down arrow)                          | Tocar simultaneamente no item selecionado              |
| ⌥ ↓ (Option-Down arrow)                            | Rolar para baixo                                        |
| ⌥↑ (Option-Up arrow)                               | Rolar para cima                                         |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | Rolar para a esquerda ou direita                        |
| ^⌥S (Control-Option-S)                             | Ativar ou desativar a fala do VoiceOver                 |
| ⌘⇧⇥ (Command-Shift-Tab)                            | Mudar para o app anterior                               |
| ⌘⇥ (Command-Tab)                                   | Voltar ao app original                                  |
| ←+→, then Option + ← or Option+→                   | Navegar pelo Dock                                      |

#### Atalhos do Safari

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | Abrir localização                                |
| ⌘T                      | Abrir uma nova aba                               |
| ⌘W                      | Fechar a aba atual                               |
| ⌘R                      | Atualizar a aba atual                            |
| ⌘.                      | Parar de carregar a aba atual                    |
| ^⇥                      | Mudar para a próxima aba                         |
| ^⇧⇥ (Control-Shift-Tab) | Ir para a aba anterior                           |
| ⌘L                      | Selecionar o campo de texto/URL para modificá-lo |
| ⌘⇧T (Command-Shift-T)   | Abrir a última aba fechada (pode ser usado várias vezes) |
| ⌘\[                     | Voltar uma página no histórico de navegação      |
| ⌘]                      | Avançar uma página no histórico de navegação     |
| ⌘⇧R                     | Ativar o Reader Mode                             |

#### Atalhos do Mail

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | Abrir localização            |
| ⌘T                         | Abrir uma nova aba           |
| ⌘W                         | Fechar a aba atual           |
| ⌘R                         | Atualizar a aba atual        |
| ⌘.                         | Parar de carregar a aba atual |
| ⌘⌥F (Command-Option/Alt-F) | Pesquisar na sua caixa de correio |

## Referências

- [1] [Breaking Out of Citrix and other Restricted Desktop Environments](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [2] [Give me a browser, I'll give you a shell](https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0)
- [3] [6 only-for-iPad gestures you need to know](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [4] [iPad shortcuts guide](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [5] [Best iPad Keyboard Shortcuts](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [6] [iPad Keyboard Shortcuts](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)
- [7] [howtohaven.com - Show File Extensions In Windows Explorer](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

{{#include ../banners/hacktricks-training.md}}
