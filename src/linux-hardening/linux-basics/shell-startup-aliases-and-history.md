# Inicialização do Shell, Aliases e Histórico

{{#include ../../banners/hacktricks-training.md}}

Um comando do shell pode se comportar de forma diferente do executável com o mesmo nome se um alias, uma função, um arquivo de inicialização ou uma variável de ambiente alterar sua execução. Verifique esses elementos antes de confiar na saída de um comando ou presumir que um script usa o mesmo PATH de uma sessão interativa.

## Inspecionar o shell atual

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` e `command -V` revelam se um nome corresponde a um alias, uma função, um builtin ou um arquivo. `command -v` e `which` podem apresentar resultados diferentes para aliases e funções. O histórico do shell pode expor comandos ou credenciais, mas pode estar incompleto, desativado ou permanecer na memória até o encerramento da sessão.

## Revisar arquivos de inicialização e histórico

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Um arquivo de inicialização gravável pelo usuário pode executar comandos na próxima vez que um shell for iniciado. Um arquivo de inicialização global ou o arquivo de inicialização de um usuário privilegiado é mais sensível se uma conta com menos privilégios puder modificá-lo. O Bash não interativo também pode ler o arquivo especificado por `BASH_ENV`; a página sobre [variáveis de ambiente](linux-environment-variables.md#bash_env--env) explica esse comportamento e outros hooks de interpretadores. Verifique quais arquivos o shell realmente lê em sessões de login, interativas e não interativas antes de afirmar que existe um caminho de persistência.

Inspecione também os arquivos incluídos por um arquivo de inicialização global. Por exemplo, um `source /opt/app/venv/bin/activate` literal em `/etc/bash.bashrc` executa o arquivo de ativação como código de shell quando um shell realmente lê esse arquivo de inicialização. Revise o arquivo de ativação, as permissões do symlink e dos diretórios-pai, e as ACLs; um usuário com menos privilégios só pode afetar um shell privilegiado se esse shell ou uma tarefa privilegiada incluir o arquivo posteriormente. Se o acesso de gravação depender de `sudoedit`, primeiro verifique a regra exata do sudoers e o pacote sudo instalado com patches do fornecedor; uma string de versão upstream, por si só, não comprova a [exposição à injeção de argumentos no sudoedit](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Verifique o histórico, os dotfiles e os backups em busca de segredos, conforme descrito em [usuários e sessões](../user-information/user-and-session-triage.md). Se um script privilegiado resolver comandos pelo nome, combine essa análise com as [orientações sobre sequestro de PATH](linux-environment-variables.md#path).
{{#include ../../banners/hacktricks-training.md}}
