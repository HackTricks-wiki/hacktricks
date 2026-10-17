# Inicialização do Shell, Aliases e Histórico

{{#include ../../banners/hacktricks-training.md}}

Um comando do shell pode se comportar de forma diferente do executável com o mesmo nome se um alias, uma função, um arquivo de inicialização ou uma variável de ambiente alterar sua execução. Verifique esses itens antes de confiar na saída de um comando ou presumir que um script usa o mesmo PATH de uma sessão interativa.

## Inspecionar o shell atual

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` e `command -V` revelam se um nome é resolvido como alias, função, builtin ou arquivo. `command -v` e `which` podem apresentar resultados diferentes para aliases e funções. O histórico do shell pode expor comandos ou credenciais, mas pode estar incompleto, desativado ou armazenado na memória até o encerramento da sessão.

## Revise os arquivos de inicialização e histórico

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

Um arquivo de inicialização gravável pelo usuário pode executar comandos na próxima inicialização do shell. Um arquivo de inicialização global ou o arquivo de inicialização de um usuário privilegiado é mais sensível se uma conta com menos privilégios puder modificá-lo. O Bash não interativo também pode ler o arquivo indicado por `BASH_ENV`; a página sobre [variáveis de ambiente](linux-environment-variables.md#bash_env--env) explica esse comportamento e outros hooks de interpretador. Verifique quais arquivos o shell real lê em sessões de login, interativas e não interativas antes de afirmar que existe um caminho de persistência.

Inspecione também os arquivos incluídos por um arquivo de inicialização global. Por exemplo, um `source /opt/app/venv/bin/activate` literal em `/etc/bash.bashrc` executa o arquivo de ativação como código de shell quando um shell realmente lê esse arquivo de inicialização. Revise o arquivo de ativação, as permissões do link simbólico e dos diretórios pai, e as ACLs; um usuário com menos privilégios só pode afetar um shell privilegiado se esse shell ou uma tarefa privilegiada incluir o arquivo posteriormente. Se o acesso de escrita depender de `sudoedit`, verifique primeiro a regra exata do sudoers e o pacote do sudo instalado com os patches do fornecedor; apenas a string da versão upstream não comprova [exposição a injeção de argumentos do sudoedit](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands).

Verifique o histórico, os dotfiles e os backups em busca de segredos, conforme descrito em [usuários e sessões](../user-information/user-and-session-triage.md). Se um script privilegiado resolver comandos pelo nome, combine esta análise com as [orientações sobre sequestro de PATH](linux-environment-variables.md#path).

## Redirecionamento da inicialização do Zsh e arquivos compilados

Com as configurações padrão de `RCS`, o zsh lê `$ZDOTDIR/.zshenv` antes das invocações normais, incluindo `zsh -c` e scripts; se `ZDOTDIR` não estiver definido, usa `$HOME`. Quando um executor de comandos aceita um mapa de ambiente, teste se ele encaminha qualquer uma dessas variáveis para um processo privilegiado do zsh. Um `.zshenv` gravável pode então ser executado **antes** do corpo do comando que o executor verifica ou permite por allowlist. Isso exige que o processo privilegiado herde o diretório redirecionado; `zsh -f` ignora os arquivos de inicialização do usuário, mas não o `zshenv` global (geralmente `/etc/zshenv`, mas os caminhos variam entre distribuições). A [página sobre injeção de zsh no macOS](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir) contém um exemplo mínimo de `ZDOTDIR`.<sup>[[1]](#references)[[2]](#references)</sup>

Um `.zshenv.zwc` ou `.zshrc.zwc` válido e mais recente é executado no lugar do arquivo de inicialização em texto simples correspondente. Se você puder gravar no diretório de inicialização, compilar um arquivo modificado e depois restaurar um arquivo em texto simples aparentemente inofensivo pode deixar código executável na cópia compilada. Isso é ofuscação, não criptografia. O teste descartável abaixo mostra por que inspecionar apenas o arquivo de texto não é suficiente; ele não afeta um diretório home real.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```bash
lab=$(mktemp -d)
printf '%s\n' 'print -r -- compiled > "$ZDOTDIR/result"' > "$lab/.zshenv"
zsh -f -c 'zcompile -R "$1"' _ "$lab/.zshenv"
printf '%s\n' 'print -r -- plaintext > "$ZDOTDIR/result"' > "$lab/.zshenv"
touch -d '2 minutes ago' "$lab/.zshenv"  # ensure the .zwc is newer
ZDOTDIR="$lab" zsh -c :
cat "$lab/result"  # compiled
zsh -f -c 'zcompile -t "$1"' _ "$lab/.zshenv.zwc"
```

Para um alvo real, determine o `ZDOTDIR`/`HOME` efetivo, inspecione os arquivos de texto e `.zwc` e verifique os horários, a propriedade e se os diretórios-pai permitem gravação. Para que um arquivo `.zwc` tenha precedência, ele deve corresponder ao arquivo de origem e ser mais recente.<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Arquivos de inicialização e encerramento do Zsh](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Aviso sobre injeção no ambiente de inicialização do shell](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Comandos internos do shell Zsh: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [O .zshrc.zwc que você esqueceu de verificar](https://dfir.ch/posts/compiled_zsh/)
{{#include ../../banners/hacktricks-training.md}}
