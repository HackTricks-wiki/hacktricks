# Monitoramento de Integridade de Arquivos

{{#include ../../banners/hacktricks-training.md}}

## Baseline

Um baseline consiste em obter um snapshot de determinadas partes de um sistema para **compará-lo com um estado futuro e destacar alterações**.

Por exemplo, você pode calcular e armazenar o hash de cada arquivo do filesystem para descobrir quais arquivos foram modificados.\
Isso também pode ser feito com as contas de usuário criadas, os processos em execução, os serviços em execução e qualquer outra coisa que não deveria mudar muito, ou não mudar de forma alguma.

Um **baseline útil** geralmente armazena mais do que apenas um digest: permissões, proprietário, grupo, timestamps, inode, destino de symlink, ACLs e atributos estendidos selecionados também merecem ser monitorados. Do ponto de vista de attacker-hunting, isso ajuda a detectar **adulteração apenas de permissões**, **substituição atômica de arquivos** e **persistência por meio de arquivos de serviço/unit modificados**, mesmo quando o hash do conteúdo não é a primeira coisa que muda.

### Monitoramento de Integridade de Arquivos

File Integrity Monitoring (FIM) é uma técnica crítica de segurança que protege ambientes de TI e dados ao rastrear alterações em arquivos. Normalmente, combina:

1. **Comparação com o baseline:** Armazenar metadados e checksums criptográficos (preferencialmente `SHA-256` ou superior) para comparações futuras.
2. **Notificações em tempo real:** Inscrever-se em eventos de arquivos nativos do OS para saber **qual arquivo mudou, quando e, idealmente, qual processo/usuário o acessou**.
3. **Nova verificação periódica:** Reforçar a confiabilidade após reboots, eventos perdidos, indisponibilidade de agents ou atividade anti-forensics deliberada.

Para threat hunting, o FIM geralmente é mais útil quando focado em **paths de alto valor**, como:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- Units do `systemd`, locais de cron, materiais de SSH, módulos PAM, web roots
- Locais de persistência do Windows, binários de serviços, arquivos de tarefas agendadas, pastas de inicialização
- Camadas graváveis de containers e secrets/configuration montados via bind

## Backends em Tempo Real e Pontos Cegos

### Linux

O backend de coleta é importante:<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**: fáceis e comuns, mas os limites de watch podem ser esgotados e alguns casos específicos podem não ser detectados.
- **`auditd` / audit framework**: melhor quando você precisa saber **quem alterou o arquivo** (`auid`, processo, pid, executável).
- **`eBPF` / `kprobes`**: opções mais recentes usadas por stacks modernas de FIM para enriquecer eventos e reduzir parte dos problemas operacionais de deployments simples baseados em `inotify`.

Alguns problemas práticos:<sup>[[1]](#references)</sup>

- Se um programa **substitui** um arquivo usando `write temp -> rename`, monitorar o próprio arquivo pode deixar de ser útil. **Monitore o diretório pai**, não apenas o arquivo.
- Coletores baseados em `inotify` podem perder eventos ou apresentar degradação em **árvores de diretórios enormes**, **atividades com hard links** ou depois que um **arquivo monitorado é excluído**.
- Conjuntos de watch recursivos muito grandes podem falhar silenciosamente se `fs.inotify.max_user_watches`, `max_user_instances` ou `max_queued_events` forem muito baixos.
- Filesystems de rede geralmente são alvos ruins para FIM com monitoramento de baixo ruído.

Exemplo de baseline + verificação com AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Exemplo de configuração de FIM do `osquery` focada nos caminhos de persistência do atacante:<sup>[[1]](#references)</sup>
```json
{
"schedule": {
"fim": {
"query": "SELECT * FROM file_events;",
"interval": 300,
"removed": false
}
},
"file_paths": {
"etc": ["/etc/%%"],
"systemd": ["/etc/systemd/system/%%", "/usr/lib/systemd/system/%%"],
"ssh": ["/root/.ssh/%%", "/home/%/.ssh/%%"]
}
}
```
Se você precisar de **atribuição de processo**, em vez de apenas alterações no nível do caminho, prefira telemetria respaldada por auditoria, como `osquery` `process_file_events` ou o modo `whodata` do Wazuh.<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

No Windows, o FIM é mais eficaz quando você combina **change journals** com **telemetria de processo/arquivo de alta relevância**:

- O **NTFS USN Journal** fornece um log persistente das alterações de arquivos por volume.
- O **Sysmon Event ID 11** é útil para criação/sobrescrita de arquivos.
- O **Sysmon Event ID 2** ajuda a detectar **timestomping**.
- O **Sysmon Event ID 15** é útil para **named alternate data streams (ADS)**, como `Zone.Identifier` ou streams de payload ocultos.

Exemplos rápidos de triagem de USN:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Para ideias mais aprofundadas de anti-forensics relacionadas a **timestamp manipulation**, **ADS abuse** e **USN tampering**, consulte [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Contêineres

O FIM de contêineres frequentemente não identifica o caminho real de escrita. Com o Docker `overlay2`, as alterações são confirmadas na **camada superior gravável** (`upperdir`/`diff`) do contêiner, e não nas camadas somente leitura da imagem. Portanto:

- Monitorar apenas os caminhos **dentro** de um contêiner de curta duração pode não detectar alterações após a recriação do contêiner.
- Monitorar o **caminho no host** que dá suporte à camada gravável ou ao volume montado por bind relevante costuma ser mais útil.
- O FIM nas camadas da imagem é diferente do FIM no sistema de arquivos do contêiner em execução.

## Notas de Hunting Orientadas ao Atacante

- Acompanhe **definições de serviços** e **agendadores de tarefas** com o mesmo cuidado aplicado aos binários. Os atacantes frequentemente obtêm persistência modificando um arquivo de unit, uma entrada do cron ou um XML de tarefa, em vez de alterar o `/bin/sshd`.
- Um hash de conteúdo isolado é insuficiente. Muitos comprometimentos são inicialmente identificados por **alterações no owner/mode/xattr/ACL**.
- Se você suspeitar de uma intrusão madura, faça ambos: **FIM em tempo real** para detectar atividades recentes e uma **comparação com uma baseline offline** usando mídia confiável.
- Se o atacante tiver execução como root ou no kernel, presuma que o agente de FIM, seu banco de dados e até mesmo a fonte dos eventos podem ter sido adulterados. Armazene logs e baselines remotamente ou em mídia somente leitura sempre que possível.

## Ferramentas

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Referências

- [1] [Monitoramento da integridade de arquivos com osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: um caso de uso de monitoramento da integridade de arquivos (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Monitoramento da integridade de arquivos do Wazuh (modo Syscheck e whodata)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
