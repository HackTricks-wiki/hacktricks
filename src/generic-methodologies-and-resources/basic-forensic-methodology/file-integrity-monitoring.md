# Monitoramento de Integridade de Arquivos

## Baseline

Um baseline consiste em obter um snapshot de determinadas partes de um sistema para **compará-lo com um estado futuro e destacar alterações**.

Por exemplo, você pode calcular e armazenar o hash de cada arquivo do sistema de arquivos para descobrir quais arquivos foram modificados.\
Isso também pode ser feito com as contas de usuário criadas, processos em execução, serviços em execução e qualquer outra coisa que não deveria mudar muito, ou de forma alguma.

Um **baseline útil** geralmente armazena mais do que apenas um digest: permissões, proprietário, grupo, timestamps, inode, destino de symlink, ACLs e atributos estendidos selecionados também valem a pena ser monitorados.<sup>[[4]](#references)</sup> Do ponto de vista da caça a atacantes, isso ajuda a detectar **adulteração somente de permissões**, **substituição atômica de arquivos** e **persistência via arquivos de serviço/unit modificados**, mesmo quando o hash do conteúdo não é a primeira coisa que muda.

### Monitoramento de Integridade de Arquivos

O File Integrity Monitoring (FIM) é uma técnica de segurança crítica que protege ambientes de TI e dados rastreando alterações em arquivos. Normalmente, ele combina:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Comparação com o baseline:** Armazenar metadados e checksums criptográficos (preferencialmente `SHA-256` ou superior) para comparações futuras.
2. **Notificações em tempo real:** Inscrever-se em eventos de arquivos nativos do sistema operacional para saber **qual arquivo mudou, quando e, idealmente, qual processo/usuário o acessou**.
3. **Nova verificação periódica:** Reforçar a confiabilidade após reinicializações, eventos perdidos, indisponibilidade do agente ou atividade anti-forense deliberada.

Para threat hunting, o FIM geralmente é mais útil quando focado em **paths de alto valor**, como:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- units do `systemd`, locais de cron, material de SSH, módulos PAM, web roots
- Locais de persistência do Windows, binários de serviços, arquivos de tarefas agendadas, pastas de inicialização
- Camadas graváveis de containers e secrets/configuration montados via bind

## Backends em Tempo Real e Pontos Cegos

### Linux

O backend de coleta é importante:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: fáceis e comuns, mas os limites de watch podem ser esgotados e alguns edge cases não são detectados.
- **`auditd` / audit framework**: melhor quando você precisa saber **quem alterou o arquivo** (login UID, ID do processo e nome do processo).
- **`eBPF` / `kprobes`**: opções mais recentes usadas por stacks modernas de FIM para enriquecer eventos e reduzir parte dos problemas operacionais de deployments baseados apenas em `inotify`.

Alguns problemas práticos:<sup>[[1]](#references)[[5]](#references)</sup>

- Se um programa **substitui** um arquivo com `write temp -> rename`, monitorar o próprio arquivo pode deixar de ser útil. **Monitore o diretório pai**, não apenas o arquivo.
- Collectors baseados em `inotify` podem perder eventos ou apresentar degradação em **árvores de diretórios enormes**, **atividade de hard links** ou depois que um **arquivo monitorado é excluído**.
- Conjuntos de watch recursivos muito grandes podem falhar silenciosamente se `fs.inotify.max_user_watches`, `max_user_instances` ou `max_queued_events` forem muito baixos.
- No monitoramento baseado em `inotify`, filesystems de rede são um ponto cego, pois alterações remotas não são reportadas.

Exemplo de baseline + verificação com AIDE:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Exemplo de configuração de FIM do `osquery` focada em caminhos de persistência de attacker:<sup>[[1]](#references)</sup>
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
Se você precisar de **atribuição de processo** em vez de apenas alterações em nível de caminho, prefira telemetria respaldada por auditoria, como `osquery` `process_file_events` ou o modo `whodata` do Wazuh.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

### Windows

No Windows, o FIM é mais eficaz quando você combina **diários de alterações** com **telemetria de processo/arquivo de alto sinal**:<sup>[[6]](#references)[[7]](#references)</sup>

- O **NTFS USN Journal** fornece um registro persistente das alterações de arquivos por volume.
- O **Sysmon Event ID 11** é útil para criação/sobrescrita de arquivos.
- O **Sysmon Event ID 2** ajuda a detectar **timestomping**.
- O **Sysmon Event ID 15** é útil para **named alternate data streams (ADS)**, como `Zone.Identifier` ou streams de payload ocultos.

Exemplos rápidos de triagem do USN:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Para obter ideias anti-forensics mais aprofundadas sobre **manipulação de timestamps**, **abuso de ADS** e **adulteração de USN**, consulte [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Contêineres

O FIM de contêineres frequentemente não detecta o caminho real de gravação. Com o Docker `overlay2`, o sistema de arquivos do contêiner combina camadas `lowerdir` somente leitura da imagem com uma **camada superior** gravável (`upperdir`/`diff`), e as gravações em arquivos da imagem são copiadas para essa camada superior.<sup>[[8]](#references)</sup> Portanto:

- Monitorar apenas os caminhos **dentro** de um contêiner de curta duração pode não detectar alterações após a recriação do contêiner.
- Monitorar o **caminho no host** que serve de base para a camada gravável ou o volume relevante montado via bind costuma ser mais útil.
- O FIM nas camadas da imagem é diferente do FIM no sistema de arquivos do contêiner em execução.

## Notas de Hunting Orientadas ao Atacante

- Acompanhe **definições de serviços** e **agendadores de tarefas** com o mesmo cuidado dedicado aos binários. Os atacantes frequentemente obtêm persistência modificando um arquivo de unidade, uma entrada do cron ou um XML de tarefa, em vez de alterar `/bin/sshd`.
- Um hash de conteúdo, por si só, é insuficiente. Muitos comprometimentos aparecem primeiro como **alterações no proprietário/modo/xattr/ACL**.
- Se você suspeitar de uma intrusão madura, faça ambos: **FIM em tempo real** para detectar atividades recentes e uma **comparação com um baseline offline** usando mídia confiável.
- Se o atacante tiver execução como root ou no kernel, considere o agente de FIM e seu banco de dados não confiáveis. Armazene os logs e os baselines remotamente ou em mídia somente leitura sempre que possível.<sup>[[4]](#references)</sup>

## Ferramentas

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Módulo de Integridade de Arquivos do Elastic Auditbeat](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [Monitoramento da integridade de arquivos com osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Rastreamento do Linux: um caso de uso de monitoramento da integridade de arquivos (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Monitoramento da integridade de arquivos do Wazuh (modo Syscheck e whodata)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [Manual do AIDE, versão 0.16.2](https://aide.github.io/doc/)
- [5] [Página do manual do Linux inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [Driver de armazenamento OverlayFS](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Configurações avançadas do Wazuh FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
{{#include ../../banners/hacktricks-training.md}}
