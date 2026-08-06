# Monitoramento da Integridade de Arquivos

{{#include ../../banners/hacktricks-training.md}}

## Baseline

Um baseline consiste em capturar um snapshot de certas partes de um sistema para **compará-lo com um estado futuro e destacar alterações**.

Por exemplo, você pode calcular e armazenar o hash de cada arquivo do filesystem para descobrir quais arquivos foram modificados.\
Isso também pode ser feito com as contas de usuário criadas, processos em execução, serviços em execução e qualquer outra coisa que não deveria mudar muito, ou nem mudar.

Um **baseline útil** normalmente armazena mais do que apenas um digest: permissões, proprietário, grupo, timestamps, inode, alvo de symlink, ACLs e atributos estendidos selecionados também vale a pena monitorar. Da perspectiva de caça a atacantes, isso ajuda a detectar **adulteração somente de permissões**, **substituição atômica de arquivos** e **persistência por meio de arquivos de serviço/unit modificados**, mesmo quando o hash do conteúdo não é a primeira coisa que muda.

### Monitoramento da Integridade de Arquivos

File Integrity Monitoring (FIM) é uma técnica crítica de segurança que protege ambientes de TI e dados rastreando alterações em arquivos. Normalmente, ele combina:

1. **Comparação com o baseline:** Armazene metadados e checksums criptográficos (prefira `SHA-256` ou melhor) para comparações futuras.
2. **Notificações em tempo real:** Inscreva-se nos eventos de arquivos nativos do OS para saber **qual arquivo mudou, quando e, idealmente, qual processo/usuário o acessou**.
3. **Nova varredura periódica:** Reforce a confiabilidade após reboots, eventos perdidos, indisponibilidade de agentes ou atividade anti-forense deliberada.

Para threat hunting, o FIM geralmente é mais útil quando focado em **paths de alto valor**, como:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- Units do `systemd`, localizações do cron, materiais de SSH, módulos PAM, web roots
- Localizações de persistência do Windows, binários de serviços, arquivos de tarefas agendadas, pastas de inicialização
- Camadas graváveis de containers e secrets/configuration montados por bind

## Backends em Tempo Real e Pontos Cegos

### Linux

O backend de coleta é importante:<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**: fáceis e comuns, mas os limites de watch podem ser esgotados e alguns casos extremos não são detectados.
- **`auditd` / framework de auditoria**: melhor quando você precisa saber **quem alterou o arquivo** (`auid`, processo, pid, executável).
- **`eBPF` / `kprobes`**: opções mais recentes usadas por stacks modernas de FIM para enriquecer eventos e reduzir parte dos problemas operacionais de deployments simples baseados em `inotify`.

Alguns problemas práticos:<sup>[[1]](#references)</sup>

- Se um programa **substitui** um arquivo com `write temp -> rename`, monitorar o próprio arquivo pode deixar de ser útil. **Monitore o diretório pai**, não apenas o arquivo.
- Coletores baseados em `inotify` podem perder eventos ou apresentar degradação em **árvores de diretórios enormes**, **atividade de hard links** ou após um **arquivo monitorado ser excluído**.
- Conjuntos muito grandes de watches recursivos podem falhar silenciosamente se `fs.inotify.max_user_watches`, `max_user_instances` ou `max_queued_events` forem muito baixos.
- Filesystems de rede geralmente são alvos ruins para FIM com monitoramento de baixo ruído.

Exemplo de baseline + verificação com AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Exemplo de configuração do `osquery` para FIM focada em caminhos de persistência do atacante:<sup>[[1]](#references)</sup>
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
Se você precisar de **atribuição de processo**, em vez de apenas alterações no nível do caminho, prefira telemetria baseada em auditoria, como `osquery` `process_file_events` ou o modo `whodata` do Wazuh.<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

No Windows, o FIM é mais robusto quando você combina **change journals** com **telemetria de processo/arquivo de alta sinalização**:

- O **NTFS USN Journal** fornece um log persistente, por volume, das alterações nos arquivos.
- O **Sysmon Event ID 11** é útil para criação/sobrescrita de arquivos.
- O **Sysmon Event ID 2** ajuda a detectar **timestomping**.
- O **Sysmon Event ID 15** é útil para **named alternate data streams (ADS)**, como `Zone.Identifier` ou streams de payload ocultos.

Exemplos rápidos de triagem do USN:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Para ideias mais aprofundadas de anti-forensics envolvendo **timestamp manipulation**, **ADS abuse** e **USN tampering**, consulte [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Contêineres

O FIM de contêineres frequentemente não identifica o caminho real de escrita. Com o Docker `overlay2`, as alterações são confirmadas na **camada gravável superior** do contêiner (`upperdir`/`diff`), e não nas camadas somente leitura da imagem. Portanto:

- Monitorar apenas caminhos **dentro** de um contêiner de curta duração pode não detectar alterações após a recriação do contêiner.
- Monitorar o **caminho no host** que sustenta a camada gravável ou o volume bind-mounted relevante costuma ser mais útil.
- O FIM nas camadas da imagem é diferente do FIM no sistema de arquivos do contêiner em execução.

## Notas de Hunting Orientadas ao Atacante

- Rastreie **definições de serviços** e **task schedulers** com o mesmo cuidado dedicado aos binários. Os atacantes frequentemente obtêm persistência modificando um unit file, uma entrada do cron ou um task XML, em vez de alterar `/bin/sshd`.
- Um hash de conteúdo, por si só, é insuficiente. Muitos comprometimentos aparecem primeiro como **alterações de owner/mode/xattr/ACL**.
- Se você suspeitar de uma intrusão madura, faça ambos: **FIM em tempo real** para atividades recentes e uma **comparação com uma baseline offline** usando mídia confiável.
- Se o atacante tiver acesso root ou execução no kernel, considere que o agente de FIM, o banco de dados e até mesmo a fonte dos eventos podem ser adulterados. Armazene logs e baselines remotamente ou em mídia somente leitura sempre que possível.

## Ferramentas

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Referências

- [1] [Monitoramento da integridade de arquivos com osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Rastreamento do Linux: um caso de uso de monitoramento da integridade de arquivos (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Monitoramento da integridade de arquivos do Wazuh (Syscheck e modo whodata)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}
