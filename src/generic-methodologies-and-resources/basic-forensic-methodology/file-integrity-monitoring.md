# Monitoramento de Integridade de Arquivos

{{#include ../../banners/hacktricks-training.md}}

## Linha de base

Uma linha de base consiste em tirar um snapshot de determinadas partes de um sistema para **compará-lo com um estado futuro e destacar alterações**.

Por exemplo, você pode calcular e armazenar o hash de cada arquivo do sistema de arquivos para descobrir quais arquivos foram modificados.\
Isso também pode ser feito com as contas de usuário criadas, processos em execução, serviços em execução e qualquer outra coisa que não deveria mudar muito, ou nem mudar.

Uma **linha de base útil** geralmente armazena mais do que apenas um digest: permissões, proprietário, grupo, timestamps, inode, destino de symlink, ACLs e atributos estendidos selecionados também valem a pena ser monitorados.<sup>[[4]](#references)</sup> Da perspectiva de caça a atacantes, isso ajuda a detectar **adulteração apenas de permissões**, **substituição atômica de arquivos** e **persistência por meio de arquivos de serviço/unit modificados**, mesmo quando o hash do conteúdo não é a primeira coisa que muda.

### Monitoramento de Integridade de Arquivos

O File Integrity Monitoring (FIM) é uma técnica de segurança crítica que protege ambientes de TI e dados ao monitorar alterações em arquivos. Ele geralmente combina:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Comparação com a linha de base:** Armazene metadados e checksums criptográficos (prefira `SHA-256` ou superior) para comparações futuras.
2. **Notificações em tempo real:** Inscreva-se nos eventos de arquivos nativos do sistema operacional para saber **qual arquivo mudou, quando e, idealmente, qual processo/usuário o acessou**.
3. **Nova verificação periódica:** Restabeleça a confiança após reinicializações, eventos perdidos, indisponibilidade do agente ou atividade anti-forense deliberada.

Para threat hunting, o FIM geralmente é mais útil quando focado em **caminhos de alto valor**, como:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- Units do `systemd`, locais de cron, material de SSH, módulos PAM, raízes web
- Locais de persistência do Windows, binários de serviços, arquivos de tarefas agendadas, pastas de inicialização
- Camadas graváveis de containers e secrets/configuration montados por bind

## Backends em Tempo Real e Pontos Cegos

### Linux

O backend de coleta é importante:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: fáceis e comuns, mas os limites de watch podem ser esgotados e alguns casos extremos não são detectados.
- **`auditd` / framework de auditoria**: melhor quando você precisa saber **quem alterou o arquivo** (UID de login, ID do processo e nome do processo).
- **`eBPF` / `kprobes`**: opções mais recentes usadas por stacks modernas de FIM para enriquecer eventos e reduzir parte dos problemas operacionais de implementações simples baseadas em `inotify`.

Alguns problemas práticos:<sup>[[1]](#references)[[5]](#references)</sup>

- Se um programa **substitui** um arquivo com `write temp -> rename`, monitorar o próprio arquivo pode deixar de ser útil. **Monitore o diretório pai**, não apenas o arquivo.
- Coletores baseados em `inotify` podem perder eventos ou apresentar degradação em **árvores de diretórios enormes**, **atividades com hard links** ou depois que um **arquivo monitorado é excluído**.
- Conjuntos de watch recursivos muito grandes podem falhar silenciosamente se `fs.inotify.max_user_watches`, `max_user_instances` ou `max_queued_events` forem muito baixos.
- No monitoramento baseado em `inotify`, sistemas de arquivos de rede são um ponto cego porque alterações remotas não são reportadas.

Exemplo de linha de base + verificação com AIDE:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Exemplo de configuração do FIM do `osquery` com foco nos caminhos de persistência do atacante:<sup>[[1]](#references)</sup>
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
Se você precisar de **atribuição de processo**, em vez de apenas alterações no nível do caminho, prefira telemetria respaldada por auditoria, como `osquery` `process_file_events` ou o modo `whodata` do Wazuh.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

#### `io_uring`: a telemetria de syscall não é FIM

No Linux moderno, monitorar `openat(2)`, `write(2)` ou outros pontos de entrada de syscall **não equivale a monitorar a operação resultante no sistema de arquivos**. A prova de conceito **Curing** de 2025 enfileirou solicitações de arquivos e rede por meio do `io_uring`, fazendo com que produtos ou políticas vinculados apenas às entradas de syscall correspondentes por operação perdessem a telemetria do processo. Nos mesmos testes, um componente de FIM com escopo de caminho ainda observou modificações em arquivos, mostrando que isso é um **ponto cego na localização do hook**, não um bypass de permissões nem uma forma de derrotar todo backend de FIM.<sup>[[10]](#references)</sup>

Ao validar um sensor, modifique o mesmo canary por vários caminhos: `write` normal, `mmap` + `msync`, `truncate`, `sendfile`/`copy_file_range`, substituição atômica e `io_uring`. Verifique não apenas se o drift do hash final foi detectado, mas também se o evento preserva o processo responsável, o container/cgroup, o caminho visível no namespace, o inode e o par de renomeação. Um evento em tempo real ausente, seguido por uma divergência na verificação periódica, deve ser tratado como **perda de telemetria**, não como uma alteração rotineira inexplicada.<sup>[[10]](#references)[[11]](#references)</sup>

Para monitoramento baseado em eBPF, prefira pontos comuns de enforcement do kernel em vez de uma lista de probes de entrada de syscall. Por exemplo, a política de acesso a arquivos do Tetragon usa `security_file_permission` para abranger I/O comum, `sendfile`, `copy_file_range`, AIO e `io_uring`; ela cobre mapeamentos de memória separadamente com `security_mmap_file` e alterações de tamanho com `security_path_truncate`. Isso também ilustra por que um único hook raramente oferece cobertura completa.<sup>[[11]](#references)</sup>

### Windows

No Windows, o FIM é mais forte quando você combina **change journals** com **telemetria de processo/arquivo de alto sinal**:<sup>[[6]](#references)[[7]](#references)</sup>

- O **NTFS USN Journal** fornece um log persistente, por volume, das alterações em arquivos.
- O **Sysmon Event ID 11** é útil para criação/sobrescrita de arquivos.
- O **Sysmon Event ID 2** ajuda a detectar **timestomping**.
- O **Sysmon Event ID 15** é útil para **named alternate data streams (ADS)**, como `Zone.Identifier` ou streams de payload ocultos.

Exemplos rápidos de triagem do USN:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Para obter ideias mais aprofundadas de anti-forensics relacionadas à **timestamp manipulation**, **ADS abuse** e **USN tampering**, consulte [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Containers

O FIM de containers frequentemente não identifica o caminho real de gravação. Com o Docker `overlay2`, o sistema de arquivos do container combina camadas `lowerdir` somente leitura da imagem com uma **camada superior** gravável (`upperdir`/`diff`), e as gravações em arquivos da imagem são copiadas para essa camada superior.<sup>[[8]](#references)</sup> Portanto:

- Monitorar apenas caminhos **dentro** de um container de curta duração pode não detectar alterações depois que o container é recriado.
- Monitorar o **caminho no host** que sustenta a camada gravável ou o volume relevante montado via bind geralmente é mais útil.
- O FIM nas camadas da imagem é diferente do FIM no sistema de arquivos do container em execução.

## Notas de Hunting Orientadas ao Atacante

- Rastreie **definições de serviços** e **agendadores de tarefas** com o mesmo cuidado que os binários. Os atacantes frequentemente obtêm persistência modificando um arquivo de unidade, uma entrada do cron ou um XML de tarefa, em vez de alterar `/bin/sshd`.
- Um hash de conteúdo, por si só, é insuficiente. Muitos comprometimentos aparecem primeiro como **alterações de owner/mode/xattr/ACL**.
- Se você suspeitar de uma intrusão sofisticada, faça ambos: **FIM em tempo real** para atividade recente e uma **comparação com uma baseline offline** a partir de mídia confiável.
- Se o atacante tiver execução como root ou no kernel, considere o agente de FIM e seu banco de dados não confiáveis. Armazene logs e baselines remotamente ou em mídia somente leitura sempre que possível.<sup>[[4]](#references)</sup>

## Ferramentas

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [Monitoramento da integridade de arquivos com osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Rastreamento do Linux: um caso de uso de monitoramento da integridade de arquivos (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Monitoramento da integridade de arquivos do Wazuh (modo Syscheck e whodata)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [Manual do AIDE versão 0.16.2](https://aide.github.io/doc/)
- [5] [Página do manual do Linux inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [Driver de armazenamento OverlayFS](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Configurações avançadas do Wazuh FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
- [10] [Rootkit io_uring contorna ferramentas de segurança do Linux (ARMO)](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)
- [11] [Acesso a nomes de arquivos: cobrindo caminhos síncronos, assíncronos, mapeados e de truncamento (Tetragon)](https://tetragon.io/docs/use-cases/filename-access/)
{{#include ../../banners/hacktricks-training.md}}
