# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## Linha de base

Uma linha de base consiste em tirar um snapshot de certas partes de um sistema para **compará-la com um estado futuro e evidenciar mudanças**.

Por exemplo, você pode calcular e armazenar o hash de cada arquivo do filesystem para poder descobrir quais arquivos foram modificados.\
Isso também pode ser feito com as contas de usuário criadas, processos em execução, serviços em execução e qualquer outra coisa que não deva mudar muito, ou de todo.

Uma **linha de base útil** normalmente armazena mais do que apenas um digest: permissões, owner, group, timestamps, inode, symlink target, ACLs e atributos estendidos selecionados também valem a pena serem rastreados. Do ponto de vista de attacker-hunting, isso ajuda a detectar **permission-only tampering**, **atomic file replacement**, e **persistence via modified service/unit files** mesmo quando o hash do conteúdo não é a primeira coisa que muda.

### File Integrity Monitoring

File Integrity Monitoring (FIM) é uma técnica crítica de segurança que protege ambientes de TI e dados rastreando mudanças em arquivos. Geralmente combina:

1. **Baseline comparison:** Armazenar metadata e checksums criptográficos (prefira `SHA-256` ou superior) para comparações futuras.
2. **Notificações em tempo real:** Assinar eventos de arquivo nativos do OS para saber **qual arquivo mudou, quando, e idealmente qual processo/usuário o tocou**.
3. **Periodic re-scan:** Reconstruir confiança após reboots, eventos perdidos, falhas do agent, ou atividade anti-forense deliberada.

Para threat hunting, FIM costuma ser mais útil quando focado em **high-value paths** tais como:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers and bind-mounted secrets/configuration

## Real-Time Backends & Blind Spots

### Linux

O backend de coleta importa:

- **`inotify` / `fsnotify`**: fácil e comum, mas os limites de watch podem ser esgotados e alguns edge cases são perdidos.
- **`auditd` / audit framework**: melhor quando você precisa de **who changed the file** (`auid`, process, pid, executable).
- **`eBPF` / `kprobes`**: opções mais novas usadas por stacks FIM modernos para enriquecer eventos e reduzir parte da dor operacional de deployments simples com `inotify`.

Alguns problemas práticos:

- Se um programa **substitui** um arquivo com `write temp -> rename`, observar o próprio arquivo pode parar de ser útil. **Observe o diretório pai**, não apenas o arquivo.
- Coletores baseados em `inotify` podem perder eventos ou degradar em árvores de diretório enormes, atividade de hard-link, ou após um watched file ser deletado.
- Conjuntos de watch recursivos muito grandes podem falhar silenciosamente se `fs.inotify.max_user_watches`, `max_user_instances`, ou `max_queued_events` estiverem muito baixos.
- Network filesystems geralmente são alvos ruins para FIM quando se busca monitoramento com baixo ruído.

Exemplo de linha de base + verificação com AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Exemplo de configuração FIM do `osquery` focada em caminhos de persistência do atacante:
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
Se você precisar de **atribuição de processo** em vez de apenas alterações ao nível de caminho, prefira telemetria respaldada por auditoria, como `osquery` `process_file_events` ou o modo `whodata` do Wazuh.

### Windows

No Windows, o FIM é mais eficaz quando você combina **registros de alteração** com **telemetria de processo/arquivo de alto sinal**:

- **NTFS USN Journal** fornece um registro persistente por volume das alterações de arquivos.
- **Sysmon Event ID 11** é útil para criação/sobrescrita de arquivos.
- **Sysmon Event ID 2** ajuda a detectar **timestomping**.
- **Sysmon Event ID 15** é útil para **named alternate data streams (ADS)** tais como `Zone.Identifier` ou fluxos de payload ocultos.

Quick USN triage examples:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Para ideias anti-forenses mais avançadas sobre **timestamp manipulation**, **ADS abuse**, e **USN tampering**, consulte [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Contêineres

O FIM de contêiner frequentemente perde o caminho de escrita real. Com Docker `overlay2`, as alterações são gravadas na **camada superior gravável** do contêiner (`upperdir`/`diff`), não nas camadas de imagem somente leitura. Portanto:

- Monitorar apenas caminhos de **dentro** de um contêiner de curta duração pode deixar passar alterações após o contêiner ser recriado.
- Monitorar o **caminho do host** que dá suporte à camada gravável ou o volume bind-mounted relevante costuma ser mais útil.
- O FIM em camadas de imagem é diferente do FIM no sistema de arquivos do contêiner em execução.

## Notas de Hunting Orientadas ao Atacante

- Acompanhe **definições de serviço** e **agendadores de tarefas** com a mesma atenção que os binários. Atacantes frequentemente conseguem persistência modificando um arquivo de unidade, uma entrada do cron ou um XML de tarefa em vez de mexer em `/bin/sshd`.
- Um hash de conteúdo sozinho é insuficiente. Muitos comprometimentos aparecem primeiro como **owner/mode/xattr/ACL drift**.
- Se suspeitar de uma intrusão madura, faça ambos: **FIM em tempo real** para atividade recente e uma **comparação de baseline a frio** a partir de mídias confiáveis.
- Se o atacante tiver execução root ou no kernel, presuma que o agente FIM, seu banco de dados e até a fonte de eventos podem ser adulterados. Armazene logs e baselines remotamente ou em mídia somente leitura sempre que possível.

## Ferramentas

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Referências

- [https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)

{{#include ../../banners/hacktricks-training.md}}
