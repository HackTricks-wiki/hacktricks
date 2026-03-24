# Assessering en Verharding

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

'n Goeie container-assessering moet twee parallelle vrae beantwoord. Eerste, wat kan 'n aanvaller doen vanaf die huidige workload? Tweedens, watter operator-keuses het dit moontlik gemaak? Enumerasie-instrumente help met die eerste vraag, en verhardingsriglyne help met die tweede. Om albei op een blad te hou maak die afdeling meer nuttig as 'n veldverwysing eerder as net 'n katalogus van escape-tricks.

## Enumerasie-instrumente

'n Aantal gereedskap bly nuttig om vinnig 'n container-omgewing te karakteriseer:

- `linpeas` kan baie container-indikatore, gemonteerde sockets, capability sets, gevaarlike lêerstelsels en breakout hints identifiseer.
- `CDK` fokus spesifiek op container-omgewings en sluit enumerasie in plus sommige geoutomatiseerde escape checks.
- `amicontained` is liggewig en nuttig om container-restriksies, capabilities, namespace exposure en waarskynlike breakout-klasse te identifiseer.
- `deepce` is nog 'n container-gefokusde enumerator met breakout-georiënteerde kontroles.
- `grype` is nuttig wanneer die assessering image-package vulnerability review insluit in plaas van net runtime escape analysis.

Die waarde van hierdie gereedskap is spoed en dekking, nie sekerheid nie. Hulle help om die ruwe postuur vinnig te onthul, maar die interessante bevindinge benodig steeds handmatige interpretasie teenoor die werklike runtime-, namespace-, capability- en mount-model.

## Prioriteite vir Verharding

Die belangrikste verhardingsbeginsels is konseptueel eenvoudig alhoewel hul implementering per platform verskil. Vermy privileged containers. Vermy gemonteerde runtime sockets. Moet nie containers writable host paths gee tensy daar 'n baie spesifieke rede is nie. Gebruik user namespaces of rootless execution waar dit prakties is. Drop alle capabilities en voeg slegs terug wat die workload werklik benodig. Hou seccomp, AppArmor, en SELinux aangeskakel eerder as om hulle af te skakel om toepassing-kompatibiliteitsprobleme op te los. Beperk hulpbronne sodat 'n gekompromitteerde container nie sommer die diens aan die host kan weier nie.

Image- en build-higiëne is net so belangrik as runtime-postuur. Gebruik minimale images, bou gereeld weer, scan hulle, vereis provenance waar dit prakties is, en hou secrets uit lae. 'n Container wat as non-root loop met 'n klein image en 'n noue syscall- en capability-oppervlak is baie makliker om te verdedig as 'n groot convenience image wat as host-equivalent root loop met debugging-gereedskap vooraf geïnstalleer.

## Voorbeelde van Hulpbron-uitputting

Hulpbronkontroles is nie glansryk nie, maar hulle maak deel uit van container security omdat hulle die blast radius van 'n kompromie beperk. Sonder memory-, CPU- of PID-limiete kan 'n eenvoudige shell genoeg wees om die host of aangrensende workloads te degradeer.

Voorbeeld toetsies wat die gasheer kan beïnvloed:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Hierdie voorbeelde is nuttig omdat hulle aantoon dat nie elke gevaarlike container-uitkoms 'n skoon "escape" is nie. Swakke cgroup-limiete kan steeds code execution in werklike operasionele impak omskakel.

## Verhardingsgereedskap

Vir Docker-gesentreerde omgewings bly `docker-bench-security` 'n nuttige gasheer-kant oudit-basislyn omdat dit algemene konfigurasiekwessies teen wyd erkende benchmark-riglyne toets:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Die hulpmiddel is nie 'n plaasvervanger vir threat modeling nie, maar dit is steeds waardevol om sorgelose daemon, mount, network, en runtime defaults te vind wat mettertyd ophoop.

## Kontroles

Gebruik hierdie as vinnige eerste-kontrole-opdragte tydens 'n assessering:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Wat hier interessant is:

- 'n root-proses met uitgebreide bevoegdhede en `Seccomp: 0` verdien onmiddellike aandag.
- Verdagte mounts en runtime-sokette bied dikwels 'n vinniger pad na impak as enige kernel exploit.
- Die kombinasie van swak runtime-houding en swak hulpbronlimiete dui gewoonlik op 'n oor die algemeen permissiewe container-omgewing eerder as 'n enkele geïsoleerde fout.
{{#include ../../../banners/hacktricks-training.md}}
