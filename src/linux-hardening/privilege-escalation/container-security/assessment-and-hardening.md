# Evaluering en verharding

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

'n Goeie container-evaluering moet twee parallelle vrae beantwoord. Eerstens, wat kan 'n aanvaller doen vanaf die huidige workload? Tweedens, watter operator-keuses het dit moontlik gemaak? Enumerasie-gereedskap help met die eerste vraag, en verhardingsriglyne help met die tweede. Om albei op een blad te hou maak die afdeling nuttiger as 'n veldverwysing eerder as net 'n katalogus van escape tricks.

## Enumerasie-gereedskap

'n Aantal gereedskap bly nuttig om vinnig 'n container-omgewing te karaktersiseer:

- `linpeas` kan baie container-aanwysers, gemonteerde sockets, capability sets, gevaarlike filesystems, en breakout hints identifiseer.
- `CDK` fokus spesifiek op container-omgewings en sluit enumerasie plus 'n paar geoutomatiseerde escape checks in.
- `amicontained` is liggewig en nuttig om container-beperkings, capabilities, namespace-eksponering, en waarskynlike breakout-klasse te identifiseer.
- `deepce` is nog 'n container-gefokusde enumerator met breakout-gefokusde checks.
- `grype` is nuttig wanneer die evaluering image-package kwetsbaarheidsoorsig insluit in plaas van slegs runtime escape analysis.

Die waarde van hierdie gereedskap is spoed en dekking, nie sekerheid nie. Hulle help om die rowwe houding vinnig te openbaar, maar die interessante bevindinge benodig steeds handmatige interpretasie teen die werklike runtime-, namespace-, capability- en mount-model.

## Verhardingsprioriteite

Die belangrikste verhardingsbeginsels is konseptueel eenvoudig, al verskil hul implementering tussen platforms. Vermy privileged containers. Vermy gemonteerde runtime sockets. Gee nie containers skryfbare host paths tensy daar 'n baie spesifieke rede is. Gebruik user namespaces of rootless execution waar dit prakties is. Verwyder alle capabilities en voeg slegs terug wat die workload werklik benodig. Hou seccomp, AppArmor, en SELinux geaktiveer in plaas daarvan om hulle uit te skakel om toepassings-kompatibiliteitsprobleme op te los. Beperk hulpbronne sodat 'n gekompromitteerde container nie maklik diens aan die host kan weier nie.

Image- en build-higiëne is net so belangrik as runtime-houding. Gebruik minimale images, herbou gereeld, skandeer dit, vereis provenance waar prakties, en hou geheime buite layers. 'n Container wat as non-root hardloop met 'n klein image en 'n noue syscall- en capability-oppervlak is baie makliker om te verdedig as 'n groot gemak-image wat as host-ekwivalente root hardloop met debugging-gereedskap vooraf geïnstalleer.

## Voorbeelde van hulpbronuitputting

Hulpbronbeheer is nie glansryk nie, maar dit is deel van container-sekuriteit omdat dit die blast radius van 'n kompromissie beperk. Sonder geheue-, CPU- of PID-limiete kan 'n eenvoudige shell genoeg wees om die host of aangrensende workloads te degradeer.

Voorbeelde van toetse wat die host raak:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Hierdie voorbeelde is nuttig omdat hulle wys dat nie elke gevaarlike container-uitkoms 'n duidelike "escape" is nie. Swak cgroup-limiete kan steeds code execution in werklike operasionele impak omskep.

## Verhardingsgereedskap

Vir Docker-sentriese omgewings bly `docker-bench-security` 'n nuttige basislyn vir gasheerkant-oudits omdat dit algemene konfigurasieprobleme teen wyd-erkende benchmarkriglyne nagaan:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Die tool is nie 'n plaasvervanger vir threat modeling nie, maar dit is steeds waardevol om sorgelose daemon-, mount-, network- en runtime-standaardinstellings te vind wat oor tyd ophoop.

## Kontroles

Gebruik hierdie as vinnige, eerste-deurloop kommando's tydens 'n assessering:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
- 'n root-proses met uitgebreide bevoegdhede en `Seccomp: 0` verdien onmiddellike aandag.
- Verdagte mounts en runtime sockets bied dikwels 'n vinniger pad na impak as enige kernel exploit.
- Die kombinasie van swak runtime-houding en swak hulpbronlimiete dui gewoonlik op 'n oorwegend permisiewe container-omgewing eerder as 'n enkele geïsoleerde fout.
{{#include ../../../banners/hacktricks-training.md}}
