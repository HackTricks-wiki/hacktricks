# Assessering en Verharding

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

'n Goeie container-assessering moet twee parallelle vrae beantwoord. Eerstens, wat kan 'n attacker doen vanaf die huidige workload? Tweedens, watter operateurkeuses het dit moontlik gemaak? Opsporingsgereedskap help met die eerste vraag, en verhardingsriglyne help met die tweede. Om beide op een blad te hou maak die afdeling meer nuttig as 'n veldverwysing eerder as net 'n katalogus van escape tricks.

## Opsporingsgereedskap

'n Aantal gereedskap bly nuttig om vinnig 'n container-omgewing te karakteriseer:

- `linpeas` kan baie container-aanwysers identifiseer, aangemonteerde sockets, capability sets, gevaarlike filesystems, en breakout hints.
- `CDK` fokus spesifiek op container-omgewings en sluit enumerasie plus sommige geoutomatiseerde escape checks in.
- `amicontained` is liggewig en nuttig om container-restrictions, capabilities, namespace exposure, en waarskynlike breakout-klasses te identifiseer.
- `deepce` is nog 'n container-focused enumerator met breakout-oriented checks.
- `grype` is nuttig wanneer die assessering image-package vulnerability review insluit in plaas van slegs runtime escape-analise.

Die waarde van hierdie gereedskap is spoed en dekking, nie sekerheid nie. Hulle help om vinnig die ruwe postuur te openbaar, maar die interessante bevindinge benodig steeds handmatige interpretasie teen die werklike runtime-, namespace-, capability- en mount-model.

## Prioriteite vir Verharding

Die belangrikste verhardingsbeginsels is konseptueel eenvoudig alhoewel hul implementering per platform verskil. Vermy privileged containers. Vermy mounted runtime sockets. Moet nie containers writable host paths gee tensy daar 'n baie spesifieke rede is nie. Gebruik user namespaces of rootless execution waar dit prakties moontlik is. Verwyder alle capabilities en voeg net die een terug wat die workload werklik nodig het. Hou seccomp, AppArmor, en SELinux geaktiveer eerder as om hulle uit te skakel om toepassingskompatibiliteitsprobleme op te los. Beperk hulpbronne sodat 'n gekompromitteerde container nie maklik diens aan die host kan weier nie.

Image- en build-higiëne doen net soveel saak as runtime-houding. Gebruik minimale images, bou gereeld weer, scan hulle, vereis provenance waar prakties, en hou secrets uit van lae. 'n Container wat as non-root hardloop met 'n klein image en 'n noue syscall- en capability-oppervlak is baie makliker om te verdedig as 'n groot convenience image wat as host-equivalent root hardloop met debugging tools vooraf geïnstalleer.

## Voorbeelde van Hulpbron-uitputting

Hulpbronbeheer is nie glansryk nie, maar dit is deel van container security omdat dit die omvang van skade by 'n kompromittering beperk. Sonder memory-, CPU- of PID-limiete kan 'n eenvoudige shell genoeg wees om die host of aangrensende workloads te degradeer.

Voorbeeld toetse wat die host kan beïnvloed:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Hierdie voorbeelde is nuttig omdat hulle toon dat nie elke gevaarlike container-uitkoms 'n netjiese "escape" is nie. Swakker cgroup-limiete kan steeds code execution in werklike operasionele impak omskep.

## Verhardingsgereedskap

Vir Docker-sentriese omgewings bly `docker-bench-security` 'n nuttige gasheerkant-oudit-basislyn, omdat dit algemene konfigurasieprobleme teenoor wyd erkende benchmark-riglyne kontroleer:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Die hulpmiddel is nie 'n plaasvervanger vir threat modeling nie, maar dit is steeds waardevol om slordige daemon-, mount-, network- en runtime-standaardinstellings te vind wat oor tyd ophoop.

## Checks

Gebruik hierdie as vinnige eerste-deurloop-kommando's tydens beoordeling:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
- ’n root-proses met uitgebreide bevoegdhede en `Seccomp: 0` verdien onmiddellike aandag.
- Verdagte mounts en runtime sockets bied dikwels 'n vinniger pad na impak as enige kernel exploit.
- Die kombinasie van swak runtime-houding en swak hulpbronlimiete dui gewoonlik op 'n oor die algemeen permissiewe container-omgewing eerder as 'n enkele geïsoleerde fout.
