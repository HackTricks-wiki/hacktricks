# Procena i ojačavanje

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Dobra procena kontejnera treba da odgovori na dva paralelna pitanja. Prvo, šta napadač može da uradi iz trenutnog workload-a? Drugo, koje odluke operatera su to omogućile? Alati za enumeraciju pomažu kod prvog pitanja, a smernice za ojačavanje pomažu kod drugog. Držanje oba na jednoj strani čini sekciju korisnijom kao priručnik u polju, a ne samo katalogom escape tricks.

## Alati za enumeraciju

Nekoliko alata ostaje korisno za brzo karakterisanje container okruženja:

- `linpeas` može identifikovati mnoge indikatore kontejnera, montirane sokete, capability setove, opasne filesystems i breakout hints.
- `CDK` se fokusira specifično na container okruženja i uključuje enumeraciju plus neke automatizovane escape provere.
- `amicontained` je lagan i koristan za identifikovanje ograničenja kontejnera, capabilities, izloženosti namespace-a i verovatnih breakout klasa.
- `deepce` je još jedan enumerator fokusiran na kontejnere sa proverama orijentisanim na breakout.
- `grype` je koristan kada procena uključuje pregled ranjivosti image-package umesto samo runtime escape analize.

Vrednost ovih alata je u brzini i pokrivenosti, ne u pouzdanosti. Pomažu da se brzo otkrije grubi položaj, ali zanimljiva otkrića i dalje zahtevaju ručnu interpretaciju u odnosu na stvarni runtime, namespace, capability i mount model.

## Prioriteti ojačavanja

Najvažniji principi ojačavanja su konceptualno jednostavni iako se implementacija razlikuje po platformama. Izbegavajte privileged containers. Izbegavajte montirane runtime socket-e. Ne dajte kontejnerima writable host puteve osim ako ne postoji veoma specifičan razlog. Koristite user namespaces ili rootless execution gde je izvodljivo. Uklonite sve capabilities i vratite samo one koje workload zaista zahteva. Održavajte seccomp, AppArmor i SELinux omogućene umesto da ih isključujete da biste rešili probleme kompatibilnosti aplikacija. Ograničite resurse tako da kompromitovan kontejner ne može trivijalno da onemogući servis hosta.

Higijena image-a i build procesa je podjednako važna kao i runtime postura. Koristite minimalne image-e, rebuild-ujte često, skenirajte ih, zahtevajte provenance gde je praktično i držite secrets van slojeva. Kontejner koji radi kao non-root sa malim image-om i uskom syscall i capability površinom mnogo je lakše braniti nego veliki convenience image koji radi kao host-ekvivalentni root sa unapred instaliranim debugging alatima.

## Primeri iscrpljivanja resursa

Kontrole resursa nisu glamurozne, ali su deo sigurnosti kontejnera jer ograničavaju blast radius kompromitacije. Bez limita za memory, CPU ili PID, jednostavan shell može biti dovoljan da degradira host ili susedne workload-e.

Primeri testova koji utiču na host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Ovi primeri su korisni jer pokazuju da svaki opasan ishod u kontejneru nije nužno čist "escape". Slaba cgroup ograničenja i dalje mogu pretvoriti izvršavanje koda u stvarni operativni uticaj.

## Hardening Tooling

Za Docker-centric okruženja, `docker-bench-security` ostaje koristan host-side audit baseline, jer proverava uobičajene konfiguracione probleme u skladu sa široko priznatim smernicama i benchmark standardima:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Alat nije zamena za modeliranje pretnji, ali je i dalje koristan za pronalaženje nepažljivih podrazumevanih podešavanja za daemon, mount, network i runtime koja se vremenom nagomilavaju.

## Provere

Koristite ih kao brze komande za početnu proveru tokom procene:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Šta je ovde zanimljivo:

- root proces sa širokim privilegijama i `Seccomp: 0` zaslužuje trenutnu pažnju.
- Sumnjiva mountovanja i runtime soketi često obezbeđuju brži put do kompromitacije nego bilo koji kernel exploit.
- Kombinacija slabe sigurnosne postavke runtime-a i slabih ograničenja resursa obično ukazuje na generalno permisivno okruženje kontejnera, a ne na jednu izolovanu grešku.
{{#include ../../../banners/hacktricks-training.md}}
