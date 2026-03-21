# Procena i učvršćivanje

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Dobra procena kontejnera treba da odgovori na dva paralelna pitanja. Prvo, šta napadač može da uradi iz trenutnog workload-a? Drugo, koje operaterske odluke su to omogućile? Alati za enumeraciju pomažu kod prvog pitanja, a smernice za učvršćivanje kod drugog. Držanje oba na jednoj stranici čini odeljak korisnijim kao referentom u terenu, a ne samo katalogom trikova za escape.

## Alati za enumeraciju

Nekoliko alata ostaje korisno za brzo karakterisanje kontejnerskog okruženja:

- `linpeas` može da identifikuje mnoge indikatore kontejnera, mountovane socket-e, setove capability-a, opasne filesystem-e i naznake za breakout.
- `CDK` se fokusira specifično na container okruženja i uključuje enumeraciju plus neke automatizovane provere za escape.
- `amicontained` je lagan i koristan za identifikovanje ograničenja kontejnera, capability-a, izloženosti namespace-a i verovatnih klasa breakout-a.
- `deepce` je još jedan enumerator fokusiran na kontejnere sa proverama orijentisanim na breakout.
- `grype` je koristan kada procena uključuje pregled ranjivosti paketa u image-u umesto samo runtime analize escape-a.

Vrednost ovih alata je brzina i obuhvat, ne sigurnost. Pomažu da se brzo otkrije grubi posture, ali zanimljiva otkrića i dalje zahtevaju ručnu interpretaciju u odnosu na stvarni runtime, namespace, capability i mount model.

## Prioriteti jačanja

Najvažnija načela za učvršćivanje su konceptualno jednostavna iako njihova implementacija varira po platformama. Izbegavajte privilegovane kontejnere. Izbegavajte mountovane runtime socket-e. Ne dajte kontejnerima writable host putanje osim ako postoji vrlo specifičan razlog. Koristite user namespaces ili rootless izvršavanje gde je izvodljivo. Uklonite sve capability-e i vratite samo one koje workload zaista zahteva. Držite seccomp, AppArmor i SELinux omogućenim umesto da ih isključujete da biste rešili probleme kompatibilnosti aplikacija. Ograničite resurse tako da kompromitovan kontejner ne može trivijalno da uskraćuje servis hostu.

Higijena image-a i build procesa je podjednako važna kao i runtime postura. Koristite minimalne image-e, rebuild-ujte često, skenirajte ih, zahtevajte provenance gde je praktično i držite tajne van layer-a. Kontejner koji radi kao ne-root sa malim image-om i uskim syscall i capability opsegom mnogo je lakše braniti nego veliki convenience image koji radi kao host-ekvivalentni root sa unapred instaliranim debugging alatima.

## Primeri iscrpljivanja resursa

Kontrole resursa nisu atraktivne, ali su deo sigurnosti kontejnera jer ograničavaju blast radius kompromitovanja. Bez ograničenja memorije, CPU-a ili PID-a, jednostavan shell može biti dovoljan da degradira host ili susedne workload-e.

Primeri testova koji utiču na host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Ovi primeri su korisni jer pokazuju da nije svaki opasan ishod u kontejneru čist "escape". Slabi cgroup limits i dalje mogu da pretvore code execution u stvaran operativni uticaj.

## Hardening Tooling

Za Docker-centric okruženja, `docker-bench-security` i dalje predstavlja koristan host-side audit baseline jer proverava uobičajene probleme u konfiguraciji u skladu sa široko priznatim smernicama za benchmark:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
Alat nije zamena za threat modeling, ali je i dalje koristan za pronalaženje nemarnih daemon, mount, network i runtime podrazumevanih postavki koje se vremenom nagomilavaju.

## Provere

Koristite ih kao brze komande za početnu procenu:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
Šta je ovde zanimljivo:

- Root proces sa širokim capabilities i `Seccomp: 0` zaslužuje hitnu pažnju.
- Sumnjivi mounts i runtime sockets često pružaju brži put do kompromitacije nego bilo koji kernel exploit.
- Kombinacija slabe runtime posture i slabih resource limits obično ukazuje na generalno permisivno container environment umesto na jednu izolovanu grešku.
