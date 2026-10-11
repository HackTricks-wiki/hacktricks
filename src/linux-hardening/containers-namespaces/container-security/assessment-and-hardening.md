# Assessering En Verharding

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

’n Goeie houerassessering behoort twee parallelle vrae te beantwoord. Eerstens, wat kan ’n aanvaller vanuit die huidige werklading doen? Tweedens, watter operateurkeuses het dit moontlik gemaak? Enumerasiehulpmiddels help met die eerste vraag, en verhardingsriglyne help met die tweede. Deur albei op een bladsy te hou, word hierdie afdeling nuttiger as ’n veldverwysing eerder as bloot ’n katalogus van ontsnappingstruuks.

Een praktiese opdatering vir moderne omgewings is dat baie ouer houerbeskrywings stilweg **rootful runtime**, **geen user namespace-isolasie**, en dikwels **cgroup v1** veronderstel. Daardie aannames is nie meer veilig nie. Voordat jy tyd aan ou ontsnappingsprimitiewe bestee, bevestig eers of die werklading rootless of userns-remapped is, of die gasheer cgroup v2 gebruik, en of Kubernetes of die runtime nou verstekprofiele vir seccomp en AppArmor toepas. Hierdie besonderhede bepaal dikwels of ’n bekende uitbreekmetode steeds van toepassing is.

## Enumerasiehulpmiddels

’n Aantal hulpmiddels bly nuttig om ’n houeromgewing vinnig te karakteriseer:

- `linpeas` kan baie houeraanwysers, gemonteerde sokkette, vermoëstelle, gevaarlike lêerstelsels en uitbreekwenke identifiseer.
- `CDK` fokus spesifiek op houeromgewings en sluit enumerasie plus ’n paar outomatiese ontsnappingskontroles in.
- `amicontained` is liggewig en nuttig om houerbeperkings, vermoëns, naamruimteblootstelling en waarskynlike uitbreekklasse te identifiseer.
- `deepce` is nog ’n houergerigte enumerasiehulpmiddel met uitbreekgerigte kontroles.
- `grype` is nuttig wanneer die assessering die hersiening van kwesbaarhede in beeldpakkette insluit, eerder as net runtime-ontsnappingsontleding.
- `Tracee` is nuttig wanneer jy **runtime-bewyse** nodig het, eerder as net statiese sekuriteitsposisie, veral vir verdagte prosesuitvoering, lêertoegang en houerbewuste gebeurtenisversameling.
- `Inspektor Gadget` is nuttig in Kubernetes- en Linux-gasheerondersoeke wanneer jy eBPF-gesteunde sigbaarheid nodig het wat na pods, houers, naamruimtes en ander hoërvlakbegrippe teruggevoer kan word.

Die waarde van hierdie hulpmiddels lê in spoed en dekking, nie sekerheid nie. Hulle help om die algemene sekuriteitsposisie vinnig te onthul, maar interessante bevindings moet steeds met die werklike runtime-, naamruimte-, vermoë- en monteermodel vergelyk en met die hand vertolk word.

## Verhardingsprioriteite

Die belangrikste verhardingsbeginsels is konseptueel eenvoudig, hoewel die implementering daarvan tussen platforms verskil. Vermy bevoorregte houers. Vermy gemonteerde runtime-sokkette. Moenie skryfbare gasheerpaadjies aan houers gee tensy daar ’n baie spesifieke rede daarvoor is nie. Gebruik user namespaces of rootless-uitvoering waar dit haalbaar is. Verwyder alle vermoëns en voeg slegs dié terug wat die werklading werklik nodig het. Hou seccomp, AppArmor en SELinux geaktiveer eerder as om dit af te skakel om toepassingsversoenbaarheidsprobleme op te los. Beperk hulpbronne sodat ’n gekompromitteerde houer nie maklik diens aan die gasheer kan weier nie.

Beeld- en bouhigiëne is net so belangrik soos die runtime-sekuriteitsposisie. Gebruik minimale beelde, bou dit gereeld weer, skandeer dit, vereis herkomsbewyse waar dit prakties is, en hou geheime uit lae. ’n Houer wat as nie-root met ’n klein beeld en ’n beperkte oppervlak vir stelseloproepe en vermoëns loop, is baie makliker om te verdedig as ’n groot geriefsbeeld wat as gasheer-ekwivalente root loop en vooraf geïnstalleerde ontfoutingshulpmiddels bevat.

Vir Kubernetes is huidige verhardingsbasislyne meer voorskriftelik as wat baie operateurs steeds aanneem. Die ingeboude **Pod Security Standards** beskou `restricted` as die profiel vir “huidige beste praktyk”: `allowPrivilegeEscalation` behoort `false` te wees, werkladings behoort as nie-root te loop, seccomp behoort uitdruklik op `RuntimeDefault` of `Localhost` gestel te wees, en vermoëstelle behoort aggressief verwyder te word. Tydens assessering is dit belangrik omdat ’n cluster wat slegs `warn`- of `audit`-etikette gebruik, op papier verhard kan lyk terwyl dit in die praktyk steeds riskante pods toelaat.<sup>[[1]](#references)</sup>

Wanneer ’n Pod ’n gemonteerde diensrekeningtoken het, beoordeel die toestemmings daarvan **per teikennaamruimte**. ’n Reël wat Pods in een naamruimte lys, bewys nie dat daar toestemming in ’n ander naamruimte is nie; ’n token wat in ’n ander Pod gemonteer is, kan ander regte hê. Gebruik `kubectl auth can-i list pods -n <target-namespace>` en `kubectl auth can-i list secrets -n <target-namespace>` met die identiteit wat werklik beoordeel word. ’n Toegelate kontrole vir die lys van Secrets is ’n ernstige leidraad omdat ’n lysreaksie Secret-inhoud kan insluit, maar dit bewys nie dat ’n bevoorregte token teenwoordig is nie. Gasheertoegang vereis ook ’n bruikbare reg om werkladings te skep, dat die voorgestelde `hostPath`-montering toegelaat word, en ’n nodus-/pod-sekuriteitskonteks wat die beoogde lêerbewerking toelaat. Sien Kubernetes se [magtigingskontroles](https://kubernetes.io/docs/reference/access-authn-authz/authorization/) en [riglyne oor RBAC-regte-eskalasie](https://kubernetes.io/docs/concepts/security/rbac-good-practices/).

## Moderne Triagevrae

Beantwoord hierdie vinnige vrae voordat jy na bladsye oor spesifieke ontsnappingsmetodes gaan:

1. Is die werklading **rootful**, **rootless** of **userns-remapped**?
2. Gebruik die nodus **cgroup v1** of **cgroup v2**?
3. Is **seccomp** en **AppArmor/SELinux** uitdruklik opgestel, of word dit bloot geërf wanneer dit beskikbaar is?
4. Word die naamruimte in Kubernetes werklik **afgedwing** met `baseline` of `restricted`, of word daar net gewaarsku/geoudit?

Nuttige kontroles:

```bash
id
cat /proc/self/uid_map 2>/dev/null
cat /proc/self/gid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/1/attr/current 2>/dev/null
find /var/run/secrets -maxdepth 3 -type f 2>/dev/null | head
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get ns "$NS" -o jsonpath='{.metadata.labels}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.supplementalGroupsPolicy}{"\n"}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.seccompProfile.type}{"\n"}{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.capabilities.drop}{"\n"}' 2>/dev/null
```

Wat hier interessant is:

- As `/proc/self/uid_map` wys dat die container se root na ’n **hoë host-UID-reeks** gekarteer is, is baie ouer write-ups oor host-root minder relevant, omdat root in die container nie meer gelykstaande aan host-root is nie.
- As `/sys/fs/cgroup` `cgroup2fs` is, behoort ou write-ups wat spesifiek op **cgroup v1** fokus, soos misbruik van `release_agent`, nie meer jou eerste raaiskoot te wees nie.
- As seccomp en AppArmor slegs implisiet oorgeërf word, kan oordraagbaarheid swakker wees as wat verdedigers verwag. In Kubernetes is dit dikwels sterker om `RuntimeDefault` eksplisiet in te stel as om stilweg op node-verstekwaardes staat te maak.
- As `supplementalGroupsPolicy` op `Strict` gestel is, behoort die pod te vermy om stilweg ekstra groep-lidmaatskappe uit `/etc/group` binne die image oor te neem. Dit maak groepgebaseerde volume- en lêertoegang meer voorspelbaar.
- Namespace-etikette soos `pod-security.kubernetes.io/enforce=restricted` is die moeite werd om direk na te gaan. `warn` en `audit` is nuttig, maar keer nie dat ’n riskante pod geskep word nie.

## Triage van die runtime-baseline

’n Runtime-baseline is die vinnige kontrole wat jou vertel of ’n container soos ’n gewone geïsoleerde workload lyk, of soos ’n foothold in die beheervlak wat die host kan raak. Dit behoort genoeg feite in te samel om te bepaal watter bladsy om volgende te lees: misbruik van runtime-sockets, host-mounts, namespaces, cgroups, capabilities of ’n hersiening van image-secrets.

Nuttige kontroles vanuit ’n workload:

```bash
id
hostname
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/uid_map 2>/dev/null
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
readlink /proc/self/ns/{pid,mnt,net,ipc,cgroup,user} 2>/dev/null
mount
find /run /var/run -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```

Interpretasie:

- Ontbrekende of onbeperkte `memory.max` / `pids.max` dui op swak beheer oor die ontploffingsradius, selfs sonder ’n skoon escape.
- ’n Root-shell met `NoNewPrivs: 0`, breë capabilities en permissiewe seccomp is baie interessanter as ’n beperkte nie-root-werklas.
- Runtime-sockets en skryfbare host-mounts weeg gewoonlik swaarder as kernel exploits omdat hulle reeds ’n beheerpad na die bestuurstelsel of lêerstelsel blootstel.
- Gedeelde PID-, netwerk-, IPC- of cgroup-naamruimtes is nie altyd op sigself volledige escapes nie, maar maak dit makliker om die volgende stap te vind.

## Voorbeelde van Hulpbronuitputting

Hulpbronbeheermaatreëls is nie glansryk nie, maar vorm deel van container-sekuriteit omdat dit die ontploffingsradius van ’n kompromittering beperk. Sonder geheue-, CPU- of PID-limiete kan ’n eenvoudige shell genoeg wees om die host of naburige werkladings te verswak.

Voorbeelde van toetse wat die host kan beïnvloed:

```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```

Hierdie voorbeelde is nuttig omdat hulle wys dat nie elke gevaarlike uitkoms met ’n container ’n skoon "escape" is nie. Swak cgroup-limiete kan kode-uitvoering steeds in werklike operasionele impak omskep.

Kontroleer in Kubernetes-gesteunde omgewings ook of hulpbronbeheermaatreëls hoegenaamd bestaan voordat jy DoS as teoreties beskou:

```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```

## Verhardingsnutsgoed

Vir Docker-sentriese omgewings bly `docker-bench-security` ’n nuttige ouditbasislyn aan die gasheerkant, omdat dit algemene konfigurasieprobleme nagaan aan die hand van algemeen erkende maatstafriglyne. Runtime-kennisgewings moet afsonderlik nagegaan word, omdat ’n konfigurasie-maatstaf nie kan vasstel of die geïnstalleerde runtime deur ’n nuut bekendgemaakte kwesbaarheid geraak word nie. <sup>[[2]](#references)</sup>

```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

Die hulpmiddel is nie ’n plaasvervanger vir threat modeling nie, maar dit is steeds nuttig om nalatige daemon-, mount-, network- en runtime-standaardinstellings op te spoor wat mettertyd ophoop.

Vir Kubernetes- en runtime-intensiewe omgewings, kombineer statiese kontroles met runtime-sigbaarheid:

- `Tracee` is nuttig vir runtime-opsporing met container-bewustheid en vinnige forensiese ondersoeke wanneer jy moet bevestig waaraan ’n gekompromitteerde workload werklik geraak het.
- `Inspektor Gadget` is nuttig wanneer die assessment kernel-vlaktelemetrie vereis wat teruggekoppel word aan pods, containers, DNS-aktiwiteit, lêeruitvoering of netwerkgedrag.

## Kontroles

Gebruik hierdie as vinnige eerstevlakopdragte tydens assessment:

```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```

Wat hier interessant is:

- ’n Root-proses met breë vermoëns en `Seccomp: 0` verdien onmiddellike aandag.
- ’n Root-proses wat ook ’n **1:1 UID-map** het, is veel interessanter as “root” binne ’n behoorlik geïsoleerde user namespace.
- `cgroup2fs` beteken gewoonlik dat baie ouer **cgroup v1**-ontsnappingskettings nie jou beste beginpunt is nie, terwyl die ontbrekende `memory.max` of `pids.max` steeds op swak beheer oor die omvang van skade dui.
- Verdagte mounts en runtime-sockets bied dikwels ’n vinniger pad na impak as enige kernel-exploit.
- Die kombinasie van ’n swak runtime-opstelling en swak hulpbronlimiete dui gewoonlik op ’n oor die algemeen permissiewe container-omgewing eerder as ’n enkele geïsoleerde fout.

## References

- [1] [Kubernetes Pod-sekuriteitstandaarde](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Docker-sekuriteitsadvies: Veelvuldige kwesbaarhede in runc, BuildKit en Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
