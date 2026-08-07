# Bezpieczeństwo kontenerów

{{#include ../../../banners/hacktricks-training.md}}

## Czym właściwie jest kontener

Praktyczny sposób zdefiniowania kontenera jest następujący: kontener to **zwykłe drzewo procesów Linux**, uruchomione zgodnie z określoną konfiguracją w stylu OCI, dzięki czemu widzi kontrolowany system plików, kontrolowany zestaw zasobów kernela oraz ograniczony model uprawnień. Proces może uważać, że jest PID 1, może uważać, że ma własny stos sieciowy, może uważać, że posiada własną nazwę hosta i zasoby IPC, a nawet może działać jako root we własnej user namespace. Jednak pod spodem nadal jest procesem hosta, planowanym przez kernel tak jak każdy inny.

Dlatego bezpieczeństwo kontenerów to w rzeczywistości badanie sposobu konstruowania tej iluzji oraz sposobu, w jaki może ona zawieść. Jeśli mount namespace jest słabo skonfigurowana, proces może zobaczyć system plików hosta. Jeśli user namespace nie istnieje lub jest wyłączona, root wewnątrz kontenera może być zbyt bezpośrednio mapowany na root na hoście. Jeśli seccomp działa w trybie unconfined, a zestaw capabilities jest zbyt szeroki, proces może uzyskać dostęp do syscalli i uprzywilejowanych funkcji kernela, które powinny pozostać poza jego zasięgiem. Jeśli socket runtime jest zamontowany wewnątrz kontenera, kontener może w ogóle nie potrzebować kernel breakout, ponieważ może po prostu poprosić runtime o uruchomienie potężniejszego kontenera równorzędnego albo bezpośrednio zamontować główny system plików hosta.

## Czym kontenery różnią się od maszyn wirtualnych

VM zwykle zawiera własny kernel i granicę abstrakcji sprzętu. Oznacza to, że awaria, panic lub wykorzystanie podatności w kernelu gościa nie musi automatycznie oznaczać bezpośredniej kontroli nad kernelem hosta. W kontenerach workload nie otrzymuje oddzielnego kernela. Zamiast tego otrzymuje starannie filtrowany i izolowany przez namespaces widok tego samego kernela, którego używa host. W rezultacie kontenery są zwykle lżejsze, szybciej się uruchamiają, łatwiej je gęsto rozmieszczać na jednej maszynie i lepiej nadają się do krótkotrwałego wdrażania aplikacji. Ceną jest to, że granica izolacji zależy znacznie bardziej bezpośrednio od prawidłowej konfiguracji hosta i runtime.

Nie oznacza to, że kontenery są „niebezpieczne”, a VM są „bezpieczne”. Oznacza to, że model bezpieczeństwa jest inny. Prawidłowo skonfigurowany stos kontenerów z rootless execution, user namespaces, domyślnym seccomp, ścisłym zestawem capabilities, bez współdzielenia host namespaces oraz z silnym egzekwowaniem SELinux lub AppArmor może być bardzo odporny. Z drugiej strony kontener uruchomiony z `--privileged`, ze współdzieleniem host PID/network, zamontowanym wewnątrz Docker socketem i zapisywalnym bind mountem `/` jest funkcjonalnie znacznie bliższy dostępowi host root niż bezpiecznie odizolowanemu application sandbox. Różnica wynika z warstw, które zostały włączone lub wyłączone.

Istnieje również rozwiązanie pośrednie, które należy rozumieć, ponieważ coraz częściej pojawia się w rzeczywistych środowiskach. **Sandboxed container runtimes**, takie jak **gVisor** i **Kata Containers**, celowo wzmacniają granicę poza poziom klasycznego kontenera `runc`. gVisor umieszcza warstwę userspace kernel pomiędzy workloadem a wieloma interfejsami kernela hosta, natomiast Kata uruchamia workload wewnątrz lekkiej maszyny wirtualnej. Nadal korzystają one z ekosystemów kontenerów i workflow orkiestracji, ale ich właściwości bezpieczeństwa różnią się od właściwości zwykłych OCI runtimes i nie należy mentalnie grupować ich z „normalnymi kontenerami Docker”, tak jakby wszystko działało w ten sam sposób.

## Stos kontenerów: wiele warstw, nie jedna

Kiedy ktoś mówi „ten kontener jest niebezpieczny”, użyteczne pytanie uzupełniające brzmi: **która warstwa sprawiła, że stał się niebezpieczny?** Workload uruchomiony w kontenerze jest zwykle wynikiem współpracy kilku komponentów.

Na najwyższym poziomie często znajduje się **image build layer**, taki jak BuildKit, Buildah lub Kaniko, który tworzy obraz OCI i jego metadane. Nad low-level runtime może znajdować się **engine lub manager**, taki jak Docker Engine, Podman, containerd, CRI-O, Incus lub systemd-nspawn. W środowiskach klastrowych może również występować **orchestrator**, taki jak Kubernetes, który określa żądany poziom bezpieczeństwa poprzez konfigurację workloadu. Ostatecznie to **kernel** faktycznie egzekwuje namespaces, cgroups, seccomp i politykę MAC.

Ten warstwowy model jest ważny dla zrozumienia ustawień domyślnych. Ograniczenie może zostać zażądane przez Kubernetes, przetłumaczone przez CRI przez containerd lub CRI-O, przekształcone w specyfikację OCI przez runtime wrapper, a dopiero potem egzekwowane przez `runc`, `crun`, `runsc` lub inny runtime wobec kernela. Gdy ustawienia domyślne różnią się między środowiskami, często wynika to ze zmiany końcowej konfiguracji w jednej z tych warstw. Ten sam mechanizm może zatem pojawiać się w Docker lub Podman jako flaga CLI, w Kubernetes jako pole Pod lub `securityContext`, a w niższych stosach runtime jako konfiguracja OCI wygenerowana dla workloadu. Z tego powodu przykłady CLI w tej sekcji należy traktować jako **składnię specyficzną dla runtime dla ogólnej koncepcji kontenera**, a nie jako uniwersalne flagi obsługiwane przez każde narzędzie.

## Rzeczywista granica bezpieczeństwa kontenera

W praktyce bezpieczeństwo kontenerów wynika z **nakładających się kontroli**, a nie z jednej idealnej kontroli. Namespaces izolują widoczność. cgroups zarządzają użyciem zasobów i je ograniczają. Capabilities redukują zakres działań, które proces wyglądający na uprzywilejowany może faktycznie wykonywać. seccomp blokuje niebezpieczne syscalle, zanim dotrą do kernela. AppArmor i SELinux dodają Mandatory Access Control ponad standardowe kontrole DAC. `no_new_privs`, zamaskowane ścieżki procfs oraz ścieżki systemowe tylko do odczytu utrudniają typowe łańcuchy wykorzystujące eskalację uprawnień oraz nadużycia proc/sys. Znaczenie ma również sam runtime, ponieważ decyduje o sposobie tworzenia mountów, socketów, etykiet i dołączania do namespaces.

Dlatego wiele dokumentacji dotyczącej bezpieczeństwa kontenerów wydaje się powtarzalne. Ten sam łańcuch ucieczki często zależy jednocześnie od wielu mechanizmów. Na przykład zapisywalny host bind mount jest niebezpieczny, ale staje się znacznie groźniejszy, jeśli kontener działa również jako rzeczywisty root na hoście, ma `CAP_SYS_ADMIN`, nie jest ograniczony przez seccomp i nie podlega restrykcjom SELinux ani AppArmor. Podobnie współdzielenie host PID jest poważnym zagrożeniem, ale staje się znacznie bardziej użyteczne dla atakującego, gdy łączy się z `CAP_SYS_PTRACE`, słabymi zabezpieczeniami procfs lub narzędziami do wchodzenia w namespaces, takimi jak `nsenter`. Właściwym sposobem dokumentowania tego tematu nie jest powtarzanie tego samego ataku na każdej stronie, lecz wyjaśnienie, jaki wkład każda warstwa wnosi do końcowej granicy bezpieczeństwa.

## Jak czytać tę sekcję

Sekcja jest zorganizowana od najbardziej ogólnych pojęć do najbardziej szczegółowych.

Zacznij od przeglądu runtime i ekosystemu:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Następnie zapoznaj się z control planes i powierzchniami supply-chain, które często decydują o tym, czy atakujący w ogóle musi przeprowadzać kernel escape:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
authorization-plugins.md
{{#endref}}

{{#ref}}
image-security-and-secrets.md
{{#endref}}

{{#ref}}
assessment-and-hardening.md
{{#endref}}

Następnie przejdź do modelu ochrony:

{{#ref}}
protections/
{{#endref}}

Strony dotyczące namespaces wyjaśniają poszczególne mechanizmy izolacji kernela:

{{#ref}}
protections/namespaces/
{{#endref}}

Strony dotyczące cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, zamaskowanych ścieżek i ścieżek systemowych tylko do odczytu wyjaśniają mechanizmy, które zwykle są nakładane na namespaces:

{{#ref}}
protections/cgroups.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/no-new-privileges.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
distroless.md
{{#endref}}

{{#ref}}
privileged-containers.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Dobre podejście do wstępnej enumeracji

Podczas oceny celu uruchomionego w kontenerze znacznie bardziej użyteczne jest zadanie niewielkiego zestawu precyzyjnych pytań technicznych niż natychmiastowe przechodzenie do znanych PoC ucieczki. Najpierw zidentyfikuj **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer lub coś bardziej wyspecjalizowanego. Następnie zidentyfikuj **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` lub inną implementację zgodną z OCI. Później sprawdź, czy środowisko jest **rootful czy rootless**, czy aktywne są **user namespaces**, czy współdzielone są jakiekolwiek **host namespaces**, jakie **capabilities** pozostały, czy włączony jest **seccomp**, czy polityka **MAC** rzeczywiście działa, czy dostępne są **niebezpieczne mounty lub sockety** oraz czy proces może komunikować się z API runtime kontenera.

Odpowiedzi na te pytania mówią o rzeczywistym poziomie bezpieczeństwa znacznie więcej niż kiedykolwiek nazwa obrazu bazowego. W wielu assessmentach można przewidzieć prawdopodobną rodzinę breakout jeszcze przed przeczytaniem choćby jednego pliku aplikacji, po prostu dzięki zrozumieniu końcowej konfiguracji kontenera.

## Zakres

Ta sekcja obejmuje dawny materiał skoncentrowany na Docker, uporządkowany według tematyki kontenerów: ekspozycję runtime i daemona, authorization plugins, zaufanie do obrazów i sekrety buildów, wrażliwe mounty hosta, workloady distroless, uprzywilejowane kontenery oraz mechanizmy ochrony kernela zwykle nakładane na uruchamianie kontenerów.

{{#include ../../../banners/hacktricks-training.md}}
