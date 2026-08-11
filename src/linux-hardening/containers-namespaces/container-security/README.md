# Bezpieczeństwo kontenerów

## Czym właściwie jest kontener

Praktyczny sposób zdefiniowania kontenera jest następujący: kontener to **zwykłe drzewo procesów Linux**, uruchomione na podstawie określonej konfiguracji w stylu OCI, dzięki czemu widzi kontrolowany system plików, kontrolowany zestaw zasobów kernela oraz ograniczony model uprawnień. Proces może uważać, że jest PID 1, może uważać, że ma własny stos sieciowy, może uważać, że posiada własną nazwę hosta i zasoby IPC, a nawet może działać jako root we własnej user namespace. Jednak pod spodem nadal jest procesem hosta, który kernel planuje tak samo jak każdy inny.

Dlatego bezpieczeństwo kontenerów to w rzeczywistości badanie sposobu konstruowania tej iluzji oraz tego, jak ulega ona awarii. Jeśli mount namespace jest słaba, proces może zobaczyć system plików hosta. Jeśli user namespace nie istnieje lub jest wyłączona, root wewnątrz kontenera może być zbyt bezpośrednio mapowany na root na hoście. Jeśli seccomp jest unconfined, a zestaw capabilities zbyt szeroki, proces może uzyskać dostęp do syscalli i uprzywilejowanych funkcji kernela, które powinny pozostać poza jego zasięgiem. Jeśli socket runtime'u jest zamontowany wewnątrz kontenera, kontener może w ogóle nie potrzebować kernel breakout, ponieważ może po prostu poprosić runtime o uruchomienie potężniejszego kontenera siostrzanego albo bezpośrednio zamontować główny system plików hosta.

## Czym kontenery różnią się od maszyn wirtualnych

VM zwykle zawiera własny kernel i warstwę abstrakcji sprzętu. Oznacza to, że awaria, panic lub wykorzystanie podatności w kernelu gościa nie oznacza automatycznie bezpośredniej kontroli nad kernelem hosta. Kontenery nie otrzymują osobnego kernela. Zamiast tego dostają starannie filtrowany i namespacowany widok tego samego kernela, którego używa host. W rezultacie kontenery są zwykle lżejsze, szybciej się uruchamiają, łatwiej upakować je na jednej maszynie i lepiej nadają się do krótkotrwałego wdrażania aplikacji. Ceną jest to, że granica izolacji zależy znacznie bardziej bezpośrednio od poprawnej konfiguracji hosta i runtime'u.

Nie oznacza to, że kontenery są „niebezpieczne”, a VM są „bezpieczne”. Oznacza to, że model bezpieczeństwa jest inny. Dobrze skonfigurowany stos kontenerów z rootless execution, user namespaces, domyślnym seccomp, ścisłym zestawem capabilities, bez współdzielenia host namespaces oraz z silnym egzekwowaniem SELinux lub AppArmor może być bardzo odporny. Z kolei kontener uruchomiony z `--privileged`, współdzieleniem host PID/network, zamontowanym wewnątrz socketem Dockera oraz zapisywalnym bind mountem `/` jest funkcjonalnie znacznie bliższy dostępowi host root niż bezpiecznie izolowanemu application sandbox. Różnica wynika z warstw, które zostały włączone lub wyłączone.

Istnieje również rozwiązanie pośrednie, które czytelnicy powinni rozumieć, ponieważ coraz częściej pojawia się w rzeczywistych środowiskach. **Sandboxed container runtimes**, takie jak **gVisor** i **Kata Containers**, celowo wzmacniają granicę izolacji bardziej niż klasyczny kontener `runc`. gVisor umieszcza userspace kernel layer pomiędzy workloadem a wieloma interfejsami kernela hosta, natomiast Kata uruchamia workload wewnątrz lekkiej maszyny wirtualnej. Nadal korzysta się z nich za pośrednictwem ekosystemów kontenerowych i workflow orkiestracji, ale ich właściwości bezpieczeństwa różnią się od zwykłych OCI runtimes i nie należy mentalnie grupować ich z „normalnymi kontenerami Dockera”, jak gdyby wszystko działało tak samo.

## Stos kontenerów: kilka warstw, a nie jedna

Kiedy ktoś mówi „ten kontener jest niebezpieczny”, przydatne pytanie uzupełniające brzmi: **która warstwa sprawiła, że jest niebezpieczny?** Workload kontenerowy jest zwykle wynikiem współdziałania kilku komponentów.

Na najwyższym poziomie często znajduje się **image build layer**, taki jak BuildKit, Buildah lub Kaniko, który tworzy obraz OCI i metadane. Nad low-level runtime może znajdować się **engine lub manager**, taki jak Docker Engine, Podman, containerd, CRI-O, Incus lub systemd-nspawn. W środowiskach klastrowych może również występować **orchestrator**, taki jak Kubernetes, który określa żądany poziom bezpieczeństwa za pomocą konfiguracji workloadu. Ostatecznie to **kernel** faktycznie egzekwuje namespaces, cgroups, seccomp i politykę MAC.

Ten warstwowy model jest ważny dla zrozumienia ustawień domyślnych. Ograniczenie może zostać zażądane przez Kubernetes, przetłumaczone przez CRI za pośrednictwem containerd lub CRI-O, zamienione na OCI spec przez runtime wrapper, a dopiero potem wyegzekwowane przez `runc`, `crun`, `runsc` lub inny runtime względem kernela. Gdy ustawienia domyślne różnią się między środowiskami, często wynika to z tego, że jedna z tych warstw zmieniła konfigurację końcową. Ten sam mechanizm może więc pojawiać się w Dockerze lub Podmanie jako flaga CLI, w Kubernetesie jako pole Pod lub `securityContext`, a w niższych stosach runtime jako konfiguracja OCI wygenerowana dla workloadu. Z tego powodu przykłady CLI w tej sekcji należy traktować jako **składnię specyficzną dla runtime'u, opisującą ogólną koncepcję kontenera**, a nie jako uniwersalne flagi obsługiwane przez każde narzędzie.

## Rzeczywista granica bezpieczeństwa kontenera

W praktyce bezpieczeństwo kontenerów wynika z **nakładających się kontroli**, a nie z jednej idealnej kontroli. Namespaces izolują widoczność. cgroups zarządzają użyciem zasobów i je ograniczają. Capabilities redukują zakres działań, które faktycznie może wykonać proces wyglądający na uprzywilejowany. seccomp blokuje niebezpieczne syscalle, zanim dotrą one do kernela. AppArmor i SELinux dodają Mandatory Access Control ponad standardowe kontrole DAC. `no_new_privs`, zamaskowane ścieżki procfs oraz ścieżki systemowe tylko do odczytu utrudniają typowe łańcuchy eskalacji uprawnień i nadużyć proc/sys. Znaczenie ma również sam runtime, ponieważ decyduje on o sposobie tworzenia mountów, socketów, etykiet i dołączania do namespaces.

Dlatego wiele materiałów dotyczących bezpieczeństwa kontenerów wydaje się powtarzalnych. Ten sam łańcuch escape często zależy jednocześnie od wielu mechanizmów. Na przykład zapisywalny host bind mount jest niebezpieczny, ale staje się znacznie groźniejszy, jeśli kontener działa również jako rzeczywisty root na hoście, ma `CAP_SYS_ADMIN`, jest unconfined przez seccomp i nie podlega ograniczeniom SELinux ani AppArmor. Podobnie współdzielenie host PID jest poważnym narażeniem, ale staje się znacznie bardziej użyteczne dla atakującego, gdy łączy się z `CAP_SYS_PTRACE`, słabymi zabezpieczeniami procfs lub narzędziami do wchodzenia do namespaces, takimi jak `nsenter`. Właściwym sposobem dokumentowania tego tematu nie jest więc powtarzanie tego samego ataku na każdej stronie, lecz wyjaśnienie, co każda warstwa wnosi do końcowej granicy bezpieczeństwa.

## Jak czytać tę sekcję

Sekcja jest uporządkowana od najbardziej ogólnych koncepcji do najbardziej szczegółowych.

Zacznij od przeglądu runtime'u i ekosystemu:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Następnie zapoznaj się z control planes i powierzchniami supply chain, które często decydują o tym, czy atakujący w ogóle potrzebuje kernel escape:

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

Strony dotyczące namespaces wyjaśniają osobno primitive izolacji kernela:

{{#ref}}
protections/namespaces/
{{#endref}}

Strony dotyczące cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, zamaskowanych ścieżek i ścieżek systemowych tylko do odczytu wyjaśniają mechanizmy, które zwykle nakłada się na namespaces:

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

## Dobre podejście do pierwszej enumeracji

Podczas oceny celu skonteneryzowanego znacznie bardziej użyteczne jest zadanie niewielkiego zestawu precyzyjnych pytań technicznych niż natychmiastowe przechodzenie do znanych PoC escape. Najpierw określ **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer lub coś bardziej wyspecjalizowanego. Następnie określ **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` lub inną implementację zgodną z OCI. Potem sprawdź, czy środowisko jest **rootful czy rootless**, czy aktywne są **user namespaces**, czy współdzielone są jakiekolwiek **host namespaces**, jakie **capabilities** pozostały, czy włączony jest **seccomp**, czy **polityka MAC** faktycznie egzekwuje ograniczenia, czy obecne są **niebezpieczne mounty lub sockety** oraz czy proces może komunikować się z API container runtime.

Te odpowiedzi mówią znacznie więcej o rzeczywistym poziomie bezpieczeństwa niż nazwa base image. W wielu assessmentach można przewidzieć prawdopodobną rodzinę breakout jeszcze przed przeczytaniem choćby jednego pliku aplikacji, po prostu dzięki zrozumieniu końcowej konfiguracji kontenera.

## Zakres

Ta sekcja obejmuje wcześniejsze materiały skupione na Dockerze, uporządkowane wokół kontenerów: ekspozycję runtime'u i daemona, authorization plugins, zaufanie do obrazów i build secrets, wrażliwe mounty hosta, workloady distroless, uprzywilejowane kontenery oraz zabezpieczenia kernela zwykle nakładane na wykonywanie kontenerów.

{{#include ../../../banners/hacktricks-training.md}}
