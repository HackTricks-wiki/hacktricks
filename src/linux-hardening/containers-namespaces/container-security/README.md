# Bezpieczeństwo kontenerów

{{#include ../../../banners/hacktricks-training.md}}

## Czym właściwie jest kontener

Praktyczny sposób zdefiniowania kontenera jest następujący: kontener to **zwykłe drzewo procesów Linux**, uruchomione z określoną konfiguracją w stylu OCI, dzięki czemu widzi kontrolowany system plików, kontrolowany zestaw zasobów kernela oraz ograniczony model uprawnień. Proces może uważać, że jest PID 1, może uważać, że ma własny stos sieciowy, może uważać, że posiada własną nazwę hosta i zasoby IPC, a nawet może działać jako root we własnej user namespace. Jednak pod spodem nadal jest procesem hosta, który kernel planuje tak samo jak każdy inny.

Dlatego bezpieczeństwo kontenerów jest w rzeczywistości badaniem sposobu konstruowania tej iluzji oraz tego, jak może ona zawieść. Jeśli mount namespace jest słabo zabezpieczona, proces może zobaczyć system plików hosta. Jeśli user namespace nie istnieje lub jest wyłączona, root wewnątrz kontenera może być zbyt bezpośrednio mapowany na roota hosta. Jeśli seccomp jest unconfined, a zestaw capabilities zbyt szeroki, proces może uzyskać dostęp do syscalli i uprzywilejowanych funkcji kernela, które powinny pozostać poza jego zasięgiem. Jeśli socket runtime jest zamontowany wewnątrz kontenera, kontener może w ogóle nie potrzebować kernel breakout, ponieważ może po prostu poprosić runtime o uruchomienie potężniejszego kontenera siostrzanego albo bezpośrednio zamontować główny system plików hosta.

## Czym kontenery różnią się od maszyn wirtualnych

VM zwykle posiada własny kernel i granicę abstrakcji sprzętu. Oznacza to, że kernel gościa może ulec awarii, panice lub zostać wykorzystany bez automatycznego uzyskania bezpośredniej kontroli nad kernelem hosta. Kontenery nie otrzymują osobnego kernela. Zamiast tego dostają starannie filtrowany i namespacowany widok tego samego kernela, którego używa host. W rezultacie kontenery są zazwyczaj lżejsze, szybciej się uruchamiają, łatwiej jest umieszczać ich wiele na jednej maszynie i lepiej nadają się do krótkotrwałego wdrażania aplikacji. Ceną jest to, że granica izolacji zależy znacznie bardziej bezpośrednio od prawidłowej konfiguracji hosta i runtime.

Nie oznacza to, że kontenery są "niebezpieczne", a VM są "bezpieczne". Oznacza to, że model bezpieczeństwa jest inny. Dobrze skonfigurowany stos kontenerów z rootless execution, user namespaces, domyślnym seccomp, restrykcyjnym zestawem capabilities, bez współdzielenia host namespaces oraz z silnym egzekwowaniem SELinux lub AppArmor może być bardzo odporny. Z drugiej strony kontener uruchomiony z `--privileged`, współdzieleniem host PID/network, zamontowanym wewnątrz Docker socketem oraz zapisywalnym bind mountem `/` jest funkcjonalnie znacznie bliższy dostępowi root do hosta niż bezpiecznie odizolowanemu sandboxowi aplikacji. Różnica wynika z warstw, które zostały włączone lub wyłączone.

Istnieje również rozwiązanie pośrednie, które czytelnicy powinni rozumieć, ponieważ coraz częściej pojawia się w rzeczywistych środowiskach. **Sandboxed container runtimes**, takie jak **gVisor** i **Kata Containers**, celowo wzmacniają granicę bezpieczeństwa bardziej niż klasyczny kontener `runc`. gVisor umieszcza warstwę kernela działającą w userspace pomiędzy workloadem a wieloma interfejsami kernela hosta, podczas gdy Kata uruchamia workload wewnątrz lekkiej maszyny wirtualnej. Nadal są one używane za pośrednictwem ekosystemów kontenerowych i workflow orkiestracji, ale ich właściwości bezpieczeństwa różnią się od zwykłych runtime OCI i nie należy mentalnie grupować ich z "normalnymi kontenerami Docker", jak gdyby wszystko działało tak samo.

## Stos kontenerów: wiele warstw, a nie jedna

Gdy ktoś mówi "ten kontener jest niebezpieczny", przydatne pytanie uzupełniające brzmi: **która warstwa sprawiła, że jest niebezpieczny?** Konteneryzowany workload jest zwykle wynikiem współpracy kilku komponentów.

Na najwyższym poziomie często znajduje się **warstwa budowania obrazu**, taka jak BuildKit, Buildah lub Kaniko, która tworzy obraz OCI i metadane. Nad niskopoziomowym runtime może znajdować się **engine lub manager**, taki jak Docker Engine, Podman, containerd, CRI-O, Incus lub systemd-nspawn. W środowiskach klastrowych może również występować **orchestrator**, taki jak Kubernetes, który określa żądany poziom bezpieczeństwa za pomocą konfiguracji workloadu. Ostatecznie to **kernel** faktycznie egzekwuje namespaces, cgroups, seccomp i politykę MAC.

Ten warstwowy model jest ważny dla zrozumienia ustawień domyślnych. Ograniczenie może zostać zażądane przez Kubernetes, przetłumaczone przez CRI za pośrednictwem containerd lub CRI-O, przekonwertowane do specyfikacji OCI przez wrapper runtime, a dopiero następnie wyegzekwowane przez `runc`, `crun`, `runsc` lub inny runtime względem kernela. Gdy ustawienia domyślne różnią się między środowiskami, często dzieje się tak dlatego, że jedna z tych warstw zmieniła końcową konfigurację. Ten sam mechanizm może zatem pojawiać się w Dockerze lub Podmanie jako flaga CLI, w Kubernetesie jako pole Pod lub `securityContext`, a w stosach runtime niższego poziomu jako konfiguracja OCI wygenerowana dla workloadu. Z tego powodu przykłady CLI w tej sekcji należy czytać jako **składnię specyficzną dla runtime dla ogólnej koncepcji kontenera**, a nie jako uniwersalne flagi obsługiwane przez każde narzędzie.

## Rzeczywista granica bezpieczeństwa kontenera

W praktyce bezpieczeństwo kontenerów wynika z **nakładających się mechanizmów kontroli**, a nie z jednego idealnego zabezpieczenia. Namespaces izolują widoczność. cgroups zarządzają wykorzystaniem zasobów i je ograniczają. Capabilities redukują zakres działań, które może faktycznie wykonać proces wyglądający na uprzywilejowany. seccomp blokuje niebezpieczne syscalle, zanim dotrą one do kernela. AppArmor i SELinux dodają Mandatory Access Control ponad standardowe kontrole DAC. `no_new_privs`, zamaskowane ścieżki procfs oraz ścieżki systemowe tylko do odczytu utrudniają typowe łańcuchy nadużyć uprawnień oraz proc/sys. Znaczenie ma również sam runtime, ponieważ decyduje, jak tworzone są mounty, sockety, etykiety i dołączanie do namespaces.

Dlatego wiele dokumentacji dotyczącej bezpieczeństwa kontenerów wydaje się powtarzalne. Ten sam łańcuch escape często zależy jednocześnie od wielu mechanizmów. Na przykład zapisywalny host bind mount jest niebezpieczny, ale staje się znacznie groźniejszy, jeśli kontener działa również jako rzeczywisty root na hoście, ma `CAP_SYS_ADMIN`, jest niezabezpieczony przez seccomp i nie podlega ograniczeniom SELinux ani AppArmor. Podobnie współdzielenie host PID jest poważnym narażeniem, ale staje się znacznie bardziej użyteczne dla atakującego, gdy połączone jest z `CAP_SYS_PTRACE`, słabą ochroną procfs lub narzędziami do wchodzenia do namespaces, takimi jak `nsenter`. Właściwym sposobem dokumentowania tego tematu nie jest powtarzanie tego samego ataku na każdej stronie, lecz wyjaśnienie, jaki wkład każda warstwa wnosi do końcowej granicy bezpieczeństwa.

## Jak czytać tę sekcję

Sekcja jest uporządkowana od najbardziej ogólnych koncepcji do najbardziej szczegółowych.

Zacznij od przeglądu runtime i ekosystemu:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Następnie przejrzyj control planes i powierzchnie supply chain, które często decydują o tym, czy atakujący w ogóle potrzebuje kernel escape:

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

Strony dotyczące namespaces wyjaśniają osobno prymitywy izolacji kernela:

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

## Dobre podejście do wstępnego rozpoznania

Podczas oceny celu działającego w kontenerze znacznie bardziej przydatne jest zadanie niewielkiego zestawu precyzyjnych pytań technicznych niż natychmiastowe przechodzenie do znanych PoC escape. Najpierw zidentyfikuj **stos**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer lub coś bardziej wyspecjalizowanego. Następnie zidentyfikuj **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` lub inną implementację zgodną z OCI. Później sprawdź, czy środowisko jest **rootful czy rootless**, czy aktywne są **user namespaces**, czy współdzielone są jakiekolwiek **host namespaces**, jakie **capabilities** pozostały, czy **seccomp** jest włączony, czy **polityka MAC** faktycznie egzekwuje ograniczenia, czy obecne są **niebezpieczne mounty lub sockety** oraz czy proces może komunikować się z API runtime kontenera.

Odpowiedzi na te pytania mówią znacznie więcej o rzeczywistym poziomie bezpieczeństwa niż kiedykolwiek nazwa obrazu bazowego. W wielu assessmentach można przewidzieć prawdopodobną kategorię breakout jeszcze przed przeczytaniem choćby jednego pliku aplikacji, po prostu rozumiejąc końcową konfigurację kontenera.

## Zakres

Ta sekcja obejmuje dawny materiał skoncentrowany na Dockerze, uporządkowany według tematyki kontenerów: narażenie runtime i daemonów, authorization plugins, zaufanie do obrazów i build secrets, wrażliwe mounty hosta, workloady distroless, kontenery uprzywilejowane oraz zabezpieczenia kernela zwykle nakładane na wykonywanie kontenerów.
{{#include ../../../banners/hacktricks-training.md}}
