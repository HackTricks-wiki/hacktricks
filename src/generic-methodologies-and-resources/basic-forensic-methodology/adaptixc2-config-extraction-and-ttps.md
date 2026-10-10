# Витягування конфігурації AdaptixC2 і TTP

{{#include ../../banners/hacktricks-training.md}}

AdaptixC2 — це модульний фреймворк з відкритим кодом для post-exploitation/C2 з Windows x86/x64 beacons (EXE/DLL/service EXE/raw shellcode) і підтримкою BOF.<sup>[[1]](#references)</sup> На цій сторінці описано:
- Як вбудовано конфігурацію, запаковану RC4, і як витягти її з beacons
- Індикатори мережі та профілю для HTTP/SMB/TCP listeners
- Поширені TTP завантажувачів і persistence, що спостерігаються в реальних атаках, із посиланнями на відповідні сторінки про техніки Windows

В останніх upstream-релізах також є DNS/DoH beacon listeners і окрема родина агентів/listeners Gopher, тому сучасна інфраструктура Adaptix може використовувати більше, ніж початкові HTTP/SMB/TCP поверхні, навіть якщо конкретний зразок досі використовує класичний beacon agent.<sup>[[2]](#references)</sup>

## Профілі та поля beacon

AdaptixC2 підтримує три основні типи beacon:<sup>[[1]](#references)</sup>
- BEACON_HTTP: веб C2 із налаштовуваними серверами/портами/SSL, методом, URI, заголовками, user-agent і власною назвою параметра
- BEACON_SMB: peer-to-peer C2 через іменований канал (intranet)
- BEACON_TCP: прямі сокети, опційно з доданим на початку маркером для обфускації початку протоколу

Це структури beacon, описані у відкритих аналізах Adaptix на ранньому етапі; вони досі є найпоширенішою відправною точкою для витягування даних зі зразків.<sup>[[1]](#references)</sup> Однак поточні upstream-збірки також постачають розширення `BeaconDNS` і Gopher на стороні сервера, тому не припускайте, що кожне активне розгортання Adaptix використовує лише HTTP/SMB/TCP інфраструктуру.<sup>[[2]](#references)</sup>

Типові поля профілю в HTTP beacon configs (після розшифрування):<sup>[[1]](#references)</sup>
- agent_type (u32)
- use_ssl (bool)
- servers_count (u32), servers (array of strings), ports (array of u32)
- http_method, uri, parameter, user_agent, http_headers (length‑prefixed strings)
- ans_pre_size (u32), ans_size (u32) – використовуються для розбору розмірів відповідей
- kill_date (u32), working_time (u32)
- sleep_delay (u32), jitter_delay (u32)
- listener_type (u32)
- download_chunk_size (u32)

Сучасні збірки BeaconHTTP також підтримують вибір оператором ротації між кількома URI, user-agents, заголовками Host і серверами — послідовний або випадковий вибір.<sup>[[2]](#references)</sup> Для threat hunting це означає, що один заражений хост може використовувати кілька callback-шляхів і комбінацій заголовків, не виходячи за межі класичної родини beacon, запакованої RC4.

Приклад стандартного HTTP-профілю (зі збірки beacon):<sup>[[1]](#references)</sup>

```json
{
  "agent_type": 3192652105,
  "use_ssl": true,
  "servers_count": 1,
  "servers": ["172.16.196.1"],
  "ports": [4443],
  "http_method": "POST",
  "uri": "/uri.php",
  "parameter": "X-Beacon-Id",
  "user_agent": "Mozilla/5.0 (Windows NT 6.2; rv:20.0) Gecko/20121202 Firefox/20.0",
  "http_headers": "\r\n",
  "ans_pre_size": 26,
  "ans_size": 47,
  "kill_date": 0,
  "working_time": 0,
  "sleep_delay": 2,
  "jitter_delay": 0,
  "listener_type": 0,
  "download_chunk_size": 102400
}
```

Виявлений шкідливий HTTP-профіль (реальна атака):<sup>[[1]](#references)</sup>

```json
{
  "agent_type": 3192652105,
  "use_ssl": true,
  "servers_count": 1,
  "servers": ["tech-system[.]online"],
  "ports": [443],
  "http_method": "POST",
  "uri": "/endpoint/api",
  "parameter": "X-App-Id",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36",
  "http_headers": "\r\n",
  "ans_pre_size": 26,
  "ans_size": 47,
  "kill_date": 0,
  "working_time": 0,
  "sleep_delay": 4,
  "jitter_delay": 0,
  "listener_type": 0,
  "download_chunk_size": 102400
}
```

## Пакування зашифрованої конфігурації та шлях її завантаження

Коли оператор натискає Create у builder, AdaptixC2 додає зашифрований profile у вигляді кінцевого blob у beacon. Формат:<sup>[[1]](#references)</sup>
- 4 байти: розмір конфігурації (uint32, little‑endian)
- N байтів: зашифровані RC4 дані конфігурації
- 16 байтів: ключ RC4

Завантажувач beacon копіює 16-байтовий ключ із кінця та розшифровує блок із N байтів за допомогою RC4 безпосередньо на місці:<sup>[[1]](#references)</sup>

```c
ULONG profileSize = packer->Unpack32();
this->encrypt_key = (PBYTE) MemAllocLocal(16);
memcpy(this->encrypt_key, packer->data() + 4 + profileSize, 16);
DecryptRC4(packer->data()+4, profileSize, this->encrypt_key, 16);
```

Практичні наслідки:<sup>[[1]](#references)</sup>
- Уся структура часто міститься в секції PE .rdata.
- Витягування є детермінованим: прочитати розмір, прочитати шифротекст цього розміру, прочитати 16-байтовий ключ, розташований одразу після нього, а потім виконати RC4-дешифрування.

## Процес витягування конфігурації (для захисників)

Напишіть екстрактор, що імітує логіку beacon:<sup>[[1]](#references)</sup>
1) Знайдіть blob у PE (зазвичай у .rdata). Практичний підхід — просканувати .rdata на наявність правдоподібної структури [розмір|шифротекст|16-байтовий ключ] і спробувати виконати RC4.
2) Прочитайте перші 4 байти → розмір (uint32 LE).
3) Прочитайте наступні N=size байтів → шифротекст.
4) Прочитайте останні 16 байтів → ключ RC4.
5) Виконайте RC4-дешифрування шифротексту. Потім розберіть звичайний профіль так:
   - скаляри u32/boolean, як зазначено вище
   - рядки з префіксом довжини (довжина u32, за якою йдуть байти; наприкінці може бути NUL)
   - масиви: servers_count, за яким іде вказана кількість пар [рядок, порт u32]

Мінімальний Python proof-of-concept (самодостатній, без зовнішніх залежностей), що працює з попередньо витягнутим blob:

```python
import struct
from typing import List, Tuple

def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) & 0xFF]
        out.append(b ^ K)
    return bytes(out)

class P:
    def __init__(self, buf: bytes):
        self.b = buf; self.o = 0
    def u32(self) -> int:
        v = struct.unpack_from('<I', self.b, self.o)[0]; self.o += 4; return v
    def u8(self) -> int:
        v = self.b[self.o]; self.o += 1; return v
    def s(self) -> str:
        L = self.u32(); s = self.b[self.o:self.o+L]; self.o += L
        return s[:-1].decode('utf-8','replace') if L and s[-1] == 0 else s.decode('utf-8','replace')

def parse_http_cfg(plain: bytes) -> dict:
    p = P(plain)
    cfg = {}
    cfg['agent_type']    = p.u32()
    cfg['use_ssl']       = bool(p.u8())
    n                    = p.u32()
    cfg['servers']       = []
    cfg['ports']         = []
    for _ in range(n):
        cfg['servers'].append(p.s())
        cfg['ports'].append(p.u32())
    cfg['http_method']   = p.s()
    cfg['uri']           = p.s()
    cfg['parameter']     = p.s()
    cfg['user_agent']    = p.s()
    cfg['http_headers']  = p.s()
    cfg['ans_pre_size']  = p.u32()
    cfg['ans_size']      = p.u32() + cfg['ans_pre_size']
    cfg['kill_date']     = p.u32()
    cfg['working_time']  = p.u32()
    cfg['sleep_delay']   = p.u32()
    cfg['jitter_delay']  = p.u32()
    cfg['listener_type'] = 0
    cfg['download_chunk_size'] = 0x19000
    return cfg

# Usage (when you have [size|ciphertext|key] bytes):
# blob = open('blob.bin','rb').read()
# size = struct.unpack_from('<I', blob, 0)[0]
# ct   = blob[4:4+size]
# key  = blob[4+size:4+size+16]
# pt   = rc4(key, ct)
# cfg  = parse_http_cfg(pt)
```

Поради:
- Для автоматизації використовуйте PE-парсер, щоб прочитати `.rdata`, а потім застосуйте ковзне вікно: для кожного зсуву `o` спробуйте `size = u32(.rdata[o:o+4])`, `ct = .rdata[o+4:o+4+size]`, а наступні 16 байтів вважайте ключем-кандидатом; розшифруйте RC4 і перевірте, чи декодуються рядкові поля як UTF-8 і чи мають довжини прийнятні значення.
- Розбирайте профілі SMB/TCP, дотримуючись тих самих домовленостей щодо довжин із префіксом.

## Власні профілі listener: не обмежуйтеся жорстко заданою класичною HTTP-схемою

Зовнішній формат пакування (`u32 size | RC4 ciphertext | 16-byte key`) можна використовувати повторно, тож у listener, налаштованих зловмисниками, можна застосувати той самий процес вилучення, навіть якщо розташування розшифрованих полів повністю інше.

Гарний нещодавній приклад — кампанія Tropic Trooper у березні 2026 року, під час якої у вилученому Adaptix beacon не було стандартного профілю HTTP/TCP. Натомість розшифрований blob містив параметри GitHub-транспорту, зокрема:<sup>[[5]](#references)</sup>
- `repo_owner`
- `repo_name`
- `api_host` (наприклад, `api.github.com`)
- `auth_token`
- `issues_api_path`
- `kill_date` / `working_time` / `sleep_delay` / `jitter`

Практична стратегія парсера:
- Спочатку виявляйте зовнішній RC4 blob звичним способом.
- Після розшифрування перевіряйте рядки-маркери та коректність полів, а не намагайтеся одразу застосувати HTTP-парсер.
- Корисні маркери: `api.github.com`, `/issues?state=open`, HTTP-методи/URI, рядки у стилі named pipe або очевидно коректні масиви серверів/портів.
- Якщо HTTP-парсер не спрацьовує, але відкритий текст містить узгоджені рядки UTF-8 із префіксами довжини, збережіть зразок і спробуйте альтернативні схеми, а не відкидайте його як хибнопозитивний результат.

У цій кампанії власний listener використовував GitHub issues як транспорт C2, а beacon звертався до `ipinfo.io`, щоб визначити зовнішню IP-адресу, оскільки GitHub API не розкриває оператору адресу джерела запиту жертви безпосередньо.<sup>[[5]](#references)</sup>

## Мережеве профілювання та пошук загроз

HTTP:<sup>[[1]](#references)</sup>
- Типова поведінка: POST-запити до URI, вибраних оператором (наприклад, /uri.php, /endpoint/api)
- Власний параметр заголовка використовується для beacon ID (наприклад, X‑Beacon‑Id, X‑App‑Id)
- User-Agent імітують Firefox 20 або актуальні на той час збірки Chrome
- Періодичність опитування можна визначити за sleep_delay/jitter_delay
- Новіші збірки можуть змінювати URI, user-agent, заголовки Host і сервери між з’єднаннями, тому для кластеризації орієнтуйтеся на рідкісні назви заголовків, шаблони розмірів відповідей, повторне використання TLS і часові інтервали, а не припускайте наявність єдиної пари шлях/UA.<sup>[[2]](#references)</sup>

SMB/TCP:<sup>[[1]](#references)</sup>
- Listener з іменованими каналами SMB для внутрішньомережевого C2, коли вихідний вебтрафік обмежено
- TCP beacons можуть додавати кілька байтів на початок трафіку, щоб приховати початок протоколу

Поточні типові налаштування upstream teamserver
- Зараз у `profile.yaml` використовуються teamserver `0.0.0.0:4321`, endpoint `/endpoint`, назви файлів сертифіката/ключа `server.rsa.crt` і `server.rsa.key`, а також розширення для HTTP, SMB, TCP, DNS, Beacon agent і Gopher.<sup>[[2]](#references)</sup>
- Для маршрутів без відповідності типовий обробник помилок повертає `Server: AdaptixC2` і `Adaptix-Version: v1.2`.<sup>[[4]](#references)</sup>
- Типове тіло відповіді 404 містить `AdaptixC2 404` і `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- У результаті сканування всього інтернету у 2026 році виявлено багато відкритих teamserver на порту `4321` і багато beacon listener на `43211`, тож обидва порти корисні для початкового пошуку, але не вичерпують усі варіанти.<sup>[[4]](#references)</sup>

Відбитки DNS/DoH listener:<sup>[[4]](#references)</sup>
- Поточне розширення BeaconDNS відповідає авторитетно (`AA=true`)
- На запити, що не відповідають формату протоколу beacon — зокрема до імен із менш ніж 5 мітками перед налаштованим доменом — зазвичай надходить відповідь `TXT "OK"`
- Якщо базовий TTL не задано (нульове значення), listener використовує базове значення 10 секунд і додає до 59 секунд випадкового відхилення
- Завдяки цьому активні проби з короткими мітками корисні, коли HTTP listener недоступний

## TTP завантажувачів і механізмів закріплення, виявлені під час інцидентів

Завантажувачі PowerShell, що працюють у пам’яті:<sup>[[1]](#references)</sup>
- Завантажують payload у форматі Base64/XOR (Invoke‑RestMethod / WebClient).<sup>[[9]](#references)</sup>
- Виділяють некеровану пам’ять, копіюють shellcode, змінюють захист пам’яті на 0x40 (PAGE_EXECUTE_READWRITE) за допомогою VirtualProtect.<sup>[[7]](#references)</sup>
- Виконують код через динамічний виклик .NET: Marshal.GetDelegateForFunctionPointer + delegate.Invoke().<sup>[[6]](#references)</sup>

Троянізоване підписане ПЗ / поетапні завантажувачі shellcode:<sup>[[5]](#references)</sup>
- У кампанії Tropic Trooper 2026 року використовувався троянізований виконуваний файл SumatraPDF (завантажувач TOSHIS), який перенаправляв `_security_init_cookie` на шкідливий код замість виправлення точки входу PE
- Завантажувач визначав адреси API за допомогою хешування Adler-32, завантажував PDF-приманку, отримував shellcode другого етапу, розшифровував його за допомогою AES-128-CBC через WinCrypt (`CryptDeriveKey` із жорстко заданого seed) і рефлексивно виконував Adaptix beacon у пам’яті
- Згодом для закріплення почали використовуватися заплановані завдання з назвами, що здаються безпечними, як-от `\MSDNSvc` або `\MicrosoftUDN`, налаштовані на повторний запуск агента приблизно кожні дві години

Перегляньте ці сторінки щодо виконання в пам’яті та особливостей AMSI/ETW:

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Спостережувані механізми закріплення:<sup>[[1]](#references)</sup>
- Ярлик (.lnk) у теці автозавантаження для повторного запуску завантажувача під час входу в систему
- Ключі реєстру Run (HKCU/HKLM ...\CurrentVersion\Run), часто з нешкідливими на вигляд назвами, як-от "Updater", для запуску loader.ps1.<sup>[[10]](#references)</sup>
- Перехоплення порядку пошуку DLL через розміщення msimg32.dll у %APPDATA%\Microsoft\Windows\Templates для вразливих процесів

Поглиблений розгляд технік і перевірки:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/privilege-escalation-with-autorun-binaries.md
{{#endref}}

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

Ідеї для пошуку загроз
- Переходи RW→RX, ініційовані PowerShell: VirtualProtect для встановлення PAGE_EXECUTE_READWRITE у powershell.exe.<sup>[[8]](#references)</sup>
- Шаблони динамічного виклику (GetDelegateForFunctionPointer)
- Невідповідні запитам HTTPS-відповіді 404 із `Server: AdaptixC2`, `Adaptix-Version`, `AdaptixC2 404` або `You need to enter the correct connection details`.<sup>[[4]](#references)</sup>
- DNS-відповіді з `AA=true` і `TXT "OK"` на короткі запити до підозрілих доменів.<sup>[[4]](#references)</sup>
- Трафік до GitHub API за шляхом `/repos/<owner>/<repo>/issues`, за яким ідуть запити до `ipinfo.io` з того самого ланцюжка завантажувача/beacon.<sup>[[5]](#references)</sup>
- Файл .lnk у теках Startup користувача або спільних теках Startup.<sup>[[1]](#references)</sup>
- Підозрілі ключі Run (наприклад, "Updater") і назви завантажувачів на кшталт update.ps1/loader.ps1.<sup>[[1]](#references)</sup>
- Троянізовані зразки PE, які перенаправляють `_security_init_cookie` на код завантажувача перед показом документа-приманки.<sup>[[5]](#references)</sup>
- Шляхи до DLL, доступні для запису користувачу, у %APPDATA%\Microsoft\Windows\Templates, що містять msimg32.dll.<sup>[[1]](#references)</sup>

## Примітки щодо полів OpSec

- KillDate: часова мітка, після якої агент самостійно припиняє роботу.<sup>[[1]](#references)</sup>
- WorkingTime: години, у які агент має бути активним, щоб його поведінка збігалася з робочою активністю.<sup>[[1]](#references)</sup>

Ці поля можна використовувати для кластеризації та пояснення періодів низької активності.

## YARA та статичні ознаки

Unit 42 опублікувала базові правила YARA для beacons (C/C++ і Go) та констант хешування API у завантажувачах.<sup>[[1]](#references)</sup> Доповніть їх правилами для пошуку структури [size|ciphertext|16-byte-key] поблизу кінця PE .rdata, типових рядків HTTP-профілю та новіших маркерів сервера/listener, як-от `AdaptixC2 404`, `You need to enter the correct connection details.`, `Adaptix-Version`, `server.rsa.crt`, `server.rsa.key`, `api.github.com`, `/issues?state=open` і `ipinfo.io`.<sup>[[4]](#references)[[5]](#references)</sup>

## References

- [1] [AdaptixC2: новий фреймворк з відкритим вихідним кодом, що використовується в реальних атаках (Unit 42)](https://unit42.paloaltonetworks.com/adaptixc2-post-exploitation-framework/)
- [2] [AdaptixC2 на GitHub](https://github.com/Adaptix-Framework/AdaptixC2)
- [3] [Документація Adaptix Framework](https://adaptix-framework.gitbook.io/adaptix-framework)
- [4] [AdaptixC2: масштабне профілювання фреймворку C2 з відкритим вихідним кодом (Censys)](https://censys.com/blog/adaptixc2-open-source-c2-framework/)
- [5] [Tropic Trooper переходить на AdaptixC2 і власний Beacon Listener (Zscaler ThreatLabz)](https://www.zscaler.com/blogs/security-research/tropic-trooper-pivots-adaptixc2-and-custom-beacon-listener)
- [6] [Marshal.GetDelegateForFunctionPointer — документація Microsoft](https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.marshal.getdelegateforfunctionpointer)
- [7] [VirtualProtect — документація Microsoft](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
- [8] [Константи захисту пам’яті — документація Microsoft](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [9] [Invoke-RestMethod — PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-restmethod)
- [10] [MITRE ATT&CK T1547.001 — ключі Run реєстру/тека автозавантаження](https://attack.mitre.org/techniques/T1547/001/)
{{#include ../../banners/hacktricks-training.md}}
