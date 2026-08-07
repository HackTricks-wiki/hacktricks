# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Το XPC, που σημαίνει XNU (ο kernel που χρησιμοποιείται από το macOS) inter-Process Communication, είναι ένα framework για **επικοινωνία μεταξύ διεργασιών** σε macOS και iOS. Το XPC παρέχει έναν μηχανισμό για την πραγματοποίηση **ασφαλών, ασύγχρονων κλήσεων μεθόδων μεταξύ διαφορετικών διεργασιών** στο σύστημα. Αποτελεί μέρος του security paradigm της Apple, επιτρέποντας τη **δημιουργία εφαρμογών με διαχωρισμένα privileges**, όπου κάθε **component** εκτελείται με **μόνο τα permissions που χρειάζεται** για να κάνει τη δουλειά του, περιορίζοντας έτσι την πιθανή ζημιά από μια compromised διεργασία.

Το XPC χρησιμοποιεί μια μορφή Inter-Process Communication (IPC), δηλαδή ένα σύνολο μεθόδων που επιτρέπουν σε διαφορετικά προγράμματα που εκτελούνται στο ίδιο σύστημα να ανταλλάσσουν δεδομένα.

Τα βασικά οφέλη του XPC περιλαμβάνουν:

1. **Ασφάλεια**: Με τον διαχωρισμό της εργασίας σε διαφορετικές διεργασίες, κάθε διεργασία μπορεί να λαμβάνει μόνο τα permissions που χρειάζεται. Αυτό σημαίνει ότι ακόμη και αν μια διεργασία γίνει compromised, η δυνατότητά της να προκαλέσει ζημιά είναι περιορισμένη.
2. **Σταθερότητα**: Το XPC βοηθά στην απομόνωση των crashes στο component όπου εμφανίζονται. Αν μια διεργασία crashάρει, μπορεί να γίνει restart χωρίς να επηρεαστεί το υπόλοιπο σύστημα.
3. **Απόδοση**: Το XPC επιτρέπει εύκολο concurrency, καθώς διαφορετικές εργασίες μπορούν να εκτελούνται ταυτόχρονα σε διαφορετικές διεργασίες.

Το μοναδικό **μειονέκτημα** είναι ότι ο **διαχωρισμός μιας εφαρμογής σε πολλές διεργασίες**, οι οποίες επικοινωνούν μέσω XPC, είναι **λιγότερο αποδοτικός**. Ωστόσο, στα σημερινά συστήματα αυτό σχεδόν δεν γίνεται αντιληπτό και τα οφέλη είναι μεγαλύτερα.

## Application Specific XPC services

Τα XPC components μιας εφαρμογής βρίσκονται **μέσα στην ίδια την εφαρμογή**. Για παράδειγμα, στο Safari μπορείς να τα βρεις στο **`/Applications/Safari.app/Contents/XPCServices`**. Έχουν την επέκταση **`.xpc`** (όπως το **`com.apple.Safari.SandboxBroker.xpc`**) και είναι **επίσης bundles**, με το κύριο binary στο εσωτερικό τους: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` και ένα `Info.plist: /Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`

Όπως ίσως σκέφτεσαι, ένα **XPC component θα έχει διαφορετικά entitlements και privileges** από τα άλλα XPC components ή από το κύριο binary της εφαρμογής. ΕΞΑΙΡΕΣΗ αποτελεί η περίπτωση όπου ένα XPC service έχει ρυθμιστεί με [**JoinExistingSession**](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession) σε “True” στο αρχείο **`Info.plist`**. Σε αυτή την περίπτωση, το XPC service θα εκτελείται στην **ίδια security session με την εφαρμογή** που το κάλεσε.

Τα XPC services **ξεκινούν** από το **launchd** όταν απαιτείται και **τερματίζονται** μόλις ολοκληρωθούν όλες οι **εργασίες**, ώστε να απελευθερώνονται system resources. Τα **application-specific XPC components μπορούν να χρησιμοποιηθούν μόνο από την εφαρμογή**, μειώνοντας έτσι τον κίνδυνο που σχετίζεται με πιθανά vulnerabilities.

## System Wide XPC services

Τα system-wide XPC services είναι προσβάσιμα από όλους τους χρήστες. Αυτές οι υπηρεσίες, είτε τύπου launchd είτε τύπου Mach, πρέπει να **ορίζονται σε αρχεία plist** που βρίσκονται σε συγκεκριμένους καταλόγους, όπως οι **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** ή **`/Library/LaunchAgents`**.

Αυτά τα αρχεία plist θα περιέχουν ένα key που ονομάζεται **`MachServices`** με το όνομα του service και ένα key που ονομάζεται **`Program`** με τη διαδρομή προς το binary:
```xml
cat /Library/LaunchDaemons/com.jamf.management.daemon.plist

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Program</key>
<string>/Library/Application Support/JAMF/Jamf.app/Contents/MacOS/JamfDaemon.app/Contents/MacOS/JamfDaemon</string>
<key>AbandonProcessGroup</key>
<true/>
<key>KeepAlive</key>
<true/>
<key>Label</key>
<string>com.jamf.management.daemon</string>
<key>MachServices</key>
<dict>
<key>com.jamf.management.daemon.aad</key>
<true/>
<key>com.jamf.management.daemon.agent</key>
<true/>
<key>com.jamf.management.daemon.binary</key>
<true/>
<key>com.jamf.management.daemon.selfservice</key>
<true/>
<key>com.jamf.management.daemon.service</key>
<true/>
</dict>
<key>RunAtLoad</key>
<true/>
</dict>
</plist>
```
Αυτά στο **`LaunchDameons`** εκτελούνται από τον root. Επομένως, αν μια unprivileged process μπορεί να επικοινωνήσει με κάποιο από αυτά, θα μπορούσε να κάνει escalate privileges.

## XPC Objects

- **`xpc_object_t`**

Κάθε XPC message είναι ένα dictionary object που απλοποιεί το serialization και το deserialization. Επιπλέον, το `libxpc.dylib` δηλώνει τους περισσότερους data types, επομένως είναι δυνατό να διασφαλιστεί ότι τα δεδομένα που λαμβάνονται είναι του αναμενόμενου type. Στο C API κάθε object είναι ένα `xpc_object_t` (και το type του μπορεί να ελεγχθεί χρησιμοποιώντας το `xpc_get_type(object)`).\
Επιπλέον, η function `xpc_copy_description(object)` μπορεί να χρησιμοποιηθεί για τη λήψη μιας string representation του object, η οποία μπορεί να είναι χρήσιμη για debugging.\
Αυτά τα objects διαθέτουν επίσης methods που μπορούν να κληθούν, όπως `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Τα `xpc_object_t` δημιουργούνται με την κλήση της function `xpc_<objetType>_create`, η οποία εσωτερικά καλεί την `_xpc_base_create(Class, Size)`, όπου υποδεικνύονται το type της class του object (ένα από τα `XPC_TYPE_*`) και το size του (θα προστεθούν επιπλέον 40B στο size για metadata). Αυτό σημαίνει ότι τα δεδομένα του object θα ξεκινούν στο offset 40B.\
Επομένως, το `xpc_<objectType>_t` είναι ένα είδος subclass του `xpc_object_t`, το οποίο θα ήταν subclass του `os_object_t*`.

> [!WARNING]
> Σημειώστε ότι ο developer είναι αυτός που πρέπει να χρησιμοποιεί τα `xpc_dictionary_[get/set]_<objectType>` για να λαμβάνει ή να ορίζει το type και την πραγματική value ενός key.

- **`xpc_pipe`**

Ένα **`xpc_pipe`** είναι ένα FIFO pipe που μπορούν να χρησιμοποιούν οι processes για να επικοινωνούν (η επικοινωνία χρησιμοποιεί Mach messages).\
Είναι δυνατό να δημιουργηθεί ένας XPC server με την κλήση των `xpc_pipe_create()` ή `xpc_pipe_create_from_port()`, ώστε να δημιουργηθεί χρησιμοποιώντας ένα συγκεκριμένο Mach port. Στη συνέχεια, για τη λήψη messages, είναι δυνατό να κληθούν οι `xpc_pipe_receive` και `xpc_pipe_try_receive`.

Σημειώστε ότι το object **`xpc_pipe`** είναι ένα **`xpc_object_t`**, με information στο struct του σχετικά με τα δύο Mach ports που χρησιμοποιούνται και το name (αν υπάρχει). Το name, για παράδειγμα, το daemon `secinitd` στο plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` ρυθμίζει το pipe που ονομάζεται `com.apple.secinitd`.

Ένα παράδειγμα **`xpc_pipe`** είναι το **bootstrap pip**e** που δημιουργείται από το **`launchd`**, επιτρέποντας την κοινή χρήση Mach ports.

- **`NSXPC*`**

Αυτά είναι Objective-C high-level objects που επιτρέπουν την abstraction των XPC connections.\
Επιπλέον, είναι ευκολότερο να γίνει debugging αυτών των objects με DTrace σε σχέση με τα προηγούμενα.

- **`GCD Queues`**

Το XPC χρησιμοποιεί GCD για τη μεταφορά messages και, επιπλέον, δημιουργεί ορισμένα dispatch queues, όπως τα `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Services

Αυτά είναι **bundles με επέκταση `.xpc`** που βρίσκονται μέσα στον φάκελο `XPCServices` άλλων projects και στο `Info.plist` έχουν το `CFBundlePackageType` ορισμένο ως **`XPC!`**.\
Αυτό το file έχει και άλλα configuration keys, όπως το `ServiceType`, το οποίο μπορεί να είναι Application, User ή System, ή το `_SandboxProfile`, το οποίο μπορεί να ορίσει ένα sandbox, ή το `_AllowedClients`, το οποίο μπορεί να υποδεικνύει entitlements ή ID που απαιτούνται για την επικοινωνία με το service. Αυτές και άλλες configuration options είναι χρήσιμες για τη ρύθμιση του service κατά την εκκίνησή του.

### Εκκίνηση ενός Service

Η εφαρμογή προσπαθεί να **συνδεθεί** σε ένα XPC service χρησιμοποιώντας το `xpc_connection_create_mach_service`, έπειτα το launchd εντοπίζει το daemon και εκκινεί το **`xpcproxy`**. Το **`xpcproxy`** επιβάλλει τους ρυθμισμένους περιορισμούς και εκκινεί το service με τα παρεχόμενα FDs και Mach ports.

Για τη βελτίωση της ταχύτητας αναζήτησης του XPC service, χρησιμοποιείται cache.

Είναι δυνατό να γίνει trace των ενεργειών του `xpcproxy` χρησιμοποιώντας:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
Η βιβλιοθήκη XPC χρησιμοποιεί το `kdebug` για την καταγραφή ενεργειών, καλώντας τις `xpc_ktrace_pid0` και `xpc_ktrace_pid1`. Οι κωδικοί που χρησιμοποιεί δεν είναι τεκμηριωμένοι, επομένως πρέπει να προστεθούν στο `/usr/share/misc/trace.codes`. Έχουν το πρόθεμα `0x29` και, για παράδειγμα, ένας από αυτούς είναι ο `0x29000004`: `XPC_serializer_pack`.\
Το βοηθητικό πρόγραμμα `xpcproxy` χρησιμοποιεί το πρόθεμα `0x22`, για παράδειγμα: `0x2200001c: xpcproxy:will_do_preexec`.

## Μηνύματα συμβάντων XPC

Οι εφαρμογές μπορούν να **εγγραφούν** σε διαφορετικά **μηνύματα** συμβάντων, επιτρέποντας την **εκκίνησή τους κατόπιν απαίτησης** όταν συμβαίνουν τέτοια συμβάντα. Η **διαμόρφωση** αυτών των υπηρεσιών γίνεται σε αρχεία **`LaunchEvent`** των **launchd plist**, τα οποία βρίσκονται στους **ίδιους καταλόγους με τα προηγούμενα** και περιέχουν ένα επιπλέον κλειδί **`LaunchEvent`**.

### Έλεγχος διαδικασίας σύνδεσης XPC

Όταν μια διαδικασία προσπαθεί να καλέσει μια μέθοδο μέσω μιας σύνδεσης XPC, η **υπηρεσία XPC πρέπει να ελέγχει αν επιτρέπεται σε αυτήν τη διαδικασία να συνδεθεί**. Ακολουθούν οι συνηθισμένοι τρόποι ελέγχου και οι συνηθισμένες παγίδες:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Εξουσιοδότηση XPC

Η Apple επιτρέπει επίσης στις εφαρμογές να **διαμορφώνουν ορισμένα δικαιώματα και τον τρόπο απόκτησής τους**, έτσι ώστε, αν η καλούσα διαδικασία τα διαθέτει, να **επιτρέπεται να καλέσει μια μέθοδο** από την υπηρεσία XPC:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

Για να παρακολουθήσετε τα μηνύματα XPC, μπορείτε να χρησιμοποιήσετε το [**xpcspy**](https://github.com/hot3eed/xpcspy), το οποίο χρησιμοποιεί **Frida**.
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Ένα ακόμη πιθανό εργαλείο που μπορείτε να χρησιμοποιήσετε είναι το [**XPoCe2**](https://newosxbook.com/tools/XPoCe2.html).

## Παράδειγμα κώδικα C επικοινωνίας XPC

{{#tabs}}
{{#tab name="xpc_server.c"}}
```c
// gcc xpc_server.c -o xpc_server

#include <xpc/xpc.h>

static void handle_event(xpc_object_t event) {
if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
// Print received message
const char* received_message = xpc_dictionary_get_string(event, "message");
printf("Received message: %s\n", received_message);

// Create a response dictionary
xpc_object_t response = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_string(response, "received", "received");

// Send response
xpc_connection_t remote = xpc_dictionary_get_remote_connection(event);
xpc_connection_send_message(remote, response);

// Clean up
xpc_release(response);
}
}

static void handle_connection(xpc_connection_t connection) {
xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
handle_event(event);
});
xpc_connection_resume(connection);
}

int main(int argc, const char *argv[]) {
xpc_connection_t service = xpc_connection_create_mach_service("xyz.hacktricks.service",
dispatch_get_main_queue(),
XPC_CONNECTION_MACH_SERVICE_LISTENER);
if (!service) {
fprintf(stderr, "Failed to create service.\n");
exit(EXIT_FAILURE);
}

xpc_connection_set_event_handler(service, ^(xpc_object_t event) {
xpc_type_t type = xpc_get_type(event);
if (type == XPC_TYPE_CONNECTION) {
handle_connection(event);
}
});

xpc_connection_resume(service);
dispatch_main();

return 0;
}
```
{{#endtab}}

{{#tab name="xpc_client.c"}}
```c
// gcc xpc_client.c -o xpc_client

#include <xpc/xpc.h>

int main(int argc, const char *argv[]) {
xpc_connection_t connection = xpc_connection_create_mach_service("xyz.hacktricks.service", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);

xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
// Print received message
const char* received_message = xpc_dictionary_get_string(event, "received");
printf("Received message: %s\n", received_message);
}
});

xpc_connection_resume(connection);

xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_string(message, "message", "Hello, Server!");

xpc_connection_send_message(connection, message);

dispatch_main();

return 0;
}
```
{{#endtab}}

{{#tab name="xyz.hacktricks.service.plist"}}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.service</string>
<key>MachServices</key>
<dict>
<key>xyz.hacktricks.service</key>
<true/>
</dict>
<key>Program</key>
<string>/tmp/xpc_server</string>
<key>ProgramArguments</key>
<array>
<string>/tmp/xpc_server</string>
</array>
</dict>
</plist>
```
{{#endtab}}
{{#endtabs}}
```bash
# Compile the server & client
gcc xpc_server.c -o xpc_server
gcc xpc_client.c -o xpc_client

# Save server on it's location
cp xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.service.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.service.plist

# Call client
./xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.service.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.service.plist /tmp/xpc_server
```
## Παράδειγμα κώδικα επικοινωνίας XPC σε Objective-C

{{#tabs}}
{{#tab name="oc_xpc_server.m"}}
```objectivec
// gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

@interface MyXPCObject : NSObject <MyXPCProtocol>
@end


@implementation MyXPCObject
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply {
NSLog(@"Received message: %@", some_string);
NSString *response = @"Received";
reply(response);
}
@end

@interface MyDelegate : NSObject <NSXPCListenerDelegate>
@end


@implementation MyDelegate

- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection {
newConnection.exportedInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];

MyXPCObject *my_object = [MyXPCObject new];

newConnection.exportedObject = my_object;

[newConnection resume];
return YES;
}
@end

int main(void) {

NSXPCListener *listener = [[NSXPCListener alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc"];

id <NSXPCListenerDelegate> delegate = [MyDelegate new];
listener.delegate = delegate;
[listener resume];

sleep(10); // Fake something is done and then it ends
}
```
{{#endtab}}

{{#tab name="oc_xpc_client.m"}}
```objectivec
// gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client
#include <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

int main(void) {
NSXPCConnection *connection = [[NSXPCConnection alloc] initWithMachServiceName:@"xyz.hacktricks.svcoc" options:NSXPCConnectionPrivileged];
connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)];
[connection resume];

[[connection remoteObjectProxy] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
NSLog(@"Received response: %@", response);
}];

[[NSRunLoop currentRunLoop] run];

return 0;
}
```
{{#endtab}}

{{#tab name="xyz.hacktricks.svcoc.plist"}}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"> <plist version="1.0">
<dict>
<key>Label</key>
<string>xyz.hacktricks.svcoc</string>
<key>MachServices</key>
<dict>
<key>xyz.hacktricks.svcoc</key>
<true/>
</dict>
<key>Program</key>
<string>/tmp/oc_xpc_server</string>
<key>ProgramArguments</key>
<array>
<string>/tmp/oc_xpc_server</string>
</array>
</dict>
</plist>
```
{{#endtab}}
{{#endtabs}}
```bash
# Compile the server & client
gcc -framework Foundation oc_xpc_server.m -o oc_xpc_server
gcc -framework Foundation oc_xpc_client.m -o oc_xpc_client

# Save server on it's location
cp oc_xpc_server /tmp

# Load daemon
sudo cp xyz.hacktricks.svcoc.plist /Library/LaunchDaemons
sudo launchctl load /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist

# Call client
./oc_xpc_client

# Clean
sudo launchctl unload /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist
sudo rm /Library/LaunchDaemons/xyz.hacktricks.svcoc.plist /tmp/oc_xpc_server
```
## Client μέσα σε κώδικα Dylb
```objectivec
// gcc -dynamiclib -framework Foundation oc_xpc_client.m -o oc_xpc_client.dylib
// gcc injection example:
// DYLD_INSERT_LIBRARIES=oc_xpc_client.dylib /path/to/vuln/bin

#import <Foundation/Foundation.h>

@protocol MyXPCProtocol
- (void)sayHello:(NSString *)some_string withReply:(void (^)(NSString *))reply;
@end

__attribute__((constructor))
static void customConstructor(int argc, const char **argv)
{
NSString*  _serviceName = @"xyz.hacktricks.svcoc";

NSXPCConnection* _agentConnection = [[NSXPCConnection alloc] initWithMachServiceName:_serviceName options:4096];

[_agentConnection setRemoteObjectInterface:[NSXPCInterface interfaceWithProtocol:@protocol(MyXPCProtocol)]];

[_agentConnection resume];

[[_agentConnection remoteObjectProxyWithErrorHandler:^(NSError* error) {
(void)error;
NSLog(@"Connection Failure");
}] sayHello:@"Hello, Server!" withReply:^(NSString *response) {
NSLog(@"Received response: %@", response);
}    ];
NSLog(@"Done!");

return;
}
```
## Remote XPC

Αυτή η λειτουργικότητα που παρέχεται από το `RemoteXPC.framework` (από το `libxpc`) επιτρέπει την επικοινωνία μέσω XPC μεταξύ διαφορετικών hosts.\
Οι υπηρεσίες που υποστηρίζουν remote XPC θα έχουν στο plist τους το key `UsesRemoteXPC`, όπως συμβαίνει στην περίπτωση του `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Ωστόσο, παρόλο που η υπηρεσία θα είναι registered με το `launchd`, είναι το `UserEventAgent` με τα plugins `com.apple.remoted.plugin` και `com.apple.remoteservicediscovery.events.plugin` αυτό που παρέχει τη λειτουργικότητα.

Επιπλέον, το `RemoteServiceDiscovery.framework` επιτρέπει τη λήψη πληροφοριών από το `com.apple.remoted.plugin`, εκθέτοντας functions όπως `get_device`, `get_unique_device`, `connect`...

Μόλις χρησιμοποιηθεί το `connect` και ληφθεί το socket `fd` της υπηρεσίας, είναι δυνατή η χρήση της κλάσης `remote_xpc_connection_*`.

Είναι δυνατή η λήψη πληροφοριών σχετικά με remote services χρησιμοποιώντας το cli tool `/usr/libexec/remotectl` με parameters όπως:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump withuot indicateing a servie
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
Η επικοινωνία μεταξύ του BridgeOS και του host πραγματοποιείται μέσω μιας αποκλειστικής διεπαφής IPv6. Το `MultiverseSupport.framework` επιτρέπει τη δημιουργία sockets των οποίων το `fd` χρησιμοποιείται για την επικοινωνία.\
Είναι δυνατός ο εντοπισμός αυτών των επικοινωνιών με χρήση των `netstat`, `nettop` ή της open source επιλογής `netbottom`.

{{#include ../../../../../banners/hacktricks-training.md}}
