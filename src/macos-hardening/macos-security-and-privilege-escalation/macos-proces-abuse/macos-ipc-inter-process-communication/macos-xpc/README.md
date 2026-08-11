# macOS XPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Βασικές πληροφορίες

Το XPC είναι ένα framework για **επικοινωνία μεταξύ διεργασιών** σε macOS και iOS. Παρέχει μηχανισμούς για την πραγματοποίηση **ασφαλών, ασύγχρονων κλήσεων μεταξύ διεργασιών**. Το XPC υποστηρίζει **εφαρμογές με διαχωρισμό προνομίων**, όπου κάθε **component** εκτελείται με **μόνο τα δικαιώματα που χρειάζεται**, περιορίζοντας έτσι την πιθανή ζημιά από μια παραβιασμένη διεργασία.<sup>[[1]](#references)</sup>

Το XPC χρησιμοποιεί μια μορφή Inter-Process Communication (IPC), δηλαδή ένα σύνολο μεθόδων που επιτρέπουν σε διαφορετικά προγράμματα τα οποία εκτελούνται στο ίδιο σύστημα να ανταλλάσσουν δεδομένα.

Τα κύρια οφέλη του XPC περιλαμβάνουν:

1. **Ασφάλεια**: Με τον διαχωρισμό της εργασίας σε διαφορετικές διεργασίες, σε κάθε διεργασία μπορούν να παραχωρηθούν μόνο τα δικαιώματα που χρειάζεται. Αυτό σημαίνει ότι ακόμη και αν μια διεργασία παραβιαστεί, έχει περιορισμένη δυνατότητα να προκαλέσει ζημιά.
2. **Σταθερότητα**: Το XPC βοηθά στην απομόνωση των crashes στο component όπου εμφανίζονται. Αν μια διεργασία καταρρεύσει, μπορεί να επανεκκινηθεί χωρίς να επηρεάσει το υπόλοιπο σύστημα.
3. **Απόδοση**: Το XPC επιτρέπει εύκολο concurrency, καθώς διαφορετικές εργασίες μπορούν να εκτελούνται ταυτόχρονα σε διαφορετικές διεργασίες.

Το κύριο **μειονέκτημα** είναι ότι ο **διαχωρισμός μιας εφαρμογής σε πολλές διεργασίες** και η επικοινωνία τους μέσω XPC προσθέτει overhead. Σε σύγχρονα συστήματα, αυτό το overhead είναι συνήθως μικρό σε σύγκριση με τα οφέλη ασφάλειας και σταθερότητας.<sup>[[1]](#references)</sup>

## Application-Specific XPC Services

Τα XPC components μιας εφαρμογής βρίσκονται **μέσα στην ίδια την εφαρμογή**. Για παράδειγμα, στο Safari μπορείτε να τα βρείτε στο **`/Applications/Safari.app/Contents/XPCServices`**. Έχουν την επέκταση **`.xpc`** (όπως το **`com.apple.Safari.SandboxBroker.xpc`**) και είναι **επίσης bundles**, που περιέχουν το κύριο binary και ένα `Info.plist`. Για παράδειγμα: `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker` και `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/Info.plist`.<sup>[[2]](#references)</sup>

Ένα **XPC component μπορεί να έχει διαφορετικά entitlements και privileges** από άλλα XPC components ή από το κύριο binary της εφαρμογής. Εξαίρεση αποτελεί μια XPC service που έχει ρυθμιστεί με **`JoinExistingSession`** σε **`true`** στο αρχείο **Info.plist**. Σε αυτήν την περίπτωση, η XPC service συμμετέχει στην **ίδια security session με την εφαρμογή** που την κάλεσε.<sup>[[4]](#references)</sup>

Οι XPC services **εκκινούνται** από το **launchd** όταν απαιτείται και μπορούν να **τερματιστούν** μόλις οι εργασίες τους **ολοκληρωθούν**, ώστε να απελευθερωθούν πόροι του συστήματος. Τα **application-specific XPC components μπορούν να χρησιμοποιηθούν μόνο από την εφαρμογή που τα περιέχει**, μειώνοντας έτσι την έκθεση σε πιθανές ευπάθειες.<sup>[[2]](#references)</sup>

## System-Wide XPC Services

Οι system-wide XPC services είναι προσβάσιμες εκτός μιας μεμονωμένης εφαρμογής. Αυτές οι Mach services, τις οποίες διαχειρίζεται το launchd, πρέπει να **ορίζονται σε αρχεία plist** που βρίσκονται σε καταλόγους όπως οι **`/System/Library/LaunchDaemons`**, **`/Library/LaunchDaemons`**, **`/System/Library/LaunchAgents`** ή **`/Library/LaunchAgents`**.<sup>[[3]](#references)</sup>

Αυτά τα αρχεία plist διαθέτουν ένα key **`MachServices`** που περιέχει το όνομα της service και ένα key **`Program`** που περιέχει τη διαδρομή προς το binary:
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
Οι υπηρεσίες στο **`LaunchDaemons`** εκτελούνται συνήθως ως root. Επομένως, αν μια unprivileged διεργασία μπορεί να αποκτήσει πρόσβαση σε μια ευάλωτη μέθοδο που εκτίθεται από κάποια από αυτές τις υπηρεσίες, ενδέχεται να μπορέσει να κάνει privilege escalation.

## XPC Objects

- **`xpc_object_t`**

Τα payloads των XPC requests και replies είναι συνήθως dictionary objects, γεγονός που απλοποιεί το serialization και το deserialization. Το `libxpc.dylib` δηλώνει επίσης τους data types που απαιτούνται για την επαλήθευση ότι τα δεδομένα που λαμβάνονται έχουν τον αναμενόμενο type. Στο C API κάθε object είναι ένα `xpc_object_t` (και ο type του μπορεί να ελεγχθεί με χρήση του `xpc_get_type(object)`).<sup>[[2]](#references)</sup>\
Επιπλέον, η συνάρτηση `xpc_copy_description(object)` μπορεί να χρησιμοποιηθεί για τη λήψη μιας string αναπαράστασης του object, η οποία μπορεί να είναι χρήσιμη για debugging.\
Αυτά τα objects διαθέτουν επίσης ορισμένες methods που μπορούν να κληθούν, όπως `xpc_<object>_copy`, `xpc_<object>_equal`, `xpc_<object>_hash`, `xpc_<object>_serialize`, `xpc_<object>_deserialize`...

Τα objects `xpc_object_t` δημιουργούνται με την κλήση μιας συνάρτησης `xpc_<objectType>_create`, η οποία εσωτερικά καλεί τη `_xpc_base_create(Class, Size)`, υποδεικνύοντας την class του object (μία από τις `XPC_TYPE_*`) και το size. Προστίθενται επιπλέον 40 bytes για metadata, επομένως τα δεδομένα του object ξεκινούν σε offset 40 bytes.\
Επομένως, το `xpc_<objectType>_t` είναι κατά κάποιον τρόπο subclass του `xpc_object_t`, το οποίο θα ήταν subclass του `os_object_t*`.

> [!WARNING]
> Σημειώστε ότι ο developer είναι αυτός που πρέπει να χρησιμοποιεί τα `xpc_dictionary_[get/set]_<objectType>` για τη λήψη ή τον ορισμό του type και της πραγματικής value ενός key.

- **`xpc_pipe`**

Ένα **`xpc_pipe`** είναι ένα FIFO pipe που μπορούν να χρησιμοποιούν οι διεργασίες για να επικοινωνούν (η επικοινωνία χρησιμοποιεί Mach messages).\
Μπορεί να δημιουργηθεί ένας XPC server με την κλήση της `xpc_pipe_create()` ή της `xpc_pipe_create_from_port()` για τη δημιουργία του με χρήση ενός συγκεκριμένου Mach port. Στη συνέχεια, για τη λήψη messages, μπορούν να κληθούν οι `xpc_pipe_receive` και `xpc_pipe_try_receive`.

Σημειώστε ότι το object **`xpc_pipe`** είναι ένα **`xpc_object_t`**, με πληροφορίες στο struct του σχετικά με τα δύο Mach ports που χρησιμοποιούνται και το name (αν υπάρχει). Το name, για παράδειγμα, το daemon `secinitd` στο plist `/System/Library/LaunchDaemons/com.apple.secinitd.plist` ρυθμίζει το pipe που ονομάζεται `com.apple.secinitd`.

Ένα παράδειγμα **`xpc_pipe`** είναι το **bootstrap pipe** που δημιουργείται από το **`launchd`**, επιτρέποντας το sharing Mach ports.

- **`NSXPC*`**

Πρόκειται για high-level Objective-C objects που κάνουν abstraction των XPC connections.\
Επιπλέον, είναι ευκολότερο να γίνει debugging αυτών των objects με DTrace από ό,τι των προηγούμενων.

- **`GCD Queues`**

Το XPC χρησιμοποιεί GCD για τη μεταβίβαση messages και, επιπλέον, δημιουργεί συγκεκριμένα dispatch queues όπως `xpc.transactionq`, `xpc.io`, `xpc-events.add-listenerq`, `xpc.service-instance`...

## XPC Services

Πρόκειται για bundles με extension `.xpc`, τα οποία βρίσκονται μέσα στον φάκελο `XPCServices` άλλων projects και στο `Info.plist` έχουν το `CFBundlePackageType` ορισμένο σε **`XPC!`**.\
Αυτό το αρχείο διαθέτει και άλλα configuration keys, όπως το `ServiceType`, το οποίο μπορεί να είναι Application, User ή System· το `_SandboxProfile`, το οποίο μπορεί να ορίζει ένα sandbox· και το `_AllowedClients`, το οποίο μπορεί να υποδεικνύει τα entitlements ή την identity που απαιτούνται για την επικοινωνία με την υπηρεσία. Αυτές και άλλες επιλογές ρυθμίζουν την υπηρεσία κατά την εκκίνησή της.<sup>[[2]](#references)</sup>

### Starting a Service

Η εφαρμογή προσπαθεί να **συνδεθεί** σε μια XPC service χρησιμοποιώντας το `xpc_connection_create_mach_service`· στη συνέχεια το launchd εντοπίζει το daemon και εκκινεί το **`xpcproxy`**. Το **`xpcproxy`** επιβάλλει τους ρυθμισμένους περιορισμούς και δημιουργεί τη service με τα file descriptors και τα Mach ports που παρέχονται.<sup>[[3]](#references)</sup>

Για τη βελτίωση της ταχύτητας αναζήτησης της XPC service χρησιμοποιείται cache.

Μπορείτε να κάνετε trace τις ενέργειες του `xpcproxy` χρησιμοποιώντας:
```bash
supraudit S -C -o /tmp/output /dev/auditpipe
```
Η βιβλιοθήκη XPC χρησιμοποιεί το `kdebug` για την καταγραφή ενεργειών, καλώντας τις `xpc_ktrace_pid0` και `xpc_ktrace_pid1`. Οι κωδικοί που χρησιμοποιεί δεν είναι τεκμηριωμένοι, επομένως πρέπει να προστεθούν στο `/usr/share/misc/trace.codes`. Έχουν το πρόθεμα `0x29`. Για παράδειγμα, το `0x29000004` είναι το `XPC_serializer_pack`.\
Το βοηθητικό πρόγραμμα `xpcproxy` χρησιμοποιεί το πρόθεμα `0x22`. Για παράδειγμα: `0x2200001c: xpcproxy:will_do_preexec`.

## Μηνύματα συμβάντων XPC

Οι εφαρμογές μπορούν να **εγγραφούν** σε διαφορετικά **μηνύματα** συμβάντων, επιτρέποντας την **εκκίνησή τους κατά απαίτηση** όταν συμβαίνουν τέτοια συμβάντα. Η **ρύθμιση** αυτών των υπηρεσιών γίνεται σε **αρχεία plist του launchd**, τα οποία βρίσκονται στους **ίδιους καταλόγους με τα προηγούμενα** και περιέχουν ένα επιπλέον κλειδί **`LaunchEvent`**.

### Έλεγχος διεργασίας που συνδέεται μέσω XPC

Όταν μια διεργασία προσπαθεί να καλέσει μια μέθοδο μέσω μιας σύνδεσης XPC, η **υπηρεσία XPC θα πρέπει να ελέγχει αν επιτρέπεται σε αυτήν τη διεργασία να συνδεθεί**. Ακολουθούν συνήθεις μέθοδοι επαλήθευσης και οι παγίδες τους:


{{#ref}}
macos-xpc-connecting-process-check/
{{#endref}}

## Εξουσιοδότηση XPC

Η Apple επιτρέπει επίσης στις εφαρμογές να **διαμορφώνουν δικαιώματα εξουσιοδότησης και τον τρόπο με τον οποίο οι καλούντες τα αποκτούν**, ώστε μια διεργασία με τα απαιτούμενα δικαιώματα να **επιτρέπεται να καλεί μια μέθοδο** που εκθέτει η υπηρεσία XPC:


{{#ref}}
macos-xpc-authorization.md
{{#endref}}

## XPC Sniffer

Για την υποκλοπή μηνυμάτων XPC, μπορείτε να χρησιμοποιήσετε το **xpcspy**, το οποίο χρησιμοποιεί το **Frida**.<sup>[[5]](#references)</sup>
```bash
# Install
pip3 install xpcspy
pip3 install xpcspy --no-deps # To not make xpcspy install Frida 15 and downgrade your Frida installation

# Start sniffing
xpcspy -U -r -W <bundle-id>
## Using filters (i: for input, o: for output)
xpcspy -U <prog-name> -t 'i:com.apple.*' -t 'o:com.apple.*' -r
```
Ένα ακόμη πιθανό εργαλείο είναι το **XPoCe2**.<sup>[[6]](#references)</sup>

## Παράδειγμα κώδικα επικοινωνίας XPC σε C

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

# Save the server in its configured location
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
## Client μέσα σε ένα Dylib
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

Η λειτουργικότητα που παρέχεται από το `RemoteXPC.framework` (από το `libxpc`) επιτρέπει την επικοινωνία XPC μεταξύ διαφορετικών hosts.\
Οι υπηρεσίες που υποστηρίζουν remote XPC διαθέτουν το κλειδί `UsesRemoteXPC` στο plist τους, όπως συμβαίνει με το `/System/Library/LaunchDaemons/com.apple.SubmitDiagInfo.plist`. Παρόλο που η υπηρεσία είναι καταχωρημένη στο `launchd`, τα plugins `com.apple.remoted.plugin` και `com.apple.remoteservicediscovery.events.plugin` του `UserEventAgent` παρέχουν τη λειτουργικότητα.

Επιπλέον, το `RemoteServiceDiscovery.framework` λαμβάνει πληροφορίες από το `com.apple.remoted.plugin`, εκθέτοντας functions όπως τα `get_device`, `get_unique_device` και `connect`.

Μόλις το `connect` επιστρέψει το socket file descriptor της υπηρεσίας, είναι δυνατή η χρήση της κλάσης `remote_xpc_connection_*`.

Είναι δυνατή η λήψη πληροφοριών σχετικά με remote services με το CLI `/usr/libexec/remotectl`, χρησιμοποιώντας commands όπως:
```bash
/usr/libexec/remotectl list # Get bridge devices
/usr/libexec/remotectl show ...# Get device properties and services
/usr/libexec/remotectl dumpstate # Like dump without indicating a service
/usr/libexec/remotectl [netcat|relay] ... # Expose a service in a port
...
```
Η επικοινωνία μεταξύ του bridgeOS και του host πραγματοποιείται μέσω μιας αποκλειστικής διεπαφής IPv6. Το `MultiverseSupport.framework` δημιουργεί sockets, των οποίων τα file descriptors χρησιμοποιούνται για την επικοινωνία.\
Είναι δυνατός ο εντοπισμός αυτών των επικοινωνιών με τα `netstat`, `nettop` ή την open-source εναλλακτική `netbottom`.

## References

- [1] [Apple Developer — XPC](https://developer.apple.com/documentation/xpc)
- [2] [Apple Developer Archive — Δημιουργία XPC Services](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [3] [Apple Developer — `xpc_connection_create_mach_service`](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service(_:_:_:))
- [4] [Apple Developer — `JoinExistingSession`](https://developer.apple.com/documentation/bundleresources/information_property_list/xpcservice/joinexistingsession)
- [5] [hot3eed/xpcspy](https://github.com/hot3eed/xpcspy)
- [6] [NewOSXBook — XPoCe2](https://newosxbook.com/tools/XPoCe2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
