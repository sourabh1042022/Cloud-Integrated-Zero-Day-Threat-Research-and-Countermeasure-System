rule Detect_Syscall_Execve
{
    meta:
        author = "Sourabh"
        description = "Detects binaries using syscall execve"
    strings:
        $execve = { 0F 05 } // syscall instruction
        $str1 = "execve"
    condition:
        $execve and $str1
}

rule Detect_Buffer_Overflow_Pattern
{
    meta:
        author = "Sourabh"
        description = "Detects common NOP sled followed by shellcode"
    strings:
        $nops = { 90 90 90 90 90 }
        $shellcode = { EB ?? ?? ?? C0 }
    condition:
        $nops and $shellcode
}

rule Detect_High_Entropy_Section
{
    meta:
        description = "Detects high entropy sections in binaries"
    condition:
        for any section in pe.sections:
            (section.entropy > 7.5)
}

rule Detect_Custom_Backdoor_Keyword
{
    strings:
        $a = "backdoor"
        $b = "reverse_shell"
    condition:
        any of them
}

rule Detect_Unsafe_Functions
{
    meta:
        author = "Sourabh"
        description = "Detects use of unsafe libc functions"
    strings:
        $s1 = "strcpy"
        $s2 = "sprintf"
        $s3 = "gets"
    condition:
        any of ($s*)
}

rule Detect_Static_IPs
{
    strings:
        $ip1 = "192.168.56.101"
        $ip2 = "10.10.10.10"
    condition:
        any of them
}

rule Detect_Persistence_Patterns
{
    strings:
        $runKey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    condition:
        $runKey
}

rule Detect_Encoded_Payload
{
    strings:
        $base64 = /[A-Za-z0-9+/]{100,}={0,2}/
    condition:
        $base64
}

rule Detect_Exec_Memory_Alloc
{
    meta:
        description = "Detects memory allocations with RWX permissions"
    strings:
        $alloc = "mmap"
        $flags = "PROT_READ|PROT_WRITE|PROT_EXEC"
    condition:
        $alloc and $flags
}

rule Detect_Inline_Shellcode
{
    meta:
        description = "Detects x86 inline shellcode patterns"
    strings:
        $s1 = { 31 C0 50 68 2F 2F 73 68 }
    condition:
        $s1
}

rule Detect_Malicious_Kernel_Mod
{
    strings:
        $a = "init_module"
        $b = "finit_module"
    condition:
        any of them
}

rule Detect_Unusual_API_Calls
{
    strings:
        $a = "VirtualAllocEx"
        $b = "CreateRemoteThread"
    condition:
        any of them
}

rule Detect_Hidden_Process_Names
{
    strings:
        $a = "svch0st.exe"
        $b = "ls1ass.exe"
    condition:
        any of them
}

rule Detect_Ghidra_Fingerprint
{
    strings:
        $ghidra = "Ghidra Project"
    condition:
        $ghidra
}

rule Detect_Hardcoded_Token
{
    strings:
        $jwt = /ey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/
    condition:
        $jwt
}
