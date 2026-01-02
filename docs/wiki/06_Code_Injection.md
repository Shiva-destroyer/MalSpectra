# Module 6: Code Injection Framework

## Overview

The Code Injection Framework implements Linux process injection using the ptrace system call. It allows you to inject shellcode into running processes for testing, debugging, and security research purposes. This module provides a controlled environment for studying process memory manipulation techniques.

**Developer**: Sai Srujan Murthy  
**Email**: saisrujanmurthy@gmail.com  
**Status**: Production Ready ⚠️ ROOT REQUIRED

---

## ⚠️ CRITICAL WARNING ⚠️

### THIS MODULE REQUIRES ROOT PRIVILEGES

**RISKS**:
- Process corruption and crashes
- System instability
- Security implications
- Potential data loss
- Kernel panics (if misused)

**USE ONLY**:
- For educational purposes
- In isolated test environments
- With processes you own
- With harmless test payloads
- After proper authorization

**DO NOT**:
- Inject into system processes
- Use on production systems
- Use malicious shellcode
- Attack systems without permission
- Bypass security controls

---

## Features

- **ptrace Integration**: Native Linux process debugging interface
- **Register Manipulation**: Read/write CPU registers
- **Memory Writing**: Inject code into process memory
- **Safe Payloads**: Harmless test shellcode (NOP, INT3, RET)
- **Process Selection**: Interactive process list
- **Safety Checks**: Root verification, process validation
- **User Confirmation**: Multi-level authorization workflow

---

## Technical Details

### Components

#### 1. payloads.py (Payloads Class)

**Purpose**: Collection of test shellcode

**Available Payloads**:

| Payload | Hex | Description | Safe |
|---------|-----|-------------|------|
| `nop_sled` | `90 90 90 90 90 90 90 90 90 90` | 10 NOP instructions | ✓ |
| `int3_trap` | `CC` | Debugger breakpoint | ✓ |
| `ret` | `C3` | Simple return instruction | ✓ |
| `nop_ret` | `90 90 90 90 C3` | NOPs + return | ✓ |

**Methods**:
- `get_available_payloads()`: List payload names
- `get_payload(name)`: Get payload dictionary
- `get_payload_bytes(name)`: Get raw bytes

#### 2. injector.py (ProcessInjector Class)

**Purpose**: ptrace-based injection engine

**Key Methods**:

- `check_root()`: Verify root privileges (required for ptrace)
- `check_process_exists(pid)`: Validate PID
- `attach(pid)`: Attach to process using PTRACE_ATTACH
- `detach()`: Detach with PTRACE_DETACH
- `get_registers()`: Read CPU registers (PTRACE_GETREGS)
- `set_registers(regs)`: Write CPU registers (PTRACE_SETREGS)
- `write_memory(address, data)`: Write bytes using PTRACE_POKETEXT
- `inject_shellcode(pid, shellcode)`: Complete injection workflow

#### 3. main.py (User Interface)

**Purpose**: Interactive injection workflow

**Safety Features**:
- Multiple confirmation prompts
- BRIGHT RED warning display
- Root privilege checking
- Process ownership verification
- Only shows user's processes

**Workflow**:
1. Display banner and safety warning
2. Check root privileges
3. Require explicit "YES" confirmation
4. List user's processes
5. User selects target PID
6. Display available payloads
7. User selects payload
8. Final confirmation before injection
9. Perform injection
10. Display result

---

## ptrace System Call

### What is ptrace?

**ptrace** is a Linux system call that enables one process to observe and control another process. It's the foundation for debuggers like gdb.

### ptrace Operations

```c
#include <sys/ptrace.h>

// Attach to process
ptrace(PTRACE_ATTACH, pid, NULL, NULL);

// Wait for process to stop
waitpid(pid, &status, 0);

// Read registers
ptrace(PTRACE_GETREGS, pid, NULL, &regs);

// Write memory
ptrace(PTRACE_POKETEXT, pid, address, data);

// Detach from process
ptrace(PTRACE_DETACH, pid, NULL, NULL);
```

### Register Structure (x86-64)

```c
struct user_regs_struct {
    unsigned long long r15, r14, r13, r12;
    unsigned long long rbp, rbx;
    unsigned long long r11, r10, r9, r8;
    unsigned long long rax, rcx, rdx, rsi, rdi;
    unsigned long long orig_rax;
    unsigned long long rip;  // Instruction pointer
    unsigned long long cs;
    unsigned long long eflags;
    unsigned long long rsp;  // Stack pointer
    unsigned long long ss;
    // ... more fields
};
```

---

## Injection Algorithm

### High-Level Flow

```
1. Check root privileges
   ↓
2. Attach to target process (PTRACE_ATTACH)
   ↓
3. Wait for process to stop (waitpid)
   ↓
4. Read current registers (PTRACE_GETREGS)
   ↓
5. Get instruction pointer (RIP)
   ↓
6. Write shellcode at RIP (PTRACE_POKETEXT)
   ↓
7. Detach from process (PTRACE_DETACH)
   ↓
8. Process resumes execution with injected code
```

### Memory Writing

```
Shellcode: 90 90 90 C3 (NOP NOP NOP RET)

1. Pad to 8-byte boundary: 90 90 90 C3 00 00 00 00
2. Convert to 64-bit word: 0x00000000C3909090
3. Write to memory: PTRACE_POKETEXT(pid, address, word)
```

### Word-by-Word Writing

ptrace writes in machine word (8 bytes on x86-64):

```python
for i in range(0, len(data), 8):
    word = int.from_bytes(data[i:i+8], 'little')
    ptrace(PTRACE_POKETEXT, pid, address + i, word)
```

---

## Usage

### Prerequisites

```bash
# Must run as root
sudo python3 main.py
```

### Basic Workflow

```bash
# 1. Start MalSpectra as root
sudo python3 main.py

# 2. Select Module 6 (Code Injection)

# 3. Read safety warning carefully

# 4. Type "YES" to confirm

# 5. Select target process from list

# 6. Select payload (e.g., nop_sled)

# 7. Confirm injection

# 8. View result
```

### Example Session

```
═══ CODE INJECTION FRAMEWORK (PTRACE) ═══

⚠️  CRITICAL WARNING ⚠️

This module requires ROOT privileges!

RISKS:
• Process corruption
• System instability
• Security implications

DO NOT:
• Inject into system processes
• Use on production systems

✓ Running as root

Do you understand the risks?
Type 'YES' to confirm: YES

✓ Authorization confirmed

Scanning for your processes...

═══ YOUR PROCESSES ═══

┏━━━┳━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━┓
┃ # ┃ PID  ┃ Process Name ┃ User  ┃
┡━━━╇━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━┩
│ 1 │ 1234 │ python3      │ user  │
│ 2 │ 5678 │ bash         │ user  │
└───┴──────┴──────────────┴───────┘

Select process number: 1
✓ Selected PID: 1234

═══ AVAILABLE PAYLOADS ═══

┏━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┳━━━━━━┓
┃ # ┃ Name             ┃ Description         ┃ Size ┃
┡━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━╇━━━━━━┩
│ 1 │ NOP Sled         │ 10 NOP instructions │ 10 B │
│ 2 │ INT3 Trap        │ Debugger breakpoint │ 1 B  │
│ 3 │ RET Instruction  │ Simple return       │ 1 B  │
└───┴──────────────────┴─────────────────────┴──────┘

Select payload: 1
✓ Selected payload: NOP Sled (10 NOPs)
Size: 10 bytes
Hex: 90909090909090909090

⚠️  Ready to inject shellcode!
Target PID: 1234
Payload: NOP Sled

Proceed? [y/n] y

Injecting shellcode...
Attaching to PID 1234...

✓ Injection successful!

╔═══════════════════════════════╗
║      Injection Complete       ║
╠═══════════════════════════════╣
║ Target PID: 1234              ║
║ Payload: NOP Sled             ║
║ Size: 10 bytes                ║
║ Status: Success               ║
╚═══════════════════════════════╝
```

---

## Payload Details

### NOP Sled (0x90)

**Purpose**: No operation instructions  
**Effect**: CPU continues to next instruction  
**Use**: Safe testing, padding, alignment

```asm
nop    ; 0x90
nop    ; 0x90
nop    ; 0x90
...
```

### INT3 Trap (0xCC)

**Purpose**: Software breakpoint  
**Effect**: Triggers debugger, process stops  
**Use**: Testing debugger response, controlled stopping

```asm
int3   ; 0xCC
```

### RET (0xC3)

**Purpose**: Return from function  
**Effect**: Pops return address and jumps  
**Use**: Early function exit, stack manipulation test

```asm
ret    ; 0xC3
```

### NOP + RET Combination

**Purpose**: Safe multi-byte payload  
**Effect**: NOPs execute, then return  
**Use**: Testing larger payloads safely

```asm
nop    ; 0x90
nop    ; 0x90
nop    ; 0x90
nop    ; 0x90
ret    ; 0xC3
```

---

## Use Cases

### 1. Security Research
Study process injection techniques used by malware and rootkits.

### 2. Debugger Development
Understand how debuggers inject breakpoints and control flow.

### 3. Memory Forensics
Practice memory analysis and injection detection.

### 4. Exploit Development
Learn exploitation primitives for educational purposes.

### 5. Reverse Engineering
Test code injection as part of dynamic analysis.

### 6. Sandbox Testing
Develop injection detection mechanisms.

---

## Advanced Techniques

### Custom Shellcode

Add custom payloads to `payloads.py`:

```python
PAYLOADS_X64 = {
    'custom_print': {
        'name': 'Custom Print',
        'description': 'Prints message via syscall',
        'bytes': b'\x48\x31\xc0\x48\x31\xff...',
        'safe': True
    }
}
```

### Register Manipulation

Modify registers before injection:

```python
regs = injector.get_registers()
regs.rip = new_address  # Change instruction pointer
regs.rsp = new_stack    # Change stack pointer
injector.set_registers(regs)
```

### Memory Dumping

Read process memory before injection:

```python
def read_memory(pid, address, length):
    data = []
    for i in range(0, length, 8):
        word = libc.ptrace(PTRACE_PEEKTEXT, pid, address + i, None)
        data.extend(word.to_bytes(8, 'little'))
    return bytes(data[:length])

# Dump first 64 bytes
original_code = read_memory(pid, rip, 64)
```

### Injection with Execution Control

```python
# Attach
injector.attach(pid)

# Save original code
regs = injector.get_registers()
original_rip = regs.rip
original_code = read_memory(pid, original_rip, len(shellcode))

# Inject shellcode
injector.write_memory(original_rip, shellcode)

# Single-step execution (PTRACE_SINGLESTEP)
# ... advanced control ...

# Restore original code
injector.write_memory(original_rip, original_code)

# Detach
injector.detach()
```

---

## Security Implications

### Detection Methods

**How to detect injection**:

1. **ptrace Protection**: Check `/proc/self/status` for `TracerPid`
2. **Memory Monitoring**: Watch for unexpected code changes
3. **Syscall Monitoring**: Detect ptrace usage with seccomp
4. **Integrity Checking**: Periodic memory checksums

**Example Detection Code**:

```c
// Check if being traced
#include <sys/ptrace.h>

if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
    printf("Debugger detected!\n");
    exit(1);
}
```

### Prevention Methods

1. **Yama LSM**: Linux Security Module restricts ptrace
   ```bash
   # Check Yama setting
   cat /proc/sys/kernel/yama/ptrace_scope
   
   # 0 = Classic ptrace (unrestricted)
   # 1 = Restricted ptrace
   # 2 = Admin-only
   # 3 = No ptrace
   ```

2. **SELinux/AppArmor**: Mandatory Access Control
3. **Seccomp**: Syscall filtering
4. **Code Signing**: Verify executable integrity

---

## Limitations

### Technical Limitations
- **Root required**: Must have superuser privileges
- **ptrace limitations**: One tracer per process
- **Architecture-specific**: x86-64 focused
- **Word alignment**: Writes must be 8-byte aligned
- **Process state**: Target may crash or behave unpredictably

### Security Limitations
- **Detection possible**: Can be detected by target
- **Protection mechanisms**: Modern systems have safeguards
- **Limited scope**: Only works on processes you can trace
- **Logging**: Kernel logs ptrace activity

### Platform Limitations
- **Linux-only**: Won't work on Windows/macOS
- **Kernel version**: Behavior varies by kernel
- **Containers**: Limited in containerized environments

---

## Troubleshooting

### "Operation not permitted"

**Causes**:
1. Not running as root
2. Yama ptrace_scope too restrictive
3. Target process protected by security policy

**Solutions**:
```bash
# Run as root
sudo python3 main.py

# Check Yama
cat /proc/sys/kernel/yama/ptrace_scope

# Temporarily disable (DANGEROUS)
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```

### "Process not found"

**Cause**: PID invalid or process terminated  
**Solution**: Select different process from list

### "Injection succeeded but process crashed"

**Cause**: Shellcode corrupted execution state  
**Solution**: Use safer payloads (NOP, RET), avoid critical processes

### "Cannot attach to process"

**Causes**:
1. Process already being traced
2. Process is a kernel thread
3. Insufficient permissions

**Debug**:
```bash
# Check if process is traced
cat /proc/<PID>/status | grep TracerPid

# TracerPid: 0 means not traced
# TracerPid: <N> means traced by PID N
```

---

## Best Practices

### 1. Always Test in VM
Create disposable VM for testing, take snapshots

### 2. Use Safe Payloads
Start with NOPs and simple instructions

### 3. Target Test Processes
Create dedicated test programs, don't target system processes

### 4. Understand Consequences
Know what your shellcode does before injection

### 5. Log Everything
Keep detailed logs of injections for analysis

### 6. Proper Cleanup
Always detach from process, restore state if possible

### 7. Legal Compliance
Only inject into processes you own, with proper authorization

---

## Example Test Program

### Create Target Process

```python
# test_injection_target.py
import time
import sys

def main():
    print("Test injection target started")
    print(f"PID: {os.getpid()}")
    print("Waiting for injection... (Ctrl+C to stop)")
    
    try:
        while True:
            time.sleep(1)
            sys.stdout.write(".")
            sys.stdout.flush()
    except KeyboardInterrupt:
        print("\nTarget stopped")

if __name__ == "__main__":
    main()
```

### Run Target

```bash
# Terminal 1: Start target
python3 test_injection_target.py
# Note the PID

# Terminal 2: Inject (as root)
sudo python3 main.py
# Select Module 6
# Select the target PID
# Inject NOP payload
```

---

## References

- **ptrace man page**: https://man7.org/linux/man-pages/man2/ptrace.2.html
- **Process Injection**: https://attack.mitre.org/techniques/T1055/
- **Yama LSM**: https://www.kernel.org/doc/Documentation/security/Yama.txt
- **Linux Exploit Development**: https://www.exploit-db.com/papers

---

## Legal Notice

This module is provided for **educational and research purposes only**.

**You must**:
- Have explicit permission
- Use only on systems you own
- Follow all applicable laws
- Use ethically and responsibly

**Misuse may result in**:
- Criminal charges
- Civil liability
- System damage
- Data loss

The developer assumes no liability for misuse of this tool.

---

**Developer**: Sai Srujan Murthy  
**Email**: saisrujanmurthy@gmail.com  
**Module**: Code Injection Framework  
**Version**: 1.0  
**Safety Level**: ⚠️ ROOT REQUIRED - USE WITH EXTREME CAUTION
