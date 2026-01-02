"""
MalSpectra - Test Shellcode Payloads
Harmless payloads for testing process injection

Developer: Sai Srujan Murthy
Email: saisrujanmurthy@gmail.com
"""

from typing import Dict, List


class Payloads:
    """
    Collection of test shellcode payloads.
    These are HARMLESS payloads for testing purposes only.
    """
    
    # x86-64 payloads
    PAYLOADS_X64 = {
        'nop_sled': {
            'name': 'NOP Sled (10 NOPs)',
            'description': 'Simple NOP instructions - does nothing',
            'bytes': b'\x90' * 10,
            'safe': True
        },
        'int3_trap': {
            'name': 'INT3 Trap (Debugger Breakpoint)',
            'description': 'Triggers debugger breakpoint (0xCC)',
            'bytes': b'\xCC',
            'safe': True
        },
        'ret': {
            'name': 'RET Instruction',
            'description': 'Simple return instruction (0xC3)',
            'bytes': b'\xC3',
            'safe': True
        },
        'nop_ret': {
            'name': 'NOP + RET',
            'description': 'NOPs followed by return',
            'bytes': b'\x90\x90\x90\x90\xC3',
            'safe': True
        }
    }
    
    @classmethod
    def get_available_payloads(cls) -> List[str]:
        """
        Get list of available payload names.
        
        Returns:
            List of payload names
        """
        return list(cls.PAYLOADS_X64.keys())
    
    @classmethod
    def get_payload(cls, name: str) -> Dict:
        """
        Get payload by name.
        
        Args:
            name: Payload name
            
        Returns:
            Payload dictionary or None
        """
        return cls.PAYLOADS_X64.get(name)
    
    @classmethod
    def get_payload_bytes(cls, name: str) -> bytes:
        """
        Get payload bytes by name.
        
        Args:
            name: Payload name
            
        Returns:
            Payload bytes or None
        """
        payload = cls.get_payload(name)
        return payload['bytes'] if payload else None
    
    @classmethod
    def list_payloads(cls) -> None:
        """Print all available payloads."""
        print("Available Payloads:")
        print("=" * 60)
        
        for name, info in cls.PAYLOADS_X64.items():
            print(f"\n[{name}]")
            print(f"  Name: {info['name']}")
            print(f"  Description: {info['description']}")
            print(f"  Size: {len(info['bytes'])} bytes")
            print(f"  Hex: {info['bytes'].hex()}")
            print(f"  Safe: {'✓' if info['safe'] else '✗'}")


if __name__ == "__main__":
    # List all payloads
    Payloads.list_payloads()
