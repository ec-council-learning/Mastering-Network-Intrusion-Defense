import struct


def create_pe_like_file(output_filename):
    # PE file signature
    dos_stub = b'MZ'
    dos_stub += b'\x00' * 58  # Padding
    dos_stub += struct.pack('<I', 0x80)  # e_lfanew

    # PE header
    pe_header = b'PE\x00\x00'
    pe_header += b'\x4C\x01'  # Machine (x86-64)
    pe_header += b'\x00' * 18  # Other header fields

    # Our target hex string
    target_hex = b'\xFD\x53\x4D\x42\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41'

    # Combine all parts
    full_content = dos_stub + pe_header + b'\x00' * 200 + target_hex + b'\x00' * 200

    with open(output_filename, 'wb') as f:
        f.write(full_content)


create_pe_like_file('defanged_smb_exploit.bin')
'''
rule SMB_Null_Pointer_Dereference_PoC
{
    meta:
        description = "Detects potential SMB Null Pointer Dereference PoC (CVE-2018-0833)"
        reference = "https://krbtgt.pw/smbv3-null-pointer-dereference-vulnerability/"
        cve = "CVE-2018-0833"

    strings:
        $mz_header = "MZ"
        $pe_header = "PE"
        $smb_signature = { FD 53 4D 42 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 }

    condition:
        $mz_header at 0 and
        $pe_header and
        $smb_signature
}
'''
'''
alert tcp-pkt any 445 -> $HOME_NET any (msg:"ET EXPLOIT SMB Null Pointer Dereference PoC Inbound (CVE-2018-0833)"; flow:from_server,established; content:"|FD 53 4D 42 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41|"; offset:4; reference:url,krbtgt.pw/smbv3-null-pointer-dereference-vulnerability/; reference:cve,2018-0833; classtype:attempted-admin; sid:2025983; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2018_08_08, cve CVE_2018_0833, deployment Internal, signature_severity Major, updated_at 2019_07_26;)
'''
