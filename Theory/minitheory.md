# SỔ TAY LINUX — BINARY, ELF, LIBC, LD & DEBUG CHO PWNABLE CTF

> **Mục đích:** Tài liệu tra cứu từ cơ bản đến thực hành khi phân tích các binary Linux trong bài CTF, phòng lab hoặc hệ thống được phép kiểm thử. Trọng tâm là **hiểu file ELF, thư viện động và môi trường chạy**, không phải chạy tùy tiện các binary không rõ nguồn gốc.
>
> **Đối tượng:** Người mới học Pwnable, đặc biệt đang làm quen bài x86 (32-bit) và x86-64 (64-bit).
>
> **Quy ước:** `$` là dấu nhắc terminal, **không gõ `$`**. Tên `./chall`, `./libc.so.6`, `pwn_chal` chỉ là ví dụ; thay bằng tên thật trên máy.

## Mục lục

1. [Bản đồ tư duy: binary, libc, ld](#1-bản-đồ-tư-duy-binary-libc-ld)
2. [Lệnh Linux nền tảng khi làm việc với file](#2-lệnh-linux-nền-tảng-khi-làm-việc-với-file)
3. [Nhận diện binary và kiến trúc](#3-nhận-diện-binary-và-kiến-trúc)
4. [Đọc cấu trúc ELF bằng readelf](#4-đọc-cấu-trúc-elf-bằng-readelf)
5. [Xem mã máy, symbols, GOT/PLT bằng objdump, nm, strings](#5-xem-mã-máy-symbols-gotplt-bằng-objdump-nm-strings)
6. [Kiểm tra cơ chế bảo vệ](#6-kiểm-tra-cơ-chế-bảo-vệ)
7. [Hiểu libc, ld, địa chỉ và offset](#7-hiểu-libc-ld-địa-chỉ-và-offset)
8. [Chạy với libc/ld phù hợp, pwninit và patchelf](#8-chạy-với-libcld-phù-hợp-pwninit-và-patchelf)
9. [Tìm và sao chép libc/ld từ Docker](#9-tìm-và-sao-chép-libcld-từ-docker)
10. [GDB và quan sát tiến trình](#10-gdb-và-quan-sát-tiến-trình)
11. [strace, ltrace, xxd và kiểm tra input/output](#11-strace-ltrace-xxd-và-kiểm-tra-inputoutput)
12. [Phân biệt chạy local và remote](#12-phân-biệt-chạy-local-và-remote)
13. [Xử lý lỗi thường gặp](#13-xử-lý-lỗi-thường-gặp)
14. [Quy trình chuẩn khi nhận một bài Pwnable](#14-quy-trình-chuẩn-khi-nhận-một-bài-pwnable)
15. [Bảng lệnh tra cứu siêu nhanh](#15-bảng-lệnh-tra-cứu-siêu-nhanh)
16. [Bài thực hành tự kiểm tra](#16-bài-thực-hành-tự-kiểm-tra)
17. [Tài liệu chính thức](#17-tài-liệu-chính-thức)

---

## 1. Bản đồ tư duy: binary, libc, ld

### 1.1 Ba thứ cần phân biệt

| Thành phần | Ví dụ | Vai trò |
|---|---|---|
| **Executable/binary** | `chall` | File chứa mã máy và thông tin để hệ điều hành chạy chương trình. |
| **libc** | `libc.so.6` | Thư viện C dùng chung, cung cấp các hàm như `read`, `write`, `printf`, `malloc`. |
| **Dynamic loader** | `ld-linux.so.2`, `ld-linux-x86-64.so.2` | Nạp các thư viện động và giải quyết liên kết động khi chương trình chạy. |

Sơ đồ khái quát:

```text
                   LINUX KERNEL
                         |
             khởi động file ELF
                         |
                DYNAMIC LOADER
                   (ld-linux)
                  /          \
                 /            \
           binary chall     libc.so.6
```

**Lưu ý:** `ld` là tên có thể gây nhầm. `ld` (GNU linker) dùng lúc **biên dịch/liên kết**; `ld-linux.so.*` là **runtime dynamic loader** dùng lúc **chạy**.

### 1.2 Những khái niệm phải nhớ

- **ELF:** Định dạng file executable/shared object phổ biến trên Linux.
- **32-bit / 64-bit:** Quyết định độ rộng con trỏ, thanh ghi và các thư viện tương thích.
- **Symbol:** Tên một hàm hoặc đối tượng được biểu diễn trong bảng symbol.
- **Offset:** Vị trí tương đối so với một mốc (ví dụ base của libc).
- **Runtime address:** Địa chỉ thực tế trong tiến trình đang chạy.
- **ASLR:** Làm ngẫu nhiên hóa vị trí của một số vùng nhớ khi chạy.
- **PIE:** Cho phép bản thân executable được nạp tại địa chỉ base thay đổi.
- **GOT/PLT:** Các cấu trúc hỗ trợ gọi và phân giải hàm liên kết động.
- **RPATH/RUNPATH:** Thông tin đường dẫn tìm shared libraries được ghi trong ELF.
- **PT_INTERP:** Program header chỉ ra dynamic loader cần sử dụng.

---

## 2. Lệnh Linux nền tảng khi làm việc với file

### 2.1 Di chuyển và kiểm tra thư mục

```bash
pwd                 # Đường dẫn thư mục hiện tại
ls                  # Liệt kê file
ls -lah             # Liệt kê chi tiết, gồm file ẩn và kích thước dễ đọc
cd ~/ctf/challenge  # Chuyển thư mục
stat ./chall        # Kích thước, quyền, thời gian, inode...
```

### 2.2 Quyền thực thi

```bash
ls -l ./chall
chmod +x ./chall   # Thêm quyền thực thi khi cần
./chall            # Chạy file trong thư mục hiện tại (chỉ với file tin cậy)
```

`./chall` khác `chall`: tiền tố `./` nói rõ đường dẫn file trong thư mục hiện tại. Shell thường không tự tìm chương trình trong thư mục hiện tại nếu `.` không nằm trong `PATH`.

### 2.3 Tìm file khi không biết đường dẫn

```bash
find . -name 'libc.so.6'               # Tìm trong thư mục hiện tại
find / -name 'libc.so.6' 2>/dev/null  # Tìm trên máy, ẩn lỗi quyền truy cập
find / -name 'ld-linux*' 2>/dev/null  # Tìm loader, kể cả symlink có tên khớp
find /lib /usr/lib -name 'libc.so*' 2>/dev/null
```

Giải nghĩa:

- `find`: duyệt cây thư mục.
- `/`: bắt đầu từ filesystem root.
- `-name`: khớp tên file; dấu `*` là wildcard, nên đặt trong dấu nháy.
- `2>/dev/null`: chuyển **stderr** (file descriptor 2) tới thiết bị bỏ dữ liệu; không che stdout.

Lệnh khác:

```bash
which gcc                 # Tìm chương trình theo PATH
command -v gdb            # Cách kiểm tra lệnh có sẵn trong shell
whereis libc.so.6         # Tìm một số đường dẫn quen thuộc (không toàn diện)
```

### 2.4 Symlink: file trỏ tới file khác

```bash
ls -l /lib/ld-linux.so.2
readlink /lib/ld-linux.so.2      # In đích link (có thể là đường dẫn tương đối)
readlink -f /lib/ld-linux.so.2   # Chuẩn hóa thành đích cuối cùng nếu tồn tại
file -L /lib/ld-linux.so.2       # Theo symlink khi nhận diện file
```

Điều này đặc biệt quan trọng khi copy loader từ Docker: một đường dẫn ngắn có thể chỉ là **symlink** tới file thực tế.

### 2.5 Kiểm tra file có giống nhau không

```bash
sha256sum libc_docker.so.6 libc_pwninit.so.6
cmp -s libc_docker.so.6 libc_pwninit.so.6 && echo 'GIỐNG NHAU' || echo 'KHÁC NHAU'
```

- **SHA-256 bằng nhau:** bằng chứng rất mạnh rằng hai file có cùng nội dung.
- **SHA-256 khác nhau:** các file khác nội dung, dù đều tự nhận là glibc 2.35.

### 2.6 Bash: biến, redirect và pipe

```bash
name=chall                         # Không có khoảng trắng quanh dấu =
echo "$name"                      # Đọc giá trị biến
out=$(readlink -f ./chall)         # Gán stdout của lệnh vào biến
echo "$out"

readelf -h ./chall > elf_header.txt   # Ghi stdout vào file
readelf -h ./chall 2> error.txt      # Ghi stderr vào file
readelf -h ./chall | grep 'Class'    # Pipe stdout qua grep
```

**Lỗi thường gặp:** `id =$(docker create pwn_chal)` là **sai** vì Bash hiểu `id` là lệnh. Viết `cid=$(docker create pwn_chal)`.

---

## 3. Nhận diện binary và kiến trúc

### 3.1 `file`: lệnh cần chạy đầu tiên

```bash
file ./chall
file ./libc.so.6
file ./ld-linux.so.2
```

Ví dụ:

```text
chall: ELF 32-bit LSB executable, Intel 80386, dynamically linked, ...
```

Giải thích:

| Cụm từ | Ý nghĩa |
|---|---|
| `ELF` | Định dạng file. |
| `32-bit` | ELF 32-bit. |
| `LSB` | Little-endian (byte thấp được lưu trước). |
| `Intel 80386` | Kiến trúc i386. |
| `dynamically linked` | Sử dụng liên kết động. |
| `stripped` | Đã loại bỏ nhiều thông tin symbol phục vụ debug. |

**Điều kiện cơ bản:** Executable x86 32-bit phải dùng các thư viện và loader phù hợp kiến trúc 32-bit, không thể thay bằng file x86-64 một cách tùy ý.

### 3.2 `readelf -h`: xem ELF header

```bash
readelf -h ./chall
```

Chú ý các trường:

- `Class`: `ELF32` hoặc `ELF64`.
- `Data`: kiểu endian.
- `Machine`: kiến trúc CPU.
- `Type`: `EXEC` hoặc `DYN` (còn những loại khác).
- `Entry point address`: địa chỉ/giá trị entry point của ELF.

**Không được đồng nhất `Type: DYN` với “chắc chắn là một thư viện”:** PIE executable cũng thường là `ET_DYN`.

### 3.3 `readelf -l`: xem program headers và interpreter

```bash
readelf -l ./chall
readelf -l ./chall | grep -i interpreter
```

Ví dụ:

```text
[Requesting program interpreter: /lib/ld-linux.so.2]
```

Đường dẫn này được ghi vào **PT_INTERP**; nó không đảm bảo file đó đang tồn tại trên máy của bạn.

---

## 4. Đọc cấu trúc ELF bằng readelf

`readelf` là một công cụ đọc thông tin trong file ELF **mà không cần chạy binary**.

| Lệnh | Xem gì? | Khi nào dùng? |
|---|---|---|
| `readelf -h ./chall` | ELF header | Xác nhận 32/64-bit, endian, type. |
| `readelf -l ./chall` | Program headers | Xem `PT_INTERP`, các `LOAD` segment. |
| `readelf -S ./chall` | Section headers | Tìm `.text`, `.data`, `.bss`, `.got`, `.plt`. |
| `readelf -d ./chall` | Dynamic section | Xem `NEEDED`, `RPATH`, `RUNPATH`. |
| `readelf -sW ./chall` | Symbol table | Xem symbol nếu có. |
| `readelf --dyn-syms -W ./chall` | Dynamic symbols | Hàm được liên kết động. |
| `readelf -rW ./chall` | Relocation | Tham chiếu cần dynamic linker xử lý. |
| `readelf -V ./libc.so.6` | Symbol versions | Kiểm tra các phiên bản symbol GLIBC. |
| `readelf -n ./chall` | ELF notes | Build ID, thông tin ghi chú nếu có. |

### 4.1 `-W` có tác dụng gì?

`-W` (hay `--wide`) tránh xuống dòng/cắt bớt một số trường dài. Rất hữu ích khi kết hợp `grep`.

### 4.2 Những section thường gặp

```text
.text       : mã máy
.rodata     : dữ liệu chỉ đọc, chuỗi hằng
.data       : dữ liệu toàn cục khởi tạo
.bss        : dữ liệu toàn cục chưa khởi tạo theo cách thông thường
.plt        : các stub liên quan gọi hàm động
.got / .got.plt : các slot địa chỉ phục vụ liên kết động
.dynsym     : dynamic symbol table
.dynstr     : tên các dynamic symbol
```

**Section ≠ segment:** Section mô tả cách tổ chức nội dung file; segment (`PT_LOAD`, v.v.) dùng cho việc nạp chương trình vào bộ nhớ.

---

## 5. Xem mã máy, symbols, GOT/PLT bằng objdump, nm, strings

### 5.1 `objdump`: đọc mã assembly

```bash
objdump -d ./chall                    # Disassemble các section có mã
objdump -d -M intel ./chall           # Dùng cú pháp Intel
objdump -d -M intel ./chall | less   # Xem từng trang
objdump -d -M intel --disassemble=main ./chall
```

Một số bản binary đã `strip` sẽ không còn symbol `main`; khi đó `--disassemble=main` có thể không hiển thị gì.

Dùng:

```bash
objdump -R ./chall     # Dynamic relocation records (hữu ích khi nghiên cứu GOT)
objdump -T ./chall     # Dynamic symbol table (nếu được hỗ trợ bởi định dạng)
objdump -x ./chall     # Nhiều thông tin header và metadata
```

### 5.2 `nm`: xem symbol

```bash
nm ./chall               # Symbol table thông thường; có thể rỗng nếu stripped
nm -D ./chall            # Dynamic symbols
nm -D ./libc.so.6 | grep -E ' (read|write|system)@@?'
```

Không phải mọi symbol trong libc đều xuất hiện đúng với cùng một định dạng tên/phiên bản. Nếu `grep` không tìm thấy, hãy xem đầu ra đầy đủ hoặc dùng `readelf -Ws`.

### 5.3 `strings`: tìm chuỗi có thể đọc được

```bash
strings -a ./chall | less
strings -a ./libc.so.6 | grep -F 'GNU C Library'
strings -a -t x ./chall | grep -F 'Hello'
```

- `-a`: quét toàn bộ file.
- `-t x`: in offset **trong file**, theo hệ 16.

> **Cực kỳ quan trọng:** Offset do `strings -t x` in ra là **file offset**, không nhất thiết bằng virtual address hay offset của symbol. Không lấy trực tiếp làm địa chỉ runtime.

### 5.4 Kiểm tra có dùng một hàm động không

```bash
readelf --dyn-syms -W ./chall | grep -E 'read|write|puts|printf'
readelf -rW ./chall | grep -E 'read|write|puts|printf'
objdump -d -M intel ./chall | grep -A8 -B4 '@plt'
```

- **PLT:** cầu nối/stub để gọi hàm trong thư viện động.
- **GOT:** vùng chứa các địa chỉ/tham chiếu cần cho liên kết động.
- **Relocation:** thông tin cho loader biết vị trí nào cần xử lý.

---

## 6. Kiểm tra cơ chế bảo vệ

Các công cụ thường gặp:

```bash
checksec --file=./chall
# Hoặc nếu đã cài Pwntools CLI:
pwn checksec ./chall
```

| Cơ chế | Dấu hiệu | Hiểu ngắn gọn |
|---|---|---|
| **NX** | `NX enabled` | Ngăn thực thi mã trên những vùng dữ liệu được đánh dấu không thực thi. |
| **Stack Canary** | `Canary found` | Giá trị kiểm tra nhằm phát hiện một số kiểu ghi đè stack. |
| **PIE** | `PIE enabled` | Địa chỉ base của executable có thể thay đổi giữa các lần chạy. |
| **RELRO** | `Partial/Full RELRO` | Tăng cường bảo vệ một số vùng liên quan relocation/GOT. |
| **Fortify** | Có/không | Một số lời gọi thư viện được bổ sung kiểm tra khi biên dịch nếu cấu hình hỗ trợ. |

**Lưu ý:** Đây là các biện pháp giảm thiểu rủi ro. Kết quả `checksec` không đủ để kết luận một binary có hoặc không có lỗ hổng.

---

## 7. Hiểu libc, ld, địa chỉ và offset

### 7.1 Tìm libc và ld trên hệ thống

```bash
find /lib /usr/lib -name 'libc.so.6' 2>/dev/null
find /lib /usr/lib -name 'ld-linux*' 2>/dev/null
file -L /lib/ld-linux.so.2
readlink -f /lib/ld-linux.so.2
```

Một số đường dẫn **thường gặp**, có thể khác tùy distro:

| Kiến trúc | libc | Loader |
|---|---|---|
| i386 (32-bit) | `/lib/i386-linux-gnu/libc.so.6` | `/lib/ld-linux.so.2` |
| x86-64 (64-bit) | `/lib/x86_64-linux-gnu/libc.so.6` | `/lib64/ld-linux-x86-64.so.2` |

### 7.2 Xem phiên bản libc

```bash
strings -a ./libc.so.6 | grep -F 'GNU C Library'
readelf -n ./libc.so.6 | grep -A3 'Build ID'
sha256sum ./libc.so.6
```

Nhiều bản glibc khác nhau **có thể cùng tên phiên bản chính** nhưng khác build, checksum hoặc offset. `Build ID`/checksum giúp so sánh chính xác hơn.

### 7.3 Xem offset symbol của libc

```bash
readelf -Ws ./libc.so.6 | grep -E ' read@@| system@@| exit@@'
nm -D ./libc.so.6 | grep ' system@@'
```

Ví dụ giả định:

```text
read offset = 0x00108000
libc base   = 0xf7d00000
runtime read address = 0xf7e08000
```

Công thức:

```text
runtime_address = library_base + symbol_offset
library_base    = runtime_address - symbol_offset
```

**Điều kiện:** `symbol_offset` phải thuộc **đúng build libc** đang được tiến trình sử dụng. Các hàm khác cũng có thể có các symbol version khác nhau.

### 7.4 Kiểm tra page alignment chỉ là dấu hiệu, không phải chứng minh

Trên Linux x86/x86-64 với trang nhớ 4 KiB thông dụng, địa chỉ base của vùng ELF mapping thường căn theo `0x1000`.

```python
base = 0xf7d00000
print(hex(base & 0xfff))  # 0x0
```

- Base **không** căn trang: có thể tính sai, đọc nhầm bytes hoặc dùng offset sai.
- Base **có** căn trang: **chưa chứng minh** libc trùng khớp. Cần thêm bằng chứng.

### 7.5 Xem thư viện nào đang được nạp

Với binary **đáng tin cậy**:

```bash
ldd ./chall
```

**Cảnh báo:** `ldd` có thể không an toàn đối với binary không rõ nguồn gốc trong một số trường hợp. Ưu tiên `readelf -d` để kiểm tra phụ thuộc **mà không chạy file**, và dùng môi trường cô lập để phân tích.

Xem phụ thuộc được khai báo mà không chạy binary:

```bash
readelf -d ./chall | grep NEEDED
```

**`NEEDED` là tên thư viện cần tìm, không phải đường dẫn file tuyệt đối.**

---

## 8. Chạy với libc/ld phù hợp, pwninit và patchelf

### 8.1 Đọc ELF bằng Python khác với chạy ELF

```python
from pwn import ELF, process

elf = ELF('./chall')         # ĐỌC và phân tích metadata file
libc = ELF('./libc.so.6')   # ĐỌC và phân tích metadata file
p = process('./chall')      # TẠO tiến trình local thật
```

Dòng `ELF('./libc.so.6')` **không** tự làm cho `process('./chall')` nạp thư viện đó.

### 8.2 Chạy file bằng loader chỉ định (trong lab)

Ví dụ khi đã có loader và libc **cùng kiến trúc, tương thích** trong thư mục:

```bash
./ld-linux.so.2 --library-path . ./chall
```

- `./ld-linux.so.2`: trực tiếp gọi dynamic loader.
- `--library-path .`: chỉ định thư mục để tìm shared libraries cho lần chạy đó.
- `./chall`: executable cần chạy.

Để **liệt kê các dependency được loader giải quyết**, có thể dùng loader phù hợp:

```bash
./ld-linux.so.2 --library-path . --list ./chall
```

Không sử dụng loader 64-bit để khởi chạy ELF i386 32-bit.

### 8.3 `LD_LIBRARY_PATH`: chỉ dẫn tìm thư viện

```bash
LD_LIBRARY_PATH="$PWD" ./chall
```

Chú ý: lệnh này **không thay đổi `PT_INTERP`**. Kernel vẫn gọi loader được ghi sẵn trong executable. Do đó đặt `LD_LIBRARY_PATH` chưa chắc đã tái tạo đúng môi trường cần kiểm tra.

### 8.4 `pwninit`: chuẩn bị môi trường local

```bash
pwninit
pwninit --bin ./chall --libc ./libc.so.6 --ld ./ld-linux.so.2
```

Tùy phiên bản/cấu hình, `pwninit` có thể:

1. Nhận diện binary/libc/ld.
2. Tìm loader phù hợp với libc.
3. Tạo một binary được patch, thường là `chall_patched`.
4. Cấu hình interpreter và RPATH/RUNPATH qua `patchelf`.
5. Tạo template Python hỗ trợ lab.

**`pwninit` không patch server từ xa.** Nó phục vụ chuẩn bị **máy local**; remote vẫn dùng môi trường của server.

### 8.5 `patchelf`: xem/chỉnh interpreter và RPATH

**Nên tạo bản sao trước khi sửa:**

```bash
cp ./chall ./chall_for_lab
patchelf --print-interpreter ./chall_for_lab
patchelf --print-rpath ./chall_for_lab
```

Sửa bản sao trong môi trường lab:

```bash
patchelf --set-interpreter "$PWD/ld-linux.so.2" ./chall_for_lab
patchelf --set-rpath '$ORIGIN' ./chall_for_lab
```

- `--set-interpreter`: đổi đường dẫn dynamic loader được khai báo.
- `--set-rpath`: chỉnh đường dẫn tìm library.
- `'$ORIGIN'`: trong ngữ cảnh dynamic linker, chỉ thư mục chứa executable; dùng **dấu nháy đơn** để shell không tự diễn giải `$ORIGIN`.

Kiểm tra lại:

```bash
readelf -l ./chall_for_lab | grep -i interpreter
readelf -d ./chall_for_lab | grep -E 'RPATH|RUNPATH|NEEDED'
```

> **Không patch nhầm file gốc.** Các thay đổi này chỉ dành cho bản local trong lab. `patchelf` có thể sửa bố cục ELF; nếu không cần patch, hãy ưu tiên chỉ đọc.

---

## 9. Tìm và sao chép libc/ld từ Docker

Giả sử image của challenge có tên `pwn_chal`.

### 9.1 Xác nhận image tồn tại

```bash
docker images
docker image inspect pwn_chal
```

### 9.2 Tìm đường dẫn thư viện trong image

Nếu image có `/bin/sh`:

```bash
docker run --rm --entrypoint /bin/sh pwn_chal -c \
  'find /lib /usr/lib -name "libc.so.6" -o -name "ld-linux*" 2>/dev/null'
```

Có thể thêm dấu ngoặc cho biểu thức phức tạp hơn:

```bash
docker run --rm --entrypoint /bin/sh pwn_chal -c \
  'find /lib /usr/lib \( -name "libc.so.6" -o -name "ld-linux*" \) 2>/dev/null'
```

Lưu ý: `docker run` **thực thi** lệnh trong container; dùng với image của bài lab được phép và đáng tin cậy.

### 9.3 Tạo container để copy file mà không chạy dịch vụ mặc định

```bash
cid=$(docker create pwn_chal)
echo "$cid"
```

`docker create` tạo container nhưng chưa start. Cần đảm bảo biến `cid` không rỗng trước khi tiếp tục:

```bash
test -n "$cid" || { echo 'Tạo container thất bại'; exit 1; }
```

### 9.4 Copy libc và ld (ví dụ đường dẫn i386)

```bash
docker cp -L "$cid":/lib/i386-linux-gnu/libc.so.6 ./libc_docker.so.6
docker cp -L "$cid":/lib/ld-linux.so.2 ./ld-linux.so.2
```

`-L` yêu cầu `docker cp` đi theo symbolic link của đường dẫn nguồn, hữu ích khi file trong `/lib` là symlink.

### 9.5 Dọn container và xác nhận kiến trúc

```bash
docker rm "$cid"
file ./libc_docker.so.6 ./ld-linux.so.2
sha256sum ./libc_docker.so.6
readelf -Ws ./libc_docker.so.6 | grep ' read@@'
```

**Lưu ý quan trọng:** `docker create` là thao tác với image đã có trên máy. Nếu bạn tự `docker build` lại một Dockerfile có `apt-get update`/`apt-get install` không cố định phiên bản gói đầy đủ, kết quả có thể khác môi trường đã được triển khai từ trước, dù base image đã pin theo digest.

---

## 10. GDB và quan sát tiến trình

> Chỉ dùng GDB với file local trong lab được phép. Mục tiêu ở đây là **quan sát địa chỉ, stack và mã máy**, không phải can thiệp hệ thống khác.

### 10.1 Mở GDB

```bash
gdb -q ./chall
```

Trong GDB:

```gdb
set disassembly-flavor intel
break main
run
info registers
disassemble main
```

Ý nghĩa:

- `break main`: đặt breakpoint tại `main` nếu symbol có sẵn.
- `run`: chạy chương trình.
- `info registers`: in thanh ghi.
- `disassemble main`: xem mã máy của hàm.

### 10.2 Các lệnh GDB dùng thường xuyên

| Lệnh | Ý nghĩa |
|---|---|
| `start` | Chạy tới đầu `main` (nếu GDB có thể xác định). |
| `starti` | Bắt đầu tại instruction đầu tiên của chương trình. |
| `b main` | Breakpoint tại `main`. |
| `b *0x...` | Breakpoint tại địa chỉ cụ thể trong tiến trình local. |
| `c` | Continue. |
| `ni` / `si` | Step một instruction; `ni` không đi vào lời gọi hàm. |
| `info reg` | Xem registers. |
| `x/16wx $esp` | Xem 16 word 4-byte từ stack pointer x86. |
| `x/16gx $rsp` | Xem 16 giant word 8-byte từ stack pointer x86-64. |
| `x/s ADDRESS` | Xem chuỗi kết thúc bằng NUL tại địa chỉ. |
| `x/i $eip` hoặc `x/i $rip` | Xem instruction hiện tại. |
| `bt` | Backtrace (chuỗi call stack nếu khả dụng). |
| `info proc mappings` | Xem các vùng nhớ được ánh xạ của tiến trình Linux. |
| `quit` | Thoát GDB. |

### 10.3 Quan sát địa chỉ libc thực tế

Trong GDB, sau khi tiến trình đang chạy:

```gdb
info proc mappings
```

Bạn sẽ thấy các mapping của executable, libc, loader, stack, heap... Mỗi mapping có địa chỉ bắt đầu, kết thúc và thuộc tính. **Không nhất thiết mọi mapping đầu tiên của libc đều tương ứng với cùng khái niệm “symbol base” bạn đang dùng**; cần đối chiếu ELF program headers và file offset khi tính chính xác.

### 10.4 Phân biệt stack 32-bit và 64-bit

```text
x86 (32-bit): EIP, ESP, EBP; pointer thường 4 byte.
x86-64:       RIP, RSP, RBP; pointer thường 8 byte.
```

Ví dụ xem stack:

```gdb
# x86
x/12wx $esp

# x86-64
x/12gx $rsp
```

---

## 11. strace, ltrace, xxd và kiểm tra input/output

### 11.1 `strace`: quan sát system calls

```bash
strace ./chall
strace -f -e trace=read,write,openat,execve ./chall
strace -o strace.log ./chall
```

- `-f`: theo dõi cả tiến trình con.
- `-e trace=...`: chỉ hiện nhóm syscall đã chọn.
- `-o`: ghi log vào file.

Dùng để xác định chương trình có gọi `read()`, `write()`, mở file gì hoặc kết thúc thế nào khi chạy local.

### 11.2 `ltrace`: quan sát lời gọi thư viện (nếu có thể)

```bash
ltrace ./chall
```

`ltrace` không phải lúc nào cũng hiện đầy đủ, ví dụ với file bị strip, gọi trực tiếp, hoặc tối ưu hóa/linking khác nhau.

### 11.3 `xxd`: nhìn byte ở dạng hex

```bash
xxd ./chall | head
printf 'ABCD' | xxd -g 1
printf '\x01\x02\x03\x04' | xxd -g 1
```

`-g 1` nhóm theo từng byte. Đây là cách rất tốt để phân biệt byte thực tế với cách terminal hiển thị ký tự.

### 11.4 Đọc byte và endian bằng Python

```python
from struct import pack, unpack

b = pack('<I', 0x12345678)    # Little-endian unsigned 32-bit
print(b.hex())                 # 78563412
print(hex(unpack('<I', b)[0])) # 0x12345678
```

Trong đó `<` = little-endian; `I` = unsigned integer 4 byte. Hãy phân biệt **giá trị số** với **thứ tự byte được gửi/trữ**.

---

## 12. Phân biệt chạy local và remote

```python
from pwn import ELF, process, remote

elf = ELF('./chall')             # Phân tích file local
libc = ELF('./libc.so.6')       # Lấy thông tin/offset local

local = process('./chall')       # Chạy tiến trình trên máy mình
# remote_conn = remote('host.example', 12345)  # Kết nối tới dịch vụ lab được phép
```

| Thành phần | Local | Remote |
|---|---|---|
| `solve.py` | Chạy trên máy bạn | Vẫn chạy trên máy bạn |
| `chall` | Thực thi trên máy bạn | Thực thi trên server |
| `libc` thực tế | Từ môi trường local | Từ môi trường server |
| `ld` thực tế | Từ môi trường local | Từ môi trường server |
| Địa chỉ runtime | Của tiến trình local | Của tiến trình remote |
| Đường truyền | stdin/stdout hoặc PTY | TCP/socket theo dịch vụ |

**Mệnh đề quan trọng:** `ELF('./libc.so.6')` chỉ **đọc** libc trên máy bạn; nó **không** thay đổi libc của tiến trình remote.

### 12.1 Vì sao cùng script có thể chạy local nhưng lỗi remote?

- Libc không cùng build/offset.
- Loader, symbol version hoặc phụ thuộc khác nhau.
- Môi trường, cách khởi động, working directory hoặc biến môi trường khác nhau.
- ASLR khiến runtime base khác nhau.
- Giao thức I/O và độ trễ mạng khác nhau.
- Chương trình/daemon ở server có timeout hoặc đóng kết nối.

### 12.2 `EOFError` nghĩa là gì?

`EOFError` khi đọc socket thường có nghĩa **bên kia đã đóng luồng/kết nối**. Bản thân thông báo này **không đủ** để khẳng định nguyên nhân: có thể chương trình kết thúc bình thường, crash, timeout hoặc wrapper đóng kết nối.

Quy trình tìm nguyên nhân:

1. Xem dữ liệu **đã nhận trước EOF**.
2. Xác định thao tác gần nhất của chương trình (echo, prompt, output...).
3. Thử cùng input ở local với libc/ld phù hợp.
4. Kiểm tra log/exit status (nếu môi trường lab cho phép).
5. Không suy diễn “libc sai” chỉ từ một dòng EOF.

---

## 13. Xử lý lỗi thường gặp

| Triệu chứng | Nguyên nhân thường gặp | Kiểm tra đầu tiên |
|---|---|---|
| `Permission denied` khi `./chall` | Thiếu quyền execute hoặc filesystem `noexec` | `ls -l`, `mount` |
| `No such file or directory` dù binary tồn tại | Interpreter trong `PT_INTERP` không tồn tại, hoặc thiếu phụ thuộc | `file`, `readelf -l`, `readelf -d` |
| `Exec format error` | Sai kiến trúc hoặc định dạng | `file`, `uname -m`, `readelf -h` |
| `wrong ELF class: ELFCLASS64` | Đang cố kết hợp 32-bit và 64-bit không tương thích | `file` cả chall/libc/ld |
| `GLIBC_x.y not found` | Libc/loader hoặc thư viện khác thiếu symbol version | `readelf -V`, `ldd` với file tin cậy |
| `segmentation fault` | Truy cập địa chỉ không hợp lệ hoặc lỗi trong chương trình | GDB `bt`, `info reg`, mapping |
| Local được, remote EOF | Khác môi trường, địa chỉ, timeout, I/O | Đọc log byte, kiểm tra libc/ld |
| `libc base` không căn trang | Có thể sai leak hoặc offset libc | Kiểm tra byte và symbol offset |
| `libc base` căn trang nhưng vẫn lỗi | Có thể trùng phần thấp ngẫu nhiên hoặc build khác | So sánh checksum/build ID, nhiều symbol |
| `docker cp` chỉ nhận symlink | Đường dẫn nguồn là link | `docker cp -L`, `readlink -f` |
| `id: ... no such user` | Viết `id =$(...)` sai Bash syntax | Viết `cid=$(...)` |

### 13.1 Khi nghi libc sai: kiểm tra theo thứ tự

```bash
# 1. So sánh kiến trúc
file ./chall ./libc_docker.so.6 ./libc_pwninit.so.6

# 2. So sánh nội dung
sha256sum ./libc_docker.so.6 ./libc_pwninit.so.6

# 3. So sánh offset symbol
readelf -Ws ./libc_docker.so.6 | grep ' read@@'
readelf -Ws ./libc_pwninit.so.6 | grep ' read@@'

# 4. Kiểm tra loader mà chall chỉ định
readelf -l ./chall | grep interpreter

# 5. Kiểm tra dependency
readelf -d ./chall | grep -E 'NEEDED|RPATH|RUNPATH'
```

**Giải thích:** Nếu hai libc khác SHA-256, bạn đã tìm được một khác biệt về file; chưa đủ để kết luận khác biệt đó chắc chắn gây lỗi. Hãy liên hệ với log runtime và symbol offset.

---

## 14. Quy trình chuẩn khi nhận một bài Pwnable

### Bước 1 — Bảo quản file gốc

```bash
mkdir -p ~/ctf/bai_moi
cd ~/ctf/bai_moi
# Đặt binary và các file đề bài vào đây
sha256sum ./chall
```

Không tự patch đè lên file gốc. Sử dụng bản sao hoặc binary `_patched`.

### Bước 2 — Khảo sát ban đầu

```bash
file ./chall
readelf -h ./chall
readelf -l ./chall | grep interpreter
readelf -d ./chall | grep NEEDED
checksec --file=./chall
```

**Câu hỏi phải trả lời:** 32/64-bit? PIE? NX? Canary? Dynamic hay static? Loader nào?

### Bước 3 — Xem cấu trúc và symbol

```bash
readelf -S ./chall
readelf --dyn-syms -W ./chall
readelf -rW ./chall
objdump -d -M intel ./chall | less
strings -a ./chall | less
```

### Bước 4 — Xác định môi trường libc/ld

```bash
file ./libc.so.6 ./ld-linux.so.2
sha256sum ./libc.so.6
readelf -Ws ./libc.so.6 | grep ' read@@'
```

Nếu đề cung cấp Docker, xem phần 9 để tìm file từ đúng image. Nếu có `pwninit`, xem phần 8 để chuẩn bị môi trường local.

### Bước 5 — Quan sát hành vi local

```bash
gdb -q ./chall
# Hoặc trên binary local đã được chuẩn bị đúng môi trường:
# gdb -q ./chall_patched
```

Quan sát: luồng nhập/xuất, vùng nhớ, call stack, chỗ crash (nếu có).

### Bước 6 — Đối chiếu kết quả local và remote

- Không giả định runtime address local = runtime address remote.
- So sánh build libc, symbol offsets và dữ liệu thực tế thu được.
- Ghi lại đầy đủ các bước và kiểm tra hypothesis lần lượt.

### Bước 7 — Ghi chép sau mỗi challenge

Nên giữ một file `notes.md` chứa:

```markdown
# Tên bài
- Kiến trúc:
- Mitigations:
- Interpreter:
- Libc (SHA256/Build ID):
- Những hàm và cấu trúc đáng chú ý:
- Những gì đã quan sát trong GDB:
- Khác biệt local/remote:
- Lỗi đã gặp và cách xác minh:
- Kiến thức mới:
```

---

## 15. Bảng lệnh tra cứu siêu nhanh

| Muốn làm gì? | Lệnh |
|---|---|
| Nhận diện file | `file ./chall` |
| Xem quyền file | `ls -l ./chall` |
| Thêm execute bit | `chmod +x ./chall` |
| Tìm libc | `find / -name 'libc.so.6' 2>/dev/null` |
| Tìm loader | `find / -name 'ld-linux*' 2>/dev/null` |
| Theo symlink | `readlink -f /lib/ld-linux.so.2` |
| So sánh file | `sha256sum file1 file2` |
| ELF header | `readelf -h ./chall` |
| ELF interpreter | `readelf -l ./chall \| grep interpreter` |
| Sections | `readelf -S ./chall` |
| Dependencies | `readelf -d ./chall \| grep NEEDED` |
| Dynamic symbols | `readelf --dyn-syms -W ./chall` |
| Relocations | `readelf -rW ./chall` |
| Disassemble | `objdump -d -M intel ./chall` |
| Dynamic symbols bằng nm | `nm -D ./libc.so.6` |
| Tìm chuỗi | `strings -a ./chall \| grep 'text'` |
| Kiểm tra mitigations | `checksec --file=./chall` |
| Xem symbol offset | `readelf -Ws ./libc.so.6 \| grep ' read@@'` |
| Kiểm tra interpreter đã patch | `patchelf --print-interpreter ./chall_patched` |
| Kiểm tra RPATH | `patchelf --print-rpath ./chall_patched` |
| Chạy với loader local | `./ld-linux.so.2 --library-path . ./chall` |
| Tạo container để copy | `cid=$(docker create pwn_chal)` |
| Copy và theo symlink | `docker cp -L "$cid":/path/to/file ./file` |
| Xóa container | `docker rm "$cid"` |
| GDB | `gdb -q ./chall` |
| Trace syscalls | `strace -f ./chall` |
| Xem bytes | `xxd -g 1 ./file` |
| Xem biến môi trường | `env \| sort` |

> **Mẹo sử dụng:** Các ký tự `\|` trong cột Markdown là để hiển thị dấu pipe `|` trong bảng. Khi copy vào terminal, hãy gõ `|` bình thường.

---

## 16. Bài thực hành tự kiểm tra

Tạo một chương trình C **không chứa lỗi tràn bộ đệm** để học cách công cụ hoạt động:

```c
// demo.c
#include <stdio.h>
#include <unistd.h>

int main(void) {
    char buf[16] = {0};
    puts("Demo ELF");
    ssize_t n = read(STDIN_FILENO, buf, sizeof(buf) - 1);
    if (n > 0) {
        printf("Ban nhap: %s\n", buf);
    }
    return 0;
}
```

Biên dịch trên Linux:

```bash
gcc -g -O0 demo.c -o demo
```

Nếu máy có môi trường biên dịch multilib và bạn muốn quan sát ELF 32-bit:

```bash
gcc -m32 -g -O0 demo.c -o demo32
```

Nếu `-m32` báo thiếu header/thư viện 32-bit, nguyên nhân là thiếu bộ công cụ tương thích trên máy; không phải lỗi của `demo.c`.

### Câu hỏi tự luyện

1. `file ./demo` báo kiến trúc gì?
2. `readelf -l ./demo | grep interpreter` cho thấy loader nào?
3. `readelf -d ./demo | grep NEEDED` cho thấy thư viện nào?
4. `readelf --dyn-syms -W ./demo | grep -E 'puts|printf|read'` hiển thị gì?
5. `objdump -d -M intel ./demo` có thể tìm được `main` không?
6. `gdb -q ./demo`, `break main`, `run`, `info proc mappings`: có thấy libc và loader trong mapping không?
7. Thử `sha256sum` trên cùng file hai lần: kết quả có thay đổi không?

**Mục tiêu:** Bạn có thể mô tả hành trình từ **file ELF → loader → libc → tiến trình → output** mà không cần nhớ máy móc mọi lệnh.

---

## 17. Tài liệu chính thức

- GNU `readelf` (binutils): <https://sourceware.org/binutils/docs/binutils/readelf.html>
- Trang hướng dẫn `ld-linux.so` / dynamic linker: <https://man7.org/linux/man-pages/man8/ld-linux.8.html>
- Docker `cp`, tùy chọn `-L`: <https://docs.docker.com/reference/cli/docker/container/cp/>
- `pwninit` (dự án gốc): <https://github.com/io12/pwninit>
- GNU Debugger (GDB): <https://sourceware.org/gdb/documentation/>
- GNU `objdump`: <https://sourceware.org/binutils/docs/binutils/objdump.html>
- `patchelf` (dự án gốc): <https://github.com/NixOS/patchelf>

---

## Lời nhắc cuối

**4 câu hỏi cần trả lời trước khi đào sâu một bài binary:**

1. Đây là file **32-bit hay 64-bit**, dynamic hay static?
2. Chương trình thực tế đang được nạp bằng **ld nào, libc nào**?
3. Tôi đang xem **file offset, symbol offset hay runtime address**?
4. Khi local và remote khác nhau, **bằng chứng cụ thể** nằm ở file, địa chỉ, I/O, timeout hay cách chạy?

Nắm chắc bốn câu này sẽ giúp bạn tránh phần lớn nhầm lẫn khi học ELF và thư viện động trong Pwnable CTF.
