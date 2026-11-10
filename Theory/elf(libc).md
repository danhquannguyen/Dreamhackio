# 📘 Pwntools `libc = ELF('./libc.so.6')` — Sổ tay tra cứu đầy đủ (x86/i386)

> Tài liệu tiếng Việt dùng cho học Linux, ELF, dynamic linking và Pwnable CTF **trong phòng lab được cấp phép**. Các địa chỉ trong ví dụ là số **minh họa**, không phải địa chỉ thực tế của file `libc.so.6` của bạn. Cú pháp chính đối chiếu theo Pwntools 4.15.0; những phiên bản khác có thể có thay đổi nhỏ.

## Mục lục

1. [Hiểu đúng `libc = ELF(...)`](#1-hiểu-đúng-libc--elf)
2. [Bảng tra cứu API và kiểu dữ liệu](#2-bảng-tra-cứu-api-và-kiểu-dữ-liệu)
3. [Khởi tạo và kiểm tra thông tin thư viện](#3-khởi-tạo-và-kiểm-tra-thông-tin-thư-viện)
4. [Symbol: `symbols`, `sym`, `functions`](#4-symbol-symbols-sym-functions)
5. [GOT và PLT: phân biệt binary với libc](#5-got-và-plt-phân-biệt-binary-với-libc)
6. [`address`: offset, base và địa chỉ runtime](#6-address-offset-base-và-địa-chỉ-runtime)
7. [`search()`: tìm chuỗi và mẫu byte](#7-search-tìm-chuỗi-và-mẫu-byte)
8. [Đọc dữ liệu, string và disassembly](#8-đọc-dữ-liệu-string-và-disassembly)
9. [Section, segment và chuyển đổi offset](#9-section-segment-và-chuyển-đổi-offset)
10. [Bảo vệ ELF, Build ID, phiên bản libc](#10-bảo-vệ-elf-build-id-phiên-bản-libc)
11. [Kết hợp `ELF(libc)` với `ROP(libc)`](#11-kết-hợp-elflibc-với-roplibc)
12. [Những lỗi phổ biến và cách chẩn đoán](#12-những-lỗi-phổ-biến-và-cách-chẩn-đoán)
13. [Script thực hành có thể chạy ngay](#13-script-thực-hành-có-thể-chạy-ngay)
14. [Cheat sheet và bài tập tự kiểm tra](#14-cheat-sheet-và-bài-tập-tự-kiểm-tra)
15. [Nguồn tham khảo](#15-nguồn-tham-khảo)

---

## 1. Hiểu đúng `libc = ELF(...)`

### 1.1. Câu lệnh này làm gì?

```python
from pwn import *

libc = ELF('./libc.so.6')
```

- `ELF(...)` là lớp của **Pwntools**, dùng để mở và phân tích file định dạng ELF.
- `'./libc.so.6'` là đường dẫn **tương đối với thư mục làm việc hiện tại**; không phải tên file sẽ tự được tải xuống.
- `libc` là biến Python chứa **đối tượng `pwnlib.elf.elf.ELF`**.
- Nó đọc thông tin file trên đĩa: header, architecture, symbol, section, segment, GOT/PLT, v.v.
- Lệnh này **không tự động đọc bộ nhớ của một process** và **không tự biết libc đang được load ở địa chỉ runtime nào**.

```python
print(type(libc))
# <class 'pwnlib.elf.elf.ELF'>
```

### 1.2. libc là gì?

`libc` (C standard library) cung cấp nhiều hàm cho chương trình C trên Linux, chẳng hạn:

- `puts()`, `printf()` — xuất dữ liệu.
- `read()`, `write()` — thao tác I/O (các symbol liên quan tới system calls).
- `malloc()`, `free()` — quản lý vùng nhớ động.
- `memcpy()`, `strlen()`, `strcmp()` — thao tác bộ nhớ, chuỗi.
- `system()` — yêu cầu shell thực thi câu lệnh; khi học nên chỉ phân tích symbol, không thực thi lệnh không rõ nguồn gốc.

Trên Linux/glibc, tên `libc.so.6` là tên thư viện chia sẻ thường gặp. **Không phải mọi Linux đều sử dụng cùng libc hoặc cùng phiên bản.**

### 1.3. ELF của chương trình và ELF của libc khác nhau thế nào?

```python
elf  = ELF('./chall')
libc = ELF('./libc.so.6')
```

Hai biến đều có kiểu `ELF`, nhưng đang mô tả **hai file khác nhau**.

| Biểu thức | File đang tra cứu | Ý nghĩa |
|---|---|---|
| `elf.sym['main']` | `./chall` | Địa chỉ/giá trị symbol `main` của chương trình |
| `libc.sym['puts']` | `./libc.so.6` | Địa chỉ/giá trị symbol `puts` trong libc |
| `elf.got['puts']` | `./chall` | Địa chỉ ô GOT cho `puts` **nếu có** |
| `elf.plt['puts']` | `./chall` | Địa chỉ stub PLT cho `puts` **nếu có** |
| `libc.search(b'...')` | `./libc.so.6` | Tìm mẫu byte trong libc |
| `ROP(libc)` | `./libc.so.6` | Tìm gadget trong libc |

**Không nhầm:** `elf.got['puts']` **không phải** `libc.sym['puts']`. Một cái là địa chỉ **ô con trỏ** trong chương trình, cái còn lại là địa chỉ **symbol** bên thư viện.

---

## 2. Bảng tra cứu API và kiểu dữ liệu

> Các kiểu dưới đây mô tả cách sử dụng thực tế. Với symbol vắng mặt, phép truy cập bằng `[...]` gây `KeyError`; dùng `.get()` để nhận `None` thay thế.

| Lệnh/thuộc tính | Kiểu kết quả | Mục đích |
|---|---|---|
| `ELF('./libc.so.6')` | `ELF` | Mở và phân tích file ELF |
| `libc.path` | `str` | Đường dẫn file |
| `libc.arch` | `str` | Kiến trúc, ví dụ `'i386'` |
| `libc.bits` | `int` | 32 hoặc 64 |
| `libc.bytes` | `int` | Kích thước con trỏ (4 hoặc 8) |
| `libc.endian` | `str` | `'little'` hoặc `'big'` |
| `libc.elftype` | `str` | `'DYN'`, `'EXEC'`, ... |
| `libc.entry` | `int` | Entry point theo base của đối tượng |
| `libc.address` | `int` | Base đang cấu hình cho ELF |
| `libc.pie` | `bool` | ELF có định vị độc lập hay không |
| `libc.symbols` / `libc.sym` | `dotdict` (`dict`-like) | Tên symbol → địa chỉ `int` |
| `libc.sym['puts']` | `int` | Giá trị symbol `puts`, nếu tồn tại |
| `libc.sym.get('puts')` | `int` hoặc `None` | Tra cứu không gây `KeyError` |
| `libc.functions` | `dotdict` | Tên hàm → đối tượng `Function` |
| `libc.functions['puts']` | `Function` | Thông tin symbol hàm, nếu có |
| `libc.plt` | `dotdict` | Tên → địa chỉ PLT có trong file này |
| `libc.got` | `dotdict` | Tên → địa chỉ ô GOT có trong file này |
| `libc.search(b'abc')` | Generator/iterator của `int` | Tìm địa chỉ mẫu byte |
| `next(libc.search(b'abc'), None)` | `int` hoặc `None` | Lấy kết quả tìm kiếm đầu tiên |
| `list(libc.search(b'abc'))` | `list[int]` | Lấy toàn bộ vị trí tìm thấy |
| `libc.read(addr, n)` | `bytes` hoặc `None` | Đọc vùng dữ liệu từ ánh xạ file ELF |
| `libc.string(addr)` | `str` | Đọc chuỗi kết thúc `\0` |
| `libc.disasm(addr, n)` | `str` | Disassemble `n` byte tại địa chỉ |
| `libc.get_data()` / `libc.data` | `bytes` | Nội dung thô của file |
| `libc.get_section_by_name('.text')` | `Section` hoặc `None` | Lấy section theo tên |
| `libc.section('.text')` | `bytes` hoặc `None` | Dữ liệu section |
| `libc.sections` | `list` các `Section` | Danh sách section |
| `libc.segments` | `list` các `Segment` | Danh sách segment |
| `libc.bss()` | `int` | Địa chỉ vùng `.bss` nếu có |
| `libc.vaddr_to_offset(addr)` | `int` hoặc `None` | Virtual address → file offset |
| `libc.offset_to_vaddr(off)` | `int` hoặc `None` | File offset → virtual address |
| `libc.buildid` | `bytes` hoặc `None` | GNU Build ID nếu có |
| `libc.canary`, `libc.nx`, `libc.relro` | Phần lớn `bool`; `relro` là `str` | Thông tin bảo vệ |
| `libc.checksec()` | Kết quả hiển thị kiểm tra | Kiểm tra cấu hình bảo vệ |
| `libc.write(addr, data)` | Thao tác sửa dữ liệu trong đối tượng ELF | Không sửa bộ nhớ process đang chạy |
| `libc.save(path)` | Thao tác lưu file | Ghi bản sao file đã sửa |
| `libc.close()` | `None` | Đóng tài nguyên ELF |

### 2.1. Kiểu dữ liệu cần nhớ

```python
print(type(libc))                   # ELF
print(type(libc.arch))              # str
print(type(libc.bits))              # int
print(type(libc.address))           # int
print(type(libc.symbols))           # dotdict (dictionary-like)
print(type(libc.sym.get('puts')))    # int nếu có symbol
print(type(libc.search(b'ELF')))    # generator
```

`hex(0x1234)` trả về **chuỗi `str`** `'0x1234'`; `p32(0x1234)` trả về **4 byte `bytes`**. Đừng nhầm định dạng hiển thị với dữ liệu nhị phân.

---

## 3. Khởi tạo và kiểm tra thông tin thư viện

### 3.1. `ELF(path, checksec=True)`

**Cú pháp:**

```python
libc = ELF('./libc.so.6', checksec=True)
```

| Tham số | Ý nghĩa |
|---|---|
| `path` | Đường dẫn đến ELF trên đĩa |
| `checksec` | Kiểm soát việc in thông tin bảo vệ trong quá trình nạp |

**Trả về:** đối tượng `ELF`; nếu file không tồn tại hoặc file không hợp lệ sẽ có exception.

Để tập trung vào dữ liệu và bớt log:

```python
libc = ELF('./libc.so.6', checksec=False)
```

### 3.2. Các thuộc tính mô tả file

```python
print('Path:    ', libc.path)
print('Arch:    ', libc.arch)
print('Bits:    ', libc.bits)
print('Bytes:   ', libc.bytes)
print('Endian:  ', libc.endian)
print('Type:    ', libc.elftype)
print('PIE:     ', libc.pie)
print('Entry:   ', hex(libc.entry))
print('Base:    ', hex(libc.address))
```

Ví dụ với libc **i386** thường có `arch == 'i386'`, `bits == 32`, `bytes == 4`, `endian == 'little'`. Đừng dựa vào tên file để kết luận kiến trúc; hãy kiểm tra thuộc tính thực tế.

### 3.3. Kiểm tra libc có khớp với binary không

```python
elf  = ELF('./chall', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

assert elf.arch == libc.arch, 'Khác kiến trúc!'
assert elf.bits == libc.bits, 'Khác số bit!'
assert elf.endian == libc.endian, 'Khác endianness!'
```

**Lưu ý:** Cùng architecture **không đủ** để kết luận đây là phiên bản libc thực sự được dùng ở runtime.

### 3.4. `elf.libc` có giống `ELF('./libc.so.6')` không?

```python
libc_local = elf.libc
```

- `elf.libc` cố xác định libc đang gắn với binary trên **máy hiện tại**.
- Trả về đối tượng `ELF` hoặc `None`.
- **Cảnh báo bảo mật:** Thuộc tính này có thể **chạy binary** để xác định thư viện. Không gọi `elf.libc`, `elf.libs` hoặc `elf.maps` với file không đáng tin ngoài môi trường cách ly.
- `ELF('./libc.so.6')` dùng **chính xác file chỉ định**, nên thích hợp khi challenge cung cấp libc đi kèm.

---

## 4. Symbol: `symbols`, `sym`, `functions`

### 4.1. `libc.symbols` và `libc.sym`

`libc.sym` là alias thuận tiện của `libc.symbols`.

```python
print(libc.symbols['puts'])
print(libc.sym['puts'])
print(libc.sym.puts)
```

Ba cách đều truy xuất symbol `puts` nếu có. Với tên symbol đặc biệt, nên dùng dấu `[...]`.

**Kiểu trả về:** `int` khi symbol tồn tại.

```python
puts_value = libc.sym['puts']
print(type(puts_value))   # <class 'int'>
print(hex(puts_value))
```

Dạng từ điển:

```python
print('puts' in libc.symbols)    # bool
print(len(libc.symbols))         # int
for name, addr in libc.symbols.items():
    if name in ('puts', 'printf', 'read', 'write'):
        print(name, hex(addr))
```

### 4.2. `[]` khác `.get()`

```python
libc.sym['this_function_does_not_exist']
# KeyError
```

```python
value = libc.sym.get('this_function_does_not_exist')
print(value)  # None
```

Viết an toàn:

```python
name = 'puts'
addr = libc.sym.get(name)
if addr is None:
    print(f'Không có symbol: {name}')
else:
    print(f'{name} = {addr:#x}')
```

### 4.3. `libc.functions`

`libc.functions` là ánh xạ tên hàm đến đối tượng `Function`, lưu thêm thông tin như tên, địa chỉ và kích thước hàm (khi metadata cho phép).

```python
func = libc.functions.get('puts')
if func is not None:
    print(func.name)       # str
    print(hex(func.address))  # int -> str khi format hex
    print(func.size)       # int
```

Không phải mọi symbol đều xuất hiện trong `functions`: biến toàn cục khác với function, và thông tin có thể thiếu khi file bị strip.

### 4.4. `libc.sym['puts']` là offset hay địa chỉ?

Điều này phụ thuộc `libc.address` hiện tại:

- Với libc chia sẻ kiểu ET_DYN có base mặc định bằng `0`, giá trị thường là **offset/relative virtual address**.
- Sau khi thiết lập một base hợp lệ, cùng biểu thức cho ra **địa chỉ đã cộng base**.
- Với ELF khác loại hoặc có `PT_LOAD` đầu tiên khác `0`, phải xét base ban đầu chứ không suy luận máy móc rằng mọi symbol luôn là offset thuần.

Công thức tổng quát:

```text
Địa chỉ mới của symbol = địa chỉ symbol cũ + (base mới - base cũ)
```

---

## 5. GOT và PLT: phân biệt binary với libc

### 5.1. PLT là gì?

**PLT (Procedure Linkage Table)** là các đoạn mã trung gian do bộ liên kết tạo ra để hỗ trợ gọi hàm từ thư viện chia sẻ.

```python
elf.plt['puts']
```

là địa chỉ đoạn PLT `puts` **trong binary `elf`**, nếu binary có stub này.

### 5.2. GOT là gì?

**GOT (Global Offset Table)** là vùng lưu các mục phục vụ liên kết động, có thể gồm địa chỉ hàm được resolver điền tại runtime.

```python
elf.got['puts']
```

là **địa chỉ của một ô trong GOT**, **không phải nội dung runtime của ô**.

Bố cục khái niệm:

```text
./chall                       ./libc.so.6
   |                               |
   | call puts@plt                 |  puts() implementation
   v                               ^
  PLT  ---> GOT entry -------------|
                  (sau khi được phân giải)
```

### 5.3. So sánh trực tiếp

```python
elf  = ELF('./chall', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

print(elf.got.get('puts'))
print(elf.plt.get('puts'))
print(libc.sym.get('puts'))
```

| Biểu thức | Ý nghĩa | Kiểu |
|---|---|---|
| `elf.got.get('puts')` | Vị trí GOT slot trong chương trình | `int` hoặc `None` |
| `elf.plt.get('puts')` | Vị trí PLT stub trong chương trình | `int` hoặc `None` |
| `libc.sym.get('puts')` | Giá trị symbol của `puts` trong libc | `int` hoặc `None` |

Bản thân libc cũng có thể có `libc.got` hoặc `libc.plt`, nhưng chúng thuộc **ELF của libc** và không tương đương các mục GOT/PLT trong chương trình.

### 5.4. Lỗi thường gặp

```python
# Sai về mặt ý nghĩa nếu bạn định lấy địa chỉ hàm puts của libc:
puts_addr = elf.got['puts']
```

`puts_addr` ở đây là **địa chỉ GOT slot** trong ELF của chương trình. Để tra cứu symbol trong libc, dùng:

```python
puts_symbol = libc.sym['puts']
```

Địa chỉ symbol lúc này vẫn cần được hiểu trong hệ quy chiếu `libc.address` hiện tại.

---

## 6. `address`: offset, base và địa chỉ runtime

Đây là phần quan trọng nhất khi làm việc với libc trong CTF.

### 6.1. Ba khái niệm khác nhau

1. **File offset:** Vị trí byte trong file `libc.so.6` (ví dụ `0x1000` từ đầu file).
2. **Symbol relative address:** Địa chỉ symbol trong không gian địa chỉ ELF, thường được gọi tắt là offset với libc ET_DYN base 0.
3. **Runtime address:** Địa chỉ thực tế khi process đã nạp libc vào bộ nhớ.

Không phải file offset và symbol relative address luôn bằng nhau. Chúng liên quan tới các `PT_LOAD` segment.

### 6.2. `libc.address` trả về gì?

```python
print(libc.address)
print(hex(libc.address))
```

**Kiểu:** `int`.

`libc.address` là địa chỉ base được đối tượng `ELF` sử dụng. Ban đầu, với libc chia sẻ ET_DYN thông thường, nó bằng `0`.

Nó không tự động lấy base từ GDB, `/proc/<pid>/maps` hay một tiến trình khác.

### 6.3. Thay đổi `libc.address`

Ví dụ chỉ để hiểu phép tính:

```python
libc = ELF('./libc.so.6', checksec=False)

initial_base = libc.address
old_puts = libc.sym['puts']

# Đây chỉ là base GIẢ ĐỊNH, không phải địa chỉ leak thực tế.
demo_base = 0xF7D00000
libc.address = demo_base

new_puts = libc.sym['puts']
assert new_puts == old_puts + (demo_base - initial_base)
```

Pwntools cập nhật các địa chỉ trong `symbols`, `got`, `plt`, `functions` khi đổi base.

**Không tự động cập nhật:** nội dung `section.header.sh_addr` hoặc `segment.header.p_vaddr` khi bạn sửa `libc.address`. Đây là điểm rất dễ gây nhầm lẫn khi đọc ELF bằng `get_section_by_name()`.

### 6.4. Công thức mô tả địa chỉ đã nạp

Với libc ET_DYN thông thường có base ban đầu `0`:

```text
runtime_symbol_address = libc_base + relative_symbol_address
```

Suy ra:

```text
libc_base = runtime_symbol_address - relative_symbol_address
```

Ví dụ toán học với số giả định:

```python
example_relative = 0x0004C8D0
example_base     = 0xF7D00000
example_runtime  = example_base + example_relative

print(hex(example_runtime))  # 0xf7d4c8d0
print(hex(example_runtime - example_relative))  # 0xf7d00000
```

Đây là phép tính địa chỉ, không phải phương pháp tự lấy địa chỉ từ một process.

### 6.5. Vì sao địa chỉ có thể thay đổi?

**ASLR (Address Space Layout Randomization)** có thể thay đổi vị trí thư viện chia sẻ mỗi lần tiến trình khởi động. Vì vậy:

- Offset/symbol layout của **cùng một file libc** thường không đổi.
- Base runtime có thể thay đổi.
- Khi đổi phiên bản libc, offset symbol cũng có thể thay đổi.

### 6.6. Đổi base và kiểm chứng bằng GDB trong lab

Với một chương trình tin cậy của chính bạn, có thể xem mappings trong GDB:

```gdb
info proc mappings
```

Hoặc ở Linux:

```bash
cat /proc/<PID>/maps
```

Thông tin này dùng để **đối chiếu địa chỉ process do bạn sở hữu/được phép phân tích**. Cần phân biệt địa chỉ bắt đầu của một mapping có file offset khác `0` với base load bias của chính thư viện.

---

## 7. `search()`: tìm chuỗi và mẫu byte

### 7.1. Cú pháp

```python
libc.search(needle, writable=False, executable=False)
```

| Tham số | Kiểu | Ý nghĩa |
|---|---|---|
| `needle` | `bytes` | Mẫu byte cần tìm |
| `writable` | `bool` | Chỉ xét segment writable |
| `executable` | `bool` | Chỉ xét segment executable |

**Trả về:** generator/iterator sinh ra các địa chỉ `int`, **không phải `int` trực tiếp**.

### 7.2. Lấy kết quả đầu tiên: `next()`

```python
first = next(libc.search(b'/bin/sh\x00'), None)
print(first)
```

- Nếu có: `first` là `int` (địa chỉ phù hợp với base hiện tại).
- Nếu không: `first` là `None`.
- Dùng giá trị mặc định `None` tránh `StopIteration`.

`b'/bin/sh\x00'` là một ví dụ quen thuộc để nghiên cứu chuỗi trong libc. Ký tự `\x00` biểu diễn byte kết thúc chuỗi C. Việc chuỗi có tồn tại hay không phụ thuộc file libc cụ thể.

### 7.3. Lấy tất cả địa chỉ

```python
matches = list(libc.search(b'GNU'))
print(type(matches))  # list
print(len(matches))
for addr in matches[:10]:
    print(hex(addr))
```

**Trả về:** `list[int]`.

### 7.4. Tìm mẫu byte khác

```python
locations = list(libc.search(b'\x7fELF'))
```

Hoặc tìm chuỗi chính xác:

```python
matches = list(libc.search(b'printf\x00'))
```

Lưu ý: tên symbol `printf` không nhất thiết xuất hiện dưới dạng chuỗi kết thúc NUL tại vị trí bạn mong đợi. **Tra cứu symbol nên ưu tiên `libc.sym`.**

### 7.5. Tìm trong segment executable

```python
# Dùng cho phân tích mã máy trong file libc, không tác động runtime.
positions = list(libc.search(b'\xc3', executable=True))
print('Số byte 0xc3 trong segment executable:', len(positions))
```

Byte `0xc3` có thể tương ứng opcode `ret` trên x86, nhưng không phải mọi lần xuất hiện đều là một lệnh hợp lệ ở ranh giới instruction. Để phân tích gadget, dùng thêm `ROP(libc)` hoặc disassembly.

### 7.6. `search()` KHÔNG tìm ở đâu?

- Không tìm ở khoảng trống giữa các segment.
- Không quét nội dung **process runtime**.
- Không tự tìm dữ liệu chỉ tồn tại trong vùng nhớ chưa được khởi tạo (`.bss`) nếu file không chứa các byte tương ứng.

---

## 8. Đọc dữ liệu, string và disassembly

### 8.1. `libc.read(address, count)`

```python
head = libc.read(libc.address, 4)
print(head)
```

Với ELF tiêu chuẩn có mapping đầu tiên chứa ELF header, kết quả có thể là:

```python
b'\x7fELF'
```

**Trả về:** `bytes` hoặc `None` khi địa chỉ không thể đọc theo bố cục ELF.

**Chú ý:** tham số `address` ở đây là **virtual address theo base của đối tượng ELF**, không phải vị trí `seek()` trong file.

### 8.2. `libc.string(address)`

Đọc chuỗi NUL-terminated:

```python
addr = next(libc.search(b'GNU'), None)
if addr is not None:
    print(libc.string(addr))
```

**Trả về:** `str` (không bao gồm `\x00`); nếu không đọc được chuỗi hợp lệ thì kết quả có thể là chuỗi rỗng.

### 8.3. `libc.disasm(address, n_bytes)`

```python
addr = libc.sym.get('puts')
if addr is not None:
    text = libc.disasm(addr, 24)
    print(text)
```

**Trả về:** `str` chứa disassembly của `n_bytes` byte từ địa chỉ đã chỉ định.

Địa chỉ của function được tính theo `libc.address` hiện tại. Khi phân tích CTF x86 32-bit, đảm bảo `libc.arch == 'i386'` để disassembler sử dụng kiến trúc tương ứng.

### 8.4. `libc.get_data()` và `libc.data`

```python
raw = libc.get_data()
print(type(raw))       # bytes
print(raw[:4])         # b'\x7fELF'

also_raw = libc.data
```

Hai cách đều giúp lấy dữ liệu toàn bộ file ELF (đây **không** phải toàn bộ vùng nhớ runtime của thư viện).

### 8.5. `libc.read` và `libc.write` không phải syscalls `read`/`write`

```python
libc.read(address, count)
```

là API đọc **bản ánh xạ nội dung ELF** trong đối tượng Python. Nó **không** tương đương lời gọi hệ thống `read(fd, ...)` trong tiến trình mục tiêu.

Tương tự:

```python
libc.write(address, b'ABCD')
```

sửa nội dung ELF đang được Pwntools quản lý; không sửa bộ nhớ của process đã chạy. Muốn lưu thay đổi vào file bản sao, dùng `libc.save('libc_copy.so.6')` (không ghi đè thư viện hệ thống).

---

## 9. Section, segment và chuyển đổi offset

### 9.1. Section là gì?

Section chia file ELF theo mục đích logic:

- `.text`: mã máy.
- `.rodata`: dữ liệu chỉ đọc.
- `.data`: dữ liệu khởi tạo, thường có quyền ghi.
- `.bss`: vùng dữ liệu chưa khởi tạo.
- `.dynsym`: bảng symbol động.
- `.dynstr`: chuỗi tên symbol động.

### 9.2. `get_section_by_name()`

```python
sec = libc.get_section_by_name('.text')
if sec is not None:
    print(sec.name)
    print(hex(sec.header['sh_addr']))
    print(hex(sec.header['sh_offset']))
    print(hex(sec.header['sh_size']))
```

**Trả về:** đối tượng `Section` của pyelftools, hoặc `None`.

- `sh_addr`: virtual address ghi trong header ELF.
- `sh_offset`: vị trí bắt đầu section **trên file**.
- `sh_size`: kích thước section.

`sh_addr` trong header không tự đổi khi sửa `libc.address`.

### 9.3. `libc.section(name)`

```python
text_bytes = libc.section('.text')
if text_bytes is not None:
    print(type(text_bytes))
    print(len(text_bytes))
```

Đây là dữ liệu nội dung section, không phải `Section` object.

### 9.4. Duyệt section

```python
for sec in libc.sections:
    print(sec.name, hex(sec['sh_addr']), hex(sec['sh_size']))
```

`libc.sections` là danh sách các section. Một số ELF bị strip hoặc tạo đặc biệt có thể thiếu nhiều section.

### 9.5. Segment là gì?

Segment (chủ yếu các `PT_LOAD`) mô tả các vùng sẽ được loader nạp vào bộ nhớ, kèm quyền như read/write/execute.

```python
for seg in libc.segments:
    print(seg.header.p_type,
          hex(seg.header.p_vaddr),
          hex(seg.header.p_offset),
          hex(seg.header.p_memsz))
```

Một segment có thể chứa nhiều section. Phân tích virtual address và file offset nên ưu tiên xét cấu trúc `PT_LOAD`.

### 9.6. `vaddr_to_offset()` và `offset_to_vaddr()`

```python
# Địa chỉ virtual -> file offset
file_offset = libc.vaddr_to_offset(libc.sym['puts'])
print(file_offset)

# File offset -> virtual address
if file_offset is not None:
    virtual_address = libc.offset_to_vaddr(file_offset)
    print(hex(virtual_address))
```

**Trả về:** `int` hoặc `None` nếu không có mapping tương ứng.

Công thức thường gặp trong một segment `PT_LOAD`:

```text
file_offset = p_offset + (virtual_address - p_vaddr)
```

Trong đó `virtual_address` và `p_vaddr` phải nằm trong **cùng hệ quy chiếu địa chỉ**. Khi base được đổi bởi Pwntools, dùng các hàm chuyển đổi thay vì tự trừ tùy ý.

### 9.7. `.bss()`

```python
bss_addr = libc.bss()
print(hex(bss_addr))
```

**Trả về:** `int` chứa địa chỉ `.bss` theo base hiện tại (nếu section tồn tại). `libc.bss(offset)` cho phép cộng thêm offset.

---

## 10. Bảo vệ ELF, Build ID, phiên bản libc

### 10.1. `libc.checksec()`

```python
print(libc.checksec())
```

Cho biết các đặc điểm bảo vệ của file, ví dụ NX, canary, RELRO, PIE, ... Tùy phiên bản, màu và định dạng trình bày có thể khác nhau.

Các thuộc tính hữu ích:

```python
print('PIE:', libc.pie)      # bool
print('NX:', libc.nx)        # bool
print('Canary:', libc.canary)  # bool
print('RELRO:', libc.relro)  # str: ví dụ 'Full', 'Partial' hoặc None
```

**Phân biệt:** PIE là đặc tính của file; ASLR là cơ chế bố trí địa chỉ của hệ thống khi chạy.

### 10.2. `libc.buildid`

```python
buildid = libc.buildid
if buildid is not None:
    print(buildid.hex())
```

**Kiểu:** `bytes` nếu có GNU Build ID; có thể không có giá trị ở một số file.

GNU Build ID giúp **nhận diện build**, thường đáng tin hơn việc đoán phiên bản từ tên file `libc.so.6`.

Kiểm tra bằng lệnh Linux:

```bash
readelf -n ./libc.so.6
```

### 10.3. Kiểm tra thư viện thực tế bằng lệnh Linux

```bash
file ./libc.so.6
readelf -h ./libc.so.6
readelf -n ./libc.so.6
readelf -Ws ./libc.so.6 | grep ' puts@@\| printf@@'
readelf -l ./libc.so.6
```

Đây là các lệnh **đọc thông tin file** và không cần chạy mã của libc.

Không có một thuộc tính `libc.version` phổ quát được tài liệu hóa trong đối tượng ELF của Pwntools 4.15.0. Nếu cần xác minh chính xác bản build, nên kiểm tra Build ID hoặc metadata gói thư viện.

### 10.4. Vì sao hai file libc có thể cho offset khác nhau?

Khác phiên bản glibc, distro, build flags, kiến trúc hoặc patch sẽ làm bố cục function thay đổi. Vì vậy không lấy offset từ một libc bất kỳ rồi mặc định sử dụng cho mọi libc khác.

### 10.5. Cảnh báo khi xem `elf.libs`, `elf.maps`, `elf.libc`

Một số API này thực hiện việc **chạy chương trình** để xác định mappings/dependencies. Với binary CTF chưa tin cậy, chỉ dùng trong sandbox/VM phù hợp; nếu chỉ cần xem file, ưu tiên `readelf`, `file`, `ldd` cũng có những trường hợp nguy hiểm với file không tin cậy, nên không xem việc phân tích động là vô hại.

---

## 11. Kết hợp `ELF(libc)` với `ROP(libc)`

`ELF()` phân tích thông tin của file; `ROP()` phân tích gadget và hỗ trợ xây dựng ROP chain.

```python
from pwn import *

libc = ELF('./libc.so.6', checksec=False)
rop  = ROP(libc)
```

### 11.1. Khác nhau về đối tượng

```python
print(type(libc))  # pwnlib.elf.elf.ELF
print(type(rop))   # pwnlib.rop.rop.ROP
```

| Cần làm | Công cụ |
|---|---|
| Xác định `puts`, `printf`, `read` | `libc.sym[...]` |
| Xem bytes/section | `libc.read(...)`, `libc.section(...)` |
| Tìm chuỗi | `libc.search(...)` |
| Tìm gadget | `rop.find_gadget([...])` |
| Hiển thị chain đã xây | `rop.dump()` |
| Xuất chain dạng bytes | `rop.chain()` |

### 11.2. Quan sát gadget trên i386

```python
if libc.arch != 'i386':
    raise ValueError('Ví dụ này dành cho libc 32-bit i386')

rop = ROP(libc)
ret = rop.find_gadget(['ret'])
if ret is not None:
    print('ret:', hex(ret.address))
    print('instructions:', ret.insns)
    print('stack move:', ret.move)
```

### 11.3. Điều gì xảy ra khi thiết lập base?

Thông thường nên thiết lập địa chỉ trên đối tượng ELF **trước khi** tạo ROP object, để các địa chỉ gadget được lập theo base đang sử dụng:

```python
libc = ELF('./libc.so.6', checksec=False)
libc.address = 0xF7D00000  # BASE GIẢ ĐỊNH CHỈ ĐỂ MINH HỌA
rop = ROP(libc)
```

Nếu đã tạo `ROP(libc)` rồi mới đổi base, hãy tái tạo đối tượng `ROP` hoặc xác minh cách địa chỉ gadget được cập nhật. Đừng giả định mọi gadget cũ sẽ tự đổi theo đối tượng ELF.

### 11.4. So sánh x86 với x86-64

Với Linux x86 **cdecl**, đối số của hàm thường nằm trên stack, không truyền qua `rdi`, `rsi` như SysV x86-64. Vì vậy cách đọc stack trong ROP chain x86 khác đáng kể với x86-64.

---

## 12. Những lỗi phổ biến và cách chẩn đoán

| Lỗi/hiện tượng | Nguyên nhân | Cách giải quyết |
|---|---|---|
| `FileNotFoundError` | Không có `./libc.so.6` trong working directory | `pwd`, `ls -l`, dùng đường dẫn tuyệt đối |
| `ELFError` hoặc lỗi parse | File không phải ELF hợp lệ | `file`, `readelf -h` |
| `libc.sym['abc']` gây `KeyError` | Symbol `abc` không tồn tại | Dùng `libc.sym.get('abc')`, liệt kê symbol |
| `next(libc.search(...))` gây `StopIteration` | Không tìm thấy mẫu | Dùng `next(..., None)` |
| `hex(libc.search(...))` gây `TypeError` | `search()` trả về generator | Dùng `next(...)` hoặc `list(...)` |
| `libc.sym['puts']` trông rất nhỏ | Đây có thể là offset/địa chỉ theo base 0 | Kiểm tra `libc.address` |
| Địa chỉ runtime sai | Base sai hoặc file libc không khớp | Xác minh mappings, Build ID và file libc |
| `libc.got['puts']` không có | libc không nhất thiết có mục GOT `puts` | Phân biệt với `elf.got['puts']` |
| `libc.plt['puts']` không có | libc không nhất thiết có stub PLT cho symbol đó | Kiểm tra `libc.plt.keys()` |
| `elf.arch != libc.arch` | Binary và libc khác kiến trúc | Dùng libc đúng i386/amd64 |
| Đổi `libc.address` nhưng `sh_addr` không đổi | Header section chưa được rebase | Dùng API ELF hoặc xét base thủ công |
| `libc.read()` khác dữ liệu process | Đang đọc ELF file, không phải runtime memory | Phân biệt rõ hai nguồn dữ liệu |
| Gọi `elf.libs` với file lạ | Có thể thực thi binary không tin cậy | Phân tích tĩnh hoặc cách ly bằng VM |

### 12.1. Phân biệt `None`, `0`, exception

- `.get('name')` có thể trả về `None`, nhưng **địa chỉ `0` vẫn là một số nguyên hợp lệ**.
- Do vậy, kiểm tra `is None` thay vì `if not value` khi phải phân biệt `0` với "không tìm thấy".
- `libc.sym['missing']` gây `KeyError`, không trả `None`.

```python
value = libc.sym.get('puts')
if value is None:
    print('Không tồn tại')
else:
    print(f'Có symbol, giá trị = {value:#x}')
```

---

## 13. Script thực hành có thể chạy ngay

Lưu dưới tên `libc_inspect.py`. Chỉ cần có file `libc.so.6` trong cùng thư mục. Script **không chạy file libc** và không sửa file.

```python
#!/usr/bin/env python3
from pwn import *
from pathlib import Path

LIBC_PATH = './libc.so.6'
assert Path(LIBC_PATH).is_file(), 'Không tìm thấy libc.so.6'

libc = ELF(LIBC_PATH, checksec=False)

print('========== BASIC INFORMATION ==========')
print('Path:', libc.path)
print('Arch:', libc.arch)
print('Bits:', libc.bits)
print('Endian:', libc.endian)
print('ELF type:', libc.elftype)
print('PIE:', libc.pie)
print('Base:', hex(libc.address))

print('\n========== SECURITY ==========')
print('NX:', libc.nx)
print('Canary:', libc.canary)
print('RELRO:', libc.relro)
buildid = libc.buildid
print('Build ID:', buildid.hex() if buildid is not None else 'N/A')

print('\n========== SYMBOLS ==========')
for name in ['puts', 'printf', 'read', 'write', 'malloc', 'free', 'system']:
    addr = libc.sym.get(name)
    print(f'{name:10s}: {addr:#x}' if addr is not None else f'{name:10s}: MISSING')

print('\n========== FIND BYTE SEQUENCES ==========')
for needle in (b'/bin/sh\x00', b'GNU'):
    first = next(libc.search(needle), None)
    print(repr(needle), '->', hex(first) if first is not None else 'NOT FOUND')

print('\n========== IMPORTANT SECTIONS ==========')
for name in ['.text', '.rodata', '.data', '.bss', '.dynsym']:
    sec = libc.get_section_by_name(name)
    if sec is None:
        print(name, '-> NOT FOUND')
    else:
        print(name, 'file offset=', hex(sec['sh_offset']),
              'vaddr=', hex(sec['sh_addr']),
              'size=', hex(sec['sh_size']))

print('\n========== BASE RELOCATION DEMO ==========')
old_base = libc.address
old_puts = libc.sym.get('puts')

if old_puts is not None:
    libc.address = old_base + 0x100000  # Phép dịch base minh họa
    print('Old base:', hex(old_base))
    print('New base:', hex(libc.address))
    print('Old puts:', hex(old_puts))
    print('New puts:', hex(libc.sym['puts']))
    assert libc.sym['puts'] - old_puts == 0x100000

libc.close()
```

Chạy:

```bash
python3 libc_inspect.py
```

**Bạn nên tự giải thích được:** vì sao `search()` cần `next()`, tại sao `sym.get()` không gây `KeyError`, và vì sao thêm `0x100000` vào `libc.address` cũng làm địa chỉ symbol tăng đúng `0x100000`.

---

## 14. Cheat sheet và bài tập tự kiểm tra

### 14.1. Cheat sheet ngắn

```python
from pwn import *

elf  = ELF('./chall', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

# Thông tin file
libc.path
libc.arch
libc.bits
libc.bytes
libc.endian
libc.elftype
libc.address
libc.buildid

# Symbol
libc.sym['puts']            # int; KeyError nếu thiếu
libc.sym.get('puts')        # int hoặc None
libc.functions.get('puts')  # Function hoặc None

# GOT/PLT: thuộc chương trình CHALL
elf.got.get('puts')         # int hoặc None
elf.plt.get('puts')         # int hoặc None

# Search
libc.search(b'/bin/sh\x00')
next(libc.search(b'/bin/sh\x00'), None)
list(libc.search(b'GNU'))

# Địa chỉ
libc.address = 0xF7D00000  # Chỉ là base giả định
libc.sym.get('puts')

# Đọc/phân tích
libc.read(libc.address, 4)
libc.get_section_by_name('.text')
libc.section('.text')
libc.vaddr_to_offset(libc.sym['puts'])
libc.offset_to_vaddr(0x1000)
libc.disasm(libc.sym['puts'], 16)

# ROP
rop = ROP(libc)
rop.find_gadget(['ret'])
```

### 14.2. Năm câu hỏi tự kiểm tra

1. `libc.sym['puts']` trả về đối tượng `Function` hay số nguyên `int`?
2. Tại sao `hex(libc.search(b'GNU'))` không dùng được?
3. Sự khác nhau giữa `elf.got['puts']` và `libc.sym['puts']` là gì?
4. Vì sao cùng một file libc có offset symbol không đổi nhưng địa chỉ runtime có thể đổi?
5. Sau khi `libc.address += 0x1000`, liệu `libc.get_section_by_name('.text').header.sh_addr` có tự cộng `0x1000` không?

**Đáp án:** (1) `int`; (2) trả về generator, cần `next()`; (3) ô GOT của chương trình so với địa chỉ symbol trong libc; (4) ASLR đổi base runtime; (5) không, phần header section không tự được rebase.

### 14.3. Ba điều nhớ lâu nhất

- **Tra cứu symbol:** `libc.sym['name']` → `int`.
- **Tìm chuỗi:** `libc.search(b'...')` → **generator**, dùng `next(..., None)` hoặc `list(...)`.
- **Đổi base:** `libc.address = ...` → các symbol của đối tượng được rebase; **không tự tìm được địa chỉ thực tế**.

---

## 15. Nguồn tham khảo

Tài liệu được viết lại bằng lời giải thích và ví dụ độc lập, đối chiếu từ các tài liệu API chính thức sau:

1. **Pwntools — `pwnlib.elf.elf` (ELF Files):** https://docs.pwntools.com/en/stable/elf/elf.html
2. **Pwntools — `pwnlib.rop.rop` (ROP):** https://docs.pwntools.com/en/stable/rop/rop.html
3. **Pwntools — `pwnlib.libcdb` (Libc Database):** https://docs.pwntools.com/en/stable/libcdb.html
4. **Linux `readelf` manual (binutils):** https://sourceware.org/binutils/docs/binutils/readelf.html
5. **ELF gABI specification:** https://gabi.xinuos.com/

> **Giới hạn:** Tài liệu tập trung vào API ELF/Pwntools và địa chỉ trong phòng lab. Nó không giả định file libc cụ thể của bạn có mọi symbol, mọi gadget hoặc có thể chạy trên hệ thống hiện tại.

---

**Gợi ý commit:**

```bash
git add pwntools_libc_elf_x86_cheatsheet.md
git commit -m "docs: add Vietnamese pwntools libc ELF x86 reference"
git push
```
