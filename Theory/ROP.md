
| Lệnh | Công dụng |
|---|---|
| `ROP(elf)` | Tạo đối tượng ROP từ ELF |
| `ROP([elf, libc])` | Phân tích gadget từ nhiều ELF |
| `rop.gadgets` | Xem danh sách gadget đã tìm |
| `rop.find_gadget([...])` | Tìm gadget theo lệnh Assembly |
| `rop.search(...)` | Tìm gadget theo tiêu chí |
| `rop.ret` | Tìm gadget `ret` |
| `rop.eax` | Tìm gadget có thể thiết lập `eax` |
| `rop(eax=value)` | Thêm thao tác thiết lập thanh ghi |
| `rop.raw(value)` | Thêm giá trị hoặc gadget vào chain |
| `rop.call(func, args)` | Thêm một lời gọi hàm |
| `rop.dump()` | Hiển thị cấu trúc ROP chain |
| `rop.chain()` | Xuất ROP chain thành bytes |
| `rop.resolve(name)` | Tra cứu địa chỉ symbol |
| `rop.migrate(address)` | Tạo bước chuyển stack (stack pivot) |

# 📘 Pwntools `ROP()` — Tài liệu tra cứu x86 (i386, 32-bit)

> Sổ tay dành cho việc học Pwnable CTF trong môi trường thực hành được cấp phép. Các địa chỉ trong tài liệu chỉ mang tính minh họa; kết quả phụ thuộc binary và phiên bản Pwntools.

## Mục lục

1. [Tổng quan API và giá trị trả về](#1-tổng-quan-api-và-giá-trị-trả-về)
2. [Khởi tạo và kiểu dữ liệu](#2-khởi-tạo-và-kiểu-dữ-liệu)
3. [Tìm kiếm gadget](#3-tìm-kiếm-gadget)
4. [Xây dựng ROP chain](#4-xây-dựng-rop-chain)
5. [Thiết lập thanh ghi](#5-thiết-lập-thanh-ghi)
6. [Xuất và kiểm tra chain](#6-xuất-và-kiểm-tra-chain)
7. [Tra cứu symbol và địa chỉ](#7-tra-cứu-symbol-và-địa-chỉ)
8. [Phương thức nâng cao](#8-phương-thức-nâng-cao)
9. [Ví dụ thực hành hoàn chỉnh](#9-ví-dụ-thực-hành-hoàn-chỉnh)
10. [Các lỗi phổ biến](#10-các-lỗi-phổ-biến)
11. [Cheat sheet](#11-cheat-sheet)
12. [Tài liệu tham khảo](#12-tài-liệu-tham-khảo)

---

## 1. Tổng quan API và giá trị trả về

| Lệnh / thuộc tính | Giá trị trả về | Công dụng |
|---|---|---|
| `ROP(elf)` | `ROP` | Khởi tạo đối tượng ROP |
| `rop.gadgets` | `dict[int, Gadget]` | Các gadget đã tìm thấy |
| `rop.find_gadget([...])` | `Gadget` hoặc `None` | Tìm gadget theo chuỗi lệnh |
| `rop.search(...)` | `Gadget` hoặc `None` | Tìm gadget theo điều kiện |
| `rop.search_iter(...)` | Iterator của `Gadget` | Duyệt các gadget thỏa điều kiện |
| `rop.ret` | `Gadget` hoặc `None` | Tìm gadget `ret` |
| `rop.eax` | `Gadget` hoặc `None` | Tìm gadget có thể nạp `eax` |
| `rop.raw(value)` | `None` | Thêm giá trị vào chain |
| `rop.call(func, args)` | `None` | Thêm lời gọi hàm |
| `rop(eax=value)` | `None` | Thêm bước thiết lập thanh ghi |
| `rop.dump()` | `str` | Mô tả nội dung chain |
| `rop.chain()` | `bytes` | Xuất chain dạng bytes |
| `rop.build()` | `DescriptiveStack` (dạng danh sách) | Xây dựng các phần tử của chain |
| `rop.setRegisters({...})` | `list` các tuple | Tính các bước thiết lập thanh ghi |
| `rop.resolve(name)` | `int` hoặc `None` | Tra cứu symbol |
| `rop.unresolve(address)` | `str` | Mô tả địa chỉ |
| `rop.describe(obj)` | `str` | Tạo mô tả dễ đọc |
| `rop.generatePadding(offset, count)` | `bytes` | Sinh padding nhận diện được |
| `rop.migrate(address)` | `None` | Thêm bước chuyển vị trí stack |
| `rop.label(name)` | `None` | Đặt nhãn trong chain |
| `rop.ref(name)` | Đối tượng tham chiếu nhãn | Tham chiếu vị trí gắn nhãn |
| `bytes(rop)` | `bytes` | Tương đương `rop.chain()` |

**Lưu ý:** Các phương thức như `raw()`, `call()` và `rop(eax=...)` thường **trả về `None`** nhưng vẫn cập nhật đối tượng `rop`. Muốn xem chain, dùng `rop.dump()` hoặc `rop.chain()`.

---

## 2. Khởi tạo và kiểu dữ liệu

### 2.1. Khởi tạo đối tượng

```python
from pwn import *

context.binary = elf = ELF('./basic_rop_x86_patched')
rop = ROP(elf)

print(type(rop))          # <class 'pwnlib.rop.rop.ROP'>
print(elf.arch)           # i386 nếu binary 32-bit x86
print(elf.bits)           # 32 nếu binary 32-bit
print(context.bytes)      # 4 nếu context là i386
```

- `ELF(...)`: đọc thông tin ELF.
- `context.binary = elf`: đồng bộ kiến trúc, số bit, endianness theo ELF.
- `ROP(elf)`: tạo đối tượng tìm gadget và dựng chain.

Có thể phân tích nhiều ELF:

```python
libc = ELF('./libc.so.6')
rop = ROP([elf, libc])
```

Địa chỉ trong thư viện chia sẻ phải được hiệu chỉnh theo địa chỉ nạp thực tế nếu muốn đối chiếu với runtime. `ROP(elf)` không tự động tìm lỗ hổng, offset tràn bộ đệm hay vượt PIE/ASLR.

### 2.2. Kiểu dữ liệu thường gặp

| Kiểu | Ví dụ | Ý nghĩa |
|---|---|---|
| `int` | `0x08049010` | Số nguyên/địa chỉ |
| `str` | `'0x8049010'` | Văn bản |
| `bytes` | `b'\x10\x90\x04\x08'` | Dữ liệu nhị phân |
| `list` | `[1, 2, 3]` | Danh sách |
| `dict` | `{address: gadget}` | Ánh xạ khóa–giá trị |
| `Gadget` | `Gadget(...)` | Mô tả gadget |
| `None` | `None` | Không tìm thấy/không có giá trị trả về |

```python
address = 0x08049010

print(type(address))       # int
print(type(hex(address)))  # str
print(type(p32(address)))  # bytes
```

`hex()` chỉ đổi biểu diễn số thành chuỗi; `p32()` đóng gói số 32-bit thành bốn byte (thường là little-endian trên i386).

---

## 3. Tìm kiếm gadget

### 3.1. `rop.gadgets`

**Đây là thuộc tính, không phải hàm.**

```python
print(rop.gadgets)
print(len(rop.gadgets))
print(rop.gadgets.keys())
print(rop.gadgets.values())

for address, gadget in rop.gadgets.items():
    print(hex(address), gadget.insns)
```

Giá trị trả về là dictionary có dạng `dict[int, Gadget]`: key là địa chỉ, value là đối tượng `Gadget`.

Tra cứu địa chỉ cụ thể:

```python
gadget = rop.gadgets.get(0x08049020)
if gadget is not None:
    print(gadget.insns)
```

Sử dụng `.get()` thay vì `[...]` nếu không chắc key tồn tại, để tránh `KeyError`.

### 3.2. `rop.find_gadget(instructions)`

Tìm gadget theo chuỗi lệnh Assembly:

```python
gadget = rop.find_gadget(['pop eax', 'ret'])
```

**Trả về:** `Gadget` nếu thấy, `None` nếu không.

Ví dụ minh họa:

```text
Gadget(0x8049020, ['pop eax', 'ret'], ['eax'], 0x8)
```

Các thuộc tính chính:

| Thuộc tính | Kiểu | Ý nghĩa |
|---|---|---|
| `.address` | `int` | Địa chỉ gadget |
| `.insns` | `list[str]` | Các lệnh Assembly |
| `.regs` | `list` | Thanh ghi được nạp từ stack hoặc mô tả dịch chuyển stack |
| `.move` | `int` | Mức dịch chuyển `esp` mà Pwntools mô hình hóa |

```python
gadget = rop.find_gadget(['pop eax', 'ret'])
if gadget is None:
    log.warning('Không tìm thấy gadget')
else:
    print(hex(gadget.address))
    print(gadget.insns)
    print(gadget.regs)
    print(gadget.move)
```

Đối với `pop eax; ret`: `pop eax` tăng `esp` 4 byte, `ret` tăng thêm 4 byte, nên `.move` thường bằng `8`.

| Gadget | `.move` thường thấy trên i386 |
|---|---:|
| `ret` | 4 |
| `pop eax; ret` | 8 |
| `pop eax; pop ebx; ret` | 12 |
| `pop eax; pop ebx; pop ecx; ret` | 16 |
| `add esp, 0x10; ret` | 20 |

Gadget làm thay đổi `esp` theo cách đặc biệt, ví dụ `leave; ret`, có thể được biểu diễn khác với phép cộng byte thông thường.

**Chú ý:** Nếu chỉ tìm `['pop eax']`, một gadget có các lệnh tiếp theo vẫn có thể được chọn; cần kiểm tra `.insns` hoặc chỉ định đủ `['pop eax', 'ret']`.

### 3.3. `rop.search(move=0, regs=None, order='size')`

Tìm gadget theo điều kiện thay vì một chuỗi Assembly cố định:

```python
gadget = rop.search(regs=['eax'])
```

**Trả về:** `Gadget` hoặc `None`.

Các tham số:

- `regs`: các thanh ghi muốn có khả năng thiết lập từ stack.
- `move`: mức dịch chuyển stack **tối thiểu**, không phải nhất thiết bằng chính xác.
- `order`: cách ưu tiên gadget, thường là `'size'` hoặc `'regs'`; một số cách chọn nội bộ có liên quan đến `leave`.

```python
g1 = rop.search(regs=['eax'])
g2 = rop.search(regs=['eax', 'ebx'], order='regs')
g3 = rop.search(move=12)
```

`search()` tìm **một gadget** thỏa điều kiện. Nó không tự kết hợp nhiều gadget để đáp ứng yêu cầu.

### 3.4. `rop.search_iter(move=None, regs=None)`

Trả về iterator duyệt các gadget phù hợp:

```python
for gadget in rop.search_iter(regs=['eax']):
    print(hex(gadget.address), gadget.insns)

all_matches = list(rop.search_iter(regs=['eax']))
print(len(all_matches))
```

Khác biệt: `search()` chọn một kết quả; `search_iter()` cho phép duyệt nhiều kết quả.

### 3.5. `rop.ret`, `rop.eax`, `rop.ebx`, ...

Các thuộc tính động giúp tìm gadget nhanh:

```python
ret_gadget = rop.ret
rax_like_gadget = rop.eax   # i386 sử dụng eax, không phải rax
multi_reg_gadget = rop.eax_ebx
```

`rop.eax` **không phải giá trị thực của thanh ghi trong tiến trình**; đó là một truy vấn tìm gadget.

Phân biệt:

```python
rop.eax                 # Gadget hoặc None
rop.eax.address         # int (nếu có gadget)
rop.eax = 0x1337        # Thêm bước thiết lập eax vào chain
```

`rop.ret_12` là cách truy vấn gadget liên quan mức dịch chuyển stack tối thiểu 12 byte; không có nghĩa nhất thiết tìm được lệnh `ret 12`.

---

## 4. Xây dựng ROP chain

### 4.1. `rop.raw(value)`

Thêm trực tiếp một hay nhiều phần tử vào chain.

**Trả về:** `None`.

```python
rop = ROP(elf)
result = rop.raw(0x12345678)
print(result)       # None
print(rop.dump())   # Có phần tử 0x12345678
```

Thêm danh sách:

```python
rop = ROP(elf)
rop.raw([0x11111111, 0x22222222, 0x33333333])
print(rop.dump())
```

Bố cục tương ứng (i386):

```text
+0x00: 0x11111111
+0x04: 0x22222222
+0x08: 0x33333333
```

Có thể thêm đối tượng `Gadget` hoặc địa chỉ của nó:

```python
rop = ROP(elf)
pop_eax = rop.find_gadget(['pop eax', 'ret'])
if pop_eax is not None:
    rop.raw(pop_eax)          # tương đương rop.raw(pop_eax.address)
    rop.raw(0x1337)
```

Đoạn trên chỉ minh họa cách xếp dữ liệu; để mô hình thực thi hoàn chỉnh còn cần xem địa chỉ tiếp theo sau gadget.

Với dữ liệu bytes:

```python
rop = ROP(elf)
rop.raw(b'AAAA')
rop.raw(b'BBBB')
```

**Cẩn thận:** `rop.raw(b'AAAAA')` có độ dài 5 byte; nó không tự động căn chỉnh về slot 4 byte.

### 4.2. `rop.call(resolvable, arguments=(), abi=None)`

Thêm một lời gọi hàm theo ABI phù hợp.

**Trả về:** `None`.

```python
# Giả sử ELF có symbol display(int a, int b)
rop = ROP(elf)
rop.call(elf.sym['display'], [10, 20])
print(rop.dump())
```

Các tham số:

| Tham số | Vai trò |
|---|---|
| `resolvable` | Tên hoặc địa chỉ hàm |
| `arguments` | Đối số truyền vào |
| `abi` | Quy ước gọi hàm; để `None` cho ABI mặc định phù hợp |

Trên i386 `cdecl`, ngay khi bắt đầu hàm, stack có dạng:

```text
[esp]     return address
[esp+4]   argument 1
[esp+8]   argument 2
```

Khi tạo lời gọi bằng ROP, dữ liệu cần mô phỏng bố cục này. Vì vậy, chuỗi phần tử thường có dạng:

```text
[địa chỉ hàm]
[return address]
[argument 1]
[argument 2]
```

Lời gọi liên tiếp:

```python
# Ví dụ khi ELF thực sự có các symbol này
rop = ROP(elf)
rop.call('display', [10, 20])
rop.call('finish', [])
print(rop.dump())
```

Pwntools sẽ cố sắp xếp việc dọn đối số trên stack giữa các lời gọi, nếu có gadget thích hợp.

Cú pháp rút gọn `rop.display(10, 20)` có thể hoạt động nếu Pwntools phân giải được tên hàm. Sử dụng `rop.call(...)` thường rõ nghĩa và dễ debug hơn.

**Khác với `raw()`:** `raw(elf.sym['display'])` chỉ thêm địa chỉ; `call(...)` còn mô hình các đối số và calling convention.

---

## 5. Thiết lập thanh ghi

### 5.1. `rop(eax=..., ebx=...)`

Đối tượng ROP có thể được gọi như một hàm để thêm các bước thiết lập thanh ghi:

```python
rop = ROP(elf)
rop(eax=0x1111, ebx=0x2222)
print(rop.dump())
```

**Trả về:** `None`.

Pwntools sẽ tìm gadget thích hợp để đưa các giá trị yêu cầu vào thanh ghi. Gadget có thể gồm một hoặc nhiều lệnh `pop`.

So sánh:

```python
rop.eax = 0x1111
rop.ebx = 0x2222
```

với:

```python
rop(eax=0x1111, ebx=0x2222)
```

Cách thứ hai cho phép công cụ xem xét đồng thời các yêu cầu, thường có thể chọn gadget tốt hơn và giảm xung đột thanh ghi.

### 5.2. `rop.setRegisters({...})`

Tính cách thiết lập các thanh ghi, nhưng **không tự thêm** các bước vào chain:

```python
rop = ROP(elf)
result = rop.setRegisters({'eax': 0x1337})
for value, description in result:
    print(value, description)
```

**Trả về:** danh sách các tuple mô tả giá trị cần đặt lên stack và thành phần tương ứng. Nội dung từng tuple có thể chứa địa chỉ gadget, giá trị thanh ghi, gadget hoặc tên thanh ghi.

```python
rop.setRegisters({'eax': 0x1337})  # tính phương án
rop(eax=0x1337)                    # thêm phương án vào chain
```

---

## 6. Xuất và kiểm tra chain

### 6.1. `rop.dump(base=None)`

**Trả về:** `str` — mô tả chain, không phải bytes gửi đến chương trình.

```python
rop = ROP(elf)
rop.raw([0x11111111, 0x22222222])
result = rop.dump()
print(type(result))  # <class 'str'>
print(result)
```

Ví dụ:

```text
0x0000:       0x11111111
0x0004:       0x22222222
```

Hiển thị theo base giả định:

```python
print(rop.dump(base=0x10000000))
```

`base` **không tự tìm ra địa chỉ stack runtime**.

### 6.2. `rop.chain(base=None)`

**Trả về:** `bytes`.

```python
rop = ROP(elf)
rop.raw([0x12345678, 0x11223344])
chain = rop.chain()
print(chain)
print(chain.hex())
print(len(chain))
```

Trên i386 little-endian, dữ liệu là:

```text
b'xV4\x12D3"\x11'
7856341244332211
8
```

Lệnh tương đương:

```python
chain = bytes(rop)
```

| `rop.dump()` | `rop.chain()` |
|---|---|
| `str` | `bytes` |
| Dùng để quan sát chain | Dữ liệu nhị phân đã đóng gói |
| Chứa mô tả và tên gadget | Chứa byte thực tế |

### 6.3. `rop.build(base=None, description=None)`

Tạo cấu trúc các phần tử stack trước khi đóng gói cuối cùng.

```python
rop = ROP(elf)
rop.raw(0x11111111)
rop.raw(0x22222222)
items = rop.build()
print(items)
```

**Trả về:** đối tượng `DescriptiveStack`, hoạt động tương tự `list` (chứ không phải bytes).

Cách hiểu:

- `build()`: tạo danh sách slot đã xử lý.
- `dump()`: biến danh sách đó thành mô tả dễ đọc.
- `chain()`: đóng gói thành bytes.

---

## 7. Tra cứu symbol và địa chỉ

### 7.1. `rop.resolve(resolvable)`

Tìm địa chỉ từ tên symbol hoặc giữ nguyên địa chỉ nguyên được truyền vào.

**Trả về:** `int` hoặc `None`.

```python
address = rop.resolve('puts')
if address is not None:
    print(hex(address))

print(rop.resolve('unknown_function'))  # Thường là None
print(rop.resolve(0x12345678))          # 0x12345678
```

### 7.2. `rop.unresolve(address)`

Tra cứu tên symbol hoặc mô tả gadget từ địa chỉ.

**Trả về:** `str`.

```python
address = elf.sym['main']
print(rop.unresolve(address))
```

Kết quả có thể là `'main'`, `'pop eax; ret'`, hoặc chuỗi rỗng nếu không có mô tả phù hợp.

### 7.3. `rop.describe(obj)`

Tạo một chuỗi mô tả dễ đọc từ gadget, địa chỉ hoặc dữ liệu:

```python
gadget = rop.find_gadget(['pop eax', 'ret'])
if gadget is not None:
    print(rop.describe(gadget))
```

**Trả về:** `str`.

---

## 8. Phương thức nâng cao

### 8.1. `rop.generatePadding(offset, count)`

Sinh `bytes` padding từ mẫu cyclic:

```python
rop = ROP([])
padding = rop.generatePadding(0, 12)
print(padding)
print(len(padding))  # 12
```

- `offset`: vị trí bắt đầu của mẫu.
- `count`: số byte muốn tạo.

### 8.2. `rop.migrate(next_base)`

Thêm các bước chuyển stack pointer sang vị trí mới nếu có gadget cần thiết:

```python
# next_base phải là địa chỉ hợp lệ trong bài lab
rop.migrate(next_base)
print(rop.migrated)  # True nếu thành công
```

**Trả về:** `None`. Phương thức này có thể báo lỗi nếu không tìm được gadget phù hợp. Nó không tự tìm địa chỉ stack mới.

### 8.3. `rop.label(name)` và `rop.ref(name, offset=0)`

Dùng khi chain cần tham chiếu tới vị trí của chính nó:

```python
rop = ROP(elf, base=0x10000000)
rop.label('start')
rop.raw(0x11111111)
rop.raw(rop.ref('start'))
print(rop.dump())
```

- `label()` đánh dấu vị trí, trả về `None`.
- `ref()` tạo tham chiếu nhãn (đối tượng `LabelUser`), được giải quyết khi build.
- Các tham chiếu vị trí cần base phù hợp; `rop.base` không phải là `elf.address`.

---

## 9. Ví dụ thực hành hoàn chỉnh

Ví dụ dùng ELF đơn giản tạo từ Assembly để nghiên cứu API; **không chạy hay gửi ROP chain vào tiến trình**.

```python
#!/usr/bin/env python3
from pwn import *

context.clear(arch='i386', os='linux')
context.log_level = 'info'

elf = ELF.from_assembly('''
.global _start
_start:
    pop eax
    ret

    pop ebx
    ret

    pop ecx
    pop edx
    ret

demo:
    ret
''')

rop = ROP(elf)

print('=== ELF ===')
print('ARCH:', elf.arch)
print('BITS:', elf.bits)

print('\n=== GADGETS ===')
for address, gadget in rop.gadgets.items():
    print(hex(address), gadget.insns)

print('\n=== FIND GADGET ===')
gadget = rop.find_gadget(['pop eax', 'ret'])
if gadget is not None:
    print('Address:', hex(gadget.address))
    print('Instructions:', gadget.insns)
    print('Registers:', gadget.regs)
    print('Stack move:', gadget.move)

print('\n=== SEARCH ===')
gadget = rop.search(regs=['ebx'])
if gadget is not None:
    print('Search result:', gadget)

print('\n=== SET REGISTERS ===')
rop_regs = ROP(elf)
rop_regs(eax=0x1111, ebx=0x2222)
print(rop_regs.dump())

print('\n=== RAW ===')
rop_raw = ROP(elf)
pop_eax = rop_raw.find_gadget(['pop eax', 'ret'])
if pop_eax is not None:
    rop_raw.raw(pop_eax)
    rop_raw.raw(0x1337)
print(rop_raw.dump())

print('\n=== CALL ===')
rop_call = ROP(elf)
rop_call.call('demo', [10, 20])
print(rop_call.dump())

print('\n=== OUTPUT ===')
chain = rop_regs.chain()
print('TYPE:', type(chain))
print('BYTES:', chain.hex())
print('LENGTH:', len(chain))
```

> `demo` chỉ chứa `ret`. Nó minh họa cách `rop.call()` bố trí lời gọi chứ không thực sự xử lý các đối số 10 và 20.

### Câu hỏi tự kiểm tra

1. `rop.gadgets` là `dict` chứa những kiểu dữ liệu nào?
2. `find_gadget(['pop eax', 'ret'])` trả về gì khi không tìm thấy?
3. Vì sao `.move` của `pop eax; ret` thường bằng 8 trên i386?
4. `search(regs=['eax'])` có bắt buộc trả về `pop eax; ret` không?
5. `rop.raw()` trả về `None` thì dữ liệu có được thêm vào chain không?
6. `rop.dump()` khác `rop.chain()` ở điểm nào?
7. `rop.call()` khác `rop.raw(elf.sym['demo'])` ở đâu?
8. Vì sao `rop.eax` không phải là giá trị của thanh ghi `eax` lúc chương trình đang chạy?

---

## 10. Các lỗi phổ biến

| Hiện tượng | Nguyên nhân | Hướng xử lý |
|---|---|---|
| `find_gadget()` trả về `None` | Không có gadget phù hợp trong tập đã phân tích | Kiểm tra lại điều kiện, thử `search()` |
| `AttributeError: 'NoneType' ...` | Truy cập `.address` của `None` | Kiểm tra kết quả trước khi truy cập |
| `raw()` trả về `None` | Bình thường | Xem `rop.dump()` |
| `call()` trả về `None` | Bình thường | Xem `rop.dump()` |
| `rop.dump()` rỗng | Chain chưa có phần tử | Thêm dữ liệu bằng `raw()`, `call()`, ... |
| `dump()` và `chain()` trông khác nhau | Một cái là `str`, một cái là `bytes` | Phân biệt biểu diễn và dữ liệu |
| Không đặt được nhiều thanh ghi | Thiếu gadget thích hợp | Kiểm tra các gadget được nạp |
| Địa chỉ gadget khác runtime | PIE/ASLR hoặc base ELF không chính xác | Đối chiếu vùng nhớ trong GDB |
| `rop.call()` không tạo được chain | Thiếu gadget/calling convention không được đáp ứng | Kiểm tra `.gadgets` và cấu trúc lời gọi |
| `rop.label()` không biết base | Chain chưa có vị trí nền | Khởi tạo `ROP(..., base=...)` với base đã biết |

---

## 11. Cheat sheet

```python
# Khởi tạo
rop = ROP(elf)

# Tìm gadget
rop.gadgets
rop.find_gadget(['pop eax', 'ret'])
rop.search(regs=['eax'])
list(rop.search_iter(regs=['eax']))
rop.ret                 # Gadget hoặc None
rop.eax                 # Gadget hoặc None

# Đọc gadget
gadget = rop.find_gadget(['pop eax', 'ret'])
if gadget is not None:
    gadget.address       # int
    gadget.insns         # list[str]
    gadget.regs          # list chứa regs/thông tin stack
    gadget.move          # int

# Thêm dữ liệu
rop.raw(0x1337)
rop.raw([1, 2, 3])

# Thiết lập thanh ghi
rop(eax=0x1337, ebx=0x2222)
rop.setRegisters({'eax': 0x1337})

# Lời gọi hàm (khi symbol tồn tại)
rop.call(elf.sym['demo'], [1, 2])

# Xuất/kiểm tra
rop.build()             # DescriptiveStack (dạng list)
rop.dump()              # str
rop.chain()             # bytes
bytes(rop)              # bytes

# Tra cứu
rop.resolve('puts')     # int hoặc None
rop.unresolve(0x8049010) # str
rop.describe(0x8049010)  # str

# Nâng cao
rop.generatePadding(0, 12)  # bytes
# rop.migrate(next_base)
# rop.label('here')
# rop.ref('here')
```

**Thứ tự nên học:** `ROP(elf)` → `find_gadget()` → `.address` → `raw()` → `dump()` → `chain()` → `call()` → `search()` → `rop(eax=...)`.

Khi phân tích một gadget, luôn kiểm tra cả **lệnh Assembly**, **thanh ghi bị ảnh hưởng** và **cách `esp` thay đổi**.

---

## 12. Tài liệu tham khảo

- [Pwntools — ROP API](https://docs.pwntools.com/en/stable/rop/rop.html)
- [Pwntools — ELF](https://docs.pwntools.com/en/stable/elf/elf.html)
- [Pwntools — Packing (`p32`, `flat`, ...)](https://docs.pwntools.com/en/stable/util/packing.html)

> **Gợi ý commit:** `docs: add Vietnamese pwntools ROP x86 reference`
