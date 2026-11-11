# SỔ TAY GDB CHO PWNABLE CTF

> **Từ cơ bản đến nâng cao — thực hành trên Linux x86-64 và x86-32**  
> Phạm vi: binary do bạn tự biên dịch, challenge CTF và hệ thống mà bạn được phép kiểm thử.  
> Mục tiêu: **đọc được trạng thái chương trình, kiểm chứng giả thuyết bằng GDB, hiểu tại sao chương trình crash**, thay vì chỉ sao chép lệnh.

---

## Mục lục

1. Tư duy debug và môi trường luyện tập
2. Khởi động GDB, chạy chương trình và điều hướng
3. Thanh ghi, ABI, `call`, `ret` và syscall
4. Đọc bộ nhớ với `x` — kỹ năng quan trọng nhất
5. Stack frame và xác định địa chỉ biến
6. Theo dấu `read`, `write`, `scanf`, `malloc`, `free`
7. Breakpoint, watchpoint, điều kiện và lệnh tự động
8. Đọc assembly, hiểu các lệnh thường gặp
9. PIE, ASLR và cách tính địa chỉ runtime
10. ELF, PLT/GOT, libc và linker động
11. Debug crash, core dump và offset
12. Sử dụng Pwndbg hiệu quả
13. Heap debugging từ cơ bản đến nâng cao
14. Tiến trình con, thread, signal và syscall
15. Tích hợp GDB với pwntools và tmux
16. Docker, libc/ld và tính nhất quán của môi trường
17. Kỹ thuật nâng cao: logging, script, reverse execution
18. Quy trình debug một challenge Pwnable
19. Phòng lab thực hành và bài tập
20. Bảng lệnh tra cứu và những lỗi thường gặp

---

# 1. Tư duy debug và môi trường luyện tập

## 1.1. GDB là gì?

**GNU Debugger (GDB)** là trình gỡ lỗi giúp bạn:

- Dừng chương trình tại một **instruction** hoặc dòng mã nguồn.
- Kiểm tra **registers**: `RIP`, `RSP`, `RBP`, `RAX`, `RDI`, `RSI`, `RDX`…
- Đọc bộ nhớ của **stack**, **heap**, **.data**, **.bss**, libc.
- Quan sát **luồng điều khiển** giữa các hàm và các lệnh nhảy.
- Phát hiện vị trí **giá trị bị thay đổi** và nguyên nhân crash.
- Đối chiếu một giả thuyết đưa ra từ IDA/Ghidra với trạng thái thật khi chạy.

Trong Pwnable, GDB không phải công cụ “tự động giải bài”; nó trả lời những câu hỏi có thể kiểm chứng:

- Dữ liệu được đọc vào **địa chỉ nào**?
- Bộ đệm có **kích thước thực tế** là bao nhiêu?
- Sau một hàm, **thanh ghi trả về** chứa gì?
- Biến cục bộ nào nằm cạnh bộ đệm trên stack?
- Một con trỏ trỏ vào vùng nhớ nào? Vùng đó có quyền đọc/ghi/chạy không?
- Vì sao một địa chỉ hoạt động trong lần chạy này nhưng không đúng ở lần khác?

## 1.2. Cài đặt (Ubuntu/Kali)

```bash
sudo apt update
sudo apt install -y gdb gdbserver gcc binutils file tmux

gdb --version
file ./chall
readelf -h ./chall
```

`file` cho biết kiến trúc (ELF 32/64-bit), liên kết động/tĩnh và phần nào thông tin strip. `readelf -h` giúp xác nhận kiểu ELF và máy đích.

**Lưu ý:** Pwndbg là tiện ích mở rộng cho GDB, không thay thế GDB. Xem hướng dẫn chính thức tại <https://pwndbg.re/>; kiểm tra yêu cầu phiên bản khi cài.

## 1.3. Chương trình thực hành an toàn

Tạo `demo.c`:

```c
#include <stdio.h>
#include <unistd.h>

struct user {
    char name[16];
    int score;
    char active;
};

struct user users[2] = {
    {.name = "alice", .score = 100, .active = 1},
    {.name = "bob",   .score = 200, .active = 1}
};

__attribute__((noinline))
void inspect(void) {
    char buf[64] = {0};
    puts("Input:");
    ssize_t n = read(0, buf, sizeof(buf));
    printf("read=%zd, first=%02x\n", n, (unsigned char)buf[0]);
}

int main(void) {
    inspect();
    return 0;
}
```

Biên dịch:

```bash
gcc -g -O0 -fno-omit-frame-pointer -o demo demo.c
```

Trong đó:

| Tùy chọn | Mục đích |
|---|---|
| `-g` | Giữ thông tin debug để xem biến, kiểu dữ liệu, dòng nguồn |
| `-O0` | Giảm tối ưu hóa, giúp việc đối chiếu mã nguồn và assembly dễ hơn |
| `-fno-omit-frame-pointer` | Giúp quan sát stack frame theo `RBP` rõ ràng hơn trên nhiều bản build |
| `-o demo` | Chọn tên file đầu ra |

Nếu muốn nghiên cứu ảnh hưởng của các cơ chế bảo vệ trong **lab riêng**, hãy biên dịch thêm các biến thể có/không có PIE, stack protector… **Không áp dụng cấu hình yếu bảo mật cho chương trình triển khai thực tế.**

---

# 2. Khởi động GDB, chạy chương trình và điều hướng

## 2.1. Mở binary

```bash
gdb -q ./demo
```

`-q` bỏ phần thông báo chào lúc khởi động.

Một số lệnh quan trọng:

```gdb
help
help x
help break
file ./demo
run
run AAA BBB
start
starti
quit
```

| Lệnh | Ý nghĩa |
|---|---|
| `run` / `r` | Khởi chạy hoặc chạy lại chương trình |
| `start` | Chạy và dừng gần điểm bắt đầu `main` khi tìm thấy symbol phù hợp |
| `starti` | Dừng ở instruction đầu tiên của quá trình khởi chạy |
| `continue` / `c` | Chạy đến breakpoint hoặc sự kiện dừng tiếp theo |
| `next` / `n` | Đi một dòng C, **không bước vào** hàm được gọi |
| `step` / `s` | Đi một dòng C, **có thể bước vào** hàm được gọi |
| `nexti` / `ni` | Đi một instruction, không bước vào `call` |
| `stepi` / `si` | Đi một instruction, có bước vào `call` |
| `finish` | Chạy đến lúc frame của hàm hiện tại trả về |
| `until` | Chạy tới điểm phù hợp tiếp theo trong frame / vị trí chỉ định |
| `backtrace` / `bt` | Xem chuỗi lời gọi hàm |

**Trong Pwnable, `ni` và `si` thường hữu ích nhất** vì câu hỏi tập trung vào máy thực thi instruction nào.

Ví dụ:

```gdb
break main
run
x/10i $rip
ni
x/10i $rip
```

### Đọc assembly nhanh

```gdb
set disassembly-flavor intel
disassemble main
disassemble /r main
x/12i $rip
x/8i $rip-16
```

`disassemble /r` hiển thị thêm mã máy. `x/12i $rip` xem 12 lệnh từ địa chỉ instruction hiện tại.

## 2.2. Đưa input cho chương trình

**Bàn phím:**

```gdb
run
```

**Chuyển hướng stdin từ file:**

```bash
printf 'hello\n' > input.txt
```

```gdb
run < input.txt
```

**Truyền tham số dòng lệnh:**

```gdb
set args one two
run
```

**Input nhị phân:**

```bash
python3 - <<'PY'
with open('input.bin', 'wb') as f:
    f.write(b'A' * 32 + b'\x00\x01\xff\n')
PY
```

```gdb
run < input.bin
```

`read(0, ...)` đọc **byte thô**; `scanf("%s", ...)` và `fgets(...)` có quy tắc xử lý khác nhau. Không suy đoán dữ liệu đã nhập vào bộ nhớ nếu chưa kiểm tra.

## 2.3. Cấu hình GDB tiện dụng

```gdb
set pagination off
set disassembly-flavor intel
set print pretty on
set print elements 0
set confirm off
```

Để lưu cấu hình, thêm các dòng cần thiết vào `~/.gdbinit`. Không chạy file cấu hình GDB không rõ nguồn gốc.

---

# 3. Thanh ghi, ABI, `call`, `ret` và syscall

## 3.1. Thanh ghi x86-64 cần nhớ

| Thanh ghi | Vai trò thường gặp |
|---|---|
| `RIP` | Instruction pointer: địa chỉ instruction hiện tại/tiếp theo sẽ chạy |
| `RSP` | Stack pointer: đỉnh stack hiện tại |
| `RBP` | Frame pointer khi compiler dùng khung stack dựa trên RBP |
| `RAX` | Giá trị trả về; thanh ghi thường dùng để chứa syscall number |
| `RDI` | Tham số 1 của hàm theo System V AMD64 ABI |
| `RSI` | Tham số 2 |
| `RDX` | Tham số 3 |
| `RCX` | Tham số 4 của **hàm thông thường** |
| `R8`, `R9` | Tham số 5, 6 của hàm thông thường |
| `R10` | Tham số 4 của **Linux syscall** |
| `EFLAGS` | Các cờ điều kiện như ZF, CF, SF, OF |

GDB:

```gdb
info registers
info registers rip rsp rbp rax rdi rsi rdx
p/x $rsi
p/d $rax
p/t $eflags
```

`$rax` là giá trị của thanh ghi `RAX`. Cú pháp `p/x` in theo hex, `p/d` theo thập phân.

**Đừng nhầm hai ABI:**

| Vị trí | Hàm C thường (System V AMD64) | Linux syscall x86-64 |
|---|---|---|
| 1 | `RDI` | `RDI` |
| 2 | `RSI` | `RSI` |
| 3 | `RDX` | `RDX` |
| 4 | `RCX` | `R10` |
| 5 | `R8` | `R8` |
| 6 | `R9` | `R9` |
| Số syscall | Không áp dụng | `RAX` |
| Trả về số nguyên/con trỏ | `RAX` | `RAX` |

Với lời gọi hàm C, các đối số bổ sung thường được đưa qua stack. `RAX` là một trong các thanh ghi trả về; giá trị dấu phẩy động dùng quy ước khác.

## 3.2. Đọc `call` và `ret`

Ví dụ:

```asm
push rbp
mov  rbp, rsp
sub  rsp, 0x50
...
leave
ret
```

Khi `call foo` thực thi, CPU lưu địa chỉ quay lại trên stack rồi chuyển điều khiển tới `foo`. `ret` lấy một địa chỉ từ stack để trở về.

Quan sát:

```gdb
x/i $rip
x/8gx $rsp
si
x/8gx $rsp
```

`leave` thường tương đương `mov rsp, rbp; pop rbp` trong trường hợp khung hàm cổ điển. **Không phải hàm nào cũng dùng `RBP` làm frame pointer**: compiler có thể tối ưu hoặc dùng mô hình stack khác.

## 3.3. x86-32 khác gì?

Ở chương trình Linux x86-32 với **cdecl**, tham số hàm thông thường thường nằm trên stack; giá trị trả về số nguyên trong `EAX`.

```gdb
info registers eip esp ebp eax ebx ecx edx
x/16wx $esp
x/10i $eip
```

Ví dụ khi dừng **ngay trước** `call foo` có 2 tham số, hãy dựa vào các lệnh `push` trước đó để xem cách truyền đối số. Khi đã vào `foo`, bố cục cổ điển là:

```text
[EBP+0x0c] tham số 2
[EBP+0x08] tham số 1
[EBP+0x04] địa chỉ trả về
[EBP+0x00] saved EBP
```

Bố cục trên là **ví dụ cho cdecl có frame pointer**, không phải quy tắc chung cho mọi ABI.

Linux x86-32 dùng `int 0x80` truyền số syscall trong `EAX` và các đối số đầu qua `EBX`, `ECX`, `EDX`…; không dùng trực tiếp bảng thanh ghi x86-64.

---

# 4. Đọc bộ nhớ với `x` — kỹ năng quan trọng nhất

## 4.1. Cú pháp chuẩn

```gdb
x/NFU ADDRESS
```

- **N — count:** số đơn vị cần hiển thị.
- **F — format:** `x` hex, `d` signed decimal, `u` unsigned decimal, `c` ký tự, `s` chuỗi, `i` instruction, `t` nhị phân, `a` địa chỉ.
- **U — unit size:** `b` = 1 byte, `h` = 2 byte, `w` = 4 byte, `g` = 8 byte.

Ví dụ:

```gdb
x/32bx $rsp       # 32 byte dưới dạng hex
x/16gx $rsp       # 16 đơn vị 8 byte = 128 byte
x/16wx $esp       # 16 đơn vị 4 byte = 64 byte
x/8i $rip         # 8 instruction
x/s $rsi          # diễn giải bộ nhớ tại RSI như chuỗi kết thúc bằng NUL
x/20cb $rsi       # 20 byte dưới dạng ký tự
```

**Rất quan trọng:** `x/10gx` là **10 × 8 = 80 byte**, không phải 10 byte. Lệnh `x/80bx` mới hiển thị đúng **80 byte**.

Nếu bạn định gõ `x/0x50xg &users` để đọc một struct dài `0x50` byte, dễ nhầm giữa **số đơn vị** và **số byte**; cách rõ nhất là:

```gdb
x/80bx &users     # 80 byte
x/10gx &users     # cùng 80 byte, nhóm thành 10 số 8 byte
```

Nếu dùng `x/80gx`, bạn sẽ đọc tới **640 byte**. Trong các lệnh `x`, nên viết N dạng **thập phân** cho dễ kiểm chứng.

## 4.2. `x/s`, `x/gx`, `p/x` khác gì?

```gdb
x/s $rsi
x/gx $rsi
p/x $rsi
```

- `x/s $rsi`: xem **nội dung tại địa chỉ** `RSI` như chuỗi C, cho tới `\0`.
- `x/gx $rsi`: xem **8 byte ở địa chỉ** `RSI` như một số hex.
- `p/x $rsi`: xem **giá trị của thanh ghi** `RSI` như hex (thường là một địa chỉ), không tự đọc dữ liệu tại địa chỉ ấy.

Ví dụ `RSI = 0x7fffffffdc00` và bộ nhớ ở đó là `41 42 43 00 ...`:

```text
p/x $rsi     -> 0x7fffffffdc00
x/s $rsi     -> "ABC"
x/4bx $rsi   -> 0x41 0x42 0x43 0x00
```

**Cảnh báo:** `x/s` chỉ phù hợp khi thực sự mong đợi chuỗi có byte `\0`. Với dữ liệu nhị phân, kết quả có thể dừng sớm hoặc đọc xa hơn phạm vi bộ đệm. Hãy ưu tiên `x/Nbx` khi chưa biết dữ liệu là gì.

## 4.3. Con trỏ và gián tiếp

```gdb
p/x &users
p/x users
p sizeof(users[0])
ptype users[0]
p users[0]
p &users[1]
x/32bx &users[0]
```

Với binary có symbol và kiểu từ `-g`, GDB giúp xem trường của struct trực tiếp.

Nếu chương trình bị `strip`, hãy dùng kiến thức từ IDA/Ghidra để tự tính offset. Ví dụ **giả sử** một mảng cấu trúc mỗi phần tử dài 80 byte:

```gdb
set $base = (char *)&users
x/80bx $base
x/80bx $base+80
x/10gx $base+80
```

Lệnh `x/80bx $base+80` đọc phần tử thứ hai nếu giả thuyết **stride = 80** là chính xác. Đừng mặc định byte đầu tiên của struct là “tên” chỉ vì bạn thấy ký tự ASCII; xác định từng trường bằng cách đối chiếu các lệnh đọc/ghi tại offset tương ứng.

## 4.4. Endianness (little-endian)

Trên x86-64 thông dụng, giá trị 64-bit:

```text
0x1122334455667788
```

nằm trong bộ nhớ theo thứ tự byte:

```text
88 77 66 55 44 33 22 11
```

Vì thế:

```gdb
x/8bx ADDRESS
x/gx ADDRESS
```

có thể tạo cảm giác “ngược thứ tự” nhưng cùng mô tả một dữ liệu.

## 4.5. Đo khoảng cách địa chỉ

```gdb
p/d (char *)&target - (char *)&buf
p/x (char *)&target - (char *)&buf
p/d (long)$rbp - (long)$rsi
```

Ví dụ `buf` ở `RBP-0x60`, `target` ở `RBP-0x10` thì chênh lệch là `0x50` byte **trong đúng bản build đó**. Nếu chỉ biết địa chỉ runtime, lấy chênh lệch hai địa chỉ sau khi chương trình đã dừng.

---

# 5. Stack frame và xác định địa chỉ biến

## 5.1. Sơ đồ minh họa x86-64

Ở hàm có prologue `push rbp; mov rbp, rsp; sub rsp, 0x60`, một bố cục **có thể** như sau:

```text
Địa chỉ cao
+----------------------------+  RBP + 0x08
| saved return address (8B) |
+----------------------------+  RBP + 0x00
| saved RBP            (8B) |
+----------------------------+  RBP - 0x08
| dữ liệu cục bộ / padding  |
+----------------------------+  RBP - 0x10
| biến local                |
+----------------------------+
| ...                      |
+----------------------------+  RBP - 0x60
| buf hoặc dữ liệu khác     |
+----------------------------+  RSP (có thể ở đây)
Địa chỉ thấp
```

**Không được coi sơ đồ là luật bắt buộc.** Compiler có thể thay thứ tự biến, padding, lưu register, canary, vector data, dùng red zone, hoặc bỏ frame pointer. `RBP-0x10` chỉ là ví dụ; không suy ra kiểu biến chỉ từ offset.

## 5.2. Xác định `buf` ở đâu

Từ source:

```c
char buf[64];
read(0, buf, 64);
```

Quan sát ngay trước lệnh `call read@plt`:

```gdb
disassemble inspect
break inspect
run
# dùng ni/si tới ngay trước call read
info registers rdi rsi rdx
p/x $rsi
x/64bx $rsi
```

Theo SysV AMD64 ABI, đối số 2 của `read` là **địa chỉ bộ đệm**, nên ở thời điểm ngay trước `call read`, thường `RSI` giữ địa chỉ `buf`.

**Điểm dễ sai:** đọc `x/s $rsi` **trước khi read trả về** có thể chỉ thấy dữ liệu cũ hoặc toàn byte 0. Phải dừng **sau** lời gọi để kiểm tra byte mới được ghi.

## 5.3. Phân biệt saved RBP, return address và dữ liệu đầu vào

```gdb
x/12gx $rsp
x/4gx $rbp
x/gx $rbp           # 8 byte saved RBP khi dùng frame pointer cổ điển
x/gx $rbp+8         # 8 byte địa chỉ trả về khi dùng frame đó
```

Một lần nữa, `RBP+8` chỉ có ý nghĩa như vậy nếu hàm thật sự dùng bố cục cổ điển và khung chưa bị phá hỏng.

## 5.4. Theo dõi stack từng instruction

```gdb
break inspect
run
disassemble inspect
x/16gx $rsp
ni
x/16gx $rsp
```

Quan sát trước/sau:

- `push reg`: `RSP` giảm, giá trị được lưu lên stack.
- `sub rsp, 0x40`: dành chỗ cho local.
- `call`: đẩy return address rồi chuyển hàm.
- `pop reg`: lấy giá trị ở stack, tăng `RSP`.
- `ret`: lấy return address từ stack.

**RSP không bắt buộc giữ nguyên trong suốt hàm**, và stack có thể được căn chỉnh trước lời gọi.

---

# 6. Theo dấu các hàm I/O và cấp phát

## 6.1. `read(fd, buf, count)`

| Trước lời gọi | Thanh ghi x86-64 |
|---|---|
| `fd` | `RDI` |
| `buf` | `RSI` |
| `count` | `RDX` |
| giá trị trả về | `RAX` sau khi hàm hoàn tất |

Quy trình:

```gdb
break read
run
info registers rdi rsi rdx
set $bufptr = $rsi
p/x $bufptr
finish
p/d $rax
x/64bx $bufptr
```

**Chú ý:** `break read` có thể dừng **bên trong libc** ở đầu hàm và `finish` thường trả về chỗ gọi; giá trị trong các thanh ghi đối số có thể bị thay đổi trong quá trình thực thi. Vì thế, lưu địa chỉ `buf` vào biến tiện ích `$bufptr` **trước khi** tiếp tục.

Kết quả `read`: số byte đã đọc (có thể ngắn hơn yêu cầu), `0` nếu EOF, `-1` khi lỗi ở mức giao diện libc. `read` **không tự thêm byte `\0`**.

## 6.2. `write(fd, buf, count)`

```gdb
break write
run
info registers rdi rsi rdx
x/64bx $rsi
x/s $rsi              # chỉ khi buffer thật sự là chuỗi C
finish
p/d $rax
```

Nếu `write(1, some_buf, 64)` thì dữ liệu xuất **luôn dựa vào địa chỉ `some_buf`**, không nhất thiết là chuỗi được kết thúc bằng `\0`.

## 6.3. `scanf`, `printf`, `puts`

- `scanf("%d", &age)`: đối số chứa **địa chỉ** để ghi kết quả, không phải chính giá trị `age`.
- `printf("x=%d", x)`: đối số biến thiên phụ thuộc định dạng và ABI.
- `puts(ptr)`: đọc chuỗi C tại `ptr`.

Ví dụ trước `scanf("%d", &age)`:

```gdb
info registers rdi rsi
x/s $rdi
p/x $rsi
x/wd $rsi
```

Ở bản build thường gặp, `RDI` trỏ tới chuỗi định dạng và `RSI` trỏ tới `age`. Sau khi `scanf` trả về, đọc lại vùng `age`. Thực tế có thể có wrapper hoặc tối ưu nên luôn đối chiếu assembly.

## 6.4. `malloc` và `free`

```gdb
break malloc
run
p/d $rdi
finish
p/x $rax
```

`malloc(size)` nhận `size` trong `RDI`, trả con trỏ trong `RAX` (hoặc `NULL` nếu thất bại).

```gdb
break free
continue
p/x $rdi
x/8gx $rdi
```

`free(ptr)` nhận con trỏ trong `RDI`. Việc bộ nhớ sau `free` còn đọc được **không có nghĩa là nó còn hợp lệ để sử dụng**.

---

# 7. Breakpoint, watchpoint và điều kiện

## 7.1. Các loại breakpoint

```gdb
break main
break inspect
break *main+42
break *0x401234
tbreak *main+42
info breakpoints
```

- `break main`: dừng tại function `main` khi symbol có sẵn.
- `break *main+42`: dừng tại **địa chỉ máy** cách đầu function 42 byte, không phải dòng 42.
- `break *0x401234`: dừng tại địa chỉ tuyệt đối trong **không gian địa chỉ runtime**.
- `tbreak`: tự xóa khi hit lần đầu.

Quản lý:

```gdb
disable 1
enable 1
delete 1
clear inspect
```

## 7.2. Breakpoint có điều kiện

```gdb
break read if $rdi == 0
break malloc if $rdi > 0x100
condition 2 $rax == 0
ignore 2 5
```

Cẩn thận với điều kiện dựa trên register tại điểm chưa phải entry của function: thanh ghi có thể đã bị sử dụng cho mục đích khác.

## 7.3. Watchpoint: ai sửa dữ liệu?

Đây là công cụ mạnh để tìm **instruction gây thay đổi giá trị**:

```gdb
watch users[0].score
watch *(int *)0x404080
rwatch *(int *)0x404080
awatch *(int *)0x404080
```

- `watch`: dừng khi biểu thức thay đổi (thường do ghi).
- `rwatch`: dừng khi có truy cập đọc vùng tương ứng, tùy nền tảng.
- `awatch`: dừng khi có truy cập đọc/ghi, tùy nền tảng.

**Quy trình mẫu:** dừng sau khi local đã được khởi tạo, lấy `&target`, đặt watchpoint, `continue`, rồi xem `$rip`/`x/10i $rip` khi bị dừng.

Hardware watchpoint có giới hạn về số lượng, kích thước và căn chỉnh; watchpoint phần mềm có thể chạy chậm.

## 7.4. Tự chạy lệnh khi dừng

```gdb
break inspect
commands
  silent
  printf "RSP = %p, RBP = %p\n", $rsp, $rbp
  x/8gx $rsp
  continue
end
```

Dùng khi muốn **ghi log nhiều lần**, không muốn thao tác tay. Thận trọng: `continue` trong `commands` khiến debugger không dừng lại để bạn tương tác.

---

# 8. Đọc assembly hiệu quả

## 8.1. Các lệnh cần thuộc

| Instruction | Ý nghĩa thực hành |
|---|---|
| `mov dst, src` | Sao chép giá trị từ `src` sang `dst` |
| `lea dst, [address]` | Tính **địa chỉ/biểu thức địa chỉ**, không dereference như `mov` |
| `push x` / `pop x` | Đặt/lấy dữ liệu trên stack |
| `add` / `sub` | Toán học và thường thay đổi flags |
| `cmp a, b` | So sánh theo hiệu để cập nhật flags |
| `test a, b` | AND bitwise, cập nhật flags, không ghi kết quả |
| `je` / `jne` | Nhảy theo cờ ZF |
| `ja` / `jb` | So sánh không dấu (`unsigned`) |
| `jg` / `jl` | So sánh có dấu (`signed`) |
| `call` | Gọi hàm và đặt địa chỉ trả về lên stack |
| `ret` | Trả về theo địa chỉ trên stack |
| `movzx` / `movsx` | Mở rộng zero/sign |
| `cdqe` / `movsxd` | Mở rộng số có dấu sang 64-bit |

## 8.2. Ví dụ dịch assembly sang ý nghĩa C

```asm
lea  rax, [rbp-0x40]
mov  edx, 0x40
mov  rsi, rax
mov  edi, 0x0
call read@plt
mov  QWORD PTR [rbp-0x8], rax
```

Diễn giải:

1. Đặt địa chỉ `RBP-0x40` vào `RAX`.
2. Đặt `count = 0x40` vào `EDX` (ghi `EDX` zero-extend lên `RDX`).
3. Chuyển địa chỉ bộ đệm sang `RSI`.
4. Đặt `fd = 0` vào `EDI`.
5. Gọi `read(0, buf, 0x40)`.
6. Lưu giá trị trả về `RAX` vào local ở `[RBP-8]`.

**Quan trọng:** `[RBP-8]` trong đoạn này chứa số byte đã đọc, không phải đương nhiên là canary hay con trỏ. **Vai trò của offset phải được chứng minh bằng luồng dữ liệu**.

## 8.3. Debug điều kiện nhảy

```gdb
x/6i $rip
info registers eflags
ni
```

Khi gặp `cmp` / `test` rồi `je`, hãy xem **các toán hạng và flags tại đúng thời điểm**. GDB `p/t $eflags` cho thấy bit; Pwndbg thường giải mã flags dễ đọc hơn.

---

# 9. PIE, ASLR và địa chỉ runtime

## 9.1. Phân biệt khái niệm

- **PIE**: binary có thể được nạp ở base address khác nhau.
- **ASLR**: hệ điều hành randomize các vùng địa chỉ (tùy cấu hình và loại mapping).
- **NX**: trang nhớ dữ liệu thường không được phép thực thi.
- **Canary**: kiểm tra biến đổi không mong muốn của vùng stack ở một số hàm.
- **RELRO**: cơ chế bảo vệ các vùng relocation/GOT theo mức cấu hình.

Kiểm tra:

```bash
file ./demo
readelf -h ./demo
readelf -l ./demo
```

Với Pwndbg:

```gdb
checksec
vmmap
piebase
```

## 9.2. Địa chỉ tĩnh khác địa chỉ runtime

Ví dụ IDA ghi một symbol ở offset `0x1250`, còn runtime mapping của PIE bắt đầu tại `0x555555554000`. **Nếu** offset đó là RVA tính từ image base tương ứng:

```text
runtime address = 0x555555554000 + 0x1250
```

Điều này chỉ đúng khi định nghĩa base và offset nhất quán với layout ELF. Đừng cộng bừa địa chỉ file offset vào memory mapping.

Dùng symbol để giảm nhầm:

```gdb
break *main+42
p/x &main
info proc mappings
```

`break *main+42` thường tiện hơn hard-code một địa chỉ tuyệt đối khi ASLR đang bật.

## 9.3. GDB có thể ảnh hưởng ASLR

Trên một số hệ Linux, GDB có tùy chọn mặc định **tắt randomization cho chương trình mà nó khởi chạy**. Kiểm tra:

```gdb
show disable-randomization
set disable-randomization off
run
```

`off` ở đây có nghĩa là **không yêu cầu tắt** ASLR. Nếu muốn tạo lần chạy dễ tái hiện trong lab, xem thêm `set disable-randomization on`. Trình duyệt/container/kernel có thể hạn chế hành vi này; phải kiểm chứng mapping thực tế.

---

# 10. ELF, PLT/GOT, libc và linker động

## 10.1. Các phần ELF hay gặp

| Vùng/section | Vai trò tổng quát |
|---|---|
| `.text` | Mã máy |
| `.rodata` | Hằng và chuỗi tĩnh chỉ đọc |
| `.data` | Biến toàn cục/static đã khởi tạo |
| `.bss` | Biến toàn cục/static zero-initialized |
| `.plt` / `.plt.sec` | Stub cho các lời gọi liên kết động (tùy toolchain) |
| `.got` / `.got.plt` | Các vị trí chứa địa chỉ/relocation phục vụ liên kết động |
| `[heap]` | Vùng cấp phát động (không phải toàn bộ allocation đều nằm ở `[heap]`) |
| `[stack]` | Stack của thread chính |

Lệnh ngoài GDB:

```bash
readelf -S ./demo
readelf -r ./demo
readelf -Ws ./demo
objdump -d -M intel ./demo
objdump -R ./demo
```

## 10.2. Theo dấu `puts@plt`

```gdb
break main
run
disassemble main
x/10i $rip
info sharedlibrary
```

Khi thấy `call puts@plt`:

- PLT là bước trung gian thường gặp trong cơ chế gọi hàm liên kết động.
- GOT chứa dữ liệu phục vụ quá trình relocation/định tuyến lời gọi.
- Nội dung và thời điểm khởi tạo GOT **phụ thuộc** kiểu relocation, lazy/eager binding và cấu hình binary.

Để kiểm tra một entry GOT cụ thể, tìm offset relocation từ `readelf -r`, cộng với base phù hợp khi cần, rồi:

```gdb
x/gx RUNTIME_GOT_ADDRESS
```

Không đồng nhất `puts@plt` (địa chỉ stub) với địa chỉ triển khai `puts` trong libc. Nếu debug symbol dùng được:

```gdb
p/x (void *)puts
info address puts
info sharedlibrary
```

## 10.3. Kiểm tra libc đang dùng

```bash
ldd ./demo
```

```gdb
info sharedlibrary
info proc mappings
```

Chú ý `ldd` trên binary không tin cậy có nguy cơ gây thực thi ngoài ý muốn trên một số trường hợp; ưu tiên phân tích trong môi trường cách ly. `readelf -d` cung cấp thông tin `NEEDED` mà không chạy binary.

---

# 11. Debug crash, core dump và xác định offset

## 11.1. Quy trình khi chương trình crash

```gdb
run < input.bin
bt
info registers
x/12i $rip
x/24gx $rsp
info proc mappings
```

Tự hỏi:

1. Crash ở **instruction nào**?
2. Instruction đó truy cập **địa chỉ nào**?
3. Giá trị địa chỉ đến từ **register/bộ nhớ nào**?
4. Register bị thay đổi ở bước nào?
5. Lỗi thuộc đọc, ghi, thực thi hay logic chương trình?

Không phải crash nào cũng là **return address bị ghi đè**. Có thể con trỏ `NULL`, dereference sai, stack alignment, assert, lỗi `free`, canary phát hiện sai lệch, hoặc đơn giản là input thiếu.

## 11.2. Core dump

Trên hệ thống cho phép:

```bash
ulimit -c unlimited
./demo < input.bin
```

Nếu core dump được tạo và đường dẫn biết rõ:

```bash
gdb -q ./demo ./core
```

Tùy hệ thống, core có thể được quản lý bởi `systemd-coredump`, không nằm ở `./core`. Khi đó xem `coredumpctl list` và `coredumpctl debug` (nếu có).

## 11.3. Cyclic pattern trong lab

Cyclic pattern là chuỗi có tính chất giúp nhận diện vị trí offset của các mẫu byte. Mục đích ở đây là **đo chính xác dữ liệu chạm tới đâu trong stack của chương trình thử nghiệm**, không phỏng đoán.

Ví dụ với pwntools:

```python
from pwn import *
pattern = cyclic(200, n=8)
open('pattern.bin', 'wb').write(pattern)
```

Sau crash, quan sát **byte thực tế** trong stack/register hoặc core. Có thể dùng `cyclic_find()` để tra vị trí của một subsequence đủ dài.

```python
from pwn import *
value = b'aaaabaaa'  # CHỈ là ví dụ chuỗi 8 byte, thay bằng dữ liệu thực tế đã thấy
print(cyclic_find(value, n=8))
```

**Phải dùng cùng giá trị `n` khi sinh và khi tìm**. Trên một số lần crash, `RIP` không trực tiếp chứa pattern vì exception xảy ra tại `ret`; khi đó xem qword ở stack, trạng thái stack và disassembly.

---

# 12. Sử dụng Pwndbg hiệu quả

Pwndbg bổ sung giao diện trình bày context, mapping và các lệnh hữu ích cho phân tích binary. Tên lệnh và đối số có thể thay đổi theo phiên bản; dùng `help COMMAND` để kiểm tra ngay trong môi trường của bạn.

| Lệnh Pwndbg | Tác dụng |
|---|---|
| `context` / `ctx` | Hiển thị tổng quan register, stack, disassembly… |
| `telescope $rsp 20` | Xem chuỗi con trỏ/dữ liệu từ stack theo dạng dễ đọc |
| `vmmap` | Xem mapping và quyền bộ nhớ |
| `xinfo ADDRESS` | Thông tin vùng chứa địa chỉ |
| `hexdump ADDRESS 64` | Hexdump dễ quan sát |
| `checksec` | Xem cơ chế bảo vệ ELF |
| `piebase` | Xem/tính base PIE (tùy cú pháp phiên bản) |
| `got` / `plt` | Thông tin GOT/PLT |
| `heap` | Thông tin heap/chunk |
| `bins` | Danh sách bin/tcache glibc |
| `vis_heap_chunks` | Quan sát heap bằng hình thức trực quan |
| `cyclic` | Sinh/tìm pattern |

Ví dụ:

```gdb
start
context
vmmap
telescope $rsp 16
xinfo $rip
```

### Khi Pwndbg hiển thị quá nhiều thứ

```gdb
context code
context stack
```

Hoặc chỉ dùng GDB chuẩn:

```gdb
x/10i $rip
x/16gx $rsp
info registers
```

GDB gốc và Pwndbg **không phải hai bộ lệnh thay thế nhau**. Học chắc `x`, `p`, `break`, `ni`, `si`, `bt` rồi dùng Pwndbg để tiết kiệm thao tác.

---

# 13. Heap debugging từ cơ bản đến nâng cao

## 13.1. Những kiến thức tối thiểu

`malloc` trả một con trỏ tới vùng dữ liệu người dùng được phép sử dụng. Bộ cấp phát của glibc có thông tin quản lý chunk và nhiều cấu trúc như tcache, fastbins, smallbins, unsorted bin... Cấu trúc cụ thể thay đổi theo **phiên bản glibc, kiến trúc và cấu hình**.

Trong GDB:

```gdb
break malloc
run
p/d $rdi
finish
set $p = $rax
x/64bx $p
```

Tiếp theo quan sát lúc `free`:

```gdb
break free
continue
p/x $rdi
x/8gx $rdi
```

Không phải mọi byte nằm ngay trước `$p` đều chắc chắn là header có bố cục giống nhau trong mọi allocator. Muốn đọc metadata, phải xác định allocator đang sử dụng và tài liệu phiên bản tương ứng.

## 13.2. Với Pwndbg

```gdb
heap
bins
vis_heap_chunks
```

Tùy phiên bản cũng có thể dùng các lệnh chuyên biệt như `tcachebins`, `fastbins`, `unsortedbin`. Hãy thử `help`/`apropos` nếu lệnh không tồn tại.

### Cách học hiệu quả

1. Tạo chương trình gọi `malloc(0x30)`, ghi dữ liệu, `free`, rồi `malloc` lại.
2. Dừng trước/sau mỗi bước.
3. Ghi nhận địa chỉ trả về, kích thước yêu cầu, nội dung bộ nhớ và bin tương ứng.
4. So sánh sự khác nhau giữa nhiều phiên bản glibc trong lab.
5. Phân biệt dữ liệu do ứng dụng sở hữu với metadata do allocator quản lý.

Không suy luận rằng một con trỏ được cấp phát lại cùng địa chỉ **luôn** có nghĩa chương trình bị lỗi: allocator có thể tái sử dụng vùng nhớ đã free hợp lệ.

---

# 14. Debug fork, thread, signal và syscall

## 14.1. Fork/child process

```gdb
set follow-fork-mode child
set detach-on-fork off
info inferiors
inferior 2
```

- `follow-fork-mode parent|child`: chọn tiến trình GDB ưu tiên theo sau.
- `detach-on-fork off`: giữ tiến trình còn lại dưới sự quản lý của GDB (nếu môi trường hỗ trợ).
- `info inferiors`: liệt kê các tiến trình được GDB quản lý.

Rất hữu ích với chương trình tạo child process. Nhưng trong lab `socat TCP-LISTEN:...,fork EXEC:...`, tiến trình bạn cần có thể là **binary con** do socat tạo, không phải chính `socat`.

## 14.2. Thread

```gdb
info threads
thread 2
thread apply all bt
set scheduler-locking step
```

`set scheduler-locking step` hữu ích trong một số tình huống khi muốn hạn chế thread khác chạy trong bước đơn; hành vi tùy target và chế độ debug.

## 14.3. Signal và syscall

```gdb
info signals
catch signal SIGSEGV
catch syscall read
catch syscall write
```

`catch syscall read` có thể dừng cả **lúc vào** và **lúc thoát** syscall. Đừng nhầm register ở thời điểm thoát với register argument lúc vào.

`handle SIGPIPE ...` cho phép cấu hình GDB dừng/in/chuyển signal; tra `help handle` trước khi thay đổi vì signal handling ảnh hưởng hành vi chương trình.

---

# 15. Tích hợp GDB với pwntools và tmux

## 15.1. `gdb.attach()` — gắn vào process đã chạy

```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./demo')
context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'info'

p = process(elf.path)

p.recvuntil(b'Input:\n')  # tiến trình đang chờ read()
gdb.attach(p, gdbscript='''
set disassembly-flavor intel
break printf          # một điểm chưa chạy đến trong demo
continue
''')

p.sendline(b'HELLO')
p.interactive()
```

**Cần hiểu:** `attach` xảy ra **sau khi process bắt đầu chạy**. Ví dụ này attach lúc `demo` đang đợi input, sau đó dừng ở `printf` còn ở phía trước. Nếu `inspect` đã được gọi trước khi attach, breakpoint `break inspect` không thể quay ngược thời gian. Khi muốn dừng ngay từ đầu, dùng `gdb.debug`.

Tùy trình tự của `p.sendlineafter`, `recvuntil` và việc attach, chương trình có thể đang chờ input hoặc đang bị debugger dừng. Quan sát xem bên nào đang chờ bên nào.

## 15.2. `gdb.debug()` — khởi chạy dưới debugger

```python
from pwn import *

context.binary = elf = ELF('./demo')
context.terminal = ['tmux', 'splitw', '-h']

p = gdb.debug(elf.path, gdbscript='''
break main
continue
''')

p.sendlineafter(b'Input:\n', b'HELLO')
p.interactive()
```

`gdb.debug()` thường cần `gdbserver` trên môi trường Linux. Khởi chạy chương trình ngay dưới GDB giúp đảm bảo breakpoint đầu tiên không bị bỏ lỡ.

## 15.3. Vì sao tmux không tự bật pane GDB?

Kiểm tra:

```bash
echo "$TMUX"
tmux list-sessions
which gdb
which gdbserver
```

Các nguyên nhân thường gặp:

- Python được chạy **ngoài phiên tmux** nhưng `context.terminal` lại yêu cầu `tmux splitw`.
- Chưa cài `gdb` hoặc `gdbserver`.
- `gdb.attach()` chưa được thực thi vì script đang chờ `recvuntil`/`sendafter`.
- Chương trình con kết thúc quá nhanh trước khi attach.
- Script dừng trước câu lệnh attach do exception.
- Breakpoint được đặt vào code đã chạy qua từ trước.

**Cách kiểm tra:** thêm `log.info("before attach")`, `log.info("after attach")` để định vị code Python đã chạy tới đâu; không suy đoán lỗi là ở tmux nếu script còn chưa gọi `gdb.attach`.

## 15.4. Copy/scroll trong tmux đang chạy GDB

- `Ctrl+b` rồi `[` để vào copy mode.
- Dùng phím mũi tên/PgUp hoặc tìm kiếm theo key binding hiện tại.
- `Enter` chọn nội dung trong copy mode (tùy cấu hình clipboard).
- `q` hoặc `Esc` thoát copy mode.
- `Ctrl+b` rồi `o` đổi pane.
- `Ctrl+b` rồi phím mũi tên chọn pane theo hướng.

Nếu `set -g mouse off`, chuột thường không thực hiện việc cuộn/copy như mong đợi. Dùng copy mode theo bàn phím, hoặc cấu hình tmux clipboard phù hợp terminal.

---

# 16. Docker, libc/ld và tính nhất quán của môi trường

Một binary có thể hành xử khác nhau giữa máy chủ và máy local vì:

- Phiên bản `libc` và `ld-linux` khác nhau.
- Cấu hình ASLR/PIE hoặc cơ chế bảo vệ khác nhau.
- Input/timeout/cơ chế I/O khác nhau.
- Container giới hạn quyền debug (`ptrace`) và tạo tiến trình con.
- Kiến trúc hoặc environment khác nhau.

## 16.1. Kiểm tra các thư viện

```bash
readelf -l ./chall | grep interpreter
readelf -d ./chall | grep NEEDED
file ./libc.so.6
file ./ld-linux-x86-64.so.2
```

Trong một **lab có bản libc/ld được cung cấp**, có thể khởi chạy qua đúng dynamic linker đó (đường dẫn chỉ là minh họa, thay bằng đường dẫn thực tế):

```bash
./ld-linux-x86-64.so.2 --library-path . ./chall
```

Hãy kiểm tra đúng kiến trúc, đúng cặp loader/libc và các thư viện phụ thuộc. Không phải mọi binary đều dùng được lệnh này; static binary không cần dynamic loader.

## 16.2. Chạy GDB với đúng đường dẫn runtime

```bash
gdb -q --args ./ld-linux-x86-64.so.2 --library-path . ./chall
```

Đây là debug **loader làm executable chính**, nên symbol/breakpoint cho `chall` có thể chỉ sẵn sàng sau khi loader nạp binary. Hãy kiểm tra `info sharedlibrary`, `info proc mappings`, `starti`, và sự kiện load thư viện.

Khi bạn cần debug trực tiếp trong container, quyền `ptrace` phải được môi trường lab cho phép. Không cố vượt quyền của hệ thống; sử dụng cấu hình container được phép cho việc debug.

---

# 17. Kỹ thuật GDB nâng cao

## 17.1. Biến tiện ích (convenience variables)

```gdb
set $buf = $rsi
set $saved_rsp = $rsp
p/x $buf
x/32bx $buf
p/d (long)$saved_rsp - (long)$buf
```

Có thể dùng để **giữ giá trị trước khi các thanh ghi bị ghi đè** sau lời gọi.

## 17.2. Hiển thị tự động khi chương trình dừng

```gdb
display/i $rip
display/8gx $rsp
info display
undisplay 1
```

Không nên thêm quá nhiều `display` vì màn hình dễ bị nhiễu.

## 17.3. Ghi log GDB

```gdb
set logging file gdb-session.log
set logging enabled on
info registers
x/24gx $rsp
set logging enabled off
```

Tên lệnh logging có thể khác trên bản GDB cũ (`set logging on/off`).

## 17.4. GDB command script

Tạo `debug.gdb`:

```gdb
set pagination off
set disassembly-flavor intel
break main
run
info registers
x/12i $rip
x/16gx $rsp
```

Chạy:

```bash
gdb -q -x debug.gdb ./demo
```

Kịch bản này lặp lại cùng một trình tự quan sát trong nhiều lần debug.

## 17.5. Python trong GDB

```gdb
python print(hex(int(gdb.parse_and_eval('$rsp'))))
```

Khi cần, có thể viết GDB Python script để tự động thu thập state sau mỗi breakpoint. Bắt đầu bằng script quan sát (read-only) trước khi học thao tác thay đổi state của tiến trình.

## 17.6. Reverse debugging

GDB có các tính năng ghi lại lịch sử thực thi trên **một số** target:

```gdb
record
reverse-stepi
reverse-continue
```

Khả năng hỗ trợ và mức tiêu thụ tài nguyên phụ thuộc CPU, nền tảng, hệ thống con và loại lệnh; nhiều chương trình không record được toàn bộ. Kiểm tra `help record` và thông báo lỗi khi thử.

## 17.7. Hardware watchpoint, memory access và địa chỉ lỗi

Khi chương trình truy cập sai bộ nhớ:

```gdb
catch signal SIGSEGV
run
x/i $rip
info registers
bt
```

Phân tích operand của instruction. Ví dụ `mov rax, [rdi+0x20]` cần đọc địa chỉ hiệu dụng `RDI+0x20` để biết vùng memory nào bị truy cập.

```gdb
p/x $rdi+0x20
info proc mappings
```

Có thể kiểm tra liệu địa chỉ có thuộc mapping hợp lệ; **không thể chỉ từ SIGSEGV mà kết luận nguyên nhân là stack overflow**.

---

# 18. Quy trình debug một challenge Pwnable

## Giai đoạn A — Recon binary trong lab

```bash
file ./chall
readelf -h ./chall
readelf -l ./chall
readelf -d ./chall
```

Tìm thông tin:

- 32 hay 64 bit?
- Stripped hay có symbol?
- PIE hay non-PIE?
- Liên kết động hay tĩnh?
- Có input nào? Cách nhập dữ liệu là `read` hay `scanf`?

## Giai đoạn B — Đọc logic tĩnh

Xác định từ disassembly/IDA:

- Những hàm xử lý input.
- Đối số của hàm và kích thước buffer.
- Các biến/thành phần struct nằm cạnh nhau.
- Điểm có khả năng sai lệch độ dài, index, loại dữ liệu, dấu.

Không nên giả định pseudocode thể hiện chính xác stack layout; hãy xác minh bằng GDB.

## Giai đoạn C — Đặt 2–3 breakpoint có mục đích

Ví dụ:

1. **Trước** lời gọi `read`: ghi địa chỉ buffer và số byte yêu cầu.
2. **Sau** `read`: ghi giá trị trả về và nội dung buffer thực tế.
3. **Trước** một nhánh quyết định hoặc khi program crash: kiểm tra biến và flags.

## Giai đoạn D — Giữ nhật ký giả thuyết

| Câu hỏi | Lệnh kiểm chứng | Kết quả cần ghi |
|---|---|---|
| Buffer ở đâu? | `p/x $rsi` trước `call read` | Địa chỉ runtime |
| Đọc bao nhiêu byte? | `p/d $rdx`, sau đó `p/d $rax` | Số yêu cầu và số thực |
| Biến local nào bị thay đổi? | `watch *(int *)ADDRESS` | Instruction ghi |
| Stack có gì? | `x/20gx $rsp` | Các qword trước/sau |
| Địa chỉ thuộc vùng nào? | `info proc mappings` / `vmmap` | Mapping và quyền |

## Giai đoạn E — Tái hiện và giải thích

Một kết luận tốt không phải “payload chạy được” mà là:

> `read` nhận con trỏ tới buffer ở `...`, số byte yêu cầu là `...`, giá trị trả về là `...`. Sau lệnh `...`, vùng địa chỉ `...` có thay đổi từ `...` sang `...`. Điều này giải thích được hành vi chương trình ở nhánh `...`.

Đó mới là writeup có giá trị học tập.

---

# 19. Phòng lab thực hành

## Lab 1 — Đọc địa chỉ và nội dung buffer

Sử dụng `demo.c` ở mục 1.

**Nhiệm vụ:**

1. `break read` và `run`.
2. Ghi lại `RDI`, `RSI`, `RDX`.
3. Lưu `$rsi` vào `$bufptr`.
4. `finish`, nhập `ABC`, kiểm tra `$rax` và `x/16bx $bufptr`.
5. Trả lời: tại sao `read` không bắt buộc tự thêm `\0`?

**Đáp án định hướng:** `RSI` là địa chỉ của buffer, `RDX` là số byte yêu cầu tại điểm gọi theo ABI; `RAX` sau lời gọi thể hiện số byte thực đọc. Byte `\0` chỉ có nếu input/caller tạo ra nó.

## Lab 2 — Struct và stride

Dùng mảng `users[2]` trong `demo.c`.

```gdb
break main
run
ptype users[0]
p sizeof(users[0])
p &users[0]
p &users[1]
x/48bx &users[0]
```

**Nhiệm vụ:** tìm offset của `score`, `active`, kích thước struct có padding không. So sánh với `sizeof` thay vì đoán rằng `16+4+1=21` là stride.

**Gợi ý:** dùng `p/d (char *)&users[1] - (char *)&users[0]` và `p/d (char *)&users[0].score - (char *)&users[0]`.

## Lab 3 — Stack frame

```gdb
break inspect
run
disassemble inspect
info registers rbp rsp
x/24gx $rsp
```

**Nhiệm vụ:** xác định instruction lập frame, phát hiện vùng local, và tìm địa chỉ buffer theo lệnh chuẩn bị đối số cho `read`. Không dùng sơ đồ stack mẫu để thay cho kết quả từ assembly.

## Lab 4 — Watchpoint

Thêm vào code tự biên dịch:

```c
users[0].score += 7;
```

Đặt `watch users[0].score`, chạy qua đoạn code và xác định instruction thay đổi điểm.

## Lab 5 — PIE và ASLR

Biên dịch hai bản trong lab:

```bash
gcc -g -O0 -fPIE -pie -o demo_pie demo.c
gcc -g -O0 -fno-pie -no-pie -o demo_nopie demo.c
```

Với mỗi bản:

```gdb
set disable-randomization off
break main
run
p/x &main
info proc mappings
run
p/x &main
```

**Nhiệm vụ:** đối chiếu địa chỉ `main` và mapping giữa các lần chạy, rồi giải thích vì sao break theo symbol/offset thường bền hơn hard-code địa chỉ.

## Lab 6 — Tự động hóa debug

Viết `debug.gdb` sao cho mỗi lần dừng ở `inspect` sẽ in:

- `RSP`, `RBP`.
- 8 qword trên stack.
- 10 instruction tại `RIP`.

Sau đó dùng `gdb -x debug.gdb ./demo` để chạy lặp lại.

---

# 20. Cheat sheet và lỗi thường gặp

## 20.1. Bảng lệnh tối thiểu (nên thuộc lòng)

| Mục tiêu | GDB |
|---|---|
| Mở binary | `gdb -q ./chall` |
| Bắt đầu ở main | `start` |
| Bắt đầu instruction đầu | `starti` |
| Break function | `b main` |
| Break offset | `b *main+42` |
| Break địa chỉ | `b *0x401234` |
| Tiếp tục | `c` |
| Step instruction | `si` |
| Next instruction | `ni` |
| Xem assembly | `disas main` |
| Xem instruction hiện tại | `x/10i $rip` |
| Xem toàn bộ thanh ghi | `info registers` |
| Xem một thanh ghi | `p/x $rsi` |
| Xem 16 qword ở stack | `x/16gx $rsp` |
| Xem 64 byte ở địa chỉ | `x/64bx ADDRESS` |
| Xem chuỗi C | `x/s ADDRESS` |
| Xem call stack | `bt` |
| Xem mapping | `info proc mappings` |
| Xem thread | `info threads` |
| Xem breakpoint | `info b` |
| Giám sát biến | `watch variable` |
| Chạy từ file stdin | `run < input.bin` |
| GDB script | `gdb -x debug.gdb ./chall` |

## 20.2. Mười lỗi rất phổ biến

**1. Nhầm `p/x $rsi` với `x/s $rsi`.** Một cái xem giá trị con trỏ, một cái đọc dữ liệu tại địa chỉ mà con trỏ trỏ tới.

**2. Nhầm số byte trong `x/10gx`.** Đó là 80 byte, không phải 10.

**3. Nhầm `RDI/RSI/RDX` sau khi hàm chạy với đối số ban đầu.** Lưu con trỏ trước lời gọi hoặc dừng đúng call site.

**4. Tin tuyệt đối rằng `RBP-8` là canary.** Offset có thể chỉ là biến local bình thường. Phân tích instruction nào ghi/đọc vị trí đó.

**5. Cho rằng `read` thêm NUL.** Nó không làm vậy; phải đọc chính xác số byte trả về.

**6. Tin rằng mọi địa chỉ IDA dùng nguyên ở runtime.** PIE và ASLR có thể làm base thay đổi.

**7. Dùng `gdb.attach` quá muộn.** Breakpoint không thể bắt một function đã chạy xong.

**8. Dùng `finish` rồi tiếp tục tin rằng toàn bộ register giữ nguyên.** Theo ABI, các caller-saved register có thể thay đổi.

**9. Debug sai libc.** Check phiên bản thực tế, loader, `info sharedlibrary`, mapping và container.

**10. Kết luận lỗi từ một screenshot.** Ghi tối thiểu: instruction, register, memory trước/sau, input và vị trí breakpoint.

## 20.3. Mô hình tư duy 5 câu hỏi

Với mỗi instruction/hàm quan trọng, hãy hỏi:

1. **Đang ở đâu?** — `RIP`, `disassemble`, mapping.
2. **Đang xử lý dữ liệu nào?** — register, `x/..` trên pointer.
3. **Dữ liệu nằm ở đâu?** — stack/heap/global/libc.
4. **Ai thay đổi nó?** — xem `mov`, `write`, `watchpoint`, thời điểm trước/sau.
5. **Điều đó gây ra điều gì?** — flags, nhánh điều kiện, giá trị trả về, crash.

Khi trả lời được năm câu hỏi này bằng chứng cứ từ debugger, khả năng giải và viết writeup Pwnable tiến bộ rõ rệt.

---

## Tài liệu tham khảo chính thức

- [GNU GDB User Manual](https://sourceware.org/gdb/current/onlinedocs/gdb.html/)
- [GDB: Examining Memory](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Memory.html)
- [GDB: Machine Code](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Machine-Code.html)
- [GDB: Starting Programs / ASLR](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Starting.html)
- [Pwndbg Documentation](https://pwndbg.re/stable/)
- [Pwntools GDB API](https://docs.pwntools.com/en/stable/gdb.html)

**Gợi ý học:** bắt đầu từ các lab 1–3, sau đó làm lab 4–6. Khi gặp challenge thật, không cần thuộc toàn bộ lệnh; chỉ cần biết **muốn chứng minh điều gì** và **lệnh nào cho bằng chứng ấy**.
