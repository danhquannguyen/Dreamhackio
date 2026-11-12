# Giáo trình `execve()`, Shellcode và Linux Syscalls trong Pwnable CTF

> **Phạm vi:** Linux x86 (i386), x86-64 (amd64), ngôn ngữ C, Assembly, GDB, Pwntools.  
> **Mục đích:** Học, phân tích và thực hành trên binary tự tạo hoặc phòng lab/CTF được cấp phép.  
> **Trình độ:** Từ kiến thức con trỏ C đến các tình huống shellcode nâng cao.

## Mục lục

1. [Bản đồ kiến thức](#1-bản-đồ-kiến-thức)
2. [`execve()` thực sự làm gì?](#2-execve-thực-sự-làm-gì)
3. [Ba tham số `pathname`, `argv`, `envp`](#3-ba-tham-số-pathname-argv-envp)
4. [Đường dẫn thường gặp trong Pwnable CTF](#4-đường-dẫn-thường-gặp-trong-pwnable-ctf)
5. [Khi stdin bị đóng: `close(0)`](#5-khi-stdin-bị-đóng-close0)
6. [Họ hàm `exec*` và các API liên quan](#6-họ-hàm-exec-và-các-api-liên-quan)
7. [Kernel tải ELF, script và dynamic loader](#7-kernel-tải-elf-script-và-dynamic-loader)
8. [Giao diện syscall x86-64 và i386](#8-giao-diện-syscall-x86-64-và-i386)
9. [Shellcode: khái niệm và cấu trúc](#9-shellcode-khái-niệm-và-cấu-trúc)
10. [Shellcode x86-64: bài thực hành an toàn](#10-shellcode-x86-64-bài-thực-hành-an-toàn)
11. [Pwntools: `asm`, `disasm`, `shellcraft`, bad bytes](#11-pwntools-asm-disasm-shellcraft-bad-bytes)
12. [Các họ challenge shellcode](#12-các-họ-challenge-shellcode)
13. [Phân tích bộ lọc opcode và seccomp](#13-phân-tích-bộ-lọc-opcode-và-seccomp)
14. [Kỹ năng xây dựng chuỗi và mảng con trỏ](#14-kỹ-năng-xây-dựng-chuỗi-và-mảng-con-trỏ)
15. [Debug với GDB, strace và /proc](#15-debug-với-gdb-strace-và-proc)
16. [Chủ đề nâng cao và lộ trình học](#16-chủ-đề-nâng-cao-và-lộ-trình-học)
17. [Các bài lab tự luyện và lời gợi ý](#17-các-bài-lab-tự-luyện-và-lời-gợi-ý)
18. [Checklist, lỗi phổ biến, tài liệu tham khảo](#18-checklist-lỗi-phổ-biến-tài-liệu-tham-khảo)

---

## 1. Bản đồ kiến thức

### 1.1. Bốn lớp cần phân biệt

```text
C source / Assembly source
       |
       v
Executable hoặc shellcode bytes
       |
       v
Tiến trình ở user space (register, stack, heap, memory mapping)
       |
       v
System call -> Linux kernel -> tài nguyên hệ điều hành
```

- **C library function**: `execve()`, `printf()`, `system()`... là các hàm có thể được chương trình gọi. Một số là lớp bọc syscall.
- **System call**: giao diện yêu cầu kernel thực hiện tác vụ đặc quyền, ví dụ `execve`, `read`, `write`.
- **Instruction**: `mov`, `push`, `lea`, `syscall`, `int 0x80` là mã máy mà CPU thực thi.
- **Shellcode**: chuỗi byte mã máy được thiết kế để chạy trong một bối cảnh cụ thể. Shellcode *không bắt buộc* mở shell.

### 1.2. Phân biệt `fork()` với `execve()`

```text
fork():                         execve():
   PID 100                         PID 100
      |                               |
      +----> PID 101                image cũ
   cha      con                        |
                                   image mới
                                   PID vẫn 100
```

- `fork()` tạo một tiến trình con.
- `execve()` thay thế **process image** của tiến trình đang gọi: mã, dữ liệu, heap, stack và trạng thái liên quan được thiết lập cho chương trình mới. **Không tự tạo PID mới**.
- Kết hợp thường gặp: `fork()` rồi tiến trình con gọi `execve()`; tiến trình cha có thể `waitpid()`.
- `execve()` thành công **không trả về**; thất bại thường trả `-1` và đặt `errno`.

---

## 2. `execve()` thực sự làm gì?

```c
#include <unistd.h>

int execve(const char *pathname,
           char *const argv[],
           char *const envp[]);
```

Đọc như một câu hỏi gồm ba phần:

1. `pathname`: **Chạy file thực thi nào?**
2. `argv`: **Chương trình mới nhận những đối số nào?**
3. `envp`: **Chương trình mới nhận những biến môi trường nào?**

Ví dụ không cần shell:

```c
#include <stdio.h>
#include <unistd.h>

int main(void) {
    char *args[] = {"echo", "Hello", "Pwnable", NULL};
    char *env[]  = {"LANG=C", NULL};

    execve("/bin/echo", args, env);

    perror("execve");  // Chỉ chạy nếu execve thất bại
    return 1;
}
```

Phân tích: kernel xác định `/bin/echo`, chương trình mới nhận hai đối số `Hello` và `Pwnable`. Kernel không tự ghép các phần tử `argv` thành chuỗi lệnh shell.

### 2.1. Tại sao không quay lại sau `execve()`?

Process image cũ đã được thay bằng chương trình mới. Khi chương trình mới kết thúc, nó không quay lại hàm `main` cũ. Nếu `execve` lỗi, nó thường trả `-1` và đặt `errno`.

### 2.2. Cái gì được giữ lại?

**Thường được giữ:** PID, thư mục làm việc hiện tại (CWD), umask, nhiều file descriptor đang mở, một số thuộc tính quyền và giới hạn tài nguyên. **Được thay hoặc thiết lập lại:** không gian địa chỉ của binary cũ, stack, heap, handler tín hiệu do chương trình cài đặt, các vùng mapping cũ. FD gắn `FD_CLOEXEC` bị đóng khi exec thành công.

`execve("/bin/sh", ...)` không tự cấp quyền root. Quyền của tiến trình mới phụ thuộc thông tin credentials và các quy tắc bảo mật Linux.

---

## 3. Ba tham số `pathname`, `argv`, `envp`

### 3.1. `pathname`: `const char *`

Chuỗi C `"/bin/cat"` nằm trong bộ nhớ dưới dạng:

```text
2f 62 69 6e 2f 63 61 74 00
 /  b  i  n  /  c  a  t  \0
```

- `\0` là byte kết thúc chuỗi C.
- Đường dẫn tuyệt đối `/bin/cat` độc lập với CWD.
- Đường dẫn tương đối `./cat` hoặc `cat` được phân giải theo CWD của tiến trình.
- `execve()` **không tìm trong `PATH`**; `execvp()` thì có.
- Kernel chọn file theo **`pathname`**, không theo `argv[0]`.

### 3.2. `argv`: mảng các con trỏ

```c
char *args[] = {
    "cat",       // args[0]
    "hello.txt", // args[1]
    NULL         // args[2]
};
execve("/bin/cat", args, NULL);
```

`args` là mảng `char *`, không phải một chuỗi dài. Trong tham số hàm, khai báo `char *const argv[]` tương đương con trỏ tới các con trỏ kiểu `char *const *`.

```text
VÙNG CHUỖI (địa chỉ minh họa)
0x401000: "cat\0"
0x401010: "hello.txt\0"

VÙNG argv (x86-64, mỗi con trỏ 8 byte)
0x7fffffffe000: 0x0000000000401000 -> "cat"
0x7fffffffe008: 0x0000000000401010 -> "hello.txt"
0x7fffffffe010: 0x0000000000000000 -> NULL
```

**Hai dạng kết thúc không được nhầm:** mỗi chuỗi C phải có **byte NULL**; cuối mảng `argv` phải có **con trỏ NULL** (8 byte giá trị zero trên amd64, 4 byte trên i386).

**`argv[0]` có bị bỏ qua?** Không. Kernel không dùng nó để tìm chương trình, nhưng chương trình mới *có thể* kiểm tra nó. Đối với `/bin/cat`, `argv[0]` thường là `cat` hoặc `/bin/cat`; một chương trình multi-call như BusyBox có thể thay đổi hành vi theo tên gọi.

**Lỗi cú pháp dễ gặp:** `execve("/bin/cat", ["cat", "hello.txt", NULL], NULL)` không phải cú pháp C hợp lệ. Hãy tạo một mảng `char *args[]` như trên.

### 3.3. `envp`: môi trường của chương trình mới

```c
char *env[] = {
    "PATH=/usr/bin:/bin",
    "LANG=C",
    "HOME=/tmp",
    NULL
};
```

Các chuỗi thường có dạng `TEN=GIA_TRI`. Chương trình mới đọc qua `getenv()`. Trên Linux, `envp = NULL` được xử lý như môi trường rỗng, nhưng đây là đặc điểm không nên dựa vào khi viết chương trình đa nền tảng; dùng `char *env[]={NULL};` rõ ràng hơn.

**Chú ý:** `PATH` ở đây không làm syscall `execve` tìm file. Hơn nữa, glibc `execvpe()` tìm bằng `PATH` của **tiến trình gọi**, không dùng `PATH` được truyền trong `envp` mới.

### 3.4. `sh -c`: ai hiểu chuỗi lệnh?

```c
char *args[] = {"hello", "-c", "echo Hello", NULL};
execve("/bin/sh", args, NULL);
```

Kernel chỉ tải chương trình `/bin/sh` và chuẩn bị `argv`; **chính shell** nhận biết `-c`, phân tích câu lệnh `echo Hello` rồi thực hiện. Nếu dùng `/bin/cat` thay shell, `/bin/cat` không phân tích cú pháp shell như `;`, `|`, `$VAR`.

Cú pháp `sh -c`:

```bash
sh -c 'COMMAND_STRING' [command_name [argument...]]
```

Ví dụ:

```bash
/bin/sh -c 'printf "0=%s 1=%s\n" "$0" "$1"' label data
# 0=label 1=data
```

Đối số sau chuỗi lệnh trở thành `$0` trong `COMMAND_STRING`; các đối số tiếp theo thành `$1`, `$2`... Đây là điểm riêng của shell `-c`.

### 3.5. Các ngộ nhận cần tránh

| Ngộ nhận | Thực tế |
|---|---|
| `argv[0]` quyết định file chạy | `pathname` quyết định |
| `argv` là chuỗi có dấu cách | `argv` là mảng con trỏ |
| `"cat file"` giống `{"cat", "file"}` | Hoàn toàn khác |
| `execve("cat", ...)` tự tìm PATH | Không |
| `execve()` thành công trả `0` | Thành công không trả về |
| `envp` là danh sách lệnh | `envp` chỉ là biến môi trường |

---
## 4. Đường dẫn thường gặp trong Pwnable CTF

> Đường dẫn chỉ mang tính phổ biến, **không đảm bảo tồn tại** trong mọi Docker image. Trên hệ usr-merge, `/bin` thường trỏ tới `/usr/bin`.

### 4.1. Đường dẫn chương trình

| Đường dẫn | Công dụng | Điều cần kiểm tra |
|---|---|---|
| `/bin/sh` | Shell giao diện POSIX | Trên Ubuntu thường trỏ tới `dash`, không nhất thiết là Bash |
| `/bin/bash` | Bash | Có thể không có trong container tối giản |
| `/bin/dash` | Shell gọn nhẹ | Một số cú pháp Bash không hoạt động |
| `/bin/cat` | Đọc file rồi ghi stdout | Có tên file trong `argv` thì không cần stdin để nhận tên file |
| `/bin/echo` | In đối số | Phù hợp thực hành `execve` an toàn |
| `/bin/ls` | Liệt kê thư mục | Hữu ích để học hành vi `argv` |
| `/usr/bin/id` | Hiển thị UID/GID | Không tự nâng quyền |
| `/usr/bin/env` | Xem môi trường / chạy chương trình | Dễ quan sát `PATH`, `LANG` |
| `/usr/bin/python3` | Trình thông dịch Python | Có thể vắng trong container |
| `/bin/busybox` | Một binary nhiều tiện ích | Tên gọi/`argv[0]` có thể ảnh hưởng hành vi |
| `/usr/bin/true`, `/usr/bin/false` | Trả exit code | Thuận tiện học `waitpid` |

### 4.2. Đường dẫn đáng biết nhưng không phải lệnh thông thường

| Đường dẫn | Ý nghĩa |
|---|---|
| `./flag`, `flag.txt`, `/home/ctf/flag.txt` | Tên file dữ liệu trong môi trường CTF; phụ thuộc đề |
| `/dev/null` | Thiết bị đặc biệt, bỏ dữ liệu ghi và đọc ra EOF |
| `/dev/tty` | Terminal điều khiển nếu có |
| `/proc/self/exe` | Link tới file thực thi hiện hành |
| `/proc/self/fd/0` | Đại diện FD 0 nếu procfs được mount |
| `/proc/self/fd/1` | Đại diện FD 1 nếu procfs được mount |
| `/lib64/ld-linux-x86-64.so.2` | Dynamic loader glibc thường gặp trên amd64 |
| `/lib/x86_64-linux-gnu/libc.so.6` | Đường dẫn libc thường gặp trên Debian/Ubuntu |

`cat flag.txt` tìm file theo **CWD**, không tự tìm trong `/bin` chỉ vì binary `cat` ở `/bin`.

Thực hành kiểm tra:

```bash
readlink -f /bin/sh
file /bin/sh /bin/cat
pwd
ls -l /bin/sh /bin/cat
readelf -l /bin/cat | grep -A1 INTERP
```

### 4.3. Gọi trực tiếp chương trình hay qua shell?

```c
// Trực tiếp: cat tự nhận tên file làm argv[1]
char *cat_args[] = {"cat", "hello.txt", NULL};
execve("/bin/cat", cat_args, NULL);
```

```c
// Qua shell: shell parse chuỗi lệnh rồi gọi cat
char *sh_args[] = {"sh", "-c", "cat hello.txt", NULL};
execve("/bin/sh", sh_args, NULL);
```

Đây là hai chương trình C *riêng biệt*. Trong code có input không tin cậy, gọi thẳng chương trình với mảng đối số thường an toàn hơn ghép chuỗi vào `system()` hay `sh -c`.

---

## 5. Khi stdin bị đóng: `close(0)`

### 5.1. File descriptor tiêu chuẩn

```text
FD 0 = stdin   : kênh nhập
FD 1 = stdout  : kênh xuất
FD 2 = stderr  : kênh xuất lỗi
```

`close(0)` chỉ đóng FD 0, **không trực tiếp đóng stdout/stderr**.

| Cách dùng | Có cần nhận câu lệnh từ stdin? | Ghi chú |
|---|---|---|
| `/bin/sh` (không đối số) | Thường có | Có thể thoát khi FD 0 đóng |
| `/bin/sh -c 'echo Hello'` | Không | Lệnh nằm trong argv, nhưng lệnh con vẫn có thể cần stdin |
| `/bin/cat hello.txt` | Không | `cat` tự mở file đã nêu tên |
| `/bin/cat` | Có | Thường lấy dữ liệu từ stdin |
| `/bin/echo Hello` | Không | In trực tiếp từ argv |

### 5.2. Đóng FD không đồng nghĩa cấm dùng lại số FD

```c
#include <fcntl.h>
#include <unistd.h>

close(0);
int fd = open("hello.txt", O_RDONLY);
```

Thông thường, kernel cấp số FD nhỏ nhất chưa sử dụng. Do đó `fd` **có thể bằng 0**. Nếu FD 1 đóng hoặc trỏ tới `/dev/null`, đầu ra cũng không nhất thiết hiện trên terminal.

### 5.3. `FD_CLOEXEC` và sự kế thừa FD

FD đang mở thường sống qua `execve()`, **trừ** FD được đánh dấu close-on-exec. Các cờ `FD_CLOEXEC`, `O_CLOEXEC` giúp phần mềm không vô tình chuyển descriptor nhạy cảm sang chương trình khác.

Phân biệt:

- `close(fd)`: đóng ngay.
- `FD_CLOEXEC`: đóng khi `execve()` thành công.
- `dup2(oldfd, newfd)`: làm `newfd` tham chiếu tới cùng open-file description với `oldfd`, với các quy tắc cờ riêng.

Kiểm tra ở lab:

```bash
ls -l /proc/$$/fd
```

---
## 6. Họ hàm `exec*` và các API liên quan

### 6.1. Giải mã tên hàm

- **`l` = list:** truyền từng đối số lần lượt.
- **`v` = vector:** truyền một mảng con trỏ `argv`.
- **`p` = PATH:** tìm tên chương trình bằng `PATH` nếu tên không chứa `/`.
- **`e` = environment:** truyền mảng môi trường tường minh.

| Hàm | Dạng đối số | Tìm PATH? | Môi trường |
|---|---|---|---|
| `execve(path, argv, envp)` | vector | Không | Tường minh |
| `execv(path, argv)` | vector | Không | Kế thừa |
| `execl(path, arg0, ..., NULL)` | list | Không | Kế thừa |
| `execvp(file, argv)` | vector | Có* | Kế thừa |
| `execlp(file, arg0, ..., NULL)` | list | Có* | Kế thừa |
| `execle(path, arg0, ..., NULL, envp)` | list | Không | Tường minh |
| `execvpe(file, argv, envp)` | vector | Có* | Tường minh |

`*` Tìm kiếm qua PATH chỉ khi tên file không chứa dấu `/`. Với glibc, `execvpe()` tìm bằng `PATH` của tiến trình **gọi**, không phải `PATH` trong `envp` mới.

Ví dụ độc lập (không viết liên tiếp rồi mong tất cả đều chạy):

```c
char *argv[] = {"echo", "Hello", NULL};
char *env[]  = {"LANG=C", NULL};

execve("/bin/echo", argv, env);  // đủ ba tham số
execv("/bin/echo", argv);        // kế thừa môi trường
execl("/bin/echo", "echo", "Hello", (char *)NULL); // dạng list
execvp("echo", argv);            // tìm qua PATH
```

### 6.2. `fexecve()` / `execveat()`

- `fexecve(fd, argv, envp)` chạy chương trình xác định bởi **file descriptor**, thay vì `pathname`.
- `execveat(dirfd, pathname, argv, envp, flags)` cho phép phân giải đường dẫn tương đối theo thư mục `dirfd`; `AT_FDCWD` nghĩa là dùng CWD; `AT_EMPTY_PATH` cho phép tham chiếu file bằng `dirfd` trong một trường hợp cụ thể.
- Với script/interpreter và `FD_CLOEXEC` có nhiều trường hợp đặc biệt; xem manual. Đây là các API riêng biệt, không phải bí danh đơn giản của `execve`.

### 6.3. `system()`, `popen()`, `posix_spawn()`

| API | Sự khác biệt |
|---|---|
| `system("echo Hello")` | Chạy chuỗi qua shell trong tiến trình con, thường chờ hoàn thành |
| `popen("echo Hello", "r")` | Tạo pipe để lấy/gửi dữ liệu liên quan lệnh do shell chạy |
| `posix_spawn()` | Tạo tiến trình mới và nạp chương trình theo giao diện spawn |
| `fork()` | Tạo tiến trình con, không tự nạp binary khác |
| `execve()` | Thay process image hiện tại, giữ PID |

Không ghép dữ liệu không tin cậy trực tiếp vào chuỗi shell; trong phần mềm thông thường, truyền đối số tách biệt giúp tránh command injection.

---

## 7. Kernel tải ELF, script và dynamic loader

### 7.1. ELF động, ELF tĩnh và `PT_INTERP`

- ELF động có thể khai báo segment `PT_INTERP` chỉ đến dynamic loader, ví dụ `/lib64/ld-linux-x86-64.so.2` trên một số hệ glibc amd64.
- ELF tĩnh không dùng external dynamic loader theo cách đó.
- `execve()` cần nạp file và interpreter hợp lệ. Nếu thiếu interpreter, `ENOENT` có thể xuất hiện ngay cả khi file chính tồn tại.

```bash
file ./chall
readelf -h ./chall
readelf -l ./chall | grep -A1 INTERP
readelf -d ./chall | head
```

### 7.2. Script và shebang

```sh
#!/bin/sh
echo "Hello from script"
```

Với script thực thi được, kernel nhận dạng `#!` và sử dụng interpreter chỉ định trong dòng đầu. Đây là cơ chế khác với việc shell hiện tại đọc chuỗi `-c`.

### 7.3. Khi execve thất bại

| `errno` | Giải thích thường gặp |
|---|---|
| `ENOENT` | Thiếu binary, phần tử đường dẫn hoặc ELF/script interpreter |
| `EACCES` | Thiếu quyền thực thi hoặc file system hạn chế |
| `ENOEXEC` | File không có định dạng thực thi được nhận diện |
| `E2BIG` | Tổng kích thước argv/envp vượt giới hạn |
| `EFAULT` | Con trỏ không hợp lệ |
| `ELOOP` | Vòng lặp symlink hoặc interpreter |
| `ENOMEM` | Thiếu bộ nhớ |

`execlp`/`execvp` có vài cơ chế xử lý lỗi đặc biệt khi tìm trong PATH; không suy diễn chúng giống `execve` ở mọi chi tiết.

---

## 8. Giao diện syscall x86-64 và i386

### 8.1. Gọi hàm C khác gọi syscall trực tiếp

**System V x86-64 function ABI:** sáu đối số đầu tiên lần lượt qua `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`.  
**Linux amd64 syscall ABI:** số syscall trong `rax`; sáu tham số qua `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`.

Do đó tham số thứ tư của syscall dùng `r10`, không phải `rcx`. Instruction `syscall` thay đổi `rcx` và `r11`.

### 8.2. `execve` trên amd64

```text
rax = 59               SYS_execve
rdi = pathname         char *
rsi = argv             char **
rdx = envp             char **
```

Ở cấp gọi hàm C `execve@libc`, wrapper của libc lo bước syscall; không cần người gọi đặt `rax=59` trước khi `call execve`.

### 8.3. `execve` trên i386 truyền thống

```text
eax = 11               SYS_execve
ebx = pathname
ecx = argv
edx = envp
```

i386 thường dùng `int 0x80`, amd64 thường dùng `syscall`; syscall number và calling convention khác nhau.

### 8.4. Bảng syscall Linux x86-64 phổ biến

| Tên | Số | Vai trò |
|---|---:|---|
| `read` | 0 | Đọc FD |
| `write` | 1 | Ghi FD |
| `open` | 2 | Mở file truyền thống |
| `close` | 3 | Đóng FD |
| `mmap` | 9 | Tạo memory mapping |
| `mprotect` | 10 | Đổi quyền memory pages |
| `execve` | 59 | Thay image tiến trình |
| `exit` | 60 | Kết thúc thread theo syscall tương ứng |
| `openat` | 257 | Mở file tương đối theo `dirfd` |
| `execveat` | 322 | Exec theo dirfd/path |

**Nhớ:** đây là **số syscall trên amd64 Linux**; không áp dụng nguyên xi trên i386, ARM hoặc AArch64. Một số wrapper libc gọi syscall tên khác (ví dụ `exit(3)` có thể sử dụng `exit_group`).

---
## 9. Shellcode: khái niệm và cấu trúc

### 9.1. Shellcode không đồng nghĩa với shell

Shellcode là **machine code** đặt trong một vùng nhớ và được CPU thực thi. Nó có thể:

- Gọi syscall `write` để xuất một chuỗi.
- Gọi `exit` để kết thúc.
- Thực hiện các phép toán hoặc đọc dữ liệu trong bộ nhớ.
- Yêu cầu `execve` chạy một chương trình.

Từ “shellcode” xuất phát từ các payload ban đầu thường mở shell; ngày nay thuật ngữ rộng hơn.

### 9.2. Các thành phần phải phân tích trước

| Thành phần | Câu hỏi |
|---|---|
| CPU/OS | amd64, i386, AArch64? Linux hay hệ khác? |
| Entry point | CPU bắt đầu thực thi tại byte nào? |
| Memory | Vùng chứa bytes có quyền `PROT_EXEC` không? |
| Stack | `rsp`/`esp` trỏ đến vùng có thể ghi? Alignment ra sao? |
| Registers | Trước khi shellcode chạy, thanh ghi nào đã có dữ liệu? |
| Input | Shellcode đi qua `read`, `scanf`, `strcpy` hay parser riêng? |
| Filtering | Cấm byte đơn, cặp byte, chuỗi, instruction hay syscall? |
| Length | Giới hạn byte đầu vào và byte thực sự được thực thi? |
| FD | stdin/stdout/stderr có mở? Có socket/pipe khác không? |
| Mitigations | NX, ASLR, PIE, canary, RELRO, seccomp áp dụng ở lớp nào? |

### 9.3. Shellcode và exploit khác nhau thế nào?

- **Shellcode:** đoạn mã máy mong muốn được thực thi.
- **Cơ chế chuyển quyền điều khiển:** lỗi phần mềm hoặc mô hình lab cho phép CPU bắt đầu thực thi đoạn mã đó.
- **ROP:** tận dụng những instruction/gadget đã có trong chương trình/thư viện để tổ chức việc tính toán/gọi hàm, thường khi không có quyền thực thi tại buffer.
- **NX/W^X:** hạn chế việc ghi và thực thi trên cùng vùng nhớ; không thể chỉ vì “có bytes” mà mặc định chúng chạy được.

Tách riêng hai câu hỏi: “Payload gồm những instruction nào?” và “Vì sao CPU sẽ thực thi ở địa chỉ đó?”.

### 9.4. PIC: Position-Independent Code

Shellcode thường không biết trước địa chỉ load do ASLR, PIE hoặc `mmap`. **PIC** hạn chế phụ thuộc địa chỉ cố định. Trên amd64, địa chỉ tương đối theo `rip` rất hữu ích:

```asm
lea rsi, [rip + message]
```

Câu lệnh trên tính **địa chỉ** của `message`; nó không tải nội dung chuỗi như `mov rsi, [rip + message]`.

---

## 10. Shellcode x86-64: bài thực hành an toàn

### 10.1. Hello World bằng `write` và `exit`

Đây là shellcode độc lập vị trí, chỉ xuất dòng chữ và thoát:

```asm
.intel_syntax noprefix
.global _start
_start:
    mov eax, 1                /* SYS_write */
    mov edi, 1                /* stdout */
    lea rsi, [rip + message]  /* địa chỉ dữ liệu */
    mov edx, 6                /* độ dài */
    syscall

    mov eax, 60               /* SYS_exit */
    xor edi, edi              /* status = 0 */
    syscall

message:
    .ascii "HELLO\n"
```

**Giải thích từng lệnh:**

1. `eax=1`: chọn syscall `write`.
2. `edi=1`: chọn stdout (FD 1).
3. `lea rsi, [rip + message]`: đưa con trỏ đầu chuỗi vào đối số thứ hai.
4. `edx=6`: ghi sáu byte.
5. `syscall`: chuyển yêu cầu tới kernel.
6. `eax=60`, `edi=0`, `syscall`: thoát với exit status 0.

**Giải thích `mov eax` thay vì `mov rax`:** ghi vào `eax` trên x86-64 sẽ zero-extend lên `rax`, thường đủ khi số syscall vừa 32-bit.

### 10.2. Chạy trong lab qua Pwntools

File `hello_shellcode.py`:

```python
#!/usr/bin/env python3
from pwn import *

context.clear(arch='amd64', os='linux')

source = r'''
    mov eax, 1
    mov edi, 1
    lea rsi, [rip + message]
    mov edx, 6
    syscall

    mov eax, 60
    xor edi, edi
    syscall
message:
    .ascii "HELLO\n"
'''

code = asm(source)
print('Length:', len(code))
print('Hex:', code.hex())
print(hexdump(code))
print(disasm(code))

# Chạy bằng ELF tạm trong lab cục bộ, không cần dịch vụ ngoài.
p = run_assembly(source)
print('Output:', repr(p.recvall(timeout=2)))
```

Vì `message` nằm chung với machine code, `disasm()` có thể cố giải mã phần bytes của chuỗi thành instruction giả. Điều đó **không** có nghĩa CPU sẽ chạy đến chúng khi syscall `exit` thành công.

### 10.3. `execve` ở mức assembly: chương trình lành tính `/bin/echo`

Mục tiêu là biểu diễn đúng con trỏ `pathname`, mảng `argv` và `envp`. Mô hình sau dùng các chuỗi đặt cạnh code; phù hợp để học ABI trong lab không có bộ lọc bad bytes.

```asm
    lea rdi, [rip + path]      /* pathname = "/bin/echo" */
    lea r8,  [rip + arg1]      /* argv[1] */
    xor edx, edx              /* envp = NULL, Linux */

    push rdx                  /* argv[2] = NULL */
    push r8                   /* argv[1] = &arg1 */
    push rdi                  /* argv[0] = &path */
    mov rsi, rsp              /* rsi = &argv[0] */

    mov eax, 59               /* SYS_execve */
    syscall

    /* Chỉ đến đây nếu execve thất bại */
    mov eax, 60
    mov edi, 1
    syscall

path: .asciz "/bin/echo"
arg1: .asciz "CTF-lab"
```

**Hình dung stack ngay trước `syscall`:**

```text
rsp+0x00 : con trỏ tới "/bin/echo"  <- rsi
rsp+0x08 : con trỏ tới "CTF-lab"
rsp+0x10 : NULL (8 bytes zero)
```

Cốt lõi: **`rsi` chứa địa chỉ mảng con trỏ**, không chứa địa chỉ chuỗi đối số thứ nhất. Các chuỗi vẫn phải có `\0` riêng.

Nếu có quy tắc cấm byte `0x00`, bản minh họa này không thỏa ràng buộc: `.asciz` và một số mã lệnh có thể sinh zero bytes. Cần kiểm tra **mã máy thực tế** thay vì nhìn source assembly.

---
## 11. Pwntools: `asm`, `disasm`, `shellcraft`, bad bytes

### 11.1. `asm()` trả về bytes chứ không phải text

```python
from pwn import *
context.clear(arch='amd64', os='linux')

sc = asm('''
    xor eax, eax
    inc eax
''')

print(sc)           # dạng Python bytes
print(sc.hex())     # hex liên tục
print(hexdump(sc))  # bytes và offset
print(disasm(sc))   # instruction được giải mã
print(len(sc))      # tổng số byte
```

**Lưu ý:** assembly source và machine code là hai loại dữ liệu khác nhau. Một instruction `mov` có thể sinh bytes chứa `0x00` dù source không có ký tự `\x00`.

### 11.2. Kiểm tra byte đơn bị cấm

```python
bad = {0x00, 0x0a, 0x0d}

for offset, byte in enumerate(sc):
    if byte in bad:
        print(f'Bad byte 0x{byte:02x} at {offset:#x}')
```

### 11.3. Kiểm tra **cặp byte liên tiếp**

Một bộ lọc có thể kiểm tra `uint16_t` tại từng offset, không phải cấm từng byte riêng. Ví dụ tập cặp opcode được phát hiện trong challenge học tập:

```python
banned_pairs = {
    b'\x0f\x05': 'syscall',
    b'\x0f\x34': 'sysenter',
    b'\xcd\x80': 'int 0x80',
}

for offset in range(len(sc) - 1):
    pair = sc[offset:offset + 2]
    if pair in banned_pairs:
        print(offset, banned_pairs[pair], pair.hex())
```

Đây là kiểm tra **theo bytes**, không khẳng định một cặp byte đó thực sự nằm tại biên instruction. Bộ lọc thô có thể nhận nhầm bytes thuộc dữ liệu hoặc nằm giữa hai instruction.

### 11.4. C của IDA: `_WORD *` và little-endian

```c
unsigned short v4 = *(_WORD *)((char *)shellcode + i);
if (v4 == 0x050F || v4 == 0x340F || v4 == 0x80CD) {
    /* bị từ chối */
}
```

Trong x86 little-endian:

| Giá trị `uint16_t` | Hai byte trong bộ nhớ | Mnemonic |
|---|---|---|
| `0x050F` | `0f 05` | `syscall` |
| `0x340F` | `0f 34` | `sysenter` |
| `0x80CD` | `cd 80` | `int 0x80` |

- `(char *)` trước phép cộng: `+ i` dịch **i byte**.
- Cast `(_WORD *)`: chọn kiểu dữ liệu cần đọc rộng **2 byte**.
- `*`: đọc 2 byte tại địa chỉ đó.
- **Kích thước của biến `v4`** phụ thuộc khai báo của nó; phép đọc vẫn rộng 2 byte. Nếu `v4` được khai báo `uint16_t`, nó cũng rộng 2 byte.
- Nếu vòng lặp quét tới byte cuối mà đọc `_WORD`, nó có thể thử đọc thêm một byte ngoài giới hạn buffer logic; cần xem điều kiện biên thật sự.

### 11.5. `shellcraft` là bộ sinh Assembly

```python
from pwn import *
context.clear(arch='amd64', os='linux')

src = shellcraft.echo('Hello, lab!\n') + shellcraft.exit(0)
print(src)           # Assembly mà shellcraft sinh
sc = asm(src)
print(hexdump(sc))
print(disasm(sc))
```

Hữu ích: `shellcraft.echo`, `shellcraft.write`, `shellcraft.read`, `shellcraft.exit`, `shellcraft.execve` (xem docs theo kiến trúc). **Không mặc định** shellcode sinh ra thỏa giới hạn size, bad bytes, seccomp hoặc trạng thái FD của đề.

### 11.6. Vì sao in hex và disasm đều cần?

- `hexdump` trả lời: “Byte tại offset này là gì?”.
- `disasm` trả lời: “Nếu CPU bắt đầu giải mã từ đây, nó thấy instruction nào?”.
- `len` trả lời: “Có vượt giới hạn số byte không?”.
- `repr` và `.hex()` giúp phát hiện ký tự newline/null ngoài ý muốn.

---

## 12. Các họ challenge shellcode

Bảng dưới là **bản đồ phân tích**, không phải công thức khai thác áp dụng cho hệ thống bên ngoài.

| Dạng challenge | Ràng buộc thường thấy | Điều cần nghiên cứu |
|---|---|---|
| Basic shellcode | Chương trình chạy buffer cho sẵn | Syscall ABI, địa chỉ buffer, quyền execute |
| Tiny shellcode | Rất ít byte | Mã máy từng instruction, register đã có sẵn |
| Bad-character | Cấm một số byte | Encoding của assembler, kiểm tra từng byte |
| Forbidden opcode | Cấm chuỗi bytes/opcode | Byte sequence, ranh giới instruction, vòng quét |
| Alphanumeric/printable | Input chỉ thuộc tập ký tự | Sự khác nhau giữa text input và instruction encoding |
| Position-independent | Không biết địa chỉ tải | RIP-relative, tránh địa chỉ hardcode |
| Close stdin/stdout | Thiếu FD tiêu chuẩn | Phân tích tài nguyên còn mở, cách chương trình nhận argv |
| Shellcode trên stack | Quyền execute phụ thuộc mapping | NX/W^X, quyền của buffer |
| `mmap` sandbox | Có vùng nhớ cấp phát riêng | Kích thước, quyền và địa chỉ vùng mapping |
| Seccomp challenge | Kernel giới hạn syscall | Chính sách BPF, argument checks, syscall được phép |
| Staged input | Input tải theo nhiều giai đoạn | Giao thức nhập, buffer size và entrypoint mỗi stage |
| Self-modifying concept | Code và dữ liệu có thể trộn | Permission, instruction cache/độ tương thích CPU |
| i386 vs amd64 | ABI khác nhau | Register map, syscall numbers, encoding |

### 12.1. Phân biệt ba lớp ràng buộc

1. **Input validation:** chương trình kiểm tra bytes trước khi chạy.
2. **Memory protection:** kernel/CPU quyết định vùng code có được thực thi không.
3. **Syscall policy:** seccomp hoặc cơ chế khác quyết định syscall có được phép không.

Ba lớp này không thay thế cho nhau. Shellcode “không có byte cấm” vẫn có thể bị seccomp chặn; syscall được cho phép cũng không có nghĩa vùng chứa shellcode được execute.

### 12.2. Những câu hỏi cần trả lời trước khi chọn chiến lược trong CTF

- Có cần thực thi chương trình khác thật không, hay chỉ cần in một thông báo xác nhận?
- Có stdin không? Có stdout không? `read` nhận từ FD nào?
- Tài liệu đề có nhắc `shellcode` nhưng binary thực sự gọi `mmap`, `mprotect`, hay nhảy vào buffer như thế nào?
- Bộ lọc xem source input, bytes sau decode, hay bytes thực sự được thực thi?
- Có vô tình dựa vào quyền hoặc đường dẫn không tồn tại trong Docker không?

---

## 13. Phân tích bộ lọc opcode và seccomp

### 13.1. Bộ lọc byte tại user space

Ví dụ một checker duyệt các cặp byte và từ chối ba mẫu đã biết. Những gì phải ghi lại khi reverse:

- Điều kiện vòng lặp: quét `i < len`, `i+1 < len` hay tới `len-2`?
- Kiểu con trỏ trước khi cộng (`char *`, `uint16_t *`)?
- Đọc byte, word hay dword?
- So sánh giá trị **little-endian** hay theo từng bytes?
- Dữ liệu input có bị thay đổi trước khi kiểm tra không?
- Việc kiểm tra có bao phủ cùng vùng bytes sau đó được thực thi không?

Khi debug, đặt breakpoint **trước** và **sau** hàm kiểm tra; so sánh `hexdump` của buffer với bytes mà CPU thực thi trong lab.

### 13.2. Seccomp khác opcode filter

**Opcode filter** thường đọc bytes ở user space và từ chối một số mẫu. **Seccomp filter** là chính sách của kernel xét syscall (và có thể xét tham số). Nếu bộ lọc không cho phép `execve`, thay đổi cách viết đường dẫn hoặc `argv[0]` **không làm syscall đó trở thành hợp lệ**.

Dùng các man-page để hiểu chính sách và cách giới hạn tác vụ; kiểm thử chỉ trong môi trường lab.

### 13.3. Dấu hiệu để phân biệt khi reverse

| Quan sát | Nghiêng về |
|---|---|
| Vòng lặp `memcmp`, so sánh `_WORD`, `strchr` trên buffer | Byte/string filter |
| `prctl(PR_SET_SECCOMP, ...)` hoặc `seccomp(...)` | Seccomp |
| Program crash `SIGSEGV` khi nhảy vào buffer | Cần xem memory mapping, pointer, NX |
| Syscall trả `-EPERM`, `-ENOSYS` hoặc process bị signal | Cần xem rule kernel và cách filter phản hồi |

Không suy luận kết quả chỉ từ tên challenge; kiểm tra implementation thật.

---
## 14. Kỹ năng xây dựng chuỗi và mảng con trỏ

Đây là phần nối trực tiếp kiến thức C với Assembly và GDB.

### 14.1. Một chuỗi không phải một con trỏ

```c
char path[] = "/bin/echo";  // bytes của chuỗi nằm trong mảng
char *p = path;             // p chứa địa chỉ byte đầu tiên
```

Trên x86-64:

- `sizeof(path)` bằng 10 (`/bin/echo` dài 9 ký tự + `\0`).
- `sizeof(p)` thường bằng 8 (kích thước con trỏ).
- `strlen(path)` bằng 9 (không tính `\0`).

### 14.2. Một mảng con trỏ khác với mảng bytes

```c
char *args[] = {"echo", "Hello", NULL};
```

Mảng `args` chứa ba con trỏ: đến `"echo"`, đến `"Hello"`, và `NULL`.

```text
args
 |
 +-- [0] --> 'e' 'c' 'h' 'o' '\0'
 +-- [1] --> 'H' 'e' 'l' 'l' 'o' '\0'
 +-- [2] --> NULL
```

Còn:

```c
char args2[] = "echo Hello";
```

`args2` chỉ là **một mảng byte**, không phải `argv` có nhiều chuỗi.

### 14.3. `lea` và `mov` tại địa chỉ

```asm
lea rdi, [rip + path]   ; rdi = địa chỉ chuỗi path
mov rax, [rdi]          ; đọc 8 byte dữ liệu từ địa chỉ rdi
mov rsi, rsp            ; rsi = địa chỉ hiện tại của stack
```

Các lệnh trên có ý nghĩa khác nhau. Khi cần `pathname` cho `execve`, thường cần **địa chỉ**, không phải giá trị 8 byte đầu của chuỗi.

### 14.4. `push` ảnh hưởng stack ra sao?

Giả sử `rsp=0x7000`:

```asm
push rax
```

Trên amd64, `rsp` giảm 8 thành `0x6ff8`, rồi giá trị 8 byte trong `rax` được ghi tại địa chỉ đó. Do stack tăng về phía địa chỉ thấp, khi tổ chức mảng con trỏ, cần quan sát thứ tự `push` **từ dưới lên**.

### 14.5. Khi dùng `argv` trên GDB

Nếu `rsi` trỏ đến mảng `argv` tại thời điểm syscall:

```gdb
x/4gx $rsi
x/s *(char **)$rsi
x/s *(char **)($rsi + 8)
x/s *(char **)($rsi + 16)
```

Lệnh đầu in 4 phần tử 8-byte. Ba lệnh tiếp theo xem chuỗi mà từng con trỏ trỏ tới. Nếu `argv[2]=NULL`, không dùng `x/s` để đọc tại địa chỉ 0.

---

## 15. Debug với GDB, strace và /proc

### 15.1. Bài test C có thể biên dịch

**File `showargs.c`:**

```c
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    for (int i = 0; i < argc; ++i)
        printf("argv[%d] = <%s>\n", i, argv[i]);

    const char *home = getenv("HOME");
    printf("HOME = <%s>\n", home ? home : "(unset)");
    return 0;
}
```

**File `launcher.c`:**

```c
#include <stdio.h>
#include <unistd.h>

int main(void) {
    char *argv[] = {"TEN_KHAC", "first", "second", NULL};
    char *envp[] = {"HOME=/tmp/demo", NULL};
    execve("./showargs", argv, envp);
    perror("execve");
    return 1;
}
```

Biên dịch và chạy:

```bash
gcc -g -O0 showargs.c -o showargs
gcc -g -O0 launcher.c -o launcher
./launcher
```

Kết quả mong đợi:

```text
argv[0] = <TEN_KHAC>
argv[1] = <first>
argv[2] = <second>
HOME = </tmp/demo>
```

Điều này chứng minh **`pathname` và `argv[0]` khác nhau mà exec vẫn chạy đúng file**.

### 15.2. Break tại hàm `execve`

```gdb
gdb ./launcher
(gdb) break execve
(gdb) run
(gdb) info registers rdi rsi rdx
(gdb) x/s $rdi
(gdb) x/4gx $rsi
(gdb) x/s *(char **)$rsi
(gdb) x/s *(char **)($rsi + 8)
(gdb) x/s *(char **)($rsi + 16)
```

`rdi` là pathname, `rsi` là địa chỉ mảng argv, `rdx` là địa chỉ mảng envp (khi đang ở entry của wrapper libc theo ABI amd64).

### 15.3. Quan sát event syscall

```gdb
(gdb) catch syscall execve
(gdb) run
(gdb) continue
```

GDB có thể dừng tại entry/return của syscall; kiểm tra thông báo GDB để biết đang ở giai đoạn nào. Khi `execve` thành công, debugger có thể thông báo image của tiến trình đã đổi; có thể dùng `set follow-exec-mode new` để điều chỉnh quản lý inferior nếu cần.

### 15.4. Quan sát `strace` trong lab

```bash
strace -f -e trace=execve,openat,read,write,close ./launcher
```

`strace` cho phép thấy các syscall của tiến trình và tiến trình con nếu có. Dấu `-f` theo dõi nhánh `fork`/clone khi phù hợp. Đừng suy luận “không thấy `open`” là không mở file: chương trình có thể dùng `openat`.

### 15.5. Xác định trạng thái chương trình

```gdb
(gdb) info proc mappings
(gdb) info registers
(gdb) x/32gx $rsp
(gdb) x/64bx $rsp
(gdb) disassemble /r $rip, $rip+32
```

- `x/32gx`: đọc 32 giá trị 8 byte.
- `x/64bx`: đọc 64 byte lẻ.
- `disassemble /r`: hiển thị instruction kèm bytes opcode.
- `info proc mappings`: xem vùng ánh xạ và quyền nếu GDB/OS hỗ trợ.

**Khi kiểm tra shellcode:** đối chiếu kết quả `asm()` với bytes *đã có trong memory thực tế*. Input API có thể cắt ở newline, chèn `\0`, hoặc biến đổi dữ liệu.

---

## 16. Chủ đề nâng cao và lộ trình học

### 16.1. Nâng cao 1: ABI và clobbered registers

Trong chương trình C bình thường, compiler biết cách tuân thủ calling convention. Khi đọc assembly, cần tự kiểm tra thanh ghi nào mang tham số, thanh ghi nào bị instruction làm thay đổi và những giá trị nào vẫn còn hữu ích ở bước tiếp theo.

Nên học:

- SysV ABI: caller-saved vs callee-saved, stack alignment.
- `syscall` ABI: `r10` cho tham số thứ tư; `rcx` và `r11` bị clobber.
- Giá trị trả về của syscall thường ở `rax`; lỗi syscall thô trên Linux thường là giá trị âm theo quy ước kernel, còn wrapper libc có thể đổi thành `-1` và thiết lập `errno`.

### 16.2. Nâng cao 2: Memory permissions, ASLR, PIE, NX

Các khái niệm cần phân biệt:

- **ASLR**: bố trí địa chỉ không gian tiến trình thay đổi giữa các lần chạy.
- **PIE**: binary có thể được load tại các base address khác nhau.
- **NX**: trang dữ liệu không được phép thực thi theo cấu hình.
- **W^X**: nguyên tắc tránh vùng nhớ vừa writable vừa executable cùng lúc.
- **`mmap`/`mprotect`**: API thiết lập/tùy chỉnh memory mapping và permissions (trong giới hạn chính sách hệ thống).

Hãy quan sát các thuộc tính đó trong chương trình lab thay vì mặc định rằng writable buffer luôn executable.

### 16.3. Nâng cao 3: Filtering và mã máy

Biết assembly syntax chưa đủ. Một instruction có thể có nhiều encoding, và cùng một dãy bytes có thể bị diễn giải khác nhau khi bắt đầu ở offset khác. Bài học chính là:

1. Luôn xem `hexdump(asm(...))`.
2. Không suy diễn bytes chỉ từ mnemonic.
3. Đọc đúng độ rộng phép so sánh (`BYTE`, `_WORD`, `DWORD`).
4. Hiểu little-endian, alignment và ranh giới buffer.
5. Tách giới hạn bytes khỏi giới hạn syscall của kernel.

### 16.4. Nâng cao 4: ORW và thao tác file theo FD

Trong tài liệu CTF bạn sẽ gặp tên viết tắt **ORW** (*open-read-write*): mô hình chương trình mở một file, đọc một phần dữ liệu và ghi đến một descriptor được lựa chọn. Đây là kiến thức quản lý file bình thường của Linux; chú ý giá trị FD trả về, offset, quyền file, và việc `read`/`write` có thể trả về số byte ít hơn yêu cầu.

**Bài thực hành an toàn:** dùng một file `hello.txt` do chính bạn tạo, kiểm tra luồng dữ liệu bằng `strace`, xác định FD nào được `openat()` trả về sau `close(0)`.

### 16.5. Nâng cao 5: ROP, SROP, staged execution — hiểu ở mức mô hình

- **ROP (Return-Oriented Programming)**: tổ chức luồng điều khiển từ các đoạn instruction sẵn có; thường được nghiên cứu cùng NX và calling conventions.
- **SROP (Sigreturn-Oriented Programming)**: tìm hiểu cơ chế khôi phục register context khi signal return; yêu cầu hiểu cấu trúc context và ABI.
- **Staged shellcode**: chia logic thành những giai đoạn phụ thuộc cách chương trình nhận input, kích thước buffer và quyền bộ nhớ.
- **Self-modifying code**: mã được thay đổi trong quá trình chạy; gắn chặt với quyền ghi/thực thi và tính nhất quán instruction cache.

Hãy học các chủ đề nâng cao trong binary lab có chủ đích; đừng lẫn khái niệm hạn chế input với quyền truy cập tài nguyên của một hệ thống thật.

### 16.6. Thứ tự học khuyến nghị

| Giai đoạn | Mục tiêu chứng minh được bằng thực nghiệm |
|---|---|
| 1 | Tự giải thích `argv[0]` và `pathname` |
| 2 | Dùng `execve` chạy `/bin/echo` trong C |
| 3 | Xem địa chỉ mảng `argv` trong GDB |
| 4 | Đọc syscall ABI của amd64 và i386 |
| 5 | Viết shellcode `write`/`exit` và giải thích từng byte |
| 6 | Dùng Pwntools kiểm tra length, disasm, bad bytes |
| 7 | Đọc bộ lọc C, xác định byte/word, endian và phạm vi |
| 8 | Phân biệt opcode filter, NX và seccomp |
| 9 | Phân tích script/ELF interpreter và lỗi exec |
| 10 | Tổng hợp thành write-up về challenge tự dựng |

---
## 17. Các bài lab tự luyện và lời gợi ý

Tất cả bài bên dưới dùng chương trình/đường dẫn do bạn sở hữu trong máy ảo hoặc container học tập. Mỗi bài nên có: (1) source, (2) output terminal, (3) GDB/strace evidence, (4) giải thích nguyên nhân.

### Lab 1 — `pathname` khác `argv[0]` (cơ bản)

**Đề:** tạo `showargs.c` và `launcher.c` trong mục 15. Thử thay `"TEN_KHAC"` thành `"echo"` rồi chạy.

**Câu hỏi:** chương trình chạy thực sự có bị thay đổi không? `showargs` nhận `argv[0]` nào?

**Gợi ý:** kernel dùng `./showargs`, không dùng `argv[0]` để tìm executable.

### Lab 2 — Đếm số bytes trong pathname

**Đề:** Với `"/bin/echo"`, hãy tính `strlen()` và `sizeof` của mảng `char path[]` và con trỏ `char *p`.

**Gợi ý:** nhớ byte `\0` có mặt trong kích thước mảng nhưng không trong `strlen`.

### Lab 3 — Tại sao `-c` khác argv thông thường?

**Đề:** so sánh:

```c
char *a[] = {"sh", "-c", "echo Hello", NULL};
char *b[] = {"cat", "echo Hello", NULL};
```

**Câu hỏi:** vì sao cách đầu hiểu `echo Hello` thành lệnh, còn cách sau coi nó là một tên file? Tự thử với dữ liệu không nhạy cảm.

**Gợi ý:** phân biệt parser của `/bin/sh` với chức năng `/bin/cat`.

### Lab 4 — `close(0)` và FD reuse

**Đề:** viết chương trình gọi `close(0)`, sau đó `open("hello.txt", O_RDONLY)`; in giá trị FD bằng `printf`.

**Câu hỏi:** `open` có trả 0 không? Trong trường hợp nào kết quả có thể khác?

**Gợi ý:** đọc quy tắc cấp phát FD chưa sử dụng thấp nhất.

### Lab 5 — Quan sát envp

**Đề:** truyền chỉ `HOME=/tmp/lab` trong `envp`; chương trình nhận in `getenv("HOME")` và `getenv("LANG")`.

**Câu hỏi:** có tự kế thừa `LANG` từ shell cha khi dùng `execve()` với `envp` mới không?

### Lab 6 — Đọc `argv` qua GDB

**Đề:** dừng tại entry `execve` của `launcher` và giải thích output `x/4gx $rsi`.

**Gợi ý:** mỗi qword là một con trỏ trên amd64; dùng `x/s` trên con trỏ vừa đọc, không trên địa chỉ mảng nếu mục tiêu là chuỗi.

### Lab 7 — Shellcode `write` đơn giản

**Đề:** dùng script Pwntools ở mục 10.2 để tạo code in `HELLO\n`.

**Câu hỏi:** instruction nào giữ số syscall, địa chỉ buffer và byte count? `lea` khác `mov` thế nào?

### Lab 8 — Bộ kiểm tra bad bytes

**Đề:** viết script đánh dấu tất cả offset chứa `0x00` và các cặp `0f 05`, `0f 34`, `cd 80` trong **một bytestring mẫu**.

```python
sample = bytes.fromhex('41 00 0f 05 42 cd 80 43')
```

**Gợi ý:** mẫu `0f 05` bắt đầu tại offset 2, `cd 80` tại offset 5. Đây là bài **kiểm tra dữ liệu**, không phải hướng dẫn vượt bộ lọc.

### Lab 9 — Reverse một `_WORD` checker

**Đề:** giải thích vì sao `(uint16_t *)(buffer + i)` khác `((uint16_t *)buffer) + i`.

**Gợi ý:** phép cộng con trỏ theo **kích thước kiểu được trỏ đến**. Trường hợp đầu cộng trên con trỏ byte (nếu `buffer` là `char *`), trường hợp sau bước `2*i` bytes.

### Lab 10 — ELF interpreter bị thiếu

**Đề:** đọc `PT_INTERP` bằng `readelf`, kiểm tra interpreter có tồn tại trong container lab không.

**Câu hỏi:** điều gì xảy ra nếu file binary tồn tại mà interpreter không tồn tại? Vì sao có thể gặp `ENOENT`?

### Lab 11 — Phân biệt các lớp bảo vệ

**Đề:** nhận một mô tả đề giả lập gồm (a) cấm byte `0x00`, (b) vùng buffer chỉ `RW`, (c) seccomp chỉ cho phép vài syscall. Hãy phân loại từng điều kiện là input filter, memory permission hay kernel syscall policy.

### Lab 12 — Viết write-up

**Yêu cầu:** viết 1 trang Markdown cho một lab bạn đã tự giải:

1. Tổng quan, binary, kiến trúc.
2. Ràng buộc bytes, memory và syscall.
3. Các giả thuyết đã kiểm tra.
4. GDB/strace chứng minh điều gì.
5. Bài học về `pathname`, `argv`, `envp` hoặc FD.
6. Kết luận và cách tránh lỗi trong chương trình thực tế.

---

## 18. Checklist, lỗi phổ biến, tài liệu tham khảo

### 18.1. Checklist khi xem một challenge shellcode

- [ ] Xác định kiến trúc thật của ELF bằng `file` / `readelf -h`.
- [ ] Kiểm tra bản thân input được đọc bằng API nào và số byte thực tế.
- [ ] Xác định điểm chuyển quyền điều khiển sang buffer.
- [ ] Kiểm tra địa chỉ và quyền của buffer trong GDB.
- [ ] Ghi rõ luật bad-byte theo **byte/word/sequence**, độ dài và endian.
- [ ] Xác định có seccomp không, có những syscall nào bị hạn chế.
- [ ] Xác định trạng thái FD 0, 1, 2 và CWD.
- [ ] Dùng `hexdump(asm(...))`, `disasm(...)`, `len(...)` để kiểm tra chính xác.
- [ ] Kiểm tra con trỏ `pathname`, `argv`, `envp` trước lời gọi `execve`.
- [ ] Đối chiếu shellcode trong file với bytes thực sự ở memory.
- [ ] Nếu `execve` lỗi, xem `errno`, interpreter, quyền file và đường dẫn.
- [ ] Chứng minh kết quả trong lab, không phỏng đoán từ tên challenge.

### 18.2. Lỗi phổ biến và nguyên nhân

| Triệu chứng | Khả năng cần kiểm tra |
|---|---|
| `execve` báo `EFAULT` | Con trỏ `argv`, chuỗi hoặc envp chưa hợp lệ |
| Binary tồn tại nhưng `ENOENT` | Thiếu script/ELF interpreter hoặc thành phần path |
| Không thấy output | stdout đóng/chuyển hướng, `write` sai FD, chương trình lỗi |
| Shell thoát ngay | Stdin đóng, EOF hoặc shell không có lệnh sẵn |
| `cat` chờ input | Không truyền tên file, mặc định đọc stdin |
| Machine code chứa `\x00` | Instruction encoding hoặc dữ liệu nhúng có zero byte |
| `disasm` thấy instruction lạ ở cuối | Dữ liệu chuỗi có thể bị giải mã như code |
| Crash khi vào buffer | Địa chỉ, permission hoặc trạng thái CPU không đúng |
| Bị filter dù mnemonic trông hợp lệ | Filter so bytes, không so tên instruction |
| Debug local khác Docker | libc/loader, đường dẫn, CWD, seccomp, FD hoặc ASLR khác |

### 18.3. Tài liệu chính thức khuyến nghị

- Linux `execve(2)`: https://man7.org/linux/man-pages/man2/execve.2.html
- Họ hàm `exec(3)`: https://man7.org/linux/man-pages/man3/exec.3.html
- Linux `fexecve(3)`: https://man7.org/linux/man-pages/man3/fexecve.3.html
- Linux `execveat(2)`: https://man7.org/linux/man-pages/man2/execveat.2.html
- Linux `seccomp(2)`: https://man7.org/linux/man-pages/man2/seccomp.2.html
- Linux `mmap(2)`: https://man7.org/linux/man-pages/man2/mmap.2.html
- Pwntools Getting Started: https://docs.pwntools.com/en/stable/intro.html
- Pwntools Shellcraft: https://docs.pwntools.com/en/stable/shellcraft.html
- Pwntools Shellcraft amd64: https://docs.pwntools.com/en/stable/shellcraft/amd64.html

### 18.4. Sáu câu hỏi tự kiểm tra cuối cùng

1. Nếu `pathname = "/bin/cat"` nhưng `argv[0] = "hello"`, chương trình nào được tải? **Đáp án:** `/bin/cat`.
2. Tại sao một chuỗi `"cat file"` không thay thế được mảng `{"cat","file",NULL}`? **Đáp án:** một chuỗi không tự biến thành nhiều con trỏ/đối số.
3. `close(0)` có đóng stdout không? **Đáp án:** không.
4. Vì sao `argv` cần có con trỏ NULL ở cuối? **Đáp án:** chương trình/kernel cần biết giới hạn danh sách phần tử.
5. Trên amd64, tham số syscall thứ tư dùng thanh ghi nào? **Đáp án:** `r10`.
6. `0x050F` là hai byte nào trong little-endian? **Đáp án:** `0f 05`.

---

> **Ghi nhớ:** `pathname` chọn chương trình; `argv` truyền các đối số; `envp` truyền môi trường. Trong shellcode, mọi khái niệm này cuối cùng trở thành **bytes, địa chỉ, con trỏ, thanh ghi và trạng thái kernel**. Học cách chứng minh từng bước bằng GDB là nền tảng bền vững nhất để giải challenge CTF.
