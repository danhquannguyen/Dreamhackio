# Hướng dẫn lấy `libc` và `ld` từ Docker, cấu hình môi trường Pwn (x86 / x86_64)

> **Mục đích:** Tái tạo môi trường chạy ELF của challenge CTF/Pwn trong phòng lab được phép, tránh sai khác giữa thư viện trên máy local và thư viện trong Docker/remote.
>
> **Phạm vi:** Linux ELF dùng **glibc**, cho cả **i386 (32-bit)** và **amd64/x86_64 (64-bit)**. Alpine Linux thường dùng **musl**, không thể áp dụng nguyên xi các đường dẫn glibc dưới đây.

## Mục lục

1. [Nắm vững `libc`, `glibc`, `ld`](#1-nắm-vững-libc-glibc-ld)
2. [Chuẩn bị môi trường](#2-chuẩn-bị-môi-trường)
3. [Kiểm tra binary trước khi làm](#3-kiểm-tra-binary-trước-khi-làm)
4. [Build Docker image từ Dockerfile](#4-build-docker-image-từ-dockerfile)
5. [Lấy thư viện x86_64 từ Docker](#5-lấy-thư-viện-x86_64-từ-docker)
6. [Lấy thư viện x86 (32-bit) từ Docker](#6-lấy-thư-viện-x86-32-bit-từ-docker)
7. [Chạy ELF local với `libc`/`ld` đã lấy](#7-chạy-elf-local-với-libcld-đã-lấy)
8. [Dùng `pwninit` hoặc `patchelf`](#8-dùng-pwninit-hoặc-patchelf)
9. [Tự biên dịch glibc từ source](#9-tự-biên-dịch-glibc-từ-source)
10. [Lỗi thường gặp](#10-lỗi-thường-gặp)
11. [Checklist và tài liệu tham khảo](#11-checklist-và-tài-liệu-tham-khảo)

---

## 1. Nắm vững `libc`, `glibc`, `ld`

### `libc` và `glibc` là gì?

- **libc** là giao diện thư viện C tiêu chuẩn: `printf`, `puts`, `malloc`, `free`, `read`, `write`, `system`, v.v.
- **glibc** (GNU C Library) là một bản triển khai libc phổ biến trên Linux.
- `libc.so.6` là tên thư viện chia sẻ (shared object) thường thấy ở hệ thống dùng glibc.
- Các bản glibc khác nhau có thể có symbol, offset, hành vi quản lý bộ nhớ và bản vá khác nhau.

### `ld` là gì?

Ở đây `ld` là **dynamic loader / ELF interpreter** (không phải chương trình link tĩnh `ld` của binutils):

- ELF 64-bit thường yêu cầu `/lib64/ld-linux-x86-64.so.2`.
- ELF 32-bit i386 thường yêu cầu `/lib/ld-linux.so.2`.
- Loader chịu trách nhiệm nạp các thư viện động mà chương trình cần và thực hiện relocation.

Sơ đồ đơn giản:

```text
Chạy ./chall
     |
     v
Kernel đọc ELF, mục PT_INTERP
     |
     v
Dynamic loader (ld-linux-*.so.*)
     |
     +----> Nạp libc.so.6 và các thư viện phụ thuộc
     |
     v
Chuyển quyền thực thi tới chương trình
```

**Lưu ý:** `libc` và `ld` nên được lấy **cùng image / cùng bộ glibc**, cùng kiến trúc. Không nên ghép ngẫu nhiên `libc` của phiên bản này với `ld` của phiên bản khác.

| Kiến trúc ELF | Tên thường dùng | libc thường gặp (Debian/Ubuntu) | Loader trong ELF thường gặp |
|---|---|---|---|
| 32-bit Intel | `i386`, `x86` | `/lib/i386-linux-gnu/libc.so.6` | `/lib/ld-linux.so.2` |
| 64-bit Intel/AMD | `amd64`, `x86_64` | `/lib/x86_64-linux-gnu/libc.so.6` | `/lib64/ld-linux-x86-64.so.2` |

> Đây là **đường dẫn phổ biến**, không phải quy tắc cho mọi distro. Ubuntu có gói `libc6-i386` dùng `/lib32/libc.so.6`; nên kiểm tra bằng `find`, `readlink` và `readelf` khi cần.

---

## 2. Chuẩn bị môi trường

Ví dụ dưới đây giả định máy local đang dùng Ubuntu/Kali/Debian trên CPU x86_64 và đã cài Docker Engine.

```bash
# Công cụ đọc thông tin ELF, biên dịch và patch loader
sudo apt update
sudo apt install -y file binutils patchelf build-essential \
    gcc-multilib g++-multilib libc6-dev-i386 \
    python3 python3-pip

# Xác minh công cụ
file --version
readelf --version
patchelf --version
docker --version
```

Cài `pwninit` bằng một trong các cách được dự án hỗ trợ, chẳng hạn qua Rust Cargo:

```bash
# Nếu đã có Rust và Cargo:
cargo install pwninit

# Kiểm tra đường dẫn lệnh và phiên bản
pwninit --help
```

Tùy distro, có thể sử dụng bản phát hành đóng gói sẵn của dự án thay vì tự biên dịch bằng Cargo. `pwntools` cũng hữu ích để kiểm tra ELF:

```bash
python3 -m pip install pwntools
```

> Với hệ thống áp dụng PEP 668, nên cài `pwntools` trong Python virtual environment (`python3 -m venv .venv`, rồi kích hoạt và cài bằng pip), không ép sửa Python hệ thống.

---

## 3. Kiểm tra binary trước khi làm

Giả sử challenge gồm `chall`, `Dockerfile` và (có thể) `docker-compose.yml`:

```text
pwn-lab/
├── chall
└── Dockerfile
```

Kiểm tra:

```bash
file ./chall
readelf -h ./chall | grep -E 'Class:|Machine:'
readelf -Wl ./chall | grep 'Requesting program interpreter'
readelf -d ./chall | grep NEEDED
```

Ví dụ kết quả:

```text
ELF 64-bit LSB executable, x86-64, dynamically linked
[Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
Shared library: [libc.so.6]
```

Diễn giải:

- `ELF32`/`ELF64`: độ rộng ELF, không suy đoán chỉ dựa trên tên file.
- `Machine`: CPU/ABI mà binary nhắm tới.
- `PT_INTERP`: loader mà kernel sẽ tìm khi chạy ELF động.
- `NEEDED`: danh sách thư viện mà ELF yêu cầu.

Nếu ELF được **static linked**, thông thường không có `PT_INTERP`, và quy trình thay loader này không phù hợp.

---

## 4. Build Docker image từ Dockerfile

### Bước 1: Đọc Dockerfile trước

Ví dụ Dockerfile đơn giản:

```dockerfile
FROM ubuntu:22.04
WORKDIR /app
COPY chall /app/chall
RUN chmod +x /app/chall
CMD ["/app/chall"]
```

Điểm cần biết:

- `FROM`: distro/image nền, ảnh hưởng tới bản glibc.
- `COPY`: chép binary vào image.
- `RUN`: chạy lệnh **khi build image**.
- `CMD`: lệnh mặc định khi **chạy container**, không bắt buộc phải chạy để copy thư viện.

Nếu Dockerfile đã được challenge cung cấp, **ưu tiên dùng nguyên Dockerfile đó**. Đổi `FROM ubuntu:20.04` thành `22.04` có thể làm khác glibc.

### Bước 2: Build image

Tại thư mục có Dockerfile:

```bash
# Dấu '.' là build context (thư mục hiện tại)
docker build -t pwn_chal .

# Hoặc chỉ rõ Dockerfile
docker build -f Dockerfile -t pwn_chal .

# Kiểm tra image
docker image ls pwn_chal
docker image inspect pwn_chal --format '{{.Os}}/{{.Architecture}}'
```

`-t pwn_chal` đặt tên image; nếu không chỉ rõ tag thì dùng `latest`.

Khi cần nhắm tới hệ 64-bit, có thể chỉ định:

```bash
docker build --platform linux/amd64 -t pwn_chal_amd64 .
```

> `linux/amd64` là **platform của image**, còn `-m32` là **tùy chọn biên dịch chương trình 32-bit**. Hai khái niệm khác nhau. Việc build khác CPU host có thể cần trình giả lập / hỗ trợ `binfmt_misc`.

---

## 5. Lấy thư viện x86_64 từ Docker

### Cách A: Tạo container tạm rồi `docker cp` (khuyến nghị)

```bash
# 1. Build image
docker build -t pwn_chal .

# 2. Tạo container nhưng KHÔNG khởi chạy chương trình
id=$(docker create pwn_chal)

# 3. Lấy libc 64-bit
docker cp -L "$id:/lib/x86_64-linux-gnu/libc.so.6" ./libc.so.6

# 4. Lấy dynamic loader 64-bit
docker cp -L "$id:/lib64/ld-linux-x86-64.so.2" ./ld-linux-x86-64.so.2

# 5. Xóa container tạm (không xóa image)
docker rm "$id"

# 6. Kiểm tra
file ./libc.so.6 ./ld-linux-x86-64.so.2
./libc.so.6
```

**Giải thích chi tiết:**

| Lệnh | Ý nghĩa |
|---|---|
| `docker build -t pwn_chal .` | Tạo image từ Dockerfile. |
| `docker create pwn_chal` | Tạo đối tượng container, **chưa start**, trả về container ID. |
| `id=$(...)` | Lưu container ID trong biến shell `id`. |
| `docker cp -L` | Copy từ container về máy host; `-L` đi theo symlink ở đường dẫn nguồn. |
| `"$id:/..."` | `docker cp` hiểu phần trước `:` là tên/ID container. |
| `docker rm "$id"` | Xóa container tạm; image `pwn_chal` vẫn còn. |

Dùng `-L` rất quan trọng khi đường dẫn trong container chỉ là **symlink** trỏ tới file thật. Docker cũng cho phép `docker cp` với container đã dừng/chưa chạy.

### Cách B: Nếu đường dẫn không tồn tại

Tạo shell để xác minh layout thư viện:

```bash
docker run --rm -it --entrypoint /bin/sh pwn_chal

# BÊN TRONG container:
find /lib /usr/lib -name 'libc.so.6' -o -name 'ld-linux*.so*' 2>/dev/null
readlink -f /lib64/ld-linux-x86-64.so.2
```

Hoặc với container tạm không cần chạy app:

```bash
id=$(docker create pwn_chal)
docker cp -L "$id:/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" ./ld-linux-x86-64.so.2
docker rm "$id"
```

Đường dẫn `/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2` là một lựa chọn khác thường thấy trên Debian/Ubuntu.

---

## 6. Lấy thư viện x86 (32-bit) từ Docker

Có **hai trường hợp** khác nhau, không nên nhầm lẫn.

### Trường hợp A: Docker image 64-bit có cài thêm libc 32-bit

Đây là trường hợp khá phổ biến khi challenge 32-bit chạy trong Ubuntu 64-bit.

Ví dụ **Dockerfile minh họa** nếu bạn tự chuẩn bị lab:

```dockerfile
FROM ubuntu:22.04
RUN dpkg --add-architecture i386 \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libc6:i386 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY chall /app/chall
RUN chmod +x /app/chall
CMD ["/app/chall"]
```

Build và lấy file:

```bash
docker build -t pwn_chal_i386_multiarch .
id=$(docker create pwn_chal_i386_multiarch)

# Ubuntu/Debian multiarch: 32-bit glibc
docker cp -L "$id:/lib/i386-linux-gnu/libc.so.6" ./libc.so.6

# Loader 32-bit (thường là symlink tới loader thực)
docker cp -L "$id:/lib/ld-linux.so.2" ./ld-linux.so.2

docker rm "$id"
file ./libc.so.6 ./ld-linux.so.2
```

**Phân biệt quan trọng:**

- Gói `libc6:i386` có thể đặt libc ở `/lib/i386-linux-gnu/libc.so.6`.
- Một số image dùng gói `libc6-i386` trên Ubuntu amd64 đặt libc ở `/lib32/libc.so.6`.
- Vì thế, khi không tìm thấy file, dùng `find` thay vì đoán.

```bash
docker run --rm --entrypoint /bin/sh pwn_chal_i386_multiarch -c \
  "find /lib /lib32 /usr/lib -name libc.so.6 -o -name ld-linux.so.2 2>/dev/null"
```

### Trường hợp B: Toàn bộ Docker image là 32-bit (`linux/386`)

Không phải tag image nào cũng phát hành bản `linux/386`. Nếu muốn một ví dụ có image 32-bit chính thức, Debian Bookworm hỗ trợ `i386`:

```dockerfile
# Dockerfile.i386: ví dụ riêng cho lab 32-bit
FROM debian:bookworm-slim
WORKDIR /app
COPY chall /app/chall
RUN chmod +x /app/chall
CMD ["/app/chall"]
```

```bash
# Tạo image Debian i386 thật sự
docker build --platform linux/386 -f Dockerfile.i386 -t pwn_i386 .

# Kiểm tra platform
docker image inspect pwn_i386 --format '{{.Os}}/{{.Architecture}}'

id=$(docker create pwn_i386)
docker cp -L "$id:/lib/i386-linux-gnu/libc.so.6" ./libc.so.6
docker cp -L "$id:/lib/ld-linux.so.2" ./ld-linux.so.2
docker rm "$id"

file ./libc.so.6 ./ld-linux.so.2
```

> **Không nên tự thay Dockerfile của challenge bằng Debian để lấy libc rồi cho rằng nó giống remote.** Trường hợp này chỉ dùng khi **tự tạo môi trường lab**. Nếu image gốc của challenge đã có libc, hãy lấy từ image đó.

### Tránh ghi đè file của hai kiến trúc

Nếu đang thực hành đồng thời 32-bit và 64-bit, hãy tách thư mục:

```text
pwn-lab/
├── x86/
│   ├── chall
│   ├── libc.so.6       # ELF 32-bit
│   └── ld-linux.so.2   # ELF 32-bit
└── x64/
    ├── chall
    ├── libc.so.6             # ELF 64-bit
    └── ld-linux-x86-64.so.2  # ELF 64-bit
```

---

## 7. Chạy ELF local với `libc`/`ld` đã lấy

### Kiểm tra cặp thư viện

```bash
file ./chall ./libc.so.6 ./ld-linux-x86-64.so.2
readelf -Wl ./chall | grep 'Requesting program interpreter'
readelf -d ./chall | grep NEEDED
./libc.so.6
```

`./libc.so.6` thường in ra thông tin version/build của glibc trên các bản hỗ trợ. Nếu lệnh đó không chạy được, vẫn có thể dùng `file` và `readelf` để xem kiến trúc, hoặc dùng loader để kiểm tra thư viện.

### Chạy 64-bit bằng loader chỉ định, chưa cần patch

```bash
chmod +x ./chall ./ld-linux-x86-64.so.2
./ld-linux-x86-64.so.2 --library-path "$PWD" ./chall
```

### Chạy 32-bit bằng loader chỉ định, chưa cần patch

```bash
chmod +x ./chall ./ld-linux.so.2
./ld-linux.so.2 --library-path "$PWD" ./chall
```

- `./ld-linux-...` chọn **loader cụ thể**.
- `--library-path "$PWD"` yêu cầu loader tìm thư viện trong thư mục hiện tại.
- `./chall` là chương trình cần chạy.

Nếu muốn xem loader thực tế chọn thư viện gì (trong lab đã tin cậy):

```bash
./ld-linux-x86-64.so.2 --library-path "$PWD" --list ./chall
```

**Vì sao chỉ `LD_LIBRARY_PATH=.` đôi khi chưa đủ?** Vì lệnh này tác động tới đường dẫn tìm thư viện, nhưng không thay đổi `PT_INTERP` của ELF. Chạy qua `ld` chỉ định hoặc patch binary mới đồng thời kiểm soát được loader.

---

## 8. Dùng `pwninit` hoặc `patchelf`

### Cách A: `pwninit` (nhanh, phù hợp Pwn CTF)

Thư mục chuẩn (64-bit):

```text
challenge/
├── chall
├── libc.so.6
└── ld-linux-x86-64.so.2
```

Chạy:

```bash
pwninit --bin ./chall \
        --libc ./libc.so.6 \
        --ld ./ld-linux-x86-64.so.2
```

Với x86 32-bit, chỉ đổi loader:

```bash
pwninit --bin ./chall \
        --libc ./libc.so.6 \
        --ld ./ld-linux.so.2
```

`pwninit` thường tạo `chall_patched` và có thể sinh mẫu `solve.py`. Nó dùng `patchelf` để chỉnh interpreter và đường dẫn tìm thư viện. Kết quả chính xác có thể thay đổi theo phiên bản `pwninit`.

Kiểm tra và chạy:

```bash
file ./chall_patched
readelf -Wl ./chall_patched | grep 'Requesting program interpreter'
readelf -d ./chall_patched | grep -E 'RPATH|RUNPATH|NEEDED'
chmod +x ./chall_patched
./chall_patched
```

Ví dụ pwntools **chỉ để chạy local**:

```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./chall_patched')
libc = ELF('./libc.so.6')

p = process(elf.path)
p.interactive()
```

**Quan trọng:** Khi dùng `chall_patched`, nên debug/run đúng file này. Đừng vô tình gọi `process('./chall')` rồi nghĩ là đang dùng libc đã copy.

### Cách B: Tự patch bằng `patchelf` (hiểu rõ cơ chế)

```bash
# Không sửa file challenge gốc
cp ./chall ./chall_manual

# Ví dụ cho ELF 64-bit: đổi PT_INTERP
patchelf --set-interpreter "$PWD/ld-linux-x86-64.so.2" ./chall_manual

# Cho loader tìm libc ở cùng thư mục với binary
patchelf --set-rpath '$ORIGIN' ./chall_manual

# Kiểm tra kết quả
patchelf --print-interpreter ./chall_manual
patchelf --print-rpath ./chall_manual
readelf -d ./chall_manual | grep -E 'RPATH|RUNPATH'
./chall_manual
```

Với x86, thay `ld-linux-x86-64.so.2` bằng `ld-linux.so.2`.

**Giải thích:**

- `--set-interpreter`: sửa loader trong `PT_INTERP`.
- `--set-rpath`: sửa đường dẫn tìm shared library.
- `'$ORIGIN'`: token do dynamic loader mở rộng thành **thư mục chứa ELF**, không phải thư mục đang đứng trong shell.
- Dấu nháy đơn quanh `'$ORIGIN'` ngăn shell mở rộng biến `$ORIGIN` trước khi `patchelf` nhận được.
- `"$PWD/ld-..."`: tạo đường dẫn tuyệt đối tới loader; nếu bạn chuyển thư mục challenge sang chỗ khác, có thể cần patch lại interpreter.

---

## 9. Tự biên dịch glibc từ source

### Khi nào cần?

Thông thường **không cần tự compile glibc** nếu Docker image của challenge đã chứa đúng bản libc. Tự biên dịch có ích khi muốn nghiên cứu internals của `malloc/free`, debug source hoặc dựng môi trường thử nghiệm có kiểm soát.

**Phân biệt:** `glibc 2.35` tự build từ GNU upstream **không nhất thiết giống** `libc6 2.35-0ubuntu...` của Ubuntu vì distro có thể thêm patch, cấu hình và cờ build riêng. Nếu muốn trùng remote, lấy thư viện từ Docker/deb tương ứng vẫn tốt hơn.

### 9.1. Build glibc x86_64 từ GNU source

Dưới đây là **ví dụ** cho bản `2.35`, không có nghĩa bản này là libc của mọi challenge.

```bash
sudo apt update
sudo apt install -y build-essential bison gawk python3 \
    texinfo wget xz-utils

mkdir -p "$HOME/glibc-work"
cd "$HOME/glibc-work"

# Lấy source chính thức
wget https://ftp.gnu.org/gnu/glibc/glibc-2.35.tar.xz

# Giải nén
tar -xf glibc-2.35.tar.xz

# Build NGOÀI source directory
mkdir build-2.35
cd build-2.35

# Cài vào thư mục riêng, KHÔNG ghi đè libc hệ thống
../glibc-2.35/configure \
    --prefix="$HOME/opt/glibc-2.35" \
    --disable-werror

make -j"$(nproc)"

# (Tùy chọn) Kiểm thử; một số môi trường có thể báo test không tương thích
make check

# Cài vào $HOME/opt/glibc-2.35
make install
```

Tìm file kết quả, bởi layout có thể khác theo cấu hình:

```bash
find "$HOME/opt/glibc-2.35" \( -name 'libc.so.6' -o -name 'ld-linux*.so*' \) -print
```

Ví dụ nếu các file nằm trong `$HOME/opt/glibc-2.35/lib`:

```bash
"$HOME/opt/glibc-2.35/lib/ld-linux-x86-64.so.2" \
    --library-path "$HOME/opt/glibc-2.35/lib" \
    ./chall
```

Nếu binary phụ thuộc thêm thư viện khác, có thể cần đưa các thư viện tương ứng vào đường dẫn tìm kiếm. Những phiên bản glibc cũ có thể cần toolchain phù hợp; `--disable-werror` không đảm bảo sửa được mọi vấn đề tương thích.

### 9.2. Build glibc i386 (32-bit)

Để giảm lỗi cross-compilation, một cách học tập dễ hiểu là build **bên trong userland Debian i386** có toolchain tương ứng. Cách dưới đây dùng source đã tải trong thư mục làm việc:

```bash
# Ở máy host, tại $HOME/glibc-work đã có thư mục glibc-2.35
cd "$HOME/glibc-work"

# Mở shell 32-bit của Debian; thư mục host được mount vào /work
docker run --rm -it --platform linux/386 \
    -v "$PWD:/work" -w /work \
    debian:bookworm-slim /bin/bash
```

**Trong container i386**:

```bash
apt-get update
apt-get install -y build-essential bison gawk python3 texinfo

mkdir -p build-2.35-i386
cd build-2.35-i386

../glibc-2.35/configure \
    --prefix=/work/install-2.35-i386 \
    --disable-werror

make -j2
make install

# Các output ở /work/install-2.35-i386 cũng hiện ở host
find /work/install-2.35-i386 \( -name libc.so.6 -o -name 'ld-linux*.so*' \) -print
exit
```

> Docker cần hỗ trợ chạy `linux/386` trên host. Trên Linux x86_64, kernel thường hỗ trợ chương trình i386 nếu có cấu hình phù hợp; trên nền tảng khác có thể phải bật emulation. Đừng mặc định mọi máy đều chạy được.

Sau đó copy cặp `libc.so.6`/loader 32-bit kết quả sang thư mục challenge **32-bit** và chạy bằng loader tương ứng như mục 7. Đây là bản **tự build cho lab**, không bảo đảm trùng với Docker challenge khác.

---

## 10. Lỗi thường gặp

### `No such file or directory` dù `chall` tồn tại

Nguyên nhân có thể là **loader ghi trong `PT_INTERP` không tồn tại**, không phải thiếu file `chall`:

```bash
file ./chall
readelf -Wl ./chall | grep 'Requesting program interpreter'
```

Giải pháp: cài đúng loader hoặc chạy/patch với cặp loader và libc tương ứng kiến trúc.

### `wrong ELF class: ELFCLASS32` hoặc `ELFCLASS64`

Đang trộn ELF 32-bit và thư viện/loader 64-bit hoặc ngược lại.

```bash
file ./chall ./libc.so.6 ./ld-linux.so.2
```

### `version 'GLIBC_2.xx' not found`

Một thư viện được dùng không cung cấp versioned symbol mà chương trình yêu cầu. Hãy kiểm tra lại image, libc, loader và các thư viện phụ thuộc; **không** mặc định đổi sang bản glibc mới nhất là sẽ giống remote.

```bash
readelf --version-info ./chall | grep GLIBC_
readelf --version-info ./libc.so.6 | grep GLIBC_ | head
```

### `docker cp: Could not find the file`

Sai đường dẫn hoặc image không chứa thư viện đó. Kiểm tra `find` trong container; nhớ phân biệt `/lib32/`, `/lib/i386-linux-gnu/` và `/lib/x86_64-linux-gnu/`.

### `Exec format error`

Binary/image có thể không đúng kiến trúc, hoặc host thiếu khả năng thực thi platform đó. Kiểm tra:

```bash
file ./chall
uname -m
docker image inspect pwn_chal --format '{{.Os}}/{{.Architecture}}'
```

### Patch xong vẫn dùng libc host

Kiểm tra `RUNPATH/RPATH`, `PT_INTERP`, và thư mục chứa `libc.so.6`:

```bash
patchelf --print-interpreter ./chall_patched
patchelf --print-rpath ./chall_patched
readelf -d ./chall_patched | grep -E 'NEEDED|RPATH|RUNPATH'
```

Lưu ý: không phải mọi file phụ thuộc đều là `libc.so.6`. Binary dùng C++, OpenSSL hoặc các thư viện khác có thể cần thêm `.so` phù hợp.

### Tuyệt đối không thay libc của hệ điều hành host

**Không** copy bản glibc của challenge đè lên `/lib/.../libc.so.6` hoặc loader hệ thống. Điều đó có thể làm hỏng cả shell và package manager. Hãy giữ thư viện trong thư mục lab, chạy qua loader riêng, `pwninit` hoặc `patchelf`.

---

## 11. Checklist và tài liệu tham khảo

### Checklist nhanh cho mỗi challenge

- [ ] Đọc Dockerfile: distro, tag, lệnh cài đặt và kiến trúc.
- [ ] Kiểm tra `file`, `readelf -h`, `PT_INTERP`, `NEEDED` của `chall`.
- [ ] `docker build` chính **Dockerfile của challenge**.
- [ ] `docker create`, rồi `docker cp -L` lấy `libc` và `ld` **từ cùng image**.
- [ ] Dùng `file` xác minh tất cả là đúng 32-bit hoặc đúng 64-bit.
- [ ] Test `./ld-... --library-path "$PWD" ./chall` trước.
- [ ] Chạy `pwninit` hoặc `patchelf` trên **bản sao** binary.
- [ ] Kiểm tra `PT_INTERP` và `RPATH/RUNPATH` của file patched.
- [ ] Khi debug bằng GDB/pwntools, chạy **file patched**, không nhầm với file gốc.

### Tham khảo chính thức

- [Docker: `docker cp`](https://docs.docker.com/reference/cli/docker/container/cp/)
- [Docker Buildx: `--platform`](https://docs.docker.com/reference/cli/docker/buildx/build/)
- [pwninit — GitHub](https://github.com/io12/pwninit)
- [patchelf — GitHub](https://github.com/NixOS/patchelf)
- [GNU libc manual: Configuring and compiling](https://snapshots.sourceware.org/glibc/trunk/latest/manual/html_node/Configuring-and-compiling.html)
- [Ubuntu: file list `libc6:i386`](https://packages.ubuntu.com/jammy/i386/libc6/filelist)
- [Ubuntu: file list `libc6-i386:amd64`](https://packages.ubuntu.com/jammy-updates/amd64/libc6-i386/filelist)

---

> **Ghi nhớ:** Muốn tái hiện sát môi trường một challenge, thứ tự ưu tiên là **(1) đúng binary → (2) đúng Docker image → (3) đúng kiến trúc → (4) đúng cặp `libc` + loader → (5) kiểm tra file đã patch thực sự đang được chạy**.
