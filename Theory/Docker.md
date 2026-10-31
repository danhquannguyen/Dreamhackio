### Lấy file `ld` và `glibc` từ Dockerfile
  - Build Docker image:
    ```sh
    docker build -t pwn_chal .
    ```
  - Tạo container tạm thời và copy file thư viện ra ngoài:
    ```sh
    # Tạo container không cần chạy
    id=$(docker create pwn_chal)
    
    # Copy libc và ld ra thư mục hiện tại
    docker cp $id:/lib/x86_64-linux-gnu/libc.so.6 ./libc.so.6
    docker cp $id:/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 ./ld-linux-x86-64.so.2

    # Xóa container tạm
    docker rm $id
    ```
  - Sau khi có file **libc** và **ld** đúng thì ta có thể dùng **pwninit** để patch **binary** chạy đúng với libc&ld trên chính local.
