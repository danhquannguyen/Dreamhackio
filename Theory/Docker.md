### Lấy file `ld` và `glibc` từ Dockerfile
  - Build image từ Dockerfile
    ```sh
    docker build -t ctf_challenge .
    ```
  - Run container và copy libc & ld ra ngoài
    ```sh
    docker run -d --name ctf_test ctf_challenge
    docker cp ctf_test:/lib/x86_64-linux-gnu/libc.so.6 ./libc.so.6
    docker cp ctf_test:/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 ./ld-linux-x86-64.so.2
    docker rm -f ctf_test
    ```
  - Sau khi có file **libc** và **ld** đúng thì ta có thể dùng **pwninit** để patch **binary** chạy đúng với libc&ld trên chính local.
