**Trong Linux, đặc biệt là khi sử dụng system() trong C hoặc Bash, có một số toán tử dùng để nối và điều khiển việc thực thi nhiều command.**

## 1. 1. Các toán tử thường gặp

| Ký tự | Ý nghĩa | Ví dụ |
|---|---|---|
| `;` | Chạy lần lượt các lệnh | `echo hello; echo world` |
| `&&` | Chạy lệnh sau nếu lệnh trước thành công | `mkdir test && cd test` |
| `\|\|` | Chạy lệnh sau nếu lệnh trước thất bại | `false \|\| echo failed` |
| `\|` | Chuyển stdout của lệnh trước sang stdin của lệnh sau | `echo hello \| cat` |
| `&` | Chạy lệnh trước ở chế độ nền | `sleep 5 &` |
| `$(...)` | Thực thi lệnh bên trong và thay bằng output | `echo $(whoami)` |
| `` `...` `` | Command substitution kiểu cũ | `` echo `whoami` `` |
| Xuống dòng (`\n`) | Có thể phân tách các lệnh | `echo A` rồi `echo B` |
