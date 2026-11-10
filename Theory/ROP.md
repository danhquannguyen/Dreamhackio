
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
