# __free_hook 
  - __free_hook là một con trỏ hàm toàn cục (global function pointer) từng được cung cấp bởi GNU C Library (glibc) trong header <malloc.h>, cho phép lập trình viên can thiệp (hook) vào quá trình giải phóng bộ nhớ của hàm free().
    ```c
    #include <malloc.h>
    void (*__free_hook)(void *ptr, const void *caller);
    ```
    - ptr: Địa chỉ con trỏ vùng nhớ được quyền vào hàm __free(ptr)__
    - caller: Địa chỉ lệnh gọi **free()** được lấy thông qua marco **RETURN_ADDRESS(0)**

# Cơ chế hoạt động của __free_hook trong glibc:
  - **__free_hook == NULL** (Mặc định):
    - Hàm **free(ptr)** kiểm tra thấy con trỏ hook rỗng.
    - Luồng thực thi tiếp tục đi xuống quy trình giải phóng bộ nhớ heap tiêu chuẩn (**_int_free**): kiểm tra tính hợp lệ của chunk, đưa chunk vào **tcache**, **fastbin**, hoặc gộp chunk trong **unsorted bin**.
  - **__free_hook != NULL**:
    - Ngay đầu hàm **free(ptr)**, glibc lấy địa chỉ đang được lưu tại **__free_hook**.
    - CPU lập tức nhảy đến địa chỉ đó và thực thi như một hàm: **(*__free_hook)(ptr, caller)**.
    - Sau khi hàm hook thực thi xong, hàm **free()** thực hiện lệnh return ngay lập tức. _Toàn bộ quy trình giải phóng bộ nhớ heap mặc định bên dưới hoàn toàn bị bỏ qua._
