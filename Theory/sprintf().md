# sprintf()
  ```c
  #include <stdio.h>

  int sprintf(char *str, const char *format, ...);
  ```
  - **str**: con trỏ trỏ tới chuỗi nơi mà dữ liệu đã định dạng sẽ được lưu trữ.
  - **format**: chuỗi định dạng
  - **...**: các đối số biển đổi tương ứng với các đặc tả định dạng.
  - **Giá trị trả về**: Trả về tổng số ký tự đã được ghi vào chuỗi(không tính ký tự kết thúc \0). Nếu lỗi trả về số âm.


    
