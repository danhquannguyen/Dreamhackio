# system call

* |syscall name|rax|rdi|rsi|rdx|
  |:--:|:--:|:--:|:--:|:--:|
  |open|0x02|const char *pathname|int flags|umode_t mode|
  |read|0x00|unsigned int fd|char *buf|size_t count|
  |write|0x01|unsigned int fd|const char *buf|size_t count|
  |execve|0x3b|const char *filename|const char *const *argv|const char *const *envp|
  |exit|0x3c|int error_code|

## sys_open

* System call `open()` là lệnh gọi hệ thống dùng để mở hoặc tạo một file và trả về một file descriptor nhỏ hơn hoặc bằng số nguyên không âm

* **syntax**
  ```c
  int open(const char *pathname, int flags, mode_t mode);
  ````

  * **pathname**: đường dẫn đến tệp tin cần mở hoặc tạo.
  * **flags**: Cờ xác định chế độ truy cập và hành vi khi mở.
  * **mode**: Quyền truy cập tệp (chỉ dùng khi cờ có tạo mới tệp).

## sys_read

* System call `read()` là lệnh gọi hệ thống dùng để đọc dữ liệu từ một tệp hoặc luồng dữ liệu thông qua mô tả tệp (file descriptor) vào một vùng đệm (buffer) do tiến trình cấp phát.

* **syntax**
  ```c
  ssize_t read(int fd, void *buf, size_t count);
  ```

  * **fd**: File descriptor (mô tả tệp) nhận được từ syscall open(), hoặc các luồng mặc định (0 cho stdin).
  * **buf**: Con trỏ tới vùng đệm chứa dữ liệu sau khi đọc xong.
  * **count**: Số lượng byte tối đa muốn đọc từ tệp.
  * **Giá trị trả về **
    * **> 0**: Số byte thực tế đã đọc được.
    * **= 0**: Đã đọc tới cuối tệp(EOF - End of file).
    * **-1**: Thất bại.
      
## sys_write 

* System call `write()` sys_write) là lệnh gọi hệ thống dùng để ghi dữ liệu từ một vùng đệm (buffer) của tiến trình vào một tệp hoặc luồng dữ liệu thông qua mô tả tệp (file descriptor).
  
* **syntax**
  ```c
  ssize_t write(int fd, const void *buf, size_t count);
  ```

  * **fd**: File descriptor (mô tả tệp) đích cần ghi (ví dụ: số nhận được từ open(), hoặc 1 cho stdout, 2 cho stderr).
  * **buf**: Con trỏ tới vùng đệm chứa dữ liệu mà bạn muốn ghi.
  * **count**: Số lượng byte tối đa muốn ghi từ vùng đệm vào tệp.
  * **Giá trị trả về**
    * **> 0**: Số byte thực tế đã ghi thành công vào tệp.
    * **= 0**: Không có byte nào đuọc ghi.
    * **-1**: Thất bại.
   
## sys_execve

* System call `execve()` lệnh gọi hệ thống cốt lõi trong Linux dùng để thay thế toàn bộ không gian địa chỉ của tiến trình hiện tại bằng một chương trình thực thi mới.

* **syntax**
  ```c
  int execve(const char *pathname, char *const argv[], char *const envp[]);
  ```

## sys_exit

* System call `_exit()` là lệnh gọi hệ thống dùng để chấm dứt ngay lập tức tiến trình đang chạy, giải phóng tài nguyên và trả lại một mã trạng thái thoát (exit status) cho tiến trình cha.

* **syntax**
  ```c
  void _exit(int status);
  ```
