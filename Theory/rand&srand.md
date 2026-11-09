## rand()

  - rand() là một hàm trong thư viện <stdlib.h> của C, dùng để sinh ra một số nguyên giả ngẫu nhiên.
    ```c
    #include <stdlib.h>

    int number = rand();
    ```
    <img width="1128" height="271" alt="image" src="https://github.com/user-attachments/assets/18a309ec-72cb-45b9-9f5e-baeb703bb95d" />
  - Điểm thú vị là trên một hệ thống glibc thông dụng, nếu chạy lại chương trình mà không thay đổi gì, bạn vẫn nhận được cùng chuỗi số.
  - Tại sao lại như vậy?

    Vì rand() không tạo ra số ngẫu nhiên thực sự. Nó sử dụng một thuật toán có trạng thái để tạo ra một chuỗi số.
## srand()

  - srand() dùng để khởi tạo trạng thái của bộ sinh số giả ngẫu nhiên thông qua một giá trị gọi là seed (hạt giống).
    ```c
    void srand(unsigned int seed);
    ```    
    <img width="263" height="150" alt="download" src="https://github.com/user-attachments/assets/63144070-0e29-46ba-b0b3-5f5cbbc32d07" />

    Cùng seed + cùng cách triển khai PRNG → cùng chuỗi kết quả

    - Cùng seed → cùng chuỗi số trên cùng một cách triển khai rand().
    - Seed khác nhau → có thể tạo ra chuỗi khác nhau.
    - Mỗi lần gọi rand() → bộ sinh cập nhật trạng thái và trả về số tiếp theo trong chuỗi.
    - Chuẩn C không quy định chính xác thuật toán của rand(), nên chuỗi có thể khác nhau giữa các thư viện C.

    
