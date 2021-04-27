---
# Documentation: https://wowchemy.com/docs/managing-content/

title: "Một cái crash thú vị"
subtitle: ""
summary: ""
authors: [pickaxe]
tags: []
categories: []
date: 2021-04-27T11:49:35+07:00
lastmod: 2021-04-27T11:49:35+07:00
featured: false
draft: false

# Featured image
# To use, add an image named `featured.jpg/png` to your page's folder.
# Focal points: Smart, Center, TopLeft, Top, TopRight, Left, Right, BottomLeft, Bottom, BottomRight.
image:
  caption: ""
  focal_point: ""
  preview_only: false

# Projects (optional).
#   Associate this post with one or more of your projects.
#   Simply enter your project's folder or file name without extension.
#   E.g. `projects = ["internal-project"]` references `content/project/deep-learning/index.md`.
#   Otherwise, set `projects = []`.
projects: []
---
Bữa mình code một chương trình dạng thế này
```c
#include <stdio.h>

int main()
{
    char *env = getenv("PATH");
    if (env == NULL)
        return 1;

    printf("%s\n", env);
    return 0;
}
```
Khi compile và chạy thì bị crash, coi core dump file thì thấy nguyên nhân do `env` trỏ sai địa chỉ khi truyền vào hàm `printf`, debug thì thấy được lỗi hàm dòng này
```
0x0000000000001181 <+24>:    call   0x1060 <getenv@plt>
0x0000000000001186 <+29>:    cdqe   
0x0000000000001188 <+31>:    mov    QWORD PTR [rbp-0x8],rax
```
Code asm gọi hàm `getenv`, sau đó lệnh `cdqe` sẽ sign extend eax rồi lưu kết quả vào rax và chính lệnh này dẫn đến con trỏ bị sai.
Ví dụ: rax đang trỏ 0x7fff ff00 0000 sau lệnh này rax thành 0xffff ffff ff00 0000
Sau đó mình coi kỹ lại output lúc compile thì thấy
```
test.c: In function ‘main’:
test.c:5:14: warning: implicit declaration of function ‘getenv’ [-Wimplicit-function-declaration]
    5 |  char *env = getenv("PATH");
```
Nguyên nhân là do mình quên include `stdlib.h` nên gcc không kiếm thấy định nghĩa của hàm này. Tuy nhiên, GNU linker (ld) trong quá trình link chương trình thì vẫn tìm thấy symbol getenv trong libc nên không có lỗi xảy ra.

Nhìn vào asm thì có thể thấy gcc nghĩ rằng hàm getenv trả về kiểu `int`. Đi đọc code của gcc từ việc search string "implicit declaration of function" thì thấy được
```c
tree
implicitly_declare (location_t loc, tree functionid)
{
    ...
    decl = build_decl (loc, FUNCTION_DECL, functionid, default_function_type);
    ...
}
```
https://github.com/gcc-mirror/gcc/blob/2cde2d620fc5ff60264ee825fd6eea457d7c51d9/gcc/c/c-decl.c#L3710

```c
  default_function_type
    = build_varargs_function_type_list (integer_type_node, NULL_TREE);
```
https://github.com/gcc-mirror/gcc/blob/2cde2d620fc5ff60264ee825fd6eea457d7c51d9/gcc/c-family/c-common.c#L4465-L4466
Vậy có thể thấy nếu ta sử dụng 1 hàm mà gcc không tìm thấy định nghĩa của hàm này, gcc sẽ giả định hàm này có kiểu int(void) dẫn đến lỗi trong quá trình compile như trên.

Coi kỹ lại warning lúc compile thì mình thấy thêm warning ở dòng khởi tạo biến `env` bằng giá trị trả về của hàm `getenv`
```
test.c:5:14: warning: initialization of ‘char *’ from ‘int’ makes pointer from integer without a cast [-Wint-conversion]
```
