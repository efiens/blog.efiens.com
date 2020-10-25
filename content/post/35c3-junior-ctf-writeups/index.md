---
# Documentation: https://sourcethemes.com/academic/docs/managing-content/

title: "[35c3 Junior Ctf] Pwn Writeups"
subtitle: ""
summary: ""
authors: [pickaxe]
tags: []
categories: []
date: 2020-10-25T15:05:04+07:00
lastmod: 2020-10-25T15:05:04+07:00
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
Sơ lược về std::string
Những phiên bản libstdc++ gần đây thì có sử dụng kỹ thuật small string optimization. Đối với chuỗi có độ dài nhỏ hơn hoặc bằng 15 (không tính null byte), chuỗi được lưu tại buffer ngay trong cấu trúc. Với những chuỗi có độ dài lớn hơn, chuỗi sẽ được lưu trên heap và trong cấu trúc xuất hiện vùng capacity lưu kích thước của vùng nhớ được cấp phát.

### stringmaster1

Source: https://junior.35c3ctf.ccc.ac/uploads/stringmaster1-484b8ecec5ffc62ba1547019ab895ff864d86ba7.zip

Chương trình có 3 tính năng chính:

swap: trao đổi ký tự giữa 2 chuỗi đã cho
replace: thay thế ký tự ở chuỗi 1 bằng 1 ký tự khác
print: in chuỗi thứ nhất

Và đặc biệt chương trình đã có sẵn hàm spawn shell.

Sau một hồi đi dịch ngược và chạy thử, thì mình nhận ra chức năng replace gọi hàm `std::find` để tìm ký tự trong chuỗi 1 và thay thế nó bằng ký tự mình nhập vào. Ý tưởng lúc đầu của mình là thử đi thay thế null byte bằng một ký tự "A" rồi xài chức năng in ra xem sao. Và kết quả in ra rất nhiều giá trị trên stack

Lúc đầu mình nghĩ là do null byte bị đè nên hàm in ra đã không xác định đúng chỗ kết thúc của chuỗi nhưng mình nhận thấy trong output lại có khá nhiều null byte. Attach debugger vào thì mình thấy kết quả khá bất ngờ.

Vùng size bị ghi đè thành 0x410000000000000a. Sau khi debug và xem reference về hàm find thì mình tìm ra lý do là:

Tất cả các hàm làm việc với string đều dùng vùng size để xác định chiều dài của chuỗi chứ không quan tâm tới null byte (đây cũng là lý do mà lúc xài chức năng print thì output thu được bao gồm cả null byte)

Khi hàm find tìm kiếm thì nó không thấy null byte trong chuỗi ban đầu nên trả về -1, chương trình không kiểm tra mà tiếp tục dùng giá trị trả về làm index để ghi ký tự "A" vào nên ta ghi đè được vùng size. Ở đây khi đọc lại source mà đề bài cho mình thấy có đoạn check index >= 0 nhưng không biết vì sao trong mình debug thì không thấy.

Tới đây thì mình dùng chức năng replace để thay đổi return address trong stack thành địa chỉ của hàm spawn shell là xong rồi.

Exploit code:
https://github.com/minhbq-99/ctf/blob/master/35c3_junior/stringmaster1.py

`35C3_a6a9d10c61a652d23fbd0e9f73e638dac093472c`

### stringmaster2

Source: https://junior.35c3ctf.ccc.ac/uploads/stringmaster2-6b4d2536f9462bdcfca815b62054d0c2d5378afb.zip

Chương trình cũng giống như bài 1 nhưng có thêm một số mitigations và không có sẵn hàm spawn shell dù vậy cách làm cũng không khác mấy:
- Dùng chức năng replace để ghi đè vùng size của string1
- Dùng chức năng print để leak được địa chỉ libc và return address
- Tính toán địa chỉ one_gadget từ địa chỉ libc, ở đây mình sử dụng gadget này:
```
0x10a38c  execve("/bin/sh", rsp+0x70, environ)
constraints:   [rsp+0x70] == NULL
```
- Dùng chức năng replace để ghi đè return address bằng địa chỉ của one_gadget

Exploit code:
https://github.com/minhbq-99/ctf/blob/master/35c3_junior/stringmaster2.py

`35C3_fb23c497dbbf35b0f13b9d16311fa59cf8ac1b02`

### sum

Source: https://junior.35c3ctf.ccc.ac/uploads/sum-b22202e31d8d84ec55a8f7cb698e2d656622f806.zip

Chương trình có flow khá đơn giản:

- Nhập số số hạng cần tính tổng chương trình sẽ cấp phát 1 vùng nhớ trên heap để chứa các số này
- Chức năng set dùng để set số hạng thứ i
- Chức năng get dùng để get số hạng thứ i
- Chức năng sum dùng để tính tổng

Bài này mình tốn khá nhiều thời gian để tìm ra lỗi. Mình đọc code và chạy thử các chức năng get và set với index âm, kiểm tra lỗi off-by-one nhưng tất cả đều thất bại. Trong lúc chạy vu vơ thì mình có được input gây ra SEGFAULT

```
How many values to you want to sum up?
> 10000000000
Allocated space for 10000000000 values
...
Enter the command you want to execute.
[1] set <x> <d>
[2] get <x>
[3] sum
[4] bye

> get 1
Segmentation fault (core dumped)
```

Dùng debugger để run mình xác định được dòng code bị lỗi

`0x400ad4 <calculator+510>    mov    rdx, qword ptr [r12 + rax*8]`

Với rax = 1 (index mình nhập vào) và r12 = 0. Mình đọc đoạn code ở trên và thấy r12 là giá trị trả về của hàm `calloc` lúc chương trình cấp phát bộ nhớ. Sau khi đọc reference thì mình biết được do mình yêu cầu cấp phát vùng nhớ quá lớn nên calloc đã không cấp phát được và trả về 0.

Tới đây thì mình xài get với index thích hợp là có thể leak địa chỉ libc từ vùng GOT. Do không thấy one_gadget phù hợp, mình quyết định ghi đè `__isoc99_sscanf_got` với địa chỉ của system rồi ở lần nhập tiếp theo nhập `/bin/sh` là ta có được shell.

Exploit code: https://github.com/minhbq-99/ctf/blob/master/35c3_junior/sum.py

`35C3_346adfac5fdfa6b65e103de62310bcf2d7606729`
