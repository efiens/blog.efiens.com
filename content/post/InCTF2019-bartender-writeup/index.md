---
# Documentation: https://sourcethemes.com/academic/docs/managing-content/

title: "[InCTF2019] Bartender writeup"
subtitle: ""
summary: ""
authors: [pickaxe]
tags: []
categories: []
date: 2019-09-24T14:16:52+07:00
lastmod: 2019-09-24T14:16:52+07:00
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

Challenge: [Link](https://github.com/minhbq-99/ctf/tree/master/inctf2019/bartender/files)

Bài này cho ta 1 file PE và 1 file xml. Mở file xml lên coi mình thấy có nhắc đến SEHOP

`<SEHOP Enable="false" TelemetryOnly="false" />`

Qua tìm hiểu trên mạng mình biết được đây là 1 mitigation để tránh SEH (Structured Exception Handler) overwrite exploit khi có lỗi buffer overflow. Vì thế, mình đi tìm lỗi buffer overflow trong bài và phát hiện được lỗi đó ở chức năng add new ingredient
```c
char Buffer; // [esp+Ch] [ebp-24h]
...
ReadFile(hFile, &Buffer, 0x100u, 0, 0);
...
```
Ở bài này có sẵn hàm để đọc flag, tuy nhiên do hàm bị lỗi buffer overflow không return về mà sẽ gọi exit khi kết thúc hàm nên không thể ghi đè địa chỉ trả về trên stack được. Và mình nghĩ ngay đến việc ghi đè SEH record nhưng trước tiên mình muốn chắc chắn hướng này là đúng nên mình đi tìm chỗ gây ra exception trong code. Sau khi coi qua code mình thấy được chỗ có thể gây ra exception ở chức năng remove ingredient trong change a drink
```c
v4 = a2;
show_ingredient_list();
puts(a99LeaveMenu_1);
printf((int)aSelectTheIngre_1);
result = scanf(aD_4, &v4);
if ( v4 != 99 )
{
*(_DWORD *)(menu[a3] + 4) /= (unsigned int)price[2 * v4];
result = printf((int)aCurrentPriceD_1, *(_DWORD *)(menu[a3] + 4));
}
return result;
```
Mình thấy được index của price không được kiểm tra và mình có thể chọn index mà ở đó phần tử là 0 từ đó sẽ gây ra division by zero exception.
Tới đây, mình đi tìm hiểu về SEH overwrite exploit và dùng x32dbg để xem cái SEH record.

SEH record gồm 2 pointer, pointer đầu trỏ tới vị trí của record tiếp theo, pointer sau trỏ tới hàm handler và SEH record nằm ngay trên stack. Như vậy chỉ cần ghi đè 2 least significant byte của pointer tới hàm handler là mình có thể kiểm soát RIP.

`payload = "A"*0x5c + "\xff\xff\xff\xff" + "\xc0\x11"`

Mình dùng payload trên ở chỗ ReadFile để overwrite stack tuy nhiên chương trình bị status stack buffer overrun ngay lập tức. Mình nghĩ là do có cơ chế nào đó phát hiện buffer overflow nhưng tìm kiếm từ khóa đó trên mạng thì mình không có được gì. Sau đó, mình debug trace tiếp các lệnh tiếp theo thì thấy exception xảy ra ở hàm strncpy_s

`strncpy_s(Dst, 0x1Fu, Src, 0x1Fu);`

Src trỏ tới Buffer mà mình ghi vào ở ReadFile còn Dst là vùng nhớ trên heap. Mình tiếp tục step vào hàm `strncpy_s` thì nhận thấy lỗi là do chiều dài của string chứa ở Src không chứa đủ trong 0x1f byte. Các bạn có thể đọc reference để hiểu rõ hơn về hàm này. Vậy mình sửa payload lại thành

`payload = "\0" + "A"*0x5b + "\xff\xff\xff\xff" + "\xc0\x11"`

Rồi make a drink xong sử dụng tính năng remove ingredient với index phù hợp là có được flag.

Exploit: [solve.py](https://github.com/minhbq-99/ctf/blob/master/inctf2019/bartender/solve.py)

`inctf{000-z3r0_iS_An_ExCept1on4l_nuMb3r-000}`
