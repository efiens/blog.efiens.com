---
# Documentation: https://sourcethemes.com/academic/docs/managing-content/

title: "[TetCTF2019] Pwn Writeups"
subtitle: ""
summary: ""
authors: [pickaxe]
tags: []
categories: []
date: 2020-10-25T14:40:14+07:00
lastmod: 2020-10-25T14:40:14+07:00
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

### babyfirst

Source: https://github.com/minhbq-99/ctf/tree/master/tetctf/babyfirst

Chương trình có 2 tính năng chính play và login nhưng để sử dụng được chức năng play mình phải login được với user là admin mà mình không biết password. Nhìn kỹ hơn thì mình nhận thấy buffer user được lưu trước buffer password cách 32 byte và nếu ta input chuỗi dài 32 byte (byte cuối khác 0xa) vào user thì chương trình sẽ không thêm null byte vào cuối user. Hơn nữa ở hàm play sẽ in ra chuỗi user nhưng do không có null byte ở cuối nên nó sẽ in ra luôn password và ta lấy cái password đó đi login thôi.

Nhìn vào hàm play ta dễ dàng thấy được lỗi buffer overflow ở chỗ `secure_read`. Bước tiếp theo, ta đi leak canary, địa chỉ nền của vùng text và địa chỉ libc sau đó ta quay lại hàm play exploit lần 2 để có được shell.

Exploit code: https://github.com/minhbq-99/ctf/blob/master/tetctf/babyfirst/solve.py

`TetCTF{Y0U_4r3_N0T_Baby}`

### babysandbox
Source: https://github.com/minhbq-99/ctf/tree/master/tetctf/sandbox

Ở bài này chương trình được chạy và bị trace bởi 1 process cha. Process cha trace các syscall number mà chương trình gọi, chặn một số syscall number như 59 (execve), 322 (stub_execveat), 57 (fork), ... còn đối với cái syscall để open file thì đường dẫn file không được chứa chuỗi "flag" (check realpath nên không thể dùng cách tạo symbolic link). Để vượt qua cái filter này mình dùng cách switch mode sang x86 khi này thì syscall number là khác nhau nên cái filter trên sẽ không còn hiệu quả nữa.

Quay lại với chương trình chính thì mình có lỗi buffer overflow nhưng sau khi đọc input vào thì chương trình close hết stdin và stdout => phải backconnect

Vì program được static build nên thường sẽ có `_dl_make_stack_executable` dùng để làm stack có quyền thực thi để bỏ shellcode vào và nhảy về đó nhưng mà binary bị stripped mất hết symbol rồi. Lúc đầu mình đã định build cái rop chain khỏi cần shellcode gì hết nhưng mà input chỉ có 256 byte nên có vẻ không khả thi lắm.

Sau một hồi dò các hàm trong binary thì mình tìm được `_dl_make_stack_executable` ở 0x47F780 từ đó suy ra được địa chỉ `__stack_prot` và `__libc_stack_end` rồi build cái rop chain nhỏ để set `__stack_prot = 7` và gọi `_dl_make_stack_executable` với `rdi = __libc_stack_end` là mình có được stack có quyền thực thi.

Tới đây, mình dùng một shellcode kiếm được trên mạng [1] chỉnh sửa lại một tý để backconnect về vps của mình, read thêm input từ vps vào bss, làm cho bss có quyền thực thi rồi nhảy về bss và switch mode.

Shellcode: https://github.com/minh1811/ctf/blob/master/tetctf/sandbox/shellcode.asm

Trên con vps, mình viết một script nhỏ để nó gửi shellcode lên server. Lúc đầu, mình dùng shellcode execve /bin/sh nhưng bị process cha kill mất vì bad syscall. Mình debug thì thấy mặc dù switch mode và gọi execve (x86, syscall number 0xb) nhưng sau đó lại thấy gọi tiếp execve (x64, syscall number 0x3b), chắc là do /bin/sh nó gọi. Vì vậy, nên mình chuyển sang dùng open_read_write shellcode để đọc file flag, lúc này syscall number của open (x86) là 0x5 nên không bị vướng cái filter tên file nữa.

Exploit code:
https://github.com/minhbq-99/ctf/blob/master/tetctf/sandbox/solve.py
Open_read_write shellcode:
https://github.com/minhbq-99/ctf/blob/master/tetctf/sandbox/shellcode_server.asm

`TetCTF{H4PPY->N3W->Y34R}`

### babyheap

Source: https://github.com/minhbq-99/ctf/tree/master/tetctf/babyheap

Chương trình có 4 chức năng chính:

Alloc: tạo một chunk có độ lớn 0xa0, chỉ được tạo tối đa 5 chunk
Edit: chỉnh sửa nội dung của chunk
Remove: xóa chunk
Show: hiển thị thông tin của chunk

Coi qua code thì mình thấy có thể leak được địa chỉ của libc và heap vì lúc alloc giá trị cũ của chunk vẫn còn mà khi cái chunk còn là free chunk thì nó sẽ lưu những giá để quản lý trong unsortedbin. Mình dùng đoạn script sau để leak

```python
alloc() #0
alloc() #1
alloc() #2
alloc() #3
remove(0)
remove(2)
alloc() #0
show(0) 
```

Tiếp theo thì mình thấy lỗi off-by-one trong hàm edit. Lỗi off-by-one có thể overwrite null byte vào vùng size cũng chunk tiếp theo. Tuy nhiên, size của chunk là 0xa0 thì lúc overwrite thành 0x00 thì làm sao exploit được. Lúc đầu, mình đã nghĩ có sai sót lúc ra đề khiến bài này không exploit được nhưng anh @hocsama (anh ra đề) đã confirm lại là exploit được.

Sau một hồi suy nghĩ và debug thì mình đã tìm ra được cách tận dụng lỗi off-by-one này: free 2 chunk kế tiếp nhau để hợp lại thành một free chunk với size là 0x141. Khi đó, mình có thể overwrite size 0x141 thành 0x100 (flip prev_inuse bit)

Bây giờ, mình cố gắng kiểm soát con trỏ BK của một chunk lúc nó trong unsortedbin để thực hiện unsorted bin attack.

Chi tiết các bước:

Bước 1: mình alloc 5 chunk, chunk 4 để tránh free chunk bị consolidate với top chunk
Bước 2: remove chunk 2 và 3
Bước 3: dùng lỗi off-by-one để overwrite vùng size từ 0x141 thành 0x100
Bước 4: free chunk 0 vì mình đã flip prev_inuse bit của chunk 2 ở bước 3 nên libc sẽ nghỉ là chunk 1 đã bị free và sẽ unlink nó rồi merge với chunk 0. Tuy nhiên, cần lưu ý setup chunk 1 để unlink được diễn ra thành công do có đoạn check

```c
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))
```
https://github.com/lattera/glibc/blob/master/malloc/malloc.c#L1393

Bước 5: alloc 2 chunk lúc này trong unsortedbin sẽ còn lại chunk 1 mà mình vẫn có quyền edit chunk 1 do mình lừa libc nghĩ rằng chunk 1 đã được free chứ mình đâu có free nó đâu. Vậy là mình nắm được BK của 1 chunk trong unsortedbin rồi.
Lưu ý khi alloc tách chunk 0x100 ra thành 2 chunk nhỏ sẽ bị libc phát hiện lỗi bộ nhớ (memory corruption) do mình đã tự thay đổi size từ 0x140 thành 0x100 dẫn đến prev_size của chunk tiếp theo chunk này không đúng với size của chunk. Do đó, mình phải fake cái prev_size để bypass chỗ check này.
Tới đây, mình lại bị vướng vì không kiếm được target chunk để trỏ BK vào vì muốn lấy target chunk ra khỏi unsorted bin (được hiện thực trên doubly linked list) thì sẽ phải sửa BK của chunk trước đó cộng với FD của chunk sau, tức là target chunk phải được setup sao cho BK chỉ đến một vùng nhớ có quyền write. Hơn thế nữa, unsorted bin dựa trên nguyên tắc FIFO (first in first out) nên chunk 1 phải có size không phù hợp với lần alloc sau (ở đây là nhỏ hơn) thì target chunk mới được trả về ở lần alloc sau.

Mình cũng có biết tới house of orange nhưng chưa thử làm bao giờ nên lúc đầu hơi ngại mà giờ hết cách rồi nên phải ngồi đọc tài liệu thôi.

Sơ lược về house of orange [2]:

Khi phát hiện lỗi bộ nhớ (memory corruption) thì libc sẽ gọi abort, abort sẽ gọi tiếp `_IO_flush_all_lockp` để flush các stream. Trong _IO_flush_all_lock, các `_IO_file` object thỏa yêu cầu sẽ gọi `_IO_OVERFLOW` (một hàm nằm trong vtable của `_IO_file` object đó)

Các `_IO_file` được nối với nhau như singly linked list con trỏ next là `_chain` và con trỏ head nằm ở `_IO_list_all`

Ý tưởng ở đây là mình dùng unsorted bin attack trỏ BK của chunk 1 đến `_IO_list_all - 0x10` thì khi chunk 1 được lấy ra thì FD của chunk sau tức `_IO_list_all` sẽ được overwrite bởi địa chỉ nằm trong main arena. Mình không thể kiểm soát được main arena nhưng trùng hợp là offset của `_chain`(con trỏ next) lại là chỗ smallbin có size 0x60 [3]. Như các bạn thấy thì sau bước 5 ở trên, mình có 1 chunk nằm trong smallbin 0x60 và mình hoàn toàn có thể setup cái chunk đó từ trước.

Tới đây, vì muốn thỏa mái hơn, mình trỏ `_chain` của small chunk đó đến chunk 0 và mình fake `_IO_file` object tại chunk 0 trỏ con trỏ vtable của nó đến fake vtable của mình, trong vtable mình one gadget vào vậy là mình có được shell.

Ở đây khi fake `_IO_file` các bạn chỉ cần thỏa điều kiện này là được
```c
if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
       || (_IO_vtable_offset (fp) == 0
           && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
                    > fp->_wide_data->_IO_write_base))
       )
      && _IO_OVERFLOW (fp, EOF) == EOF)
```
https://github.com/lattera/glibc/blob/master/libio/genops.c#L701

Exploit code:
https://github.com/minhbq-99/ctf/blob/master/tetctf/babyheap/solve.py

`TetCTF{Roi_Ai_Cung_Bo_Anh_Di}`
