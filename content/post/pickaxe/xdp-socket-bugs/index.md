---
# Documentation: https://sourcethemes.com/academic/docs/managing-content/

title: "Phân tích lỗi trong XDP socket Linux kernel"
subtitle: ""
summary: ""
authors: [pickaxe]
tags: [linux-kernel-bug]
categories: []
date: 2020-10-25T11:15:18+07:00
lastmod: 2020-10-25T11:15:18+07:00
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

Ở bài viết này, mình xin chia sẻ về 2 lỗi trong XDP socket ở Linux kernel mà mình tìm được. Cả 2 bug này mình đều tìm được thông qua việc đọc source code và lý do mình chọn XDP socket để xem là vì thấy code ở phần này có coverage không cao trong dashboard của syzbot [[1]](https://syzkaller.appspot.com/) 

Source code được sử dụng trong bài viết là phiên bản 5.5.11

#### 1. Tổng quan về XDP socket
XDP socket được dùng để chuyển tiếp gói tin giữa BPF program và một userspace program. Để sử dụng XDP socket, chúng ta cần đăng ký một vùng nhớ dùng để lưu các gói tin, vùng nhớ này sẽ được map ở cả userspace lẫn kernel address space. Vùng nhớ này có tên là `umem`. Ngoài ra để gửi vào nhận các gói tin, chúng ta cần thiết lập TX queue/ring, RX queue, Fill queue và Completion queue. Các phần tử trong queue chứa cái thông tin về 1 chunk cần được xử lý trong `umem`

![](https://static.lwn.net/images/2018/af_xdp4.png)  
Nguồn: https://lwn.net/Articles/750845/

Mọi người có thể tìm hiểu rõ hơn tại [[2]](https://www.kernel.org/doc/html/latest/networking/af_xdp.html)

#### 2. Lỗi không kiểm tra tham số headroom
Lỗi này khá đơn giản, `headroom` là một tham số do người dùng truyền vào nhưng không được kiểm tra.
```c
static int xdp_umem_reg(struct xdp_umem *umem, struct xdp_umem_reg *mr)
{
    u32 chunk_size = mr->chunk_size, headroom = mr->headroom;
    /* ... snip ... */
    umem->headroom = headroom;
    /* ... snip ... */
}
```
##### Khả năng khai thác
Trong report mình gửi lên [bugzilla](https://bugzilla.kernel.org/show_bug.cgi?id=207225), mình nghĩ là lỗi này có thể dẫn đến out of bound write do `chunk_size_nohr` được tính như sau
`umem->chunk_size_nohr = chunk_size - headroom`
Do `headroom` không được kiểm tra `chunk_size_nohr` có thể lớn hơn `chunk_size`. `chunk_size_nohr` được dùng trong hàm `xsk_generic_rcv` để kiểm tra gói tin có chứa đủ trong 1 chunk ở `umem` hay không
```c
int xsk_generic_rcv(struct xdp_sock *xs, struct xdp_buff *xdp)
{
    u64 offset = xs->umem->headroom;
    /* ... snip ... */
    if (!xskq_peek_addr(xs->umem->fq, &addr, xs->umem) ||
        len > xs->umem->chunk_size_nohr - XDP_PACKET_HEADROOM) {
        err = -ENOSPC;
        goto out_drop;
    }
    addr = xsk_umem_adjust_offset(xs->umem, addr, offset);  (1)
    buffer = xdp_umem_get_data(xs->umem, addr);
    memcpy(buffer, xdp->data_meta, len + metalen);
    /* ... snip ... */
}
```
Tuy nhiên, khi phân tích kỹ hơn hàm này, mình nhận thấy lỗi này hoàn toàn có thể dẫn đến arbitrary write. Giả sử `umem` có kích thước 0x8000, mỗi chunk có kích thước 0x1000, `addr` mình truyền vào 0x6000 (địa chỉ tương đối so với điểm đầu của `umem`), `headroom` là 0xFFFFEF00 và không sử dụng `XDP_UMEM_UNALIGNED_CHUNK_FLAG`. Ở dòng (1), `addr = addr + headroom = 0x100004F00`, tiếp theo để tính `buffer`, 0x100004 sẽ được dùng làm index cho một array để chuyển đổi địa chỉ tương đối này thành địa chỉ (virtual address) trong kernel, còn 0xF00 sẽ dùng làm offset cộng vào kết quả trả về. 

```c
static inline char *xdp_umem_get_data(struct xdp_umem *umem, u64 addr)
{
    /* ... snip ... */
    page_addr = (unsigned long)umem->pages[addr >> PAGE_SHIFT].addr;

    return (char *)(page_addr & PAGE_MASK) + (addr & ~PAGE_MASK);
}
```
Việc dùng index là 0x100004 dẫn đến out of bound read trong array umem->pages, kẻ tấn công hoàn toàn có thể spray địa chỉ mà mình muốn ghi phía sau array rồi dùng lỗi này để ghi vào địa chỉ đó.
Tuy nhiên, lỗi này là một lỗi không quá nghiêm trọng do để thiết lập cho việc nhận 1 gói tin thì BPF program, có những bước yêu cầu CAP_NET_ADMIN và việc tạo XDP socket yêu cầu CAP_NET_RAW trong net_namespace hiện tại. Để tìm hiểu thêm về cách thiết lập XDP socket để nhận gói tin từ một BPF program, mọi người có thể xem bài blog này [[3]](https://mr.gy/blog/snabb-xdp.html)

Do thấy lỗi này không quá nghiêm trọng nên mình đã không xem xét TX path để xem có thể đạt được arbitrary read hay không.

Poc gây kernel panic do ghi vào một địa chỉ rác khi chạy với đủ capability cần thiết: [poc.c](https://github.com/minhbq-99/linux_kernel_bugs/blob/master/CVE-2020-12659/poc.c)

Poc này có thể gọn hơn nếu sử dụng thư viện libbpf nhưng do mình không thể compile với libbpf nên mình tự viết lại và có copy một số hàm ở thư viện libbpf

Fix commit: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/net/xdp?id=99e3a236dd43d06c65af0a2ef9cb44306aef6e02

#### 2. Lỗi xử lý số nguyên
```c
static int xdp_umem_reg(struct xdp_umem *umem, struct xdp_umem_reg *mr)
{
    u64 addr = mr->addr, size = mr->len;
    /* ... snip ... */
    umem->npgs = size / PAGE_SIZE; (2)
    /* ... snip ... */
}
```
Ban đầu, mình không nhận ra lỗi này, tuy nhiên khi đang xem kiểu dữ liệu của các biến để kiểm tra những ý tưởng về lỗi tràn số nguyên khi thực hiện phép nhân, mình nhận thấy
```c
struct xdp_umem {
    /* ... snip ... */
    u32 npgs;
    /* ... snip ... */
}
```
`size` là một biến 64 bit, vậy kết quả của phép chia ở dòng (2) hoàn toàn có thể lớn hơn 32 bit. Tuy nhiên, `npgs` lại là một biến chỉ có 32 bit như vậy biến này không thể lưu trọn vẹn kết quả của phép chia

##### Khả năng khai thác
Giả sử chúng ta truyền `size` của `umem` là 0x1000 0000 8000, kết quả phép chia là 0x1 0000 0008, `npgs` chứa 0x8, array umem->pages để chuyển đổi giữa địa chỉ tương đối với đầu `umem` và địa chỉ ảo trong kernel chỉ có 8 phần tử. Khi ta truyền vào `addr = 0x9000` (địa chỉ tương đối với đầu `umem`), địa chỉ này được kiểm với `size` của `umem` vốn là một số rất lớn, tiếp theo 0x9 được dùng làm index vào array umem->pages để dẫn đến out of bound read tương tự như lỗi ở trên.
Lỗi này có thể dùng để arbitrary read, write nếu có đủ CAP_NET_ADMIN và CAP_NET_RAW. Trong trường hợp, người dùng thiếu những capability trên nếu CONFIG_USER_NS được bật cho phép người dùng không có đặc quyền (unprivileged user) tạo user namespace. Khi đó, người dùng không có đặc quyền sẽ có đầy đủ capability trong namespace này, có thể tạo XDP socket, gửi một gói tin (không thiết lập được BPF program ở đích đến do chỗ kiểm tra CAP_NET_ADMIN kiểm tra capability ở init_user_ns), gây ra đọc ở địa chỉ rác dẫn đến kernel panic.

Poc khi chạy bởi unprivileged user gây kernel panic: [poc.c](https://github.com/minhbq-99/linux_kernel_bugs/blob/master/XDP_integer_truncation/poc.c)

Fix commit: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/net/xdp?id=b16a87d0aef7a6be766f6618976dc5ff2c689291

Cảm ơn mọi người đã đọc.

#### Tham khảo
\[1\] https://syzkaller.appspot.com/  
\[2\] https://www.kernel.org/doc/html/latest/networking/af_xdp.html  
\[3\] https://mr.gy/blog/snabb-xdp.html  
