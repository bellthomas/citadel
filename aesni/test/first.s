# A program to be called from a C program
# Declaring data that doesn't change
.section .data
    string: .ascii  "Hello from assembler\n"
    length: .quad   . - string

# The actual code
.section .text
.global print
.type print, @function              #<-Important

print:
    mov     $0x1,%rax               # Move 1(write) into rax
    mov     $0x1,%rdi               # Move 1(fd stdOut) into rdi.
    mov     $string,%rsi            # Move the _location_ of the string into rsi
    mov     length,%rdx             # Move the _length_ of the string into rdx
    syscall                         # Call the kernel

    mov     %rax,%rdi               # Move the number of bytes written to rdi
    mov     $0x3c,%rax              # Move 60(sys_exit) into rax
    syscall                         # Call the kernel