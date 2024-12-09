# Python_Computer
LSF NUDT homework. (^ _ ^)

## Introduction

### 1st commit

Requirement

 - Memory
    - 32-bit address
    - 8-bit cell
 - Register File
    - 32 32-bit-registers, with 2 read ports and 1 write port

Test bench

```
Load r1, #0
Load r2, #1
Add r3, r1, r2
Store r3, #3
```

从Requirement和Test bench可以得出：

1. 汇编指令中的操作数中，内存地址是以#为开头表示的
2. 内存以8bit即字节为单位编址
3. 32位的指令，如果直接在指令的操作数中给出地址，则能表示的内存非常有限，所以今后肯定要实现更多寻址方式，不过鉴于作业要求，暂时只实现了立即数寻址

于是不妨设计：

1. 将31号寄存器设置为基址寄存器
2. 将30号寄存器设置为PC
3. 将29号寄存器设置为指令寄存器
4. 将28号寄存器设置为数据寄存器

由于指令寄存器长度为32位，不妨设计机器码：

1. 高5位为操作码
2. 低27位为三个操作数，若指令不需要那么多操作数，则后面多余的操作数位置弃用
3. 当9位操作数的第1位为1时，代表这是一个寄存器，于是操作数的低5位表示寄存器号，第2-4位备用，于是有32个寄存器，第2-4位可以用于标识今后可能实现的其它寻址方式
4. 当9位操作数的第1位为0时，直接将低8位视为一个内存地址，于是可以直接表示256个内存单元

指令执行逻辑：

- LOAD指令：将第二个操作数表示的内存位置的32位数据，即四个地址单元的数据传送到数据寄存器，再复制到第一个操作数表示的寄存器中
- STORE指令：将一个操作数表示的寄存器的内容复制到数据寄存器，再传送到第二个操作数表示的内存位置为起始的32位空间
- ADD指令：将后两个操作数表示的寄存器中的值相加，保存在第一个操作数表示的寄存器中

代码设计：

- 一个类，汇编指令翻译器，将汇编指令翻译为机器码，使得计算机可以只与机器码打交道
- 一个类，计算机本身，接收机器码，执行相应动作

一些额外的小设计：

- 鉴于作业要求中#开头表示的内存不明确是十进制还是十六进制，因此都做了支持

令人困惑的规定：

- 2 read ports and 1 write port. 这条规定在当前条件下似乎没有意义。因为对同一个寄存器的读、写冲突只会发生在流水线模式下，而当前并没有设计流水线。也许这条规定会在未来对这份代码进行扩展时发生作用。在代码的当前阶段暂不对本规定做出体现
- test bench 中#0, #1, #3如果作为内存地址，读地址0则会读到0123连续四个地址的数据到寄存器，最后结果又被写回了3，这相当奇怪。于是修改了这里的地址，改为其它不在32位内相邻的内存地址

### Version 2

添加了对JGE（大于等于则跳转）指令的支持，并将示例执行程序修改为了一个使用JGE实现的循环；循环体中另有一个必然被触发的JGE，用于跳过一条Add指令，来验证JGE的有效性。

## How to run

```
python Run.py
```