@echo off

qemu-system-x86_64 -monitor telnet:0.0.0.0:1235,server,nowait -vga virtio -gdb tcp:0.0.0.0:1234 -no-reboot -d int -D ./log.txt -smp 4 -cpu qemu64,apic,fsgsbase -m 128M -drive format=raw,file=moose.iso -serial stdio
