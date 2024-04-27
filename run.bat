@echo off

qemu-system-x86_64 -gdb tcp:0.0.0.0:1234 -no-reboot -smp 4 -cpu qemu64,apic,fsgsbase -m 128M -drive format=raw,file=moose.iso -serial stdio
