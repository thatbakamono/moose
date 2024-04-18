@echo off

qemu-system-x86_64 -gdb tcp:0.0.0.0:1234 -no-reboot -d int -D ./log.txt -smp 4 -cpu qemu64,apic,fsgsbase -m 512M -drive format=raw,file=moose.iso -serial stdio
