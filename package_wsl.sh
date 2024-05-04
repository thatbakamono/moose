dd if=/dev/zero of=moose.img bs=1M count=64
parted moose.img mklabel msdos mkpart primary fat32 1MiB 100% set 1 boot on
./limine/limine.exe bios-install moose.img
mformat -i moose.img@@1M -F ::
mmd -i moose.img@@1M ::/EFI ::/EFI/BOOT ::/boot ::/boot/limine
mcopy -i moose.img@@1M ./target/x86_64-moose/$1/moose ::/boot
mcopy -i moose.img@@1M limine.cfg limine/limine-bios.sys ::/boot/limine
mcopy -i moose.img@@1M limine/BOOTX64.EFI ::/EFI/BOOT
mcopy -i moose.img@@1M limine/BOOTIA32.EFI ::/EFI/BOOT