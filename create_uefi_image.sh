dd if=/dev/zero of=moose_uefi.img bs=512 count=93750
echo "o -> y -> n -> default -> default -> default -> ef00 -> w -> y"
gdisk test.img
sudo losetup --offset 1048576 --sizelimit 46934528 /dev/loop5 moose_uefi.img
sudo mkdosfs -F 32 /dev/loop5
sudo mkdir /mnt/image
sudo mount /dev/loop5 /mnt/image
sudo mkdir /mnt/image/EFI
sudo mkdir /mnt/image/EFI/BOOT
sudo mkdir /mnt/image/boot
sudo mkdir /mnt/image/boot/limine
sudo cp limine.cfg limine/limine-bios.sys /mnt/image/boot/limine
sudo cp ./target/x86_64-moose/release/moose /mnt/image/boot
sudo cp limine/BOOTX64.EFI /mnt/image/EFI/BOOT
sudo cp limine/BOOTIA32.EFI /mnt/image/EFI/BOOT
sudo umount /dev/loop5