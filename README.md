# Rust ile eBPF Hello World

Bu örnek tamamen Rust ile yazılmıştır. Aya kullanarak `syscalls/sys_enter_execve`
tracepoint'ine bağlanır ve her yeni program çalıştırıldığında çekirdeğin izleme
tamponuna `hello world (Rust eBPF)!` yazar.

## Gereksinimler

- Linux (eBPF ve debugfs/tracefs etkin olmalı)
- Rust stable ve nightly
- LLVM/Clang ile `bpf-linker`

Ubuntu/Debian üzerinde örnek kurulum:

```bash
sudo apt install clang llvm libelf-dev
rustup toolchain install stable
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
```

## Derleme ve çalıştırma

```bash
make run
```

Program açıkken başka bir terminalde `ls`, `date` gibi bir komut çalıştırın.
Yükleyici, eBPF programının ürettiği satırı gösterecektir. Durdurmak için
`Ctrl+C` kullanın.

Yalnızca derlemek için:

```bash
make build
```

Yetki veya tracefs hatası alınırsa:

```bash
sudo mount -t debugfs none /sys/kernel/debug
```

> `bpf_printk`, eğitim ve hata ayıklama içindir; yüksek hacimli üretim olayları
> için ring buffer tercih edilmelidir.
