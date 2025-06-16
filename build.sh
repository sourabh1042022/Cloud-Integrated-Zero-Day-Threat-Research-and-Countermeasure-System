echo "[*] Compiling hook.rs into hook.so..."
rustc -C prefer-dynamic -O --crate-type=cdylib hook.rs -o libhook.so
echo "[+] Done. Output: libhook.so"
