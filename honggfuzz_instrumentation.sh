CC=clang
CXX=clang++
CFLAGS="-fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp"
CXXFLAGS="-fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp"
./configure --disable-vlm --enable-debug --with-libfuzzer=ok --disable-qt --with-sanitizer=address LDFLAGS=-lasan
ASAN_OPTIONS=detect_leaks=0
make -j
#cd "test"
#rm vlc-demux-run

#../doltlibtool --tag=CC --mode=link clang -DTOP_BUILDDIR="/home/raefko/fuzzing/vlc" -DTOP_SRCDIR="/home/raefko/fuzzing/vlc" -fsanitize-coverage=trace-pc-guard,trace-cmp -Werror=unknown-warning-option -Werror=invalid-command-line-argument -pthread -Wall -Wextra -Wsign-compare -Wundef -Wpointer-arith -Wvolatile-register-var -Wformat -Wformat-security -Wbad-function-cast -Wwrite-strings -Wmissing-prototypes -Werror-implicit-function-declaration -Winit-self -pipe -fvisibility=hidden
#-fsanitize=address -g -fsanitize-address-use-after-scope -fno-omit-frame-pointer -fno-math-errno -funsafe-math-optimizations -funroll-loops -fstack-protector-strong -no-install -static -o vlc-demux-run vlc-demux-run.o ../lib/libvlc.la -Wl,--whole-archive -L/home/raefko/fuzzing/honggfuzz/libhfuzz/ -lhfuzz -u,LIBHFUZZ_module_instrument -u,LIBHFUZZ_module_memorycmp -Wl,--no-whole-archive


#../doltlibtool --tag=CC --mode=link clang -DTOP_BUILDDIR="/home/raefko/fuzzing/vlc/test" -DTOP_SRCDIR="/home/raefko/fuzzing/vlc/test" -fsanitize-coverage=trace-pc-guard,trace-cmp -Werror=unknown-warning-option -Werror=invalid-command-line-argument -pthread -Wall -Wextra -Wsign-compare -Wundef -Wpointer-arith -Wvolatile-register-var -Wformat -Wformat-security -Wbad-function-cast -Wwrite-strings -Wmissing-prototypes -Werror-implicit-function-declaration -Winit-self -pipe -fvisibility=hidden -fsanitize=address -g -fsanitize-address-use-after-scope -fno-omit-frame-pointer -fno-math-errno -funsafe-math-optimizations -funroll-loops -fstack-protector-strong -no-install -static  -o vlc-demux-run vlc-demux-run.c libvlc_demux_run.la ../lib/libvlc.la -Wl,--whole-archive -L/home/raefko/fuzzing/honggfuzz/libhfuzz/ -u,LIBHFUZZ_module_instrument -u,LIBHFUZZ_module_memorycmp -Wl,--no-whole-archive
