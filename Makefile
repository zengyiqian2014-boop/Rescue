# Rescue - cross-compile with MinGW for x86_64 and ARM64 Windows.
#
#   make            both tools, both architectures
#   make x64        -> build/x86_64/*.exe   (mingw-w64 GCC)
#   make arm64      -> build/arm64/*.exe     (llvm-mingw Clang)
#   make clean
#
# ARM64 needs llvm-mingw on PATH (aarch64-w64-mingw32-clang++); mingw-w64 GCC
# does not target Windows-on-ARM64.

X64_CXX   ?= x86_64-w64-mingw32-g++
X64_WINDRES ?= x86_64-w64-mingw32-windres
ARM64_CXX ?= aarch64-w64-mingw32-clang++
ARM64_WINDRES ?= aarch64-w64-mingw32-windres

CXXFLAGS  = -O2 -std=c++17 -municode -Wall -Wextra \
            -static -static-libgcc -static-libstdc++
# Console subsystem + libraries Rescue links against. -pthread: ransom_guard
# uses std::thread (winpthreads, linked statically by the flags above).
LDFLAGS   = -Wl,--subsystem,console -pthread
# -lwintrust -lcrypt32: Authenticode verification in asep_cleaner (signature.h).
# -lbcrypt: SHA-256 (CNG) in scanner.
# mingw ignores #pragma comment(lib), so the libs must be listed here.
LIBS      = -ladvapi32 -lkernel32 -luser32 -lshlwapi -lwintrust -lcrypt32 -lbcrypt

# Tools: internal name -> is built for both arches.
TOOLS     = lockdown_breaker ransom_guard asep_cleaner watchdog scanner backup

X64_OUT   = $(patsubst %,build/x86_64/%.exe,$(TOOLS))
ARM64_OUT = $(patsubst %,build/arm64/%.exe,$(TOOLS))

.PHONY: all x64 arm64 clean
all: x64 arm64
x64:   $(X64_OUT)
arm64: $(ARM64_OUT)

build/x86_64/%.exe: src/%.cpp src/%.rc src/privilege.h src/signature.h src/etw_filemon.h src/rescue.manifest
	@mkdir -p build/x86_64
	$(X64_WINDRES) src/$*.rc -O coff -o build/x86_64/$*_res.o
	$(X64_CXX) $(CXXFLAGS) $< build/x86_64/$*_res.o -o $@ $(LDFLAGS) $(LIBS)
	@echo "built $@"

build/arm64/%.exe: src/%.cpp src/%.rc src/privilege.h src/signature.h src/etw_filemon.h src/rescue.manifest
	@mkdir -p build/arm64
	$(ARM64_WINDRES) src/$*.rc -O coff -o build/arm64/$*_res.o
	$(ARM64_CXX) $(CXXFLAGS) $< build/arm64/$*_res.o -o $@ $(LDFLAGS) $(LIBS)
	@echo "built $@"

clean:
	rm -rf build
