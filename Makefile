# Rescue - cross-compile with MinGW for x86_64 and ARM64 Windows.
#
#   make            both architectures
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
# Console subsystem + libraries Rescue links against.
LDFLAGS   = -Wl,--subsystem,console
LIBS      = -ladvapi32 -lkernel32 -luser32 -lshlwapi

SRC       = src/lockdown_breaker.cpp
RC        = src/lockdown_breaker.rc

.PHONY: all x64 arm64 clean
all: x64 arm64

x64: build/x86_64/lockdown_breaker.exe
arm64: build/arm64/lockdown_breaker.exe

build/x86_64/lockdown_breaker.exe: $(SRC) $(RC) src/privilege.h src/rescue.manifest
	@mkdir -p build/x86_64
	$(X64_WINDRES) $(RC) -O coff -o build/x86_64/res.o
	$(X64_CXX) $(CXXFLAGS) $(SRC) build/x86_64/res.o -o $@ $(LDFLAGS) $(LIBS)
	@echo "built $@"

build/arm64/lockdown_breaker.exe: $(SRC) $(RC) src/privilege.h src/rescue.manifest
	@mkdir -p build/arm64
	$(ARM64_WINDRES) $(RC) -O coff -o build/arm64/res.o
	$(ARM64_CXX) $(CXXFLAGS) $(SRC) build/arm64/res.o -o $@ $(LDFLAGS) $(LIBS)
	@echo "built $@"

clean:
	rm -rf build
