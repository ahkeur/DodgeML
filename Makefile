CC=x86_64-w64-mingw32-gcc
WINDRES=x86_64-w64-mingw32-windres
# -fno-ident: removes "GCC: (GNU) x.x" string from .comment section
CFLAGS=-O1 -s -static -fno-ident -ffunction-sections -fdata-sections
LIBS=-lcomctl32 -lgdi32 -luser32 -lshlwapi -lshell32 -lpowrprof -ladvapi32

# Output names matching resource identities
EXE_NAME=sysmon.exe
DLL_NAME=rthelper.dll

all: exe dll

exe: main.c resource_exe.rc manifest_exe.xml
	mkdir -p dist
	$(WINDRES) resource_exe.rc -o dist/resource_exe.o
	$(CC) $(CFLAGS) -o dist/$(EXE_NAME) main.c base64.c dist/resource_exe.o $(LIBS)

dll: main.c resource_dll.rc manifest_dll.xml
	mkdir -p dist
	$(WINDRES) resource_dll.rc -o dist/resource_dll.o
	$(CC) $(CFLAGS) -shared -o dist/$(DLL_NAME) -Ddll main.c base64.c dist/resource_dll.o $(LIBS)

clean:
	rm -rf dist/*
