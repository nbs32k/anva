#include <Windows.h>
#include <stdio.h>

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    PVOID Handle;
} CURDIR, * PCURDIR;

typedef struct _STRING
{
    WORD Length;
    WORD MaximumLength;
    CHAR* Buffer;
} STRING, * PSTRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    WORD Flags;
    WORD Length;
    ULONG TimeStamp;
    STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    PVOID ConsoleHandle;
    ULONG ConsoleFlags;
    PVOID StandardInput;
    PVOID StandardOutput;
    PVOID StandardError;
    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
    ULONG EnvironmentSize;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA
{
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB
{
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[13];
    PVOID BaseAddress;
    PPEB_LDR_DATA LoaderData;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    BYTE Reserved3[254];
    ULONG Subsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
} PEB;

typedef struct _PEB32
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages : 1;                                    //0x3
            UCHAR IsProtectedProcess : 1;                                     //0x3
            UCHAR IsLegacyProcess : 1;                                        //0x3
            UCHAR IsImageDynamicallyRelocated : 1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders : 1;                           //0x3
            UCHAR IsPackagedProcess : 1;                                      //0x3
            UCHAR IsAppContainer : 1;                                         //0x3
            UCHAR SpareBits : 1;                                              //0x3
        };
    };
    ULONG Mutant;                                                           //0x4
    ULONG ImageBaseAddress;                                                 //0x8
    PPEB_LDR_DATA Ldr;                                                              //0xc
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;                                                //0x10
    ULONG SubSystemData;                                                    //0x14
}PEB32;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
inline PEB* NtCurrentPeb( )
{
#ifdef _M_X64
    return ( PEB* )(__readgsqword( 0x60 ));
#elif _M_IX86
    return ( PEB32* )(__readfsdword( 0x30 ));
#endif
}

void main( int argc, char* argv[] )
{

    for ( ULONG i = 0; i < 25; i++ )
    {
        HANDLE hDevice = CreateFileW(
            L"\\\\.\\C:", GENERIC_ALL,
            FILE_SHARE_READ | FILE_SHARE_WRITE, 0,
            OPEN_EXISTING, 0, 0 );

        CloseHandle( hDevice );
    }
   
    Sleep( 1000 );

    HANDLE hDevice = CreateFileW(
        L"\\\\.\\C:", GENERIC_ALL,
        FILE_SHARE_READ | FILE_SHARE_WRITE, 0,
        OPEN_EXISTING, 0, 0 );

    CloseHandle( hDevice );
    Sleep( 3000 );

    hDevice = CreateFileW(
        L"\\\\.\\C:", GENERIC_ALL,
        FILE_SHARE_READ | FILE_SHARE_WRITE, 0,
        OPEN_EXISTING, 0, 0 );

    CloseHandle( hDevice );

	wchar_t szPath[MAX_PATH] = { 0 };
	DWORD dwSize = GetModuleFileNameW( NULL, szPath, ARRAYSIZE( szPath ) );

	PVOID ModuleHandle = GetModuleHandleW( 0 );

	wprintf( L"GetModuleFileNameW: %s\n", szPath );
	wprintf( L"GetModuleHandleW(0): %p\n", ModuleHandle );

#ifdef _M_X64
    PEB* ProcessEnvironmentBlock = NtCurrentPeb( );
#else
    PEB32* ProcessEnvironmentBlock = NtCurrentPeb( );
#endif
    wprintf( L"CommandLine: %s\n", ProcessEnvironmentBlock->ProcessParameters->CommandLine.Buffer );
    wprintf( L"ImagePathName: %s\n", ProcessEnvironmentBlock->ProcessParameters->ImagePathName.Buffer );
    wprintf( L"DllPath: %s\n", ProcessEnvironmentBlock->ProcessParameters->DllPath.Buffer );
    wprintf( L"CurrentDirectory: %s\n", ProcessEnvironmentBlock->ProcessParameters->CurrentDirectory.DosPath.Buffer );
    printf( "CurrentDirecotry.Handle: %p\n", ProcessEnvironmentBlock->ProcessParameters->CurrentDirectory.Handle );
    for ( int i = 0; i < argc; i++ )
    {
        printf( "Argument passed: %s\n", argv[i] );
    }

	Sleep( INFINITE );
}