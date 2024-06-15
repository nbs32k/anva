#include <ldr/ldr.h>
#include <ldr/minhook/minhook.h>
#include <time.h>

NTSTATUS
NTAPI
hNtProtectVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection );

NTSTATUS
NTAPI
hNtWriteVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN ULONG                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten OPTIONAL );

NTSTATUS
NTAPI
hNtAllocateVirtualMemory(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect );

NTSTATUS
NTAPI
hNtCreateFile(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES* ObjectAttributes,
	VOID* IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength );

NTSTATUS
NTAPI
hNtRaiseHardError(
	NTSTATUS ErrorStatus,
	ULONG NumberOfParameters,
	ULONG UnicodeStringParameterMask,
	PULONG_PTR* Parameters,
	ULONG ValidResponseOption,
	PULONG Response );


ANVA_WIN32_HOOK_TABLE AnvaWin32HookTable[] = {

	{"NtWriteVirtualMemory", "ntdll.dll", &hNtWriteVirtualMemory, 0},
	{"NtAllocateVirtualMemory", "ntdll.dll", &hNtAllocateVirtualMemory, 0},
	{"NtCreateFile", "ntdll.dll", &hNtCreateFile, 0},
	{"NtRaiseHardError", "ntdll.dll", &hNtRaiseHardError, 0},

};

PVOID AnvaGetHookOrig(
	PSTR pStr)
{
	for ( ULONG i = 0; i < ARRAYSIZE( AnvaWin32HookTable ); i++ )
	{
		//printf( "%s\n", AnvaWin32HookTable[i].Api );
		if ( strcmp( pStr, AnvaWin32HookTable[i].Api ) == 0 )
			return AnvaWin32HookTable[i].Original;
	}

	printf( "Anva!AnvaGetHookOrig: couldn't find %s\n", pStr );
	Sleep( INFINITE );
	return 0;
}

NTSTATUS
NTAPI
hNtWriteVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN ULONG                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten OPTIONAL )
{

	NTSTATUS( *orig )(HANDLE, PVOID, PVOID, ULONG, PULONG) = AnvaGetHookOrig( "NtWriteVirtualMemory" );


	printf( "Anva!hNtWriteVirtualMemory: handle=%p, base=%p, buffer=%p, size=%lx\n", ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite );
	orig( ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten );
}

NTSTATUS
NTAPI
hNtProtectVirtualMemory(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection )
{

	NTSTATUS( *orig )(HANDLE, PVOID*, PULONG, ULONG, PULONG) = AnvaGetHookOrig( "NtProtectVirtualMemory" );


	printf( "Anva!hNtProtectVirtualMemory: handle=%p, base=%p, size=%lx, prot=%lx\n", ProcessHandle, BaseAddress, *NumberOfBytesToProtect, NewAccessProtection );
	orig( ProcessHandle, BaseAddress, BaseAddress, NumberOfBytesToProtect, NewAccessProtection );
}

NTSTATUS
NTAPI
hNtCreateFile(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES* ObjectAttributes,
	VOID* IoStatusBlock,
	PLARGE_INTEGER AllocationSize,
	ULONG FileAttributes,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	PVOID EaBuffer,
	ULONG EaLength )
{

#define THRESHOLD_CALL_COUNT 5
#define DETECTION_WINDOW 1
#define COOLDOWN_PERIOD 120

	NTSTATUS( *orig )(PHANDLE, ACCESS_MASK, OBJECT_ATTRIBUTES*, VOID*, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG)
		= AnvaGetHookOrig( "NtCreateFile" );


	// Ransomware detection.
	if ( DesiredAccess & GENERIC_WRITE || DesiredAccess & GENERIC_ALL )
	{

		static ULONG LastTimeCalled = 0;
		static ULONG TimesCalled = 0;
		static BOOLEAN HasBeenFlagged = FALSE;
		static ULONG FlaggedTime = 0;
		ULONG CurrentTime = GetTickCount( );

		if ( HasBeenFlagged )
		{
			if ( CurrentTime > FlaggedTime + 2000 )
			{
				HasBeenFlagged = FALSE;
				TimesCalled = 0;
			}
			else
			{
				wprintf( L"Anva!hNtCreateFile: Ransomware behavior found on accessing %s\n", ObjectAttributes->ObjectName->Buffer );
				*FileHandle = INVALID_HANDLE_VALUE;
				SetLastError( ERROR_ACCESS_DENIED );
				return;
			}
		}


		if ( CurrentTime < LastTimeCalled + 1000 )
		{
			TimesCalled++;

			if ( TimesCalled >= 5 )
			{
				HasBeenFlagged = TRUE;
				FlaggedTime = CurrentTime;
				wprintf( L"Anva!hNtCreateFile: Ransomware behavior found on accessing %s\n", ObjectAttributes->ObjectName->Buffer );
				*FileHandle = INVALID_HANDLE_VALUE;
				SetLastError( ERROR_ACCESS_DENIED );
				return;
			}
		}
		else
		{
			LastTimeCalled = CurrentTime;
			TimesCalled = 1;
		}


	}
	

	CONST WCHAR* BadSymbolicLinks[] = { L"PhysicalDrive", L"HarddiskVolume", L"Volume", L"GLOBALROOT", L"Harddisk" };
	//wprintf( L"Accessing %s\n", ObjectAttributes->ObjectName->Buffer );
	for ( ULONG i = 0; i < ARRAYSIZE( BadSymbolicLinks ); i++ )
		if ( wcsstr( ObjectAttributes->ObjectName->Buffer, BadSymbolicLinks[i] ) != 0 )
		{
			wprintf( L"Anva!hNtCreateFile: program has tried to access a vulnerable Symbolic Link (%s), access denied.\n", ObjectAttributes->ObjectName->Buffer );
			*FileHandle = INVALID_HANDLE_VALUE;
			return ERROR_ACCESS_DENIED;
		}

	CONST WCHAR DiskPath[5];
	CONST WCHAR* Alphabet[] = {L"A", L"B", L"C", L"D", L"E", L"F", L"G", L"H", L"I", L"J", L"K", 
	L"L", L"M", L"N", L"O", L"P", L"Q", L"R", L"S", L"T", L"U", L"V", L"W", L"X", L"Y", L"Z" };

	for ( ULONG i = 0; i < ARRAYSIZE( Alphabet ); i++ )
	{
		wsprintfW( DiskPath, L"%s:", Alphabet[i] );
		if ( lstrlenW( ObjectAttributes->ObjectName->Buffer ) <= 8 && (wcsstr( ObjectAttributes->ObjectName->Buffer, DiskPath ) == 0) )
		{
			wprintf( L"Anva!hNtCreateFile: program has tried to access a vulnerable Symbolic Link (%s), access denied.\n", ObjectAttributes->ObjectName->Buffer );
			*FileHandle = INVALID_HANDLE_VALUE;
			return ERROR_ACCESS_DENIED;
		}
	}
		

	return orig( FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
		CreateOptions, EaBuffer, EaLength );
}

NTSTATUS
NTAPI
hNtAllocateVirtualMemory(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect )
{
	NTSTATUS( *orig )(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG)
		= AnvaGetHookOrig( "NtAllocateVirtualMemory" );

	orig( ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect );

	if ( Protect == PAGE_EXECUTE || Protect == PAGE_EXECUTE_READ ||
		Protect == PAGE_EXECUTE_READWRITE || Protect == PAGE_EXECUTE_WRITECOPY )
	{
		printf( "Anva!hNtAllocateVirtualMemory: allocated executable page %p in %s\n", 
			BaseAddress, ProcessHandle == GetCurrentProcess() ? "current process" : "external process" );
	}

	
}

NTSTATUS
NTAPI
hNtRaiseHardError(
	NTSTATUS ErrorStatus,
	ULONG NumberOfParameters,
	ULONG UnicodeStringParameterMask,
	PULONG_PTR* Parameters,
	ULONG ValidResponseOption,
	PULONG Response )
{
	printf( "Anva!hNtRaiseHardError: program just tried to summon a BugCheck, error_status=%lx\n", ErrorStatus );
	return ERROR_ACCESS_DENIED;
}

VOID LdrInitialiseHooks( )
{
	PCHAR DllName;
	PCHAR ApiName;

	if ( MH_Initialize( ) != MH_OK )
	{
		printf( "Anva!LdrInitialiseHooks: Minhook did not initialise!\n" );
		Sleep( INFINITE );
	}
	
	for ( ULONG i = 0;
		i < ARRAYSIZE( AnvaWin32HookTable );
		i++ )
	{

		DllName = AnvaWin32HookTable[i].DllName;
		ApiName = AnvaWin32HookTable[i].Api;

		ULONG_PTR FunctionAddress = ( ULONG_PTR )GetProcAddress( GetModuleHandleA( DllName ), ApiName );
		if ( FunctionAddress == 0 )
		{
			printf( "Anva!LdrInitialiseHooks: Api not found %s!%s\n", DllName, ApiName );
			continue;
		}

		printf( "Anva!LdrInitialiseHooks: Registering hook on API %s!%s\n", DllName, ApiName );
		if ( MH_CreateHook(
			( LPVOID )FunctionAddress, AnvaWin32HookTable[i].Hook,
			&AnvaWin32HookTable[i].Original ) != MH_OK )
		{


			printf( "Anva!LdrInitialiseHooks: Hook did not work, aborting..!\n" );
			Sleep( INFINITE );
		}

	}

	if ( MH_EnableHook( MH_ALL_HOOKS ) != MH_OK )
	{
		printf( "Anva!LdrInitialiseHooks: Couldn't enable hooks, aborting..!\n" );
		Sleep( INFINITE );
	}
	
}