#include <ldr/ldr.h>

PEB LdrpProcessorBlock;

VOID LdrCreatePebCopy( )
{
	ULONG_PTR PebAddress = NtCurrentPeb();
	RtlCopyMemory( &LdrpProcessorBlock, PebAddress, sizeof( PEB ) );

	// this won't copy everything, pointers like ProcessParameters have to be
	// allocated too
}


VOID LdrChangePebLdr(
	PIMAGE_NT_HEADERS NtHeaders,
	ULONG_PTR BaseAddress )
{
	PLIST_ENTRY HeadEntry = NULL;

#ifdef _M_X64
	PEB* ProcessEnvironmentBlock;
#else
	PEB32* ProcessEnvironmentBlock;
#endif
	PPEB_LDR_DATA Ldr;

	PLDR_DATA_TABLE_ENTRY LdrEntry = NULL;

	WCHAR *CommandLine;

	LdrCreatePebCopy( );

	VOID( *RtlInitUnicodeString )(
		UNICODE_STRING * DestinationString,
		PCWSTR SourceString
		) = (ULONG_PTR)GetProcAddress( GetModuleHandleA( "ntdll.dll" ), "RtlInitUnicodeString" );

	ProcessEnvironmentBlock = NtCurrentPeb( );
#ifdef _M_X64
	Ldr = ProcessEnvironmentBlock->LoaderData;
	HeadEntry = &Ldr->InMemoryOrderModuleList;

	// Get first entry (always our module)
	LdrEntry = CONTAINING_RECORD( HeadEntry->Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList );
	LdrEntry->DllBase = ( PVOID )BaseAddress;
	LdrEntry->EntryPoint = ( PVOID )NtHeaders->OptionalHeader.AddressOfEntryPoint;
	LdrEntry->SizeOfImage = NtHeaders->OptionalHeader.SizeOfImage;


	RtlInitUnicodeString( &LdrEntry->FullDllName, ConvertToLPCWSTR( AnvaEmuFullPath ) );
	RtlInitUnicodeString( &ProcessEnvironmentBlock->ProcessParameters->ImagePathName, ConvertToLPCWSTR( AnvaEmuFullPath ) );
	RtlInitUnicodeString( &ProcessEnvironmentBlock->ProcessParameters->CurrentDirectory.DosPath, ConvertToLPCWSTR( AnvaEmuDirectoryPath ) );
	
	// I know, I'm not proud of this either.
	CommandLine = ( WCHAR* )malloc( MAX_PATH * 2 + 1 );
	if ( CommandLine )
	{

		CommandLine[0] = 0;

		lstrcatW( CommandLine, L"\"" );
		lstrcatW( CommandLine, LdrEntry->FullDllName.Buffer );
		lstrcatW( CommandLine, L"\" " );
		lstrcatW( CommandLine, L"doggers" );
		RtlInitUnicodeString( &ProcessEnvironmentBlock->ProcessParameters->CommandLine, CommandLine );

	}
	
	
	
	ProcessEnvironmentBlock->BaseAddress = ( PVOID )BaseAddress;


	ProcessEnvironmentBlock->Subsystem = NtHeaders->OptionalHeader.Subsystem;
	ProcessEnvironmentBlock->ImageSubsystemMajorVersion = NtHeaders->OptionalHeader.MajorSubsystemVersion;
	ProcessEnvironmentBlock->ImageSubsystemMinorVersion = NtHeaders->OptionalHeader.MinorSubsystemVersion;
#endif

	// We can't manipulate the console from PEB because it will mess with Anva.

	// Useless lol but we just shift it off because we can.
	ProcessEnvironmentBlock->BeingDebugged = FALSE;
}