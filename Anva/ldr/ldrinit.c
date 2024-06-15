#include <ldr/ldr.h>

ULONG_PTR LdrpBasicBuffer = 0;
ULONG_PTR LdrpSystemExecutive = 0;

typedef int WinMain_t(
	HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPSTR     lpCmdLine,
	int       nShowCmd
);

typedef BOOL WINAPI DllMain_t(
	HINSTANCE hinstDLL,
	DWORD fdwReason,
	LPVOID lpvReserved
);

typedef int mainCRTStartup_t( PEB* );
char*** __cdecl _p___argv_0( void )
{
	static const char* dawg[] = { "test" };
	static char** argv = ( char** )dawg;
	return &argv;
}

int* __cdecl _p___argc_0( void )
{
	static int count = 0; //1
	return &count;
}

VOID* LdrRetrieveRelevantBase(
	ULONG Size )
{
	ULONG_PTR RelevantBase = 0;
	MEMORY_BASIC_INFORMATION MemoryInfo;
	SIZE_T Result;
	ULONG_PTR FreeRegionBase;
	SIZE_T FreeRegionSize;

#ifdef _M_X64
	RelevantBase = 0x7FF740000000;
#else
	RelevantBase = 0x00400000;
#endif
	for ( ULONG_PTR CurrentBase = RelevantBase;; CurrentBase += 0x1000 )
	{
		Result = VirtualQuery( ( LPCVOID )CurrentBase, &MemoryInfo, sizeof( MemoryInfo ) );
		if ( Result == 0 )
			return NULL;

		if ( MemoryInfo.State == MEM_FREE )
		{
			FreeRegionBase = ( ULONG_PTR )MemoryInfo.BaseAddress;
			FreeRegionSize = 0;

			for ( ULONG Offset = 0; Offset < Size; Offset += 0x1000 )
			{
				Result = VirtualQuery( ( LPCVOID )(FreeRegionBase + Offset), &MemoryInfo, sizeof( MemoryInfo ) );
				if ( Result == 0 || MemoryInfo.State != MEM_FREE )
				{
					FreeRegionSize = 0;
					break;
				}
				FreeRegionSize += MemoryInfo.RegionSize;
			}

			if ( FreeRegionSize >= Size )
				return ( VOID* )FreeRegionBase;

			CurrentBase = FreeRegionBase + FreeRegionSize;
		}
	}

	return NULL;
}

VOID LdrResolveImports(
	PIMAGE_NT_HEADERS NtHeaders )
{

	PIMAGE_IMPORT_DESCRIPTOR pImports;
	IMAGE_DATA_DIRECTORY Directory;
	PIMAGE_OPTIONAL_HEADER pOptional;

	HMODULE hModule;
	LPCSTR ModuleName;

	LPCSTR OrdinalFunction;
	PIMAGE_IMPORT_BY_NAME Function;

	PIMAGE_THUNK_DATA pImportThunk;

	CHAR Path[MAX_PATH];



	pOptional = &NtHeaders->OptionalHeader;

	Directory = pOptional->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	pImports = ( PIMAGE_IMPORT_DESCRIPTOR )(Directory.VirtualAddress + ( DWORD_PTR )LdrpSystemExecutive);

	
	do
	{

		ModuleName = ( LPCSTR )(( DWORD_PTR )pImports->Name + ( DWORD_PTR )LdrpSystemExecutive);
		hModule = LoadLibraryA( ModuleName );

		if ( !hModule )
		{
			//
			//	Maybe a module in the path
			//
			sprintf( Path, "%s%s", AnvaEmuDirectoryPath, ModuleName );

			hModule = LoadLibraryA( Path );
			printf( "Loading unsigned %s module!\n", Path );

			if ( !hModule )
			{
				printf( "		-> failed\n" );
				pImports++;
				continue;
			}

		}

		pImportThunk = ( PIMAGE_THUNK_DATA )(( DWORD_PTR )LdrpSystemExecutive + pImports->FirstThunk);

		while ( pImportThunk->u1.AddressOfData )
		{
			Function = ( PIMAGE_IMPORT_BY_NAME )(( DWORD_PTR )LdrpSystemExecutive + pImportThunk->u1.AddressOfData);
			OrdinalFunction = ( LPCSTR )IMAGE_ORDINAL( pImportThunk->u1.Ordinal );

			if ( IMAGE_SNAP_BY_ORDINAL( pImportThunk->u1.Ordinal ) )
				pImportThunk->u1.Function = ( DWORD_PTR )GetProcAddress( hModule, OrdinalFunction );
			else
			{
				printf( "Anva!LdrResolveImports: resolving import %s!%s\n", ModuleName, Function->Name );
				if ( strstr( Function->Name, "__p___argv" ) )
					pImportThunk->u1.Function = ( DWORD_PTR )&_p___argv_0;
				else if ( strstr( Function->Name, "__p___argc" ) )
					pImportThunk->u1.Function = ( DWORD_PTR )&_p___argc_0;
				else
					pImportThunk->u1.Function = ( DWORD_PTR )GetProcAddress( hModule, Function->Name );
				
			}
			

			++pImportThunk;
		}


		pImports++;


	} while ( pImports->Name );


}

VOID LdrResolveSections(
	PIMAGE_NT_HEADERS NtHeaders )
{

	PIMAGE_SECTION_HEADER Section;
	ULONG SectionCount;
	ULONG_PTR Destination;
	ULONG_PTR Buffer;
	ULONG Protection;
	ULONG OldProtection;


	Section = IMAGE_FIRST_SECTION( NtHeaders );
	SectionCount = NtHeaders->FileHeader.NumberOfSections;

	if ( SectionCount == 0 )
	{
		printf( "Anva!LdrResolveSections: Something went really wrong, SectionCount == 0\n" );
		Sleep( INFINITE );
	}

	for ( ULONG i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++, Section++ )
	{
		Destination = ( ULONG_PTR )LdrpSystemExecutive + Section->VirtualAddress;
		Buffer = ( ULONG_PTR )LdrpBasicBuffer + Section->PointerToRawData;
		RtlCopyMemory( Destination, Buffer, Section->SizeOfRawData );

#ifdef _M_X64

		if ( Section->Characteristics & IMAGE_SCN_MEM_EXECUTE &&
			Section->Characteristics & IMAGE_SCN_MEM_WRITE )
			Protection = PAGE_EXECUTE_READWRITE;

		else if ( Section->Characteristics & IMAGE_SCN_MEM_EXECUTE )
			Protection = PAGE_EXECUTE_READ;

		else if ( Section->Characteristics & IMAGE_SCN_MEM_WRITE )
			Protection = PAGE_READWRITE;

		else
			Protection = PAGE_READWRITE;	// PAGE_READONLY can't be done, then we can't do relocation.

		
		//
		//	Todo: do a way to get around the upper issue.
		//
#else
		Protection = PAGE_EXECUTE_READWRITE;
#endif

		VirtualProtect( Destination, Section->SizeOfRawData, Protection, &OldProtection );

		printf( "Anva!LdrResolveSections: resolving section %s (0x%llx to 0x%llx) with protection 0x%lx\n", Section->Name, Buffer, Destination, Protection );
	}


}

VOID LdrResolveRelocations(
	PIMAGE_NT_HEADERS NtHeaders )
{

	IMAGE_DATA_DIRECTORY RelocationsDirectory;
	ULONG_PTR* LocationDelta;
	IMAGE_BASE_RELOCATION* BaseRelocation;
	ULONG RelocationEntries;
	USHORT* Relative;

	RelocationsDirectory = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	LocationDelta = ( ULONG_PTR )LdrpSystemExecutive - NtHeaders->OptionalHeader.ImageBase;
	BaseRelocation = ( IMAGE_BASE_RELOCATION* )(( ULONG_PTR )LdrpSystemExecutive + RelocationsDirectory.VirtualAddress);;
	
	if ( RelocationsDirectory.Size )
	{

		for ( ULONG j = 0; j < RelocationsDirectory.Size; j++ )
		{
			if ( !BaseRelocation->SizeOfBlock )
				continue;

			RelocationEntries = (BaseRelocation->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION )) / sizeof( USHORT );
			Relative = ( USHORT* )(&BaseRelocation[1]);

			for ( UINT i = 0; i != RelocationEntries; ++i, ++Relative )
			{
				if ( RELOC_FLAG( *Relative ) )
				{
					ULONG_PTR* pPatch = ( ULONG_PTR )(LdrpSystemExecutive + BaseRelocation->VirtualAddress + RELOC_OFFSET( *Relative ));
					*pPatch += ( ULONG_PTR )LocationDelta;
				}
			}

			BaseRelocation = ( ULONG_PTR )BaseRelocation + BaseRelocation->SizeOfBlock;
		}
	}


}


VOID LdrResolveTLS(
	PIMAGE_NT_HEADERS NtHeaders )
{

	LDR_DATA_TABLE_ENTRY LdrDataEntry;
	ULONG_PTR LdrpHandleTlsData_ = 0;

	LdrDataEntry.DllBase = LdrpSystemExecutive;

#ifdef _M_X64
	LdrpHandleTlsData_ = AnvaFindModulePattern( GetModuleHandleA("ntdll.dll" ),
		"\x48\x89\x7c\x24\x00\x41\x55\x41\x56\x41\x57\x48\x81\xec",
		"xxxx?xxxxxxxxx" ) + 0x5;


	if ( LdrpHandleTlsData_ == 0 )
	{
		printf( "Anva!LdrResolveTLS: Couldn't resolve TLS, aborting...\n" );
		Sleep( INFINITE );
	}

	void (*LdrpHandleTlsData)(LDR_DATA_TABLE_ENTRY * ldr) = LdrpHandleTlsData_;
	LdrpHandleTlsData( &LdrDataEntry );
#else
	LdrpHandleTlsData_ = AnvaFindModulePattern( GetModuleHandleA( "ntdll.dll" ),
		"\x6a\x78\x68\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x8b\xc1\x89\x45\xb0\x89\x45\x98",
		"xxx????x????xxxxxxxx" );
#endif


}

VOID LdrResolveExceptions(
	PIMAGE_NT_HEADERS NtHeaders )
{

	IMAGE_DATA_DIRECTORY ExceptionDirectory;
	IMAGE_RUNTIME_FUNCTION_ENTRY* FunctionTable;
	ULONG FunctionsCount;

#ifdef _M_X64

	ExceptionDirectory = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	

	if ( ExceptionDirectory.Size )
	{
		FunctionTable = ( ULONG_PTR )LdrpSystemExecutive + ExceptionDirectory.VirtualAddress;
		FunctionsCount = ExceptionDirectory.Size / sizeof( IMAGE_RUNTIME_FUNCTION_ENTRY );

		if ( !RtlAddFunctionTable( FunctionTable, FunctionsCount, LdrpSystemExecutive ) )
			printf( "Anva!LdrResolveExceptions: Couldn't setup SEH Handlers.\n" );

	}
#endif
}

ANVASTATUS LdrInitialiseThunk(
	LPCSTR ExecutablePath )
{

	HANDLE hHandle = INVALID_HANDLE_VALUE;
	ULONG FileSize = 0;
	DWORD dwTemporaryVariable;
	PIMAGE_DOS_HEADER DosHeader = 0;
	PIMAGE_NT_HEADERS NtHeaders = 0;
	ULONG_PTR ImageBase = 0;
	ULONG ImageSize = 0;
	ULONG EntryPoint = 0;
	ULONG DllCharacteristics = 0;
	ULONG Characteristics = 0;
	USHORT Subsystem = 0;
	BOOL DynamicBase = TRUE;
	ULONG_PTR RelevantBase = 0;


	hHandle = CreateFileA(
		ExecutablePath,
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		0,
		OPEN_EXISTING,
		0,
		0 );

	if ( hHandle == INVALID_HANDLE_VALUE )
		return STATUS_HANDLE_FAILED;

	FileSize = GetFileSize( hHandle, 0 );
	if ( FileSize == INVALID_FILE_SIZE )
		return STATUS_HANDLE_FAILED;

	LdrpBasicBuffer = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, FileSize );
	if ( LdrpBasicBuffer == 0 )
		return STATUS_BAD_ALLOCATION;

	if ( !ReadFile( hHandle, LdrpBasicBuffer, FileSize, &dwTemporaryVariable, 0 ) )
		return STATUS_HANDLE_FAILED;


	// PE Procedures
	DosHeader = ( PIMAGE_DOS_HEADER )LdrpBasicBuffer;
	if ( DosHeader->e_magic != IMAGE_DOS_SIGNATURE )
		return STATUS_BAD_PE_IMAGE;

	NtHeaders = ( PIMAGE_NT_HEADERS )(( ULONG_PTR )DosHeader + DosHeader->e_lfanew);
	if ( NtHeaders->Signature != IMAGE_NT_SIGNATURE )
		return STATUS_BAD_PE_IMAGE;

	if ( NtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC )
		return STATUS_INVALID_PE_ARCH;

	ImageBase = NtHeaders->OptionalHeader.ImageBase;
	ImageSize = NtHeaders->OptionalHeader.SizeOfImage;
	EntryPoint = NtHeaders->OptionalHeader.AddressOfEntryPoint;
	DllCharacteristics = NtHeaders->OptionalHeader.DllCharacteristics;
	Characteristics = NtHeaders->FileHeader.Characteristics;
	Subsystem = NtHeaders->OptionalHeader.Subsystem;
	DynamicBase = (DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);

	// Executive
	if ( LdrpSystemExecutive != 0 )
		VirtualFree( LdrpSystemExecutive, 0, MEM_RELEASE );

	//
	// Allocate the executive
	// LdrRetrieveRelevantBase will find the best legit usermode looking
	// address for our program's base.
	// If LdrRetrieveRelevantBase fails, VirtualAlloc will still allocate a page for us.
	//
	if( DynamicBase )
		RelevantBase = LdrRetrieveRelevantBase( ImageSize );


	LdrpSystemExecutive =
		VirtualAlloc(
			DynamicBase ? RelevantBase : ImageBase,
			ImageSize,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_EXECUTE_READWRITE );
	if ( LdrpSystemExecutive == 0 )
	{
		LdrpSystemExecutive =
			VirtualAlloc(
				0,
				ImageSize,
				MEM_RESERVE | MEM_COMMIT,
				PAGE_EXECUTE_READWRITE );
		if ( LdrpSystemExecutive == 0 )
			return STATUS_BAD_ALLOCATION;

	}
	printf( "Allocation made at %p\n", ( ULONG_PTR* )LdrpSystemExecutive );


	RtlCopyMemory( LdrpSystemExecutive, LdrpBasicBuffer, NtHeaders->OptionalHeader.SizeOfHeaders );


	LdrChangePebLdr( NtHeaders, LdrpSystemExecutive );

	LdrResolveSections( NtHeaders );
	printf( "[Anva] Resolved sections.\n" );
	if ( DynamicBase )
	{
		LdrResolveRelocations( NtHeaders );
		printf( "[Anva] Applied relocations.\n" );
	}
	
	LdrResolveImports( NtHeaders );
	printf( "[Anva] Resolved imports.\n" );

	LdrResolveTLS( NtHeaders );
	printf( "[Anva] Resolved TLS.\n" );

	if ( !(DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) )
	{
		LdrResolveExceptions( NtHeaders );
		printf( "[Anva] Resolved SEH Handlers.\n" );

	}

	printf( "Module: %p\n", GetModuleHandleA( 0 ) );

	LdrInitialiseHooks( );
	ULONG_PTR EntryCall = ( ULONG_PTR )LdrpSystemExecutive + EntryPoint;
	if ( Characteristics & IMAGE_FILE_DLL )
	{
		DllMain_t* DllMain = ( DllMain_t* )EntryCall;
		DllMain( ( HINSTANCE )LdrpSystemExecutive, DLL_PROCESS_ATTACH, 0 );
	}
	else if ( Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI )
	{
		WinMain_t* WinMain = ( WinMain_t* )EntryCall;
		WinMain( ( HINSTANCE )LdrpSystemExecutive, 0, 0, FALSE );
	}
	else if ( Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI )
	{
		mainCRTStartup_t* main = ( mainCRTStartup_t* )EntryCall;
		main( 0 );
	}
	else
	{
		printf( "Anva!LdrInitialiseThunk: Unsupported subsystem %d\n", Subsystem );
		Sleep( INFINITE );
	}
	

	HeapFree( GetProcessHeap(), 0, LdrpBasicBuffer );
	return STATUS_SUCCESS;
}