#include <anva.h>
#include <ldr/ldr.h>
#include <Psapi.h>

LPCWSTR ConvertToLPCWSTR( LPCSTR lpstr )
{
	int len = MultiByteToWideChar( CP_ACP, 0, lpstr, -1, NULL, 0 );
	if ( len == 0 )
	{
		return NULL;
	}
	LPWSTR lpwstr = ( LPWSTR )malloc( len * sizeof( WCHAR ) );
	if ( lpwstr == NULL )
	{
		return NULL;
	}
	MultiByteToWideChar( CP_ACP, 0, lpstr, -1, lpwstr, len );
	return lpwstr;
}

ULONG_PTR FindPattern(
    CONST UCHAR* Data,
    ULONG Size,
    CONST UCHAR* Pattern,
    CONST CHAR* Mask )
{
    size_t PatternLength;
    UCHAR Found;

    PatternLength = strlen( Mask );

    for ( size_t i = 0; i < Size - PatternLength; i++ )
    {
        Found = TRUE;
        for ( ULONG j = 0; j < PatternLength; j++ )
        {
            if ( Mask[j] != '?' && Pattern[j] != Data[i + j] )
            {
                Found = FALSE;
                break;
            }
        }
        if ( Found )
        {
            return ( uintptr_t )&Data[i];
        }
    }
    return 0;
}

ULONG_PTR AnvaFindModulePattern(
    HMODULE Module,
    CONST UCHAR* Pattern,
    CONST CHAR* Mask )
{

    MODULEINFO ModuleInfo;
    ULONG_PTR ModuleBase;
    ULONG ModuleSize;

    if ( !GetModuleInformation( GetCurrentProcess( ), Module, &ModuleInfo, sizeof( ModuleInfo ) ) )
        return 0;

    ModuleBase = ModuleInfo.lpBaseOfDll;
    ModuleSize = ModuleInfo.SizeOfImage;

    return FindPattern( ( CONST UCHAR* )ModuleBase, ModuleSize, Pattern, Mask );
}

