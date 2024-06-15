#include <anva.h>
#include <ldr/ldr.h>

PCSTR AnvaEmuFileName = 0;
UCHAR AnvaEmuDirectoryPath[256];
UCHAR AnvaEmuFullPath[MAX_PATH];

int main( int argc, char* argv[] )
{

    SetConsoleTitleA( "Analyzing Non-Volatile Applications" );

    if ( argc < 2 )
    {
        printf( "Anva!AnvaStartup: No PE file specified!\n" );
        Sleep( INFINITE );
    }

    printf( "Anva is running..\n" );

    LPCSTR PathArgument = argv[1];
    AnvaEmuFileName = strrchr( PathArgument, '\\' ) + 1;
    INT LengthDirPath = strlen( PathArgument ) - strlen( AnvaEmuFileName );
    memcpy( AnvaEmuDirectoryPath, PathArgument, LengthDirPath );
    AnvaEmuDirectoryPath[LengthDirPath + 1] = 0;
    strcpy( AnvaEmuFullPath, PathArgument );


    printf( "AnvaEmuDirectoryPath: %s\n", AnvaEmuDirectoryPath );
    printf( "AnvaEmuFileName: %s\n", AnvaEmuFileName );

    NTSTATUS LoaderStartup = LdrInitialiseThunk( PathArgument );
    if ( LoaderStartup != STATUS_SUCCESS )
    {
        printf( "Anva!LdrInitialiseThunk: PE couldn't be setup (0x%lx)!\n", LoaderStartup );
        Sleep( INFINITE );
    }
   
    
  
    Sleep( INFINITE );
    return 0;
}