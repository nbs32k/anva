#pragma once
#include <Windows.h>
#include <stdio.h>

typedef long ANVASTATUS;
#define STATUS_SUCCESS				0x0
#define STATUS_BAD_PE_IMAGE			0x0000000A
#define STATUS_INVALID_PE_ARCH		0x0000000B
#define STATUS_HANDLE_FAILED		0x0000000C
#define STATUS_BAD_ALLOCATION		0x0000000D

PCSTR AnvaEmuFileName;
UCHAR AnvaEmuDirectoryPath[];
UCHAR AnvaEmuFullPath[];

LPCWSTR ConvertToLPCWSTR( LPCSTR lpstr );

ULONG_PTR AnvaFindModulePattern(
    HMODULE Module,
    CONST UCHAR* Pattern,
    CONST CHAR* Mask );