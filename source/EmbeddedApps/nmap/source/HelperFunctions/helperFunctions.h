#pragma once
#pragma comment(lib, "Version.lib")  // Needed for GetFileVersionInfoSize, GetFileVersionInfo, VerQueryValue

#include <windows.h>
#include <winternl.h>
#include <codecvt>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <locale>
#include <map>
#include <sstream>
#include <stdint.h>
#include <string>
#include <vector>

// ***** Start: Required for process hollowing
#pragma comment(lib,"ntdll.lib")
EXTERN_C NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtGetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtSetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
EXTERN_C NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);
// ***** End: Required for process hollowing

std::int_fast32_t base64Decode(const std::string&, std::vector<BYTE>& encodedContent, std::vector<BYTE>& decodedContent);
std::int_fast32_t base64Encode(std::vector<BYTE>& decodedContent, std::vector<BYTE>& encodedContent);
std::int_fast32_t displayFileInfo();
std::int_fast32_t errorHandler(const std::string&);
std::int_fast32_t extractFileResource(const std::string&, const int&, const std::string&, const std::string&, const bool&);
void launchCreateProcess(const std::string&, const std::string&, const std::string&);
void launchHollowing(const std::string&, const std::string&, const std::string&, const std::string&);
void launchPowerShellStartProcess(const std::string&, const std::string&, const std::string&);
void launchPowerShellEncodedCommand(const std::string&, const std::string&, const std::string&);
void launchShellExecute(const std::string&, const std::string&, const std::string&);
void launchShellExecuteExA(const std::string&, const std::string&, const std::string&);
void launchStdSystem(const std::string&, const std::string&, const std::string&);
std::string splitStringIntoSegments(const std::string&, const std::size_t&, const size_t&);
std::int_fast32_t utf8_to_utf16(const std::string&, std::wstring&);
