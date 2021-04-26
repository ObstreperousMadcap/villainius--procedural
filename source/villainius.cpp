/*
villainius - A benign application used to demonstrate an EDR detection. 

Copyright(C) 2021 Michael Logan, ObstreperousMadcap@gmail.com
Repo: https://github.com/ObstreperousMadcap/villainius

This program is free software : you can redistribute it and /or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version. This program is distributed in 
the hope that it will be useful, but WITHOUT ANY WARRANTY; without 
even the implied warranty of MERCHANTABILITY or FITNESS FOR A 
PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program. If not, see https://www.gnu.org/licenses/.
*/

#include "villainius.h"

std::int_fast32_t main(std::int_fast32_t argc, char* argv[])
{
	// ****************************************************************************
	// Start: Using these variables turns the rest of the app into a template.
	// ****************************************************************************
	const std::string nameOfThisApp = std::filesystem::path(argv[0]).filename().string(); // Used for prompts and parameters.
	const std::string hollowedAppEXEName = "lsass.exe";
	const int hollowedAppResourceID = IDR_B64TEXTFILE1;

	// Using enum and map to enable the use of a switch for arguments.
	enum class launchEXEOption
	{
		evLaunchEXENotDefined,
		evLaunchEXEmimikats,
		evLaunchEXEnbtscan,
		evLaunchEXEnmap,
		evLaunchEXEpaexec,
		evLaunchEXEprocdump,
		evLaunchEXEpsexec,
		evLaunchEXEwce
	};
	static std::map<std::string, launchEXEOption> s_mapLaunchEXEOption;
	s_mapLaunchEXEOption["mimikats"] = launchEXEOption::evLaunchEXEmimikats;
	s_mapLaunchEXEOption["nbtscan"] = launchEXEOption::evLaunchEXEnbtscan;
	s_mapLaunchEXEOption["nmap"] = launchEXEOption::evLaunchEXEnmap;
	s_mapLaunchEXEOption["paexec"] = launchEXEOption::evLaunchEXEpaexec;
	s_mapLaunchEXEOption["procdump"] = launchEXEOption::evLaunchEXEprocdump;
	s_mapLaunchEXEOption["psexec"] = launchEXEOption::evLaunchEXEpsexec;
	s_mapLaunchEXEOption["wce"] = launchEXEOption::evLaunchEXEwce;

	// Using map as flags for launch executable selected.
	bool launchEXEAlreadySelected = false; // Only one executable allowed because methods are not the same for all.
	std::map<launchEXEOption, bool> b_mapLaunchEXESelected;
 	b_mapLaunchEXESelected[launchEXEOption::evLaunchEXEmimikats] = false;
	b_mapLaunchEXESelected[launchEXEOption::evLaunchEXEnbtscan] = false;
	b_mapLaunchEXESelected[launchEXEOption::evLaunchEXEnmap] = false;
	b_mapLaunchEXESelected[launchEXEOption::evLaunchEXEpaexec] = false;
	b_mapLaunchEXESelected[launchEXEOption::evLaunchEXEprocdump] = false;
	b_mapLaunchEXESelected[launchEXEOption::evLaunchEXEpsexec] = false;
	b_mapLaunchEXESelected[launchEXEOption::evLaunchEXEwce] = false;

	// Using map to connect launch executable option and filename.
	std::string launchEXEFilename; // Used for launch to avoid another for() loop.
	std::map<launchEXEOption, std::string> s_mapLaunchEXEFilename;
	s_mapLaunchEXEFilename[launchEXEOption::evLaunchEXEmimikats] = "mimikats.exe";
	s_mapLaunchEXEFilename[launchEXEOption::evLaunchEXEnbtscan] = "nbtscan.exe";
	s_mapLaunchEXEFilename[launchEXEOption::evLaunchEXEnmap] = "nmap.exe";
	s_mapLaunchEXEFilename[launchEXEOption::evLaunchEXEpaexec] = "paexec.exe";
	s_mapLaunchEXEFilename[launchEXEOption::evLaunchEXEprocdump] = "procdump.exe";
	s_mapLaunchEXEFilename[launchEXEOption::evLaunchEXEpsexec] = "psexec.exe";
	s_mapLaunchEXEFilename[launchEXEOption::evLaunchEXEwce] = "wce.exe";

	// Using map to connect launch executable option and resourceID.
	std::map<launchEXEOption, int> i_mapLaunchEXEResourceID;
	i_mapLaunchEXEResourceID[launchEXEOption::evLaunchEXEmimikats] = IDR_B64TEXTFILE2;
	i_mapLaunchEXEResourceID[launchEXEOption::evLaunchEXEnbtscan] = IDR_B64TEXTFILE3;
	i_mapLaunchEXEResourceID[launchEXEOption::evLaunchEXEnmap] = IDR_B64TEXTFILE4;
	i_mapLaunchEXEResourceID[launchEXEOption::evLaunchEXEpaexec] = IDR_B64TEXTFILE5;
	i_mapLaunchEXEResourceID[launchEXEOption::evLaunchEXEprocdump] = IDR_B64TEXTFILE6;
	i_mapLaunchEXEResourceID[launchEXEOption::evLaunchEXEpsexec] = IDR_B64TEXTFILE7;
	i_mapLaunchEXEResourceID[launchEXEOption::evLaunchEXEwce] = IDR_B64TEXTFILE8;

	const std::string helpText =
		"Usage:\n"
		"  villainius.exe [options]\n\n"
		"    [options]\n"
		"      -h               Print this help.\n"
		"      -e <executable>  (required) Embedded executable to be launched:\n"
		"                         mimikats      Benign version of mimikatz.\n"
		"                         nbtscan       Benign version of nbtscan.\n"
		"                         nmap          Benign version of nmap.\n"
		"                         paexec        Benign version of paexec.\n"
		"                         procdump      Benign version of procdump.\n"
		"                         psexec        Benign version of psexec.\n"
		"                         wce           Benign version of wce.\n"
		"                       Note: Only one may be specified; extras are ignored.\n"
		"      -l <method>      (required) Method used to launch embedded executable:\n"
		"                         createproc    CreateProcess\n"
		"                         hollowing     Process hollowing of embedded lsass.exe\n"
		"                         psenccmd      PowerShell -EncodedCommand\n"
		"                         psstartproc   PowerShell Start-Process\n"
		"                         shellex       ShellExecute\n"
		"                         shellexa      ShellExecuteExA\n"
		"                         stdsystem     std::system\n"
		"                       Note: One or more may be specified; The same\n"
		"                         <parameters> are used for all launch methods.\n"
		"      -p <parameters>  Parameters used with the official version of the\n"
		"                         embedded executable. This must be the *final* option.\n\n"
		"Examples:\n\n"
		"  villainius.exe -e mimikats -l createproc -p SEKURLSA::LogonPasswords full\n"
		"  villainius.exe -e nbtscan -l hollowing -p -vh <ipnetwork>/<maskbits>\n"
		"  villainius.exe -e nmap -l psenccmd -p <ipnetwork>/<maskbits> --spoof-mac 0\n"
		"  villainius.exe -e paexec -l psstartproc -p \\\\<ipaddress> --spoof-mac 0 <filename.exe>\n"
		"  villainius.exe -e procdump -l shellex -p -ma <filename.exe> <filename.dmp>\n"
		"  villainius.exe -e psexec -l shellexa -p \\\\<ipaddress> <command> -ab\n"
		"  villainius.exe -e wce -l stdsystem -p -s <username>:<domain>:<lmhash>:<nthash>\n";
	// ****************************************************************************
	// End: Using these variables turns the rest of the app into a template.
	// ****************************************************************************

	std::cout << nameOfThisApp << ": Starting." << std::endl;

	// Using enum and map to enable the use of a switch for arguments.
	enum class argumentValue
	{
		evArgumentNotDefined,
		evArgumentHelp,
		evArgumentExecutable,
		evArgumentLaunch,
		evArgumentParameters
	};
	static std::map<std::string, argumentValue> s_mapArguments;
	s_mapArguments["-h"] = argumentValue::evArgumentHelp;
	s_mapArguments["-e"] = argumentValue::evArgumentExecutable;
	s_mapArguments["-l"] = argumentValue::evArgumentLaunch;
	s_mapArguments["-p"] = argumentValue::evArgumentParameters;

	// Using enum and map to enable the use of a switch for launch methods.
	enum class launchMethod
	{
		notDefined,
		createproc,
		hollowing,
		psenccmd,
		psstartproc,
		shellex,
		shellexa,
		stdsystem
	};
	static std::map<std::string, launchMethod> s_mapLaunchMethod;
	s_mapLaunchMethod["createproc"] = launchMethod::createproc;
	s_mapLaunchMethod["hollowing"] = launchMethod::hollowing;
	s_mapLaunchMethod["psenccmd"] = launchMethod::psenccmd;
	s_mapLaunchMethod["psstartproc"] = launchMethod::psstartproc;
	s_mapLaunchMethod["shellex"] = launchMethod::shellex;
	s_mapLaunchMethod["shellexa"] = launchMethod::shellexa;
	s_mapLaunchMethod["stdsystem"] = launchMethod::stdsystem;

	// Using map as flags for launch method(s) selected.
	std::map<launchMethod, bool> b_mapLaunchMethodSelected;
	b_mapLaunchMethodSelected[launchMethod::createproc] = false;
	b_mapLaunchMethodSelected[launchMethod::hollowing] = false;
	b_mapLaunchMethodSelected[launchMethod::psenccmd] = false;
	b_mapLaunchMethodSelected[launchMethod::psstartproc] = false;
	b_mapLaunchMethodSelected[launchMethod::shellex] = false;
	b_mapLaunchMethodSelected[launchMethod::shellexa] = false;
	b_mapLaunchMethodSelected[launchMethod::stdsystem] = false;

	// Kept in a separate variable for use at the end when deleting extracted executables.
	std::string pauseSeconds;

	// Capture the arguments.
	std::vector<std::string> arguments(argv + 1, argv + argc); // Starting with argv + 1 excludes this executable.

	// No options or modules provided; force display of help.
	if (arguments.size() == 0) { arguments.push_back("-h"); }

	// Holds parsed arguments used when launching embedded executable.
	std::string launchEXEArguments;

	// Examine arguments.
	std::string lowercaseArgument;
	for (std::vector<std::string>::iterator argument = arguments.begin(); argument != arguments.end(); ++argument)
	{
		// Convert to lowercase to use s_map in switch.
		lowercaseArgument = *argument;
		std::transform(lowercaseArgument.begin(), lowercaseArgument.end(), lowercaseArgument.begin(), ::tolower);
		switch (s_mapArguments[lowercaseArgument])
		{
		case argumentValue::evArgumentHelp:
			if (displayFileInfo() == EXIT_FAILURE)
			{
				std::cerr << nameOfThisApp << ": Unable to retrieve product information." << std::endl;
				return EXIT_FAILURE;
			}
			std::cout << helpText;
			return EXIT_SUCCESS;
 		
		case argumentValue::evArgumentExecutable:
			if (++argument != arguments.end())
			{
				if (launchEXEAlreadySelected == false) // Only one executable allowed. 
				{
					launchEXEAlreadySelected = true; // Putting this here presumes that a valid option is specified.
					std::transform((*argument).begin(), (*argument).end(), (*argument).begin(), ::tolower);
					switch (s_mapLaunchEXEOption[*argument])
					{
					case launchEXEOption::evLaunchEXEmimikats:
						b_mapLaunchEXESelected[launchEXEOption::evLaunchEXEmimikats] = true;
						break;

					case launchEXEOption::evLaunchEXEprocdump:
						b_mapLaunchEXESelected[launchEXEOption::evLaunchEXEprocdump] = true;
						break;

					case launchEXEOption::evLaunchEXEwce:
						b_mapLaunchEXESelected[launchEXEOption::evLaunchEXEwce] = true;
						break;
					}
				}
			}
			break;

		case argumentValue::evArgumentLaunch:
			if (++argument != arguments.end())
			{
				std::transform((*argument).begin(), (*argument).end(), (*argument).begin(), ::tolower);
				switch (s_mapLaunchMethod[*argument])
				{
				case launchMethod::createproc:
					b_mapLaunchMethodSelected[launchMethod::createproc] = true;
					break;
				case launchMethod::hollowing:
					b_mapLaunchMethodSelected[launchMethod::hollowing] = true;
					break;
				case launchMethod::psenccmd:
					b_mapLaunchMethodSelected[launchMethod::psenccmd] = true;
					break;
				case launchMethod::psstartproc:
					b_mapLaunchMethodSelected[launchMethod::psstartproc] = true;
					break;
				case launchMethod::shellex:
					b_mapLaunchMethodSelected[launchMethod::shellex] = true;
					break;
				case launchMethod::shellexa:
					b_mapLaunchMethodSelected[launchMethod::shellexa] = true;
					break;
				case launchMethod::stdsystem:
					b_mapLaunchMethodSelected[launchMethod::stdsystem] = true;
					break;
				}
			}
			break;

		case argumentValue::evArgumentParameters:
			launchEXEArguments += lowercaseArgument + " ";
			++argument;
			for (std::vector<std::string>::iterator module = argument; module != arguments.end(); ++module)
			{
				launchEXEArguments += *module + " ";
			}
			break;              
		}
	}

	// Miscellaneous variables use for extracting, decoding, and saving embedded executables.
	const std::string customResourceType = "B64TEXTFILE";
	std::list<std::string> extractedEXENames; // Used to track extracted EXEs for deletion.

	// No need to extract lsass.exe if hollowing was not the selected launch method.
	if (b_mapLaunchMethodSelected[launchMethod::hollowing])
	{
		// Add to list for deletion later.
		extractedEXENames.push_front(hollowedAppEXEName);

		// Retrieve and decode Base64-encoded lsass.exe.
		std::cout << nameOfThisApp << ": Retrieving and decoding Base64-encoded " << hollowedAppEXEName << " from resources." << std::endl;
		if (extractFileResource(nameOfThisApp, hollowedAppResourceID, customResourceType, hollowedAppEXEName, true) == EXIT_FAILURE)
		{
			std::cerr << nameOfThisApp << ": Failed to retrieve and decode Base64-encoded " << hollowedAppEXEName << " from resources." << std::endl;
			return EXIT_FAILURE;
		}
	}

	// Extract only the launch executables specified on the command line.
	for (auto const& [launchEXEoption, launchEXESelected] : b_mapLaunchEXESelected)
	{
		if (launchEXESelected == true)
		{
			extractedEXENames.push_front(s_mapLaunchEXEFilename[launchEXEoption]); // Add to list for deletion later.
			launchEXEFilename = s_mapLaunchEXEFilename[launchEXEoption]; // Used for launch to avoid another for() loop.
			// Retrieve and decode Base64-encoded launch app.
			std::cout << nameOfThisApp << ": Retrieving, decoding, and exporting Base64-encoded " << s_mapLaunchEXEFilename[launchEXEoption] << " from resources." << std::endl;
			if (extractFileResource(nameOfThisApp, i_mapLaunchEXEResourceID[launchEXEoption], customResourceType, s_mapLaunchEXEFilename[launchEXEoption], true) == EXIT_FAILURE)
			{
				std::cerr << nameOfThisApp << ": Failed to retrieve, decode, and export Base64-encoded << " << s_mapLaunchEXEFilename[launchEXEoption] << " from resources." << std::endl;
				return EXIT_FAILURE;
			}
		}
	}

	if (b_mapLaunchMethodSelected[launchMethod::createproc]) { launchCreateProcess(nameOfThisApp, launchEXEFilename, launchEXEArguments); }
	if (b_mapLaunchMethodSelected[launchMethod::hollowing]) { launchHollowing(nameOfThisApp, launchEXEFilename, launchEXEArguments, hollowedAppEXEName); }
	if (b_mapLaunchMethodSelected[launchMethod::psenccmd]) { launchPowerShellEncodedCommand(nameOfThisApp, launchEXEFilename, launchEXEArguments); }
	if (b_mapLaunchMethodSelected[launchMethod::psstartproc]) { launchPowerShellStartProcess(nameOfThisApp, launchEXEFilename, launchEXEArguments); }
	if (b_mapLaunchMethodSelected[launchMethod::shellex]) { launchShellExecute(nameOfThisApp, launchEXEFilename, launchEXEArguments); }
	if (b_mapLaunchMethodSelected[launchMethod::shellexa]) { launchShellExecuteExA(nameOfThisApp, launchEXEFilename, launchEXEArguments); }
	if (b_mapLaunchMethodSelected[launchMethod::stdsystem]) { launchStdSystem(nameOfThisApp, launchEXEFilename, launchEXEArguments); }

	// All done - time to delete extracted EXEs.
	const std::int_fast32_t waitLoopsMaximum = 10;
	std::int_fast32_t waitLoopIteration;
	std::int_fast32_t waitLoopDuration; // Seconds per iteration.

	for (std::list<std::string>::iterator exeToDelete = extractedEXENames.begin(); exeToDelete != extractedEXENames.end(); ++exeToDelete)
	{
		waitLoopIteration = 1;
		while ((!DeleteFile(exeToDelete->c_str())) && (waitLoopIteration <= waitLoopsMaximum))
		{

			DWORD lastError = GetLastError();
			if (lastError == ERROR_ACCESS_DENIED)
			{
				std::cout << nameOfThisApp << ": " << exeToDelete->c_str() << " is in use and cannot be deleted." << std::endl;
				waitLoopDuration = 60;
				while (waitLoopDuration > 0)
				{
					std::cout << nameOfThisApp << ": Pausing for " << waitLoopDuration << " second(s) before trying again. ";
					std::cout << "(Attempt " << waitLoopIteration << " of " << waitLoopsMaximum << ")" << std::endl;
					std::this_thread::sleep_for(std::chrono::seconds(5));
					waitLoopDuration -= 5;
				}
			}
			++waitLoopIteration;
		}

		if (waitLoopIteration <= waitLoopsMaximum)
		{
			std::cout << nameOfThisApp << ": " << exeToDelete->c_str() << " has been deleted." << std::endl;
		}
		else
		{
			std::cerr << nameOfThisApp << ": " << exeToDelete->c_str() << " could not be deleted." << std::endl;
		}

	}

	std::cout << nameOfThisApp << ": Exiting." << std::endl;
	return EXIT_SUCCESS;
}