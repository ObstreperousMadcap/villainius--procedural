/*
wce - A benign application used to demonstrate an EDR detection.
This IS NOT the official WCE application.
A compiled version is not distributed.

Copyright (C) 2021 Michael Logan, ObstreperousMadcap@gmail.com
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

#include "wce.h"

std::int_fast32_t main(std::int_fast32_t argc, char* argv[])
{
	const std::string nameOfThisApp = std::filesystem::path(argv[0]).filename().string(); // Used for prompts.

	// ****************************************************************************
	// Start: Using this variable turns the rest of the app into a template.
	// ****************************************************************************

	const std::string helpText =
		"Usage:\n\n"
		"  wce.exe [options] <parameters>\n\n"
		"    [options]\n"
		"      -h  Print this help.\n\n"
		"    <parameters>\n"
		"      Parameters used with the official wce.\n\n"
		"Examples:\n\n"
		"  wce.exe -a\n"
		"  wce.exe -w -o <filename.txt>\n"
		"  wce.exe -g <cleartextpassword>\n"
		"  wce.exe -s <username>:<domain>:<lmhash>:<nthash>\n"
		"  wce.exe -s <username>:<domain>:<lmhash>:<nthash> -c <filename.exe>\n\n";

	// ****************************************************************************
	// End: Using this variable turns the rest of the app into a template.
	// ****************************************************************************

	std::cout << nameOfThisApp << ": Starting." << std::endl << std::endl;

	// Extensibilty choice - Using enum and map to enable the use of a switch for arguments. 
	enum argumentValue
	{
		evArgumentNotDefined,
		evArgumentHelp,
	};
	static std::map<std::string, argumentValue> s_mapArguments;
	s_mapArguments["-h"] = evArgumentHelp;

	// Capture the arguments.
	std::vector<std::string> arguments(argv + 1, argv + argc); // Starting with argv + 1 excludes the executable.

	// No options or parameters provided; force display of help.
	if (arguments.size() == 0) { arguments.push_back("-h"); }

	// Examine arguments.
	std::string lowercaseArgument;
	std::string parameters = " ";
	for (std::vector<std::string>::iterator argument = arguments.begin(); argument != arguments.end(); ++argument)
	{
		// Convert to lowercase to use s_map in switch.
		lowercaseArgument = *argument;
		std::transform(lowercaseArgument.begin(), lowercaseArgument.end(), lowercaseArgument.begin(), ::tolower);
		switch (s_mapArguments[lowercaseArgument])
		{
		case evArgumentHelp:
			if (displayFileInfo() == EXIT_FAILURE)
			{
				std::cerr << nameOfThisApp << ": Unable to retrieve product information." << std::endl;
			}
			std::cout << helpText;
			std::cout << nameOfThisApp << ": Exiting." << std::endl;
			return EXIT_SUCCESS;

		default: // Everything else is treated as a parameter.
			parameters += *argument + " ";
			break;
		}
	}

	std::cout << nameOfThisApp << ": Parameter(s) {" << ((parameters.length() > 0) ? parameters : " None ") << "}" << std::endl;

	std::int_fast32_t pauseSeconds = 15;
	while (pauseSeconds > 0)
	{
		std::cout << nameOfThisApp << " : Pausing for " + std::to_string(pauseSeconds) + " second(s) before exiting." << std::endl;
		std::this_thread::sleep_for(std::chrono::seconds(5));
		pauseSeconds -= 5;
	}

	std::cout << nameOfThisApp << ": Exiting." << std::endl;

	return EXIT_SUCCESS;
}
