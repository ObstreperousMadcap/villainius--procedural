/*
lsass - A benign application used to demonstrate an EDR detection.
This IS NOT the official lsass application.
A compiled version is not distributed.

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

#include "lsass.h"

std::int_fast32_t main(std::int_fast32_t argc, char* argv[])
{
	const std::string nameOfThisApp = std::filesystem::path(argv[0]).filename().string(); // Used for prompts and parameters.

	std::cout << nameOfThisApp << " : Starting." << std::endl;
	if (displayFileInfo() == EXIT_FAILURE)
	{
		std::cerr << nameOfThisApp << " : Unable to retrieve product information. Exiting." << std::endl;
		return EXIT_FAILURE;
	}

	std::int_fast32_t pauseSeconds = 60;
	while (pauseSeconds > 0)
	{
		std::cout << nameOfThisApp << " : Pausing for " + std::to_string(pauseSeconds) + " second(s) before exiting." << std::endl;
		std::this_thread::sleep_for(std::chrono::seconds(5));
		pauseSeconds -= 5;
	}

	std::cout << nameOfThisApp << " : Exiting." << std::endl;

	return EXIT_SUCCESS;
}
