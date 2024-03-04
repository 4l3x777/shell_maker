#include <iostream>
#include "shell_builder.h"

#include <string>

int main(int argc, char* argv[]) {
	if (argc != 2) std::cout << "Usage: " << argv[0] << " [PATH_TO_PE]" << std::endl;
	else {
		ShellBuilder builder;
		if (builder.load_PE(argv[1])) {
			if(builder.build_loader()) builder.save_SHELL();
		}
	}
	return 0;
}