#include "Server.h"

int main(void) {
	int exitStatus = -1;

	Networking::Server server;

	if (!server.Initialize()) {
	}

	else {
		server.AcceptClients();

		server.Run();

		exitStatus = 0;
	};

	return exitStatus;
};