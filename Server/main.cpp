#include "Server.h"

int main(void) {
	Server server;

	if (!server.Initialize()) {
		return -1;
	};

	server.AcceptClients();

	server.Run();

	return 0;
};