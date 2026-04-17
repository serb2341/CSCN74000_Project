#include "InFlightClient.h"

int main(int argc, char* argv[]) {
	int status = -1;

	Client::InFlightClient inflightclient;

	if (argc < 2) {
		std::cout << "[Client] Enter FlightID upon startup\n";
	}

	else {
		int flightId = std::stoi(argv[1]); //***US - 10


		if (inflightclient.Initialize(flightId)) {
			inflightclient.ValidateConnection();

			inflightclient.Run();

			status = 0;
		};
	};

	return status;
};