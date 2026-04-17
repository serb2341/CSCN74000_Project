#include "GroundControlClient.h"

int main() {
    Client::GroundControlClient gc;
    if (gc.Initialize()) {
        gc.ValidateConnection();
        gc.Run();
    }
    return 0;
}