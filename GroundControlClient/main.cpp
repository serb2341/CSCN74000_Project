#include "GroundControlClient.h"

int main() {
    GroundControlClient::GroundControlClient gc;
    if (gc.Initialize()) {
        gc.ValidateConnection();
        gc.Run();
    }
    return 0;
}