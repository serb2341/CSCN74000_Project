#include "GroundControlClient.h"

int main() {
    GroundControlClient gc;
    if (gc.Initialize()) {
        gc.ValidateConnection();
        gc.Run();
    }
    return 0;
}