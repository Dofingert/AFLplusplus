#include <stdio.h>

int fb(int n) {
    if(n < 2) {
        return 1;
    }
    return fb(n - 1) + fb(n - 2);
}
