#include <stdio.h>

int fb2(int n) {
    if(n <= 2) {
        return 1;
    }
    return fb2(n - 1) + fb2(n - 2);
}

int fb(int n) {
    if(n <= 2) {
        return 1;
    }
    return fb2(n - 1) + fb2(n - 2);
}

int main_wrapper(int argc, char* argv[])
{
    if(argc != 2 || (argv[1][0] > '9' || argv[1][0] < '0')
                 || (argv[1][1] > '9' || argv[1][1] < '0')) {
        printf("please input [xy].\n");
        return 0;
    }
    int n = 10*(argv[1][0] - '0')+argv[1][1] - '0';
    printf("n is %d\n",n);
    fb(n);
    fb2(n);
}
