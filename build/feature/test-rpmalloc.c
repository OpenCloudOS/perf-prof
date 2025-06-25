#include <rpmalloc.c>

int main(void)
{
	char *p = rpmalloc(32);
        if (p)
                return 0;
        else
                return 1;
}
