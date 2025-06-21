#include <gperftools/tcmalloc.h>

int main()
{
	char *p = tc_malloc(32);
	if (p)
		return 0;
	else
		return 1;
}
