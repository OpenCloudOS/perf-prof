// SPDX-License-Identifier: GPL-2.0
#include <sqlite3.h>

int main(void)
{
	sqlite3 *db;
	int ret;

	ret = sqlite3_open(":memory:", &db);
	if (ret == SQLITE_OK)
		sqlite3_close(db);

	return ret != SQLITE_OK;
}
