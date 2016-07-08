#ifndef __QDL_H__
#define __QDL_H__

#include "patch.h"
#include "program.h"

int firehose_run(int fd);
int sahara_run(int fd, char *prog_mbn);
void print_hex_dump(const char *prefix, const void *buf, size_t len);

int content_load(const char *content_file);

#endif