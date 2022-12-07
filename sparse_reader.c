/*
 * Copyright (c) 2022, Collabora Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include "sparse_reader.h"

static int next_chunk(struct sparse_reader *s_reader, int fd)
{
	ssize_t r, skip;
	struct sparse_header *s_hdr = &s_reader->s_hdr;
	struct chunk_header *chunk = &s_reader->c_hdr;

	r = read(fd, chunk, sizeof(struct chunk_header));
	if (r != sizeof(struct chunk_header))
		return r;

	if (s_hdr->chunk_hdr_sz > sizeof(struct chunk_header)) {
		skip = s_hdr->chunk_hdr_sz -
			sizeof(struct chunk_header);
		r = lseek(fd, skip, SEEK_CUR);
		if (r == -1)
			return -1;
	}

	s_reader->c_left = s_reader->s_hdr.blk_sz * chunk->chunk_sz;

	/* sanity for this chunk */
	switch (chunk->chunk_type) {
	case CHUNK_TYPE_RAW:
		if (chunk->total_sz != s_hdr->chunk_hdr_sz + s_reader->c_left)
			return -1;
		break;
	case CHUNK_TYPE_FILL:
		if (chunk->total_sz !=
		    s_hdr->chunk_hdr_sz + sizeof(uint32_t))
			return -1;
		r = read(fd, &s_reader->c_fill_val, sizeof(uint32_t));
		if (r != sizeof(uint32_t))
			return -1;
		break;
	case CHUNK_TYPE_DONT_CARE:
		if (chunk->total_sz != s_hdr->chunk_hdr_sz)
			return -1;
		break;
	case CHUNK_TYPE_CRC32:
		if (chunk->total_sz != s_hdr->chunk_hdr_sz + 4)
			return -1;
		r = lseek(fd, 4, SEEK_CUR);
		if (r == -1)
			return -1;

		break;
	default:
		return -1;
	}

	return 0;
}

static ssize_t fill_buff(struct sparse_reader *s_reader, int fd, void *buf, size_t count)
{
	uint32_t *fill_buf = buf;
	ssize_t ret, i;

	switch(s_reader->c_hdr.chunk_type) {
	case CHUNK_TYPE_RAW:
		ret = read(fd, buf, count);
		if (ret != count)
			return -1;
		break;
	case CHUNK_TYPE_FILL:
		for (i = 0; i <  count / sizeof(uint32_t); i++)
			fill_buf[i] = s_reader->c_fill_val;
		break;
	case CHUNK_TYPE_DONT_CARE:
		/* sounds nice to fill the buffer with something */
		memset(buf, 0, count);
		break;
	case CHUNK_TYPE_CRC32:
		count = 0;
		break;
	default:
		/* should not happen, already checked in next_chunk */
		return -1;
	}

	return count;
}

static ssize_t sparse_reader_read_chunk(struct sparse_reader *s_reader, int fd,
					void *buf, size_t count)
{
	ssize_t n;
	int ret;
	if (!s_reader->c_left) {
		if (s_reader->chunk_idx < s_reader->s_hdr.total_chunks - 1) {
			ret = next_chunk(s_reader, fd);
			if (ret) {
				return ret;
			}
			s_reader->chunk_idx++;
		} else
			return -1;
	}

	if (s_reader->c_left < count)
		n = s_reader->c_left;
	else
		n = count;

	ret = fill_buff(s_reader, fd, buf, n);
	if (ret < 0)
		return ret;

	s_reader->c_left -= n;

	return n;
}

ssize_t sparse_output_size(struct sparse_reader *s_reader)
{
	return s_reader->s_hdr.total_blks * s_reader->s_hdr.blk_sz;
}

ssize_t sparse_reader_read(struct sparse_reader *s_reader, int fd, void *buf, size_t count)
{
	size_t read = 0, ret;

	while (read < count) {
		ret = sparse_reader_read_chunk(s_reader,
					       fd, (uint8_t *)buf + read,
					       count - read);
		if (ret == -1)
			break;
		read += ret;
	}

	return read;
}

int sparse_reader_init(struct sparse_reader *s_reader, int fd)
{
	int ret;
	ssize_t r;

	r = read(fd, &s_reader->s_hdr, sizeof(struct sparse_header));
	if (r != sizeof(struct sparse_header))
		return -1;

	if (s_reader->s_hdr.magic != SPARSE_HEADER_MAGIC ||
	    s_reader->s_hdr.major_version != 1)
		return -1;
	ret = lseek(fd, s_reader->s_hdr.file_hdr_sz, SEEK_SET);
	if (ret != s_reader->s_hdr.file_hdr_sz)
		return -1;

	ret = next_chunk(s_reader, fd);
	if (ret)
		return ret;
	s_reader->chunk_idx = 0;

	return 0;
}
