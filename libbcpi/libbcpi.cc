#include <sys/cdefs.h>
#include <sys/utsname.h>

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <zlib.h>

#include <algorithm>
#include <string>
#include <unordered_map>
#include <vector>

#include "libbcpi.h"

struct bcpi_serializer {
	int max_size;
	int size;
	int read_cursor;
	unsigned int overflow : 1;
	unsigned int underflow : 1;
	unsigned int read_mode : 1;
	char *data;
};

//#define BCPI_DEBUG_FORMAT 1
#define BCPI_SERIALIZER_FIRST_SIZE 32

/*
 * Initialize structure for in memory arbitrary data writing.
 * Allocate space.
 */

void
bcpi_serializer_init(bcpi_serializer *b)
{
	b->size = 0;
	b->max_size = BCPI_SERIALIZER_FIRST_SIZE;
	b->read_cursor = 0;
	b->overflow = 0;
	b->underflow = 0;
	b->read_mode = 0;
	b->data = (char *)malloc(b->max_size);
}

void
bcpi_serilizer_finish(bcpi_serializer *b)
{
	if (!b->read_mode) {
		free(b->data);
	}
}

/*
 * Initialize structure to act like an interface for reading
 * arbitrary binary data. Does not allocate space.
 */

void
bcpi_serializer_init_read(bcpi_serializer *b, char *data, int size)
{
	b->size = size;
	b->max_size = size;
	b->read_cursor = 0;
	b->overflow = 0;
	b->underflow = 0;
	b->read_mode = 1;
	b->data = data;
}

void
bcpi_serializer_set_size(bcpi_serializer *b, int size)
{
	b->size = size;
}

int
bcpi_serializer_get_size(bcpi_serializer *b)
{
	return b->size;
}

void *
bcpi_serializer_get_write_cursor(bcpi_serializer *b)
{
	return &b->data[b->size];
}

void *
bcpi_serializer_get_read_cursor(bcpi_serializer *b)
{
	return &b->data[b->read_cursor];
}

void *
bcpi_serializer_get_data(bcpi_serializer *b)
{
	return b->data;
}

/*
 * Check, and possibilly allocate space so that item_size bytes of data could be
 * written. Update interval state overflow if allocation failed.
 */
void
bcpi_serializer_check_add(bcpi_serializer *b, int item_size)
{
	if (b->overflow) {
		return;
	}

	int new_size = b->size + item_size;
	if (new_size > b->max_size) {
		int new_max_size = std::max(b->max_size * 2, new_size);
		char *new_data = (char *)realloc(b->data, new_max_size);
		if (!new_data) {
			b->overflow = true;
		} else {
			b->data = new_data;
			b->max_size = new_max_size;
		}
	}
}

/*
 * Check if item_size bytes of data are available for reading.
 * Sets internal flag underflow if failed.
 *
 */
void
bcpi_serializer_check_get(bcpi_serializer *b, int item_size)
{
	if (b->underflow) {
		return;
	}
	int new_size = b->read_cursor + item_size;
	if (new_size > b->size) {
		b->underflow = true;
		return;
	}
}

void
bcpi_serializer_add_bytes(bcpi_serializer *b, const void *data, int size)
{
#ifdef BCPI_DEBUG_FORMAT
	uint32_t magic = 0x42595445 ^ size;
	bcpi_serializer_check_get(b, sizeof(magic));
	assert(!b->overflow);
	memcpy(&b->data[b->size], &magic, sizeof(magic));
	b->size += sizeof(magic);
#endif
	bcpi_serializer_check_add(b, size);
	if (b->overflow) {
		return;
	}
	memcpy(&b->data[b->size], data, size);
	b->size += size;
}

void
bcpi_serializer_get_bytes(bcpi_serializer *b, void *data, int size)
{
#ifdef BCPI_DEBUG_FORMAT
	uint32_t magic;
	bcpi_serializer_check_get(b, sizeof(magic));
	assert(!b->underflow);
	memcpy(&magic, &b->data[b->read_cursor], sizeof(magic));
	b->read_cursor += sizeof(magic);
	assert(magic == (0x42595445 ^ size));
#endif
	bcpi_serializer_check_get(b, size);
	if (b->underflow) {
		return;
	}
	memcpy(data, &b->data[b->read_cursor], size);
	b->read_cursor += size;
}

void
bcpi_serializer_add_uint64(bcpi_serializer *b, uint64_t i)
{
	bcpi_serializer_add_bytes(b, &i, sizeof(i));
}

void
bcpi_serializer_add_int64(bcpi_serializer *b, int64_t i)
{
	bcpi_serializer_add_bytes(b, &i, sizeof(i));
}

void
bcpi_serializer_add_int32(bcpi_serializer *b, int32_t i)
{
	bcpi_serializer_add_bytes(b, &i, sizeof(i));
}

void
bcpi_serializer_add_int24(bcpi_serializer *b, int32_t i)
{
	bcpi_serializer_add_bytes(b, &i, 3);
}

void
bcpi_serializer_add_int8(bcpi_serializer *b, int8_t i)
{
#ifdef BCPI_DEBUG_FORMAT
	uint32_t magic = 0x38424955;
	bcpi_serializer_check_get(b, sizeof(magic));
	assert(!b->overflow);
	memcpy(&b->data[b->size], &magic, sizeof(magic));
	b->size += sizeof(magic);
#endif
	int item_size = sizeof(i);
	bcpi_serializer_check_add(b, item_size);
	if (b->overflow) {
		return;
	}
	b->data[b->size++] = i;
}

void
bcpi_serializer_add_uint8(bcpi_serializer *b, uint8_t i)
{
#ifdef BCPI_DEBUG_FORMAT
	uint32_t magic = 0x38424954;
	bcpi_serializer_check_get(b, sizeof(magic));
	assert(!b->overflow);
	memcpy(&b->data[b->size], &magic, sizeof(magic));
	b->size += sizeof(magic);
#endif
	int item_size = sizeof(i);
	bcpi_serializer_check_add(b, item_size);
	if (b->overflow) {
		return;
	}
	b->data[b->size++] = i;
}

int8_t
bcpi_serializer_get_int8(bcpi_serializer *b)
{
#ifdef BCPI_DEBUG_FORMAT
	uint32_t magic;
	bcpi_serializer_check_get(b, sizeof(magic));
	assert(!b->underflow);
	memcpy(&magic, &b->data[b->read_cursor], sizeof(magic));
	b->read_cursor += sizeof(magic);
	assert(magic == 0x38424955);
#endif
	int8_t r = 0;
	int item_size = sizeof(r);
	bcpi_serializer_check_get(b, item_size);
	if (b->underflow) {
		return r;
	}
	r = b->data[b->read_cursor++];
	return r;
}

uint8_t
bcpi_serializer_get_uint8(bcpi_serializer *b)
{
#ifdef BCPI_DEBUG_FORMAT
	uint32_t magic;
	bcpi_serializer_check_get(b, sizeof(magic));
	assert(!b->underflow);
	memcpy(&magic, &b->data[b->read_cursor], sizeof(magic));
	b->read_cursor += sizeof(magic);
	assert(magic == 0x38424954);
#endif
	uint8_t r = 0;
	int item_size = sizeof(r);
	bcpi_serializer_check_get(b, item_size);
	if (b->underflow) {
		return r;
	}
	r = b->data[b->read_cursor++];
	return r;
}

int64_t
bcpi_serializer_get_int64(bcpi_serializer *b)
{
	int64_t r = 0;
	bcpi_serializer_get_bytes(b, &r, sizeof(r));
	return r;
}

int32_t
bcpi_serializer_get_int32(bcpi_serializer *b)
{
	int32_t r = 0;
	bcpi_serializer_get_bytes(b, &r, sizeof(r));
	return r;
}

int32_t
bcpi_serializer_get_int24(bcpi_serializer *b)
{
	int32_t r = 0;
	bcpi_serializer_get_bytes(b, &r, 3);
	return r;
}

void
bcpi_serializer_add_string(bcpi_serializer *b, const char *str)
{
	size_t len = strlen(str) + 1;
	bcpi_serializer_check_add(b, len + 1);
	if (b->overflow) {
		return;
	}
	assert(len < 256);
	bcpi_serializer_add_uint8(b, len);
	bcpi_serializer_add_bytes(b, str, len);
}

void
bcpi_serializer_add_string(bcpi_serializer *b, const std::string &str)
{
	bcpi_serializer_add_string(b, str.c_str());
}

/*
 * Get pointer to next string in the stream. Note that
 * string needs to be copied if used for extended amount of time.
 */

char *
bcpi_serializer_get_string(bcpi_serializer *b)
{
	unsigned int len = bcpi_serializer_get_uint8(b);
	if (b->underflow) {
		return 0;
	}
	bcpi_serializer_check_get(b, len);
	if (b->underflow) {
		return 0;
	}
#ifdef BCPI_DEBUG_FORMAT
	// Skip magic
	b->read_cursor += 4;
#endif
	char *str = &b->data[b->read_cursor];
	str[len - 1] = 0;
	b->read_cursor += len;
	return str;
}

struct bcpi_object_info {
	uint64_t function_first_addr;
	uint64_t node_first_addr;
	uint8_t function_chain_bits;
	uint8_t function_size_bits;
	uint8_t node_chain_bits;
	uint8_t node_num_edge_bits;
	uint8_t counter_bits[BCPI_MAX_NUM_COUNTER];
};

#define BCPI_CLZ(_v) ((!(_v)) ? 64 : __builtin_clzl((_v)))
#define BCPI_LOG2(_v) (64 - BCPI_CLZ((_v)))
#define BCPI_CEIL_DIV(_v, _d) (((_v) + (_d)-1) / (_d))

int
bcpi_function_compare(const void *a, const void *b)
{
	bcpi_function *f1 = (bcpi_function *)a;
	bcpi_function *f2 = (bcpi_function *)b;

	if (f1->begin_address < f2->begin_address) {
		return -1;
	}

	if (f1->begin_address > f2->begin_address) {
		return 1;
	}

	return 0;
}

int
bcpi_node_compare(const void *a, const void *b)
{
	bcpi_node *n1 = (bcpi_node *)a;
	bcpi_node *n2 = (bcpi_node *)b;

	if (n1->node_address < n2->node_address) {
		return -1;
	}

	if (n1->node_address > n2->node_address) {
		return 1;
	}

	return 0;
}

#define BCPI_IS_EQUAL_FAIL(_v)                              \
	do {                                                \
		fprintf(stderr, "BCPI_IS_EQUAL: %s\n", _v); \
		abort();                     \
	} while (0)

#define BCPI_CHECK_EQUAL(_a, _b)                            \
	do {                                                \
		if ((_a) != (_b)) {                         \
			BCPI_IS_EQUAL_FAIL(#_a " != " #_b); \
		}                                \
	} while (0)

bool
bcpi_is_equal(const bcpi_record &a, const bcpi_record &b)
{
	BCPI_CHECK_EQUAL(a.epoch_end, b.epoch_end);
	if (a.system_name != b.system_name) {
		BCPI_IS_EQUAL_FAIL("system_name");
	}
	BCPI_CHECK_EQUAL(a.counters.size(), b.counters.size());
	for (unsigned int i = 0; i < a.counters.size(); ++i) {
		if (a.counters[i] != b.counters[i]) {
			BCPI_IS_EQUAL_FAIL("counters");
		}
	}

	BCPI_CHECK_EQUAL(a.objects.size(), b.objects.size());
	for (unsigned int i = 0; i < a.objects.size(); ++i) {
		const bcpi_object &roa = a.objects[i];
		const bcpi_object &rob = b.objects[i];

		BCPI_CHECK_EQUAL(roa.functions.size(), rob.functions.size());
		BCPI_CHECK_EQUAL(roa.nodes.size(), rob.nodes.size());
		BCPI_CHECK_EQUAL(roa.object_index, rob.object_index);

		if (roa.path != rob.path) {
			BCPI_IS_EQUAL_FAIL("path");
		}

		if (memcmp(&roa.hash, &rob.hash, sizeof(roa.hash))) {
			BCPI_IS_EQUAL_FAIL("hash");
		}

		for (unsigned int j = 0; j < roa.functions.size(); ++j) {
			const bcpi_function &fa = roa.functions[j];
			const bcpi_function &fb = roa.functions[j];

			BCPI_CHECK_EQUAL(fa.begin_address, fb.begin_address);
			BCPI_CHECK_EQUAL(fa.end_address, fb.end_address);

			if (fa.name != fb.name) {
				BCPI_IS_EQUAL_FAIL("function_name");
			}
		}

		for (unsigned int j = 0; j < roa.nodes.size(); ++j) {
			const bcpi_node &rna = roa.nodes[j];
			const bcpi_node &rnb = rob.nodes[j];

			BCPI_CHECK_EQUAL(rna.edges.size(), rnb.edges.size());
			BCPI_CHECK_EQUAL(rna.node_address, rnb.node_address);
			BCPI_CHECK_EQUAL(rna.node_index, rnb.node_index);

			for (unsigned int k = 0; k < a.counters.size(); ++k) {
				BCPI_CHECK_EQUAL(rna.terminal_counters[k],
				    rnb.terminal_counters[k]);
			}

			for (unsigned int k = 0; k < rna.edges.size(); ++k) {
				const bcpi_edge &rea = rna.edges[k];
				const bcpi_edge &reb = rnb.edges[k];

				BCPI_CHECK_EQUAL(rea.from->node_address,
				    rea.from->node_address);
				BCPI_CHECK_EQUAL(
				    rea.to->node_address, rea.to->node_address);

				for (unsigned int l = 0; l < a.counters.size();
				     ++l) {
					BCPI_CHECK_EQUAL(
					    rea.counters[l], reb.counters[l]);
				}
			}
		}
	}

	return true;
}

void
bcpi_save(const bcpi_record &record, char **buffer, int *size)
{
	bcpi_object_info *object_info =
	    new bcpi_object_info[record.objects.size()];

	size_t num_node_max = 0;
	int num_node = 0;
	int num_function = 0;
	int num_edge = 0;

	for (unsigned int i = 0; i < record.objects.size(); ++i) {
		const bcpi_object &object = record.objects[i];

		uint64_t function_chain_max = 0;
		uint64_t function_size_max = 0;

		uint64_t prev_function_end = 0;
		uint64_t function_first_addr, node_first_addr;

		num_function += object.functions.size();

		for (unsigned int j = 0; j < object.functions.size(); ++j) {
			const bcpi_function &function = object.functions[j];

			uint64_t function_size = function.end_address -
			    function.begin_address;
			function_size_max = std::max(
			    function_size, function_size_max);

			if (!j) {
				function_first_addr = function.begin_address;
			} else {
				uint64_t chain_next = function.begin_address -
				    prev_function_end;
				function_chain_max = std::max(
				    function_chain_max, chain_next);
			}

			prev_function_end = function.end_address;
		}

		uint64_t counter_maximum[BCPI_MAX_NUM_COUNTER] = { 0 };
		uint64_t node_chain_max = 0;
		uint64_t prev_node_addr = 0;
		size_t node_num_edge_max = 0;

		num_node_max = std::max(num_node_max, object.nodes.size());
		num_node += object.nodes.size();

		for (unsigned int j = 0; j < object.nodes.size(); ++j) {
			const bcpi_node &node = object.nodes[j];

			node_num_edge_max = std::max(
			    node_num_edge_max, node.edges.size());
			if (!j) {
				node_first_addr = node.node_address;
			} else {
				uint64_t chain_next = node.node_address -
				    prev_node_addr;
				node_chain_max = std::max(
				    node_chain_max, chain_next);
			}
			prev_node_addr = node.node_address;

			num_edge += node.edges.size();

			for (unsigned int k = 0; k < record.counters.size();
			     ++k) {
				counter_maximum[k] = std::max(
				    counter_maximum[k],
				    node.terminal_counters[k]);
			}

			for (unsigned int k = 0; k < node.edges.size(); ++k) {
				const bcpi_edge &edge = node.edges[k];

				for (unsigned int l = 0;
				     l < record.counters.size(); ++l) {
					counter_maximum[l] = std::max(
					    counter_maximum[l],
					    edge.counters[l]);
				}
			}
		}

		bcpi_object_info *oi = &object_info[i];
		oi->function_chain_bits = BCPI_LOG2(function_chain_max);
		oi->function_size_bits = BCPI_LOG2(function_size_max);
		oi->node_chain_bits = BCPI_LOG2(node_chain_max);
		oi->node_num_edge_bits = BCPI_LOG2(node_num_edge_max);
		oi->function_first_addr = function_first_addr;
		oi->node_first_addr = node_first_addr;

		for (unsigned int j = 0; j < record.counters.size(); ++j) {
			oi->counter_bits[j] = BCPI_LOG2(counter_maximum[j]);
		}
	}

	int object_id_bits = BCPI_LOG2(record.objects.size());
	int node_id_bits = BCPI_LOG2(num_node_max);

	bcpi_serializer _builder;
	bcpi_serializer *builder = &_builder;
	bcpi_serializer_init(builder);

	/*
	 * All strings are in Pascal-like format (1 byte of length including
	 * termating null followed by actual string with null terminator)
	 *
	 * The on disk structure is as follows:
	 *
	 * unix timestamp: 8 bytes
	 * name of system: variable length string
	 * number of counters recorded: 1 byte
	 * array of counter names: variable length strings one after the other
	 * number of bits for node ID: 1 byte
	 * number of objects: 3 bytes
	 * array of objects: (one after the other without gaps)
	 *      path to object: variable length string
	 *      hash of object (crc32): 4 bytes
	 *      number of functions: 3 bytes
	 *      number of nodes: 3 bytes
	 *      object info: see bcpi_object_info. it is
	 *          written to the stream as is, except last member counter_bits
	 *          where only the actual number of counters is written
	 *      array of functions:
	 *          currently unused
	 *      array of nodes: (one after the other without gaps)
	 *          offset of next node's address relative to current:
	 * node_chain_bits/8 bytes bit vector denoting non-zero counter values:
	 * num_counter/8 bytes array of counter values: (one after the other
	 * without gaps, containing n values where n is number of non-zero bits
	 * in the bit vector) each counter is represented as counter_bits[i]/8
	 * bytes number of edges: node_num_edge_bits/8 bytes array of edges:
	 * (one after the other without gaps) source object index:
	 * object_id_bits/8 bytes source node index in that object:
	 * node_id_bits/8 bytes bit vector denoting non-zero counter values:
	 * num_counter/8 bytes array of counter values: (one after the other
	 * without gaps, containing n values where n is number of non-zero bits
	 * in the bit vector) each counter is represented as counter_bits[i]/8
	 * bytes
	 *
	 * The whole stream is then compressed with libz
	 */

	bcpi_serializer_add_int64(builder, record.epoch_end);
	bcpi_serializer_add_string(builder, record.system_name);
	bcpi_serializer_add_int8(builder, record.counters.size());
	for (auto &c : record.counters) {
		bcpi_serializer_add_string(builder, c);
	}

	bcpi_serializer_add_int8(builder, node_id_bits);
	bcpi_serializer_add_int24(builder, record.objects.size());

	for (unsigned int i = 0; i < record.objects.size(); ++i) {
		const bcpi_object &ro = record.objects[i];
		bcpi_object_info *oi = &object_info[i];

#ifdef BCPI_DEBUG_FORMAT
		bcpi_serializer_add_int32(builder, 0x4f424a54);
#endif
		bcpi_serializer_add_string(builder, ro.path);
		bcpi_serializer_add_bytes(builder, &ro.hash, sizeof(ro.hash));
		bcpi_serializer_add_int24(builder, ro.functions.size());
		bcpi_serializer_add_int24(builder, ro.nodes.size());

		int counter_bytes = sizeof(*oi) - sizeof(oi->counter_bits) +
		    sizeof(oi->counter_bits[0]) * record.counters.size();
		bcpi_serializer_add_bytes(builder, oi, counter_bytes);

		for (unsigned int j = 0; j < ro.nodes.size(); ++j) {
			const bcpi_node &rn = ro.nodes[j];

			uint64_t next_node_value = 0;
			if (j < ro.nodes.size() - 1) {
				next_node_value = ro.nodes[j + 1].node_address -
				    rn.node_address;
			}

#ifdef BCPI_DEBUG_FORMAT
			bcpi_serializer_add_int32(builder, 0x4e4f4445);
#endif

			bcpi_serializer_add_bytes(builder, &next_node_value,
			    BCPI_CEIL_DIV(oi->node_chain_bits, 8));

			uint64_t counter_nz_flag = 0;
			for (unsigned int k = 0; k < record.counters.size();
			     ++k) {
				if (rn.terminal_counters[k]) {
					counter_nz_flag |= 1 << k;
				}
			}

			bcpi_serializer_add_bytes(builder, &counter_nz_flag,
			    BCPI_CEIL_DIV(record.counters.size(), 8));
			for (unsigned int k = 0; k < record.counters.size();
			     ++k) {
				if (rn.terminal_counters[k]) {
					bcpi_serializer_add_bytes(builder,
					    &rn.terminal_counters[k],
					    BCPI_CEIL_DIV(
						oi->counter_bits[k], 8));
				}
			}

			int edges = rn.edges.size();
			bcpi_serializer_add_bytes(builder, &edges,
			    BCPI_CEIL_DIV(oi->node_num_edge_bits, 8));

			for (unsigned int k = 0; k < rn.edges.size(); ++k) {
				const bcpi_edge &re = rn.edges[k];

#ifdef BCPI_DEBUG_FORMAT
				bcpi_serializer_add_int32(builder, 0x45444745);
#endif

				bcpi_serializer_add_bytes(builder,
				    &re.from->object->object_index,
				    BCPI_CEIL_DIV(object_id_bits, 8));
				bcpi_serializer_add_bytes(builder,
				    &re.from->node_index,
				    BCPI_CEIL_DIV(node_id_bits, 8));
				uint64_t counter_nz_flag = 0;
				for (unsigned int l = 0;
				     l < record.counters.size(); ++l) {
					if (re.counters[l]) {
						counter_nz_flag |= 1 << l;
					}
				}

				bcpi_serializer_add_bytes(builder,
				    &counter_nz_flag,
				    BCPI_CEIL_DIV(record.counters.size(), 8));
				for (unsigned int l = 0;
				     l < record.counters.size(); ++l) {
					if (re.counters[l]) {
						bcpi_serializer_add_bytes(
						    builder, &re.counters[l],
						    BCPI_CEIL_DIV(
							oi->counter_bits[l],
							8));
					}
				}
			}
		}
	}

	delete[] object_info;
	bcpi_archive_header header;
	int header_size = sizeof(header);

	uint32_t raw_data_size = bcpi_serializer_get_size(builder);

	uint64_t bound = compressBound(raw_data_size);
	char *compressed = (char *)malloc(bound + header_size);
	int status = compress((unsigned char *)compressed + header_size, &bound,
	    (unsigned char *)bcpi_serializer_get_data(builder),
	    (uint64_t)raw_data_size);
	assert(status == Z_OK);

	bcpi_serilizer_finish(builder);

	header.identifier = 'BCPI';
	header.size = raw_data_size;
	memcpy(compressed, &header, header_size);

	*buffer = compressed;
	*size = bound + header_size;
	fprintf(stderr,
	    "%lu/%d/%d/%d object/function/node/edge processed, "
	    "%ld (%d) bytes\n",
	    record.objects.size(), num_function, num_node, num_edge, bound,
	    raw_data_size);
}

int
bcpi_load(char *compressed_buffer, int size, bcpi_record *record)
{
	bcpi_archive_header *header = (bcpi_archive_header *)compressed_buffer;
	int header_size = sizeof(bcpi_archive_header);

	uint64_t raw_size = header->size;
	char *buffer = (char *)malloc(raw_size);
	int status = uncompress((unsigned char *)buffer, &raw_size,
	    (unsigned char *)compressed_buffer + header_size,
	    size - header_size);
	assert(status == Z_OK);

	bcpi_serializer _reader;
	bcpi_serializer *reader = &_reader;
	bcpi_serializer_init_read(reader, buffer, raw_size);

	record->epoch_end = bcpi_serializer_get_int64(reader);
	record->system_name = bcpi_serializer_get_string(reader);
	int num_counter = bcpi_serializer_get_int8(reader);
	for (int i = 0; i < num_counter; ++i) {
		record->counters.push_back(bcpi_serializer_get_string(reader));
	}

	int node_id_bits = bcpi_serializer_get_int8(reader);
	int num_object = bcpi_serializer_get_int24(reader);
	int object_id_bits = BCPI_LOG2(num_object);

	record->objects.resize(num_object);
	for (int i = 0; i < num_object; ++i) {
		bcpi_object &ro = record->objects[i];
		ro.internal = 0;
		ro.object_index = i;

		bcpi_object_info _oi, *oi = &_oi;

#ifdef BCPI_DEBUG_FORMAT
		assert(bcpi_serializer_get_int32(reader) == 0x4f424a54);
#endif

		ro.path = bcpi_serializer_get_string(reader);
		bcpi_serializer_get_bytes(reader, &ro.hash, sizeof(ro.hash));
		bcpi_serializer_get_int24(reader); // XXX: Compatibility
		int num_node = bcpi_serializer_get_int24(reader);

		int counter_bytes = sizeof(*oi) - sizeof(oi->counter_bits) +
		    sizeof(oi->counter_bits[0]) * num_counter;
		bcpi_serializer_get_bytes(reader, oi, counter_bytes);

		ro.nodes.resize(num_node);

		for (int j = 0; j < num_node; ++j) {
			bcpi_node &rn = ro.nodes[j];
			rn.internal = 0;
			rn.node_index = j;
			rn.object = &ro;

#ifdef BCPI_DEBUG_FORMAT
			assert(bcpi_serializer_get_int32(reader) == 0x4e4f4445);
#endif

			if (!j) {
				rn.node_address = oi->node_first_addr;
			}
			uint64_t node_addr = 0;
			bcpi_serializer_get_bytes(reader, &node_addr,
			    BCPI_CEIL_DIV(oi->node_chain_bits, 8));
			if (j < num_node - 1) {
				ro.nodes[j + 1].node_address = rn.node_address +
				    node_addr;
			}

			uint64_t counter_nz_flag = 0;
			bcpi_serializer_get_bytes(reader, &counter_nz_flag,
			    BCPI_CEIL_DIV(num_counter, 8));
			for (int k = 0; k < num_counter; ++k) {
				rn.terminal_counters[k] = 0;
				if (counter_nz_flag & 1) {
					bcpi_serializer_get_bytes(reader,
					    &rn.terminal_counters[k],
					    BCPI_CEIL_DIV(
						oi->counter_bits[k], 8));
				}
				counter_nz_flag = counter_nz_flag >> 1;
			}

			int num_edge = 0;
			bcpi_serializer_get_bytes(reader, &num_edge,
			    BCPI_CEIL_DIV(oi->node_num_edge_bits, 8));

			rn.edges.resize(num_edge);
			for (int k = 0; k < num_edge; ++k) {
				bcpi_edge &re = rn.edges[k];
				re.internal = 0;
				int object_index = 0;
				int node_index = 0;

#ifdef BCPI_DEBUG_FORMAT
				assert(bcpi_serializer_get_int32(reader) ==
				    0x45444745);
#endif

				bcpi_serializer_get_bytes(reader, &object_index,
				    BCPI_CEIL_DIV(object_id_bits, 8));
				bcpi_serializer_get_bytes(reader, &node_index,
				    BCPI_CEIL_DIV(node_id_bits, 8));

				re.from = (bcpi_node *)(uint64_t)object_index;
				re.to = (bcpi_node *)(uint64_t)node_index;

				uint64_t counter_nz_flag = 0;
				bcpi_serializer_get_bytes(reader,
				    &counter_nz_flag,
				    BCPI_CEIL_DIV(num_counter, 8));
				for (int l = 0; l < num_counter; ++l) {
					re.counters[l] = 0;
					if (counter_nz_flag & 1) {
						bcpi_serializer_get_bytes(
						    reader, &re.counters[l],
						    BCPI_CEIL_DIV(
							oi->counter_bits[l],
							8));
					}
					counter_nz_flag = counter_nz_flag >> 1;
				}
			}
		}
	}

	for (unsigned int i = 0; i < record->objects.size(); ++i) {
		bcpi_object &ro = record->objects[i];
		for (unsigned int j = 0; j < ro.nodes.size(); ++j) {
			bcpi_node &rn = ro.nodes[j];
			for (unsigned int k = 0; k < rn.edges.size(); ++k) {
				bcpi_edge &re = rn.edges[k];
				int object_index = (uint64_t)re.from;
				int node_index = (uint64_t)re.to;

				re.to = &rn;
				re.from = &record->objects[object_index]
					       .nodes[node_index];
			}
		}
	}

	free(buffer);

	return 0;
}

int
bcpi_save_file(const bcpi_record &r, const char *f)
{
	char *data;
	int size;
	int ret = -1;

	bcpi_save(r, &data, &size);

	FILE *file = fopen(f, "wb");
	if (!file) {
		perror("fopen");
		return -1;
	}

	int status = fwrite(data, size, 1, file);
	free(data);

	if (status <= 0) {
		perror("fwrite");
	}

	status = fclose(file);
	if (status) {
		perror("fclose");
	} else {
		ret = 0;
	}

	return ret;
}

int
bcpi_load_file(const char *f, bcpi_record *r)
{
	FILE *file = fopen(f, "rb");
	int ret = -1;
	if (!file) {
		perror("fopen");
		return -1;
	}

	fseek(file, 0, SEEK_END);
	uint64_t size = ftell(file);
	fseek(file, 0, SEEK_SET);

	char *data = (char *)malloc(size);
	int status = fread(data, size, 1, file);
	if (status <= 0) {
		perror("fread");
	}

	if (bcpi_load(data, size, r) < 0) {
		free(data);
		fclose(file);
		return -1;
	}
	free(data);

	status = fclose(file);
	if (status) {
		perror("fclose");
	} else {
		ret = 0;
	}

	return ret;
}

int
bcpi_merge(bcpi_record **out __unused, const bcpi_record **list __unused,
    int num __unused)
{
	return 0;
}

int
bcpi_get_index_from_name(const bcpi_record &record, const std::string &name)
{
	for (unsigned int i = 0; i < record.counters.size(); ++i) {
		if (record.counters[i] == name) {
			return i;
		}
	}
	return -1;
}

int g_bcpi_sort_index;

bool
bcpi_node_sort_function(const bcpi_node *a, const bcpi_node *b)
{
	return a->terminal_counters[g_bcpi_sort_index] >
	    b->terminal_counters[g_bcpi_sort_index];
}

bool
bcpi_node_sort_addr_function(const bcpi_node *a, const bcpi_node *b)
{
	return a->node_address < b->node_address;
}

bool
bcpi_edge_sort_function(const bcpi_edge *a, const bcpi_edge *b)
{
	return a->counters[g_bcpi_sort_index] > b->counters[g_bcpi_sort_index];
}

void
bcpi_collect_node(bcpi_record *record, std::vector<bcpi_node *> &node_out)
{
	for (unsigned int i = 0; i < record->objects.size(); ++i) {
		bcpi_object &ro = record->objects[i];

		for (unsigned int j = 0; j < ro.nodes.size(); ++j) {
			bcpi_node &rn = ro.nodes[j];

			node_out.emplace_back(&rn);
		}
	}
}

void
bcpi_collect_object(bcpi_record *record, std::vector<bcpi_object *> &object_out,
    const char *name)
{
	for (unsigned int i = 0; i < record->objects.size(); ++i) {
		bcpi_object &ro = record->objects[i];
		if (ro.path.find(name) != std::string::npos) {
			object_out.emplace_back(&ro);
		}
	}
}

void
bcpi_collect_node_from_object(bcpi_record *record __unused,
    std::vector<bcpi_node *> &node_out, bcpi_object *ro)
{
	for (unsigned int i = 0; i < ro->nodes.size(); ++i) {
		bcpi_node &rn = ro->nodes[i];
		node_out.push_back(&rn);
	}
}

void
bcpi_collect_edge(bcpi_node *n, std::vector<bcpi_edge *> &edge_out)
{
	for (unsigned int i = 0; i < n->edges.size(); ++i) {
		edge_out.emplace_back(&n->edges[i]);
	}
}

void
bcpi_node_sort(int index, std::vector<bcpi_node *> &sorted_nodes)
{
	g_bcpi_sort_index = index;
	sort(sorted_nodes.begin(), sorted_nodes.end(), bcpi_node_sort_function);
}

void
bcpi_node_sort(std::vector<bcpi_node *> &sorted_nodes)
{
	sort(sorted_nodes.begin(), sorted_nodes.end(),
	    bcpi_node_sort_addr_function);
}

void
bcpi_edge_sort(int index, std::vector<bcpi_edge *> &sorted_edges)
{
	g_bcpi_sort_index = index;
	sort(sorted_edges.begin(), sorted_edges.end(), bcpi_edge_sort_function);
}

void
bcpi_print_summary(const bcpi_record &r)
{
	time_t tend = r.epoch_end;
	struct tm *t = gmtime(&tend);
	char time_buffer[128];

	strftime(time_buffer, 127, "%c", t);
	printf("%s\n", time_buffer);
	printf("%s\n", r.system_name.c_str());
	printf("%lu counters\n", r.counters.size());
	for (unsigned int i = 0; i < r.counters.size(); ++i) {
		printf(" %d: %s\n", i + 1, r.counters[i].c_str());
	}
	printf("%lu objects\n", r.objects.size());
	for (unsigned int i = 0; i < r.objects.size(); i++) {
		const bcpi_object &o = r.objects[i];
		printf(" %3d: %5lu nodes, %8x, %s\n", i + 1, o.nodes.size(),
		    o.hash, o.path.c_str());
	}
}

void
bcpi_dump_edges(const bcpi_record &record, const bcpi_node &node)
{
	for (auto &e : node.edges) {
		printf("        Edge from %08lx", e.from->node_address);
		for (unsigned int c = 0; c < record.counters.size(); c++) {
			printf(" %8ld", e.counters[c]);
		}
		printf("\n");
	}
}

void
bcpi_dump_nodes(const bcpi_record &record)
{
	for (auto &o : record.objects) {
		printf(
		    "Object ID %d Path %s\n", o.object_index, o.path.c_str());

		for (auto &n : o.nodes) {
			printf("    Address %08lx", n.node_address);
			for (unsigned int k = 0; k < record.counters.size();
			     k++) {
				printf(" %8ld", n.terminal_counters[k]);
			}
			printf("\n");
			bcpi_dump_edges(record, n);
		}
	}
}

void
bcpi_show_node_info(bcpi_record *r, bcpi_node *n, const char *sort_crit)
{
	printf("\nNode ID %d in object ID %d\n", n->node_index,
	    (n->object->object_index) + 1);
	printf("Address %lx in %s\n", n->node_address, n->object->path.c_str());
	printf(" Counter hits (as terminal node):\n");
	for (unsigned int i = 0; i < r->counters.size(); ++i) {
		printf(" %8ld", n->terminal_counters[i]);
	}
	printf("\n");

	std::vector<bcpi_edge *> edges;
	bcpi_collect_edge(n, edges);
	if (sort_crit) {
		int index = bcpi_get_index_from_name(*r, sort_crit);
		g_bcpi_sort_index = index;

		sort(edges.begin(), edges.end(), bcpi_edge_sort_function);
	}

	// printf(" Callchain reaching this node (exclude above):\n");
	// int edge_size = edges.size();
	// for (unsigned int i = 0; i < edge_size; ++i) {
	//    bcpi_edge *e = edges[i];
	//    printf(" %lx in %s\n", e->from->node_address,
	//    e->from->object->path); for (unsigned int j = 0; j <
	//    r->num_counter; ++j) {
	//        printf(" %8ld", e->counters[j]);
	//    }
	//    printf("\n");
	//}
}

std::vector<bcpi_node *>
hash2vec(std::unordered_map<uint64_t, bcpi_node *> umap)
{
	std::unordered_map<uint64_t, bcpi_node *>::iterator itr;
	std::vector<bcpi_node *> new_nodes;
	for (itr = umap.begin(); itr != umap.end(); itr++) {
		new_nodes.push_back(itr->second);
		// cout << hex<<itr->first << "  " <<
		// dec<<itr->second->terminal_counters[0] << endl;
	}
	return new_nodes;
}

std::vector<bcpi_node *>
vec2hash_merge_nodes(std::vector<bcpi_node *> nodes)
{
	std::unordered_map<uint64_t, bcpi_node *> umap;

	for (unsigned int i = 0; i < nodes.size(); i++) {
		if (umap.find(nodes[i]->node_address) == umap.end()) {
			umap.emplace(nodes[i]->node_address, nodes[i]);
		} else {
			for (unsigned int c = 0; c < BCPI_MAX_NUM_COUNTER;
			     c++) {
				umap[nodes[i]->node_address]
				    ->terminal_counters[c] +=
				    nodes[i]->terminal_counters[c];
			}
		}
	}

	return hash2vec(umap);
}

std::vector<bcpi_node *>
vec2hash_merge_nodes(int index, std::vector<bcpi_node *> nodes)
{
	std::unordered_map<uint64_t, bcpi_node *> umap;
	for (unsigned int i = 0; i < nodes.size(); i++) {
		if (umap.find(nodes[i]->node_address) == umap.end())
			umap.emplace(nodes[i]->node_address, nodes[i]);
		else
			umap[nodes[i]->node_address]
			    ->terminal_counters[index] +=
			    nodes[i]->terminal_counters[index];
	}
	return hash2vec(umap);
}
