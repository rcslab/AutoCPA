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
#include <unordered_map>
#include <vector>

#include "libbcpi.h"

struct bcpi_serializer {
	int max_size;
	int size;
	int read_cursor;
	int overflow : 1;
	int underflow : 1;
	int read_mode : 1;
	char *data;
};

#define BCPI_SERIALIZER_FIRST_SIZE 32

/*
 * Initialize structure for in memory arbitrary data writing.
 * Allocate space.
 */

void
bcpi_serializer_init(struct bcpi_serializer *b)
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
bcpi_serilizer_finish(struct bcpi_serializer *b)
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
bcpi_serializer_init_read(struct bcpi_serializer *b, char *data, int size)
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
bcpi_serializer_set_size(struct bcpi_serializer *b, int size)
{
	b->size = size;
}

int
bcpi_serializer_get_size(struct bcpi_serializer *b)
{
	return b->size;
}

void *
bcpi_serializer_get_write_cursor(struct bcpi_serializer *b)
{
	return &b->data[b->size];
}

void *
bcpi_serializer_get_read_cursor(struct bcpi_serializer *b)
{
	return &b->data[b->read_cursor];
}

void *
bcpi_serializer_get_data(struct bcpi_serializer *b)
{
	return b->data;
}

/*
 * Check, and possibilly allocate space so that item_size bytes of data could be
 * written. Update interval state overflow if allocation failed.
 */
void
bcpi_serializer_check_add(struct bcpi_serializer *b, int item_size)
{
	if (b->overflow) {
		return;
	}
	int new_size = b->size + item_size;
	if (new_size > b->max_size) {
		int new_max_size = b->max_size * 2;
		char *new_data = (char *)realloc(b->data, new_max_size);
		if (!new_data) {
			b->overflow = true;
		} else {
			b->data = new_data;
			b->max_size = new_max_size;
		}
		return;
	}
}

/*
 * Check if item_size bytes of data are available for reading.
 * Sets internal flag underflow if failed.
 *
 */
void
bcpi_serializer_check_get(struct bcpi_serializer *b, int item_size)
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
bcpi_serializer_add_bytes(struct bcpi_serializer *b, const void *data, int size)
{
	bcpi_serializer_check_add(b, size);
	if (b->overflow) {
		return;
	}
	memcpy(&b->data[b->size], data, size);
	b->size += size;
}

void
bcpi_serializer_get_bytes(struct bcpi_serializer *b, void *data, int size)
{
	bcpi_serializer_check_get(b, size);
	if (b->underflow) {
		return;
	}
	memcpy(data, &b->data[b->read_cursor], size);
	b->read_cursor += size;
}

void
bcpi_serializer_add_uint64(struct bcpi_serializer *b, uint64_t i)
{
	bcpi_serializer_add_bytes(b, &i, sizeof(i));
}

void
bcpi_serializer_add_int64(struct bcpi_serializer *b, int64_t i)
{
	bcpi_serializer_add_bytes(b, &i, sizeof(i));
}

void
bcpi_serializer_add_int32(struct bcpi_serializer *b, int32_t i)
{
	bcpi_serializer_add_bytes(b, &i, sizeof(i));
}

void
bcpi_serializer_add_int24(struct bcpi_serializer *b, int32_t i)
{
	bcpi_serializer_add_bytes(b, &i, 3);
}

void
bcpi_serializer_add_int8(struct bcpi_serializer *b, int8_t i)
{
	int item_size = sizeof(i);
	bcpi_serializer_check_add(b, item_size);
	if (b->overflow) {
		return;
	}
	b->data[b->size++] = i;
}

void
bcpi_serializer_add_uint8(struct bcpi_serializer *b, uint8_t i)
{
	int item_size = sizeof(i);
	bcpi_serializer_check_add(b, item_size);
	if (b->overflow) {
		return;
	}
	b->data[b->size++] = i;
}

int8_t
bcpi_serializer_get_int8(struct bcpi_serializer *b)
{
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
bcpi_serializer_get_uint8(struct bcpi_serializer *b)
{
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
bcpi_serializer_get_int64(struct bcpi_serializer *b)
{
	int64_t r = 0;
	bcpi_serializer_get_bytes(b, &r, sizeof(r));
	return r;
}

int32_t
bcpi_serializer_get_int32(struct bcpi_serializer *b)
{
	int32_t r = 0;
	bcpi_serializer_get_bytes(b, &r, sizeof(r));
	return r;
}

int32_t
bcpi_serializer_get_int24(struct bcpi_serializer *b)
{
	int32_t r = 0;
	bcpi_serializer_get_bytes(b, &r, 3);
	return r;
}

void
bcpi_serializer_add_string(struct bcpi_serializer *b, const char *str)
{
	int len = strlen(str) + 1;
	bcpi_serializer_check_add(b, len + sizeof(len));
	if (b->overflow) {
		return;
	}
	assert(len <= 256);
	bcpi_serializer_add_uint8(b, len);
	bcpi_serializer_add_bytes(b, str, len);
}

/*
 * Get pointer to next string in the stream. Note that
 * string needs to be copied if used for extended amount of time.
 */

char *
bcpi_serializer_get_string(struct bcpi_serializer *b)
{
	unsigned int len = bcpi_serializer_get_uint8(b);
	if (b->underflow) {
		return 0;
	}
	bcpi_serializer_check_get(b, len);
	if (b->underflow) {
		return 0;
	}
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

#define BCPI_CLZ(_v) (!(_v) ? sizeof(_v) * 8 : __builtin_clz(_v))
#define BCPI_LOG2(_v) (sizeof(_v) * 8 - BCPI_CLZ(_v))
#define BCPI_CEIL_DIV(_v, _d) (((_v) + (_d)-1) / (_d))

int
bcpi_function_compare(const void *a, const void *b)
{
	struct bcpi_function *f1 = (struct bcpi_function *)a;
	struct bcpi_function *f2 = (struct bcpi_function *)b;

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
	struct bcpi_node *n1 = (struct bcpi_node *)a;
	struct bcpi_node *n2 = (struct bcpi_node *)b;

	if (n1->node_address < n2->node_address) {
		return -1;
	}

	if (n1->node_address > n2->node_address) {
		return 1;
	}

	return 0;
}

#define BCPI_IS_EQUAL_FAIL(_v)               \
	do {                                 \
		fprintf(stderr, "%s\n", _v); \
		abort();                     \
	} while (0)

//#define BCPI_IS_EQUAL_FAIL(_v) return false

#define BCPI_CHECK_EQUAL(_a, _b)                 \
	do {                                     \
		if ((_a) != (_b)) {              \
			BCPI_IS_EQUAL_FAIL(#_a); \
		}                                \
	} while (0)

bool
bcpi_is_equal(struct bcpi_record *a, struct bcpi_record *b)
{
	BCPI_CHECK_EQUAL(a->epoch, b->epoch);
	if (strcmp(a->system_name, b->system_name)) {
		BCPI_IS_EQUAL_FAIL("system_name");
	}
	BCPI_CHECK_EQUAL(a->num_counter, b->num_counter);
	for (int i = 0; i < a->num_counter; ++i) {
		if (strcmp(a->counter_name[i], b->counter_name[i])) {
			BCPI_IS_EQUAL_FAIL("counter_name");
		}
	}

	BCPI_CHECK_EQUAL(a->num_object, b->num_object);
	for (int i = 0; i < a->num_object; ++i) {
		struct bcpi_object *roa = &a->object_list[i];
		struct bcpi_object *rob = &b->object_list[i];

		BCPI_CHECK_EQUAL(roa->num_function, rob->num_function);
		BCPI_CHECK_EQUAL(roa->num_node, rob->num_node);
		BCPI_CHECK_EQUAL(roa->object_index, rob->object_index);

		if (strcmp(roa->path, rob->path)) {
			BCPI_IS_EQUAL_FAIL("path");
		}

		if (memcmp(&roa->hash, &rob->hash, sizeof(roa->hash))) {
			BCPI_IS_EQUAL_FAIL("hash");
		}

		for (int j = 0; j < roa->num_function; ++j) {
			struct bcpi_function *fa = &roa->function_list[j];
			struct bcpi_function *fb = &roa->function_list[j];

			BCPI_CHECK_EQUAL(fa->begin_address, fb->begin_address);
			BCPI_CHECK_EQUAL(fa->end_address, fb->end_address);

			if (strcmp(fa->name, fb->name)) {
				BCPI_IS_EQUAL_FAIL("function_name");
			}
		}

		for (int j = 0; j < roa->num_node; ++j) {
			struct bcpi_node *rna = &roa->node_list[j];
			struct bcpi_node *rnb = &rob->node_list[j];

			BCPI_CHECK_EQUAL(
			    rna->num_incoming_edge, rnb->num_incoming_edge);
			BCPI_CHECK_EQUAL(rna->node_address, rnb->node_address);
			BCPI_CHECK_EQUAL(rna->node_index, rnb->node_index);

			for (int k = 0; k < a->num_counter; ++k) {
				BCPI_CHECK_EQUAL(rna->terminal_counters[k],
				    rnb->terminal_counters[k]);
			}

			for (int k = 0; k < rna->num_incoming_edge; ++k) {
				struct bcpi_edge *rea = &rna->edge_list[k];
				struct bcpi_edge *reb = &rnb->edge_list[k];

				BCPI_CHECK_EQUAL(rea->from->node_address,
				    rea->from->node_address);
				BCPI_CHECK_EQUAL(rea->to->node_address,
				    rea->to->node_address);

				for (int l = 0; l < a->num_counter; ++l) {
					BCPI_CHECK_EQUAL(
					    rea->counters[l], reb->counters[l]);
				}
			}
		}
	}

	return true;
}

void
bcpi_free(struct bcpi_record *record)
{
	free((void *)record->system_name);

	for (int i = 0; i < record->num_counter; ++i) {
		free((void *)record->counter_name[i]);
	}
	free(record->counter_name);

	for (int i = 0; i < record->num_object; ++i) {
		struct bcpi_object *ro = &record->object_list[i];
		free((void *)ro->path);

		for (int j = 0; j < ro->num_function; ++j) {
			struct bcpi_function *function = &ro->function_list[j];
			free((void *)function->name);
		}

		free(ro->function_list);

		for (int j = 0; j < ro->num_node; ++j) {
			struct bcpi_node *rn = &ro->node_list[j];

			free(rn->edge_list);
		}

		free(ro->node_list);
	}

	free(record->object_list);

	free(record);
}

void
bcpi_save(const struct bcpi_record *record, char **buffer, int *size)
{
	struct bcpi_object_info *object_info = (struct bcpi_object_info *)
	    malloc(sizeof(*object_info) * record->num_object);

	int num_node_max = 0;
	int num_node = 0;
	int num_function = 0;
	int num_edge = 0;

	for (int i = 0; i < record->num_object; ++i) {
		struct bcpi_object *object = &record->object_list[i];

		uint64_t function_chain_max = 0;
		uint64_t function_size_max = 0;

		uint64_t prev_function_end = 0;
		uint64_t function_first_addr, node_first_addr;

		num_function += object->num_function;

		for (int j = 0; j < object->num_function; ++j) {
			struct bcpi_function *function =
			    &object->function_list[j];

			uint64_t function_size = function->end_address -
			    function->begin_address;
			function_size_max = std::max(
			    function_size, function_size_max);

			if (!j) {
				function_first_addr = function->begin_address;
			} else {
				uint64_t chain_next = function->begin_address -
				    prev_function_end;
				function_chain_max = std::max(
				    function_chain_max, chain_next);
			}

			prev_function_end = function->end_address;
		}

		uint64_t counter_maximum[BCPI_MAX_NUM_COUNTER] = { 0 };
		uint64_t node_chain_max = 0;
		uint64_t prev_node_addr = 0;
		int node_num_edge_max = 0;

		num_node_max = std::max(num_node_max, object->num_node);
		num_node += object->num_node;

		for (int j = 0; j < object->num_node; ++j) {
			struct bcpi_node *node = &object->node_list[j];

			node_num_edge_max = std::max(
			    node_num_edge_max, node->num_incoming_edge);
			if (!j) {
				node_first_addr = node->node_address;
			} else {
				uint64_t chain_next = node->node_address -
				    prev_node_addr;
				node_chain_max = std::max(
				    node_chain_max, chain_next);
			}
			prev_node_addr = node->node_address;

			num_edge += node->num_incoming_edge;

			for (int k = 0; k < record->num_counter; ++k) {
				counter_maximum[k] = std::max(
				    counter_maximum[k],
				    node->terminal_counters[k]);
			}

			for (int k = 0; k < node->num_incoming_edge; ++k) {
				struct bcpi_edge *edge = &node->edge_list[k];

				for (int l = 0; l < record->num_counter; ++l) {
					counter_maximum[l] = std::max(
					    counter_maximum[l],
					    edge->counters[l]);
				}
			}
		}

		struct bcpi_object_info *oi = &object_info[i];
		oi->function_chain_bits = BCPI_LOG2(function_chain_max);
		oi->function_size_bits = BCPI_LOG2(function_size_max);
		oi->node_chain_bits = BCPI_LOG2(node_chain_max);
		oi->node_num_edge_bits = BCPI_LOG2(node_num_edge_max);
		oi->function_first_addr = function_first_addr;
		oi->node_first_addr = node_first_addr;

		for (int j = 0; j < record->num_counter; ++j) {
			oi->counter_bits[j] = BCPI_LOG2(counter_maximum[j]);
		}
	}

	int object_id_bits = BCPI_LOG2(record->num_object);
	int node_id_bits = BCPI_LOG2(num_node_max);

	struct bcpi_serializer _builder;
	struct bcpi_serializer *builder = &_builder;
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
	 *      object info: see struct bcpi_object_info. it is
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

	bcpi_serializer_add_int64(builder, record->epoch);
	bcpi_serializer_add_string(builder, record->system_name);
	bcpi_serializer_add_int8(builder, record->num_counter);
	for (int i = 0; i < record->num_counter; ++i) {
		bcpi_serializer_add_string(builder, record->counter_name[i]);
	}

	bcpi_serializer_add_int8(builder, node_id_bits);
	bcpi_serializer_add_int24(builder, record->num_object);
	for (int i = 0; i < record->num_object; ++i) {
		struct bcpi_object *ro = &record->object_list[i];
		struct bcpi_object_info *oi = &object_info[i];
		bcpi_serializer_add_string(builder, ro->path);
		bcpi_serializer_add_bytes(builder, &ro->hash, sizeof(ro->hash));
		bcpi_serializer_add_int24(builder, ro->num_function);
		bcpi_serializer_add_int24(builder, ro->num_node);

		int counter_bytes = sizeof(*oi) - sizeof(oi->counter_bits) +
		    sizeof(oi->counter_bits[0]) * record->num_counter;
		bcpi_serializer_add_bytes(builder, oi, counter_bytes);

		for (int j = 0; j < ro->num_node; ++j) {
			struct bcpi_node *rn = &ro->node_list[j];

			uint64_t next_node_value = 0;
			if (j < ro->num_node - 1) {
				next_node_value =
				    ro->node_list[j + 1].node_address -
				    rn->node_address;
			}
			bcpi_serializer_add_bytes(builder, &next_node_value,
			    BCPI_CEIL_DIV(oi->node_chain_bits, 8));

			uint64_t counter_nz_flag = 0;
			for (int k = 0; k < record->num_counter; ++k) {
				if (rn->terminal_counters[k]) {
					counter_nz_flag |= 1 << k;
				}
			}

			bcpi_serializer_add_bytes(builder, &counter_nz_flag,
			    BCPI_CEIL_DIV(record->num_counter, 8));
			for (int k = 0; k < record->num_counter; ++k) {
				if (rn->terminal_counters[k]) {
					bcpi_serializer_add_bytes(builder,
					    &rn->terminal_counters[k],
					    BCPI_CEIL_DIV(
						oi->counter_bits[k], 8));
				}
			}

			bcpi_serializer_add_bytes(builder,
			    &rn->num_incoming_edge,
			    BCPI_CEIL_DIV(oi->node_num_edge_bits, 8));

			for (int k = 0; k < rn->num_incoming_edge; ++k) {
				struct bcpi_edge *re = &rn->edge_list[k];
				bcpi_serializer_add_bytes(builder,
				    &re->from->object->object_index,
				    BCPI_CEIL_DIV(object_id_bits, 8));
				bcpi_serializer_add_bytes(builder,
				    &re->from->node_index,
				    BCPI_CEIL_DIV(node_id_bits, 8));
				uint64_t counter_nz_flag = 0;
				for (int l = 0; l < record->num_counter; ++l) {
					if (re->counters[l]) {
						counter_nz_flag |= 1 << l;
					}
				}

				bcpi_serializer_add_bytes(builder,
				    &counter_nz_flag,
				    BCPI_CEIL_DIV(record->num_counter, 8));
				for (int l = 0; l < record->num_counter; ++l) {
					if (re->counters[l]) {
						bcpi_serializer_add_bytes(
						    builder, &re->counters[l],
						    BCPI_CEIL_DIV(
							oi->counter_bits[l],
							8));
					}
				}
			}
		}
	}

	free(object_info);
	struct bcpi_archive_header header;
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
	    "%d/%d/%d/%d object/function/node/edge processed, "
	    "%ld (%d) bytes\n",
	    record->num_object, num_function, num_node, num_edge, bound,
	    raw_data_size);
}

void
bcpi_load(char *compressed_buffer, int size, struct bcpi_record **r)
{
	struct bcpi_archive_header *header = (struct bcpi_archive_header *)
	    compressed_buffer;
	int header_size = sizeof(struct bcpi_archive_header);

	uint64_t raw_size = header->size;
	char *buffer = (char *)malloc(raw_size);
	int status = uncompress((unsigned char *)buffer, &raw_size,
	    (unsigned char *)compressed_buffer + header_size,
	    size - header_size);
	assert(status == Z_OK);

	struct bcpi_serializer _reader;
	struct bcpi_serializer *reader = &_reader;
	bcpi_serializer_init_read(reader, buffer, raw_size);

	struct bcpi_record *record = (struct bcpi_record *)malloc(
	    sizeof(*record));
	record->epoch = bcpi_serializer_get_int64(reader);

	const char *system_name = bcpi_serializer_get_string(reader);
	record->system_name = strdup(system_name);
	record->num_counter = bcpi_serializer_get_int8(reader);
	record->counter_name = (const char **)malloc(
	    sizeof(*record->counter_name) * record->num_counter);
	for (int i = 0; i < record->num_counter; ++i) {
		record->counter_name[i] = strdup(
		    bcpi_serializer_get_string(reader));
	}

	int node_id_bits = bcpi_serializer_get_int8(reader);
	record->num_object = bcpi_serializer_get_int24(reader);
	int object_id_bits = BCPI_LOG2(record->num_object);
	record->object_list = (struct bcpi_object *)malloc(
	    sizeof(*record->object_list) * record->num_object);
	for (int i = 0; i < record->num_object; ++i) {
		struct bcpi_object *ro = &record->object_list[i];
		ro->internal = 0;
		ro->object_index = i;

		struct bcpi_object_info _oi, *oi = &_oi;

		ro->path = strdup(bcpi_serializer_get_string(reader));
		bcpi_serializer_get_bytes(reader, &ro->hash, sizeof(ro->hash));
		ro->num_function = bcpi_serializer_get_int24(reader);
		ro->num_node = bcpi_serializer_get_int24(reader);

		int counter_bytes = sizeof(*oi) - sizeof(oi->counter_bits) +
		    sizeof(oi->counter_bits[0]) * record->num_counter;
		bcpi_serializer_get_bytes(reader, oi, counter_bytes);

		if (!ro->num_function) {
			ro->function_list = 0;
		} else {
			ro->function_list = (struct bcpi_function *)malloc(
			    sizeof(*ro->function_list) * ro->num_function);
		}

		ro->node_list = (struct bcpi_node *)malloc(
		    sizeof(*ro->node_list) * ro->num_node);

		for (int j = 0; j < ro->num_node; ++j) {
			struct bcpi_node *rn = &ro->node_list[j];
			rn->internal = 0;
			rn->node_index = j;
			rn->object = ro;

			if (!j) {
				rn->node_address = oi->node_first_addr;
			}
			uint64_t node_addr = 0;
			bcpi_serializer_get_bytes(reader, &node_addr,
			    BCPI_CEIL_DIV(oi->node_chain_bits, 8));
			if (j < ro->num_node - 1) {
				ro->node_list[j + 1].node_address =
				    rn->node_address + node_addr;
			}

			uint64_t counter_nz_flag = 0;
			bcpi_serializer_get_bytes(reader, &counter_nz_flag,
			    BCPI_CEIL_DIV(record->num_counter, 8));
			for (int k = 0; k < record->num_counter; ++k) {
				rn->terminal_counters[k] = 0;
				if (counter_nz_flag & 1) {
					bcpi_serializer_get_bytes(reader,
					    &rn->terminal_counters[k],
					    BCPI_CEIL_DIV(
						oi->counter_bits[k], 8));
				}
				counter_nz_flag = counter_nz_flag >> 1;
			}

			int num_edge = 0;
			bcpi_serializer_get_bytes(reader, &num_edge,
			    BCPI_CEIL_DIV(oi->node_num_edge_bits, 8));
			rn->num_incoming_edge = num_edge;
			rn->edge_list = (struct bcpi_edge *)malloc(
			    sizeof(*rn->edge_list) * rn->num_incoming_edge);
			for (int k = 0; k < rn->num_incoming_edge; ++k) {
				struct bcpi_edge *re = &rn->edge_list[k];
				re->internal = 0;
				int object_index = 0;
				int node_index = 0;

				bcpi_serializer_get_bytes(reader, &object_index,
				    BCPI_CEIL_DIV(object_id_bits, 8));
				bcpi_serializer_get_bytes(reader, &node_index,
				    BCPI_CEIL_DIV(node_id_bits, 8));

				re->from = (struct bcpi_node *)(uint64_t)
				    object_index;
				re->to = (struct bcpi_node *)(uint64_t)
				    node_index;

				uint64_t counter_nz_flag = 0;
				bcpi_serializer_get_bytes(reader,
				    &counter_nz_flag,
				    BCPI_CEIL_DIV(record->num_counter, 8));
				for (int l = 0; l < record->num_counter; ++l) {
					re->counters[l] = 0;
					if (counter_nz_flag & 1) {
						bcpi_serializer_get_bytes(
						    reader, &re->counters[l],
						    BCPI_CEIL_DIV(
							oi->counter_bits[l],
							8));
					}
					counter_nz_flag = counter_nz_flag >> 1;
				}
			}
		}
	}

	for (int i = 0; i < record->num_object; ++i) {
		struct bcpi_object *ro = &record->object_list[i];
		for (int j = 0; j < ro->num_node; ++j) {
			struct bcpi_node *rn = &ro->node_list[j];
			for (int k = 0; k < rn->num_incoming_edge; ++k) {
				struct bcpi_edge *re = &rn->edge_list[k];
				int object_index = (uint64_t)re->from;
				int node_index = (uint64_t)re->to;

				re->to = rn;
				re->from = &record->object_list[object_index]
						.node_list[node_index];
			}
		}
	}

	free(buffer);

	*r = record;
}

int
bcpi_save_file(const struct bcpi_record *r, const char *f)
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
bcpi_load_file(const char *f, struct bcpi_record **r)
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

	bcpi_load(data, size, r);
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
bcpi_merge(struct bcpi_record **out, const struct bcpi_record **list, int num)
{
	return 0;
}

int
bcpi_get_index_from_name(struct bcpi_record *record, const char *name)
{
	for (int i = 0; i < record->num_counter; ++i) {
		if (!strcmp(record->counter_name[i], name)) {
			return i;
		}
	}
	return -1;
}

int g_bcpi_sort_index;

bool
bcpi_node_sort_function(const struct bcpi_node *a, const struct bcpi_node *b)
{
	return a->terminal_counters[g_bcpi_sort_index] >
	    b->terminal_counters[g_bcpi_sort_index];
}

bool
bcpi_edge_sort_function(const struct bcpi_edge *a, const struct bcpi_edge *b)
{
	return a->counters[g_bcpi_sort_index] > b->counters[g_bcpi_sort_index];
}

void
bcpi_collect_node(
    struct bcpi_record *record, std::vector<struct bcpi_node *> &node_out)
{
	for (int i = 0; i < record->num_object; ++i) {
		struct bcpi_object *ro = &record->object_list[i];

		for (int j = 0; j < ro->num_node; ++j) {
			struct bcpi_node *rn = &ro->node_list[j];

			node_out.emplace_back(rn);
		}
	}
}

void
bcpi_collect_object(struct bcpi_record *record,
    std::vector<struct bcpi_object *> &object_out, const char *name)
{
	for (int i = 0; i < record->num_object; ++i) {
		struct bcpi_object *ro = &record->object_list[i];
		if (strcasestr(ro->path, name)) {
			fprintf(stderr, "adding %s\n", ro->path);
			object_out.emplace_back(ro);
		}
	}
}

void
bcpi_collect_node_from_object(struct bcpi_record *record,
    std::vector<struct bcpi_node *> &node_out, struct bcpi_object *ro)
{
	for (int i = 0; i < ro->num_node; ++i) {
		struct bcpi_node *rn = &ro->node_list[i];
		node_out.push_back(rn);
	}
}

void
bcpi_collect_edge(
    struct bcpi_node *n, std::vector<struct bcpi_edge *> &edge_out)
{
	for (int i = 0; i < n->num_incoming_edge; ++i) {
		edge_out.emplace_back(&n->edge_list[i]);
	}
}

void
bcpi_node_sort(int index, std::vector<struct bcpi_node *> &sorted_nodes)
{
	g_bcpi_sort_index = index;
	sort(sorted_nodes.begin(), sorted_nodes.end(), bcpi_node_sort_function);
}

void
bcpi_edge_sort(int index, std::vector<struct bcpi_edge *> &sorted_edges)
{
	g_bcpi_sort_index = index;
	sort(sorted_edges.begin(), sorted_edges.end(), bcpi_edge_sort_function);
}

void
bcpi_print_summary(const struct bcpi_record *r)
{
	struct tm *t = gmtime((time_t *)&r->epoch);
	char time_buffer[128];

	strftime(time_buffer, 127, "%c", t);
	printf("%s\n", time_buffer);
	printf("%s\n", r->system_name);
	printf("%d counters\n", r->num_counter);
	for (int i = 0; i < r->num_counter; ++i) {
		printf(" %d: %s\n", i + 1, r->counter_name[i]);
	}
	printf("%d objects\n", r->num_object);
	for (int i = 0; i < r->num_object; ++i) {
		bcpi_object *obj = &r->object_list[i];

		printf(
		    " %3d: %5d nodes, %8x, ", i + 1, obj->num_node, obj->hash);
		printf(" %s \n", obj->path);
	}
}

void
bcpi_show_node_info(
    struct bcpi_record *r, struct bcpi_node *n, const char *sort_crit)
{
	printf("\nNode ID %d in object ID %d\n", n->node_index,
	    (n->object->object_index) + 1);
	printf("Address %lx in %s\n", n->node_address, n->object->path);
	printf(" Counter hits (as terminal node):\n");
	for (int i = 0; i < r->num_counter; ++i) {
		printf(" %8ld", n->terminal_counters[i]);
	}
	printf("\n");

	std::vector<struct bcpi_edge *> edges;
	bcpi_collect_edge(n, edges);
	if (sort_crit) {
		int index = bcpi_get_index_from_name(r, sort_crit);
		g_bcpi_sort_index = index;

		sort(edges.begin(), edges.end(), bcpi_edge_sort_function);
	}

	// printf(" Callchain reaching this node (exclude above):\n");
	// int edge_size = edges.size();
	// for (int i = 0; i < edge_size; ++i) {
	//    struct bcpi_edge *e = edges[i];
	//    printf(" %lx in %s\n", e->from->node_address,
	//    e->from->object->path); for (int j = 0; j < r->num_counter; ++j) {
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
vec2hash_merge_nodes(int index, std::vector<bcpi_node *> nodes)
{
	std::unordered_map<uint64_t, bcpi_node *> umap;
	for (int i = 0; i < nodes.size(); i++) {
		if (umap.find(nodes[i]->node_address) == umap.end())
			umap.emplace(nodes[i]->node_address, nodes[i]);
		else
			umap[nodes[i]->node_address]
			    ->terminal_counters[index] +=
			    nodes[i]->terminal_counters[index];
	}
	return hash2vec(umap);
}
