#pragma once

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#include "util.h"

/**
 * A simple key-value entry
 *
 * Provides a simple, inefficient, key-value when combined with `get()`,
 * `set()`, and `delete()`.
 */
struct tuple {
    string key;
    char* value;
    size_t value_length;
};


typedef struct{
    int initialized;

    int PRED_ID;
    const char* PRED_IP;
    int PRED_PORT;
    int SUCC_ID;
    const char* SUCC_IP;
    int SUCC_PORT;

    int SELF_ID;
    int SELF_PORT;
    const char* SELF_IP;
} dht_node;

#pragma pack(1)

typedef struct{
    uint8_t message_type;
    uint16_t hash_id;
    uint16_t node_id;
    uint32_t node_ip;
    uint16_t node_port;
} chord_message;

#pragma pack()

/**
 * Get the value matching the key in an array of tuples
 *
 * Returns a pointer to the begin of the value, stores its length in `value_length`.
 */
const char* get(const string key, struct tuple* tuples, size_t n_tuples, size_t* value_length);

/**
 * Set the value for the key in an array of tuples
 *
 * Returns true if a value was overwritten, false if it was created.
 */
bool set(const string key, char* value, size_t value_length, struct tuple* tuples, size_t n_tuples);


/**
 * Deletes the key in the array of tuples.
 *
 * Returns true if it existed.
 */
bool delete(const string key, struct tuple* tuples, size_t n_tuples);

chord_message create_chordMessage(uint8_t message_type, uint16_t hash_id, uint16_t node_id, uint32_t node_ip, uint16_t node_port);
