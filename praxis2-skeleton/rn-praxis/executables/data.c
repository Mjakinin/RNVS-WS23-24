#include "data.h"

#include <string.h>
#include <netinet/in.h>


struct tuple* find(string key, struct tuple* tuples, size_t n_tuples) {
    for (size_t i = 0; i < n_tuples; i += 1) {
        // compare keys with 'strcmp'
        if (tuples[i].key && strcmp(key, tuples[i].key) == 0) {
            return &(tuples[i]);
        }
    }
    return NULL;
}


const char* get(const string key, struct tuple* tuples, size_t n_tuples, size_t* value_length) {
    struct tuple* tuple = find(key, tuples, n_tuples);
    if (tuple) {
        *value_length = tuple->value_length;
        return tuple->value;
    } else {
        return NULL;
    }
}


bool set(const string key, char* value, size_t value_length, struct tuple* tuples, size_t n_tuples) {
    // check if tuple already exists
    struct tuple* tuple = find(key, tuples, n_tuples);

    if (tuple) {  // overwrite existing value
        free(tuple->value);
        tuple->value = (char*) malloc(value_length * sizeof(char));
        strcpy(tuple->value, value);
        tuple->value_length = value_length;
        return true;
    } else {  // add tuple
        for (size_t i = 0; i < n_tuples; i += 1) {
            if (tuples[i].key == NULL) {
                tuples[i].key = (char*) malloc((strlen(key) + 1) * sizeof(char));
                strcpy(tuples[i].key, key);
                tuples[i].value = (char*) malloc(value_length * sizeof(char));
                memcpy(tuples[i].value, value, value_length);
                tuples[i].value_length = value_length;
                return false;
            }
        }
    }
    return false;  // fail silently if no space for a new tuple is available 
}


bool delete(const string key, struct tuple* tuples, size_t n_tuples) {
    struct tuple* tuple = find(key, tuples, n_tuples);

    if (tuple) {
        free(tuple->key);
        tuple->key = NULL;
        free(tuple->value);
        tuple->value = NULL;
        tuple->value_length = 0;
        return true;
    } else {
        return false;
    }
}

chord_message create_chordMessage(uint8_t message_type, uint16_t hash_id, uint16_t node_id, uint32_t node_ip, uint16_t node_port){
    chord_message new_msg;
    new_msg.message_type = message_type;
    new_msg.hash_id = htons(hash_id);
    new_msg.node_id = htons(node_id);
    new_msg.node_ip = htonl(node_ip);
    new_msg.node_port = htons(node_port);

    return new_msg;
}
