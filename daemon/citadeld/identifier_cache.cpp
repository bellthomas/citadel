
#include "includes/identifier_cache.h"

#include <algorithm>
#include <iostream>
#include <string>
#include <sys/time.h>


#include <sparsehash/sparse_hash_map>

const unsigned char defaultCacheValue[_CITADEL_IDENTIFIER_LENGTH] = {'\0'};

// A custom value type that has a default constructor
class IdentifierCacheEntry {
public:
    // The usual boilerplate
    IdentifierCacheEntry() : _value((const unsigned char*)&defaultCacheValue) {
        gettimeofday(&_time, NULL);
    }
    IdentifierCacheEntry(const IdentifierCacheEntry &other) : _value(other._value) {
        gettimeofday(&_time, NULL);
    }
    IdentifierCacheEntry(const unsigned char value[_CITADEL_IDENTIFIER_LENGTH]) : _value(value) {
        gettimeofday(&_time, NULL);
    }
    void operator=(const IdentifierCacheEntry &other) {
        _value = other._value;
        gettimeofday(&_time, NULL);
    }
    const std::string asString() const {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < _CITADEL_IDENTIFIER_LENGTH; ++i)
            ss << std::uppercase << std::setw(2) << static_cast<unsigned>(_value[i]);
        return ss.str();;
    }
    const unsigned char *get_value() const {
        return _value;
    }
    bool expired() {
        struct timeval end;
        gettimeofday(&end, NULL);
        unsigned long us = ((end.tv_sec - _time.tv_sec) * 1000000 + end.tv_usec - _time.tv_usec);
        return (us > _CITADEL_CACHE_EXPIRY * 1000000);
    }
private:
    const unsigned char *_value;
    struct timeval _time;
};

// Allow value type to be redirected to std::ostream
std::ostream & operator<<(std::ostream &o, const IdentifierCacheEntry &value) {
    o << value.asString();
    return o;
}

// A sparse_hash_map typedef, for convenience
typedef google::sparse_hash_map<std::string, IdentifierCacheEntry> IdentifierCache;
IdentifierCache identifierCache;


static const unsigned char* _hex_identifier_to_bytes(char* hexstring) {
	size_t i, j;
	size_t len = strlen(hexstring);
	size_t final_len = len / 2;
	unsigned char* identifier; 

    if(len % 2 != 0) return NULL;

	identifier = (unsigned char*) malloc(final_len);
    for (i = 0, j = 0; j < final_len; i += 2, j++) {
        identifier[j] = (hexstring[i] % 32 + 9) % 25 * 16 + (hexstring[i+1] % 32 + 9) % 25;
	}
	return (const unsigned char*)identifier;
}

const unsigned char *get_identifier_for_path(std::string *path) {
    char identifier_hex[2*_CITADEL_IDENTIFIER_LENGTH+1] = {'\0'};
    const char *c_path = (*path).c_str();
    size_t xattr_size = getxattr(c_path, _CITADEL_XATTR_IDENTIFIER, &identifier_hex, sizeof(identifier_hex));
    if (xattr_size == 2*_CITADEL_IDENTIFIER_LENGTH) {
        // Success.
        return _hex_identifier_to_bytes(identifier_hex);
    }
    return NULL;
} 

bool metadata_path_to_identifier(void *metadata_value) {
    bool retval = true;
    size_t len = strlen((const char*)metadata_value);
    std::string s((const char*)metadata_value, len);
    // // Remember to free: delete sp;

    const IdentifierCache::iterator itr = identifierCache.find(s);
    if (itr == identifierCache.end() || itr->second.expired()) {
        // Not in the cache or expired.
        if (itr != identifierCache.end() && itr->second.expired()) {
            identifierCache.erase(itr);
        }

        const unsigned char *identifier = get_identifier_for_path(&s);
        if (identifier) {
            const std::pair<IdentifierCache::const_iterator, bool> result = identifierCache.insert(std::make_pair(s, identifier));
            if (!result.second) {
                std::cout << "Failed to insert item into sparse_hash_map" << std::endl;
                retval = false;
            } else {
                IdentifierCacheEntry entry = result.first->second;
#if CITADEL_DEBUG
                std::cout << "Cache (*). " << s << ": " << result.first->second << std::endl;
#endif 
                memcpy(metadata_value, (const void*)(entry.get_value()), _CITADEL_IDENTIFIER_LENGTH);
            }
        }
        else {
            std::cout << "No identifier found for file." << std::endl;
            memset(metadata_value, 0, _CITADEL_IDENTIFIER_LENGTH);
        }

    } else {
        IdentifierCacheEntry entry = itr->second;
#if CITADEL_DEBUG
        std::cout << "Cache. " << s << ": " << entry << std::endl;
#endif
        memcpy(metadata_value, (const void*)(entry.get_value()), _CITADEL_IDENTIFIER_LENGTH);
    }

    return retval;
}

bool cache_passthrough(void *message, size_t message_len) {
    bool success = true;
    struct citadel_op_request *request;
    struct citadel_op_extended_request *extended_request = NULL;
    if (message_len == sizeof(struct citadel_op_request)) {
        request = (struct citadel_op_request*)message;
    } 
    else if (message_len == sizeof(struct citadel_op_extended_request)) {
        extended_request = (struct citadel_op_extended_request*)message;
        request = &extended_request->request;
    }
    else {
        return false;
    }

    // Invoke cache lookup if required.
    if (extended_request && extended_request->translate) {
        success = metadata_path_to_identifier((void *)extended_request->metadata);
    }
    // switch (request->operation) {
    // case CITADEL_OP_OPEN:
    //     if (extended_)
    //     if (extended_request) success = metadata_path_to_identifier((void *)extended_request->metadata);
    //     else success = false;
    //     break;
    // default:
    //     break;
    // }

    return success;
}
 

void identifier_cache_setup(void) {
    identifierCache.set_deleted_key("");
}

int hashmap_test() {
    // identifierCache["roses"] = "red";

    // The other way to insert items, as with std::map
    // const std::pair<IdentifierCache::const_iterator, bool> result =
    //     identifierCache.insert(std::make_pair("violets", "blue"));
    // if (!result.second) {
    //     std::cout << "Failed to insert item into sparse_hash_map" << std::endl;
    //     return 1;
    // }

    // std::cout << "violets: " << result.first->second << std::endl;

    // // The other way to retrieve values
    // const IdentifierCache::iterator itr = identifierCache.find("violets");
    // if (itr == identifierCache.end()) {
    //     std::cout << "Failed to find item in sparse_hash_map" << std::endl;
    //     return 1;
    // }

    // // Fails if 'set_deleted_key()' has not been called
    // identifierCache.erase(itr);

    // // Accessing values using [] is only permitted when the value type has a
    // // default constructor. This line will not compile without one.
    // const IdentifierCacheEntry &roses = identifierCache["roses"];

    // // Print output
    // std::cout << "roses: " << roses << std::endl;
    // std::cout << "violets: " << identifierCache["violets"] << std::endl;

    return 0;
}