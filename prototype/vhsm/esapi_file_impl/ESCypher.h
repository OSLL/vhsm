#ifndef CYPHER_H
#define CYPHER_H

#include "esapi/Types.h"

namespace ES {

class Cypher {
public:
    static bool encrypt(const char *data, size_t length, const Key &key, char **result, size_t *res_length);
    static bool decrypt(const char *data, size_t length, const Key &key, char **result, size_t *res_length);
};

}

#endif // CYPHER_H
