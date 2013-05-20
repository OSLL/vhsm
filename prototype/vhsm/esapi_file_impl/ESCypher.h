#ifndef CYPHER_H
#define CYPHER_H

#include <Types.h>

namespace ES {

namespace Cypher {
    bool encrypt(const char *data, size_t length, const Key &key, char **result, size_t *res_length);
    bool decrypt(const char *data, size_t length, const Key &key, char **result, size_t *res_length);
}

}

#endif // CYPHER_H
