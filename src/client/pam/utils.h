#ifndef UTILS_H
#define UTILS_H

#include <security/pam_appl.h>
#include <string>

int unix_update_shadow(pam_handle_t *pamh, const char *forwho, char *towhat);

int lock_pwdf();
void unlock_pwdf();

std::string generate_block(int size);
std::string to_base64(const char *str, unsigned int size);
std::string to_base64(const char *str);

char *apply_crypt(const char *raw_key, unsigned int key_size, const char *hash);
char *apply_crypt(const char *raw_key, unsigned int key_size = 0);


#endif // UTILS_H
