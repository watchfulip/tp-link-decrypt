#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>
#include <ctype.h>

/**
 * Calculates a 32-bit hash of the given string.
 * - Skips double quotes (").
 * - Uses a modulo-based approach with prime 0x7fffffff.
 */
unsigned int hash(const char *str) 
{
    if (str == NULL) 
    {
        puts("str is null ptr");
        return 0;
    }

    unsigned int hash_value = 0;
    
    while (*str != '\0') 
    {
        if (*str != '"') 
        {
            hash_value = ((hash_value * 31) + (unsigned char)(*str)) % 0x7fffffff;
        }
        str++;
    }
    return hash_value;
}

/**
 * Converts a 32-bit unsigned integer (key) to a standard 8-character hex string,
 * then each character of that hex string is converted to two hexadecimal digits
 * representing its ASCII code.
 * 
 * For instance, if key = 0x5982abe6, the standard hex string is "5982abe6".
 * Each character of that string is then converted to its ASCII code in hex:
 * '5' -> 0x35, '9' -> 0x39, '8' -> 0x38, etc.
 * 
 * The final result would be 16 hexadecimal digits, for example: "3539383261626536".
 */
void convert_to_ascii_hex(unsigned int key, char *hex_value) 
{
    // Step 1: create a normal 8-char hex string for the integer (e.g., "5982abe6")
    char tmp[9]; // 8 characters + null terminator
    snprintf(tmp, sizeof(tmp), "%08x", key);

    // Step 2: convert each character to its ASCII code in hex
    // '5' (0x35) -> "35", '9' (0x39) -> "39", etc.
    for (int i = 0; i < 8; i++) 
    {
        unsigned char c = (unsigned char) tmp[i];
        // Write ASCII code of 'c' as two hex digits
        sprintf(&hex_value[2 * i], "%02x", c);
    }
    // Terminate the string (16 hex characters + null)
    hex_value[16] = '\0';
}

/**
 * Recursively searches for the file "etc/usr_conf_data" within subdirectories
 * of 'start_dir'.
 * - If found, returns true and copies the file path to 'result'.
 * - Otherwise, returns false.
 */
bool find_usr_conf_data(const char *start_dir, char *result, size_t result_size) 
{
    DIR *d = opendir(start_dir);
    if (!d) 
    {
        return false;
    }

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) 
    {
        // Skip "." and ".."
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) 
        {
            continue;
        }

        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", start_dir, entry->d_name);

        struct stat st;
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) 
        {
            // Form "path/etc/usr_conf_data"
            char test_path[2048];
            snprintf(test_path, sizeof(test_path), "%s/etc/usr_conf_data", path);

            // Check if the file exists
            if (access(test_path, F_OK) == 0) 
            {
                // Found the file
                strncpy(result, test_path, result_size);
                result[result_size - 1] = '\0'; // ensure null-termination
                closedir(d);
                return true;
            }

            // Otherwise, recurse into this subdirectory
            if (find_usr_conf_data(path, result, result_size)) 
            {
                closedir(d);
                return true;
            }
        }
    }

    closedir(d);
    return false;
}

/**
 * Attempts to find a pattern like:
 *   'C' + (one or more digits) + 'v' + (one or more digits)
 * For example:
 *   C210v1  -> returns "C210 1.0"
 *   C220v5  -> returns "C220 5.0"
 *   C200v4  -> returns "C200 4.0"
 * 
 * Returns true if the pattern is found, otherwise false.
 * 
 * Logic:
 *   1. Search for 'C' in the input string.
 *   2. After 'C', read any digits (this becomes the model, e.g., 210, 220, etc.).
 *   3. Expect a 'v', then read version digits (e.g., 1, 2, 5, etc.).
 *   4. Construct a final string like "C210 1.0".
 */
bool extractCModelVersion(const char *input, char *output, size_t output_size) 
{
    // Find each 'C' in the string
    const char *ptr = input;
    while ((ptr = strchr(ptr, 'C')) != NULL) 
    {
        ptr++; // move past 'C'

        // Gather digits after 'C'
        char modelDigits[32];
        int modelIdx = 0;
        while (isdigit((unsigned char)*ptr) && modelIdx < (int)(sizeof(modelDigits) - 1)) 
        {
            modelDigits[modelIdx++] = *ptr;
            ptr++;
        }
        modelDigits[modelIdx] = '\0';

        if (modelIdx == 0) 
        {
            // No digits immediately after 'C' -> try next 'C'
            continue;
        }

        // Expect 'v' next
        if (*ptr != 'v') 
        {
            // No 'v' -> try next 'C' in the outer loop
            continue;
        }

        // Found 'v', move on
        ptr++;

        // Gather digits after 'v'
        char versionDigits[32];
        int versionIdx = 0;
        while (isdigit((unsigned char)*ptr) && versionIdx < (int)(sizeof(versionDigits) - 1)) 
        {
            versionDigits[versionIdx++] = *ptr;
            ptr++;
        }
        versionDigits[versionIdx] = '\0';

        if (versionIdx == 0) 
        {
            // No digits after 'v' -> not a valid pattern
            continue;
        }

        // Construct "C<modelDigits> <versionDigits>.0"
        snprintf(output, output_size, "C%s %s.0", modelDigits, versionDigits);
        return true;
    }

    // No match found
    return false;
}

int main(int argc, char *argv[]) 
{
    if (argc != 2) 
    {
        fprintf(stderr, "Usage: %s <extracted_directory>\n", argv[0]);
        return 1;
    }

    // 1) Attempt to automatically extract a substring like "C210v1", "C220v5", etc.
    char auto_str[256];
    bool got_auto_str = extractCModelVersion(argv[1], auto_str, sizeof(auto_str));

    char final_str[256];
    if (got_auto_str) 
    {
        // Successfully found something like "C220 5.0"
        strncpy(final_str, auto_str, sizeof(final_str));
        final_str[sizeof(final_str) - 1] = '\0';
        printf("Auto-detected string for DES key: %s\n", final_str);
    } 
    else 
    {
        // No matching substring found; ask for user input
        printf("Enter the string to generate DES key: ");
        if (fgets(final_str, sizeof(final_str), stdin) == NULL) 
        {
            fprintf(stderr, "Error reading input\n");
            return 1;
        }
        // Remove trailing newline if present
        size_t len = strlen(final_str);
        
        if (len > 0 && final_str[len - 1] == '\n') 
        {
            final_str[len - 1] = '\0';
        }
    }

    // 2) Recursively search for etc/usr_conf_data in the given directory
    char usr_conf_path[2048];
    
    if (!find_usr_conf_data(argv[1], usr_conf_path, sizeof(usr_conf_path))) 
    {
        fprintf(stderr, "File etc/usr_conf_data not found in subdirectories of: %s\n", argv[1]);
        return 1;
    }

    printf("File found: %s\n", usr_conf_path);

    // 3) Compute the 32-bit hash of the selected string
    unsigned int key = hash(final_str);
    printf("Key: %08x\n", key);

    // 4) Convert the key to ASCII-hex (each character -> 2 hex digits for its ASCII code)
    char hex_key[17];
    convert_to_ascii_hex(key, hex_key);
    printf("Hex value key: %s\n", hex_key);

    // 5) Append the key and hex to "DES_key_n_hex.txt"
    FILE *fp = fopen("DES_key_n_hex.txt", "a");
    if (fp == NULL) 
    {
        fprintf(stderr, "Failed to open DES_key_n_hex.txt for writing.\n");
        return 1;
    }

    // Write the key and hex value, plus a separator or newline.
    fprintf(fp, "Key: %08x\n", key);
    fprintf(fp, "Hex value key: %s\n", hex_key);
    fprintf(fp, "----------------------\n");

    fclose(fp);

    return 0;
}

