## tp-link-decrypt changes

Utilization of the cleanup function:
    - Universal resource freeing function.
    - Ensures that memory is cleaned and freed in any situation.

Safe buffer handling:
    - Uses snprintf to create the output file name, preventing buffer overflow.

Read and write error handling:
    - Checks the result of fread and fwrite to ensure that the data was processed correctly.

Memory leak prevention:
    - Any allocated memory is freed even in case of an error.

Clearing sensitive data:
    - Flash memory is cleared with memset before being freed.

Checking all memory allocation calls:
    - Added check for success of malloc, calloc calls

## New

Added `gen_keys_for_usr_conf_data.c` and `decrypt_usr_conf_data.sh` to find and decrypt `etc/usr_conf_data`
