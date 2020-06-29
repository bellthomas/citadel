

// App.cpp : Define the entry point for the console application.
//

#include <string.h>
#include <assert.h>
#include <fstream>
#include <thread>
#include <iostream>

#include "sgx_urts.h"
#include "Enclave_u.h"
#include "ErrorSupport.h"

#define SEALED_DATA_FILE "sealed_data_blob.txt"


static size_t get_file_size(const char *filename)
{
    std::ifstream ifs(filename, std::ios::in | std::ios::binary);
    if (!ifs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return -1;
    }
    ifs.seekg(0, std::ios::end);
    size_t size = (size_t)ifs.tellg();
    return size;
}

static bool read_file_to_buf(const char *filename, uint8_t *buf, size_t bsize)
{
    if (filename == NULL || buf == NULL || bsize == 0)
        return false;
    std::ifstream ifs(filename, std::ios::binary | std::ios::in);
    if (!ifs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return false;
    }
    ifs.read(reinterpret_cast<char *> (buf), bsize);
    if (ifs.fail())
    {
        std::cout << "Failed to read the file \"" << filename << "\"" << std::endl;
        return false;
    }
    return true;
}

static bool write_buf_to_file(const char *filename, const uint8_t *buf, size_t bsize, long offset)
{
    if (filename == NULL || buf == NULL || bsize == 0)
        return false;
    std::ofstream ofs(filename, std::ios::binary | std::ios::out);
    if (!ofs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return false;
    }
    ofs.seekp(offset, std::ios::beg);
    ofs.write(reinterpret_cast<const char*>(buf), bsize);
    if (ofs.fail())
    {
        std::cout << "Failed to write the file \"" << filename << "\"" << std::endl;
        return false;
    }

    return true;
}

/* Initialize the enclave:
*   Call sgx_create_enclave to initialize an enclave instance
*/
static sgx_status_t initialize_enclave(const char* enclave_path, sgx_enclave_id_t *eid)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(enclave_path, SGX_DEBUG_FLAG, NULL, NULL, eid, NULL);
    if (ret != SGX_SUCCESS) {
        return ret;
    }
    return SGX_SUCCESS;
}


static bool seal_and_save_data(const char* enclave_path, const char* datafile) {
    sgx_enclave_id_t eid_seal = 0;
    // Load the enclave for sealing
    sgx_status_t ret = initialize_enclave(enclave_path, &eid_seal);
    if (ret != SGX_SUCCESS) {
        ret_error_support(ret);
        return false;
    }

    // Load data from file.
    size_t plain_len = get_file_size(datafile);
    if (plain_len <= 0) {
        std::cout << "Failed to get file size" << std::endl;
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    
    uint8_t *plain_text = (uint8_t *)malloc(plain_len);
    if(plain_text == NULL) {
        std::cout << "Out of memory" << std::endl;
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    if (!read_file_to_buf(datafile, plain_text, plain_len)) {
        std::cout << "Failed to read file" << std::endl;
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    // Get the sealed data size
    uint32_t sealed_data_size = 0;
    ret = get_sealed_data_size(eid_seal, &sealed_data_size, (uint32_t)plain_len);
    if (ret != SGX_SUCCESS) {
        ret_error_support(ret);
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    else if(sealed_data_size == UINT32_MAX) {
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    
    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    if(temp_sealed_buf == NULL) {
        std::cout << "Out of memory" << std::endl;
        sgx_destroy_enclave(eid_seal);
        return false;
    }


    sgx_status_t retval;
    ret = seal_data(eid_seal, &retval, (uint8_t*)plain_text, (uint32_t)plain_len, temp_sealed_buf, sealed_data_size);
    if (ret != SGX_SUCCESS)
    {
        ret_error_support(ret);
        free(temp_sealed_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }
    
    else if( retval != SGX_SUCCESS)
    {
        ret_error_support(retval);
        free(temp_sealed_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    // Save the sealed blob
    size_t filename_len = strlen(datafile);
    char outfile[filename_len + 7 + 1];
    memcpy(outfile, datafile, filename_len);
    memcpy(outfile + filename_len, ".sealed", 7);
    outfile[filename_len + 7] = '\0';

    if (write_buf_to_file(outfile, temp_sealed_buf, sealed_data_size, 0) == false)
    {
        std::cout << "Failed to save the sealed data blob to \"" << outfile << "\"" << std::endl;
        free(temp_sealed_buf);
        sgx_destroy_enclave(eid_seal);
        return false;
    }

    free(temp_sealed_buf);
    sgx_destroy_enclave(eid_seal);

    std::cout << "Sealing data succeeded." << std::endl;
    return true;

}


int main(int argc, char* argv[])
{
    // (void)argc, (void)argv;

    if (argc != 3) {
        std::cout << "Invalid number of arguments." << std::endl;
        return -2; 
    }

    // Enclave_Seal: seal the secret and save the data blob to a file
    if (seal_and_save_data((const char*)argv[1], (const char*)argv[2]) == false)
    {
        std::cout << "Failed to seal the secret and save it to a file." << std::endl;
        return -1;
    }

    // Enclave_Unseal: read the data blob from the file and unseal it.
    // if (read_and_unseal_data() == false)
    // {
    //     std::cout << "Failed to unseal the data blob." << std::endl;
    //     return -1;
    // }

    return 0;
}

