#include <gpgme.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstdlib>

void import_public_key(gpgme_ctx_t ctx, const std::string& key_file_path) {
    gpgme_error_t err;
    gpgme_data_t key_data;

    // Open the key file
    std::ifstream key_file(key_file_path, std::ios::binary);
    if (!key_file) {
        std::cerr << "Failed to open public key file: " << key_file_path << std::endl;
        std::exit(1);
    }

    // Read the key file content into a string
    std::ostringstream oss;
    oss << key_file.rdbuf();
    std::string key_content = oss.str();
    key_file.close();

    // Create a data buffer from the key content
    err = gpgme_data_new_from_mem(&key_data, key_content.c_str(), key_content.size(), 0);
    if (err) {
        std::cerr << "Failed to create data buffer for key: " << gpgme_strerror(err) << std::endl;
        std::exit(1);
    }

    // Import the key
    err = gpgme_op_import(ctx, key_data);
    if (err) {
        std::cerr << "Failed to import key: " << gpgme_strerror(err) << std::endl;
        std::exit(1);
    }

    gpgme_data_release(key_data);
}

std::string get_recipient_keyid(gpgme_ctx_t ctx) {
    gpgme_error_t err;
    gpgme_key_t key;
    std::string recipient;

    // list keys
    err = gpgme_op_keylist_start(ctx, NULL, 0);
    if (err) {
        std::cerr << "Failed to start keylist: " << gpgme_strerror(err) << std::endl;
        std::exit(1);
    }

    // Get the first key in the keyring
    err = gpgme_op_keylist_next(ctx, &key);
    if (err) {
        std::cerr << "No keys found in keyring: " << gpgme_strerror(err) << std::endl;
        std::exit(1);
    }

    // Use the key ID of the first key
    recipient = key->subkeys->keyid;
    gpgme_key_unref(key);
    gpgme_op_keylist_end(ctx);

    return recipient;
}

void encrypt_csv_with_pgp(gpgme_ctx_t ctx, const std::string& recipient, const std::string& csv_content, const std::string& output_file) {
    gpgme_data_t plaintext, ciphertext;
    gpgme_key_t key[2] = {nullptr, nullptr};
    gpgme_error_t err;

    // Set output to be ASCII-armored
    gpgme_set_armor(ctx, 1);

    // Load the recipient's public key
    err = gpgme_get_key(ctx, recipient.c_str(), &key[0], 0);
    if (err) {
        std::cerr << "Failed to retrieve public key: " << gpgme_strerror(err) << std::endl;
        std::exit(1);
    }

    // Data buffer for CSV content (plaintext)
    err = gpgme_data_new_from_mem(&plaintext, csv_content.c_str(), csv_content.size(), 0);
    if (err) {
        std::cerr << "Failed to create plaintext data object: " << gpgme_strerror(err) << std::endl;
        std::exit(1);
    }

    // Data buffer for encrypted output (ciphertext)
    err = gpgme_data_new(&ciphertext);
    if (err) {
        std::cerr << "Failed to create encrypted data object: " << gpgme_strerror(err) << std::endl;
        std::exit(1);
    }

    // Encrypt the plaintext data
    err = gpgme_op_encrypt(ctx, key, GPGME_ENCRYPT_ALWAYS_TRUST, plaintext, ciphertext);
    if (err) {
        std::cerr << "Encryption failed: " << gpgme_strerror(err) << std::endl;
        std::exit(1);
    }

    // Get the encrypted data and write it to the output file
    std::ofstream outfile(output_file, std::ios::out | std::ios::binary);
    if (!outfile) {
        std::cerr << "Failed to open output file: " << output_file << std::endl;
        std::exit(1);
    }
    char buffer[512];
    ssize_t nread;
    gpgme_data_seek(ciphertext, 0, SEEK_SET);
    while ((nread = gpgme_data_read(ciphertext, buffer, sizeof(buffer))) > 0) {
        outfile.write(buffer, nread);
    }

    // Cleanup
    outfile.close();
    gpgme_key_unref(key[0]);
    gpgme_data_release(plaintext);
    gpgme_data_release(ciphertext);
}

int main() {
    std::string public_key_file = "test_public_key.asc";
    std::string csv_file_path = "dummy_pan_data.csv";
    std::string output_file = "encrypted_dummy_pan_data.pgp";

    // Initialize the GPGME library
    gpgme_check_version(nullptr);

    gpgme_ctx_t ctx;
    gpgme_error_t err = gpgme_new(&ctx);
    if (err) {
        std::cerr << "Failed to create GPGME context: " << gpgme_strerror(err) << std::endl;
        std::exit(1);
    }

    // Set output to be ASCII-armored
    gpgme_set_armor(ctx, 1);

    // Import PGP key
    import_public_key(ctx, public_key_file);

    // Get the PGP key ID (assumes only key in keyring)
    std::string recipient = get_recipient_keyid(ctx);

    // Read CSV content into string (in-memory)
    std::ifstream csv_file(csv_file_path);
    if (!csv_file) {
        std::cerr << "Failed to open CSV file: " << csv_file_path << std::endl;
        std::exit(1);
    }
    std::ostringstream csv_oss;
    csv_oss << csv_file.rdbuf();
    std::string csv_content = csv_oss.str();
    csv_file.close();

    // Encrypt the CSV content (in-memory)
    encrypt_csv_with_pgp(ctx, recipient, csv_content, output_file);

    // Release the GPGME context
    gpgme_release(ctx);

    std::cout << "CSV file encrypted and saved to " << output_file << std::endl;
    return 0;
}
