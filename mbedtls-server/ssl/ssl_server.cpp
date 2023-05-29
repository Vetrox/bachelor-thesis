#include "mbedtls/build_info.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform.h"

#include <fstream>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/x509_crt.h"

#include <iostream>
#include <iomanip>

#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n" \
    "<p>Successful connection using: %s</p>\r\n"

#define DEBUG_LEVEL 4

static void my_debug([[maybe_unused]] void *ctx, int level,
                     const char *file, int line,
                     const char *str)
{
    std::cout << std::string(file).substr(38) << ":" << std::setw(4) << std::dec << std::setfill('0') << line << ":";
    for (int i = 0; i < level; ++i)
        std::cout << ' ';
    std::cout << str << std::flush;
}

void init_working_state(mbedtls_entropy_context& entropy);
int my_generate(void *p_rng, unsigned char *output, size_t output_len, const unsigned char *additional, size_t add_len);

int my_drbg_random(void *p_rng, unsigned char *output,
                            size_t output_len)
{
    // mbedtls_ctr_drbg_random(p_rng, output, output_len);
    my_generate(p_rng, output, output_len, NULL, 0);
    return 0;
}

int main(void)
{
    int ret, len;
    mbedtls_net_context listen_fd, client_fd;
    unsigned char buf[1024];
    const char *pers = "ssl_server";

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;

    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_debug_set_threshold(DEBUG_LEVEL);

    // 1. Seed the RNG
    std::cout << "Setting up the random number generator...";
    // NOTE: This call is the DRBG_Instantiate call in SP 800-90A
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     reinterpret_cast<const unsigned char *>(pers),
                                     strlen(pers))) != 0) {
        std::cout << " failed: mbedtls_ctr_drbg_seed returned " << ret << std::endl;
        goto exit;
    }
    init_working_state(entropy);
    std::cout << " ok" << std::endl;

    // 2. Load the certificates and private RSA key
    std::cout << "Loading the server certificate and key...";
    ret = mbedtls_x509_crt_parse_file(&srvcert, "server-cert.pem");
    if (ret != 0) {
        std::cout << " failed: mbedtls_x509_crt_parse_file returned " << ret << std::endl;
        goto exit;
    }

    ret = mbedtls_pk_parse_keyfile(&pkey, "server-private-key.pem", NULL, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        std::cout << " failed: mbedtls_pk_parse_key returned " << ret << std::endl;
        goto exit;
    }
    std::cout << " ok" << std::endl;

    // 3. Setup the listening TCP socket
    std::cout << "Bind on https://localhost:4433/ ...";
    if ((ret = mbedtls_net_bind(&listen_fd, NULL, "4433", MBEDTLS_NET_PROTO_TCP)) != 0) {
        std::cout << " failed: mbedtls_net_bind returned " << ret << std::endl;
        goto exit;
    }
    std::cout << " ok" << std::endl;

    // 4. Setup
    std::cout <<"Setting up the SSL data...";
    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        std::cout << " failed: mbedtls_ssl_config_defaults returned " << ret << std::endl;
        goto exit;
    }

    mbedtls_ssl_conf_rng(&conf, my_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

    mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
    if ((ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)) != 0) {
        std::cout << " failed: mbedtls_ssl_conf_own_cert returned " << ret << std::endl;
        goto exit;
    }

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        std::cout << " failed: mbedtls_ssl_setup returned " << ret << std::endl;
        goto exit;
    }
    std::cout << " ok" << std::endl;

reset:
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }

    mbedtls_net_free(&client_fd);
    mbedtls_ssl_session_reset(&ssl);

    // 3. Wait until a client connects
    std::cout << "Waiting for a remote connection ..." << std::flush;
    if ((ret = mbedtls_net_accept(&listen_fd, &client_fd,
                                  NULL, 0, NULL)) != 0) {
        std::cout << " failed: mbedtls_net_accept returned " << ret << std::endl;
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    std::cout << " ok" << std::endl;

    // 5. Handshake
    std::cout << "Performing the SSL/TLS handshake...";
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            std::cout << " failed: mbedtls_ssl_handshake returned " << ret << std::endl;
            goto reset;
        }
    }

    std::cout << " ok" << std::endl;

    // 6. Read the HTTP Request
    std::cout << "< Read from client:";
    do {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }

        if (ret <= 0) {
            switch (ret) {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    mbedtls_printf(" connection was closed gracefully\n");
                    break;

                case MBEDTLS_ERR_NET_CONN_RESET:
                    mbedtls_printf(" connection was reset by peer\n");
                    break;

                default:
                    mbedtls_printf(" mbedtls_ssl_read returned -0x%x\n", static_cast<unsigned int>(-ret));
                    break;
            }

            break;
        }

        len = ret;
        std::cout << " " << len << "bytes read\n\n" << reinterpret_cast<char*>(buf);

        if (ret > 0) {
            break;
        }
    } while (1);

    // 7. Write the 200 Response
    mbedtls_printf("  > Write to client:");
    fflush(stdout);

    len = sprintf((char *) buf, HTTP_RESPONSE,
                  mbedtls_ssl_get_ciphersuite(&ssl));

    while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            mbedtls_printf(" failed\n  ! peer closed the connection\n\n");
            goto reset;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            goto exit;
        }
    }

    len = ret;
    mbedtls_printf(" %d bytes written\n\n%s\n", len, (char *) buf);

    mbedtls_printf("  . Closing the connection...");

    while ((ret = mbedtls_ssl_close_notify(&ssl)) < 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_close_notify returned %d\n\n", ret);
            goto reset;
        }
    }

    mbedtls_printf(" ok\n");

    ret = 0;
    goto reset;

exit:

    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }

    mbedtls_net_free(&client_fd);
    mbedtls_net_free(&listen_fd);

    mbedtls_x509_crt_free(&srvcert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    mbedtls_exit(ret);
}
