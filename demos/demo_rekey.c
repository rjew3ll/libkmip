/* Copyright (c) 2018 The Johns Hopkins University/Applied Physics Laboratory
 * All Rights Reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "kmip.h"
#include "kmip_io.h"
#include "kmip_bio.h"

void
print_help(const char *app)
{
    printf("Usage: %s [flag value | flag] ...\n\n", app);
    printf("Flags:\n");
    printf("-a addr : the IP address of the KMIP server\n");
    printf("-c path : path to client certificate file\n");
    printf("-h      : print this help info\n");
    printf("-i id   : the ID of the symmetric key to rekey\n");
    printf("-k path : path to client key file\n");
    printf("-p port : the port number of the KMIP server\n");
    printf("-r path : path to CA certificate file\n");
}

int
parse_arguments(int argc, char **argv,
                char **server_address, char **server_port,
                char **client_certificate, char **client_key, char **ca_certificate,
                char **id,
                int *print_usage)
{
    if(argc <= 1)
    {
        print_help(argv[0]);
        return(-1);
    }
    
    for(int i = 1; i < argc; i++)
    {
        if(strncmp(argv[i], "-a", 2) == 0)
        {
            *server_address = argv[++i];
        }
        else if(strncmp(argv[i], "-c", 2) == 0)
        {
            *client_certificate = argv[++i];
        }
        else if(strncmp(argv[i], "-h", 2) == 0)
        {
            *print_usage = 1;
        }
        else if(strncmp(argv[i], "-i", 2) == 0)
        {
            *id = argv[++i];
        }
        else if(strncmp(argv[i], "-k", 2) == 0)
        {
            *client_key = argv[++i];
        }
        else if(strncmp(argv[i], "-p", 2) == 0)
        {
            *server_port = argv[++i];
        }
        else if(strncmp(argv[i], "-r", 2) == 0)
        {
            *ca_certificate = argv[++i];
        }
        else
        {
            printf("Invalid option: '%s'\n", argv[i]);
            print_help(argv[0]);
            return(-1);
        }
    }
    
    return(0);
}

int use_low_level_api(KMIP *ctx, BIO *bio,
                      char *uuid, int uuid_size, int offset,
                      TemplateAttribute *template_attribute,
                      char **rekey_uuid, int *rekey_uuid_size)
{
    if(ctx == NULL || bio == NULL || rekey_uuid == NULL || rekey_uuid_size == NULL)
    {
        return(KMIP_ARG_INVALID);
    }

    printf("bio rekey start \n");
    if( uuid && uuid_size <= 0)
    {
        return(KMIP_ARG_INVALID);
    }

    /* Set up the initial encoding buffer. */
    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;

    uint8 *encoding = ctx->calloc_func(ctx->state, buffer_blocks, buffer_block_size);
    if(encoding == NULL)
        return(KMIP_MEMORY_ALLOC_FAILED);
    printf("encoding = %p\n", encoding);
    kmip_set_buffer(ctx, encoding, buffer_total_size);

    /* Build the request message. */
    ProtocolVersion pv = {0};
    kmip_init_protocol_version(&pv, ctx->version);

    RequestHeader rh = {0};
    kmip_init_request_header(&rh);

    rh.protocol_version = &pv;
    rh.maximum_response_size = ctx->max_message_size;
    rh.time_stamp = time(NULL);
    rh.batch_count = 1;

    TextString id = { 0 };
    if (uuid)
    {
        printf("uuid=%s\n", uuid);
        id.value = uuid;
        id.size = uuid_size;
    }

    RekeyRequestPayload rkrp = {0};
    rkrp.offset = offset;  // -1 = KMIP_UNSET
    if (uuid)
    {
        rkrp.unique_identifier = &id;
    }
    rkrp.template_attribute = template_attribute;

    RequestBatchItem rbi = {0};
    kmip_init_request_batch_item(&rbi);
    rbi.operation = KMIP_OP_REKEY;
    rbi.request_payload = &rkrp;

    RequestMessage rm = {0};
    rm.request_header = &rh;
    rm.batch_items = &rbi;
    rm.batch_count = 1;

    /* Add the context credential to the request message if it exists. */
    /* TODO (ph) Update this to add multiple credentials. */
    Authentication auth = {0};
    if(ctx->credential_list != NULL)
    {
        LinkedListItem *item = ctx->credential_list->head;
        if(item != NULL)
        {
            auth.credential = (Credential *)item->data;
            rh.authentication = &auth;
        }
    }

    /* Encode the request message. Dynamically resize the encoding buffer */
    /* if it's not big enough. Once encoding succeeds, send the request   */
    /* message.                                                           */
    int encode_result = kmip_encode_request_message(ctx, &rm);
    while(encode_result == KMIP_ERROR_BUFFER_FULL)
    {
        kmip_reset(ctx);
        ctx->free_func(ctx->state, encoding);

        buffer_blocks += 1;
        buffer_total_size = buffer_blocks * buffer_block_size;

        encoding = ctx->calloc_func(ctx->state, buffer_blocks, buffer_block_size);
        if(encoding == NULL)
        {
            kmip_set_buffer(ctx, NULL, 0);
            printf("Failure: Could not automatically enlarge the encoding ");
            printf("buffer for the rekey request.\n");

            return(KMIP_MEMORY_ALLOC_FAILED);
        }
        printf("encoding = %p\n", encoding);

        kmip_set_buffer(ctx,encoding,buffer_total_size);
        encode_result = kmip_encode_request_message(ctx, &rm);
    }

    if(encode_result != KMIP_OK)
    {
        printf("An error occurred while encoding the rekey request.\n");
        printf("Error Code: %d\n", encode_result);
        printf("Error Name: ");
        kmip_print_error_string(stdout, encode_result);
        printf("\n");
        printf("Context Error: %s\n", ctx->error_message);
        printf("Stack trace:\n");
        kmip_print_stack_trace(stdout, ctx);

        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(encode_result);
    }

    kmip_print_request_message(stdout, &rm);
    printf("\n");

    char *response = NULL;
    int response_size = 0;

    printf("bio rekey send request\n");

    int result = kmip_bio_send_request_encoding(ctx, bio, (char *)encoding,
                                                ctx->index - ctx->buffer,
                                                &response, &response_size);

    printf("bio rekey response = %p\n", response);


    printf("\n");
    if(result < 0)
    {
        printf("An error occurred in rekey request.\n");
        printf("Error Code: %d\n", result);
        printf("Error Name: ");
        kmip_print_error_string(stderr, result);
        printf("\n");
        printf("Context Error: %s\n", ctx->error_message);
        printf("Stack trace:\n");
        kmip_print_stack_trace(stderr, ctx);

        kmip_free_buffer(ctx, encoding, buffer_total_size);
        kmip_free_buffer(ctx, response, response_size);
        encoding = NULL;
        response = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(result);
    }

    // kmip_free_rekey_request_payload(ctx, &rkrp);

    if (response)
    {
        FILE* out = fopen( "/tmp/kmip_rekey.dat", "w" );
        if (out)
        {
            if (fwrite( response, response_size, 1, out ) != 1 )
                fprintf(stderr, "failed writing dat file\n");
            fclose(out);
        }
        kmip_print_buffer(stdout, response, response_size);
        printf("\n");
    }

    printf("bio rekey free encoding =  %p\n", encoding);
    kmip_free_buffer(ctx, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(ctx, response, response_size);

    /* Decode the response message and retrieve the operation results. */
    ResponseMessage resp_m = {0};
    int decode_result = kmip_decode_response_message(ctx, &resp_m);

    kmip_set_buffer(ctx, NULL, 0);

    if(decode_result != KMIP_OK)
    {
        printf("An error occurred while decoding the rekey response.\n");
        printf("Error Code: %d\n", decode_result);
        printf("Error Name: ");
        kmip_print_error_string(stderr, decode_result);
        printf("\n");
        printf("Context Error: %s\n", ctx->error_message);
        printf("Stack trace:\n");
        kmip_print_stack_trace(stderr, ctx);

        kmip_free_response_message(ctx, &resp_m);
        kmip_free_buffer(ctx, response, response_size);
        response = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(decode_result);
    }

    kmip_print_response_message(stdout, &resp_m);
    printf("\n");

    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        printf("Expected to find one batch item in the rekey response.\n");
        kmip_free_response_message(ctx, &resp_m);
        kmip_free_buffer(ctx, response, response_size);
        response = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_MALFORMED_RESPONSE);
    }

    ResponseBatchItem resp_item = resp_m.batch_items[0];
    enum result_status result_status = resp_item.result_status;

    kmip_set_last_result(&resp_item);
    printf("The KMIP operation was executed with no errors.\n");
    printf("Result: ");
    kmip_print_result_status_enum(stdout, result_status);
    printf(" (%d)\n\n", result_status);

    if(result_status != KMIP_STATUS_SUCCESS)
    {
        printf("Result Reason: ");
        kmip_print_result_reason_enum(stdout, resp_item.result_reason);
        printf("\n");

        kmip_print_text_string(stdout, 0, "Result Message", resp_item.result_message);
    }

    if(result == KMIP_STATUS_SUCCESS)
    {
        RekeyResponsePayload *pld = (RekeyResponsePayload *)resp_item.response_payload;

        if (pld)
        {
            TextString *unique_identifier = pld->unique_identifier;

            /* KMIP text strings are not null-terminated by default. Add an extra */
            /* character to the end of the UUID copy to make space for the null   */
            /* terminator.                                                        */
            char *result_id = ctx->calloc_func(ctx->state,1,unique_identifier->size + 1);
            *rekey_uuid_size = unique_identifier->size;
            for(int i = 0; i < *rekey_uuid_size; i++)
                result_id[i] = unique_identifier->value[i];
            *rekey_uuid = result_id;
        }
    }

    /* Clean up the response message, the encoding buffer, and the KMIP */
    /* context. */
    kmip_free_response_message(ctx, &resp_m);
    kmip_free_buffer(ctx, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(ctx, NULL, 0);

    return(result);
}

int
use_high_level_api(BIO* bio, char *id, char** rekey_id,int* rekey_id_size)
{
    /* Set up the KMIP context and the initial encoding buffer. */
    KMIP kmip_context = {0};
    kmip_init(&kmip_context, NULL, 0, KMIP_1_0);

    /* Send the request message. */
    int result = kmip_bio_rekey_symmetric_key_with_context(&kmip_context, bio, id, kmip_strnlen_s(id, 128), KMIP_UNSET, NULL, rekey_id, rekey_id_size);
    
    /* Handle the response results. */
    printf("\n");
    if(result < 0)
    {
        printf("An error occurred while activating object: %s\n", id);
        printf("Error Code: %d\n", result);
        printf("Error Name: ");
        kmip_print_error_string(stderr, result);
        printf("\n");
        printf("Context Error: %s\n", kmip_context.error_message);
        printf("Stack trace:\n");
        kmip_print_stack_trace(stderr, &kmip_context);
    }
    else
    {
        printf("The KMIP operation was executed with no errors.\n");
        printf("Result: ");
        kmip_print_result_status_enum(stdout, result);
        printf(" (%d)\n", result);
    }
    
    /* Clean up the KMIP context and return the results. */
    kmip_destroy(&kmip_context);
    return(result);
}

int
main(int argc, char **argv)
{
    char *server_address = NULL;
    char *server_port = NULL;
    char *client_certificate = NULL;
    char *client_key = NULL;
    char *ca_certificate = NULL;
    char *id = NULL;
    int help = 0;
    
    int error = parse_arguments(argc, argv, &server_address, &server_port, &client_certificate, &client_key, &ca_certificate, &id, &help);
    if(error)
    {
        return(error);
    }
    if(help)
    {
        print_help(argv[0]);
        return(0);
    }

    printf("id=%s\n", id);
    
    /* Set up the TLS connection to the KMIP server. */
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    #if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
    OPENSSL_init_ssl(0, NULL);
    ctx = SSL_CTX_new(TLS_client_method());
    #else
    SSL_library_init();
    ctx = SSL_CTX_new(SSLv23_client_method());
    #endif

    printf("\n");
    printf("Loading the client certificate: %s\n", client_certificate);
    if(SSL_CTX_use_certificate_file(ctx, client_certificate, SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Loading the client certificate failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return(-1);
    }

    printf("Loading the client key: %s\n", client_key);
    if(SSL_CTX_use_PrivateKey_file(ctx, client_key, SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Loading the client key failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return(-1);
    }

    printf("Loading the CA certificate: %s\n", ca_certificate);
    if(SSL_CTX_load_verify_locations(ctx, ca_certificate, NULL) != 1)
    {
        fprintf(stderr, "Loading the CA file failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return(-1);
    }

    BIO *bio = NULL;
    bio = BIO_new_ssl_connect(ctx);
    if(bio == NULL)
    {
        fprintf(stderr, "BIO_new_ssl_connect failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return(-1);
    }

    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(bio, server_address);
    BIO_set_conn_port(bio, server_port);
    if(BIO_do_connect(bio) != 1)
    {
        fprintf(stderr, "BIO_do_connect failed\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return(-1);
    }

    char* rekey_id = NULL;
    int rekey_len = 0;

    int result = 0;
    int use_low = 1;
    if (use_low)
    {
        /* Set up the KMIP context and the initial encoding buffer. */
        KMIP kmip_context = {0};
        kmip_init(&kmip_context, NULL, 0, KMIP_1_0);

        result = use_low_level_api(&kmip_context, bio, id, kmip_strnlen_s(id, 128), KMIP_UNSET, NULL, &rekey_id, &rekey_len);
    }
    else
        result = use_high_level_api(bio, id, &rekey_id, &rekey_len);

    if (rekey_id)
    {
        printf("Rekey id: %s\n", rekey_id);
        free(rekey_id);
    }

    BIO_free_all(bio);
    SSL_CTX_free(ctx);

    return(result);
}
