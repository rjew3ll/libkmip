/* Copyright (c) 2018 The Johns Hopkins University/Applied Physics Labora`tory
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
#include "kmip_memset.h"

void
print_help(const char *app)
{
    printf("Usage: %s [flag value | flag] ...\n\n", app);
    printf("Flags:\n");
    printf("-a addr : the IP address of the KMIP server\n");
    printf("-c path : path to client certificate file\n");
    printf("-h      : print this help info\n");
    printf("-k path : path to client key file\n");
    printf("-p port : the port number of the KMIP server\n");
    printf("-r path : path to CA certificate file\n");
    printf("-i id   : the ID of the item to get\n");
    printf("-n %d   : get uuid\n", KMIP_ATTR_UNIQUE_IDENTIFIER);
    printf("-n %d   : get name\n", KMIP_ATTR_NAME);
    printf("-n %d   : get link\n", KMIP_ATTR_LINK);
    printf("-n %d   : get operationpolicy name\n", KMIP_ATTR_OPERATION_POLICY_NAME);
    printf("-n %d   : get state\n", KMIP_ATTR_STATE);
    printf("-n %d   : get object group\n", KMIP_ATTR_OBJECT_GROUP);
    printf("-n %d   : get contact information\n", KMIP_ATTR_CONTACT_INFORMATION);
    printf("-n %d   : get activation date\n", KMIP_ATTR_ACTIVATION_DATE);
    printf("-n %d   : get deactivation date\n", KMIP_ATTR_DEACTIVATION_DATE);
    printf("-n %d   : get process start date\n", KMIP_ATTR_PROCESS_START_DATE);
    printf("-n %d   : get process stop date\n", KMIP_ATTR_PROTECT_STOP_DATE);
}

int
parse_arguments(int argc, char **argv,
                char **server_address, char **server_port,
                char **client_certificate, char **client_key, char **ca_certificate,
                char **uuid,
                enum attribute_type* attribs, size_t* attrib_count,
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
        else if(strncmp(argv[i], "-i", 2) == 0)
        {
            *uuid = argv[++i];
        }
        else if(strncmp(argv[i], "-n", 2) == 0)
        {
            attribs[*attrib_count] = atoi(argv[++i]);
            *attrib_count = *attrib_count + 1;
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


void *
demo_calloc(void *state, size_t num, size_t size)
{
    void* ptr = calloc(num, size);
    printf("demo_calloc called: state = %p, num = %zu, size = %zu, ptr = %p\n", state, num, size, ptr);
    return(ptr);
}

void *
demo_realloc(void *state, void *ptr, size_t size)
{
    void* reptr = realloc(ptr, size);
    printf("demo_realloc called: state = %p, ptr = %p, size = %zu, reptr = %p\n", state, ptr, size, reptr);
    return(realloc(reptr, size));
}

void
demo_free(void *state, void *ptr)
{
    printf("demo_free called: state = %p, ptr = %p\n", state, ptr);
    free(ptr);
    return;
}


int use_low_level_api(KMIP *ctx, BIO *bio, char *uuid, enum attribute_type* attribs, size_t attrib_count, GetAttributesResponse* getattributes_result)
{
    if (ctx == NULL || bio == NULL || getattributes_result == NULL)
    {
        return(KMIP_ARG_INVALID);
    }
    if ( attribs == NULL && attrib_count != 0)
    {
        return(KMIP_ARG_INVALID);
    }

    printf("bio get_attribute start \n");

    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;

    uint8 *encoding = ctx->calloc_func(ctx->state, buffer_blocks, buffer_block_size);
    if(encoding == NULL)
    {
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
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

    TextString id = {0};
    id.value = uuid;
    id.size = strlen(uuid);;

    // convert input array of attr types to list of attribute names
    AttributeNames names = {0};
    LinkedList *name_list = ctx->calloc_func(ctx->state, 1, sizeof(LinkedList));
    for(size_t i = 0; i < attrib_count; i++)
    {
        LinkedListItem *item = ctx->calloc_func(ctx->state, 1, sizeof(LinkedListItem));

        TextString attrname = {0};
        char nametext[MAX_GETATTR_LEN] = "";

        kmip_get_attribute_type_text(nametext, sizeof(nametext), attribs[i]);

        attrname.value = nametext;
        attrname.size = strlen(nametext);

        item->data = kmip_deep_copy_text_string(ctx, &attrname);
        kmip_linked_list_enqueue(name_list, item);
    }
    names.name_list = name_list;

    GetAttributesRequestPayload garp = {0};
    garp.attribute_names = &names;
    garp.unique_identifier = &id;

    RequestBatchItem rbi = {0};
    kmip_init_request_batch_item(&rbi);
    rbi.operation = KMIP_OP_GET_ATTRIBUTES;
    rbi.request_payload = &garp;

    RequestMessage rm = {0};
    rm.request_header = &rh;
    rm.batch_items = &rbi;
    rm.batch_count = 1;

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
            printf("Failure: Could not automatically enlarge the encoding ");
            printf("buffer for the get attribute request.\n");

            return(KMIP_MEMORY_ALLOC_FAILED);
        }
        printf("encoding = %p\n", encoding);

        kmip_set_buffer(ctx, encoding, buffer_total_size);
        encode_result = kmip_encode_request_message(ctx, &rm);
    }

    if(encode_result != KMIP_OK)
    {
        printf("An error occurred while encoding the get attribute request.\n");
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

    printf("bio get attribute send request\n");

    int result = kmip_bio_send_request_encoding(ctx, bio, (char *)encoding,
                                                ctx->index - ctx->buffer, 
                                                &response, &response_size);

    printf("bio get attribute response = %p\n", response);


    printf("\n");
    if(result < 0)
    {
        printf("An error occurred in get attribute request.\n");
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

    kmip_free_attribute_names(ctx, &names);

    if (response)
    {
        FILE* out = fopen( "/tmp/kmip_get_attributes.dat", "w" );
        if (out)
        {
            if (fwrite( response, response_size, 1, out ) != 1 )
                fprintf(stderr, "failed writing dat file\n");
            fclose(out);
        }
        kmip_print_buffer(stdout, response, response_size);
        printf("\n");
    }

    printf("bio get attributes free encoding =  %p\n", encoding);
    kmip_free_buffer(ctx, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(ctx, response, response_size);

    /* Decode the response message and retrieve the operation results. */
    ResponseMessage resp_m = {0};
    int decode_result = kmip_decode_response_message(ctx, &resp_m);
    if(decode_result != KMIP_OK)
    {
        printf("An error occurred while decoding the get attributes response.\n");
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
        printf("Expected to find one batch item in the get attributes response.\n");
        kmip_free_response_message(ctx, &resp_m);
        kmip_free_buffer(ctx, response, response_size);
        response = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        return(KMIP_MALFORMED_RESPONSE);
    }

    ResponseBatchItem req = resp_m.batch_items[0];
    enum result_status result_status = req.result_status;

    printf("The KMIP operation was executed with no errors.\n");
    printf("Result: ");
    kmip_print_result_status_enum(stdout, result);
    printf(" (%d)\n\n", result);

    if(result == KMIP_STATUS_SUCCESS)
    {
        kmip_copy_get_attributes_result(getattributes_result, (GetAttributesResponsePayload*) req.response_payload);
    }

    printf("bio get attributes free response resp_m =  %p, response = %p\n", (void*)&resp_m, response);

    /* Clean up the response message, the response buffer, and the KMIP */
    /* context.                                                         */
    kmip_free_response_message(ctx, &resp_m);
    kmip_free_buffer(ctx, response, response_size);
    response = NULL;

    kmip_set_buffer(ctx, NULL, 0);

    printf("bio get attr done \n");

    return(result_status);
}


int
use_mid_level_api(BIO* bio,
                  char *uuid,
                  enum attribute_type* attribs, size_t attrib_count,
                  GetAttributesResponse* getattributes_result)
{
    int result;

    /* Set up the KMIP context and send the request message. */
    KMIP kmip_context = {0};

    kmip_init(&kmip_context, NULL, 0, KMIP_1_0);
    
    result = kmip_bio_get_attributes_with_context(&kmip_context, bio, uuid, attribs, attrib_count, getattributes_result);
    
    /* Handle the response results. */
    printf("\n");
    if(result < 0)
    {
        printf("An error occurred while running the get attribute.");
        printf("Error Code: %d\n", result);
        printf("Error Name: ");
        kmip_print_error_string(stderr, result);
        printf("\n");
        printf("Context Error: %s\n", kmip_context.error_message);
        printf("Stack trace:\n");
        kmip_print_stack_trace(stderr, &kmip_context);
    }
    else if(result >= 0)
    {
        printf("The KMIP operation was executed with no errors.\n");
        printf("Result: ");
        kmip_print_result_status_enum(stdout, result);
        printf(" (%d)\n", result);
        
        if(result == KMIP_STATUS_SUCCESS)
        {
            printf("get attributes results: ");
            printf("got : %ld\n", (long)getattributes_result->attr_size);
            printf("\n");
        }
    }
    
    printf("\n");
    
    /* Clean up the KMIP context and return the results. */
    kmip_set_buffer(&kmip_context, NULL, 0);
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
    char *uuid = NULL;
    enum attribute_type attribs[128];
    size_t attrib_count = 0;

    int help = 0;
    
    int error = parse_arguments(argc, argv, &server_address, &server_port,
                                &client_certificate, &client_key, &ca_certificate, 
                                &uuid, attribs, &attrib_count, &help);
    if(error)
    {
        return(error);
    }
    if(help)
    {
        print_help(argv[0]);
        return(0);
    }

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

    int result;
    GetAttributesResponse getattributes_result = {0};

    int use_low = 1;
    if (use_low)
    {
        KMIP kmip_context = {0};
        kmip_init(&kmip_context, NULL, 0, KMIP_1_0);
        result = use_low_level_api(&kmip_context, bio, uuid, attribs, attrib_count, &getattributes_result);
        kmip_destroy(&kmip_context);
    }
    else
    {
        result = use_mid_level_api(bio, uuid, attribs, attrib_count, &getattributes_result);
    }

    if(result == KMIP_STATUS_SUCCESS)
    {
        printf("get attr results: ");
        printf("returned items: %zu\n", getattributes_result.attr_size);
        for (int i=0; i<(int)getattributes_result.attr_size; i++)
        {
            if (getattributes_result.attr_info[i].attr_subtype[0] != 0)
            {
                printf("attr[%d]: \"%s(%s)\" = %s\n", i,
                       getattributes_result.attr_info[i].attr_name,
                       getattributes_result.attr_info[i].attr_subtype,
                       getattributes_result.attr_info[i].attr_value);
            }
            else
            {
                printf("attr[%d]: \"%s\" = %s\n", i,
                       getattributes_result.attr_info[i].attr_name,
                       getattributes_result.attr_info[i].attr_value);
            }
        }
        printf("\n");
    }

    BIO_free_all(bio);
    SSL_CTX_free(ctx);

    return(result);
}
