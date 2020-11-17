// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// CAVEAT: This sample is to demonstrate azure IoT client concepts only and is not a guide design principles or style
// Checking of return codes and error values shall be omitted for brevity.  Please practice sound engineering practices
// when writing production code.

#include <stdio.h>
#include <stdlib.h>

#include "iothub.h"
#include "iothub_device_client_ll.h"
#include "iothub_client_options.h"
#include "iothub_message.h"
#include "azure_c_shared_utility/threadapi.h"
#include "azure_c_shared_utility/shared_util_options.h"

/* This sample uses the _LL APIs of iothub_client for example purposes.
Simply changing the using the convenience layer (functions not having _LL)
and removing calls to _DoWork will yield the same results. */

// The protocol you wish to use should be uncommented
//
#define SAMPLE_MQTT
//#define SAMPLE_MQTT_OVER_WEBSOCKETS
//#define SAMPLE_AMQP
//#define SAMPLE_AMQP_OVER_WEBSOCKETS
//#define SAMPLE_HTTP

#ifdef SAMPLE_MQTT
    #include "iothubtransportmqtt.h"
#endif // SAMPLE_MQTT
#ifdef SAMPLE_MQTT_OVER_WEBSOCKETS
    #include "iothubtransportmqtt_websockets.h"
#endif // SAMPLE_MQTT_OVER_WEBSOCKETS
#ifdef SAMPLE_AMQP
    #include "iothubtransportamqp.h"
#endif // SAMPLE_AMQP
#ifdef SAMPLE_AMQP_OVER_WEBSOCKETS
    #include "iothubtransportamqp_websockets.h"
#endif // SAMPLE_AMQP_OVER_WEBSOCKETS
#ifdef SAMPLE_HTTP
    #include "iothubtransporthttp.h"
#endif // SAMPLE_HTTP

#ifdef MBED_BUILD_TIMESTAMP
    #define SET_TRUSTED_CERT_IN_SAMPLES
#endif // MBED_BUILD_TIMESTAMP

#ifdef SET_TRUSTED_CERT_IN_SAMPLES
    #include "certs.h"
#endif // SET_TRUSTED_CERT_IN_SAMPLES


//#define TPM2TSS
#define ISKS
//#define ISKS_DIRECT

#ifdef TPM2TSS
/* Paste in the your x509 iothub connection string  */
/*  "HostName=<host_name>;DeviceId=<device_id>;x509=true"                      */
static const char* connectionString = "HostName=crispop-iothub1.azure-devices.net;DeviceId=tpm2engine;x509=true";

static const char* opensslEngine = "tpm2tss";
static const char* x509certificate =
"-----BEGIN CERTIFICATE-----\n"
"MIIBJTCBywIUUennAV2WbZsckSIcMHLXuak/iCswCgYIKoZIzj0EAwIwFTETMBEG\n"
"A1UEAwwKdHBtMmVuZ2luZTAeFw0yMDExMDQyMzQyNDJaFw0yMTExMDQyMzQyNDJa\n"
"MBUxEzARBgNVBAMMCnRwbTJlbmdpbmUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\n"
"AAT8+wQr2MJV6x/ds+IWc0mknJbE8QIRHEHaW6BopGHd6Xll5aBvHt/HtSCHCXcX\n"
"IcUscCQpMZJh18ZuYYamn+ovMAoGCCqGSM49BAMCA0kAMEYCIQD3ERO717bt6lDy\n"
"OkZcAK4VBLwYnoH+glXK6pWqDkXE0wIhAM0OFOTbVIuXOGDXaCKxFLIvMifo2RJZ\n"
"b5pjgB2gaGGi\n"
"-----END CERTIFICATE-----\n";

static const char* x509privatekey = "/home/cristian/cert/tpm2ec.tss";
static const OPTION_OPENSSL_KEY_TYPE x509keyengine = KEY_TYPE_ENGINE;
#endif

#ifdef ISKS
/* Paste in the your x509 iothub connection string  */
/*  "HostName=<host_name>;DeviceId=<device_id>;x509=true"                      */
static const char* connectionString = "HostName=crispop-iothub1.azure-devices.net;DeviceId=iot-key-service1;x509=true";

static const char* opensslEngine = "aziot_keys";
static const char* x509certificate = 
"-----BEGIN CERTIFICATE-----\n"
"MIIBMTCB1wIUTu66kxJIBR5t5IkAwh7Lqm/AM+IwCgYIKoZIzj0EAwIwGzEZMBcG\n"
"A1UEAwwQaW90LWtleS1zZXJ2aWNlMTAeFw0yMDEwMzAwMDQwMTZaFw0yMTEwMzAw\n"
"MDQwMTZaMBsxGTAXBgNVBAMMEGlvdC1rZXktc2VydmljZTEwWTATBgcqhkjOPQIB\n"
"BggqhkjOPQMBBwNCAARuUKXqZvNDCOhqdRMhOluD5xpm00E5arOXbqrqrCrOhjT4\n"
"7o3NamR9UPuC3Nbp9qTckzcQMoWPu9hgGkbniBN0MAoGCCqGSM49BAMCA0kAMEYC\n"
"IQC2hvx3haS3kxpIQzrzsKKpWlAGed0z7dn2HOY4x5bzlwIhAKyYtxbF62laYahF\n"
"DItkq1MHqzqExB1eTrMHQVY11w62\n"
"-----END CERTIFICATE-----\n";

static const char* x509privatekey = "sr=eyJrZXlfaWQiOnsiS2V5UGFpciI6ImRldmljZS1pZCJ9LCJub25jZSI6IlQ2eWo3cE0vMHY5anAyNm5qL2NFWUdNZjFTL2lSRGdKMnpEeWpoNkQycE52S0FhdStEdGNhNXNkd2dWbGZKaVlkbHJKeG5wOE1XdmpDcnhmd1A4eHhRPT0ifQ==&sig=wITb99HtU/zGwtvKYW6dlkjtPK2ljVqUjmC9gqvZTmw=";

static const OPTION_OPENSSL_KEY_TYPE x509keyengine = KEY_TYPE_ENGINE;
#endif

#ifdef ISKS_DIRECT


#endif

#define MESSAGE_COUNT        5
static bool g_continueRunning = true;
static size_t g_message_count_send_confirmations = 0;

typedef struct EVENT_INSTANCE_TAG
{
    IOTHUB_MESSAGE_HANDLE messageHandle;
    size_t messageTrackingId;  // For tracking the messages within the user callback.
} EVENT_INSTANCE;

static void send_confirm_callback(IOTHUB_CLIENT_CONFIRMATION_RESULT result, void* userContextCallback)
{
    (void)userContextCallback;
    // When a message is sent this callback will get envoked
    g_message_count_send_confirmations++;
    (void)printf("Confirmation callback received for message %zu with result %s\r\n", g_message_count_send_confirmations, MU_ENUM_TO_STRING(IOTHUB_CLIENT_CONFIRMATION_RESULT, result));
}

int main(void)
{
    IOTHUB_CLIENT_TRANSPORT_PROVIDER protocol;
    IOTHUB_MESSAGE_HANDLE message_handle;
    size_t messages_sent = 0;
    const char* telemetry_msg = "test_message";

    // Select the Protocol to use with the connection
#ifdef SAMPLE_MQTT
    protocol = MQTT_Protocol;
#endif // SAMPLE_MQTT
#ifdef SAMPLE_MQTT_OVER_WEBSOCKETS
    protocol = MQTT_WebSocket_Protocol;
#endif // SAMPLE_MQTT_OVER_WEBSOCKETS
#ifdef SAMPLE_AMQP
    protocol = AMQP_Protocol;
#endif // SAMPLE_AMQP
#ifdef SAMPLE_AMQP_OVER_WEBSOCKETS
    protocol = AMQP_Protocol_over_WebSocketsTls;
#endif // SAMPLE_AMQP_OVER_WEBSOCKETS
#ifdef SAMPLE_HTTP
    protocol = HTTP_Protocol;
#endif // SAMPLE_HTTP

    IOTHUB_DEVICE_CLIENT_LL_HANDLE device_ll_handle;

    // Used to initialize IoTHub SDK subsystem
    (void)IoTHub_Init();

    (void)printf("Creating IoTHub handle\r\n");
    // Create the iothub handle here
    device_ll_handle = IoTHubDeviceClient_LL_CreateFromConnectionString(connectionString, protocol);
    if (device_ll_handle == NULL)
    {
        (void)printf("Failure creating IotHub device. Hint: Check your connection string.\r\n");
    }
    else
    {
        // Set any option that are neccessary.
        // For available options please see the iothub_sdk_options.md documentation
        bool traceOn = true;
        IoTHubDeviceClient_LL_SetOption(device_ll_handle, OPTION_LOG_TRACE, &traceOn);

        // Setting the Trusted Certificate. This is only necessary on systems without
        // built in certificate stores.
#ifdef SET_TRUSTED_CERT_IN_SAMPLES
        IoTHubDeviceClient_LL_SetOption(device_ll_handle, OPTION_TRUSTED_CERT, certificates);
#endif // SET_TRUSTED_CERT_IN_SAMPLES

        // Set the X509 certificates in the SDK
        if (
            (IoTHubDeviceClient_LL_SetOption(device_ll_handle, OPTION_OPENSSL_ENGINE, opensslEngine) != IOTHUB_CLIENT_OK) ||
            (IoTHubDeviceClient_LL_SetOption(device_ll_handle, OPTION_X509_CERT, x509certificate) != IOTHUB_CLIENT_OK) ||
            (IoTHubDeviceClient_LL_SetOption(device_ll_handle, OPTION_X509_PRIVATE_KEY, x509privatekey) != IOTHUB_CLIENT_OK) || 
            //(IoTHubDeviceClient_LL_SetOption(device_ll_handle, OPTION_OPENSSL_CERT_TYPE, &x509keyengine) != IOTHUB_CLIENT_OK) || 
            (IoTHubDeviceClient_LL_SetOption(device_ll_handle, OPTION_OPENSSL_PRIVATE_KEY_TYPE, &x509keyengine) != IOTHUB_CLIENT_OK)
            )
        {
            printf("failure to set options for x509, aborting\r\n");
        }
        else
        {
            do
            {
                if (messages_sent < MESSAGE_COUNT)
                {
                    // Construct the iothub message from a string or a byte array
                    message_handle = IoTHubMessage_CreateFromString(telemetry_msg);
                    //message_handle = IoTHubMessage_CreateFromByteArray((const unsigned char*)msgText, strlen(msgText)));

                    // Set Message property
                    (void)IoTHubMessage_SetMessageId(message_handle, "MSG_ID");
                    (void)IoTHubMessage_SetCorrelationId(message_handle, "CORE_ID");
                    (void)IoTHubMessage_SetContentTypeSystemProperty(message_handle, "application%2Fjson");
                    (void)IoTHubMessage_SetContentEncodingSystemProperty(message_handle, "utf-8");

                    // Add custom properties to message
                    (void)IoTHubMessage_SetProperty(message_handle, "property_key", "property_value");

                    (void)printf("Sending message %d to IoTHub\r\n", (int)(messages_sent + 1));
                    IoTHubDeviceClient_LL_SendEventAsync(device_ll_handle, message_handle, send_confirm_callback, NULL);

                    // The message is copied to the sdk so the we can destroy it
                    IoTHubMessage_Destroy(message_handle);

                    messages_sent++;
                }
                else if (g_message_count_send_confirmations >= MESSAGE_COUNT)
                {
                    // After all messages are all received stop running
                    g_continueRunning = false;
                }

                IoTHubDeviceClient_LL_DoWork(device_ll_handle);
                ThreadAPI_Sleep(1);

            } while (g_continueRunning);
        }
        // Clean up the iothub sdk handle
        IoTHubDeviceClient_LL_Destroy(device_ll_handle);
    }
    // Free all the sdk subsystem
    IoTHub_Deinit();

    printf("Press any key to continue");
    (void)getchar();

    return 0;
}
