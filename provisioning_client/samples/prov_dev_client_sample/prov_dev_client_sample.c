// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// CAVEAT: This sample is to demonstrate azure IoT client concepts only and is not a guide design principles or style
// Checking of return codes and error values shall be omitted for brevity.  Please practice sound engineering practices
// when writing production code.

#include <stdio.h>
#include <stdlib.h>

#include "iothub.h"
#include "azure_c_shared_utility/shared_util_options.h"
#include "azure_c_shared_utility/http_proxy_io.h"
#include "azure_c_shared_utility/threadapi.h"

#include "azure_prov_client/prov_device_client.h"
#include "azure_prov_client/prov_security_factory.h"

#include "iothub_client_options.h"
#include "iothub_device_client.h"

#ifdef SET_TRUSTED_CERT_IN_SAMPLES
#include "certs.h"
#endif // SET_TRUSTED_CERT_IN_SAMPLES

//
// The protocol you wish to use should be uncommented
//
//#define SAMPLE_MQTT
//#define SAMPLE_MQTT_OVER_WEBSOCKETS
#define SAMPLE_AMQP
//#define SAMPLE_AMQP_OVER_WEBSOCKETS
//#define SAMPLE_HTTP

#ifdef SAMPLE_MQTT
#include "iothubtransportmqtt.h"
#include "azure_prov_client/prov_transport_mqtt_client.h"
#endif // SAMPLE_MQTT
#ifdef SAMPLE_MQTT_OVER_WEBSOCKETS
#include "iothubtransportmqtt_websockets.h"
#include "azure_prov_client/prov_transport_mqtt_ws_client.h"
#endif // SAMPLE_MQTT_OVER_WEBSOCKETS
#ifdef SAMPLE_AMQP
#include "iothubtransportamqp.h"
#include "azure_prov_client/prov_transport_amqp_client.h"
#endif // SAMPLE_AMQP
#ifdef SAMPLE_AMQP_OVER_WEBSOCKETS
#include "iothubtransportamqp_websockets.h"
#include "azure_prov_client/prov_transport_amqp_ws_client.h"
#endif // SAMPLE_AMQP_OVER_WEBSOCKETS
#ifdef SAMPLE_HTTP
#include "iothubtransporthttp.h"
#include "azure_prov_client/prov_transport_http_client.h"
#endif // SAMPLE_HTTP

#ifdef SET_TRUSTED_CERT_IN_SAMPLES
#include "certs.h"
#endif // SET_TRUSTED_CERT_IN_SAMPLES

int tpm_sim_port = 2321;
int tpm_sim_platform_port = 2322;


// This sample is to demostrate iothub reconnection with provisioning and should not
// be confused as production code

MU_DEFINE_ENUM_STRINGS_WITHOUT_INVALID(PROV_DEVICE_RESULT, PROV_DEVICE_RESULT_VALUE);
MU_DEFINE_ENUM_STRINGS_WITHOUT_INVALID(PROV_DEVICE_REG_STATUS, PROV_DEVICE_REG_STATUS_VALUES);

static const char* global_prov_uri = "global.azure-devices-provisioning.net";
static const char* id_scope = "0ne00003E26";

volatile static bool g_registration_complete = false;
static bool g_use_proxy = false;
static const char* PROXY_ADDRESS = "127.0.0.1";

static char g_iothub[256];
static char g_device_id[256];
volatile static bool g_message_sent = false;

#define PROXY_PORT                  8888
#define MESSAGES_TO_SEND            2
#define TIME_BETWEEN_MESSAGES       2

static void registration_status_callback(PROV_DEVICE_REG_STATUS reg_status, void* user_context)
{
    (void)user_context;
    (void)printf("Provisioning Status: %s\r\n", MU_ENUM_TO_STRING(PROV_DEVICE_REG_STATUS, reg_status));
}

static void register_device_callback1(PROV_DEVICE_RESULT register_result, const char* iothub_uri, const char* device_id, void* user_context)
{
    (void)user_context;
    if (register_result == PROV_DEVICE_RESULT_OK)
    {
        (void)printf("\r\nRegistration Information received from service: %s, deviceId: %s\r\n", iothub_uri, device_id);
        strcpy(g_iothub, iothub_uri);
        strcpy(g_device_id, device_id);
    }
    else
    {
        (void)printf("\r\nFailure registering device: %s\r\n", MU_ENUM_TO_STRING(PROV_DEVICE_RESULT, register_result));
    }
    g_registration_complete = true;
}

static void message_callback(IOTHUB_CLIENT_CONFIRMATION_RESULT result, void* userContextCallback)
{
    if (result == IOTHUB_CLIENT_CONFIRMATION_OK)
    {
        (void)printf("\r\nMessage sent.\r\n");    
    }
    else
    {
        (void)printf("\r\nError sending message: 0x%x\r\n", result);
    }
    
    g_message_sent = true;
}


int main()
{
    SECURE_DEVICE_TYPE hsm_type;
    hsm_type = SECURE_DEVICE_TYPE_TPM;
    //hsm_type = SECURE_DEVICE_TYPE_X509;
    //hsm_type = SECURE_DEVICE_TYPE_SYMMETRIC_KEY;

    // Used to initialize IoTHub SDK subsystem
    (void)IoTHub_Init();
    (void)prov_dev_security_init(hsm_type);

    // Set the symmetric key if using they auth type
    //prov_dev_set_symmetric_key_info("<symm_registration_id>", "<symmetric_Key>");

    HTTP_PROXY_OPTIONS http_proxy;
    PROV_DEVICE_TRANSPORT_PROVIDER_FUNCTION prov_transport;

    memset(&http_proxy, 0, sizeof(HTTP_PROXY_OPTIONS));

    // Protocol to USE - HTTP, AMQP, AMQP_WS, MQTT, MQTT_WS
#ifdef SAMPLE_MQTT
    prov_transport = Prov_Device_MQTT_Protocol;
#endif // SAMPLE_MQTT
#ifdef SAMPLE_MQTT_OVER_WEBSOCKETS
    prov_transport = Prov_Device_MQTT_WS_Protocol;
#endif // SAMPLE_MQTT_OVER_WEBSOCKETS
#ifdef SAMPLE_AMQP
    prov_transport = Prov_Device_AMQP_Protocol;
#endif // SAMPLE_AMQP
#ifdef SAMPLE_AMQP_OVER_WEBSOCKETS
    prov_transport = Prov_Device_AMQP_WS_Protocol;
#endif // SAMPLE_AMQP_OVER_WEBSOCKETS
#ifdef SAMPLE_HTTP
    prov_transport = Prov_Device_HTTP_Protocol;
#endif // SAMPLE_HTTP

    printf("Provisioning API Version: %s\r\n", Prov_Device_GetVersionString());

    if (g_use_proxy)
    {
        http_proxy.host_address = PROXY_ADDRESS;
        http_proxy.port = PROXY_PORT;
    }

    PROV_DEVICE_RESULT prov_device_result = PROV_DEVICE_RESULT_ERROR;
    PROV_DEVICE_HANDLE h1;
    PROV_DEVICE_HANDLE h2;
    if ((h1 = Prov_Device_Create(global_prov_uri, id_scope, prov_transport)) == NULL)
    {
        (void)printf("failed calling Prov_Device_Create\r\n");
    }
    else
    {
        if (http_proxy.host_address != NULL)
        {
            Prov_Device_SetOption(h1, OPTION_HTTP_PROXY, &http_proxy);
        }

        bool traceOn = true;
        Prov_Device_SetOption(h1, PROV_OPTION_LOG_TRACE, &traceOn);       

        // This option sets the registration ID it overrides the registration ID that is 
        // set within the HSM so be cautious if setting this value
        //Prov_Device_SetOption(h1, PROV_REGISTRATION_ID, "[REGISTRATION ID]");

        prov_device_result = Prov_Device_Register_Device(h1, register_device_callback1, NULL, registration_status_callback, NULL);

        (void)printf("\r\nRegistering Device\r\n\r\n");
        do
        {
            ThreadAPI_Sleep(1000);
        } while (!g_registration_complete);

        Prov_Device_Destroy(h1);
    }
    prov_dev_security_deinit();
    
    g_registration_complete=false;
    tpm_sim_platform_port+=1000;
    tpm_sim_port+=1000;

    if ((h2 = Prov_Device_Create(global_prov_uri, id_scope, prov_transport)) == NULL)
    {
        (void)printf("failed calling Prov_Device_Create\r\n");
    }
    else
    {
        if (http_proxy.host_address != NULL)
        {
            Prov_Device_SetOption(h2, OPTION_HTTP_PROXY, &http_proxy);
        }

        bool traceOn = true;
        Prov_Device_SetOption(h2, PROV_OPTION_LOG_TRACE, &traceOn);       

        // This option sets the registration ID it overrides the registration ID that is 
        // set within the HSM so be cautious if setting this value
        //Prov_Device_SetOption(h2, PROV_REGISTRATION_ID, "[REGISTRATION ID]");

        prov_device_result = Prov_Device_Register_Device(h2, register_device_callback1, NULL, registration_status_callback, NULL);

        (void)printf("\r\nRegistering Device\r\n\r\n");
        do
        {
            ThreadAPI_Sleep(1000);
        } while (!g_registration_complete);

        Prov_Device_Destroy(h2);
    }
    prov_dev_security_deinit();
    

    tpm_sim_platform_port-=1000;
    tpm_sim_port-=1000;
    IOTHUB_DEVICE_CLIENT_HANDLE hub1, hub2;
    
    if ((hub1 = IoTHubDeviceClient_CreateFromDeviceAuth(g_iothub, g_device_id, AMQP_Protocol)) == NULL)
    {
        (void)printf("Failed to create IoTHub Device");
        return 1;
    }

    tpm_sim_platform_port+=1000;
    tpm_sim_port+=1000;
    if ((hub2 = IoTHubDeviceClient_CreateFromDeviceAuth(g_iothub, g_device_id, AMQP_Protocol)) == NULL)
    {
        (void)printf("Failed to create IoTHub Device");
        return 1;
    }

    bool traceOn = true;
    (void)IoTHubDeviceClient_SetOption(hub1, OPTION_LOG_TRACE, &traceOn);
    (void)IoTHubDeviceClient_SetOption(hub2, OPTION_LOG_TRACE, &traceOn);

    IOTHUB_MESSAGE_HANDLE message1 = IoTHubMessage_CreateFromString("Hello World 1!");
    IOTHUB_MESSAGE_HANDLE message2 = IoTHubMessage_CreateFromString("Hello World 2!");
    IoTHubDeviceClient_SendEventAsync(hub1, message1, message_callback, NULL);
    IoTHubDeviceClient_SendEventAsync(hub2, message2, message_callback, NULL);

    (void)printf("\r\nSending message...\r\n\r\n");
    do
    {
        ThreadAPI_Sleep(1000);
    } while (!g_message_sent);

    IoTHubMessage_Destroy(message1);
    IoTHubMessage_Destroy(message2);

    // Free all the sdk subsystem
    IoTHub_Deinit();


    (void)printf("Press enter key to exit:\r\n");
    (void)getchar();

    return 0;
}
