#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_ota_ops.h"
#include "esp_http_client.h"
#include "esp_app_desc.h"
#include "mqtt_client.h"

#include "nvs_flash.h"
#include "nvs.h"
#include "esp_netif.h"

#include "esp_http_server.h"

#include "driver/gpio.h"

#include "mbedtls/base64.h"

/* ─────────────────────────────────────────
   CONFIGURACION
   ───────────────────────────────────────── */

#define CONFIG_AP_SSID      "ESP32_CONFIG"
#define CONFIG_AP_PASS      "config1234"

#define RELAY_GPIO          2
#define LED_GPIO            4

#define WIFI_MAX_RETRY      20
#define ANTISPAM_MS         3000
#define RELAY_ON_MS         500
#define RELAY_FAILSAFE_US   2000000

#define OTA_FIRMWARE_URL    "http://192.168.19.134:8080/firmware.bin"

/* ── ThingsBoard MQTT ── */
#define MQTT_BROKER         "mqtt://192.168.19.134:1884"
#define MQTT_TOKEN          "T3GkykrqyewShDhDyrIM"
#define MQTT_TELEMETRY      "v1/devices/me/telemetry"
#define MQTT_ATTRIBUTES     "v1/devices/me/attributes"
#define MQTT_RPC_REQUEST    "v1/devices/me/rpc/request/+"
#define MQTT_RPC_RESPONSE   "v1/devices/me/rpc/response/%d"
#define MQTT_TELEMETRY_MS   30000    /* publicar estado cada 30 segundos */

static const char *TAG = "SYSTEM";


/* ─────────────────────────────────────────
   ESTADO GLOBAL
   ───────────────────────────────────────── */

static TaskHandle_t    relay_task_handle = NULL;
static httpd_handle_t  server            = NULL;

static bool  wifi_conectado      = false;
static bool  modo_configuracion  = false;
static int   wifi_retry_count    = 0;

static int64_t last_open_time   = 0;
static int64_t relay_start_time = 0;

static bool ota_en_progreso = false;

/* MQTT */
static esp_mqtt_client_handle_t mqtt_client  = NULL;
static bool                     mqtt_conectado = false;


/* ─────────────────────────────────────────
   NVS – CREDENCIALES AUTH
   ───────────────────────────────────────── */

static void save_default_credentials(void)
{
    nvs_handle_t nvs;

    if (nvs_open("auth", NVS_READWRITE, &nvs) != ESP_OK)
    {
        ESP_LOGE(TAG, "No se pudo abrir NVS para credenciales");
        return;
    }

    size_t len = 0;

    if (nvs_get_str(nvs, "user", NULL, &len) == ESP_ERR_NVS_NOT_FOUND)
    {
        nvs_set_str(nvs, "user", "admin");
        nvs_set_str(nvs, "pass", "1234");
        nvs_commit(nvs);
        ESP_LOGI(TAG, "Credenciales por defecto guardadas en NVS");
    }

    nvs_close(nvs);
}


/* ─────────────────────────────────────────
   NVS – WIFI
   ───────────────────────────────────────── */

/**
 * Lee SSID y password WiFi desde NVS.
 * Retorna true si existen, false si no.
 */
static bool load_wifi_config(char *ssid, size_t ssid_len,
                             char *pass, size_t pass_len)
{
    nvs_handle_t nvs;

    if (nvs_open("wifi_cfg", NVS_READONLY, &nvs) != ESP_OK)
        return false;

    bool ok = (nvs_get_str(nvs, "ssid", ssid, &ssid_len) == ESP_OK &&
               nvs_get_str(nvs, "pass", pass, &pass_len) == ESP_OK);

    nvs_close(nvs);
    return ok;
}

/**
 * Guarda SSID y password WiFi en NVS.
 */
static void save_wifi_config(const char *ssid, const char *pass)
{
    nvs_handle_t nvs;

    if (nvs_open("wifi_cfg", NVS_READWRITE, &nvs) != ESP_OK)
    {
        ESP_LOGE(TAG, "No se pudo abrir NVS para WiFi");
        return;
    }

    nvs_set_str(nvs, "ssid", ssid);
    nvs_set_str(nvs, "pass", pass);
    nvs_commit(nvs);
    nvs_close(nvs);

    ESP_LOGI(TAG, "WiFi guardado en NVS: SSID=%s", ssid);
}


/* ─────────────────────────────────────────
   AUTENTICACION HTTP BASIC
   ───────────────────────────────────────── */

static bool check_auth(httpd_req_t *req)
{
    char auth_header[128] = {0};

    if (httpd_req_get_hdr_value_str(req, "Authorization",
                                    auth_header, sizeof(auth_header)) != ESP_OK)
        goto fail;

    if (strncmp(auth_header, "Basic ", 6) != 0)
        goto fail;

    const char *b64_recibido = auth_header + 6;

    nvs_handle_t nvs;
    char stored_user[32] = {0};
    char stored_pass[32] = {0};

    if (nvs_open("auth", NVS_READONLY, &nvs) != ESP_OK)
    {
        ESP_LOGE(TAG, "No se pudo leer NVS en check_auth");
        goto fail;
    }

    size_t u_len = sizeof(stored_user);
    size_t p_len = sizeof(stored_pass);

    nvs_get_str(nvs, "user", stored_user, &u_len);
    nvs_get_str(nvs, "pass", stored_pass, &p_len);
    nvs_close(nvs);

    char expected[64] = {0};
    snprintf(expected, sizeof(expected), "%s:%s", stored_user, stored_pass);

    unsigned char b64_calculado[96] = {0};
    size_t b64_len = 0;

    if (mbedtls_base64_encode(b64_calculado, sizeof(b64_calculado), &b64_len,
                              (unsigned char *)expected, strlen(expected)) != 0)
    {
        ESP_LOGE(TAG, "Error codificando Base64");
        goto fail;
    }

    b64_calculado[b64_len] = '\0';

    if (strcmp((char *)b64_calculado, b64_recibido) == 0)
        return true;

fail:
    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"ESP32\"");
    httpd_resp_send(req, "Auth Required", HTTPD_RESP_USE_STRLEN);
    return false;
}


/* ─────────────────────────────────────────
   MQTT – PUBLICAR TELEMETRIA
   ───────────────────────────────────────── */

static void mqtt_publicar_estado(void)
{
    if (!mqtt_conectado || mqtt_client == NULL)
        return;

    const esp_app_desc_t *app_desc = esp_app_get_description();

    char payload[200];
    snprintf(payload, sizeof(payload),
             "{\"relay\":%d,\"wifi\":%d,\"version\":\"%s\"}",
             gpio_get_level(RELAY_GPIO),
             wifi_conectado ? 1 : 0,
             app_desc->version);

    esp_mqtt_client_publish(mqtt_client, MQTT_TELEMETRY, payload, 0, 1, 0);
    ESP_LOGI(TAG, "MQTT telemetria publicada: %s", payload);
}

static void mqtt_publicar_evento(const char *evento)
{
    if (!mqtt_conectado || mqtt_client == NULL)
        return;

    char payload[64];
    snprintf(payload, sizeof(payload), "{\"evento\":\"%s\"}", evento);

    esp_mqtt_client_publish(mqtt_client, MQTT_TELEMETRY, payload, 0, 1, 0);
    ESP_LOGI(TAG, "MQTT evento: %s", evento);
}


/* ─────────────────────────────────────────
   MQTT – TASK TELEMETRIA PERIODICA
   Publica estado cada 30 segundos
   ───────────────────────────────────────── */

static void mqtt_telemetry_task(void *pvParameters)
{
    while (1)
    {
        vTaskDelay(pdMS_TO_TICKS(MQTT_TELEMETRY_MS));
        mqtt_publicar_estado();
    }
}


/* ─────────────────────────────────────────
   MQTT – EVENT HANDLER
   ───────────────────────────────────────── */

static void mqtt_event_handler(void *handler_args,
                               esp_event_base_t base,
                               int32_t event_id,
                               void *event_data)
{
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;

    switch (event_id)
    {
        case MQTT_EVENT_CONNECTED:
            ESP_LOGI(TAG, "MQTT conectado a ThingsBoard");
            mqtt_conectado = true;

            /* Suscribirse a comandos RPC desde ThingsBoard */
            esp_mqtt_client_subscribe(mqtt_client, MQTT_RPC_REQUEST, 1);

            /* Publicar estado inicial */
            mqtt_publicar_estado();

            /* Publicar atributos del dispositivo */
            {
                const esp_app_desc_t *app = esp_app_get_description();
                char attr[128];
                snprintf(attr, sizeof(attr),
                         "{\"firmware\":\"%s\",\"sdk\":\"%s\"}",
                         app->version, app->idf_ver);
                esp_mqtt_client_publish(mqtt_client, MQTT_ATTRIBUTES, attr, 0, 1, 0);
            }
            break;

        case MQTT_EVENT_DISCONNECTED:
            ESP_LOGW(TAG, "MQTT desconectado");
            mqtt_conectado = false;
            break;

        case MQTT_EVENT_DATA:
        {
            /* Comando RPC recibido desde ThingsBoard
               Ejemplo: {"method":"abrir","params":{}} */
            char topic[64]  = {0};
            char data[128]  = {0};

            int t_len = event->topic_len < 63  ? event->topic_len : 63;
            int d_len = event->data_len  < 127 ? event->data_len  : 127;

            strncpy(topic, event->topic, t_len);
            strncpy(data,  event->data,  d_len);

            ESP_LOGI(TAG, "MQTT RPC recibido: %s → %s", topic, data);

            /* Extraer request_id del topic para la respuesta */
            int request_id = 0;
            sscanf(topic, "v1/devices/me/rpc/request/%d", &request_id);

            /* Procesar comando */
            if (strstr(data, "\"abrir\"") != NULL ||
                strstr(data, "abrir")    != NULL)
            {
                ESP_LOGI(TAG, "MQTT: comando abrir recibido");

                xTaskNotify(relay_task_handle, 1, eSetValueWithOverwrite);
                mqtt_publicar_evento("puerta_abierta");

                /* Responder al RPC */
                char resp_topic[64];
                snprintf(resp_topic, sizeof(resp_topic),
                         MQTT_RPC_RESPONSE, request_id);
                esp_mqtt_client_publish(mqtt_client, resp_topic,
                                        "{\"result\":\"ok\"}", 0, 1, 0);
            }
            else if (strstr(data, "\"status\"") != NULL ||
                     strstr(data, "status")     != NULL)
            {
                mqtt_publicar_estado();

                char resp_topic[64];
                snprintf(resp_topic, sizeof(resp_topic),
                         MQTT_RPC_RESPONSE, request_id);
                esp_mqtt_client_publish(mqtt_client, resp_topic,
                                        "{\"result\":\"ok\"}", 0, 1, 0);
            }
            break;
        }

        case MQTT_EVENT_ERROR:
            ESP_LOGE(TAG, "MQTT error");
            break;

        default:
            break;
    }
}


/* ─────────────────────────────────────────
   MQTT – INIT
   ───────────────────────────────────────── */

static void mqtt_init(void)
{
    esp_mqtt_client_config_t mqtt_cfg = {
        .broker.address.uri = MQTT_BROKER,
        .credentials.username = MQTT_TOKEN,
    };

    mqtt_client = esp_mqtt_client_init(&mqtt_cfg);

    esp_mqtt_client_register_event(mqtt_client,
                                   ESP_EVENT_ANY_ID,
                                   mqtt_event_handler,
                                   NULL);

    esp_mqtt_client_start(mqtt_client);

    /* Tarea que publica telemetria periodica */
    xTaskCreate(mqtt_telemetry_task, "mqtt_telem", 4096, NULL, 3, NULL);

    ESP_LOGI(TAG, "MQTT iniciado → %s", MQTT_BROKER);
}


/* ─────────────────────────────────────────
   RELAY TASK
   ───────────────────────────────────────── */

void relay_task(void *pvParameters)
{
    uint32_t cmd;

    while (1)
    {
        if (xTaskNotifyWait(0, 0, &cmd, pdMS_TO_TICKS(100)))
        {
            ESP_LOGI(TAG, "Activando relay");

            relay_start_time = esp_timer_get_time();

            gpio_set_level(RELAY_GPIO, 1);
            gpio_set_level(LED_GPIO,   1);

            vTaskDelay(pdMS_TO_TICKS(RELAY_ON_MS));

            gpio_set_level(RELAY_GPIO, 0);
            gpio_set_level(LED_GPIO,   0);

            ESP_LOGI(TAG, "Relay listo nuevamente");
        }

        /* FAILSAFE */
        if (gpio_get_level(RELAY_GPIO) == 1)
        {
            int64_t now = esp_timer_get_time();

            if ((now - relay_start_time) > RELAY_FAILSAFE_US)
            {
                ESP_LOGW(TAG, "Failsafe: relay forzado a OFF");
                gpio_set_level(RELAY_GPIO, 0);
                gpio_set_level(LED_GPIO,   0);
            }
        }
    }
}


/* ─────────────────────────────────────────
   OTA TASK
   ───────────────────────────────────────── */

static void ota_task(void *pvParameters)
{
    ESP_LOGI(TAG, "OTA: descargando desde %s", OTA_FIRMWARE_URL);

    esp_http_client_config_t http_config = {
        .url        = OTA_FIRMWARE_URL,
        .timeout_ms = 10000,
    };

    esp_http_client_handle_t client = esp_http_client_init(&http_config);

    if (client == NULL)
    {
        ESP_LOGE(TAG, "OTA: error al crear cliente HTTP");
        ota_en_progreso = false;
        vTaskDelete(NULL);
        return;
    }

    esp_err_t err = esp_http_client_open(client, 0);

    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "OTA: error al conectar: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        ota_en_progreso = false;
        vTaskDelete(NULL);
        return;
    }

    int content_length = esp_http_client_fetch_headers(client);
    ESP_LOGI(TAG, "OTA: tamano firmware: %d bytes", content_length);

    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);

    if (update_partition == NULL)
    {
        ESP_LOGE(TAG, "OTA: no hay particion disponible");
        esp_http_client_cleanup(client);
        ota_en_progreso = false;
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "OTA: escribiendo en particion %s", update_partition->label);

    esp_ota_handle_t ota_handle;
    err = esp_ota_begin(update_partition, OTA_WITH_SEQUENTIAL_WRITES, &ota_handle);

    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "OTA: esp_ota_begin fallo: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        ota_en_progreso = false;
        vTaskDelete(NULL);
        return;
    }

    char *buf = malloc(1024);

    if (buf == NULL)
    {
        ESP_LOGE(TAG, "OTA: sin memoria para buffer");
        esp_ota_abort(ota_handle);
        esp_http_client_cleanup(client);
        ota_en_progreso = false;
        vTaskDelete(NULL);
        return;
    }

    int total    = 0;
    int read_len = 0;

    while ((read_len = esp_http_client_read(client, buf, 1024)) > 0)
    {
        err = esp_ota_write(ota_handle, buf, read_len);

        if (err != ESP_OK)
        {
            ESP_LOGE(TAG, "OTA: error de escritura: %s", esp_err_to_name(err));
            free(buf);
            esp_ota_abort(ota_handle);
            esp_http_client_cleanup(client);
            ota_en_progreso = false;
            vTaskDelete(NULL);
            return;
        }

        total += read_len;
        ESP_LOGI(TAG, "OTA: %d bytes escritos...", total);
    }

    free(buf);
    esp_http_client_cleanup(client);

    err = esp_ota_end(ota_handle);

    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "OTA: esp_ota_end fallo: %s", esp_err_to_name(err));
        ota_en_progreso = false;
        vTaskDelete(NULL);
        return;
    }

    err = esp_ota_set_boot_partition(update_partition);

    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "OTA: set_boot_partition fallo: %s", esp_err_to_name(err));
        ota_en_progreso = false;
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "OTA OK – %d bytes – reiniciando en 2 segundos...", total);

    for (int i = 0; i < 6; i++)
    {
        gpio_set_level(LED_GPIO, i % 2);
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    esp_restart();
}


/* ─────────────────────────────────────────
   PAGINA HTML DE CONFIGURACION WIFI
   ───────────────────────────────────────── */

static const char *CONFIG_HTML =
"<!DOCTYPE html><html><head>"
"<meta charset='UTF-8'>"
"<meta name='viewport' content='width=device-width,initial-scale=1'>"
"<title>ESP32 Configuracion</title>"
"<style>"
"body{font-family:Arial,sans-serif;background:#1a1a2e;color:#eee;"
"display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}"
".card{background:#16213e;padding:2rem;border-radius:12px;width:90%;max-width:360px;"
"box-shadow:0 4px 20px rgba(0,0,0,0.5)}"
"h2{text-align:center;color:#e94560;margin-bottom:1.5rem}"
"label{display:block;margin-bottom:.3rem;font-size:.9rem;color:#aaa}"
"input{width:100%;padding:.6rem;margin-bottom:1rem;border:1px solid #e94560;"
"border-radius:6px;background:#0f3460;color:#fff;box-sizing:border-box;font-size:1rem}"
"button{width:100%;padding:.8rem;background:#e94560;color:#fff;border:none;"
"border-radius:6px;font-size:1rem;cursor:pointer}"
"button:hover{background:#c73652}"
".note{font-size:.8rem;color:#888;text-align:center;margin-top:1rem}"
"</style></head><body>"
"<div class='card'>"
"<h2>&#128273; Configurar WiFi</h2>"
"<form action='/guardar' method='POST'>"
"<label>Red WiFi (SSID)</label>"
"<input name='ssid' type='text' placeholder='Nombre de tu WiFi' required>"
"<label>Contrasena WiFi</label>"
"<input name='wpass' type='password' placeholder='Contrasena de tu WiFi'>"
"<label>Usuario chapa</label>"
"<input name='user' type='text' value='admin' required>"
"<label>Contrasena chapa</label>"
"<input name='pass' type='password' placeholder='Contrasena para abrir la puerta' required>"
"<button type='submit'>Guardar y conectar</button>"
"</form>"
"<p class='note'>El dispositivo se reiniciara y conectara a tu red.</p>"
"</div></body></html>";

static const char *OK_HTML =
"<!DOCTYPE html><html><head>"
"<meta charset='UTF-8'>"
"<meta name='viewport' content='width=device-width,initial-scale=1'>"
"<title>Guardado</title>"
"<style>"
"body{font-family:Arial,sans-serif;background:#1a1a2e;color:#eee;"
"display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0}"
".card{background:#16213e;padding:2rem;border-radius:12px;width:90%;max-width:360px;"
"text-align:center;box-shadow:0 4px 20px rgba(0,0,0,0.5)}"
"h2{color:#4caf50}.note{color:#aaa;font-size:.9rem;margin-top:1rem}"
"</style></head><body>"
"<div class='card'>"
"<h2>&#10003; Configuracion guardada</h2>"
"<p>El dispositivo se esta conectando a tu red WiFi.</p>"
"<p class='note'>Reconectate a tu red WiFi normal y accede al dispositivo desde la app.</p>"
"</div></body></html>";


/* ─────────────────────────────────────────
   HANDLERS MODO CONFIGURACION
   ───────────────────────────────────────── */

/* GET / → muestra el formulario */
static esp_err_t config_index_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Connection", "close");
    httpd_resp_send(req, CONFIG_HTML, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

/* POST /guardar → recibe y guarda los datos */
static esp_err_t config_guardar_handler(httpd_req_t *req)
{
    char buf[256] = {0};
    int  ret      = httpd_req_recv(req, buf, sizeof(buf) - 1);

    if (ret <= 0)
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Sin datos");
        return ESP_OK;
    }

    buf[ret] = '\0';
    ESP_LOGI(TAG, "Config recibida: %s", buf);

    /* Parsear campos: ssid, wpass, user, pass */
    char ssid[64]  = {0};
    char wpass[64] = {0};
    char user[32]  = {0};
    char pass[32]  = {0};

    /* Función auxiliar para extraer valor de query string */
    #define EXTRACT(key, dst) do { \
        char *p = strstr(buf, key "="); \
        if (p) { \
            p += strlen(key) + 1; \
            char *end = strchr(p, '&'); \
            size_t ln = end ? (size_t)(end - p) : strlen(p); \
            if (ln >= sizeof(dst)) ln = sizeof(dst) - 1; \
            strncpy(dst, p, ln); \
            dst[ln] = '\0'; \
        } \
    } while(0)

    EXTRACT("ssid",  ssid);
    EXTRACT("wpass", wpass);
    EXTRACT("user",  user);
    EXTRACT("pass",  pass);

    /* Decodificar '+' como espacio (form encoding básico) */
    for (int i = 0; ssid[i]; i++)  if (ssid[i]  == '+') ssid[i]  = ' ';
    for (int i = 0; wpass[i]; i++) if (wpass[i] == '+') wpass[i] = ' ';

    ESP_LOGI(TAG, "SSID: %s  USER: %s", ssid, user);

    /* Guardar WiFi en NVS */
    save_wifi_config(ssid, wpass);

    /* Guardar credenciales de la chapa en NVS */
    if (strlen(user) > 0 && strlen(pass) > 0)
    {
        nvs_handle_t nvs;
        if (nvs_open("auth", NVS_READWRITE, &nvs) == ESP_OK)
        {
            nvs_set_str(nvs, "user", user);
            nvs_set_str(nvs, "pass", pass);
            nvs_commit(nvs);
            nvs_close(nvs);
            ESP_LOGI(TAG, "Credenciales de chapa actualizadas");
        }
    }

    /* Responder con página de OK */
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, OK_HTML, HTTPD_RESP_USE_STRLEN);

    /* Reiniciar después de 2 segundos */
    vTaskDelay(pdMS_TO_TICKS(2000));
    esp_restart();

    return ESP_OK;
}


/* ─────────────────────────────────────────
   HANDLER /abrir
   ───────────────────────────────────────── */

static esp_err_t abrir_handler(httpd_req_t *req)
{
    if (!check_auth(req))
        return ESP_OK;

    if (ota_en_progreso)
    {
        httpd_resp_send(req, "OTA en progreso, espere", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    int64_t now = esp_timer_get_time() / 1000;

    if (now - last_open_time < ANTISPAM_MS)
    {
        ESP_LOGW(TAG, "Intento bloqueado: anti-spam");
        httpd_resp_send(req, "Espere 3 segundos", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    last_open_time = now;

    ESP_LOGI(TAG, "Peticion /abrir recibida");

    xTaskNotify(relay_task_handle, 1, eSetValueWithOverwrite);
    mqtt_publicar_evento("puerta_abierta");   /* notificar a ThingsBoard */

    httpd_resp_send(req, "Abriendo puerta", HTTPD_RESP_USE_STRLEN);

    return ESP_OK;
}


/* ─────────────────────────────────────────
   HANDLER /status
   ───────────────────────────────────────── */

static esp_err_t status_handler(httpd_req_t *req)
{
    if (!check_auth(req))
        return ESP_OK;

    const esp_app_desc_t *app_desc = esp_app_get_description();

    char buf[200];
    snprintf(buf, sizeof(buf),
             "{\"relay\":%d,\"wifi\":%d,\"ota\":%d,\"version\":\"%s\"}",
             gpio_get_level(RELAY_GPIO),
             wifi_conectado  ? 1 : 0,
             ota_en_progreso ? 1 : 0,
             app_desc->version);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, HTTPD_RESP_USE_STRLEN);

    return ESP_OK;
}


/* ─────────────────────────────────────────
   HANDLER /ota
   ───────────────────────────────────────── */

static esp_err_t ota_handler(httpd_req_t *req)
{
    if (!check_auth(req))
        return ESP_OK;

    if (ota_en_progreso)
    {
        httpd_resp_send(req, "OTA ya en progreso", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    if (!wifi_conectado)
    {
        httpd_resp_send(req, "Sin WiFi – OTA no disponible", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    ota_en_progreso = true;

    ESP_LOGI(TAG, "Peticion /ota recibida – lanzando OTA task");

    xTaskCreate(ota_task, "ota_task", 8192, NULL, 5, NULL);

    httpd_resp_send(req, "OTA iniciada – el dispositivo se reiniciara al terminar",
                    HTTPD_RESP_USE_STRLEN);

    return ESP_OK;
}


/* ─────────────────────────────────────────
   HANDLER /reset  (borrar WiFi y reiniciar)
   ───────────────────────────────────────── */

static esp_err_t reset_handler(httpd_req_t *req)
{
    if (!check_auth(req))
        return ESP_OK;

    ESP_LOGW(TAG, "Reset de configuracion WiFi solicitado");

    nvs_handle_t nvs;
    if (nvs_open("wifi_cfg", NVS_READWRITE, &nvs) == ESP_OK)
    {
        nvs_erase_all(nvs);
        nvs_commit(nvs);
        nvs_close(nvs);
    }

    httpd_resp_send(req, "WiFi borrado – reiniciando en modo configuracion",
                    HTTPD_RESP_USE_STRLEN);

    vTaskDelay(pdMS_TO_TICKS(1000));
    esp_restart();

    return ESP_OK;
}


/* ─────────────────────────────────────────
   SERVIDOR HTTP – MODO CONFIGURACION
   Solo muestra el formulario WiFi
   ───────────────────────────────────────── */

static httpd_handle_t start_config_server(void)
{
    if (server != NULL)
        return server;

    httpd_config_t config    = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers  = 8;
    config.recv_wait_timeout = 10;
    config.send_wait_timeout = 10;
    config.stack_size        = 8192;

    if (httpd_start(&server, &config) != ESP_OK)
    {
        ESP_LOGE(TAG, "Error al iniciar servidor de configuracion");
        server = NULL;
        return NULL;
    }

    httpd_uri_t index_uri = {
        .uri     = "/",
        .method  = HTTP_GET,
        .handler = config_index_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &index_uri);

    httpd_uri_t guardar_uri = {
        .uri     = "/guardar",
        .method  = HTTP_POST,
        .handler = config_guardar_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &guardar_uri);

    ESP_LOGI(TAG, "Servidor configuracion listo en 192.168.4.1");

    return server;
}


/* ─────────────────────────────────────────
   SERVIDOR HTTP – MODO NORMAL
   ───────────────────────────────────────── */

static httpd_handle_t start_webserver(void)
{
    if (server != NULL)
    {
        ESP_LOGW(TAG, "Servidor ya iniciado, ignorando llamada duplicada");
        return server;
    }

    httpd_config_t config   = HTTPD_DEFAULT_CONFIG();
    config.max_uri_handlers = 8;

    ESP_LOGI(TAG, "Iniciando servidor HTTP...");

    if (httpd_start(&server, &config) != ESP_OK)
    {
        ESP_LOGE(TAG, "Error al iniciar servidor HTTP");
        server = NULL;
        return NULL;
    }

    httpd_uri_t abrir_uri = {
        .uri     = "/abrir",
        .method  = HTTP_GET,
        .handler = abrir_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &abrir_uri);

    httpd_uri_t status_uri = {
        .uri     = "/status",
        .method  = HTTP_GET,
        .handler = status_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &status_uri);

    httpd_uri_t ota_uri = {
        .uri     = "/ota",
        .method  = HTTP_GET,
        .handler = ota_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &ota_uri);

    httpd_uri_t reset_uri = {
        .uri     = "/reset",
        .method  = HTTP_GET,
        .handler = reset_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(server, &reset_uri);

    ESP_LOGI(TAG, "Servidor HTTP iniciado (rutas: /abrir  /status  /ota  /reset)");

    return server;
}


/* ─────────────────────────────────────────
   ACCESS POINT DE CONFIGURACION
   ───────────────────────────────────────── */

static void start_config_ap(void)
{
    ESP_LOGI(TAG, "Iniciando AP de configuracion: %s", CONFIG_AP_SSID);

    esp_netif_create_default_wifi_ap();

    wifi_config_t ap_config = {
        .ap = {
            .ssid           = CONFIG_AP_SSID,
            .ssid_len       = strlen(CONFIG_AP_SSID),
            .password       = CONFIG_AP_PASS,
            .max_connection = 4,
            .authmode       = WIFI_AUTH_WPA_WPA2_PSK
        }
    };

    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    esp_wifi_start();

    ESP_LOGI(TAG, "AP listo: SSID=%s  PASS=%s  → abrir 192.168.4.1",
             CONFIG_AP_SSID, CONFIG_AP_PASS);
}


/* ─────────────────────────────────────────
   ACCESS POINT DE EMERGENCIA
   ───────────────────────────────────────── */

static void start_emergency_ap(void)
{
    ESP_LOGW(TAG, "Activando Access Point de emergencia");

    esp_netif_create_default_wifi_ap();

    wifi_config_t ap_config = {
        .ap = {
            .ssid           = "ESP32_DOOR",
            .ssid_len       = strlen("ESP32_DOOR"),
            .password       = "12345678",
            .max_connection = 4,
            .authmode       = WIFI_AUTH_WPA_WPA2_PSK
        }
    };

    esp_wifi_set_mode(WIFI_MODE_APSTA);
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    esp_wifi_start();

    ESP_LOGI(TAG, "AP emergencia listo: SSID=ESP32_DOOR  PASS=12345678");
}


/* ─────────────────────────────────────────
   WIFI EVENT HANDLER
   ───────────────────────────────────────── */

static void wifi_event_handler(void *arg,
                               esp_event_base_t event_base,
                               int32_t event_id,
                               void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
    {
        esp_wifi_connect();
    }

    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED)
    {
        wifi_conectado = false;
        wifi_retry_count++;

        ESP_LOGW(TAG, "WiFi desconectado – intento %d de %d",
                 wifi_retry_count, WIFI_MAX_RETRY);

        if (wifi_retry_count >= WIFI_MAX_RETRY)
        {
            ESP_LOGE(TAG, "No se pudo conectar. Modo AP de emergencia.");
            start_emergency_ap();
            start_webserver();
        }
        else
        {
            esp_wifi_connect();
        }
    }

    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)
    {
        wifi_retry_count = 0;
        wifi_conectado   = true;

        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "WiFi conectado – IP: " IPSTR,
                 IP2STR(&event->ip_info.ip));
    }
}


/* ─────────────────────────────────────────
   WIFI INIT – MODO NORMAL
   Lee credenciales desde NVS
   ───────────────────────────────────────── */

static void wifi_init_sta(const char *ssid, const char *pass)
{
    esp_netif_init();
    esp_event_loop_create_default();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);

    esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                        &wifi_event_handler, NULL, NULL);

    esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                        &wifi_event_handler, NULL, NULL);

    wifi_config_t wifi_config = {0};
    strncpy((char *)wifi_config.sta.ssid,     ssid, sizeof(wifi_config.sta.ssid) - 1);
    strncpy((char *)wifi_config.sta.password, pass, sizeof(wifi_config.sta.password) - 1);

    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
    esp_wifi_start();
}


/* ─────────────────────────────────────────
   APP MAIN
   ───────────────────────────────────────── */

void app_main(void)
{
    /* ── NVS ── */
    esp_err_t ret = nvs_flash_init();

    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_LOGW(TAG, "NVS corrupta – formateando...");
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }

    ESP_ERROR_CHECK(ret);

    /* ── Credenciales por defecto (solo primer arranque) ── */
    save_default_credentials();

    /* ── Verificar particion OTA ── */
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t   ota_state;

    if (esp_ota_get_state_partition(running, &ota_state) == ESP_OK)
    {
        if (ota_state == ESP_OTA_IMG_PENDING_VERIFY)
        {
            ESP_LOGI(TAG, "OTA: firmware nuevo verificado OK");
            esp_ota_mark_app_valid_cancel_rollback();
        }
    }

    /* ── GPIOs ── */
    gpio_set_direction(RELAY_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_direction(LED_GPIO,   GPIO_MODE_OUTPUT);
    gpio_set_level(RELAY_GPIO, 0);
    gpio_set_level(LED_GPIO,   0);

    /* ── Relay task ── */
    xTaskCreatePinnedToCore(
        relay_task, "relay_task",
        2048, NULL, 5,
        &relay_task_handle, 1);

    /* ── Leer WiFi desde NVS ── */
    char wifi_ssid[64] = {0};
    char wifi_pass[64] = {0};

    bool tiene_wifi = load_wifi_config(wifi_ssid, sizeof(wifi_ssid),
                                       wifi_pass,  sizeof(wifi_pass));

    if (!tiene_wifi || strlen(wifi_ssid) == 0)
    {
        /* ── MODO CONFIGURACION ──────────────────────────
           No hay WiFi guardado → levantar AP con formulario */
        ESP_LOGW(TAG, "Sin WiFi configurado – modo configuracion");

        modo_configuracion = true;

        esp_netif_init();
        esp_event_loop_create_default();

        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        esp_wifi_init(&cfg);

        start_config_ap();
        start_config_server();

        ESP_LOGI(TAG, "Conectate a '%s' y abre 192.168.4.1", CONFIG_AP_SSID);

        /* Quedarse aquí — el handler /guardar hace esp_restart() */
        while (1) vTaskDelay(pdMS_TO_TICKS(1000));
    }

    /* ── MODO NORMAL ─────────────────────────────────────
       Hay WiFi en NVS → conectar y arrancar servidor      */
    ESP_LOGI(TAG, "Conectando a WiFi: %s", wifi_ssid);

    wifi_init_sta(wifi_ssid, wifi_pass);

    ESP_LOGI(TAG, "Esperando conexion WiFi...");

    int timeout = 0;

    while (!wifi_conectado && timeout < (WIFI_MAX_RETRY * 2))
    {
        vTaskDelay(pdMS_TO_TICKS(500));
        timeout++;
    }

    start_webserver();

    /* ── MQTT → ThingsBoard ── */
    mqtt_init();

    ESP_LOGI(TAG, "Sistema listo y estable");
}