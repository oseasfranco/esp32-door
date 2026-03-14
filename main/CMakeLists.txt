idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES
        esp_wifi
        esp_event
        nvs_flash
        esp_http_server
        esp_http_client
        driver
        esp_timer
        mbedtls
        app_update
        mqtt
)