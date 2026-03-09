idf_component_register(SRCS "main.cpp" "pdulib.cpp"
                    INCLUDE_DIRS "."
                    REQUIRES nvs_flash esp_wifi esp_http_server esp_http_client esp-tls lwip esp_netif driver esp_timer)