#include <stdio.h>
#include <string.h>
#include <string>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "esp_http_server.h"
#include "esp_http_client.h"
#include "esp_tls.h"
#include "esp_crt_bundle.h"
#include "esp_sntp.h"
#include "esp_timer.h"

#include "pdulib.h" 

static const char *TAG = "MAIN_APP";
PDU pdu(4096);

// ================= 引脚与总线定义 =================
#define U1_TX_PIN GPIO_NUM_1
#define U1_RX_PIN GPIO_NUM_2
#define U1_EN_PIN GPIO_NUM_3
#define UART_PORT1 UART_NUM_0 // DL 模块 (4G 推送)

#define U2_TX_PIN GPIO_NUM_7
#define U2_RX_PIN GPIO_NUM_6
#define U2_EN_PIN GPIO_NUM_5
#define UART_PORT2 UART_NUM_1 // DSLN 模块 (接收短信)

#define U3_TX_PIN GPIO_NUM_12
#define U3_RX_PIN GPIO_NUM_11
#define U3_EN_PIN GPIO_NUM_13
#define UART_PORT3 UART_NUM_2 // DC 模块 (接收短信)

#define BUF_SIZE (1024)

// ================= 全局变量 =================
const char* AP_SSID = "ESP32-SMS";
const char* AP_PASS = "712387500";
const char* PUSH_URL = "https://14409.push.ft07.com/send/sctp14409tno3vvkydvds2gazyz1er96.send";

char savedSSID[32] = {0};
char savedPass[64] = {0};
char currentIP[20] = "0.0.0.0";
bool isWifiConnected = false;

typedef enum { MSG_TYPE_BOOT, MSG_TYPE_SMS } MsgType_t;
typedef struct {
    MsgType_t type;
    char sender[32];
    char timestamp[64];
    char content[256];
} PushMsg_t;

QueueHandle_t pushQueue;
enum SMSState { IDLE, WAIT_PDU };
SMSState state2 = IDLE;
SMSState state3 = IDLE;
std::string rx_buffer2 = "";
std::string rx_buffer3 = "";

// ================= 辅助函数 =================
std::string formatPDUTime(const char* pduTime) {
    int y, m, d, h, min, s;
    if (strlen(pduTime) >= 12 && sscanf(pduTime, "%2d%2d%2d%2d%2d%2d", &y, &m, &d, &h, &min, &s) == 6) {
        char buf[64];
        snprintf(buf, sizeof(buf), "20%02d年%02d月%02d日%02d点%02d分%02d秒", y, m, d, h, min, s);
        return std::string(buf);
    }
    return std::string(pduTime);
}

// 验证码提取函数
std::string extractVerificationCode(const std::string& content) {
    // 策略 1：关键词向后匹配（适用于 "验证码是：123456" 或带有字母的 "Code: A4b9C"）
    const char* keywords[] = {"验证码", "校验码", "动态码", "确认码", "激活码", "随机码", "提取码", "取件码", "code", "Code", "密码"};
    for (const char* kw : keywords) {
        size_t pos = content.find(kw);
        if (pos != std::string::npos) {
            size_t start = pos + strlen(kw);
            std::string code = "";
            bool found_start = false;
            // 往后最多扫描 30 个字符
            for (size_t i = start; i < content.length() && i < start + 30; ++i) {
                char c = content[i];
                // 仅提取数字和大小写字母
                if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
                    code += c;
                    found_start = true;
                } else if (found_start) {
                    break; // 遇到非字母/数字，认为验证码结束
                }
            }
            // 常见的验证码长度在 4 到 8 位之间
            if (code.length() >= 4 && code.length() <= 8) {
                return code;
            }
        }
    }

    // 策略 2：纯数字兜底扫描（适用于验证码在开头的情况，例如 "【某某云】123456是您的登录验证码"）
    std::string digits = "";
    std::string best_fallback = "";
    for (size_t i = 0; i < content.length(); ++i) {
        char c = content[i];
        if (c >= '0' && c <= '9') {
            digits += c;
        } else {
            // 找到了一个独立的数字串
            if (digits.length() >= 4 && digits.length() <= 8) {
                if (digits.length() == 6) return digits; // 6位数字最可能是验证码，直接返回
                if (best_fallback.empty()) best_fallback = digits; // 暂存 4, 5, 7, 8 位的数字
            }
            digits = ""; // 清空，准备记录下一个数字串
        }
    }
    // 检查末尾收尾的数字串
    if (digits.length() >= 4 && digits.length() <= 8) {
        if (digits.length() == 6) return digits;
        if (best_fallback.empty()) best_fallback = digits;
    }
    
    return best_fallback; // 如果没找到验证码，这里会返回空字符串 ""
}

bool sendCmdAndWait(uart_port_t uart_num, const char* cmd, const char* resp1, const char* resp2, uint32_t timeout_ms) {
    uart_flush(uart_num);
    if (cmd != nullptr) {
        std::string cmd_str = std::string(cmd) + "\r\n";
        uart_write_bytes(uart_num, cmd_str.c_str(), cmd_str.length());
    }
    uint32_t start = esp_timer_get_time() / 1000; 
    std::string resp = "";
    uint8_t data[2];
    while((esp_timer_get_time() / 1000) - start < timeout_ms) {
        int len = uart_read_bytes(uart_num, data, 1, pdMS_TO_TICKS(10));
        if (len > 0) {
            resp += (char)data[0];
            if (resp1 && resp.find(resp1) != std::string::npos) return true;
            if (resp2 && resp.find(resp2) != std::string::npos) return true;
        }
        vTaskDelay(1);
    }
    return false;
}

void initModem(uart_port_t uart_num, const char* modName) {
    vTaskDelay(pdMS_TO_TICKS(1000));
    sendCmdAndWait(uart_num, "AT+MIPCALL=0,1", "OK", "ERROR", 2000);
    vTaskDelay(pdMS_TO_TICKS(1000));
    sendCmdAndWait(uart_num, "AT+CNMI=2,2,0,0,0", "OK", "ERROR", 2000); 
    vTaskDelay(pdMS_TO_TICKS(1000));
    sendCmdAndWait(uart_num, "AT+CMGF=0", "OK", "ERROR", 2000); 
    ESP_LOGI(TAG, "✅ [%s] 模组初始化完成！", modName);
}

// ================= 推送引擎 =================
bool exec4GPost(const std::string& payload) {
    uart_flush(UART_PORT1);
    std::string cmd = "AT+MIPOPEN=0,\"TCP\",\"14409.push.ft07.com\",80,,1\r\n";
    uart_write_bytes(UART_PORT1, cmd.c_str(), cmd.length());
    
    uint32_t startWait = esp_timer_get_time() / 1000;
    std::string respBuffer = "";
    uint8_t data[2];
    bool gotConnect = false;
    
    // 【修改点 1】：将 10000 (10秒) 缩短为 5000 (5秒)
    while ((esp_timer_get_time() / 1000) - startWait < 5000) {
        int len = uart_read_bytes(UART_PORT1, data, 1, pdMS_TO_TICKS(10));
        if (len > 0) {
            respBuffer += (char)data[0];
            
            // 【修改点 2，极其重要】：给 4G 串口接收也加上内存保护（泄洪阀）
            // 如果 4G 模块一直发乱码且找不到 CONNECT，超 512 字节就清空，防止死机
            if (respBuffer.length() > 512) {
                respBuffer.clear();
            }

            if (respBuffer.find("CONNECT") != std::string::npos) { gotConnect = true; break; }
            if (respBuffer.find("ERROR") != std::string::npos) return false;
        }
    }
    
    if (!gotConnect) {
        ESP_LOGW(TAG, "4G 模块 TCP 连接超时或失败");
        return false;
    }
    
    std::string http_req = "POST /send/sctp14409tno3vvkydvds2gazyz1er96.send HTTP/1.1\r\nHost: 14409.push.ft07.com\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(payload.length()) + "\r\nConnection: close\r\n\r\n" + payload;
    uart_write_bytes(UART_PORT1, http_req.c_str(), http_req.length());
    
    startWait = esp_timer_get_time() / 1000;
    bool pushSuccess = false;
    
    // 发送 POST 数据后的等待响应时间，你原本就是写的 5000ms，保持不变即可
    while ((esp_timer_get_time() / 1000) - startWait < 5000) {
        int len = uart_read_bytes(UART_PORT1, data, 1, pdMS_TO_TICKS(10));
        if (len > 0 && ((char)data[0] == '2')) { pushSuccess = true; } // 粗略匹配 200 OK
    }
    
    vTaskDelay(pdMS_TO_TICKS(1000));
    uart_write_bytes(UART_PORT1, "+++", 3);
    vTaskDelay(pdMS_TO_TICKS(1000));
    return pushSuccess;
}

bool execWiFiPost(const std::string& payload) {
    if (!isWifiConnected) return false;
    esp_http_client_config_t config = {};
    config.url = PUSH_URL;
    config.transport_type = HTTP_TRANSPORT_OVER_SSL;
    config.crt_bundle_attach = esp_crt_bundle_attach; 

    esp_http_client_handle_t client = esp_http_client_init(&config);
    config.timeout_ms = 5000;
    if (client == NULL) {
        ESP_LOGE(TAG, "HTTPS 客户端初始化失败");
        return false;
    }
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, payload.c_str(), payload.length());
    esp_err_t err = esp_http_client_perform(client);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "HTTPS POST 失败: %s", esp_err_to_name(err));
    }
    bool success = (err == ESP_OK && esp_http_client_get_status_code(client) == 200);
    esp_http_client_cleanup(client);
    return success;
}

void Task_Push_Dispatcher(void *pvParameters) {
    PushMsg_t msg;
    while(1) {
        if (xQueueReceive(pushQueue, &msg, portMAX_DELAY) == pdPASS) {
            // 修复点：在 if 外面声明变量，确保全范围可见
            std::string base_title, desp, tags;

            if (msg.type == MSG_TYPE_BOOT) {
                ESP_LOGI(TAG, "等待 IP 获取...");
                int wait_count = 0;
                while (!isWifiConnected && wait_count < 20) { vTaskDelay(pdMS_TO_TICKS(500)); wait_count++; }
                base_title = "设备开机通知";
                desp = isWifiConnected ? ("设备启动成功\\n\\n局域网IP：" + std::string(currentIP)) : "设备启动成功\\n\\n网络：WiFi 未连接";
                tags = "开机信息";
            } else {
                std::string content_str = std::string(msg.content);
                std::string vcode = extractVerificationCode(content_str);
                if (!vcode.empty()) {
                    base_title = "验证码："+ vcode; 
                } else {
                    base_title = "收到新短信";
                }
                desp = "- 发件人: " + std::string(msg.sender) + "\\n\\n- 时间: " + std::string(msg.timestamp) + "\\n\\n- 内容: \\n\\n> " + content_str;
                tags = "短信";
            }

            bool pushSuccess = false;
            // 策略 A: 4G
            for (int i = 0; i < 2; i++) {
                std::string payload = "{\"title\":\"" + base_title + "[4G]\",\"desp\":\"" + desp + "\",\"tags\":\"" + tags + "\"}";
                if (exec4GPost(payload)) { pushSuccess = true; break; }
                vTaskDelay(pdMS_TO_TICKS(2000));
            }
            // 策略 B: WiFi
            if (!pushSuccess && isWifiConnected) {
                for (int i = 0; i < 2; i++) {
                    std::string payload = "{\"title\":\"" + base_title + "[WIFI]\",\"desp\":\"" + desp + "\",\"tags\":\"" + tags + "\"}";
                    if (execWiFiPost(payload)) { pushSuccess = true; break; }
                    vTaskDelay(pdMS_TO_TICKS(2000));
                }
            }
        }
    }
}

// ================= 串口与 WiFi 逻辑 =================
void processSMS(uart_port_t uart_num, int devNum, SMSState& state, std::string& rx_buffer) {
    uint8_t data[128];
    int length = uart_read_bytes(uart_num, data, sizeof(data) - 1, pdMS_TO_TICKS(10));
    if (length > 0) { data[length] = '\0'; rx_buffer += (char*)data; }
    if (rx_buffer.length() > 2048) {
        ESP_LOGE(TAG, "[设备%d] RX Buffer 溢出！执行清空", devNum);
        rx_buffer.clear();
        state = IDLE;
    }
    size_t pos;
    while ((pos = rx_buffer.find('\n')) != std::string::npos) {
        std::string line = rx_buffer.substr(0, pos);
        rx_buffer.erase(0, pos + 1);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        ESP_LOGI(TAG, "[设备%d] <- %s", devNum, line.c_str());
        if (state == IDLE && line.find("+CMT:") != std::string::npos) { state = WAIT_PDU; }
        else if (state == WAIT_PDU) {
            if (pdu.decodePDU(line.c_str())) {
                PushMsg_t msg = { .type = MSG_TYPE_SMS };
                strncpy(msg.sender, pdu.getSender(), 31);
                strncpy(msg.timestamp, formatPDUTime(pdu.getTimeStamp()).c_str(), 63);
                strncpy(msg.content, pdu.getText(), 255);
                xQueueSend(pushQueue, &msg, 0);
            }
            state = IDLE;
        }
    }
}

void Task_SMS_Rx(void *pvParameters) {
    while(1) {
        processSMS(UART_PORT2, 2, state2, rx_buffer2);
        processSMS(UART_PORT3, 3, state3, rx_buffer3);
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}

static void wifi_event_handler(void* arg, esp_event_base_t base, int32_t id, void* data) {
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) esp_wifi_connect();
    else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) { isWifiConnected = false; esp_wifi_connect(); }
    else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* ev = (ip_event_got_ip_t*) data;
        sprintf(currentIP, IPSTR, IP2STR(&ev->ip_info.ip));
        isWifiConnected = true;
    }
}

// ================= 主函数 =================
extern "C" void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) { nvs_flash_erase(); nvs_flash_init(); }
    
    gpio_reset_pin(U1_EN_PIN); gpio_set_direction(U1_EN_PIN, GPIO_MODE_OUTPUT); gpio_set_level(U1_EN_PIN, 0);
    gpio_reset_pin(U2_EN_PIN); gpio_set_direction(U2_EN_PIN, GPIO_MODE_OUTPUT); gpio_set_level(U2_EN_PIN, 0);
    gpio_reset_pin(U3_EN_PIN); gpio_set_direction(U3_EN_PIN, GPIO_MODE_OUTPUT); gpio_set_level(U3_EN_PIN, 0);
    
    // 修复点：完整的初始化列表，消除警告
    uart_config_t uart_cfg = {};
    uart_cfg.baud_rate = 115200;
    uart_cfg.data_bits = UART_DATA_8_BITS;
    uart_cfg.parity = UART_PARITY_DISABLE;
    uart_cfg.stop_bits = UART_STOP_BITS_1;
    uart_cfg.flow_ctrl = UART_HW_FLOWCTRL_DISABLE;
    uart_cfg.source_clk = UART_SCLK_DEFAULT;

    uart_param_config(UART_PORT1, &uart_cfg); uart_set_pin(UART_PORT1, U1_TX_PIN, U1_RX_PIN, -1, -1); uart_driver_install(UART_PORT1, BUF_SIZE * 2, 0, 0, NULL, 0);
    uart_param_config(UART_PORT2, &uart_cfg); uart_set_pin(UART_PORT2, U2_TX_PIN, U2_RX_PIN, -1, -1); uart_driver_install(UART_PORT2, BUF_SIZE, 0, 0, NULL, 0);
    uart_param_config(UART_PORT3, &uart_cfg); uart_set_pin(UART_PORT3, U3_TX_PIN, U3_RX_PIN, -1, -1); uart_driver_install(UART_PORT3, BUF_SIZE, 0, 0, NULL, 0);
    
    pushQueue = xQueueCreate(10, sizeof(PushMsg_t));
    vTaskDelay(pdMS_TO_TICKS(500));

    gpio_set_level(U1_EN_PIN, 1); vTaskDelay(pdMS_TO_TICKS(3500));
    sendCmdAndWait(UART_PORT1, "AT", "OK", NULL, 1000);

    gpio_set_level(U2_EN_PIN, 1); vTaskDelay(pdMS_TO_TICKS(1500));
    initModem(UART_PORT2, "Port2");

    gpio_set_level(U3_EN_PIN, 1); vTaskDelay(pdMS_TO_TICKS(1500));
    initModem(UART_PORT3, "Port3");

    nvs_handle_t h;
    if (nvs_open("wifi_config", NVS_READONLY, &h) == ESP_OK) {
        size_t s = 32; nvs_get_str(h, "ssid", savedSSID, &s);
        s = 64; nvs_get_str(h, "pass", savedPass, &s);
        nvs_close(h);
    }

    esp_netif_init();
    esp_event_loop_create_default();
    if (strlen(savedSSID) > 0) {
        esp_netif_create_default_wifi_sta();
        esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL);
        esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL);
        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        esp_wifi_init(&cfg);
        wifi_config_t w_cfg = {};
        strcpy((char*)w_cfg.sta.ssid, savedSSID);
        strcpy((char*)w_cfg.sta.password, savedPass);
        esp_wifi_set_mode(WIFI_MODE_STA);
        esp_wifi_set_config(WIFI_IF_STA, &w_cfg);
        esp_wifi_start();
        PushMsg_t boot = { .type = MSG_TYPE_BOOT }; xQueueSend(pushQueue, &boot, 0);
    }

    xTaskCreate(Task_SMS_Rx, "SMSRx", 4096, NULL, 5, NULL);
    xTaskCreate(Task_Push_Dispatcher, "PushTask", 8192, NULL, 5, NULL);
}