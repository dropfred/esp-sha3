#include <sdkconfig.h>

#include <stdio.h>
#include <inttypes.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include <esp_chip_info.h>
#include <esp_flash.h>
#include <esp_timer.h>
#include <esp_clk_tree.h>

#include <functional>
#include <string>

#include "sha3.h"

#define BENCH_SAMPLE 100
#define LOOP_DELAY 10000

namespace
{
    std::string const data[] =
    {
        "",
        "0123456789",
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"
    };

    void bench(char const * name, std::function<void(void const *, std::size_t, void *)> hash, std::size_t size)
    {
        for (auto d : data)
        {
            int64_t t = INT64_MAX;

            for (std::size_t b = BENCH_SAMPLE; b != 0; --b)
            {
                uint8_t digest[size];
                auto dt = esp_timer_get_time();
                hash(d.data(), d.size(), digest);
                dt = esp_timer_get_time() - dt;
                if (dt < t)
                {
                    t = dt;
                }
            }
            printf("%s(%.10s%s): %" PRId64 " us\n", name, d.c_str(), ((d.size() > 10) ? "..." : ""), t);
        }
    }
}

#define BENCH(s) bench("sha3_" #s, sha3_ ## s, SHA3_ ## s ## _DIGEST_SIZE)

extern "C" void app_main()
{
    {
        esp_chip_info_t chip_info;
        uint32_t freq;
        uint32_t flash_size;

        esp_chip_info(&chip_info);

        if (esp_clk_tree_src_get_freq_hz(SOC_MOD_CLK_CPU, ESP_CLK_TREE_SRC_FREQ_PRECISION_EXACT, &freq) != ESP_OK)
        {
            printf("get CPU frequency failed");
            freq = 0;
        }
        
        if (esp_flash_get_size(NULL, &flash_size) != ESP_OK)
        {
            printf("get flash size failed");
            flash_size = 0;
        }
        printf
        (
            "%s v%u.%u\n"
            "  Core(s): %u\n"
            "  Frequency %u MHz\n"
            "  Flash: %u MB (%s)\n",
            CONFIG_IDF_TARGET, chip_info.revision / 100U, chip_info.revision % 100U,
            (unsigned int)(chip_info.cores),
            (unsigned int)(freq / 1000000U),
            (unsigned int)(flash_size / (1024U * 1024U)), (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "embedded" : "external"
        );
    }

    while (true)
    {
        printf("\n");
        BENCH(224);
        BENCH(256);
        BENCH(512);
        fflush(stdout);
        vTaskDelay(LOOP_DELAY / portTICK_PERIOD_MS);
    }
}
