// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2026 changchuanyong

/**
 * @file scud_bms_driver.cpp
 * @brief 飞毛腿 SCUD 485 协议（daemon）与 Unix socket 客户端驱动实现。
 * @details 协议帧: 0xFE 0xFE | CMD | LEN | data | CRC_H CRC_L | 0xBB，
 *          CRC16-CCITT（多项式 0x1201、初值 0），多字节字段大端。
 */

#include "scud_bms_driver.hpp"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <poll.h>

#include <chrono>
#include <cerrno>
#include <cstring>
#include <thread>
#include <vector>

namespace scud_bms {

namespace {
constexpr uint8_t FRAME_HEAD = 0xFE;          // 帧头两字节同为 0xFE
constexpr uint8_t FRAME_TAIL = 0xBB;          // 帧尾
constexpr uint8_t QUERY_PARAM = 0x01;         // 查询参数固定 0x01
constexpr uint8_t CMD_USER_INFO = 0x61;       // 用户通信信息
constexpr uint8_t CMD_BATTERY_SUMMARY = 0x31; // 电池信息汇总
constexpr int LEN_USER_INFO = 28;
constexpr int LEN_BATTERY_SUMMARY = 38;
} // namespace

ScudBmsProtocol::ScudBmsProtocol(const std::string& port_name, int baud_rate,
                                 int timeout_ms)
    : port_name_(port_name), baud_rate_(baud_rate), timeout_ms_(timeout_ms) {}

ScudBmsProtocol::~ScudBmsProtocol() { close_port(); }

bool ScudBmsProtocol::open() {
    return serial_.open(port_name_, baud_rate_);
}

void ScudBmsProtocol::close_port() { serial_.close(); }

bool ScudBmsProtocol::is_open() const { return serial_.is_open(); }

void ScudBmsProtocol::flush() { serial_.flush(); }

// 协议文档 3.2.2 参考算法：CRC16-CCITT，多项式 0x1201，初值 0
uint16_t ScudBmsProtocol::crc16_ccitt(const uint8_t* data, size_t len) {
    uint16_t crc = 0;
    for (size_t i = 0; i < len; i++) {
        crc = static_cast<uint16_t>((crc >> 8) | (crc << 8));
        crc ^= data[i];
        crc ^= static_cast<uint16_t>((crc & 0xFF) >> 4);
        crc ^= static_cast<uint16_t>((crc << 8) << 4);
        crc ^= static_cast<uint16_t>(((crc & 0xFF) << 4) << 1);
    }
    return crc;
}

// 命令序列: FE FE | CMD | 01 | 01 | CRC_H CRC_L | BB
bool ScudBmsProtocol::send_query(uint8_t cmd) {
    uint8_t body[3] = {cmd, 1, QUERY_PARAM};
    uint16_t crc = crc16_ccitt(body, sizeof(body));

    uint8_t frame[8] = {
        FRAME_HEAD, FRAME_HEAD, body[0], body[1], body[2],
        static_cast<uint8_t>(crc >> 8), static_cast<uint8_t>(crc & 0xFF),
        FRAME_TAIL};

    flush();
    usleep(10000);
    return serial_.write_raw(frame, sizeof(frame)) ==
           static_cast<ssize_t>(sizeof(frame));
}

// 读取并校验一帧应答，data 输出纯参数区（不含帧头/CRC/帧尾）
// 整次查询共用 timeout_ms_ 截止时间，避免持续杂乱数据把轮询卡死
bool ScudBmsProtocol::read_frame(std::vector<uint8_t>& data, uint8_t expect_cmd,
                                 int expect_len) {
    if (!serial_.is_open()) return false;

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms_);
    auto remaining_ms = [&deadline]() -> int {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) return 0;
        return static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now)
                .count());
    };

    // 逐字节同步帧头（杂散字节自动丢弃重同步）
    uint8_t cmd = 0, len = 0;
    int stage = 0; // 0=等帧头1 1=等帧头2 2=收CMD 3=收LEN
    while (stage < 4) {
        const int wait = remaining_ms();
        if (wait <= 0) return false;
        uint8_t byte = 0;
        if (serial_.read_raw(&byte, 1, wait) != 1) return false;
        switch (stage) {
        case 0: if (byte == FRAME_HEAD) stage = 1; break;
        case 1: stage = (byte == FRAME_HEAD) ? 2 : 0; break;
        case 2: cmd = byte; stage = 3; break;
        case 3: len = byte; stage = 4; break;
        }
    }
    if (cmd != expect_cmd || len != static_cast<uint8_t>(expect_len)) return false;

    // 剩余部分: data[expect_len] + CRC_H + CRC_L + 帧尾
    std::vector<uint8_t> rest(expect_len + 3, 0);
    int total = 0;
    while (total < static_cast<int>(rest.size())) {
        const int wait = remaining_ms();
        if (wait <= 0) return false;
        ssize_t n = serial_.read_raw(rest.data() + total,
                                     rest.size() - total, wait);
        if (n <= 0) return false;
        total += static_cast<int>(n);
    }
    if (rest[expect_len + 2] != FRAME_TAIL) return false;

    // CRC 覆盖 CMD + LEN + data
    std::vector<uint8_t> crcbuf;
    crcbuf.push_back(cmd);
    crcbuf.push_back(len);
    crcbuf.insert(crcbuf.end(), rest.begin(), rest.begin() + expect_len);
    uint16_t calc = crc16_ccitt(crcbuf.data(), crcbuf.size());
    uint16_t recv = static_cast<uint16_t>((rest[expect_len] << 8) |
                                          rest[expect_len + 1]);
    if (calc != recv) return false;

    data.assign(rest.begin(), rest.begin() + expect_len);
    return true;
}

bool ScudBmsProtocol::query_0x61(std::vector<uint8_t>& data) {
    if (!send_query(CMD_USER_INFO)) return false;
    return read_frame(data, CMD_USER_INFO, LEN_USER_INFO);
}

bool ScudBmsProtocol::query_0x31(std::vector<uint8_t>& data) {
    if (!send_query(CMD_BATTERY_SUMMARY)) return false;
    return read_frame(data, CMD_BATTERY_SUMMARY, LEN_BATTERY_SUMMARY);
}

uint16_t ScudBmsProtocol::get_u16_be(const uint8_t* buf, int offset) {
    return static_cast<uint16_t>(buf[offset] << 8) | buf[offset + 1];
}

int16_t ScudBmsProtocol::get_i16_be(const uint8_t* buf, int offset) {
    return static_cast<int16_t>(get_u16_be(buf, offset));
}

uint16_t ScudBmsProtocol::get_u16_be(const std::vector<uint8_t>& buf,
                                     int offset) {
    return get_u16_be(buf.data(), offset);
}

int16_t ScudBmsProtocol::get_i16_be(const std::vector<uint8_t>& buf,
                                    int offset) {
    return get_i16_be(buf.data(), offset);
}

bool ScudBmsProtocol::read_basic_info(bms::BatteryStatus& status) {
    std::vector<uint8_t> d;
    if (!query_0x61(d)) return false;

    uint16_t flag = get_u16_be(d, 0);
    uint16_t chg_ma = get_u16_be(d, 2);
    uint16_t dis_ma = get_u16_be(d, 4);

    status.voltage = get_u16_be(d, 10) / 1000.0; // 输出电压 mV -> V
    // 协议将充/放电电流分为两字段，合并为带符号电流：充电为正、放电为负
    int mA = (chg_ma > 0) ? static_cast<int>(chg_ma) : -static_cast<int>(dis_ma);
    status.current = mA / 1000.0;
    status.temperature = get_i16_be(d, 24);      // 最高单体电池温度 ℃
    status.max_cell_voltage = get_u16_be(d, 12) / 1000.0;
    status.min_cell_voltage = get_u16_be(d, 14) / 1000.0;
    status.protect_status = flag;                // BAT FLAG 全 16 位
    status.work_state = flag & 0x000F;           // bit0-3: 使能充/放电、充/放电状态
    status.cycles = get_u16_be(d, 26);           // 循环次数，随每轮 0x61 更新
    return true;
}

bool ScudBmsProtocol::read_capacity_info(bms::BatteryStatus& status) {
    std::vector<uint8_t> d;
    if (!query_0x61(d)) return false;

    status.percentage = get_u16_be(d, 20) / 100.0; // SOC % -> 0~1 分数
    status.charge = get_u16_be(d, 18) / 1000.0;    // 剩余容量 mAh -> Ah
    status.capacity = get_u16_be(d, 16) / 1000.0;  // 当前总容量 mAh -> Ah
    status.design_capacity = status.capacity;      // 协议无标称容量，以当前总容量代填
    status.soh = 0;                                // 协议无 SOH，显式置零，防止 daemon 复制未初始化的栈值
    return true;
}

bool ScudBmsProtocol::read_version_info(bms::BatteryStatus& status) {
    std::vector<uint8_t> d;
    if (!query_0x61(d)) return false;

    status.cycles = get_u16_be(d, 26); // 循环次数
    // 协议不提供软硬件版本与 SOH，清零避免上层打印未初始化值
    status.sw_version = 0;
    status.hw_version = 0;
    status.soh = 0;
    return true;
}

bool ScudBmsProtocol::read_io_state(bms::BatteryStatus& status) {
    // power_on 必须来自本轮有效的 0x61，且不能被 0x31 失败阻断：
    // 0x31 只负责单体电压兜底，与放电使能无关。
    std::vector<uint8_t> d61;
    if (!query_0x61(d61)) return false;
    const uint16_t flag = get_u16_be(d61, 0);
    status.power_on = (flag & 0x0001) ? 1 : 0;     // bit0 sys_dch_on
    status.io_state = 0;

    std::vector<uint8_t> d;
    if (!query_0x31(d)) return true; // 0x61 已成功，0x31 失败仅跳过电压兜底

    // 用 15 节单体电压重算极值作为兜底（空节位读 0，忽略）
    uint16_t mx = 0, mn = 0xFFFF;
    for (int i = 0; i < 15; i++) {
        uint16_t v = get_u16_be(d, i * 2);
        if (v == 0) continue;
        if (v > mx) mx = v;
        if (v < mn) mn = v;
    }
    if (mn != 0xFFFF) {
        status.max_cell_voltage = mx / 1000.0;
        status.min_cell_voltage = mn / 1000.0;
    }

    return true;
}

bool ScudBmsProtocol::read_serial_number(std::string&) {
    return false; // 协议无 SN 命令
}

bool ScudBmsProtocol::set_discharge_output(bool) {
    return false; // 协议为只读
}

} // namespace scud_bms

ScudBmsDriver::ScudBmsDriver(const std::string& socket_path)
    : BmsDriver(), socket_path_(socket_path) {
    std::memset(&cached_, 0, sizeof(cached_));
    running_ = true;
    reader_thread_ = std::thread(&ScudBmsDriver::reader_loop, this);
    logger_->info("SCUD BMS driver started, socket={}", socket_path_);
}

ScudBmsDriver::~ScudBmsDriver() {
    running_ = false;
    if (reader_thread_.joinable()) {
        reader_thread_.join();
    }
    disconnect();
}

bool ScudBmsDriver::try_connect() {
    if (sock_fd_ >= 0) return true;

    sock_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd_ < 0) return false;

    struct sockaddr_un addr {};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path_.c_str(), sizeof(addr.sun_path) - 1);

    if (connect(sock_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        close(sock_fd_);
        sock_fd_ = -1;
        return false;
    }

    connected_ = true;
    logger_->info("Connected to SCUD BMS daemon at {}", socket_path_);
    return true;
}

void ScudBmsDriver::disconnect() {
    if (sock_fd_ >= 0) {
        close(sock_fd_);
        sock_fd_ = -1;
    }
    connected_ = false;
}

void ScudBmsDriver::reader_loop() {
    pthread_setname_np(pthread_self(), "scud_bms_reader");

    bms::BatteryStatus wire {};
    size_t got = 0;

    while (running_) {
        if (!try_connect()) {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            continue;
        }

        struct pollfd pfd {sock_fd_, POLLIN, 0};
        int ret = poll(&pfd, 1, 500);
        if (ret < 0) {
            if (errno == EINTR) continue;
            logger_->warn("SCUD BMS poll error, reconnecting...");
            disconnect();
            got = 0;
            continue;
        }
        if (ret == 0) continue;
        if (pfd.revents & (POLLERR | POLLHUP)) {
            logger_->warn("SCUD BMS daemon disconnected, reconnecting...");
            disconnect();
            got = 0;
            continue;
        }

        // SOCK_STREAM 可能短读，累积收满整个 BatteryStatus 再更新
        ssize_t n = read(sock_fd_, reinterpret_cast<uint8_t*>(&wire) + got,
                         sizeof(wire) - got);
        if (n < 0) {
            if (errno == EINTR) continue;
            logger_->warn("SCUD BMS read error, reconnecting...");
            disconnect();
            got = 0;
            continue;
        }
        if (n == 0) {
            logger_->warn("SCUD BMS daemon disconnected, reconnecting...");
            disconnect();
            got = 0;
            continue;
        }

        got += static_cast<size_t>(n);
        if (got < sizeof(wire)) continue;

        {
            std::unique_lock lock(data_mutex_);
            cached_ = wire;
        }
        got = 0;
    }
}

double ScudBmsDriver::get_voltage() const {
    std::shared_lock lock(data_mutex_);
    return cached_.voltage;
}

double ScudBmsDriver::get_current() const {
    std::shared_lock lock(data_mutex_);
    return cached_.current;
}

double ScudBmsDriver::get_temperature() const {
    std::shared_lock lock(data_mutex_);
    return cached_.temperature;
}

double ScudBmsDriver::get_percentage() const {
    std::shared_lock lock(data_mutex_);
    return cached_.percentage;
}

double ScudBmsDriver::get_charge() const {
    std::shared_lock lock(data_mutex_);
    return cached_.charge;
}

double ScudBmsDriver::get_capacity() const {
    std::shared_lock lock(data_mutex_);
    return cached_.capacity;
}

double ScudBmsDriver::get_design_capacity() const {
    std::shared_lock lock(data_mutex_);
    return cached_.design_capacity;
}

uint32_t ScudBmsDriver::get_protect_status() const {
    std::shared_lock lock(data_mutex_);
    return cached_.protect_status;
}

uint16_t ScudBmsDriver::get_work_state() const {
    std::shared_lock lock(data_mutex_);
    return cached_.work_state;
}

double ScudBmsDriver::get_max_cell_voltage() const {
    std::shared_lock lock(data_mutex_);
    return cached_.max_cell_voltage;
}

double ScudBmsDriver::get_min_cell_voltage() const {
    std::shared_lock lock(data_mutex_);
    return cached_.min_cell_voltage;
}

uint16_t ScudBmsDriver::get_soh() const {
    std::shared_lock lock(data_mutex_);
    return cached_.soh;
}

uint32_t ScudBmsDriver::get_cycles() const {
    std::shared_lock lock(data_mutex_);
    return cached_.cycles;
}

uint32_t ScudBmsDriver::get_io_state() const {
    std::shared_lock lock(data_mutex_);
    return cached_.io_state;
}

bool ScudBmsDriver::is_power_on() const {
    std::shared_lock lock(data_mutex_);
    return cached_.power_on != 0;
}

bool ScudBmsDriver::is_connected() const {
    return connected_.load();
}
