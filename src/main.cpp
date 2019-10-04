extern "C" {
  #include "user_interface.h"
}
#include <Arduino.h>
#include <ESP8266WiFi.h>

const uint8_t LED_PIN = LED_BUILTIN;
const bool LED_LEVEL = LOW;

enum wifi_promiscuous_pkt_type_t {
  WIFI_PKT_MGMT,
  WIFI_PKT_CTRL,
  WIFI_PKT_DATA,
  WIFI_PKT_MISC,
};

enum wifi_mgmt_subtypes_t {
  ASSOCIATION_REQ,
  ASSOCIATION_RES,
  REASSOCIATION_REQ,
  REASSOCIATION_RES,
  PROBE_REQ,
  PROBE_RES,
  NU1,
  NU2,
  BEACON,
  ATIM,
  DISASSOCIATION,
  AUTHENTICATION,
  DEAUTHENTICATION,
  ACTION,
  ACTION_NACK,
};

struct __packed wifi_mgmt_beacon_t {
  uint16_t interval;
  uint16_t capability;
  uint8_t tag_number;
  uint8_t tag_length;
  char ssid[0];
  uint8_t rates[1];
};

struct __packed wifi_header_frame_control_t {
  uint16_t protocol : 2;
  uint16_t type : 2;
  uint16_t subtype : 4;
  uint16_t to_ds : 1;
  uint16_t from_ds : 1;
  uint16_t more_frag : 1;
  uint16_t retry : 1;
  uint16_t pwr_mgmt : 1;
  uint16_t more_data : 1;
  uint16_t wep : 1;
  uint16_t strict : 1;
};

struct __packed wifi_ieee80211_mac_hdr_t {
  wifi_header_frame_control_t frame_ctrl;
  uint16_t duration_id;
  uint8_t addr1[6]; /* receiver address */
  uint8_t addr2[6]; /* sender address */
  uint8_t addr3[6]; /* filtering address */
  uint16_t sequence_ctrl;
  uint8_t addr4[6]; /* optional */
};

struct __packed wifi_ieee80211_packet_t {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
};

struct __packed wifi_pkt_rx_ctrl_t {
  signed rssi : 8;            /**< signal intensity of packet */
  unsigned rate : 4;          /**< data rate */
  unsigned is_group : 1;
  unsigned : 1;               /**< reserve */
  unsigned sig_mode : 2;      /**< 0:is not 11n packet; 1:is 11n packet */
  unsigned legacy_length : 12;
  unsigned damatch0 : 1;
  unsigned damatch1 : 1;
  unsigned bssidmatch0 : 1;
  unsigned bssidmatch1 : 1;
  unsigned mcs : 7;           /**< if is 11n packet, shows the modulation(range from 0 to 76) */
  unsigned cwb : 1;           /**< if is 11n packet, shows if is HT40 packet or not */
  unsigned HT_length : 16;    /**< reserve */
  unsigned smoothing : 1;     /**< reserve */
  unsigned not_sounding : 1;  /**< reserve */
  unsigned : 1;               /**< reserve */
  unsigned aggregation : 1;   /**< Aggregation */
  unsigned stbc : 2;          /**< STBC */
  unsigned fec_coding : 1;    /**< Flag is set for 11n packets which are LDPC */
  unsigned sgi : 1;           /**< SGI */
  unsigned rxend_state : 8;
  unsigned ampdu_cnt : 8;     /**< ampdu cnt */
  unsigned channel : 4;       /**< which channel this packet in */
  unsigned : 4;               /**< reserve */
  signed noise_floor : 8;
};

struct __packed wifi_pkt_mgmt_t {
  wifi_pkt_rx_ctrl_t rx_ctrl;
  uint8_t buf[112];
  uint16_t cnt;
  uint16_t len; // length of packet
};

struct __packed wifi_pkt_lenseq_t {
  uint16_t length;
  uint16_t seq;
  uint8_t address3[6];
};

struct __packed wifi_pkt_data_t {
  wifi_pkt_rx_ctrl_t rx_ctrl;
  uint8_t buf[36];
  uint16_t cnt;
  wifi_pkt_lenseq_t lenseq[1];
};

struct __packed wifi_promiscuous_pkt_t {
  wifi_pkt_rx_ctrl_t rx_ctrl; /**< metadata header */
  uint8_t payload[0];         /**< Data or management payload. Length of payload is described by rx_ctrl.sig_len. Type of content determined by packet type argument of callback. */
};

typedef uint8_t mac_t[6];

class LookupTable {
public:
  LookupTable() : _start(0), _len(0) {}

  uint16_t length() const {
    return _len;
  }
  int16_t find(const mac_t &mac);
  bool add(const mac_t &mac);

protected:
  static const uint16_t MAX_SIZE = 1024;

  mac_t _macs[MAX_SIZE];
  uint16_t _start, _len;
};

int16_t LookupTable::find(const mac_t &mac) {
  for (int16_t i = 0; i < _len; ++i) {
    if (! memcmp(_macs[i], mac, sizeof(mac_t)))
      return i;
  }

  return -1;
}

bool LookupTable::add(const mac_t &mac) {
  if (find(mac) >= 0)
    return false;

  if (_len < MAX_SIZE) {
    memcpy(_macs[_len++], mac, sizeof(mac_t));
  } else {
    memcpy(_macs[_start], mac, sizeof(mac_t));
    if (++_start >= MAX_SIZE)
      _start = 0;
  }

  return true;
}

void printHeader() {
  Serial.println(F("       mac       |ch|rssi"));
  Serial.println(F("-----------------+--+----"));
}

LookupTable macs;

void wifi_sniffer_packet_handler(uint8_t *buff, uint16_t len) {
  const int8_t SENSITIVITY = -127;

  // First layer: type cast the received buffer into our generic SDK structure
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t*)buff;
  // Second layer: define pointer to where the actual 802.11 packet is within the structure
  const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t*)ppkt->payload;
  // Third layer: define pointers to the 802.11 packet header and payload
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

  if (ppkt->rx_ctrl.rssi >= SENSITIVITY) {
    if (macs.add(hdr->addr2)) {
      const uint8_t PAGE_SIZE = 16;

      static uint8_t pageLen = 0;

      Serial.printf_P(PSTR("%02x:%02x:%02x:%02x:%02x:%02x|%2d|%4d\n"),
        hdr->addr2[0], hdr->addr2[1], hdr->addr2[2], hdr->addr2[3], hdr->addr2[4], hdr->addr2[5], ppkt->rx_ctrl.channel, ppkt->rx_ctrl.rssi);
      if (++pageLen >= PAGE_SIZE) {
        Serial.println(F("-----"));
        Serial.print(macs.length());
        Serial.println(F(" unique macs"));
        printHeader();
        pageLen = 0;
      }
    }
  }
}

void setup() {
  Serial.begin(115200);
  Serial.println();

  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, ! LED_LEVEL);

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();

  wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler);
  wifi_promiscuous_enable(1);

  printHeader();
}

void loop() {
  const uint8_t MAX_CHANNEL = 13;
  const uint32_t SWITCH_TIME = 100; // 100 ms
  const uint32_t BLINK_TIME = 25; // 25 ms

  static uint8_t channel = 1;

  wifi_set_channel(channel);
  if (channel == 1) {
    digitalWrite(LED_PIN, LED_LEVEL);
    delay(BLINK_TIME);
    digitalWrite(LED_PIN, ! LED_LEVEL);
    delay(SWITCH_TIME - BLINK_TIME);
  } else {
    delay(SWITCH_TIME);
  }
  if (++channel > MAX_CHANNEL)
    channel = 1;
}
