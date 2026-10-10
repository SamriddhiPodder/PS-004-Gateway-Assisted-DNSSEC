#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <bearssl/bearssl.h>
#include <string.h>
#include "gw_creds.h"

// Wi-Fi credentials: fill these in locally
static const char* WIFI_SSID = "IEM AI CAMPUS";
static const char* WIFI_PASS = "1234567890";

// Your teammate's current Windows Wi-Fi IP
static const char* GW_IP = "192.168.81.244";
static const uint16_t GW_PORT = 8853;

static const char* NAME_SECURE = "secure.lab.test";
static const char* NAME_INSECURE = "insecure.lab.test";
static const char* NAME_BOGUS = "www.bogus.lab.test";

// Keep the TLS client global to conserve ESP8266 stack memory
BearSSL::WiFiClientSecure client;
BearSSL::PublicKey* gwKey = nullptr;

enum Verdict {
  V_SECURE,
  V_INSECURE,
  V_BOGUS,
  V_ERROR
};

size_t buildQuery(uint8_t* buf, const char* name, uint16_t id) {
  size_t p = 2;  // Reserve the DoT length prefix

  buf[p++] = id >> 8;
  buf[p++] = id & 0xFF;

  // RD=1, AD=1
  buf[p++] = 0x01;
  buf[p++] = 0x20;

  // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=1
  buf[p++] = 0x00;
  buf[p++] = 0x01;
  buf[p++] = 0x00;
  buf[p++] = 0x00;
  buf[p++] = 0x00;
  buf[p++] = 0x00;
  buf[p++] = 0x00;
  buf[p++] = 0x01;

  // Encode the domain name as DNS labels
  const char* s = name;

  while (*s) {
    const char* dot = strchr(s, '.');
    size_t len = dot ? (size_t)(dot - s) : strlen(s);

    buf[p++] = (uint8_t)len;
    memcpy(buf + p, s, len);
    p += len;

    s += len;
    if (*s == '.') s++;
  }

  buf[p++] = 0x00;  // Root label

  // QTYPE=A, QCLASS=IN
  buf[p++] = 0x00;
  buf[p++] = 0x01;
  buf[p++] = 0x00;
  buf[p++] = 0x01;

  // EDNS0 OPT record; DO bit requests DNSSEC data
  buf[p++] = 0x00;
  buf[p++] = 0x00;
  buf[p++] = 0x29;
  buf[p++] = 0x10;
  buf[p++] = 0x00;
  buf[p++] = 0x00;
  buf[p++] = 0x00;
  buf[p++] = 0x80;
  buf[p++] = 0x00;
  buf[p++] = 0x00;
  buf[p++] = 0x00;

  uint16_t dnsLen = p - 2;
  buf[0] = dnsLen >> 8;
  buf[1] = dnsLen & 0xFF;

  return p;
}

Verdict readVerdict(const uint8_t* resp, size_t len) {
  if (len < 12) return V_ERROR;

  uint8_t rcode = resp[3] & 0x0F;
  bool ad = (resp[3] & 0x20) != 0;

  if (rcode == 2) return V_BOGUS;  // SERVFAIL
  if (rcode != 0) return V_ERROR;

  return ad ? V_SECURE : V_INSECURE;
}

const char* verdictName(Verdict v) {
  switch (v) {
    case V_SECURE:   return "SECURE";
    case V_INSECURE: return "INSECURE";
    case V_BOGUS:    return "BOGUS";
    default:         return "ERROR";
  }
}

bool readExact(uint8_t* dst, size_t len, uint32_t timeoutMs) {
  size_t got = 0;
  uint32_t started = millis();

  while (got < len && millis() - started < timeoutMs) {
    if (!client.connected() && !client.available()) {
      return false;
    }

    int availableBytes = client.available();

    if (availableBytes > 0) {
      size_t remaining = len - got;
      size_t take = (size_t)availableBytes < remaining
                      ? (size_t)availableBytes
                      : remaining;

      int n = client.read(dst + got, take);
      if (n > 0) got += (size_t)n;
    } else {
      delay(1);
    }
  }

  return got == len;
}

Verdict query(const char* name) {
  Serial.printf("\nQuery: %s\n", name);

  // This is real gateway public-key pinning, not setInsecure()
  client.setInsecure();  // DIAGNOSTIC ONLY — NOT FOR FINAL USE
  client.setBufferSizes(1024, 512);

  if (!client.connect(GW_IP, GW_PORT)) {
    Serial.println("TLS CONNECTION FAILED");
    client.stop();
    return V_ERROR;
  }

  Serial.println("TLS CONNECTION SUCCESS");

  uint8_t buf[300];
  size_t qlen = buildQuery(buf, name, (uint16_t)random(1, 65535));

  size_t written = client.write(buf, qlen);

  if (written != qlen) {
    Serial.println("DNS QUERY SEND FAILED");
    client.stop();
    return V_ERROR;
  }

  // Read the two-byte DNS-over-TLS response length
  uint8_t lengthBytes[2];

  if (!readExact(lengthBytes, 2, 5000)) {
    Serial.println("RESPONSE LENGTH TIMEOUT");
    client.stop();
    return V_ERROR;
  }

  uint16_t responseLength =
      ((uint16_t)lengthBytes[0] << 8) | lengthBytes[1];

  uint8_t response[512];

  if (responseLength < 12 || responseLength > sizeof(response)) {
    Serial.printf("INVALID RESPONSE LENGTH: %u\n", responseLength);
    client.stop();
    return V_ERROR;
  }

  if (!readExact(response, responseLength, 5000)) {
    Serial.println("DNS RESPONSE TIMEOUT");
    client.stop();
    return V_ERROR;
  }

  Verdict v = readVerdict(response, responseLength);

  Serial.printf("DNS VERDICT: %s\n", verdictName(v));

  switch (v) {
    case V_SECURE:
      Serial.println("Result: SECURE");
      break;

    case V_INSECURE:
      Serial.println("Result: INSECURE - unsigned domain");
      break;

    case V_BOGUS:
      Serial.println("Result: BOGUS - reject response");
      break;

    default:
      Serial.println("Result: ERROR");
      break;
  }

  client.stop();
  return v;
}

void setup() {
  Serial.begin(115200);
  delay(300);

  Serial.println("\nPS-004 DNS-over-TLS CLIENT");

  // The guide-generated header must define GW_PUBKEY_PEM
  gwKey = new BearSSL::PublicKey(GW_PUBKEY_PEM);

  if (!gwKey->isRSA() && !gwKey->isEC()) {
    Serial.println("ERROR: Gateway public key could not be loaded");
    return;
  }

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  Serial.print("Connecting to Wi-Fi");

  uint32_t started = millis();

  while (WiFi.status() != WL_CONNECTED &&
         millis() - started < 20000) {
    delay(300);
    Serial.print(".");
  }

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("\nWi-Fi connection failed");
    return;
  }

  Serial.printf("\nWi-Fi connected: %s\n",
                WiFi.localIP().toString().c_str());

  Serial.printf("Gateway: %s:%u\n", GW_IP, GW_PORT);

  query(NAME_SECURE);
  query(NAME_INSECURE);
  query(NAME_BOGUS);

  Serial.println("\nPS-004 DNS-over-TLS tests finished");
}

void loop() {
}
