// Copyright (c) 2026 Baptiste Boussemart. Tous droits réservés.
// lab-secured-v3 — la clé naît ici. Le serveur décide de l'enrôlement.
//
// Le sketch public contient le nom (une étiquette) et l'adresse du service
// d'enrôlement. Il ne contient ni clé de device, ni certificat client,
// ni adresse du broker MQTT.
//
//   1. Générer une clé P-256 et un CSR. Afficher l'empreinte (SHA-256 du SPKI).
//   2. Envoyer le nom et le CSR en HTTPS. La CA publique est dans ca_pin.h.
//   3. Attendre. L'administrateur approuve l'empreinte lue sur ce moniteur.
//   4. Recevoir le certificat, la CA et la configuration MQTT. Les charger en RAM.
//   5. Se connecter. Le broker applique l'ACL. Une révocation coupe la publication.
//
// La clé privée n'est pas affichée. Un reset fabrique une nouvelle clé :
// l'empreinte précédente ne correspond plus.

#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <time.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>
#include <mbedtls/md.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/sha256.h>
#include <mbedtls/error.h>
#include "ca_pin.h"

// Étiquette présentée au serveur. Ce n'est pas un secret.
// Deux sketches avec le même nom : le second est refusé tant que le premier est en cours.
static const char* DEVICE_NAME = "sensor-001";

static const char* ENROLL_HOST = "play.why.noematic.eu";
static const int ENROLL_PORT = 8443;

// L'AP virtuelle fournie par Wokwi : réseau ouvert, canal 6.
static const char* WIFI_SSID = "Wokwi-GUEST";
static const int WIFI_CHANNEL = 6;

static const int LED_PIN = 2;

enum State { ST_BOOT, ST_AWAITING, ST_CONNECTING, ST_ACTIVE, ST_REJECTED };
static State state = ST_BOOT;

static char keyPem[800];
static char csrPem[1200];
static char certPem[2048];
static char caPem[2048];
static char fingerprint[65];
static char mqttHost[64];
static int mqttPort = 0;
static char topicTelemetry[80];
static char topicStatus[80];
static char topicCmd[80];
static char deviceId[40];

static WiFiClientSecure net;
static PubSubClient mqtt(net);

static unsigned long lastPoll = 0;
static unsigned long lastTelemetry = 0;
static float temperature = 21.0f;

void onMqttMessage(char* topic, byte* payload, unsigned int length);

extern "C" uint32_t esp_random(void);

static int espRng(void* ctx, unsigned char* buf, size_t len) {
  (void)ctx;
  size_t i = 0;
  while (i < len) {
    uint32_t word = esp_random();
    for (int b = 0; b < 4 && i < len; b++, i++) {
      buf[i] = (unsigned char)(word & 0xFF);
      word >>= 8;
    }
  }
  return 0;
}

static void logMbedtls(const char* what, int code) {
  char buf[100];
  mbedtls_strerror(code, buf, sizeof(buf));
  Serial.printf("[clé] %s : -0x%04X %s\n", what, -code, buf);
}

static bool copyText(const char* src, char* dst, size_t dstLen, const char* label) {
  if (src == nullptr || src[0] == '\0') {
    Serial.printf("[copie] %s absent\n", label);
    return false;
  }
  size_t n = strlen(src);
  if (n + 1 > dstLen) {
    Serial.printf("[copie] %s trop long (%u)\n", label, (unsigned)n);
    return false;
  }
  memcpy(dst, src, n + 1);
  return true;
}

// L'association avec l'AP virtuelle peut être lente ou échouer à la première
// tentative (gateway Wokwi, onglet en arrière-plan). On retente l'association
// au lieu d'attendre indéfiniment une seule tentative.
static bool connectWiFi() {
  const int MAX_ATTEMPTS = 8;
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    if (attempt > 1) {
      WiFi.disconnect();
      delay(300);
    }
    Serial.printf("[WiFi] tentative %d/%d ", attempt, MAX_ATTEMPTS);
    WiFi.begin(WIFI_SSID, "", WIFI_CHANNEL);
    unsigned long t0 = millis();
    while (millis() - t0 < 10000 && WiFi.status() != WL_CONNECTED) {
      delay(200);
      Serial.print(".");
    }
    if (WiFi.status() == WL_CONNECTED) {
      Serial.printf(" OK — IP %s\n", WiFi.localIP().toString().c_str());
      return true;
    }
    Serial.println(" — non connecté, nouvelle tentative");
  }
  return false;
}

static bool clockReady() {
  // Trois serveurs de repli : un seul injoignable ne bloque pas la synchro.
  configTime(0, 0, "pool.ntp.org", "time.google.com", "time.windows.com");
  Serial.print("[NTP] ");
  struct tm timeinfo;
  for (int i = 0; i < 20; i++) {
    if (getLocalTime(&timeinfo, 500) && timeinfo.tm_year + 1900 >= 2024) {
      Serial.printf("%04d-%02d-%02d %02d:%02d:%02d\n",
                    timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
                    timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
      return true;
    }
    Serial.print(".");
  }
  Serial.println("\n[NTP] heure indisponible — le contrôle du certificat serveur échouera");
  return false;
}

static bool generateKeyAndCsr() {
  mbedtls_pk_context key;
  mbedtls_pk_init(&key);
  int rc = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
  if (rc != 0) {
    logMbedtls("pk_setup", rc);
    return false;
  }
  rc = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(key), espRng, nullptr);
  if (rc != 0) {
    logMbedtls("ecp_gen_key", rc);
    mbedtls_pk_free(&key);
    return false;
  }

  unsigned char der[160];
  int derLen = mbedtls_pk_write_pubkey_der(&key, der, sizeof(der));
  if (derLen < 0) {
    logMbedtls("pubkey_der", derLen);
    mbedtls_pk_free(&key);
    return false;
  }
  unsigned char hash[32];
  // mbedtls écrit le SPKI à la fin du tampon.
  mbedtls_sha256(der + sizeof(der) - derLen, derLen, hash, 0);
  for (int i = 0; i < 32; i++) {
    sprintf(fingerprint + i * 2, "%02x", hash[i]);
  }
  fingerprint[64] = '\0';

  mbedtls_x509write_csr csr;
  mbedtls_x509write_csr_init(&csr);
  mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);
  mbedtls_x509write_csr_set_key(&csr, &key);
  // Le serveur ignore ce CN et impose le nom approuvé.
  rc = mbedtls_x509write_csr_set_subject_name(&csr, "CN=pending");
  if (rc != 0) {
    logMbedtls("csr_subject", rc);
    mbedtls_x509write_csr_free(&csr);
    mbedtls_pk_free(&key);
    return false;
  }
  rc = mbedtls_x509write_csr_pem(&csr, (unsigned char*)csrPem, sizeof(csrPem), espRng, nullptr);
  mbedtls_x509write_csr_free(&csr);
  if (rc != 0) {
    logMbedtls("csr_pem", rc);
    mbedtls_pk_free(&key);
    return false;
  }
  rc = mbedtls_pk_write_key_pem(&key, (unsigned char*)keyPem, sizeof(keyPem));
  mbedtls_pk_free(&key);
  if (rc != 0) {
    logMbedtls("key_pem", rc);
    memset(keyPem, 0, sizeof(keyPem));
    return false;
  }

  Serial.println("═══════════════════════════════════════");
  Serial.println("  DEMANDE D'ENRÔLEMENT");
  Serial.printf("  nom       : %s\n", DEVICE_NAME);
  Serial.printf("  empreinte : %s\n", fingerprint);
  Serial.println("  clé P-256 en RAM, non affichée");
  Serial.println("  Lisez l'empreinte à l'administrateur.");
  Serial.println("═══════════════════════════════════════");
  return true;
}

static bool httpExchange(const char* method, const char* path, const String& body, int& status, String& response) {
  WiFiClientSecure client;
  client.setCACert(ENROLL_CA_PEM);
  client.setTimeout(20);
  if (!client.connect(ENROLL_HOST, ENROLL_PORT)) {
    char err[100];
    int code = client.lastError(err, sizeof(err));
    Serial.printf("[HTTP] %s:%d injoignable (mbedtls -0x%04X %s)\n", ENROLL_HOST, ENROLL_PORT, -code, err);
    return false;
  }

  String head = String(method) + " " + path + " HTTP/1.0\r\nHost: " + ENROLL_HOST +
                "\r\nConnection: close\r\n";
  if (body.length() > 0) {
    head += "Content-Type: application/json\r\nContent-Length: " + String(body.length()) + "\r\n";
  }
  head += "\r\n";
  client.print(head);
  if (body.length() > 0) {
    client.print(body);
  }

  String raw;
  raw.reserve(6000);
  unsigned long start = millis();
  while (millis() - start < 20000) {
    while (client.available()) {
      raw += (char)client.read();
      start = millis();
      if (raw.length() > 10000) {
        client.stop();
        Serial.println("[HTTP] réponse trop grande");
        return false;
      }
    }
    if (!client.connected() && !client.available()) {
      break;
    }
    delay(10);
  }
  client.stop();

  int split = raw.indexOf("\r\n\r\n");
  if (split < 0 || !raw.startsWith("HTTP/")) {
    Serial.println("[HTTP] réponse illisible");
    return false;
  }
  int codeStart = raw.indexOf(' ');
  status = raw.substring(codeStart + 1, codeStart + 4).toInt();
  response = raw.substring(split + 4);
  return true;
}

static void becomeRejected(const char* why) {
  state = ST_REJECTED;
  digitalWrite(LED_PIN, LOW);
  Serial.printf("[enrôlement] REFUSÉ — %s\n", why);
  Serial.println("  Reset le simulateur pour générer une nouvelle clé.");
}

static bool connectMqtt() {
  net.stop();
  net.setTimeout(15);
  net.setCACert(caPem);
  net.setCertificate(certPem);
  net.setPrivateKey(keyPem);
  mqtt.setServer(mqttHost, mqttPort);
  mqtt.setCallback(onMqttMessage);
  mqtt.setBufferSize(512);

  String will = String("{\"online\":false,\"device_id\":\"") + deviceId + "\"}";
  String clientId = String("wokwi-") + deviceId;
  bool ok = mqtt.connect(clientId.c_str(), topicStatus, 1, true, will.c_str());
  if (!ok) {
    Serial.printf("[MQTT] échec (état %d)\n", mqtt.state());
    return false;
  }
  if (!mqtt.subscribe(topicCmd, 1)) {
    Serial.println("[MQTT] abonnement commande refusé");
    return false;
  }
  String online = String("{\"online\":true,\"device_id\":\"") + deviceId + "\"}";
  mqtt.publish(topicStatus, online.c_str(), true);
  state = ST_ACTIVE;
  digitalWrite(LED_PIN, HIGH);
  Serial.println("═══════════════════════════════════════");
  Serial.printf("  CONNECTÉ  %s:%d\n", mqttHost, mqttPort);
  Serial.printf("  identité  %s\n", deviceId);
  Serial.printf("  pub       %s\n", topicTelemetry);
  Serial.printf("  sub       %s\n", topicCmd);
  Serial.println("═══════════════════════════════════════");
  return true;
}

static bool takeBundle(JsonDocument& doc) {
  if (!copyText(doc["device_id"].as<const char*>(), deviceId, sizeof(deviceId), "device_id")) return false;
  if (strcmp(deviceId, DEVICE_NAME) != 0) {
    becomeRejected("device_id différent du nom demandé");
    return false;
  }
  if (!copyText(doc["cert_pem"].as<const char*>(), certPem, sizeof(certPem), "certificat")) return false;
  if (!copyText(doc["ca_pem"].as<const char*>(), caPem, sizeof(caPem), "CA")) return false;
  if (!copyText(doc["mqtt"]["host"].as<const char*>(), mqttHost, sizeof(mqttHost), "hôte MQTT")) return false;
  mqttPort = doc["mqtt"]["port"].as<int>();
  if (mqttPort < 1 || mqttPort > 65535) {
    becomeRejected("port MQTT absent");
    return false;
  }
  if (!copyText(doc["mqtt"]["topics"]["telemetry"].as<const char*>(), topicTelemetry, sizeof(topicTelemetry), "telemetry")) return false;
  if (!copyText(doc["mqtt"]["topics"]["status"].as<const char*>(), topicStatus, sizeof(topicStatus), "status")) return false;
  if (!copyText(doc["mqtt"]["topics"]["cmd"].as<const char*>(), topicCmd, sizeof(topicCmd), "cmd")) return false;
  if (strstr(topicTelemetry, deviceId) == nullptr || strstr(topicStatus, deviceId) == nullptr ||
      strstr(topicCmd, deviceId) == nullptr) {
    becomeRejected("topics sans l'identité");
    return false;
  }
  const char* exp = doc["expires_at"].as<const char*>();
  Serial.printf("[enrôlement] approuvé, certificat jusqu'à %s\n", exp ? exp : "?");
  state = ST_CONNECTING;
  return connectMqtt();
}

static void handleDecision(int status, const String& response) {
  JsonDocument doc;
  if (deserializeJson(doc, response)) {
    Serial.println("[enrôlement] JSON illisible");
    return;
  }
  if (status == 409 || status == 400) {
    const char* err = doc["error"].as<const char*>();
    becomeRejected(err != nullptr ? err : "requête refusée");
    return;
  }
  const char* decision = doc["status"].as<const char*>();
  if (decision == nullptr) {
    Serial.println("[enrôlement] statut absent");
    return;
  }
  if (strcmp(decision, "pending") == 0) {
    Serial.println("[enrôlement] en attente de l'empreinte");
    return;
  }
  if (strcmp(decision, "rejected") == 0 || strcmp(decision, "revoked") == 0) {
    becomeRejected(decision);
    return;
  }
  if (strcmp(decision, "approved") == 0) {
    takeBundle(doc);
  }
}

static void sendRequest() {
  JsonDocument body;
  body["name"] = DEVICE_NAME;
  body["csr_pem"] = csrPem;
  String payload;
  serializeJson(body, payload);
  int status = 0;
  String response;
  if (!httpExchange("POST", "/v1/enroll", payload, status, response)) {
    return;
  }
  state = ST_AWAITING;
  handleDecision(status, response);
}

static void poll() {
  String path = String("/v1/enroll/") + fingerprint;
  int status = 0;
  String response;
  if (!httpExchange("GET", path.c_str(), "", status, response)) {
    return;
  }
  handleDecision(status, response);
}

void onMqttMessage(char* topic, byte* payload, unsigned int length) {
  if (state != ST_ACTIVE || strcmp(topic, topicCmd) != 0) {
    return;
  }
  JsonDocument doc;
  if (deserializeJson(doc, payload, length)) {
    Serial.println("[cmd] JSON invalide");
    return;
  }
  if (!doc["led"].isNull()) {
    bool on = doc["led"].as<bool>();
    digitalWrite(LED_PIN, on ? HIGH : LOW);
    Serial.println(on ? "[LED] ON" : "[LED] OFF");
  }
}

void setup() {
  Serial.begin(115200);
  delay(300);
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);
  Serial.println("lab-secured-v3 — enrôlement par CSR");

  if (!connectWiFi()) {
    Serial.println("[WiFi] réseau indisponible après plusieurs tentatives.");
    Serial.println("  Reset le simulateur et relancez le sketch.");
    state = ST_REJECTED;
    return;
  }

  if (!clockReady()) {
    becomeRejected("horloge non synchronisée");
    return;
  }
  if (!generateKeyAndCsr()) {
    becomeRejected("génération de clé impossible");
    return;
  }
  sendRequest();
}

void loop() {
  if (state == ST_REJECTED) {
    delay(500);
    return;
  }
  // Le lien peut tomber pendant l'exécution (onglet en arrière-plan, gateway).
  // On le rétablit avant de tenter HTTP ou MQTT.
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("[WiFi] lien perdu — reconnexion");
    unsigned long t0 = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - t0 < 8000) {
      WiFi.reconnect();
      delay(400);
    }
    if (WiFi.status() != WL_CONNECTED) {
      delay(500);
      return;
    }
    Serial.println("[WiFi] lien rétabli");
  }
  if (state == ST_AWAITING && millis() - lastPoll > 3000) {
    lastPoll = millis();
    poll();
  }
  if (state == ST_CONNECTING && millis() - lastPoll > 3000) {
    lastPoll = millis();
    connectMqtt();
  }
  if (state == ST_ACTIVE) {
    if (!mqtt.connected()) {
      Serial.println("[MQTT] session coupée — nouvelle tentative (ACL, révocation ou lien)");
      state = ST_CONNECTING;
      return;
    }
    mqtt.loop();
    if (millis() - lastTelemetry > 5000) {
      lastTelemetry = millis();
      temperature += (random(-5, 6) / 10.0f);
      if (temperature < 15.0f) temperature = 15.0f;
      if (temperature > 35.0f) temperature = 35.0f;
      char payload[96];
      snprintf(payload, sizeof(payload), "{\"device_id\":\"%s\",\"temp_c\":%.1f}", deviceId, temperature);
      if (!mqtt.publish(topicTelemetry, payload)) {
        Serial.println("[MQTT] publication non remise");
      } else {
        Serial.printf("[TELEM] %.1f °C\n", temperature);
      }
    }
  }
}
