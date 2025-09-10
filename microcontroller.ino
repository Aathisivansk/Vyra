#include <LiquidCrystal_I2C.h>
#include "EmonLib.h"
#include <EEPROM.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>

// --- Server Configuration ---
const char* serverUrl = "http://192.168.1.5:5000/add_data"; // IMPORTANT: Use your computer's IP address
const char* apiKey = "911fe0a92f50d448b82a938bf28d15c5cc4e65f06175b3d2";
const char* motorId = "Motor 1";

// --- Your WiFi Credentials ---
const char* ssid = "Sharbin";
const char* pass = "12345679";

// --- Pin Definitions ---
#define RELAY_PIN 32
#define VOLTAGE_PIN 35
#define CURRENT_PIN 34

// --- Global Objects ---
LiquidCrystal_I2C lcd(0x27, 20, 4);
EnergyMonitor emon;
WiFiClient client;
HTTPClient http;

// --- Calibration Constants ---
#define V_CALIBRATION 83.3
#define CURR_CALIBRATION 2.0

// --- Timing Variables ---
unsigned long previousMillis = 0;
const long interval = 2000;

/**
 * Sends sensor data to the Flask server.
 */
void sendDataToServer(float voltage, float current, float power, bool isOverload) {
    if (WiFi.status() == WL_CONNECTED) {
        
        DynamicJsonDocument doc(1024);

        // --- Populate the JSON object (MODIFIED to match new server) ---
        doc["motor_id"] = motorId;
        doc["voltage"] = voltage;
        doc["current"] = current;
        doc["power"] = power;
        doc["over_voltage"] = (voltage > 240.0);
        doc["over_load_details"] = isOverload;

        String jsonPayload;
        serializeJson(doc, jsonPayload);

        http.begin(client, serverUrl);
        http.addHeader("Content-Type", "application/json");
        http.addHeader("X-API-KEY", apiKey);

        int httpResponseCode = http.POST(jsonPayload);

        if (httpResponseCode > 0) {
            Serial.printf("✅ HTTP Response code: %d\n", httpResponseCode);
        } else {
            Serial.printf("❌ Error sending POST: %s\n", http.errorToString(httpResponseCode).c_str());
        }

        http.end();
    } else {
        Serial.println("WiFi Disconnected. Cannot send data.");
    }
}

/**
 * Reads sensor data, updates the LCD, and checks for overload.
 */
void readAndProcessData()
{
    emon.calcVI(20, 2000);
    bool isOverload = (emon.Irms > 0.3);

    if (isOverload) {
        lcd.clear();
        lcd.setCursor(3, 0);
        lcd.print("OVERLOAD DETECTED");
        lcd.setCursor(5, 1);
        lcd.print("MOTOR IS OFF");
        digitalWrite(RELAY_PIN, HIGH);
    } else {
        digitalWrite(RELAY_PIN, LOW);
        
        lcd.clear();
        lcd.setCursor(0, 0);
        lcd.print("Vrms: ");
        lcd.print(emon.Vrms, 2);
        lcd.print(" V");

        lcd.setCursor(0, 1);
        lcd.print("Irms: ");
        lcd.print(emon.Irms, 4);
        lcd.print(" A");

        lcd.setCursor(0, 2);
        lcd.print("Power: ");
        lcd.print(emon.apparentPower, 4);
        lcd.print(" W");
    }
    
    sendDataToServer(emon.Vrms, emon.Irms, emon.apparentPower, isOverload);
}

void setup()
{
    Serial.begin(115200);

    lcd.init();
    lcd.backlight();
    lcd.setCursor(3, 0);
    lcd.print("INDUCTION MOTOR");
    lcd.setCursor(2, 1);
    lcd.print("OVERLOAD MONITOR");
    delay(2000);
    lcd.clear();

    emon.voltage(VOLTAGE_PIN, V_CALIBRATION, 1.7);
    emon.current(CURRENT_PIN, CURR_CALIBRATION);

    pinMode(RELAY_PIN, OUTPUT);
    digitalWrite(RELAY_PIN, LOW);

    Serial.print("Connecting to ");
    Serial.println(ssid);
    WiFi.begin(ssid, pass);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("\nWiFi connected!");
    Serial.print("IP address: ");
    Serial.println(WiFi.localIP());
}

void loop()
{
    unsigned long currentMillis = millis();
    if (currentMillis - previousMillis >= interval) {
        previousMillis = currentMillis;
        readAndProcessData();
    }
}