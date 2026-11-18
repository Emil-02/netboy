// Package oui provides offline MAC address vendor resolution.
package oui

import (
	"strings"
)

// curatedOUIs maps uppercase 6-hex-digit prefix (OUI) to vendor name.
var curatedOUIs = map[string]string{
	// Popular Networking & Routers
	"001A2B": "Ayecom Technology",
	"001D7E": "Cisco-Linksys",
	"00259C": "Cisco Systems",
	"004096": "Cisco Systems",
	"0050BA": "D-Link Systems",
	"0018E7": "TP-Link Technologies",
	"14CC20": "TP-Link Technologies",
	"50C7BF": "TP-Link Technologies",
	"704F57": "TP-Link Technologies",
	"AC84C6": "TP-Link Technologies",
	"B04E26": "TP-Link Technologies",
	"D807B6": "TP-Link Technologies",
	"E848B8": "TP-Link Technologies",
	"0014D1": "Trendnet",
	"0024A5": "Buffalo Inc.",
	"000FB5": "NETGEAR",
	"20E52A": "NETGEAR",
	"A00460": "NETGEAR",
	"000C42": "MikroTik",
	"488F5A": "MikroTik",
	"64D154": "MikroTik",
	"789A18": "MikroTik",
	"B869F4": "MikroTik",
	"CC2DE0": "MikroTik",
	"E48D8C": "MikroTik",
	"0418D6": "Ubiquiti Networks",
	"24A43C": "Ubiquiti Networks",
	"788A20": "Ubiquiti Networks",
	"AC8BA9": "Ubiquiti Networks",
	"B4FBE4": "Ubiquiti Networks",
	"F09FC2": "Ubiquiti Networks",
	"706979": "Ruijie Networks",

	// IoT, Single-Board Computers & Microcontrollers
	"B827EB": "Raspberry Pi Foundation",
	"DCA632": "Raspberry Pi Trading",
	"E45F01": "Raspberry Pi Trading",
	"28CDC1": "Raspberry Pi Trading",
	"240AC4": "Espressif Systems (ESP32/ESP8266)",
	"30AE7B": "Espressif Systems (ESP32/ESP8266)",
	"246F28": "Espressif Systems (ESP32/ESP8266)",
	"A4CF12": "Espressif Systems (ESP32/ESP8266)",
	"3C71BF": "Espressif Systems (ESP32/ESP8266)",
	"84F3EB": "Espressif Systems (ESP32/ESP8266)",
	"D8BFC0": "Espressif Systems (ESP32/ESP8266)",
	"4022D8": "Espressif Systems (ESP32/ESP8266)",
	"48E729": "Espressif Systems (ESP32/ESP8266)",
	"A0764E": "Espressif Systems (ESP32/ESP8266)",
	"2C3AE8": "Arduino SA",
	"A4E57C": "Arduino SA",

	// Tech Giants & End Devices
	"001788": "Philips Lighting (Hue)",
	"001E06": "Wistron InfoComm",
	"00216A": "Intel Corporate",
	"001B21": "Intel Corporate",
	"3C5AB4": "Google Inc.",
	"D8EB97": "Google Inc.",
	"F4F5DB": "Google Inc.",
	"546009": "Google Inc.",
	"00FC8B": "Amazon Technologies",
	"38F73D": "Amazon Technologies",
	"44650D": "Amazon Technologies",
	"6854FD": "Amazon Technologies",
	"AC63BE": "Amazon Technologies",
	"F0F002": "Amazon Technologies",
	"FC65DE": "Amazon Technologies",

	// Apple
	"000393": "Apple Inc.",
	"001451": "Apple Inc.",
	"001C42": "Apple Inc.",
	"1499E2": "Apple Inc.",
	"3C0754": "Apple Inc.",
	"701124": "Apple Inc.",
	"A483E7": "Apple Inc.",
	"BC5451": "Apple Inc.",
	"F01898": "Apple Inc.",

	// Virtualization & Containers
	"000569": "VMware, Inc.",
	"000C29": "VMware, Inc.",
	"005056": "VMware, Inc.",
	"080027": "Oracle VirtualBox",
	"525400": "QEMU/KVM Virtual NIC",
	"0242AC": "Docker Container Bridge",

	// PC & Server Hardware
	"001422": "Dell Inc.",
	"001E4F": "Dell Inc.",
	"1866DA": "Dell Inc.",
	"001EC9": "HP Inc.",
	"2C59E5": "HP Inc.",
	"002354": "ASUSTek Computer Inc.",
	"04D4C4": "ASUSTek Computer Inc.",
	"704D7B": "ASUSTek Computer Inc.",
	"001A92": "ASRock Incorporation",
	"00D861": "Micro-Star INT'L (MSI)",
	"D85ED3": "Micro-Star INT'L (MSI)",
	"54EE75": "Pegatron Corporation",
	"6045CB": "Shenzhen Bilian Electronic",

	// Mobile & Smart Devices
	"002637": "Samsung Electronics",
	"3423BA": "Samsung Electronics",
	"508569": "Samsung Electronics",
	"68EBae": "Samsung Electronics",
	"A80600": "Samsung Electronics",
	"CC07AB": "Samsung Electronics",
	"009EEA": "Xiaomi Communications",
	"286C07": "Xiaomi Communications",
	"3480B3": "Xiaomi Communications",
	"50642B": "Xiaomi Communications",
	"646E69": "Xiaomi Communications",
	"880145": "Xiaomi Communications",
	"C871A2": "Xiaomi Communications",
	"00237D": "Huawei Device Co., Ltd.",
	"200BC7": "Huawei Device Co., Ltd.",
	"4846FB": "Huawei Device Co., Ltd.",
	"708A09": "Huawei Device Co., Ltd.",
}

// NormalizeMAC strips separators and returns standard formatted prefix.
func cleanPrefix(mac string) string {
	mac = strings.ToUpper(mac)
	var sb strings.Builder
	for _, ch := range mac {
		if (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') {
			sb.WriteRune(ch)
		}
	}
	s := sb.String()
	if len(s) >= 6 {
		return s[:6]
	}
	return ""
}

// Lookup attempts to resolve a MAC address to a known vendor string.
// If unknown, returns "Unknown" or empty string if mac is invalid.
func Lookup(mac string) string {
	prefix := cleanPrefix(mac)
	if prefix == "" {
		return ""
	}
	if vendor, ok := curatedOUIs[prefix]; ok {
		return vendor
	}
	return "Unknown Vendor"
}
