


all: hostapd wpa_supplicant
	@echo success

hostapd:
	make -C ./hostapd-2.11/hostapd/ -j4


wpa_supplicant:
	make -C ./wpa_supplicant-2.10/wpa_supplicant/ -j4

clean:
	make -C ./hostapd-2.11/hostapd/ clean
	make -C ./wpa_supplicant-2.10/wpa_supplicant/ clean
