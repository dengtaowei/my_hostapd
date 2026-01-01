
sudo killall hostapd
sudo killall wpa_supplicant

sudo ./hostapd-2.11/hostapd/hostapd -d ./hostapd-2.11/hostapd/hostapdwlan0.conf &

sleep 2

sudo ./wpa_supplicant-2.10/wpa_supplicant/wpa_supplicant -D nl80211 -i wlan1 -c ./wpa_supplicant-2.10/wpa_supplicant.conf -d &
