import unittest
from unittest.mock import patch, MagicMock
import platform

# This is a bit of a hack to make the test run in this environment
# We need to import the class we're testing
import sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from discovery import HostDiscoverer

class TestHostDiscoverer(unittest.TestCase):

    def setUp(self):
        self.discoverer = HostDiscoverer()

    @unittest.skipIf(platform.system() != "Linux", "This test is for Linux only")
    @patch('subprocess.check_output')
    def test_get_ssid_linux_iwgetid(self, mock_check_output):
        # Mock the output of 'iwgetid -r'
        mock_check_output.return_value = "MyTestSSID\n"

        ssid = self.discoverer._get_ssid_linux('wlan0')

        self.assertEqual(ssid, "MyTestSSID")
        mock_check_output.assert_called_once_with(['iwgetid', '-r', 'wlan0'], text=True, timeout=3)

    @unittest.skipIf(platform.system() != "Linux", "This test is for Linux only")
    @patch('subprocess.check_output')
    def test_get_ssid_linux_nmcli(self, mock_check_output):
        # Mock the output of 'nmcli' and a failure for 'iwgetid'
        mock_check_output.side_effect = [
            FileNotFoundError,  # Simulate 'iwgetid' not found
            "yes:MyTestSSID\nno:OtherSSID\n"
        ]

        ssid = self.discoverer._get_ssid_linux('wlan0')

        self.assertEqual(ssid, "MyTestSSID")
        self.assertEqual(mock_check_output.call_count, 2)

    @unittest.skipIf(platform.system() != "Windows", "This test is for Windows only")
    @patch('subprocess.check_output')
    def test_get_ssid_windows(self, mock_check_output):
        # Mock the output of 'netsh wlan show interfaces'
        mock_output = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    GUID                   : 12345678-1234-1234-1234-1234567890ab
    Physical address       : ab:cd:ef:12:34:56
    State                  : connected
    SSID                   : MyTestSSID
    BSSID                  : 12:34:56:78:90:ab
    Network type           : Infrastructure
    Radio type             : 802.11ax
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Connection mode        : Auto Connect
    Channel                : 149
    Receive rate (Mbps)    : 1201
    Transmit rate (Mbps)   : 1201
    Signal                 : 99%
    Profile                : MyTestSSID

    Hosted network status  : Not available
"""
        mock_check_output.return_value = mock_output

        ssid = self.discoverer._get_ssid_windows()

        self.assertEqual(ssid, "MyTestSSID")
        mock_check_output.assert_called_once_with(
            ['netsh', 'wlan', 'show', 'interfaces'],
            text=True, timeout=3, creationflags=unittest.mock.ANY
        )

if __name__ == '__main__':
    unittest.main()
