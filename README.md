# FTC Robocol Wireshark Plugin
This [Wireshark](https://www.wireshark.org/) plugin will allow you to better analyze robocol traffic between the FIRST
Tech Challenge Robot Controller and Drvier Station apps.

## Prerequisites for capturing robocol traffic
* [Your WiFi adapter needs to be in monitor mode](https://gitlab.com/wireshark/wireshark/-/wikis/CaptureSetup/WLAN#turning-on-monitor-mode).
    * [airmon-ng](https://www.aircrack-ng.org/doku.php?id=airmon-ng) is a useful tool for this.
    * This only applies when _capturing_ robocol traffic. You do not need to be in monitor mode when you are analyzing a saved packet capture.
* You need to [set up Wireshark to decrypt the WiFi traffic](https://gitlab.com/wireshark/wireshark/-/wikis/HowToDecrypt802.11).
    * Note that the initial WiFi connection (the "4-way handshake") must be included in the capture, or this will not work.
    * You only need to do this when _analyzing_ robocol traffic. You do not need to know the WiFi passwords at the time of capture.
    
## Installing the robocol plugin
1. From the About Wireshark window, select the folders tab, and click the link next to "Personal Lua Plugins".
    ![wireshark about dialog, folders tab](assets/Wireshark-Folders.png)
2. Download the latest version of `robocol.lua` from the [Releases page](https://github.com/REVrobotics/FTC-robocol-Wireshark-plugin/releases), and put it in that folder.
3. Restart Wireshark. Wireshark should now be able to recognize and analyze robocol packets.

Feel free to submit a bug report or a pull request, but please do not contact REV Robotics to ask for Wireshark help.

```
Copyright 2020 REV Robotics

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
```
