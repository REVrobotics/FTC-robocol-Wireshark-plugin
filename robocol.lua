--[[
    Copyright (C) 2020 REV Robotics

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
]]

set_plugin_info({
    version = "0.0.1",
    description = "FIRST Tech Challenge robocol dissector",
    author = "REV Robotics",
    repository = "https://github.com/REVrobotics/FTC-robocol-Wireshark-plugin"
})

local proto_robocol = Proto.new("robocol", "Robocol")

-- Mapping of type values to their names
local typesTable = {
    [0] = "Empty",
    [1] = "Heartbeat",
    [2] = "Gamepad",
    [3] = "Peer Discovery",
    [4] = "Command",
    [5] = "Telemetry",
    [6] = "Keepalive"
}

-- Our packet will be parsed according to these ProtoFields
local pf_type = ProtoField.uint8("robocol.type", "Type", base.DEC, typesTable)
local pf_payload_len = ProtoField.uint16("robocol.payload_len", "Payload Length", base.DEC)
local pf_sequence_num = ProtoField.uint16("robocol.sequence_num", "Sequence Number", base.DEC)
local pf_payload = ProtoField.new("Payload", "robocol.payload", ftypes.NONE)
-- Fields only populated for PeerDiscovery packets
local pf_version = ProtoField.uint8("robocol.version", "Version", base.DEC)
local pf_peer_type = ProtoField.uint8("robocol.peer_type", "Peer Type", base.DEC)
--
proto_robocol.fields = { pf_type, pf_payload_len, pf_sequence_num, pf_payload, pf_version, pf_peer_type }

-- These fields will allow us to access the data after it has been parsed
local type_field = Field.new("robocol.type")

-- Dissection function
function proto_robocol.dissector(tvb, pinfo, root)
    local tree = root:add(proto_robocol, tvb())

    local type_pos = 0
    local type_buffer = tvb(type_pos, 1)
    tree:add(pf_type, type_buffer)

    local payload_len_pos = 1
    local payload_len_buffer = tvb(payload_len_pos, 2)
    tree:add(pf_payload_len, payload_len_buffer)

    local sequence_num_pos = 3
    local payload_pos = 5

    if type_buffer:uint() == 3 then
        -- This is a peer discovery packet, which has a different format from all other packet types.

        local version_pos = 3
        local version_buffer = tvb(version_pos, 1)
        tree:add(pf_version, version_buffer)

        local peer_type_pos = 4
        local peer_type_buffer = tvb(peer_type_pos, 1)
        tree:add(pf_peer_type, peer_type_buffer)

        sequence_num_pos = 5
        payload_pos = 7
    end

    local sequence_num_buffer = tvb(sequence_num_pos, 2)
    tree:add(pf_sequence_num, sequence_num_buffer)

    local payload_buffer = tvb(payload_pos)
    tree:add(pf_payload, payload_buffer)

    pinfo.cols.protocol = "Robocol"
    pinfo.cols.info:clear()
    pinfo.cols.info:append("Type: " .. type_field().display)
    tree:append_text(", Type: " .. type_field().display)
end

udp_table = DissectorTable.get("udp.port"):add(20884, proto_robocol)
