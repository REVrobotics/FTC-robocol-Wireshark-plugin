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
    version = "0.0.2",
    description = "FIRST Tech Challenge robocol dissector",
    author = "REV Robotics",
    repository = "https://github.com/REVrobotics/FTC-robocol-Wireshark-plugin"
})

local proto_robocol = Proto.new("robocol", "Robocol")

-- Mapping of Robocol type values to their names
local robocol_types_table = {
    [0] = "Empty",
    [1] = "Heartbeat",
    [2] = "Gamepad",
    [3] = "Peer Discovery",
    [4] = "Command",
    [5] = "Telemetry",
    [6] = "Keepalive"
}

-- The Robocol packet will be parsed according to these ProtoFields
local robocol_field_type = ProtoField.int8("robocol.type", "Type", base.DEC, robocol_types_table)
local robocol_field_payload_len = ProtoField.int16("robocol.payload_len", "Payload Length", base.DEC)
local robocol_field_sequence_num = ProtoField.int16("robocol.sequence_num", "Sequence Number", base.DEC)
local robocol_field_payload = ProtoField.new("Payload", "robocol.payload", ftypes.NONE)
-- Fields only populated for PeerDiscovery packets
local robocol_field_version = ProtoField.int8("robocol.version", "Version", base.DEC)
local robocol_field_peer_type = ProtoField.int8("robocol.peer_type", "Peer Type", base.DEC)
--
proto_robocol.fields = { robocol_field_type, robocol_field_payload_len, robocol_field_sequence_num, robocol_field_payload, robocol_field_version, robocol_field_peer_type }

-- These fields will allow us to access the data after it has been parsed
local robocol_type_field = Field.new("robocol.type")

-- Robocol dissection function
function proto_robocol.dissector(buf, pinfo, root)
 	-- Before we add a tree to the root, check what type of packet this is, and thereby determine the header length
    local type_pos = 0
    local type_buffer = buf(type_pos, 1)
	local packet_type = type_buffer:uint()
	local is_peer_discovery = packet_type == 3

    local header_length
    if is_peer_discovery then
		header_length = 13
	else
		header_length = 5
	end

    -- For now we only parse Heartbeat payloads
    local parse_payload = packet_type == 1

    local packet_length
    if parse_payload then
        packet_length = header_length
    else
        packet_length = buf:len()
    end
	
	local tree = root:add(proto_robocol, buf(0, packet_length))
    tree:add(robocol_field_type, type_buffer)

    local payload_len_pos = 1
    local payload_len_buffer = buf(payload_len_pos, 2)
    tree:add(robocol_field_payload_len, payload_len_buffer)

    local sequence_num_pos = 3

    if is_peer_discovery then
        -- This is a peer discovery packet, which has a different format from all other packet types.
        local version_pos = 3
        local version_buffer = buf(version_pos, 1)
        tree:add(robocol_field_version, version_buffer)

        local peer_type_pos = 4
        local peer_type_buffer = buf(peer_type_pos, 1)
        tree:add(robocol_field_peer_type, peer_type_buffer)

        sequence_num_pos = 5
    end

    local sequence_num_buffer = buf(sequence_num_pos, 2)
    tree:add(robocol_field_sequence_num, sequence_num_buffer)
	
	if packet_type == 1 then
		Dissector.get("robocol-heartbeat"):call(buf(header_length):tvb(), pinfo, tree)
    else
        local payload_buffer = buf(header_length)
        tree:add(robocol_field_payload, payload_buffer)
	end

    pinfo.cols.protocol = "Robocol"
    pinfo.cols.info:clear()
    pinfo.cols.info:append("Type: " .. robocol_type_field().display)
    tree:append_text(", Type: " .. robocol_type_field().display)
end

udp_table = DissectorTable.get("udp.port"):add(20884, proto_robocol)

-- Robocol Heartbeat parsing

local proto_robocol_heartbeat = Proto.new("robocol-heartbeat", "Robocol Heartbeat")

-- The Heartbeat packet will be parsed according to these ProtoFields
local robocol_heartbeat_field_timestamp = ProtoField.int64("robocol-heartbeat.timestamp", "Timestamp", base.DEC)
local robocol_heartbeat_field_robot_state = ProtoField.int8("robocol-heartbeat.robot_state", "Robot State", base.DEC)
local robocol_heartbeat_field_t0 = ProtoField.int64("robocol-heartbeat.t0", "t0", base.DEC)
local robocol_heartbeat_field_t1 = ProtoField.int64("robocol-heartbeat.t1", "t1", base.DEC)
local robocol_heartbeat_field_t2 = ProtoField.int64("robocol-heartbeat.t2", "t2", base.DEC)
local robocol_heartbeat_field_timezone_id_length = ProtoField.int8("robocol-heartbeat.timezone_id_length", "Timezone ID Length", base.DEC)
local robocol_heartbeat_field_timezone_id = ProtoField.string("robocol-heartbeat.timezone_id", "Timezone ID", base.UNICODE)

proto_robocol_heartbeat.fields = {
	robocol_heartbeat_field_timestamp,
	robocol_heartbeat_field_robot_state,
	robocol_heartbeat_field_t0,
	robocol_heartbeat_field_t1,
	robocol_heartbeat_field_t2,
	robocol_heartbeat_field_timezone_id_length,
	robocol_heartbeat_field_timezone_id
}

-- These fields will allow us to access the data after it has been parsed
local robocol_heartbeat_timezone_id_length_field = Field.new("robocol-heartbeat.timezone_id_length")

function proto_robocol_heartbeat.dissector(buf, pinfo, root)
	local tree = root:add(proto_robocol_heartbeat, buf())
	
	local timestamp_position = 0
    local timestamp_buffer = buf(timestamp_position, 8)
    tree:add(robocol_heartbeat_field_timestamp, timestamp_buffer)
	
	local robot_state_position = 8
    local robot_state_buffer = buf(robot_state_position, 1)
    tree:add(robocol_heartbeat_field_robot_state, robot_state_buffer)

    local t0_position = 9
    local t0_buffer = buf(t0_position, 8)
    tree:add(robocol_heartbeat_field_t0, t0_buffer)

    local t1_position = 17
    local t1_buffer = buf(t1_position, 8)
    tree:add(robocol_heartbeat_field_t1, t1_buffer)

    local t2_position = 25
    local t2_buffer = buf(t2_position, 8)
    tree:add(robocol_heartbeat_field_t2, t2_buffer)

    local timezone_id_length_position = 33
    local timezone_id_length_buffer = buf(timezone_id_length_position, 1)
    tree:add(robocol_heartbeat_field_timezone_id_length, timezone_id_length_buffer)

    local timezone_id_position = 34
    local timezone_id_buffer = buf(timezone_id_position, robocol_heartbeat_timezone_id_length_field().value)
    tree:add(robocol_heartbeat_field_timezone_id, timezone_id_buffer)

    pinfo.cols.protocol = "Robocol Heartbeat"
end
