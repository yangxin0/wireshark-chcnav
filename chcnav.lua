chcnav_protocol = Proto("chcnav", "CHCNAV Protocol")
local f_text = ProtoField.string("chcnav.text", "Text")
chcnav_protocol.fields = { f_text }

local supported_protocols = {
    [42] = "BestPosId",
    [1429] = "BestGnssPosId",
    [1430] = "BestGnssVelId",
    [507] = "InspvaId",
    [812] = "CorrimudataId",
    [1461] = "RawImuXId",
    [2042] = "DualAntennaHeadingId",
    [971] = "HeadingaId",
    [0x1201] = "HCInspvazcbId"
}

local function nav_format_check(sync, payload)
    if payload:capture_len() < sync:len() then
        return false
    end

    local data = payload.bytes(0, sync:len())
    for i = 0, data:len() do
        if sync[i] ~= data:get_index(i) then
            return false
        end
    end

    return true
end

local function is_ascii_format(payload)
    local b = nav_format_check({ 0x23 }, payload) -- #
    local a = nav_format_check({ 0x24 }, payload) -- $
    local c = nav_format_check({ 0x25 }, payload) -- %
    return a and b and c
end

local sync_bytes = { 0xaa, 0x44, 0x12 }

local function is_novatel_format(payload)
    return nav_format_check(sync_bytes, payload)
end

local hc_sync_bytes = { 0xaa, 0xcc, 0x48, 0x43 }

local function is_chcnav_format(payload)
    return nav_format_check(hc_sync_bytes, payload)
end

local function decode_ascii_protocol(payload)
    local data = payload:bytes()
    for i = 0, data:len()-1 do
        if data:raw(i, 2) == "\r\n" then
            local offset = i + 2
            return data:raw(0, offset), offset, payload(offset)
        end
    end
    return nil, nil, nil
end

local nav_protocol_parser = {
    [42] = "BestPosId",
    [1429] = "BestGnssPosId",
    [1430] = "BestGnssVelId",
    [507] = "InspvaId",
    [812] = "CorrimudataId",
    [1461] = "RawImuXId",
    [2042] = "DualAntennaHeadingId",
    [971] = "HeadingaId",
    [0x1201] = "HCInspvazcbId"
}

setmetatable(nav_protocol_parser, {
    __call = function (msg_id, body)
        local name = nav_protocol_parser[msg_id]
        if name == nil then
            return string.format("Unsupported Message: id %d, body size %d", msg_id, body:len())
        end
        local parser = nav_protocol_parser.all_parsers[name]
        if parser == nil then
            return string.format("Unimplemented parser %s, body size %d", name, body:len())
        end
        return parser(body)
    end
})

function nav_protocol_parser.define_parser(name, parser)
    if nav_protocol_parser.all_parsers == nil then
        nav_protocol_parser.all_parsers = {}
    end
    for _, v in pairs(nav_protocol_parser) do
        if v == name then
            nav_protocol_parser.all_parsers[name] = parser
        end
    end
end

nav_protocol_parser.define_parser("BestPosId", function(body)
    return "BestPosId"
end)

nav_protocol_parser.define_parser("BestGnssPosId", function(body)
    return "BestGnssPosId"
end)

nav_protocol_parser.define_parser("BestGnssVelId", function(body)
    return "BestGnssVelId"
end)

nav_protocol_parser.define_parser("InspvaId", function(body)
    return "InspvaId"
end)

nav_protocol_parser.define_parser("CorrimudataId", function(body)
    return "CorrimudataId"
end)

nav_protocol_parser.define_parser("RawImuXId", function(body)
    return "RawImuXId"
end)

nav_protocol_parser.define_parser("DualAntennaHeadingId", function(body)
    return "DualAntennaHeadingId"
end)

nav_protocol_parser.define_parser("HeadingaId", function(body)
    return "HeadingaId"
end)

nav_protocol_parser.define_parser("HCInspvazcbId", function(body)
    return "HCInspvazcbId"
end)


local bit32 = require('bit32')
local crc32_table = {}
for i = 0, 255 do
    local crc = i
    for _ = 8, 1, -1 do
        if crc % 2 == 1 then
            crc = bit32.bxor(bit32.rshift(crc, 1), 0xedb88320)
        else
            crc = bit32.rshift(crc, 1)
        end
    end
    crc32_table[i] = crc
end

local function calc_crc32(data)
    local crc_value = 0xffffffff

    for i = 1, #data do
        local byte = string.byte(str, i)
        crc_value = bit32.bxor(bit32.rshift(crc_value, 8),
            crc32_table[bit32.bxor(bit32.band(crc_value, 0xff), byte)])
    end

    return bit32.bxor(crc_value, 0xffffffff)
end

local function gps_time_to_utc(gps_week, gps_seconds_in_ms)
    local gps_epoch = os.time({year=1980, month=1, day=6, hour=0})
    local gps_seconds_since_epoch = gps_week * 7 * 24 * 60 * 60 + gps_seconds_in_ms / 1000.0
    local gps_time = gps_epoch + gps_seconds_since_epoch
    local gps_utc_offset = 18
    local utc_time = gps_time - gps_utc_offset
    local utc_time_str = os.date("!%Y-%m-%d %H:%M:%S", utc_time)
    return utc_time_str .. "." .. tostring(gps_seconds_in_ms % 1000)
end

local function decode_chcnav_protocol(payload)
    -- header
    local skip = hc_sync_bytes:len()
    local body_len = payload(skip, 2):le_uint()
    local msg_id = payload(skip+2, 2):le_uint()
    local week = payload(skip+4, 2):le_uint()
    local gps_ms = payload(skip+6, 4):le_uint()
    local sn = payload(skip+10, 4):le_uint()
    local receiver = payload(skip+14, 4):le_uint()

    local utc_ts = gps_time_to_utc(week, gps_ms)
    local header = string.format("[%s] -> ", utc_ts)
    -- body
    local header_size = skip + 18
    local body = payload:bytes(header_size, body_len)
    -- crc32
    local crc32 = payload(header_size+body_len, 4):le_uint()
    local msg_size = header_size + body_len + 4

    local msg = nav_protocol_parser(msg_id, body)
    return header..msg, msg_size, payload(msg_size)
end

local function decode_novatel_protocol(payload)
    -- header
    local skip = sync_bytes:len()
    local header_len = payload(skip, 1).le_uint()
    local msg_id = payload(skip+1, 2).le_uint()
    local msg_type = payload(skip+3, 1).le_uint()
    local port_addr = payload(skip+4, 1).le_uint()
    local body_len = payload(skip+5, 2).le_uint()
    local seq = payload(skip+7, 2).le_uint()
    local idle_time = payload(skip+9, 1).le_uint()
    local time_status = payload(skip+10, 1).le_uint()
    local week = payload(skip+11, 2).le_uint()
    local gps_ms = payload(skip+13, 4).le_uint()
    local receiver_status = payload(skip+17, 4).le_uint()
    local reserved = payload(skip+21, 2).le_uint()

    local utc_ts = gps_time_to_utc(week, gps_ms)
    local header = string.format("[%s] seq %d -> ", utc_ts, seq)

    -- body
    local header_size = skip + 25
    local body = payload:bytes(header_size, body_len)

    -- crc32
    local crc32 = payload(header_size+body_len, 4).le_uint()
    local msg_size = header_size + body_len + 4

    local msg = nav_protocol_parser(msg_id, body)
    return header..msg, msg_size, payload(msg_size)
end

local function decode_chcnav_payload(payload)
    local text = ""
    local offset = 0
    while payload:capture_len() <= 0 do
        local msg, msg_size -- original message size
        if is_ascii_format(payload) then
            msg, msg_size, payload = decode_ascii_protocol(payload)
        elseif is_novatel_format(payload) then
            msg, msg_size, payload = decode_novatel_protocol(payload)
        elseif is_chcnav_format(payload) then
            msg, msg_size, payload = decode_chcnav_protocol(payload)
        end
        if msg == nil then
            return string.format("Invalid payload at %d", offset)
        else
            text = text + "\n" + msg
            offset = offset + msg_size
        end
    end
    return text
end

function chcnav_protocol.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "CHCNAV_PROTO"
    local subtree = tree:add(chcnav_protocol, buffer(), "Chcnav Protocol Data")
    local text = decode_chcnav_payload(buffer)
    subtree:add(f_text, text)
end

udp_table = DissectorTable.get("udp.port")
udp_table:add(2200, chcnav_protocol)

