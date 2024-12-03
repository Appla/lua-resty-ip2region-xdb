---
--- ip2region v2's LuaJIT FFI based implementation
---
--- @author Appla<bhg@live.it>.
--- @version 0.2.0
--- @license Apache License Version 2.0
---

local ffi = require "ffi"

local ffi_new = ffi.new
local ffi_string = ffi.string
local ffi_cast = ffi.cast
local ffi_typeof = ffi.typeof

local bit = require "bit"
local lshift = bit.lshift
local rshift = bit.rshift
local band = bit.band

local assert = assert
local error = error
local type = type
local select = select
local setmetatable = setmetatable
local io_open = io.open
local str_find = string.find
local str_sub = string.sub
local new_tab = require "table.new"

--// public constants definition
--local XDB_HEADER_SIZE = 256
--local XDB_IDX_ROWS = 256
local XDB_IDX_COLS = 256
--local XDB_IDX_ENTRY_SIZE = 8
local XDB_SEGMENT_IDX_SIZE = 14
local XDB_SEGMENT_IDX_IP_SIZE = 8

ffi.cdef [[
typedef union {
    uint32_t u32;
    struct {
        uint8_t b0;
        uint8_t b1;
        uint8_t b2;
        uint8_t b3;
    };
} la_u32_ut;

typedef struct {
    la_u32_ut sp;
    la_u32_ut ep;
} xdb_1st_idx_entity_t;

typedef struct {
    unsigned short version;
    unsigned short index_policy;
    unsigned int created_at;
    unsigned int start_index_ptr;
    unsigned int end_index_ptr;
    unsigned char buffer[240];
    xdb_1st_idx_entity_t indexes[65536];
} xdb_header_t;

typedef struct {
    unsigned int length;
    xdb_header_t *header;
    const unsigned char *data;
} xdb_entity_t;

typedef struct __attribute((packed, aligned(2))) {
    la_u32_ut start_ip;
    la_u32_ut end_ip;
    uint16_t data_len;
    uint32_t data_ptr;
} xdb_2nd_idx_entity_t;

typedef struct {
    la_u32_ut start_ip;
    la_u32_ut end_ip;
} xdb_2nd_idx_entity_ip_t;

typedef struct __attribute((packed, aligned(2))){
    uint16_t data_len;
    uint32_t data_ptr;
} xdb_2nd_idx_entity_data_t;

typedef xdb_2nd_idx_entity_t xdb_segment_index_t;

void *memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);
int inet_pton(int af, const char *src, void *dst);
uint32_t ntohl(uint32_t netlong);
]]

-- holding the file content
local XDB_FILE_REGISTRY = new_tab(0, 4)

-- the official xdb data format is like: country/region|flags|province|city|isp
-- 中国|0|上海|上海市|电信
local IP_INFO_FIELD_INDEXES = {
    country = 1,
    region = 2,
    flags = 2,
    province = 3,
    city = 4,
    isp = 5,
}

-- C functions
local C = ffi.C

-- ctypes
local const_char_ptr_ct = ffi_typeof("const unsigned char *")
local xdb_2nd_idx_entity_data_ptr_ct = ffi_typeof('xdb_2nd_idx_entity_data_t *')
local xdb_2nd_idx_entity_ip_ptr_ct = ffi_typeof('xdb_2nd_idx_entity_ip_t *')

local _M = {
    _VERSION = '0.2.0',
    IP_INFO_FIELD_INDEXES = IP_INFO_FIELD_INDEXES,

    --constants
    IDX_COUNTRY = 1,
    IDX_REGION = 2,
    IDX_FLAGS = 2,
    IDX_PROVINCE = 3,
    IDX_CITY = 4,
    IDX_ISP = 5,
    IDX_MAX = 6,
}

local mt = { __index = _M }

local ipv4_to_long
do
    local in_addr = ffi_new('uint32_t[1]')

    --ipv4 to bin
    ---@param ip4 string ensuring ipv4 is valid
    ---@return number
    function ipv4_to_long(ip4)
        local rc = C.inet_pton(2, ip4, in_addr)
        if rc ~= 1 then
            return 0
        end
        return C.ntohl(in_addr[0])
    end
end

local parse_bin_ipv4
do
    local inet_in_addr = ffi_new("uint32_t[1]")
    local ffi_copy = ffi.copy

    function parse_bin_ipv4(ip)
        if type(ip) ~= "string" or #ip ~= 4 then
            return nil, "invalid ip"
        end

        ffi_copy(inet_in_addr, ip, 4)
        return C.ntohl(inet_in_addr[0])
    end
end

-- This should be called in sep-thread or blocking-tolerance contexts
---@param filename string
---@return string
local function load_file(filename)
    local f = assert(io_open(filename, "rb"))
    local content = f:read("*all")
    f:close()
    return content
end

do
    -- openresty specific
    if ngx then
        -- @TODO using ngx.run_worker_thread to load?
        local get_phase = ngx.get_phase
        function load_file(filename)
            local phase = get_phase()
            if phase ~= "init" and phase ~= "init_worker" then
                error("load_file should be called in init phase or init_worker phase")
            end
            local f = assert(io_open(filename, "rb"))
            local content = f:read("*all")
            f:close()
            return content
        end
    end
end

---@param content string
---@return table
local function new_xdb_searcher(content)
    local entry = ffi_new("xdb_entity_t")
    entry.length = #content
    entry.header = ffi_cast("xdb_header_t *", content)
    entry.data = ffi_cast(const_char_ptr_ct, content)
    return entry
end

-- ensure this is called in non-blocking ctx or blocking tolerate ctx
---@param filename string
---@return table, string
local function new_xdb_searcher_from_file(filename)
    local content = load_file(filename)
    return new_xdb_searcher(content), content
end

-- Split by str separator(this usually more faster than ffi version, but alloc more strings)
---@param str string
---@param separator string
---@param dst_tab table
---@return table
local function str_split(str, separator, dst_tab)
    if type(str) == "string" then
        dst_tab = dst_tab or new_tab(5, 5)
        local idx = 1
        local offset = 1
        while true do
            local pos_s, pos_e = str_find(str, separator, offset, true);
            if not pos_s then
                dst_tab[idx] = offset > 1 and str_sub(str, offset) or str
                break
            end
            dst_tab[idx] = str_sub(str, offset, pos_s - 1)
            idx = idx + 1
            offset = pos_e + 1
        end
        return dst_tab
    end
    return nil, "invalid args"
end

-- search IP(long int little endian) in xdb
--- @param xdb_searcher table xdb_searcher_t cdata
--- @param ip number ip in long int little endian
--- @return cdata|nil, string|number
--- @todo using be ip to eliminate shifting?
local function search_binary_ip(xdb_searcher, ip)
    if ip == 0 then return nil, "invalid ip"; end
    local l = 0
    local start_idx, h
    do
        local col, row = band(rshift(ip, 24), 0xFF), band(rshift(ip, 16), 0xFF)
        local ptr = xdb_searcher.header.indexes[col * XDB_IDX_COLS + row]
        start_idx = ptr.sp.u32
        h = (ptr.ep.u32 - start_idx) / XDB_SEGMENT_IDX_SIZE;
    end
    local data_ptr
    local data_len = 0
    while l <= h do
        local m = rshift(l + h, 1)
        local m_ptr = xdb_searcher.data + start_idx + (m * XDB_SEGMENT_IDX_SIZE)
        local idx_elt = ffi_cast(xdb_2nd_idx_entity_ip_ptr_ct, m_ptr)
        if ip < idx_elt.start_ip.u32 then
            h = m - 1
        else
            if ip > idx_elt.end_ip.u32 then
                l = m + 1
            else
                local data_elt = ffi_cast(xdb_2nd_idx_entity_data_ptr_ct, m_ptr + XDB_SEGMENT_IDX_IP_SIZE)
                data_len = data_elt.data_len
                data_ptr = data_elt.data_ptr
                break
            end
        end
    end

    if data_len == 0 then
        return nil, "not found"
    end
    return xdb_searcher.data + data_ptr, data_len
end

do
    -- @FIXME test needed for big-endian version
    -- big-endian version
    if ffi.abi("be") then
        local function la_u32_to_big_endian(la_u32_elt)
            return la_u32_elt.b0 + lshift(la_u32_elt.b1, 8) + lshift(la_u32_elt.b2, 16) + lshift(la_u32_elt.b3, 24)
        end

        search_binary_ip = function(xdb_searcher, ip)
            if ip == 0 then return nil, "invalid ip"; end
            local l = 0
            local start_idx, h
            do
                local col, row = band(rshift(ip, 24), 0xFF), band(rshift(ip, 16), 0xFF)
                local ptr = xdb_searcher.header.indexes[col * XDB_IDX_COLS + row]
                start_idx = la_u32_to_big_endian(ptr.sp)
                h = (la_u32_to_big_endian(ptr.ep) - start_idx) / XDB_SEGMENT_IDX_SIZE;
            end
            local data_ptr
            local data_len = 0
            while l <= h do
                local m = rshift(l + h, 1)
                local m_ptr = xdb_searcher.data + start_idx + (m * XDB_SEGMENT_IDX_SIZE)
                local idx_elt = ffi_cast(xdb_2nd_idx_entity_ip_ptr_ct, m_ptr)
                local seg_start_ip = la_u32_to_big_endian(idx_elt.start_ip)
                if ip < seg_start_ip then
                    h = m - 1
                else
                    local seg_end_ip = la_u32_to_big_endian(idx_elt.end_ip)
                    if ip > seg_end_ip then
                        l = m + 1
                    else
                        local data_elt = ffi_cast(xdb_2nd_idx_entity_data_ptr_ct, m_ptr + XDB_SEGMENT_IDX_IP_SIZE)
                        data_len = data_elt.data_len
                        data_ptr = data_elt.data_ptr
                        break
                    end
                end
            end

            if data_len == 0 then
                return nil, "not found"
            end
            return xdb_searcher.data + data_ptr, data_len
        end
    end
end

-- Search an IP address
---@param xdb_searcher table
---@param ip_str string
---@return cdata|nil, string|number
local function search_ip(xdb_searcher, ip_str)
    return search_binary_ip(xdb_searcher, ipv4_to_long(ip_str))
end

-- Search meta info contains any of needles
---@param xdb_searcher table
---@param ip string
---@param arg_t string
---@param nds string|table if table is provided all the rest needles will be ignored.
---@param ... string
---@return boolean, string|nil
local function bin_ip_info_contains_internal(xdb_searcher, ip, arg_t, nds, ...)
    local ptr, len = search_binary_ip(xdb_searcher, ip)
    if not ptr then
        return nil, "not found"
    end
    if arg_t == "string" then
        -- empty needle or found
        if C.memmem(ptr, len, nds, #nds) ~= nil then
            return true
        end
        local nn = select("#", ...)
        for i = 1, nn do
            local needle = select(i, ...)
            if type(needle) ~= "string" then
                return nil, "needle must be type of string"
            end
            if C.memmem(ptr, len, needle, #needle) ~= nil then
                return true
            end
        end
    elseif arg_t == "table" then
        local nn = #nds
        for i = 1, nn do
            local needle = nds[i]
            if type(needle) ~= "string" then
                return nil, "needle must be type of string"
            end
            if C.memmem(ptr, len, needle, #needle) ~= nil then
                return true
            end
        end
    end

    return false, "no one matched"
end

-- Check if binary IP 's region info contains any of needles for official xdb data.
---@param self table
---@param ip string
---@param nds string|table if table is provided all the rest needles will be ignored.
---@param ... string
---@return boolean, string|nil
function _M.binary_ip_info_contains(self, ip, nds, ...)
    local arg_t = type(nds)
    if arg_t ~= "string" and arg_t ~= "table" then
        return nil, "needle must be type of string or table"
    end
    if #nds == 0 then return nil, "needle must not be empty"; end
    if type(ip) ~= "number" then
        ip = parse_bin_ipv4(ip)
        if not ip then
            return nil, "ip must be a number or a string(4)"
        end
    end

    return bin_ip_info_contains_internal(self.xdb_searcher, ip, arg_t, nds, ...)
end

-- Check if IP 's region info contains any of needles for official xdb data.
---@param self table
---@param ip_str number
---@param nds string|table if table is provided all the rest needles will be ignored.
---@param ... string
---@return boolean, string|nil
function _M.ip_info_contains(self, ip_str, nds, ...)
    local arg_t = type(nds)
    if arg_t ~= "string" and arg_t ~= "table" then
        return nil, "needle must be type of string or table"
    end
    if #nds == 0 then return nil, "needle must not be empty"; end
    if type(ip_str) ~= "string" then
        return nil, "ip must be a string"
    end
    return bin_ip_info_contains_internal(self.xdb_searcher, ipv4_to_long(ip_str), arg_t, nds, ...)
end

-- shared table for lookup
local shared_res_tab = new_tab(5, 5)

-- format response
---@param s string
---@param ct number|boolean|nil { nil: table, true: var-args, number: single field, false: raw string }.
---@param dst_tab table|nil
local function format_response(s, ct, dst_tab)
    if ct == nil then
        if type(dst_tab) ~= "table" then
            dst_tab = new_tab(0, 5)
        end
        local res = str_split(s, "|", shared_res_tab)
        dst_tab['country'] = res[1]
        dst_tab['region'] = res[2]
        dst_tab['province'] = res[3]
        dst_tab['city'] = res[4]
        dst_tab['isp'] = res[5]
        return dst_tab
    elseif ct == true then
        local tab = str_split(s, '|', shared_res_tab)
        -- 1:IDX_COUNTRY, 3:IDX_PROVINCE, 4:IDX_CITY, 5:IDX_ISP, 2:IDX_REGION
        return tab[1], tab[3], tab[4], tab[5], tab[2]
    elseif type(ct) == 'number' and ct < 6 then
        -- @TODO create sub-str only if needed?
        shared_res_tab[ct] = nil
        local tab = str_split(s, '|', shared_res_tab)
        return tab[ct]
    else
        return s
    end
end

-- Search IP info for official xdb data.
---@param self table
---@param ip string
---@param ct number|boolean|nil { nil: table, true: var-args, number: single field, false: raw string }.
---@param dst_tab table|nil table to store result, if nil, return a new table.
---@return table,number|nil, string
local function lookup(self, ip, ct, dst_tab)
    if type(ip) ~= "string" then
        return nil, "ip must be a string"
    end
    local s, len_or_err = search_ip(self.xdb_searcher, ip, dst_tab)
    if s then
        return format_response(ffi_string(s, len_or_err), ct, dst_tab)
    end

    return s, len_or_err
end

_M.lookup = lookup

-- Get the city name of an IP address for official xdb data.
---@param ip string
---@return table,number|nil, string
function _M:lookup_city(ip)
    return lookup(self, ip, self.IDX_CITY)
end

-- Alias for lookup
_M.search_ip = lookup

-- Get IP info for official xdb data.
---@param self table
---@param ip number|string binary/uint32 ip address.
---@param ct number|boolean|nil { nil: table, true: var-args, number: single field, false: raw string }.
---@param dst_tab table|nil table to store result, if nil, return a new table.
---@return string|table|nil, string|nil
function _M.search_binary_ip(self, ip, ct, dst_tab)
    if type(ip) ~= "number" then
        ip = parse_bin_ipv4(ip)
        if not ip then
            return nil, "ip must be a number"
        end
    end
    local s, len_or_err = search_binary_ip(self.xdb_searcher, ip)
    if s then
        return format_response(ffi_string(s, len_or_err), ct, dst_tab)
    end
    return s, len_or_err
end

-- Set custom parser
---@param self table
---@param parser_fn function Result Parser function(res_ptr/nil, len/error): any.
---@return table
function _M.set_parser(self, parser_fn)
    if type(parser_fn) ~= "function" then
        return nil, "func must be a function"
    end
    self.parser_fn = parser_fn
    return self
end

-- Get IP info with custom parser for binary ip.
---@param self table
---@param ip number|string binary/uint32 ip address.
---@param parser_fn function Result Parser function.
---@return string|table|nil, string|nil
function _M.lookup_and_parse_binary(self, ip, parser_fn)
    if type(ip) ~= "number" then
        ip = parse_bin_ipv4(ip)
        if not ip then return nil, "ip must be a number or byte[4]"; end
    end
    if type(parser_fn) ~= "function" then
        parser_fn = self.parser_fn;
    end
    return parser_fn(search_binary_ip(self.xdb_searcher, ip))
end

-- Get IP info with custom parser
---@param self table
---@param ip string dot-decimal ip address.
---@param parser_fn function Result Parser function.
---@return string|table|nil, string|nil
function _M.lookup_and_parse(self, ip, parser_fn)
    if type(ip) ~= "string" then
        return nil, "ip must be a string"
    end
    if type(parser_fn) ~= "function" then
        parser_fn = self.parser_fn;
    end
    return parser_fn(search_binary_ip(self.xdb_searcher, ipv4_to_long(ip)))
end

-- Forward the result as string
---@param ptr cdata
---@param len number
---@return string, number
local function forward_str(ptr, len)
    return ffi_string(ptr, len), len
end

-- Forward the result as pointer
---@param ptr cdata
---@param len number
---@return cdata, number
local function forward_ptr(ptr, len)
    return ptr, len
end

-- create a new ip2region object
---@param opts table
---@return table
local function new(opts)
    if type(opts.db_path) ~= "string" then
        error("filename must be a string")
    end
    local self = {
        _raw_contents_ = nil,
        parser_fn = type(opts.parser_fn) == "function" and opts.parser_fn or forward_str,
    }
    if XDB_FILE_REGISTRY[opts.db_path] then
        self._raw_contents_ = XDB_FILE_REGISTRY[opts.db_path]
        self.xdb_searcher = new_xdb_searcher(XDB_FILE_REGISTRY[opts.db_path])
    else
        self.xdb_searcher, self._raw_contents_ = new_xdb_searcher_from_file(opts.db_path)
        XDB_FILE_REGISTRY[opts.db_path] = self._raw_contents_
    end
    setmetatable(self, mt)
    return self
end

_M.new = new

return _M
