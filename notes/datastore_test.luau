--!strict
-- DataStore test runner for Studio-Offline.
-- Run this as a LocalScript or Script in Studio (or paste into the Command Bar).
-- It exercises the local file-backed datastore served by studio_offline_server
-- at /v2/persistence/{user_id}/datastores/... via DataStoreService.
--
-- How to use:
--   1. Start Studio-Offline server (port 80) and open Studio offline.
--   2. Create a Script in Workspace (or ServerScriptService), paste this in.
--   3. Run/play the place; read the Output window.
--
-- Results are reported as:  [PASS] name   /   [FAIL] name - reason

local DataStoreService = game:GetService("DataStoreService")

local STORE_NAME = "OfflineTestStore"
local SCOPE = "global" -- "global" is stored as the default scope dir
local KEY_PREFIX = "test_key_"

local passed = 0
local failed = 0

local function report(name: string, ok: boolean, detail: string?)
	if ok then
		passed += 1
		print(string.format("[PASS] %s", name))
	else
		failed += 1
		print(string.format("[FAIL] %s - %s", name, detail or "no detail"))
	end
end

local function expect(cond: boolean, msg: string): boolean
	if not cond then
		error(msg, 2)
	end
	return true
end

-- A tiny JSON encoder/decoder so we can verify table round-trips without
-- relying on HttpService. Values stored are raw file bytes; DataStoreService
-- will serialize Lua tables to JSON on the server side.
local Json = {
	encode = function(v)
		local function enc(x)
			if type(x) == "string" then
				return '"' .. x:gsub('"', '\\"') .. '"'
			elseif type(x) == "number" then
				return tostring(x)
			elseif type(x) == "boolean" then
				return tostring(x)
			elseif type(x) == "table" then
				local parts = {}
				for k, val in pairs(x) do
					table.insert(parts, '"' .. tostring(k) .. '":' .. enc(val))
				end
				return "{" .. table.concat(parts, ",") .. "}"
			else
				return 'null'
			end
		end
		return enc(v)
	end,
}

local function makeStore()
	return DataStoreService:GetDataStore(STORE_NAME, SCOPE)
end

local function cleanupKeys()
	-- Remove any leftover keys from a previous run so results are deterministic.
	local ok, err = pcall(function()
		local store = makeStore()
		local pages = store:ListKeysAsync(KEY_PREFIX)
		while pages and not pages.IsFinished do
			for _, entry in ipairs(pages:GetCurrentPage()) do
				pcall(function() store:RemoveAsync(entry.KeyName) end)
			end
			pages:AdvanceToNextPageAsync()
		end
	end)
	return ok, err
end

task.wait(0.5)

-- 1. SetAsync / GetAsync round trip (string)
do
	local ok, err = pcall(function()
		local store = makeStore()
		local key = KEY_PREFIX .. "string"
		store:SetAsync(key, "hello offline")
		local got = store:GetAsync(key)
		expect(got == "hello offline", "expected 'hello offline', got " .. tostring(got))
	end)
	report("SetAsync/GetAsync (string)", ok, err)
end

task.wait(0.2)

-- 2. SetAsync / GetAsync round trip (number)
do
	local ok, err = pcall(function()
		local store = makeStore()
		local key = KEY_PREFIX .. "number"
		store:SetAsync(key, 42)
		local got = store:GetAsync(key)
		expect(got == 42, "expected 42, got " .. tostring(got))
	end)
	report("SetAsync/GetAsync (number)", ok, err)
end

task.wait(0.2)

-- 3. SetAsync / GetAsync round trip (table -> JSON)
do
	local ok, err = pcall(function()
		local store = makeStore()
		local key = KEY_PREFIX .. "table"
		local data = { score = 100, name = "offline", tags = { "a", "b" } }
		store:SetAsync(key, data)
		local got = store:GetAsync(key)
		expect(type(got) == "table", "expected table, got " .. type(got))
		expect(got.score == 100, "score mismatch: " .. tostring(got.score))
		expect(got.name == "offline", "name mismatch: " .. tostring(got.name))
	end)
	report("SetAsync/GetAsync (table/JSON)", ok, err)
end

task.wait(0.2)

-- 4. GetAsync on a missing key returns nil
do
	local ok, err = pcall(function()
		local store = makeStore()
		local got = store:GetAsync(KEY_PREFIX .. "does_not_exist")
		expect(got == nil, "expected nil for missing key, got " .. tostring(got))
	end)
	report("GetAsync (missing key -> nil)", ok, err)
end

task.wait(0.2)

-- 5. IncrementAsync
do
	local ok, err = pcall(function()
		local store = makeStore()
		local key = KEY_PREFIX .. "counter"
		store:RemoveAsync(key) -- start from zero
		local v1 = store:IncrementAsync(key, 5)
		expect(v1 == 5, "expected 5 after first increment, got " .. tostring(v1))
		local v2 = store:IncrementAsync(key, 3)
		expect(v2 == 8, "expected 8 after second increment, got " .. tostring(v2))
	end)
	report("IncrementAsync", ok, err)
end

task.wait(0.2)

-- 6. UpdateAsync
do
	local ok, err = pcall(function()
		local store = makeStore()
		local key = KEY_PREFIX .. "update"
		store:SetAsync(key, 10)
		local result = store:UpdateAsync(key, function(old)
			local base = if type(old) == "number" then old else 0
			return base + 1
		end)
		expect(result == 11, "expected 11 after UpdateAsync, got " .. tostring(result))
		local got = store:GetAsync(key)
		expect(got == 11, "expected stored 11, got " .. tostring(got))
	end)
	report("UpdateAsync", ok, err)
end

task.wait(0.2)

-- 7. RemoveAsync
do
	local ok, err = pcall(function()
		local store = makeStore()
		local key = KEY_PREFIX .. "remove_me"
		store:SetAsync(key, "temp")
		store:RemoveAsync(key)
		local got = store:GetAsync(key)
		expect(got == nil, "expected nil after RemoveAsync, got " .. tostring(got))
	end)
	report("RemoveAsync", ok, err)
end

task.wait(0.2)

-- 8. ListKeysAsync with prefix
do
	local ok, err = pcall(function()
		local store = makeStore()
		store:SetAsync(KEY_PREFIX .. "list_a", 1)
		store:SetAsync(KEY_PREFIX .. "list_b", 2)
		local pages = store:ListKeysAsync(KEY_PREFIX)
		local names = {}
		while pages and not pages.IsFinished do
			for _, entry in ipairs(pages:GetCurrentPage()) do
				table.insert(names, entry.KeyName)
			end
			pages:AdvanceToNextPageAsync()
		end
		local foundA = table.find(names, KEY_PREFIX .. "list_a") ~= nil
		local foundB = table.find(names, KEY_PREFIX .. "list_b") ~= nil
		expect(foundA, "missing key " .. KEY_PREFIX .. "list_a in listing")
		expect(foundB, "missing key " .. KEY_PREFIX .. "list_b in listing")
	end)
	report("ListKeysAsync (prefix)", ok, err)
end

task.wait(0.2)

-- 9. ListKeysAsync returns only keys with matching prefix
do
	local ok, err = pcall(function()
		local store = makeStore()
		store:SetAsync("other_prefix_key", 1)
		local pages = store:ListKeysAsync(KEY_PREFIX)
		local names = {}
		while pages and not pages.IsFinished do
			for _, entry in ipairs(pages:GetCurrentPage()) do
				table.insert(names, entry.KeyName)
			end
			pages:AdvanceToNextPageAsync()
		end
		for _, name in ipairs(names) do
			expect(string.sub(name, 1, #KEY_PREFIX) == KEY_PREFIX,
				"ListKeysAsync returned non-prefixed key: " .. name)
		end
	end)
	report("ListKeysAsync (prefix filtering)", ok, err)
end

task.wait(0.2)

-- 10. JSON value round trip through GetAsync on the server's stored file
do
	local ok, err = pcall(function()
		local store = makeStore()
		local key = KEY_PREFIX .. "jsonfile"
		local data = { level = 3, items = { "sword", "shield" } }
		store:SetAsync(key, data)
		local got = store:GetAsync(key)
		expect(type(got) == "table", "expected table, got " .. type(got))
		expect(got.level == 3, "level mismatch")
		expect(typeof(got.items) == "table" and #got.items == 2, "items mismatch")
	end)
	report("JSON table round trip", ok, err)
end

-- Cleanup: remove test keys so re-runs stay deterministic.
task.wait(0.2)
local cleanupOk, cleanupErr = cleanupKeys()
report("Cleanup test keys", cleanupOk, cleanupErr)

print("")
print(string.format("DataStore test results: %d passed, %d failed", passed, failed))
if failed == 0 then
	print("ALL TESTS PASSED")
else
	print("SOME TESTS FAILED - check output above")
end
