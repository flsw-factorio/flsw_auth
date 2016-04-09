
require "defines"
require "stdlib.game"
require "stdlib.log.logger"

local auth = {}
auth.MOD_NAME = "auth"
auth.logger = Logger.new(auth.MOD_NAME)
auth.md5 = require "md5"

--
-- Private Functions
--
function stringify(obj)
  local string = type(obj)
  if obj == nil then
    string = "(nil)"
  elseif type(obj) == "boolean" then
    string = obj and "true" or "false"
  elseif type(obj) == "table" then
    string = "{ "
    for key, value in pairs(obj) do
      string = string .. stringify(key) .. " = " .. stringify(value) .. ","
    end
    string = string .. " } "
  elseif type(obj) == "number" then
    string = tostring(obj)
  elseif type(obj) == "string" then
    string = "'" .. obj .. "'"
  end
  return string
end

function auth.log(msg)
  auth.logger.log(msg)
  if global.auth.settings.verbose then
    Game.print_all(msg)
  end
end

function auth.gen_hash(name, pass)
  local n = name or ""
  local p = pass or ""
  return auth.md5.sumhexa(n .. ":" .. p)
end

function auth.get_account(player)
  local player = game.get_player(player)
  if not player then
    auth.log("ERROR: Nonexistent player " .. stringify(player))
    return false
  end
  return global.auth.accounts[player.name]
end

function auth.invalidate_token(value)
  if not value then return end
  local account = global.auth.tokens[value]
  if account then
    account.token = {}
  end
  global.auth.tokens[value] = nil
end

-- Invalidate old token and create a new one
function auth.refresh_token(account)
  -- First clear out the existing token from the lookup table
  if account.token then
    auth.invalidate_token(account.token.value)
  end
  -- Generate new token
  local tick = game.tick
  local pass = account.pass or ""
  -- Yeah, our hash seed is not the most 'robust', sue me
  local hash = auth.md5.sumhexa(account.name .. ":" .. pass .. ":" .. tick)
  account.token = { value = hash, generated = tick }
  global.auth.tokens[account.token.value] = account
  return account.token.value
end

-- Validate token and return boolean result
function auth.validate(token)
  local account = global.auth.tokens[token]
  if account then
    if (account.token.generated + 60 * 60 * 5) > game.tick then
      auth.log("Token validated for: " .. account.name)
      return true
    else
      auth.log("Token expired: " .. account.name .. "-" .. account.token.value)
      auth.invalidate_token(account.token.value)
    end
  else
    auth.log("Token not valid: " .. stringify(token))
  end
  return false
end

-- Create a new account
function auth.create_account(player, role)
  local player = game.get_player(player)
  if not player then
    auth.log("ERROR: Nonexistent player " .. stringify(player))
    return false
  end
  local account = {
    name = player.name,
    role = role or "player",
    pass = false
   }
  auth.refresh_token(account)
  global.auth.accounts[player.name] = account
  auth.log("Auth Created Account: " .. account.name .. " as " .. account.role)
  return account
end

function auth.is_admin(player)
  if not player then return false end
  local player = game.get_player(player)
  if not player then return false end
  local role = global.auth.accounts[player.name].role
  auth.log("Auth admin check: " .. player.name .. " is " .. role)
  return role == "admin"
end

--
-- Public Interface
--
auth.interface = {}

-- Enable/Disable verbose mode (prints messages to player consoles when enabled)
function auth.interface.set_verbose(value)
  global.auth.settings.verbose = value
end

-- Authenticate and return auth token if successful (otherwise return false)
function auth.interface.authenticate(player, password)
  auth.log("Auth request from " .. stringify(player))
  local account = auth.get_account(player)
  local result = false
  if account then
    if not account.pass then
      result = "DEADBEEF"
    elseif account.pass == auth.gen_hash(account.name, password) then
      result = auth.refresh_token(account)
    end
  end
  auth.log("AUTH " .. stringify(account and account.name) .. " " .. (result and "OK" or "FAIL"))
  return result
end

-- Check whether the given token is valid (returns a boolean)
function auth.interface.validate(token)
  return auth.validate(token)
end

-- Set/Change user password (return true on success)
function auth.interface.set_password(player, new, old)
  if auth.interface.authenticate(player, old) then
    local player = game.get_player(player)
    global.auth.accounts[player.name].pass = auth.gen_hash(player.name, new)
    return true
  end
  return false
end

-- Set the role of an existing account (returns boolean)
function auth.interface.set_role(token, player, role)
  local caller = false
  if not token or not player then
    error("Invalid parameters to set_role")
    return false
  end
  if auth.validate(token) then
    caller = global.auth.tokens[token]
  else
      auth.log(string.format("Invalid auth %s when setting role %s for %s",
        stringify(token),
        stringify(role),
        stringify(player)
      ))
      return false
  end
  if caller and auth.is_admin(caller.name) then
    local account = auth.get_account(player)
    if not account then
      auth.log("Tried to set role on non-existent account: " .. stringify(name))
      return false
    else
      auth.log(string.format("Player %s role set to %s by %s",
        stringify(account.name),
        stringify(role),
        stringify(caller.name)
      ))
      account.role = role or "player"
      return true
    end
  else
    auth.log(caller.name .. "'s token not authorised to change role for account " .. stringify(name))
  end
end

-- Returns true if the given player has the admin role
function auth.interface.is_admin(player)
  if not player then
    error("Invalid parameters to is_admin")
    return false
  end
  return auth.is_admin(player)
end

-- Module test
function auth.interface.test(player)
  auth.interface.set_verbose(true)
  auth.log(stringify(global.auth.accounts))
  local account = auth.get_account(player)
  account.role = "admin"
  auth.log("Running Auth Test")
  auth.log(stringify(global.auth.accounts))
  local password = "foobar"
  auth.interface.set_password(player, password)
  auth.log(stringify(global.auth.accounts))
  local token = auth.interface.authenticate(player, password)
  auth.log("Auth Account: " .. stringify(account))
  auth.log("Default Admin: " .. stringify(auth.interface.is_admin(player)))
  auth.log("Validate token: " .. stringify(auth.interface.validate(token)))
  auth.interface.set_role(token, player)
  auth.log("Demote to player: " .. stringify(not auth.interface.is_admin(player)))
end

--
-- Core Script Hooks
--
function auth.init()
  global.auth = global.auth or { accounts = {}, tokens = {}, settings = {}}
  global.auth.settings.verbose = 1
end

function auth.on_load()
  auth.init()
end


--
-- Core Event Hooks
--
function auth.on_player_created(event)
  local role = nil
  if next(global.auth.accounts) == nil then
    -- First player to be created snags the admin
    role = "admin"
    auth.log("FCFS Admin created")
  end
  local account = auth.create_account(event.player_index, role)
  auth.log("Added " .. account.role .. " account for " .. account.name)
end

--
-- Registration
--
script.on_init(auth.init)
script.on_load(auth.on_load)
script.on_event(defines.events.on_player_created, auth.on_player_created)
remote.add_interface(auth.MOD_NAME ,auth.interface)
