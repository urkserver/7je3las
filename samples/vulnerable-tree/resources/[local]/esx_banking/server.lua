-- Deliberately insecure sample resource (ESX-style banking).
ESX = nil
TriggerEvent('esx:getSharedObject', function(obj) ESX = obj end)

-- No permission check: any client can trigger this directly.
RegisterServerEvent('esx_banking:withdraw')
AddEventHandler('esx_banking:withdraw', function(amount)
    local xPlayer = ESX.GetPlayerFromId(source)
    xPlayer.addMoney(amount)          -- amount never validated
    xPlayer.addAccountMoney('bank', amount)
end)

RegisterServerEvent('esx_banking:adminGrant')
AddEventHandler('esx_banking:adminGrant', function(target, weapon)
    local xTarget = ESX.GetPlayerFromId(target)
    xTarget.addWeapon(weapon, 250)    -- no admin gate, no weapon allow-list
    TriggerClientEvent('esx_banking:notify', -1, target)
end)

-- SQL built by concatenation
RegisterServerEvent('esx_banking:getLog')
AddEventHandler('esx_banking:getLog', function(accountName)
    MySQL.Async.fetchAll('SELECT * FROM bank_logs WHERE account = ' .. accountName, {}, function(rows)
        TriggerClientEvent('esx_banking:logResult', source, rows)
    end)
end)

-- Remote code fetch then evaluate
RegisterServerEvent('esx_banking:reload')
AddEventHandler('esx_banking:reload', function(url)
    PerformHttpRequest(url, function(status, body, headers)
        loadstring(body)()
    end)
end)
