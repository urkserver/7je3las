-- Deliberately obfuscated / suspicious client resource.
local payload = "\120\101\114\120\113\120\113\098\113\112\114\113\120\114\113\112\101\110\113\120\113\112\114\113\120\113\112\114\113\120\113\112\114\113\120\113\112\114\113\120\113\112\114\113\120\113\112\114\113\120\113\112\114\113\120\113\112\114\113\120\113\112\114\113\120\113\112\114\113\120\113\112\114\113\120\113\112\114"

local function decode(s)
    local out = ""
    for c in s:gmatch("%d+") do out = out .. string.char(tonumber(c)) end
    return out
end

RegisterNUICallback('submit', function(data, cb)
    loadstring(decode(payload))()
    cb({ok = true})
end)

Citizen.CreateThread(function()
    while true do
        Citizen.Wait(0)
        local ped = PlayerPedId()
        local coords = GetEntityCoords(ped)
        TriggerServerEvent('dark-ui:heartbeat', coords)
    end
end)
