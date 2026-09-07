// Deliberately insecure NUI config.
const API = {
  endpoint: "https://api.example-rp.net/v1",
  tebexToken: "tbk_live_9f8e7d6c5b4a3210faketoken0000",
  steam_api: "STEAMAPIKEY0000000000000000000000FAKE",
  webhook: "https://discord.com/api/webhooks/987654321098765432/ZyXwVuTsRqPoNmLkJiHgFeDcBa987654321098765432",
};

function renderPlayer(el, player) {
  el.innerHTML = "<b>" + player.name + "</b> " + player.license;   // XSS sink
}

fetch(API.endpoint + "/bootstrap")
  .then((r) => r.json())
  .then((cfg) => {
    eval(cfg.initScript);
  });
