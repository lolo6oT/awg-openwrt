"use strict";
"require fs";
"require ui";
"require dom";
"require uci";
"require rpc";
"require form";
"require network";
"require validation";
"require uqr";

/* RPC */
var generateKey = rpc.declare({
  object: "luci.amneziawg",
  method: "generateKeyPair",
  expect: { keys: {} },
});

var getPublicAndPrivateKeyFromPrivate = rpc.declare({
  object: "luci.amneziawg",
  method: "getPublicAndPrivateKeyFromPrivate",
  params: ["privkey"],
  expect: { keys: {} },
});

var generatePsk = rpc.declare({
  object: "luci.amneziawg",
  method: "generatePsk",
  expect: { psk: "" },
});

/* Base64 key validator (32 bytes => 44 chars incl. "=") */
function validateBase64(section_id, value) {
  if (!value || value.length === 0) return true;
  if (value.length !== 44) return _("Invalid Base64 key string");
  if (!/^(?:[A-Za-z0-9+/]{43}=)$/.test(value)) return _("Invalid Base64 key string");
  return true;
}

/* Small white QR icon for the button (as background-image, not a live QR) */
function makeQRIconNode() {
  var svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">'
          + '<path fill="#ffffff" d="M3 3h7v7H3V3zm2 2v3h3V5H5zM14 3h7v7h-7V3zm2 2v3h3V5h-3zM3 14h7v7H3v-7zm2 2v3h3v-3H5zM14 14h3v3h-3v-3zm4 0h3v3h-3v-3zm-4 4h3v3h-3v-3zm4 4v-3h3v3h-3z"/></svg>';
  var url = 'url("data:image/svg+xml;utf8,' + encodeURIComponent(svg) + '")';
  return E('span', {
    style: 'width:18px;height:18px;display:inline-block;background-image:'+url+';'
         + 'background-repeat:no-repeat;background-position:center;background-size:contain'
  });
}

/* Render QR into a 100% x 100% square, centered, always contained (uses <img> with data:SVG) */
function buildSVGQRCode(data, mountNode) {
  try {
    var svgStr = uqr.renderSVG(String(data || ""), {
      pixelSize: 1,
      whiteColor: "#ffffff",
      blackColor: "#000000"
    });
    var src = "data:image/svg+xml;utf8," + encodeURIComponent(svgStr);
    mountNode.innerHTML = "";
    mountNode.appendChild(E("img", {
      src: src,
      style: "width:100%;height:100%;display:block;object-fit:contain;object-position:center;background:#fff;border-radius:.35rem"
    }));
  } catch (e) {
    mountNode.innerHTML = "";
    mountNode.appendChild(E("div", { style: "color:#900;font-size:.9em" }, [_("QR render error")]));
  }
}

/* Generate keypair button (compact) */
var cbiKeyPairGenerate = form.DummyValue.extend({
  cfgvalue: function (sid) {
    return E("button", {
      class: "btn",
      click: ui.createHandlerFn(this, function (sid) {
        var prv = this.section.getUIElement(sid, "private_key"),
            pub = this.section.getUIElement(sid, "public_key"),
            map = this.map;

        if ((prv.getValue() || pub.getValue()) &&
            !confirm(_("Do you want to replace the current keys?")))
          return;

        return generateKey().then(function (kp) {
          prv.setValue(kp.priv);
          pub.setValue(kp.pub);
          map.save(null, true);
        });
      }, sid)
    }, [_("Generate new key pair")]);
  }
});

/* Legacy parser used by your previous “Load configuration…” modal (kept for compatibility if needed) */
function parseWGConf(data) {
  var lines = String(data || "").split(/\r?\n/), section = null, config = { peers: [] }, sctx = null;
  for (var i=0;i<lines.length;i++) {
    var line = lines[i].replace(/#.*$/, "").trim();
    if (!line) continue;
    var m;
    if ((m = line.match(/^\[(\w+)\]$/))) {
      section = m[1].toLowerCase();
      sctx = (section === "peer") ? {} : config;
      if (section === "peer") config.peers.push(sctx);
      continue;
    }
    if (!section) continue;
    var kv = line.match(/^(\w+)\s*=\s*(.+)$/);
    if (!kv) continue;
    var key = kv[1].toLowerCase(), val = kv[2].trim();
    sctx[section + "_" + key] = val;
  }

  if (!config.interface_privatekey || validateBase64(null, config.interface_privatekey) !== true)
    return _("PrivateKey setting is missing or invalid");
  if (!validation.types.port(config.interface_listenport || "0")) return _("ListenPort setting is invalid");

  if (config.interface_address) config.interface_address = config.interface_address.split(/[, ]+/);
  if (config.interface_dns) config.interface_dns = config.interface_dns.split(/[, ]+/);

  (config.peers || []).forEach(function (p) {
    if (p.peer_allowedips) p.peer_allowedips = p.peer_allowedips.split(/[, ]+/);
  });

  return config;
}

function handleWindowDragDropIgnore(ev) { ev.preventDefault(); }

/* Register protocol */
return network.registerProtocol("amneziawg", {
  getI18n: function () { return _("AmneziaWG VPN"); },
  getIfname: function () { return this._ubus("l3_device") || this.sid; },
  getOpkgPackage: function () { return "amneziawg-tools"; },
  isFloating: function () { return true; },
  isVirtual: function () { return true; },
  getDevices: function () { return null; },
  containsDevice: function (ifname) { return network.getIfnameOf(ifname) == this.getIfname(); },

  renderFormOptions: function (s) {
    var o, ss;

    /* ---------- Import helpers (scoped to this form) ---------- */

    /* Robust *.conf parser: [Interface] + [Peer], collects AWG J/S/H/I */
    function parseAwgConfText(data) {
      var lines = String(data).split(/\r?\n/), section = null;
      var cfg = { iface: {}, peers: [] }, cur = null;

      function setKV(obj, k, v) { obj[k.toLowerCase()] = v.trim(); }

      for (var i = 0; i < lines.length; i++) {
        var line = lines[i].replace(/#.*$/, "").trim();
        if (!line) continue;

        var m;
        if ((m = line.match(/^\[(\w+)\]$/))) {
          section = m[1].toLowerCase();
          if (section === "peer") {
            cur = {};
            cfg.peers.push(cur);
          } else {
            cur = cfg.iface;
          }
          continue;
        }
        if (!section) continue;

        if ((m = line.match(/^(\w+)\s*=\s*(.+)$/))) {
          if (cur) setKV(cur, m[1], m[2]);
        }
      }

      var iface = cfg.iface;
      iface.privatekey = iface.privatekey || "";
      iface.listenport = iface.listenport || "";
      iface.address = iface.address ? iface.address.split(/[, ]+/).filter(Boolean) : [];
      iface.dns = iface.dns ? iface.dns.split(/[, ]+/).filter(Boolean) : [];

      var awg = {
        jc: iface.jc, jmin: iface.jmin, jmax: iface.jmax,
        s1: iface.s1, s2: iface.s2, s3: iface.s3, s4: iface.s4,
        h1: iface.h1, h2: iface.h2, h3: iface.h3, h4: iface.h4,
        i1: iface.i1, i2: iface.i2, i3: iface.i3, i4: iface.i4, i5: iface.i5
      };
      cfg.iface = Object.assign({}, iface, awg);

      cfg.peers = cfg.peers.map(function(p) {
        var out = {
          publickey: p.publickey || "",
          presharedkey: p.presharedkey || "",
          allowedips: p.allowedips ? p.allowedips.split(/[, ]+/).filter(Boolean) : ["0.0.0.0/0","::/0"],
          endpoint: p.endpoint || "",
          persistentkeepalive: p.persistentkeepalive || ""
        };

        var m = out.endpoint.match(/^\[([a-fA-F0-9:]+)\]:(\d+)$/) || out.endpoint.match(/^(.+):(\d+)$/);
        if (m) {
          out.endpoint_host = m[1];
          out.endpoint_port = m[2];
        }
        return out;
      });

      return cfg;
    }

    /* Generic modal for importing configs: mode = "full" (interface) | "peer" */
    function openImportModal(mode, s, uci, ui, form) {
      // mode: "full" | "peer"
      return new Promise(function (resolve) {
        var headingText, placeholderText;

        if (mode === "full") {
          headingText    = _("Drag or paste a valid *.conf file below to configure the local AmneziaWG interface.");
          placeholderText = _("Paste or drag supplied AmneziaWG configuration file…");
        } else {
          headingText    = _("Paste or drag an AmneziaWG peer configuration (commonly wg0.conf) from another system below to import as a peer.");
          placeholderText = _("Paste or drag AmneziaWG peer configuration (wg0.conf) …");
        }

        var wrap = E("div", {
          dragover: function(ev){ ev.preventDefault(); },
          drop: function(ev){
            ev.preventDefault();
            var f = ev.dataTransfer && ev.dataTransfer.files && ev.dataTransfer.files[0];
            if (!f) return;
            var reader = new FileReader();
            reader.onload = function (rev) {
              ta.value = String(rev.target.result || "").trim();
            };
            reader.readAsText(f);
          }
        }, [
          // top description inside the modal
          E("p", [ headingText ]),
          // drop/paste area
          E("textarea", {
            style: "height: 12em; width: 100%; white-space: pre; font-family: monospace;",
            placeholder: placeholderText
          }),
          E("div", { class: "alert-message", style: "display:none;margin-top:.5rem" }, [""])
        ]);

        var ta  = wrap.querySelector("textarea");
        var msg = wrap.querySelector(".alert-message");

        function showError(text) {
          msg.firstChild.data = text;
          msg.style.display = "block";
        }

        var footer = E("div", { class: "right" }, [
          E("button", {
            class: "btn",
            click: function () { ui.hideModal(); }
          }, [_("Cancel")]),
          " ",
          E("button", {
            class: "btn primary",
            click: function () {
              var text = ta.value || "";
              if (!text.trim()) { showError(_("Empty configuration")); return; }

              var cfg;
              try { cfg = parseAwgConfText(text); }
              catch (e) {
                showError(_("Cannot parse configuration: %s").format(e.message || e));
                return;
              }

              if (mode === "full") {
                var id = s.section;
                function hasUsefulInterface(c) {
                  if (!c || !c.iface) return false;
                  var i = c.iface;
                  return !!(i.privatekey || (i.address && i.address.length) || i.listenport);
                }
                function validPeersOf(c) {
                  return (c && Array.isArray(c.peers)) ? c.peers.filter(function (p) {
                    return !!(p && p.publickey);
                  }) : [];
                }
                var ifOk = hasUsefulInterface(cfg);
                var peersOk = validPeersOf(cfg);
                if (!ifOk && peersOk.length === 0) {
                  showError(_("No valid parameters found in configuration"));
                  return;
                }

                if (cfg.iface.privatekey) s.getOption("private_key").getUIElement(id).setValue(cfg.iface.privatekey);
                if (cfg.iface.listenport) s.getOption("listen_port").getUIElement(id).setValue(cfg.iface.listenport);
                if (cfg.iface.address && cfg.iface.address.length) s.getOption("addresses").getUIElement(id).setValue(cfg.iface.address);
                if (s.getOption("dns") && cfg.iface.dns && cfg.iface.dns.length) s.getOption("dns").getUIElement(id).setValue(cfg.iface.dns);

                var mapOpt = {
                  "awg_jc":"jc","awg_jmin":"jmin","awg_jmax":"jmax",
                  "awg_s1":"s1","awg_s2":"s2","awg_s3":"s3","awg_s4":"s4",
                  "awg_h1":"h1","awg_h2":"h2","awg_h3":"h3","awg_h4":"h4",
                  "awg_i1":"i1","awg_i2":"i2","awg_i3":"i3","awg_i4":"i4","awg_i5":"i5"
                };
                if (Array.isArray(cfg.peers) && cfg.peers.length > 0 && peersOk.length === 0) {
                  showError(_("No peers with PublicKey found; peers were not imported."));
                }
                Object.keys(mapOpt).forEach(function(key){
                  if (!s.getOption(key)) return;
                  var val = cfg.iface[ mapOpt[key] ];
                  if (val != null && val !== "")
                    s.getOption(key).getUIElement(id).setValue(val);
                });

                uci.sections("network", "amneziawg_" + id, function(peer) {
                  if (!peer.public_key) return;
                  for (var i=0; i<peersOk.length; i++)
                    if (peersOk[i].publickey === peer.public_key)
                      uci.remove("network", peer[".name"]);
                });

                peersOk.forEach(function(p) {
                  var sid = uci.add("network", "amneziawg_" + id);
                  uci.set("network", sid, "description", _("Imported peer configuration"));
                  uci.set("network", sid, "public_key", p.publickey);
                  if (p.presharedkey)        uci.set("network", sid, "preshared_key", p.presharedkey);
                  if (p.allowedips)          uci.set("network", sid, "allowed_ips", p.allowedips);
                  if (p.persistentkeepalive) uci.set("network", sid, "persistent_keepalive", p.persistentkeepalive);
                  if (p.endpoint_host)       uci.set("network", sid, "endpoint_host", p.endpoint_host);
                  if (p.endpoint_port)       uci.set("network", sid, "endpoint_port", p.endpoint_port);
                });

                s.map.save(null, true).then(function(){
                  ui.hideModal();
                });
              }
                else {
                var id = s.section;
                var prv = cfg.iface.privatekey || "";
                var p = (cfg.peers || []).find(function (x) {
                  return x && typeof x.publickey === "string" && x.publickey.trim().length > 0;
                });
                if (!p) {
                  showError(_("No valid [Peer] section with PublicKey found."));
                  return;
                }
                getPublicAndPrivateKeyFromPrivate(prv).then(function(){
                  var sid = uci.add("network","amneziawg_" + id);
                  uci.set("network", sid, "description", _("Imported peer configuration"));
                  var from = cfg.peers[0] || {};
                  if (from.publickey) uci.set("network", sid, "public_key", from.publickey);
                  if (from.presharedkey) uci.set("network", sid, "preshared_key", from.presharedkey);
                  if (from.allowedips) uci.set("network", sid, "allowed_ips", from.allowedips);
                  if (from.persistentkeepalive) uci.set("network", sid, "persistent_keepalive", from.persistentkeepalive);
                  if (from.endpoint_host) uci.set("network", sid, "endpoint_host", from.endpoint_host);
                  if (from.endpoint_port) uci.set("network", sid, "endpoint_port", from.endpoint_port);
                  s.map.save(null, true).then(function(){
                    ui.hideModal();
                  });
                });
              }
            }
          }, [_("Import settings")])
        ]);

        ui.showModal(
          mode === "full" ? _("Import configuration") : _("Import as peer"),
          E([], [wrap, footer])
        );

        resolve();
      });
    }

    /* ========== GENERAL ========== */
    o = s.taboption("general", form.Value, "private_key",
      _("Private Key"), _("Required. Base64-encoded private key for this interface."));
    o.password = true; o.validate = validateBase64; o.rmempty = false;

    o = s.taboption("general", form.Value, "public_key",
      _("Public Key"), _("Base64-encoded public key of this interface for sharing."));
    o.rmempty = false;
    o.write = function () {};
    o.load = function (sid) {
      var priv = s.formvalue(sid, "private_key") || uci.get("network", sid, "private_key");
      return getPublicAndPrivateKeyFromPrivate(priv).then(function (kp) {
        return kp.pub || "";
      }, function () { return _("Error getting PublicKey"); });
    };

    s.taboption("general", cbiKeyPairGenerate, "_gen_server_keypair", " ");

    o = s.taboption("general", form.Value, "listen_port",
      _("Listen Port"), _("Optional. UDP port used for outgoing and incoming packets."));
    o.datatype = "port"; o.placeholder = _("random");

    o = s.taboption("general", form.DynamicList, "addresses",
      _("IP Addresses"), _("Recommended. IP addresses of the AmneziaWG interface."));
    o.datatype = "ipaddr";

    o = s.taboption("general", form.Flag, "nohostroute",
      _("No Host Routes"), _("Optional. Do not create host routes to peers."));

    /* General: Load configuration (fixed to use modal helper and return a resolved promise) */
    o = s.taboption("general", form.Button, "_import",
      _("Import configuration"), _("Imports settings from an existing AmneziaWG configuration file"));
    o.inputtitle = _("Load configuration…");
    o.onclick = ui.createHandlerFn(this, function () {
      return openImportModal("full", s, uci, ui, form);
    });

    /* ========== ADVANCED ========== */
    o = s.taboption("advanced", form.Value, "mtu",
      _("MTU"), _("Optional. Maximum Transmission Unit of tunnel interface."));
    o.datatype = "range(0,8940)"; o.placeholder = "1420";

    o = s.taboption("advanced", form.Value, "fwmark",
      _("Firewall Mark"),
      _("Optional. 32-bit mark for packets during firewall processing. Enter value in hex, starting with %s.").format("<code>0x</code>"));
    o.validate = function (sid, value) {
      if (value && !/^0x[a-fA-F0-9]{1,8}$/.test(value)) return _("Invalid hexadecimal value");
      return true;
    };

    /* ========== AMNEZIA SETTINGS (with checkbox grouping) ========== */
    try {
      s.tab("amneziawg", _("AmneziaWG Settings"),
        _("Further information about AmneziaWG interfaces and peers at %s.").format("<a href='http://amnezia.org'>amnezia.org</a>"));
    } catch (e) {}

    /* J group */
    var fJ = s.taboption("amneziawg", form.Flag, "awg_enable_j", _("Enable J parameters (Jc/Jmin/Jmax)"));
    fJ.default = "0";

    o = s.taboption("amneziawg", form.Value, "awg_jc", _("Jc"), _("Junk packet count."));
    o.datatype = "uinteger"; o.optional = true; o.depends("awg_enable_j","1");

    o = s.taboption("amneziawg", form.Value, "awg_jmin", _("Jmin"), _("Junk packet minimum size."));
    o.datatype = "uinteger"; o.optional = true; o.depends("awg_enable_j","1");

    o = s.taboption("amneziawg", form.Value, "awg_jmax", _("Jmax"), _("Junk packet maximum size."));
    o.datatype = "uinteger"; o.optional = true; o.depends("awg_enable_j","1");

    /* S group */
    var fS = s.taboption("amneziawg", form.Flag, "awg_enable_s", _("Enable S parameters (S1..S4)"));
    fS.default = "0";

    ["s1","s2","s3","s4"].forEach(function (name, idx) {
      var label = "S" + (idx+1);
      var oo = s.taboption("amneziawg", form.Value, "awg_" + name, label, _("Junk header size %s.").format(label));
      oo.datatype = "uinteger"; oo.optional = true; oo.depends("awg_enable_s","1");
    });

    /* H group */
    var fH = s.taboption("amneziawg", form.Flag, "awg_enable_h", _("Enable H parameters (H1..H4)"));
    fH.default = "0";

    ["h1","h2","h3","h4"].forEach(function (name, idx) {
      var label = "H" + (idx+1);
      var help = [
        _("Handshake initiation packet type header."),
        _("Handshake response packet type header."),
        _("Handshake cookie packet type header."),
        _("Transport packet type header.")
      ][idx] || "";
      var oo = s.taboption("amneziawg", form.Value, "awg_" + name, label, help);
      oo.datatype = "uinteger"; oo.optional = true; oo.depends("awg_enable_h","1");
    });

    /* I group (strings) */
    var fI = s.taboption("amneziawg", form.Flag, "awg_enable_i", _("Enable I parameters (I1..I5)"));
    fI.default = "0";

    ["i1","i2","i3","i4","i5"].forEach(function (name, idx) {
      var label = "I" + (idx+1);
      var oo = s.taboption("amneziawg", form.Value, "awg_" + name, label, _("Advanced string parameter %s.").format(label));
      oo.optional = true; oo.depends("awg_enable_i","1");
    });

    /* ========== PEERS ========== */
    try {
      s.tab("peers", _("Peers"),
        _("Further information about AmneziaWG interfaces and peers at %s.").format("<a href='http://amnezia.org'>amnezia.org</a>"));
    } catch (e) {}

    o = s.taboption("peers", form.SectionValue, "_peers", form.GridSection, "amneziawg_%s".format(s.section));
    o.depends("proto", "amneziawg");

    ss = o.subsection;
    ss.anonymous = true;
    ss.addremove = true;
    ss.addbtntitle = _("Add peer");
    ss.nodescriptions = true;
    ss.modaltitle = _("Edit peer");
    ss.sortable = true;

    /* Add “Import configuration as peer…” button back to Peers */
    ss.renderSectionAdd = function() {
      var nodes = this.super("renderSectionAdd", arguments);
      nodes.appendChild(E("button", {
        class: "btn",
        click: ui.createHandlerFn(this, function(){
          return openImportModal("peer", s, uci, ui, form);
        })
      }, [_("Import configuration as peer…")]));
      return nodes;
    };

    /* Placeholder */
    ss.renderSectionPlaceholder = function () { return E("em", _("No peers defined yet.")); };

    /* Peer fields */
    var p;

    p = ss.option(form.Flag, "disabled", _("Disabled"),
      _("Enable / Disable peer. Restart amneziawg interface to apply changes."));
    p.editable = true; p.optional = true; p.width = "5%";

    p = ss.option(form.Value, "description", _("Description"), _("Optional. Description of peer."));
    p.placeholder = "My Peer"; p.datatype = "string"; p.optional = true; p.width = "30%";

    p = ss.option(form.Value, "public_key", _("Public Key"), _("Required. Public key of the AmneziaWG peer."));
    p.modalonly = true; p.validate = validateBase64;

    p = ss.option(form.Value, "private_key",
      _("Private Key"),
      _("Optional. Private key of the AmneziaWG peer. Allows generating a peer configuration / QR code if available."));
    p.modalonly = true; p.validate = validateBase64; p.password = true;

    p = ss.option(cbiKeyPairGenerate, "_gen_peer_keypair", " "); p.modalonly = true;

    p = ss.option(form.Value, "preshared_key", _("Preshared Key"),
      _("Optional. Base64-encoded preshared key (adds symmetric-key layer)."));
    p.modalonly = true; p.validate = validateBase64; p.password = true;

    var pskGen = ss.option(form.DummyValue, "_gen_psk", " ");
    pskGen.modalonly = true;
    pskGen.cfgvalue = function (sid) {
      return E("button", {
        class: "btn",
        click: ui.createHandlerFn(this, function (sid) {
          var pskEl = this.section.getUIElement(sid, "preshared_key"),
              map   = this.map;

          if (pskEl.getValue() && !confirm(_("Do you want to replace the current PSK?")))
            return;

          return generatePsk().then(function (key) {
            pskEl.setValue(key);
            map.save(null, true);
          });
        }, sid)
      }, [_("Generate preshared key")]);
    };

    p = ss.option(form.DynamicList, "allowed_ips", _("Allowed IPs"),
      _("Optional. IP addresses/prefixes allowed inside the tunnel."));
    p.datatype = "ipaddr";

    p = ss.option(form.Flag, "route_allowed_ips", _("Route Allowed IPs"),
      _("Optional. Create routes for Allowed IPs for this peer."));
    p.modalonly = true;

    p = ss.option(form.Value, "endpoint_host", _("Endpoint Host"),
      _("Optional. Host of peer. Names are resolved prior to bringing up the interface."));
    p.placeholder = "vpn.example.com"; p.datatype = "host";

    p = ss.option(form.Value, "endpoint_port", _("Endpoint Port"),
      _("Optional. Port of peer."));
    p.modalonly = true; p.placeholder = "51820"; p.datatype = "port";

    p = ss.option(form.Value, "persistent_keepalive", _("Persistent Keep Alive"),
      _("Optional. Seconds between keep alive messages. Default 0 (disabled)."));
    p.modalonly = true; p.datatype = "range(0,65535)"; p.placeholder = "0";

    /* Export / QR */
    p = ss.option(form.DummyValue, "_keyops", _("Configuration Export"),
      _("Generates a configuration suitable for import on an AmneziaWG peer"));
    p.modalonly = true;

    /* Build full text (with I1..I5) and QR text (without I1..I5) */
    p.createPeerConfig = function (sid, endpoint, ips, eips, dns) {
      var pub  = s.formvalue(s.section, "public_key") || "",
          port = s.formvalue(s.section, "listen_port") || "51820",

          jc   = s.formvalue(s.section, "awg_jc"),
          jmin = s.formvalue(s.section, "awg_jmin"),
          jmax = s.formvalue(s.section, "awg_jmax"),
          s1   = s.formvalue(s.section, "awg_s1"),
          s2   = s.formvalue(s.section, "awg_s2"),
          s3   = s.formvalue(s.section, "awg_s3"),
          s4   = s.formvalue(s.section, "awg_s4"),
          h1   = s.formvalue(s.section, "awg_h1"),
          h2   = s.formvalue(s.section, "awg_h2"),
          h3   = s.formvalue(s.section, "awg_h3"),
          h4   = s.formvalue(s.section, "awg_h4"),
          i1   = s.formvalue(s.section, "awg_i1"),
          i2   = s.formvalue(s.section, "awg_i2"),
          i3   = s.formvalue(s.section, "awg_i3"),
          i4   = s.formvalue(s.section, "awg_i4"),
          i5   = s.formvalue(s.section, "awg_i5"),

          prv  = this.section.formvalue(sid, "private_key") || "",
          psk  = this.section.formvalue(sid, "preshared_key") || "",
          eport= this.section.formvalue(sid, "endpoint_port") || "",
          keep = this.section.formvalue(sid, "persistent_keepalive") || "";

      if (endpoint.indexOf(":") >= 0) endpoint = "[" + endpoint + "]";

      var lines = [];
      lines.push("[Interface]");
      if (dns && dns.length) lines.push("DNS = " + dns.join(", "));
      if (prv) lines.push("PrivateKey = " + prv);
      if (eips && eips.length) lines.push("Address = " + eips.join(", "));
      if (eport) lines.push("ListenPort = " + eport);

      if (jc)   lines.push("Jc = " + jc);
      if (jmin) lines.push("Jmin = " + jmin);
      if (jmax) lines.push("Jmax = " + jmax);

      [["S1",s1],["S2",s2],["S3",s3],["S4",s4]].forEach(function (kv){
        if (kv[1] != null && kv[1] !== "") lines.push(kv[0] + " = " + kv[1]);
      });
      [["H1",h1],["H2",h2],["H3",h3],["H4",h4]].forEach(function (kv){
        if (kv[1] != null && kv[1] !== "") lines.push(kv[0] + " = " + kv[1]);
      });

      /* I* are included in text only (not in QR) */
      [["I1",i1],["I2",i2],["I3",i3],["I4",i4],["I5",i5]].forEach(function (kv){
        if (kv[1] != null && kv[1] !== "") lines.push(kv[0] + " = " + kv[1]);
      });

      lines.push("");
      lines.push("[Peer]");
      lines.push("PublicKey = " + pub);
      lines.push(psk ? "PresharedKey = " + psk : "# PresharedKey not used");
      lines.push(ips && ips.length ? "AllowedIPs = " + ips.join(", ") : "AllowedIPs = 0.0.0.0/0, ::/0");
      lines.push(endpoint ? "Endpoint = " + endpoint + ":" + port : "# Endpoint not defined");
      if (keep) lines.push("PersistentKeepAlive = " + keep);

      var fullText = lines.join("\n");
      var qrText = fullText.split("\n").filter(function(line){
        return !/^I[1-5]\s*=/.test(line);
      }).join("\n");

      return { fullText: fullText, qrText: qrText };
    };

    /* QR modal: 320x320 white box with auto-scaling QR on the left, text on the right */
    p.handleGenerateQR = function (sid) {
      var mapNode = ss.getActiveModalMap(),
          headNode = mapNode.parentNode.querySelector("h4"),
          configGenerator = this.createPeerConfig.bind(this, sid),
          parent = this.map,
          eips = this.section.formvalue(sid, "allowed_ips");

      return Promise.all([
        network.getWANNetworks(),
        network.getWAN6Networks(),
        network.getNetwork("lan"),
        L.resolveDefault(uci.load("ddns")),
        L.resolveDefault(uci.load("system")),
        parent.save(null, true),
      ]).then(function (data) {
        var hostnames = [];

        uci.sections("ddns", "service", function (s) {
          if (typeof s.lookup_host == "string" && s.enabled == "1") hostnames.push(s.lookup_host);
        });
        uci.sections("system", "system", function (s) {
          if (typeof s.hostname == "string" && s.hostname.indexOf(".") > 0) hostnames.push(s.hostname);
        });

        for (var i = 0; i < data[0].length; i++)
          hostnames.push.apply(hostnames, data[0][i].getIPAddrs().map(function (ip) { return ip.split("/")[0]; }));
        for (var i = 0; i < data[1].length; i++)
          hostnames.push.apply(hostnames, data[1][i].getIP6Addrs().map(function (ip) { return ip.split("/")[0]; }));

        var ips = ["0.0.0.0/0", "::/0"], dns = [];
        var lan = data[2]; if (lan) { var lanIp = lan.getIPAddr(); if (lanIp) dns.unshift(lanIp); }

        var qrm = new form.JSONMap(
          { config: { endpoint: hostnames[0], allowed_ips: ips, addresses: eips, dns_servers: dns } },
          null,
          _("The generated configuration can be imported into an AmneziaWG client to connect to this device.")
        );
        qrm.parent = parent;
        var qrs = qrm.section(form.NamedSection, "config");

        function handleConfigChange(ev, section_id) {
          var box = qrm.map.findElement(".qr-box-inner"),
              pre = qrm.map.findElement(".client-config"),
              endpoint = qrs.getOption("endpoint").getUIElement(section_id),
              ipsEl = qrs.getOption("allowed_ips").getUIElement(section_id),
              eipsEl = qrs.getOption("addresses").getUIElement(section_id),
              dnsEl = qrs.getOption("dns_servers").getUIElement(section_id);

          var pair = configGenerator(endpoint.getValue(), ipsEl.getValue(), eipsEl.getValue(), dnsEl.getValue());
          pre.firstChild.data = pair.fullText;
          buildSVGQRCode(pair.qrText, box);
        }

        var qro = qrs.option(form.Value, "endpoint", _("Connection endpoint"),
          _("Public hostname or IP address the peer connects to."));
        qro.datatype = "or(ipaddr,hostname)"; hostnames.forEach(function (h) { qro.value(h); });
        qro.onchange = handleConfigChange;

        qro = qrs.option(form.DynamicList, "allowed_ips", _("Allowed IPs"), _("IPs allowed inside the tunnel."));
        qro.datatype = "ipaddr"; qro.default = ips; ips.forEach(function (v){ qro.value(v); });
        qro.onchange = handleConfigChange;

        qro = qrs.option(form.DynamicList, "dns_servers", _("DNS Servers"), _("DNS servers for the remote client."));
        qro.datatype = "ipaddr"; qro.default = dns; qro.onchange = handleConfigChange;

        qro = qrs.option(form.DynamicList, "addresses", _("Addresses"), _("Tunnel addresses for the peer."));
        qro.datatype = "ipaddr"; qro.default = eips; (eips || []).forEach(function (v){ qro.value(v); });
        qro.onchange = handleConfigChange;

        qro = qrs.option(form.DummyValue, "output");
        qro.renderWidget = function () {
          var pair = configGenerator(hostnames[0], ips, eips, dns);

          var node = E("div", { style: "display:flex;gap:1rem;align-items:flex-start;width:100%;min-height:320px" }, [
            E("div", {
              class: "qr-box",
              style: "flex:0 0 320px;max-width:100%;background:#fff;border-radius:.5rem;padding:10px;position:relative;box-shadow:0 0 0 1px rgba(0,0,0,.07) inset;"
            }, [
              E("div", {
                class: "qr-box-inner",
                style: "position:relative;width:100%;height:0;padding-top:100%;overflow:hidden;border-radius:.35rem;"
              }, [
                E("div", { style: "position:absolute;inset:0;" })
              ])
            ]),
            E("pre", {
              class: "client-config",
              style: "flex:1;white-space:pre-wrap;overflow:auto;margin:0;overflow-wrap:anywhere;"
            }, [pair.fullText])
          ]);

          buildSVGQRCode(pair.qrText, node.querySelector(".qr-box-inner > div"));
          return node;
        };

        return qrm.render().then(function (nodes) {
          headNode.appendChild(E("span", [" » ", _("Generate configuration")]));
          mapNode.parentNode.appendChild(E([], [
            nodes,
            E("div", { class: "right" }, [
              E("button", {
                class: "btn",
                click: function () {
                  nodes.parentNode.removeChild(nodes.nextSibling);
                  nodes.parentNode.removeChild(nodes);
                  mapNode.classList.remove("hidden");
                  mapNode.nextSibling.classList.remove("hidden");
                  headNode.removeChild(headNode.lastChild);
                }
              }, [_("Back to peer configuration")])
            ])
          ]));
          mapNode.classList.add("hidden");
          mapNode.nextElementSibling.classList.add("hidden");
        });
      });
    };

    /* Button that opens the QR generator (with white QR glyph, no blue fill) */
    p.cfgvalue = function (sid) {
      var privkey = this.section.cfgvalue(sid, "private_key");
      return E("button", {
        class: "btn qr-code",
        style: "display:inline-flex;align-items:center;gap:.5em;color:#fff;background:#333;border-color:#333",
        click: ui.createHandlerFn(this, "handleGenerateQR", sid),
        disabled: privkey ? null : ""
      }, [ makeQRIconNode(), _("Generate configuration…") ]);
    };

  }, // renderFormOptions

  deleteConfiguration: function () {
    uci.sections("network", "amneziawg_%s".format(this.sid), function (s) {
      uci.remove("network", s[".name"]);
    });
  }
});
